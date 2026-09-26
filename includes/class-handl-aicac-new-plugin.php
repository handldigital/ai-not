<?php
/**
 * AICAC-NEWPLUGIN: review-first mode for newly installed/activated plugins (#141)
 * plus AICAC-NEWCOMER-HOLD: first AI call hold (#271).
 *
 * Review-first (off by default): a plugin first seen after enablement gets a
 * needs-review state (interim Deny or Observe) until an admin chooses Allow or
 * Deny. Plugins present at enablement are grandfathered.
 *
 * Newcomer hold (off by default): a plugin's first AI Client call is Watch
 * (allow + log + flag) or Deny until the owner Allow / Deny / keep watching.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class New_Plugin {

	/** Interim modes while a plugin awaits review. */
	public const INTERIM_DENY    = 'deny';
	public const INTERIM_OBSERVE = 'observe';

	/** AICAC-NEWCOMER-HOLD (#271). */
	public const HOLD_WATCH = 'watch';
	public const HOLD_DENY  = 'deny';
	public const REASON     = 'newcomer_hold';

	public const POST_HOLD_PRESENT = 'handl_aicac_newcomer_hold_present';
	public const POST_HOLD_ENABLED = 'handl_aicac_newcomer_hold_enabled';
	public const POST_HOLD_MODE    = 'handl_aicac_newcomer_hold_mode';

	public const ACTION_ALLOW = 'handl_aicac_newcomer_allow';
	public const ACTION_DENY  = 'handl_aicac_newcomer_deny';
	public const ACTION_WATCH = 'handl_aicac_newcomer_watch';

	private static ?New_Plugin $instance = null;

	public static function instance(): New_Plugin {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function init(): void {
		add_action( 'activated_plugin', array( $this, 'on_activated_plugin' ), 10, 2 );
		add_action( 'handl_aicac_protections_settings', array( $this, 'render_hold_settings' ) );
		add_filter( 'pre_update_option_' . Plugin::OPTION_KEY, array( self::class, 'merge_hold_on_policy_save' ), 10, 2 );
		add_action( 'admin_post_' . self::ACTION_ALLOW, array( $this, 'handle_hold_allow' ) );
		add_action( 'admin_post_' . self::ACTION_DENY, array( $this, 'handle_hold_deny' ) );
		add_action( 'admin_post_' . self::ACTION_WATCH, array( $this, 'handle_hold_watch' ) );
		if ( is_admin() ) {
			add_action( 'admin_notices', array( $this, 'maybe_admin_notice' ) );
			add_action( 'admin_notices', array( $this, 'maybe_hold_notice' ) );
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			CLI_Newcomer::register();
		}
	}

	/**
	 * @param string $plugin Plugin basename.
	 * @param bool   $network_wide Network activation flag (unused; single-site rules).
	 */
	public function on_activated_plugin( $plugin, $network_wide = false ): void {
		unset( $network_wide );
		$basename = Plugin_Profile::sanitize_plugin( $plugin );
		if ( '' === $basename ) {
			return;
		}

		$policy = Policy::get_policy();
		if ( ! self::is_enabled( $policy ) ) {
			return;
		}

		$result = self::mark_first_seen( $policy, $basename, time() );
		if ( empty( $result['changed'] ) ) {
			return;
		}

		Policy::save_policy( $result['policy'] );
	}

	/**
	 * Admin notice listing plugins awaiting review (manage_options only).
	 */
	public function maybe_admin_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$policy = Policy::get_policy();
		if ( ! self::is_enabled( $policy ) ) {
			return;
		}

		$pending = self::pending_plugins( $policy );
		if ( empty( $pending ) ) {
			return;
		}

		// Avoid stacking a second copy on our own settings page (Dashboard line covers it).
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( $screen && isset( $screen->id ) && false !== strpos( (string) $screen->id, 'handl-ai-connector-access-control' ) ) {
			return;
		}

		$plugins = function_exists( 'get_plugins' ) ? get_plugins() : array();
		$links   = array();
		foreach ( $pending as $basename ) {
			$label = isset( $plugins[ $basename ]['Name'] ) ? (string) $plugins[ $basename ]['Name'] : $basename;
			$url   = self::review_rules_url( $basename );
			$links[] = '<a href="' . esc_url( $url ) . '">' . esc_html( $label ) . '</a>';
		}

		$count = count( $pending );
		echo '<div class="notice notice-warning"><p>';
		echo esc_html(
			sprintf(
				/* translators: %d: number of plugins awaiting AI policy review */
				_n(
					'%d new plugin needs an AI access decision.',
					'%d new plugins need an AI access decision.',
					$count,
					'handl-ai-connector-access-control'
				),
				$count
			)
		);
		echo ' ';
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- links built with esc_url/esc_html above.
		echo implode( ', ', $links );
		echo ' <a href="' . esc_url( self::review_all_url() ) . '">' . esc_html__( 'Review all', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p></div>';
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function is_enabled( array $policy ): bool {
		return ! empty( $policy['new_plugin_review_enabled'] );
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return 'deny'|'observe'
	 */
	public static function interim_mode( array $policy ): string {
		$mode = isset( $policy['new_plugin_interim'] ) ? sanitize_key( (string) $policy['new_plugin_interim'] ) : self::INTERIM_DENY;
		return self::INTERIM_OBSERVE === $mode ? self::INTERIM_OBSERVE : self::INTERIM_DENY;
	}

	/**
	 * @param mixed $raw
	 * @return 'deny'|'observe'
	 */
	public static function sanitize_interim( $raw ): string {
		$mode = sanitize_key( (string) $raw );
		return self::INTERIM_OBSERVE === $mode ? self::INTERIM_OBSERVE : self::INTERIM_DENY;
	}

	/**
	 * @param mixed $raw
	 * @return list<string>
	 */
	public static function sanitize_known( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $basename ) {
			$basename = Plugin_Profile::sanitize_plugin( $basename );
			if ( '' !== $basename ) {
				$out[] = $basename;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Basename => first-seen unix.
	 *
	 * @param mixed $raw
	 * @return array<string,int>
	 */
	public static function sanitize_pending( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $basename => $ts ) {
			$basename = Plugin_Profile::sanitize_plugin( $basename );
			if ( '' === $basename ) {
				continue;
			}
			if ( is_string( $ts ) && ! preg_match( '/^\s*\d+\s*$/', $ts ) ) {
				continue;
			}
			$n = (int) $ts;
			if ( $n <= 0 ) {
				continue;
			}
			$out[ $basename ] = $n;
		}
		return $out;
	}

	/**
	 * Normalize policy keys for read/write paths.
	 *
	 * @param array<string,mixed> $policy
	 * @return array<string,mixed>
	 */
	public static function normalize_policy( array $policy ): array {
		$policy['new_plugin_review_enabled'] = ! empty( $policy['new_plugin_review_enabled'] );
		$policy['new_plugin_interim']        = self::sanitize_interim( $policy['new_plugin_interim'] ?? self::INTERIM_DENY );
		$policy['new_plugin_known']          = self::sanitize_known( $policy['new_plugin_known'] ?? array() );
		$policy['new_plugin_pending']        = self::sanitize_pending( $policy['new_plugin_pending'] ?? array() );
		if ( self::policy_has_hold_keys( $policy ) ) {
			$policy['newcomer_hold_enabled']   = ! empty( $policy['newcomer_hold_enabled'] );
			$policy['newcomer_hold_mode']      = self::sanitize_hold_mode( $policy['newcomer_hold_mode'] ?? self::HOLD_WATCH );
			$policy['newcomer_hold_known']     = self::sanitize_known( $policy['newcomer_hold_known'] ?? array() );
			$policy['newcomer_hold_pending']   = self::sanitize_pending( $policy['newcomer_hold_pending'] ?? array() );
			$policy['newcomer_hold_email_at']  = self::sanitize_pending( $policy['newcomer_hold_email_at'] ?? array() );
			$policy['newcomer_hold_watch_ack'] = self::sanitize_pending( $policy['newcomer_hold_watch_ack'] ?? array() );
		}
		return $policy;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private static function policy_has_hold_keys( array $policy ): bool {
		foreach ( array( 'newcomer_hold_enabled', 'newcomer_hold_mode', 'newcomer_hold_known', 'newcomer_hold_pending', 'newcomer_hold_email_at', 'newcomer_hold_watch_ack' ) as $key ) {
			if ( array_key_exists( $key, $policy ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Apply settings from Rules save, grandfathering on first enable.
	 *
	 * @param array<string,mixed> $policy Policy being built for save.
	 * @param array<string,mixed> $previous Previously stored/normalized policy.
	 * @param list<string>|null   $active_basenames Active plugins for grandfather seed (tests inject).
	 * @return array<string,mixed>
	 */
	public static function apply_settings_transition( array $policy, array $previous, ?array $active_basenames = null ): array {
		$was_on = self::is_enabled( $previous );
		$now_on = ! empty( $policy['new_plugin_review_enabled'] );

		$policy['new_plugin_review_enabled'] = $now_on;
		$policy['new_plugin_interim']        = self::sanitize_interim( $policy['new_plugin_interim'] ?? self::INTERIM_DENY );
		$policy['new_plugin_known']          = self::sanitize_known( $policy['new_plugin_known'] ?? ( $previous['new_plugin_known'] ?? array() ) );
		$policy['new_plugin_pending']        = self::sanitize_pending( $policy['new_plugin_pending'] ?? ( $previous['new_plugin_pending'] ?? array() ) );

		if ( $now_on && ! $was_on ) {
			// First enable (or re-enable with empty known): grandfather currently active plugins.
			if ( empty( $policy['new_plugin_known'] ) ) {
				$policy['new_plugin_known'] = self::active_plugin_basenames( $active_basenames );
			}
			// Do not retroactively flag existing plugins — clear any stale pending for known set.
			$known_lookup = array_fill_keys( $policy['new_plugin_known'], true );
			foreach ( array_keys( $policy['new_plugin_pending'] ) as $bn ) {
				if ( isset( $known_lookup[ $bn ] ) ) {
					unset( $policy['new_plugin_pending'][ $bn ] );
				}
			}
		}

		if ( ! $now_on ) {
			// Off: zero behavior change for enforcement/notices; keep maps for re-enable continuity.
			return $policy;
		}

		return $policy;
	}

	/**
	 * @param list<string>|null $override
	 * @return list<string>
	 */
	public static function active_plugin_basenames( ?array $override = null ): array {
		if ( null !== $override ) {
			return self::sanitize_known( $override );
		}
		if ( ! function_exists( 'get_option' ) ) {
			return array();
		}
		$active = get_option( 'active_plugins', array() );
		if ( ! is_array( $active ) ) {
			return array();
		}
		return self::sanitize_known( $active );
	}

	/**
	 * Mark a plugin as first-seen when the feature is on.
	 *
	 * @param array<string,mixed> $policy
	 * @return array{policy:array<string,mixed>,changed:bool,pending:bool}
	 */
	public static function mark_first_seen( array $policy, string $basename, ?int $now = null ): array {
		$policy   = self::normalize_policy( $policy );
		$basename = Plugin_Profile::sanitize_plugin( $basename );
		$now      = null !== $now ? (int) $now : time();

		if ( '' === $basename || ! self::is_enabled( $policy ) ) {
			return array(
				'policy'  => $policy,
				'changed' => false,
				'pending' => false,
			);
		}

		$known = $policy['new_plugin_known'];
		if ( in_array( $basename, $known, true ) ) {
			return array(
				'policy'  => $policy,
				'changed' => false,
				'pending' => false,
			);
		}

		$pending = $policy['new_plugin_pending'];
		if ( isset( $pending[ $basename ] ) ) {
			return array(
				'policy'  => $policy,
				'changed' => false,
				'pending' => true,
			);
		}

		$pending[ $basename ]         = $now;
		$policy['new_plugin_pending'] = $pending;

		// Needs-review rule: interim Deny writes an explicit plugin deny until review.
		if ( self::INTERIM_DENY === self::interim_mode( $policy ) ) {
			$plugins = is_array( $policy['plugins'] ?? null ) ? (array) $policy['plugins'] : array();
			if ( ! isset( $plugins[ $basename ] ) || ( 'allow' !== $plugins[ $basename ] && 'deny' !== $plugins[ $basename ] ) ) {
				$plugins[ $basename ] = 'deny';
				$policy['plugins']    = $plugins;
			}
		}

		return array(
			'policy'  => $policy,
			'changed' => true,
			'pending' => true,
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function is_pending( array $policy, string $basename ): bool {
		if ( ! self::is_enabled( $policy ) ) {
			return false;
		}
		$basename = Plugin_Profile::sanitize_plugin( $basename );
		if ( '' === $basename ) {
			return false;
		}
		$pending = self::sanitize_pending( $policy['new_plugin_pending'] ?? array() );
		return isset( $pending[ $basename ] );
	}

	/**
	 * Whether interim Deny should block this plugin (feature on + pending + deny mode).
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function should_deny_interim( array $policy, ?string $plugin_basename ): bool {
		if ( null === $plugin_basename || '' === $plugin_basename ) {
			return false;
		}
		if ( ! self::is_enabled( $policy ) ) {
			return false;
		}
		if ( self::INTERIM_DENY !== self::interim_mode( $policy ) ) {
			return false;
		}
		return self::is_pending( $policy, $plugin_basename );
	}

	/**
	 * Pending basenames (sorted), empty when feature off.
	 *
	 * @param array<string,mixed> $policy
	 * @return list<string>
	 */
	public static function pending_plugins( array $policy ): array {
		if ( ! self::is_enabled( $policy ) ) {
			return array();
		}
		$pending = self::sanitize_pending( $policy['new_plugin_pending'] ?? array() );
		$keys    = array_keys( $pending );
		sort( $keys );
		return $keys;
	}

	/**
	 * Clear needs-review after an explicit Allow or Deny choice.
	 *
	 * @param array<string,mixed> $policy
	 * @return array<string,mixed>
	 */
	public static function clear_review( array $policy, string $basename ): array {
		$policy   = self::normalize_policy( $policy );
		$basename = Plugin_Profile::sanitize_plugin( $basename );
		if ( '' === $basename ) {
			return $policy;
		}

		if ( isset( $policy['new_plugin_pending'][ $basename ] ) ) {
			unset( $policy['new_plugin_pending'][ $basename ] );
		}

		if ( ! in_array( $basename, $policy['new_plugin_known'], true ) ) {
			$policy['new_plugin_known'][] = $basename;
		}
		$policy['new_plugin_known'] = self::sanitize_known( $policy['new_plugin_known'] );

		if ( self::policy_has_hold_keys( $policy ) ) {
			$policy = self::clear_hold( $policy, $basename );
		}

		return $policy;
	}

	/**
	 * After rules save / quick rule: clear pending for plugins with explicit allow|deny.
	 *
	 * @param array<string,mixed> $policy
	 * @return array<string,mixed>
	 */
	public static function clear_reviewed_from_plugins_map( array $policy ): array {
		$policy  = self::normalize_policy( $policy );
		$plugins = is_array( $policy['plugins'] ?? null ) ? (array) $policy['plugins'] : array();
		foreach ( $plugins as $basename => $rule ) {
			$rule = (string) $rule;
			if ( ( 'allow' === $rule || 'deny' === $rule )
				&& isset( $policy['new_plugin_pending'][ (string) $basename ] ) ) {
				$policy = self::clear_review( $policy, (string) $basename );
			} elseif ( ( 'allow' === $rule || 'deny' === $rule )
				&& isset( $policy['newcomer_hold_pending'][ (string) $basename ] ) ) {
				$policy = self::clear_hold( $policy, (string) $basename );
			}
		}
		return $policy;
	}

	/**
	 * Rules tab filtered to plugins awaiting a new-plugin decision.
	 */
	public static function review_all_url(): string {
		return Admin::screen_url(
			'rules',
			array(
				'handl_aicac_access' => 'pending-review',
			)
		);
	}

	/**
	 * Rules-tab URL focusing the plugin row (graduate-style prefill fragment).
	 */
	public static function review_rules_url( string $plugin_basename ): string {
		$proposal = Graduate::proposal_from_plugin( $plugin_basename );
		if ( null === $proposal ) {
			return Admin::screen_url( 'rules' );
		}
		return Graduate::rules_url( $proposal );
	}

	/**
	 * @param mixed $raw
	 * @return 'watch'|'deny'
	 */
	public static function sanitize_hold_mode( $raw ): string {
		$mode = sanitize_key( (string) $raw );
		return self::HOLD_DENY === $mode ? self::HOLD_DENY : self::HOLD_WATCH;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function hold_is_enabled( array $policy ): bool {
		return ! empty( $policy['newcomer_hold_enabled'] );
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return 'watch'|'deny'
	 */
	public static function hold_mode( array $policy ): string {
		return self::sanitize_hold_mode( $policy['newcomer_hold_mode'] ?? self::HOLD_WATCH );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function hold_is_pending( array $policy, string $basename ): bool {
		if ( ! self::hold_is_enabled( $policy ) ) {
			return false;
		}
		$basename = Plugin_Profile::sanitize_plugin( $basename );
		if ( '' === $basename ) {
			return false;
		}
		$pending = self::sanitize_pending( $policy['newcomer_hold_pending'] ?? array() );
		return isset( $pending[ $basename ] );
	}

	/**
	 * Hold applies when the feature is on, the plugin has no explicit Allow/Deny,
	 * and it has not been resolved (Allow/Deny) yet.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function hold_should_apply( array $policy, ?string $plugin_basename ): bool {
		if ( ! self::hold_is_enabled( $policy ) ) {
			return false;
		}
		$basename = Plugin_Profile::sanitize_plugin( (string) $plugin_basename );
		if ( '' === $basename ) {
			return false;
		}
		$known = self::sanitize_known( $policy['newcomer_hold_known'] ?? array() );
		if ( in_array( $basename, $known, true ) ) {
			return false;
		}
		$rules = is_array( $policy['plugins'] ?? null ) ? (array) $policy['plugins'] : array();
		if ( isset( $rules[ $basename ] ) ) {
			$rule = (string) $rules[ $basename ];
			if ( 'allow' === $rule || 'deny' === $rule ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function should_deny_hold( array $policy, ?string $plugin_basename ): bool {
		if ( ! self::hold_should_apply( $policy, $plugin_basename ) ) {
			return false;
		}
		return self::HOLD_DENY === self::hold_mode( $policy );
	}

	/**
	 * Tag the live AI Client event, persist first-call pending, email once per 24h.
	 *
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 * @return array{active:bool,prevent:bool,reason:string,emailed:bool,first:bool}
	 */
	public static function apply_to_event( array &$event, array $policy, ?int $now = null, bool $persist = true ): array {
		$empty = array(
			'active'   => false,
			'prevent'  => false,
			'reason'   => '',
			'emailed'  => false,
			'first'    => false,
		);
		if ( class_exists( Selftest::class ) && Selftest::is_synthetic_row( $event ) ) {
			return $empty;
		}
		$plugin = isset( $event['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $event['plugin'] ) : '';
		if ( ! self::hold_should_apply( $policy, $plugin ) ) {
			return $empty;
		}

		$now    = null !== $now && $now > 0 ? (int) $now : ( isset( $event['ts'] ) ? (int) $event['ts'] : time() );
		$result = self::mark_first_ai_call( $policy, $plugin, $now );
		$policy = $result['policy'];

		$event['first_seen_hold'] = true;
		$prevent                  = self::HOLD_DENY === self::hold_mode( $policy );
		if ( $prevent ) {
			$event['newcomer_hold'] = self::HOLD_DENY;
		}

		$emailed = false;
		if ( self::should_send_hold_email( $policy, $plugin, $now ) ) {
			$emailed = self::send_hold_email( $policy, $plugin );
			if ( $emailed ) {
				$policy['newcomer_hold_email_at'][ $plugin ] = $now;
				$result['changed']                           = true;
			}
		}

		if ( $persist && ! empty( $result['changed'] ) ) {
			Policy::save_policy( $policy );
		}

		return array(
			'active'   => true,
			'prevent'  => $prevent,
			'reason'   => $prevent ? self::REASON : '',
			'emailed'  => $emailed,
			'first'    => ! empty( $result['first'] ),
			'policy'   => $policy,
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array{policy:array<string,mixed>,changed:bool,first:bool}
	 */
	public static function mark_first_ai_call( array $policy, string $basename, ?int $now = null ): array {
		$policy   = self::normalize_policy( $policy );
		$basename = Plugin_Profile::sanitize_plugin( $basename );
		$now      = null !== $now ? (int) $now : time();
		if ( '' === $basename || ! self::hold_is_enabled( $policy ) ) {
			return array(
				'policy'  => $policy,
				'changed' => false,
				'first'   => false,
			);
		}
		if ( isset( $policy['newcomer_hold_pending'][ $basename ] ) ) {
			return array(
				'policy'  => $policy,
				'changed' => false,
				'first'   => false,
			);
		}
		$policy['newcomer_hold_pending'][ $basename ] = $now;
		return array(
			'policy'  => $policy,
			'changed' => true,
			'first'   => true,
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function should_send_hold_email( array $policy, string $basename, int $now ): bool {
		$sent = self::sanitize_pending( $policy['newcomer_hold_email_at'] ?? array() );
		if ( ! isset( $sent[ $basename ] ) ) {
			return true;
		}
		return ( $now - (int) $sent[ $basename ] ) >= DAY_IN_SECONDS;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function send_hold_email( array $policy, string $plugin ): bool {
		if ( ! class_exists( Alerts::class ) ) {
			return false;
		}
		$to = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return false;
		}
		$label   = self::plugin_label( $plugin );
		$site    = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$subject = sprintf(
			/* translators: 1: site name, 2: plugin name */
			__( '[%1$s] HandL: Review AI access for %2$s', 'handl-ai-connector-access-control' ),
			$site,
			$label
		);
		$lines   = array();
		$lines[] = sprintf(
			/* translators: %s: plugin display name */
			__( '%s tried to use AI. Review its access.', 'handl-ai-connector-access-control' ),
			$label
		);
		$lines[] = '';
		$lines[] = __( 'Allow:', 'handl-ai-connector-access-control' );
		$lines[] = self::hold_action_url( self::ACTION_ALLOW, $plugin );
		$lines[] = __( 'Deny:', 'handl-ai-connector-access-control' );
		$lines[] = self::hold_action_url( self::ACTION_DENY, $plugin );
		$lines[] = self::hold_ack_is_dismiss( $policy )
			? __( 'Dismiss notice:', 'handl-ai-connector-access-control' )
			: __( 'Keep watching:', 'handl-ai-connector-access-control' );
		$lines[] = self::hold_action_url( self::ACTION_WATCH, $plugin );
		if ( self::hold_ack_is_dismiss( $policy ) ) {
			$lines[] = __( 'Dismissing this notice does not change access.', 'handl-ai-connector-access-control' );
		}
		$body    = implode( "\n", $lines ) . "\n";
		return Alerts::safe_wp_mail( $to, $subject, $body );
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array<string,mixed>
	 */
	public static function clear_hold( array $policy, string $basename ): array {
		$policy   = self::normalize_policy( $policy );
		$basename = Plugin_Profile::sanitize_plugin( $basename );
		if ( '' === $basename ) {
			return $policy;
		}
		$was_pending = isset( $policy['newcomer_hold_pending'][ $basename ] );
		unset(
			$policy['newcomer_hold_pending'][ $basename ],
			$policy['newcomer_hold_email_at'][ $basename ],
			$policy['newcomer_hold_watch_ack'][ $basename ]
		);
		$known = self::sanitize_known( $policy['newcomer_hold_known'] ?? array() );
		if ( $was_pending && ! in_array( $basename, $known, true ) ) {
			$known[] = $basename;
		}
		if ( $was_pending || self::policy_has_hold_keys( $policy ) ) {
			$policy['newcomer_hold_known'] = $known;
		}
		return $policy;
	}

	/**
	 * Allow / Deny writes a stored plugin rule and clears the hold.
	 * The watch action stores only the ack (notice dismiss); access is unchanged.
	 *
	 * @param array<string,mixed>|null $policy
	 * @return array<string,mixed>
	 */
	public static function resolve_hold( string $action, string $basename, ?array $policy = null, ?int $now = null, bool $persist = true ): array {
		$action   = sanitize_key( $action );
		$basename = Plugin_Profile::sanitize_plugin( $basename );
		$policy   = self::normalize_policy( is_array( $policy ) ? $policy : Policy::get_policy() );
		$now      = null !== $now ? (int) $now : time();
		if ( '' === $basename ) {
			return $policy;
		}

		if ( 'watch' === $action ) {
			$policy['newcomer_hold_watch_ack'][ $basename ] = $now;
			if ( $persist ) {
				Policy::save_policy( $policy );
			}
			return $policy;
		}

		if ( 'allow' === $action || 'deny' === $action ) {
			$plugins              = is_array( $policy['plugins'] ?? null ) ? (array) $policy['plugins'] : array();
			$plugins[ $basename ] = $action;
			$policy['plugins']    = $plugins;
			$policy               = self::clear_review( $policy, $basename );
			if ( $persist ) {
				Policy::save_policy( $policy );
			}
			return $policy;
		}

		return $policy;
	}

	/**
	 * Pending hold plugins whose review notice has not been acknowledged.
	 *
	 * @param array<string,mixed> $policy
	 * @return list<string>
	 */
	public static function hold_notice_plugins( array $policy ): array {
		if ( ! self::hold_is_enabled( $policy ) ) {
			return array();
		}
		$pending = self::sanitize_pending( $policy['newcomer_hold_pending'] ?? array() );
		$acked   = self::sanitize_pending( $policy['newcomer_hold_watch_ack'] ?? array() );
		$out     = array();
		foreach ( array_keys( $pending ) as $basename ) {
			if ( ! isset( $acked[ $basename ] ) ) {
				$out[] = $basename;
			}
		}
		sort( $out );
		return $out;
	}

	public function maybe_hold_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$policy  = Policy::get_policy();
		$pending = self::hold_notice_plugins( $policy );
		if ( empty( $pending ) ) {
			return;
		}
		$plugins = function_exists( 'get_plugins' ) ? get_plugins() : array();
		echo '<div class="notice notice-warning"><p>';
		foreach ( $pending as $i => $basename ) {
			$label = isset( $plugins[ $basename ]['Name'] ) ? (string) $plugins[ $basename ]['Name'] : $basename;
			if ( $i > 0 ) {
				echo '</p><p>';
			}
			echo esc_html(
				sprintf(
					/* translators: %s: plugin display name */
					__( '%s tried to use AI. Review its access.', 'handl-ai-connector-access-control' ),
					$label
				)
			);
			echo ' ';
			self::echo_hold_action_button( self::ACTION_ALLOW, $basename, __( 'Allow', 'handl-ai-connector-access-control' ) );
			echo ' ';
			self::echo_hold_action_button( self::ACTION_DENY, $basename, __( 'Deny', 'handl-ai-connector-access-control' ) );
			echo ' ';
			self::echo_hold_action_button( self::ACTION_WATCH, $basename, self::hold_ack_label( $policy ) );
			if ( self::hold_ack_is_dismiss( $policy ) ) {
				echo '</p><p class="description">';
				echo esc_html__( 'Dismissing this notice does not change access.', 'handl-ai-connector-access-control' );
			}
		}
		echo '</p></div>';
	}

	/**
	 * Watch mode keeps "Keep watching". Block mode labels the same ack as dismiss.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function hold_ack_is_dismiss( array $policy ): bool {
		return self::HOLD_DENY === self::hold_mode( $policy );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function hold_ack_label( array $policy ): string {
		if ( self::hold_ack_is_dismiss( $policy ) ) {
			return __( 'Dismiss notice', 'handl-ai-connector-access-control' );
		}
		return __( 'Keep watching', 'handl-ai-connector-access-control' );
	}

	private static function echo_hold_action_button( string $action, string $plugin, string $label ): void {
		$admin_post = function_exists( 'admin_url' ) ? admin_url( 'admin-post.php' ) : 'admin-post.php';
		echo '<form method="post" action="' . esc_url( $admin_post ) . '" style="display:inline">';
		echo '<input type="hidden" name="action" value="' . esc_attr( $action ) . '" />';
		echo '<input type="hidden" name="plugin" value="' . esc_attr( $plugin ) . '" />';
		echo '<input type="hidden" name="_wpnonce" value="' . esc_attr( wp_create_nonce( $action ) ) . '" />';
		echo '<button type="submit" class="button button-small">' . esc_html( $label ) . '</button>';
		echo '</form>';
	}

	public static function hold_action_url( string $action, string $plugin ): string {
		$admin_post = function_exists( 'admin_url' ) ? admin_url( 'admin-post.php' ) : 'admin-post.php';
		$args       = array(
			'action'   => $action,
			'plugin'   => $plugin,
			'_wpnonce' => wp_create_nonce( $action ),
		);
		return $admin_post . '?' . http_build_query( $args );
	}

	public function handle_hold_allow(): void {
		self::handle_hold_action( 'allow' );
	}

	public function handle_hold_deny(): void {
		self::handle_hold_action( 'deny' );
	}

	public function handle_hold_watch(): void {
		self::handle_hold_action( 'watch' );
	}

	private static function handle_hold_action( string $action ): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You cannot change this rule.', 'handl-ai-connector-access-control' ), '', array( 'response' => 403 ) );
		}
		$hook = 'allow' === $action ? self::ACTION_ALLOW : ( 'deny' === $action ? self::ACTION_DENY : self::ACTION_WATCH );
		check_admin_referer( $hook );
		$plugin = isset( $_REQUEST['plugin'] ) ? sanitize_text_field( wp_unslash( (string) $_REQUEST['plugin'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		self::resolve_hold( $action, $plugin );
		if ( function_exists( 'wp_safe_redirect' ) ) {
			$to = function_exists( 'wp_get_referer' ) ? wp_get_referer() : '';
			wp_safe_redirect( is_string( $to ) && '' !== $to ? $to : admin_url() );
			exit;
		}
	}

	/**
	 * @param mixed $value New option value.
	 * @param mixed $old   Previous option value.
	 * @return mixed
	 */
	public static function merge_hold_on_policy_save( $value, $old ) {
		if ( ! is_array( $value ) ) {
			return $value;
		}
		$posted = isset( $_POST[ self::POST_HOLD_PRESENT ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Admin save already verified the form nonce.
		if ( $posted ) {
			$value['newcomer_hold_enabled'] = ! empty( $_POST[ self::POST_HOLD_ENABLED ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$value['newcomer_hold_mode']    = self::sanitize_hold_mode( $_POST[ self::POST_HOLD_MODE ] ?? self::HOLD_WATCH ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
		} elseif ( is_array( $old ) ) {
			if ( array_key_exists( 'newcomer_hold_enabled', $old ) ) {
				$value['newcomer_hold_enabled'] = ! empty( $old['newcomer_hold_enabled'] );
			}
			if ( array_key_exists( 'newcomer_hold_mode', $old ) ) {
				$value['newcomer_hold_mode'] = self::sanitize_hold_mode( $old['newcomer_hold_mode'] );
			}
		}
		if ( is_array( $old ) ) {
			foreach ( array( 'newcomer_hold_known', 'newcomer_hold_pending', 'newcomer_hold_email_at', 'newcomer_hold_watch_ack' ) as $key ) {
				if ( array_key_exists( $key, $old ) && ! array_key_exists( $key, $value ) ) {
					$value[ $key ] = $old[ $key ];
				}
			}
		}
		return $value;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public function render_hold_settings( $policy ): void {
		$policy  = is_array( $policy ) ? $policy : array();
		$enabled = self::hold_is_enabled( $policy );
		$mode    = self::hold_mode( $policy );

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Review new AI activity', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<input type="hidden" name="' . esc_attr( self::POST_HOLD_PRESENT ) . '" value="1" />';
		echo '<label>';
		echo '<input type="checkbox" name="' . esc_attr( self::POST_HOLD_ENABLED ) . '" value="1"' . ( $enabled ? ' checked="checked"' : '' ) . ' /> ';
		echo esc_html__( 'Ask me to review AI activity from plugins without an Allow or Deny rule', 'handl-ai-connector-access-control' );
		echo '</label>';
		echo '<p><label for="handl-aicac-newcomer-hold-mode">' . esc_html__( 'While awaiting review', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<select name="' . esc_attr( self::POST_HOLD_MODE ) . '" id="handl-aicac-newcomer-hold-mode">';
		echo '<option value="' . esc_attr( self::HOLD_WATCH ) . '"' . ( self::HOLD_WATCH === $mode ? ' selected="selected"' : '' ) . '>' . esc_html__( 'Watch (ask without adding a block)', 'handl-ai-connector-access-control' ) . '</option>';
		echo '<option value="' . esc_attr( self::HOLD_DENY ) . '"' . ( self::HOLD_DENY === $mode ? ' selected="selected"' : '' ) . '>' . esc_html__( 'Block (block until reviewed)', 'handl-ai-connector-access-control' ) . '</option>';
		echo '</select></p>';
		echo '<p class="description">' . esc_html__( 'Off by default. Plugins with an Allow or Deny rule are skipped. Other safeguards still apply. Learn mode does not block calls.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td>';
		echo '</tr>';
	}

	public static function plugin_label( string $basename ): string {
		if ( function_exists( 'get_plugins' ) ) {
			$plugins = get_plugins();
			if ( isset( $plugins[ $basename ]['Name'] ) && is_string( $plugins[ $basename ]['Name'] ) ) {
				return (string) $plugins[ $basename ]['Name'];
			}
		}
		return $basename;
	}
}

/**
 * WP-CLI: wp handl-aicac newcomer status|allow|deny.
 *
 * @when after_wp_load
 */
final class CLI_Newcomer {

	public static function register(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac newcomer', self::class );
	}

	/**
	 * Show newcomer-hold status for one plugin (or all pending).
	 *
	 * ## OPTIONS
	 *
	 * [<plugin>]
	 * : Plugin basename (e.g. acme/acme.php). Omit to list pending holds.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac newcomer status
	 *     wp handl-aicac newcomer status acme/acme.php
	 *
	 * @subcommand status
	 *
	 * @param array<int,string> $args
	 */
	public function status( $args, $assoc_args ): void {
		unset( $assoc_args );
		$policy = Policy::get_policy();
		$plugin = Plugin_Profile::sanitize_plugin( isset( $args[0] ) ? (string) $args[0] : '' );
		if ( '' !== $plugin ) {
			$held = New_Plugin::hold_should_apply( $policy, $plugin );
			\WP_CLI::log(
				sprintf(
					'%s: enabled=%s mode=%s held=%s pending=%s',
					$plugin,
					New_Plugin::hold_is_enabled( $policy ) ? 'yes' : 'no',
					New_Plugin::hold_mode( $policy ),
					$held ? 'yes' : 'no',
					New_Plugin::hold_is_pending( $policy, $plugin ) ? 'yes' : 'no'
				)
			);
			return;
		}
		$pending = array_keys( New_Plugin::sanitize_pending( $policy['newcomer_hold_pending'] ?? array() ) );
		sort( $pending );
		if ( empty( $pending ) ) {
			\WP_CLI::log( 'No plugins on first-AI-call hold.' );
			return;
		}
		foreach ( $pending as $basename ) {
			\WP_CLI::log( $basename );
		}
	}

	/**
	 * Allow a plugin and clear the first-AI-call hold.
	 *
	 * ## OPTIONS
	 *
	 * <plugin>
	 * : Plugin basename.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac newcomer allow acme/acme.php
	 *
	 * @subcommand allow
	 *
	 * @param array<int,string> $args
	 */
	public function allow( $args, $assoc_args ): void {
		unset( $assoc_args );
		self::cmd_resolve( 'allow', $args );
	}

	/**
	 * Deny a plugin and clear the first-AI-call hold.
	 *
	 * ## OPTIONS
	 *
	 * <plugin>
	 * : Plugin basename.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac newcomer deny acme/acme.php
	 *
	 * @subcommand deny
	 *
	 * @param array<int,string> $args
	 */
	public function deny( $args, $assoc_args ): void {
		unset( $assoc_args );
		self::cmd_resolve( 'deny', $args );
	}

	/**
	 * @param array<int,string> $args
	 */
	private static function cmd_resolve( string $action, array $args ): void {
		$plugin = Plugin_Profile::sanitize_plugin( isset( $args[0] ) ? (string) $args[0] : '' );
		if ( '' === $plugin ) {
			\WP_CLI::error( 'Need a plugin basename like acme/acme.php.' );
		}
		New_Plugin::resolve_hold( $action, $plugin );
		\WP_CLI::success( sprintf( '%s %s.', $plugin, $action ) );
	}
}
