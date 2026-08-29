<?php
/**
 * AICAC-NEWPLUGIN: review-first mode for newly installed/activated plugins (#141).
 *
 * Optional setting (off by default). When on, a plugin first seen after enablement
 * gets a needs-review state: interim Deny or Observe-only until an admin chooses
 * Allow or Deny. Plugins present at enablement are grandfathered.
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

	private static ?New_Plugin $instance = null;

	public static function instance(): New_Plugin {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function init(): void {
		add_action( 'activated_plugin', array( $this, 'on_activated_plugin' ), 10, 2 );
		if ( is_admin() ) {
			add_action( 'admin_notices', array( $this, 'maybe_admin_notice' ) );
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
		return $policy;
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
			}
		}
		return $policy;
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
}
