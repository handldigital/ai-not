<?php
/**
 * AICAC-TRIPWIRE (#497): real-secret egress guard.
 *
 * Default deny + alert (reason tripwire) when an outbound payload contains
 * this site's own secrets: wp-config DB password / AUTH_KEY+SALT family,
 * and Keyscan-inventoried provider keys (read-only). Per-plugin warn
 * override allows the call but still logs + alerts. Digest set is
 * request-local and never persisted. Logs secret KIND + count only.
 *
 * README-FREE. Own admin surface. Zero keyscan.php / admin.php / readme.txt.
 * Policy.php is the same three call-sites PII-WARN / Taint use.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hash-screen outbound payloads against live site secrets.
 */
final class Tripwire {

	public const MODE_WARN = 'warn';
	public const MODE_DENY = 'deny';

	public const KIND_DB       = 'db-password';
	public const KIND_AUTH     = 'auth-salt';
	public const KIND_PROVIDER = 'provider-key';

	public const REASON = 'tripwire';

	public const CHANNEL = 'tripwire';

	public const FILTER = 'handl_aicac_tripwire_secrets';

	public const PAGE_SLUG = 'handl-aicac-tripwire';

	public const ACTION_SAVE = 'handl_aicac_tripwire_save';

	public const PREFIX_LEN = 12;

	/** @var bool */
	private static $registered = false;

	/**
	 * Request-local digest. Never persisted.
	 *
	 * @var list<array{kind:string,exact:string,prefix:?string,needle:string,prefix_needle:?string}>|null
	 */
	private static $digest = null;

	/** @var int */
	private static $builds = 0;

	/**
	 * Test override: list of {kind,value}. Null = collect live.
	 *
	 * @var list<array{kind:string,value:string}>|null
	 */
	private static $test_secrets = null;

	/**
	 * @return list<string>
	 */
	public static function all_kinds(): array {
		return array(
			self::KIND_DB,
			self::KIND_AUTH,
			self::KIND_PROVIDER,
		);
	}

	/**
	 * wp-config constants → kind.
	 *
	 * @return array<string,string>
	 */
	public static function wp_config_constants(): array {
		return array(
			'DB_PASSWORD'        => self::KIND_DB,
			'AUTH_KEY'           => self::KIND_AUTH,
			'SECURE_AUTH_KEY'    => self::KIND_AUTH,
			'LOGGED_IN_KEY'      => self::KIND_AUTH,
			'NONCE_KEY'          => self::KIND_AUTH,
			'AUTH_SALT'          => self::KIND_AUTH,
			'SECURE_AUTH_SALT'   => self::KIND_AUTH,
			'LOGGED_IN_SALT'     => self::KIND_AUTH,
			'NONCE_SALT'         => self::KIND_AUTH,
		);
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_mode( $raw ): string {
		$mode = sanitize_key( (string) $raw );
		if ( self::MODE_WARN === $mode ) {
			return self::MODE_WARN;
		}

		return self::MODE_DENY;
	}

	/**
	 * Per-plugin warn overrides. Absent / deny → omitted (treated as deny).
	 *
	 * @param mixed $raw
	 * @return array<string,string> plugin => warn
	 */
	public static function sanitize_plugin_modes( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $plugin => $mode ) {
			$plugin = self::sanitize_plugin( (string) $plugin );
			if ( '' === $plugin ) {
				continue;
			}
			if ( self::MODE_WARN !== self::sanitize_mode( $mode ) ) {
				continue;
			}
			$out[ $plugin ] = self::MODE_WARN;
		}

		return $out;
	}

	/**
	 * Default deny. Warn only when the policy map says so.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function mode_for_plugin( array $policy, ?string $plugin ): string {
		$plugin = self::sanitize_plugin( (string) $plugin );
		if ( '' === $plugin ) {
			return self::MODE_DENY;
		}
		$map = self::sanitize_plugin_modes( $policy['tripwire_screen'] ?? array() );

		return isset( $map[ $plugin ] ) ? self::MODE_WARN : self::MODE_DENY;
	}

	/**
	 * @param list<array{kind?:string,value?:string}> $rows
	 */
	public static function set_test_secrets( array $rows ): void {
		$clean = array();
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$kind  = self::sanitize_kind( (string) ( $row['kind'] ?? '' ) );
			$value = (string) ( $row['value'] ?? '' );
			if ( '' === $kind || ! self::usable_secret( $value ) ) {
				continue;
			}
			$clean[] = array(
				'kind'  => $kind,
				'value' => $value,
			);
		}
		self::$test_secrets = $clean;
		self::$digest       = null;
	}

	public static function digest_build_count(): int {
		return self::$builds;
	}

	/**
	 * Screen text. Returns kind => count. Never includes secret values.
	 *
	 * @return array<string,int>
	 */
	public static function screen( string $text ): array {
		if ( '' === $text ) {
			return array();
		}
		$counts = array();
		foreach ( self::digest_set() as $row ) {
			$hit = false;
			if ( false !== strpos( $text, $row['needle'] )
				&& hash_equals( $row['exact'], self::hmac( $row['needle'] ) ) ) {
				$hit = true;
			} elseif ( is_string( $row['prefix_needle'] ) && is_string( $row['prefix'] )
				&& false !== strpos( $text, $row['prefix_needle'] )
				&& hash_equals( $row['prefix'], self::hmac( $row['prefix_needle'] ) ) ) {
				$hit = true;
			}
			if ( $hit ) {
				$kind = $row['kind'];
				$counts[ $kind ] = ( $counts[ $kind ] ?? 0 ) + 1;
			}
		}

		return $counts;
	}

	/**
	 * Replace matched secrets with kind tokens so logged previews cannot leak.
	 */
	public static function redact( string $text ): string {
		if ( '' === $text ) {
			return $text;
		}
		$rows = self::digest_set();
		usort(
			$rows,
			static function ( $a, $b ) {
				return strlen( $b['needle'] ) <=> strlen( $a['needle'] );
			}
		);
		foreach ( $rows as $row ) {
			$token = '[redacted-' . $row['kind'] . ']';
			$text  = str_replace( $row['needle'], $token, $text );
			if ( is_string( $row['prefix_needle'] ) && $row['prefix_needle'] !== $row['needle'] ) {
				$text = str_replace( $row['prefix_needle'], $token, $text );
			}
		}

		return $text;
	}

	/**
	 * Apply screen to an Activity event. Mutates $event (tripwire_match, redacted preview).
	 *
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 * @param mixed               $builder Optional builder for full-text screen.
	 * @return array{active:bool,prevent:bool,mode:string,matches:array<string,int>}
	 */
	public static function apply_to_event( array &$event, array $policy, $builder = null ): array {
		$plugin = isset( $event['plugin'] ) ? (string) $event['plugin'] : '';
		$mode   = self::mode_for_plugin( $policy, $plugin );

		$text = self::payload_text( $builder );
		if ( '' === $text && isset( $event['prompt_preview'] ) && is_string( $event['prompt_preview'] ) ) {
			$text = (string) $event['prompt_preview'];
		}
		if ( '' === $text ) {
			return array(
				'active'  => true,
				'prevent' => false,
				'mode'    => $mode,
				'matches' => array(),
			);
		}

		$matches = self::screen( $text );
		if ( empty( $matches ) ) {
			return array(
				'active'  => true,
				'prevent' => false,
				'mode'    => $mode,
				'matches' => array(),
			);
		}

		if ( isset( $event['prompt_preview'] ) && is_string( $event['prompt_preview'] ) ) {
			$event['prompt_preview'] = self::redact( (string) $event['prompt_preview'] );
		}

		$event['tripwire_match'] = array(
			'kinds' => $matches,
			'mode'  => $mode,
		);

		return array(
			'active'  => true,
			'prevent' => ( self::MODE_DENY === $mode ),
			'mode'    => $mode,
			'matches' => $matches,
		);
	}

	/**
	 * Alert after the row is retained. Never embeds secret values.
	 *
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 * @return array{alerted:bool,reason:string}
	 */
	public static function maybe_alert( array $event, array $policy ): array {
		$match = isset( $event['tripwire_match'] ) && is_array( $event['tripwire_match'] ) ? $event['tripwire_match'] : null;
		if ( null === $match ) {
			return array( 'alerted' => false, 'reason' => 'no_match' );
		}

		$channel = isset( $event['channel'] ) ? (string) $event['channel'] : '';
		if ( self::CHANNEL === $channel ) {
			return array( 'alerted' => false, 'reason' => 'skip_channel' );
		}

		$kinds = isset( $match['kinds'] ) && is_array( $match['kinds'] ) ? $match['kinds'] : array();
		$kinds = self::sanitize_match_kinds( $kinds );
		if ( empty( $kinds ) ) {
			return array( 'alerted' => false, 'reason' => 'empty_kinds' );
		}

		$plugin = isset( $event['plugin'] ) ? self::sanitize_plugin( (string) $event['plugin'] ) : '';
		$ts     = isset( $event['ts'] ) ? (int) $event['ts'] : time();
		if ( $ts <= 0 ) {
			$ts = time();
		}

		if ( class_exists( Quiet_Hours::class, false ) && null !== Quiet_Hours::active_window( $policy, $ts ) ) {
			return array( 'alerted' => false, 'reason' => 'quiet_hours' );
		}

		if ( '' !== $plugin && class_exists( Alert_Snooze::class, false ) && Alert_Snooze::should_suppress( $plugin, self::CHANNEL, $ts ) ) {
			return array( 'alerted' => false, 'reason' => 'suppressed' );
		}

		if ( ! class_exists( Alerts::class, false ) ) {
			return array( 'alerted' => false, 'reason' => 'no_alerts' );
		}

		$to = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return array( 'alerted' => false, 'reason' => 'no_recipient' );
		}

		$mode    = self::sanitize_mode( $match['mode'] ?? '' );
		$subject = self::build_subject( $plugin );
		$body    = self::build_body( $plugin, $kinds, $mode );
		$ok      = Alerts::safe_wp_mail( $to, $subject, $body );

		$webhook = isset( $policy['alert_webhook_url'] ) ? Alerts::sanitize_webhook_url( (string) $policy['alert_webhook_url'] ) : '';
		if ( '' !== $webhook ) {
			$hook_ok = Alerts::safe_wp_remote_post(
				$webhook,
				array(
					'type'   => 'handl_aicac_tripwire',
					'plugin' => $plugin,
					'mode'   => $mode,
					'kinds'  => $kinds,
					'site'   => function_exists( 'home_url' ) ? home_url( '/' ) : '',
				),
				'tripwire'
			);
			$ok = $ok || $hook_ok;
		}

		if ( ! $ok ) {
			return array( 'alerted' => false, 'reason' => 'delivery_failed' );
		}

		return array( 'alerted' => true, 'reason' => 'alerted' );
	}

	/**
	 * @param array<string,mixed> $kinds
	 * @return array<string,int>
	 */
	public static function sanitize_match_kinds( array $kinds ): array {
		$allowed = array_fill_keys( self::all_kinds(), true );
		$out     = array();
		foreach ( $kinds as $kind => $count ) {
			$kind = self::sanitize_kind( (string) $kind );
			if ( ! isset( $allowed[ $kind ] ) ) {
				continue;
			}
			$count = (int) $count;
			if ( $count > 0 ) {
				$out[ $kind ] = $count;
			}
		}

		return $out;
	}

	public static function kind_label( string $kind ): string {
		$map = array(
			self::KIND_DB       => __( 'Database password', 'handl-ai-connector-access-control' ),
			self::KIND_AUTH     => __( 'Authentication key', 'handl-ai-connector-access-control' ),
			self::KIND_PROVIDER => __( 'Provider API key', 'handl-ai-connector-access-control' ),
		);
		$kind = self::sanitize_kind( $kind );

		return $map[ $kind ] ?? $kind;
	}

	/**
	 * Receipt line: secret kinds only, never values.
	 *
	 * @param array<string,int> $kinds
	 */
	public static function receipt_summary( array $kinds ): string {
		$kinds = self::sanitize_match_kinds( $kinds );
		if ( empty( $kinds ) ) {
			return '';
		}
		$parts = array();
		foreach ( $kinds as $kind => $count ) {
			$parts[] = sprintf( '%s (%d)', self::kind_label( $kind ), (int) $count );
		}

		return implode( ', ', $parts );
	}

	public static function build_subject( string $plugin ): string {
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$label = self::plugin_label( $plugin );

		return sprintf(
			/* translators: 1: site name, 2: plugin label */
			__( '[%1$s] Site secret detected in an AI call by %2$s', 'handl-ai-connector-access-control' ),
			$site,
			$label
		);
	}

	/**
	 * @param array<string,int> $kinds
	 */
	public static function build_body( string $plugin, array $kinds, string $mode ): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control found a site secret in this plugin\'s AI request.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: plugin basename or label */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			self::plugin_label( $plugin )
		);
		if ( self::MODE_WARN === self::sanitize_mode( $mode ) ) {
			$lines[] = __( 'Screen result: Warn (this check did not block the request).', 'handl-ai-connector-access-control' );
		} else {
			$lines[] = __( 'Screen result: Deny (this check blocked the request).', 'handl-ai-connector-access-control' );
		}
		$lines[] = __( 'Secret types and counts (values are not included in this alert):', 'handl-ai-connector-access-control' );
		$summary = self::receipt_summary( $kinds );
		if ( '' !== $summary ) {
			$lines[] = $summary;
		}
		$lines[] = '';
		$lines[] = __( 'A site secret in an AI prompt is never legitimate. Secret values are never stored.', 'handl-ai-connector-access-control' );

		return implode( "\n", $lines );
	}

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
	}

	public static function reset_for_tests(): void {
		self::$registered   = false;
		self::$digest       = null;
		self::$builds       = 0;
		self::$test_secrets = null;
	}

	public static function register_menu(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) || ! class_exists( Admin::class, false ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Secret tripwire', 'handl-ai-connector-access-control' ),
			__( 'Secret tripwire', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		$policy     = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		$modes      = self::sanitize_plugin_modes( $policy['tripwire_screen'] ?? array() );
		$can_manage = class_exists( Caps::class, false ) && Caps::user_can_manage();
		$plugins    = self::candidate_plugins( $policy );

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Secret tripwire', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Block AI requests that include this site\'s own secrets: the database password, authentication keys, and stored provider API keys. On by default.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p class="description">' . esc_html__( 'This check does not save secret values. Alerts name the secret type only.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<p>' . esc_html__( 'Secret tripwire is on. Matching requests are blocked.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( empty( $plugins ) ) {
			echo '<p>' . esc_html__( 'No plugins are available yet.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
		}

		echo '<table class="widefat striped" style="max-width:52em;"><thead><tr>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Screen', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $plugins as $basename => $label ) {
			$current = $modes[ $basename ] ?? self::MODE_DENY;
			echo '<tr><td>' . esc_html( $label ) . '<br /><code>' . esc_html( $basename ) . '</code></td><td>';
			if ( $can_manage ) {
				echo '<select name="handl_aicac_tripwire_modes[' . esc_attr( $basename ) . ']">';
				foreach ( self::mode_choices() as $value => $choice_label ) {
					$sel = ( $current === $value ) ? ' selected="selected"' : '';
					echo '<option value="' . esc_attr( $value ) . '"' . $sel . '>' . esc_html( $choice_label ) . '</option>';
				}
				echo '</select>';
			} else {
				echo esc_html( self::mode_choices()[ $current ] ?? $current );
			}
			echo '</td></tr>';
		}
		echo '</tbody></table>';
		echo '<p class="description">' . esc_html__( 'Deny blocks the request. Warn records the secret type and still allows the call. Other rules still apply.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			if ( function_exists( 'submit_button' ) ) {
				submit_button( __( 'Save tripwire', 'handl-ai-connector-access-control' ) );
			} else {
				echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Save tripwire', 'handl-ai-connector-access-control' ) . '</button></p>';
			}
			echo '</form>';
		}

		echo '</div>';
	}

	public static function handle_save(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_manage() ) {
			self::die_forbidden();
		}
		if ( function_exists( 'check_admin_referer' ) ) {
			check_admin_referer( self::ACTION_SAVE );
		}
		$raw   = isset( $_POST['handl_aicac_tripwire_modes'] ) && is_array( $_POST['handl_aicac_tripwire_modes'] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing
			? wp_unslash( $_POST['handl_aicac_tripwire_modes'] ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			: array();
		$modes = self::sanitize_plugin_modes( is_array( $raw ) ? $raw : array() );

		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' ) && method_exists( Policy::class, 'save_policy' ) ) {
			$policy                    = Policy::get_policy();
			$policy['tripwire_screen'] = $modes;
			Policy::save_policy( $policy );
		}

		self::redirect();
	}

	/**
	 * Request-local hashed digest. Built once, lazily. Never persisted.
	 *
	 * @return list<array{kind:string,exact:string,prefix:?string,needle:string,prefix_needle:?string}>
	 */
	private static function digest_set(): array {
		if ( is_array( self::$digest ) ) {
			return self::$digest;
		}

		++self::$builds;
		$secrets = null !== self::$test_secrets ? self::$test_secrets : self::collect_live_secrets();
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( self::FILTER, $secrets );
			if ( is_array( $filtered ) ) {
				$secrets = $filtered;
			}
		}

		$out  = array();
		$seen = array();
		foreach ( $secrets as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$kind  = self::sanitize_kind( (string) ( $row['kind'] ?? '' ) );
			$value = (string) ( $row['value'] ?? '' );
			if ( '' === $kind || ! self::usable_secret( $value ) ) {
				continue;
			}
			$exact = self::hmac( $value );
			if ( isset( $seen[ $exact ] ) ) {
				continue;
			}
			$seen[ $exact ] = true;
			$prefix_needle  = null;
			$prefix_hash    = null;
			if ( strlen( $value ) >= self::PREFIX_LEN ) {
				$prefix_needle = substr( $value, 0, self::PREFIX_LEN );
				$prefix_hash   = self::hmac( $prefix_needle );
			}
			$out[] = array(
				'kind'          => $kind,
				'exact'         => $exact,
				'prefix'        => $prefix_hash,
				'needle'        => $value,
				'prefix_needle' => $prefix_needle,
			);
		}

		self::$digest = $out;

		return self::$digest;
	}

	/**
	 * @return list<array{kind:string,value:string}>
	 */
	private static function collect_live_secrets(): array {
		$out = array();
		foreach ( self::wp_config_constants() as $const => $kind ) {
			if ( ! defined( $const ) ) {
				continue;
			}
			$value = (string) constant( $const );
			if ( ! self::usable_secret( $value ) ) {
				continue;
			}
			$out[] = array(
				'kind'  => $kind,
				'value' => $value,
			);
		}
		foreach ( self::collect_keyscan_secrets() as $value ) {
			$out[] = array(
				'kind'  => self::KIND_PROVIDER,
				'value' => $value,
			);
		}

		return $out;
	}

	/**
	 * Re-extract live Keyscan-inventoried keys (suffix match against stored findings).
	 * Read-only: never writes Keyscan state. Skips plugin file scans.
	 *
	 * @return list<string>
	 */
	private static function collect_keyscan_secrets(): array {
		if ( ! class_exists( Keyscan::class, false ) ) {
			return array();
		}
		if ( ! method_exists( Keyscan::class, 'scan_plugin_options' ) || ! method_exists( Keyscan::class, 'active_findings' ) ) {
			return array();
		}
		$findings = Keyscan::active_findings();
		if ( ! is_array( $findings ) || empty( $findings ) ) {
			return array();
		}
		$suffixes = array();
		$plugins  = array();
		foreach ( $findings as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$suf    = isset( $row['suffix'] ) ? (string) $row['suffix'] : '';
			$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			if ( '' !== $suf ) {
				$suffixes[ $suf ] = true;
			}
			if ( '' !== $plugin ) {
				$plugins[ $plugin ] = true;
			}
		}
		if ( empty( $plugins ) || empty( $suffixes ) ) {
			return array();
		}
		$keys = array();
		foreach ( array_keys( $plugins ) as $basename ) {
			$hits = Keyscan::scan_plugin_options( $basename );
			if ( ! is_array( $hits ) ) {
				continue;
			}
			foreach ( $hits as $hit ) {
				if ( ! is_array( $hit ) ) {
					continue;
				}
				$key = isset( $hit['key'] ) ? (string) $hit['key'] : '';
				if ( ! self::usable_secret( $key ) ) {
					continue;
				}
				$suf = method_exists( Keyscan::class, 'suffix_only' )
					? (string) Keyscan::suffix_only( $key )
					: substr( $key, -4 );
				if ( isset( $suffixes[ $suf ] ) ) {
					$keys[ $key ] = true;
				}
			}
		}

		return array_keys( $keys );
	}

	private static function hmac( string $value ): string {
		$salt = function_exists( 'wp_salt' ) ? (string) wp_salt( 'auth' ) : 'handl-aicac-tripwire';

		return hash_hmac( 'sha256', $value, $salt );
	}

	private static function usable_secret( string $value ): bool {
		$value = trim( $value );

		return strlen( $value ) >= 8;
	}

	private static function sanitize_kind( string $kind ): string {
		$kind = sanitize_key( $kind );
		$ok   = array_fill_keys( self::all_kinds(), true );

		return isset( $ok[ $kind ] ) ? $kind : '';
	}

	/**
	 * @return array<string,string>
	 */
	private static function mode_choices(): array {
		return array(
			self::MODE_DENY => __( 'Deny (default)', 'handl-ai-connector-access-control' ),
			self::MODE_WARN => __( 'Warn', 'handl-ai-connector-access-control' ),
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array<string,string>
	 */
	private static function candidate_plugins( array $policy ): array {
		$out = array();
		if ( function_exists( 'get_plugins' ) ) {
			foreach ( get_plugins() as $basename => $info ) {
				$plugin = self::sanitize_plugin( $basename );
				if ( '' === $plugin ) {
					continue;
				}
				$label          = is_array( $info ) && isset( $info['Name'] ) ? (string) $info['Name'] : $plugin;
				$out[ $plugin ] = '' !== $label ? $label : $plugin;
			}
		}
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] ) ? $policy['plugins'] : array();
		foreach ( array_keys( $plugins ) as $basename ) {
			$plugin = self::sanitize_plugin( (string) $basename );
			if ( '' !== $plugin && ! isset( $out[ $plugin ] ) ) {
				$out[ $plugin ] = $plugin;
			}
		}
		ksort( $out );

		return $out;
	}

	private static function payload_text( $builder ): string {
		if ( class_exists( Pii_Warn::class, false ) && method_exists( Pii_Warn::class, 'payload_text_from_builder' ) ) {
			return (string) Pii_Warn::payload_text_from_builder( $builder );
		}

		return '';
	}

	private static function plugin_label( string $plugin ): string {
		$plugin = self::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return __( '(unattributed)', 'handl-ai-connector-access-control' );
		}
		if ( function_exists( 'get_plugins' ) ) {
			$plugins = get_plugins();
			if ( isset( $plugins[ $plugin ]['Name'] ) ) {
				return (string) $plugins[ $plugin ]['Name'] . ' (' . $plugin . ')';
			}
		}

		return $plugin;
	}

	private static function sanitize_plugin( $raw ): string {
		if ( class_exists( Plugin_Profile::class, false ) && method_exists( Plugin_Profile::class, 'sanitize_plugin' ) ) {
			return Plugin_Profile::sanitize_plugin( $raw );
		}
		$plugin = sanitize_text_field( (string) $raw );

		return preg_match( '/^[A-Za-z0-9._\-]+(?:\/[A-Za-z0-9._\-]+)*\.php$/', $plugin ) ? $plugin : '';
	}

	private static function die_forbidden(): void {
		$message = __( 'You do not have permission to save these settings.', 'handl-ai-connector-access-control' );
		if ( function_exists( 'wp_die' ) ) {
			wp_die( esc_html( $message ) );
		}
	}

	private static function redirect(): void {
		$url = admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $url );
			exit;
		}
	}
}
