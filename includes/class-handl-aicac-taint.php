<?php
/**
 * AICAC-TAINT (#496): opt-in outbound payload injection screen.
 *
 * Per-plugin modes ride the policy option: off (default) / warn (log +
 * alert, allow) / deny (block with reason taint). Patterns are classes
 * (instruction-override, role-reassignment, exfil-bait, obfuscation),
 * not a blocklist of exact strings. Logs class + count only — never the
 * matched text.
 *
 * README-FREE. Own admin surface. Zero pii-warn.php / admin.php / readme.txt.
 * Policy.php is the same three call-sites PII-WARN uses.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Lightweight regex screen of outbound prompt/payload text for injection shapes.
 */
final class Taint {

	public const MODE_OFF  = 'off';
	public const MODE_WARN = 'warn';
	public const MODE_DENY = 'deny';

	public const CLASS_INSTRUCTION = 'instruction_override';
	public const CLASS_ROLE        = 'role_reassignment';
	public const CLASS_EXFIL       = 'exfil_bait';
	public const CLASS_OBFUSCATION = 'obfuscation';

	public const REASON = 'taint';

	public const CHANNEL = 'taint';

	public const FILTER = 'handl_aicac_taint_patterns';

	public const PAGE_SLUG = 'handl-aicac-taint';

	public const ACTION_SAVE = 'handl_aicac_taint_save';

	/** @var bool */
	private static $registered = false;

	/**
	 * @return list<string>
	 */
	public static function all_classes(): array {
		return array(
			self::CLASS_INSTRUCTION,
			self::CLASS_ROLE,
			self::CLASS_EXFIL,
			self::CLASS_OBFUSCATION,
		);
	}

	/**
	 * Bundled pattern table. Each class maps to a list of PCRE shapes.
	 * Filterable: `handl_aicac_taint_patterns`.
	 *
	 * @return array<string,list<string>>
	 */
	public static function pattern_table(): array {
		$table = array(
			self::CLASS_INSTRUCTION => array(
				'/(?:ignore|disregard|forget|override).{0,80}(?:instructions?|prompts?|rules?|guidelines?)/iu',
			),
			self::CLASS_ROLE        => array(
				'/(?:you\s+are\s+now|act\s+as(?:\s+if)?|pretend\s+to\s+be|from\s+now\s+on\s+you\s+are|your\s+new\s+role)\b/iu',
			),
			self::CLASS_EXFIL       => array(
				'/(?:repeat|print|reveal|output|dump|show|display).{0,60}(?:system\s+prompt|hidden\s+prompt|secret\s+instructions?|your\s+instructions?|your\s+guidelines?)/iu',
			),
			self::CLASS_OBFUSCATION => array(
				'/[\x{200B}\x{200C}\x{200D}\x{2060}\x{FEFF}\x{180E}]/u',
				'/\b(?=[A-Za-z]*[\x{0400}-\x{04FF}])(?=[\x{0400}-\x{04FF}]*[A-Za-z])[\x{0400}-\x{04FF}A-Za-z]{3,}\b/u',
			),
		);

		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( self::FILTER, $table );
			if ( is_array( $filtered ) ) {
				$table = $filtered;
			}
		}

		return self::sanitize_pattern_table( $table );
	}

	/**
	 * @param mixed $raw
	 * @return array<string,list<string>>
	 */
	public static function sanitize_pattern_table( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $class => $regexes ) {
			$class = sanitize_key( (string) $class );
			if ( '' === $class ) {
				continue;
			}
			if ( ! is_array( $regexes ) ) {
				continue;
			}
			$list = array();
			foreach ( $regexes as $rx ) {
				if ( ! is_string( $rx ) || '' === $rx ) {
					continue;
				}
				if ( false === @preg_match( $rx, '' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
					continue;
				}
				$list[] = $rx;
			}
			if ( ! empty( $list ) ) {
				$out[ $class ] = array_values( array_unique( $list ) );
			}
		}

		return $out;
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_mode( $raw ): string {
		$mode = sanitize_key( (string) $raw );
		if ( self::MODE_WARN === $mode || self::MODE_DENY === $mode ) {
			return $mode;
		}

		return self::MODE_OFF;
	}

	/**
	 * Per-plugin mode map. Absent / invalid / off → omitted (treated as off).
	 *
	 * @param mixed $raw
	 * @return array<string,string> plugin => warn|deny
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
			$mode = self::sanitize_mode( $mode );
			if ( self::MODE_OFF === $mode ) {
				continue;
			}
			$out[ $plugin ] = $mode;
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function mode_for_plugin( array $policy, ?string $plugin ): string {
		$plugin = self::sanitize_plugin( (string) $plugin );
		if ( '' === $plugin ) {
			return self::MODE_OFF;
		}
		$map = self::sanitize_plugin_modes( $policy['taint_screen'] ?? array() );
		if ( ! isset( $map[ $plugin ] ) ) {
			return self::MODE_OFF;
		}

		return self::sanitize_mode( $map[ $plugin ] );
	}

	/**
	 * Screen text for injection-shape classes.
	 *
	 * @return array<string,int> class => count (never includes matched text)
	 */
	public static function screen( string $text ): array {
		if ( '' === $text ) {
			return array();
		}
		$counts = array();
		foreach ( self::pattern_table() as $class => $regexes ) {
			$n = 0;
			foreach ( $regexes as $rx ) {
				$n += self::count_matches( $rx, $text );
			}
			if ( $n > 0 ) {
				$counts[ $class ] = $n;
			}
		}

		return $counts;
	}

	/**
	 * Replace matched substrings with class tokens so logged previews cannot leak.
	 */
	public static function redact( string $text ): string {
		if ( '' === $text ) {
			return $text;
		}
		foreach ( self::pattern_table() as $class => $regexes ) {
			$token = '[redacted-' . $class . ']';
			foreach ( $regexes as $rx ) {
				$replaced = preg_replace( $rx, $token, $text );
				if ( is_string( $replaced ) ) {
					$text = $replaced;
				}
			}
		}

		return $text;
	}

	/**
	 * Apply screen to an Activity event + decide prevent override.
	 *
	 * Zero work when mode is off. Mutates $event in place (taint_match, redacted preview).
	 *
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 * @param mixed               $builder Optional builder for full-text screen.
	 * @return array{active:bool,prevent:bool,mode:string,matches:array<string,int>}
	 */
	public static function apply_to_event( array &$event, array $policy, $builder = null ): array {
		$empty = array(
			'active'  => false,
			'prevent' => false,
			'mode'    => self::MODE_OFF,
			'matches' => array(),
		);

		$plugin = isset( $event['plugin'] ) ? (string) $event['plugin'] : '';
		$mode   = self::mode_for_plugin( $policy, $plugin );
		if ( self::MODE_OFF === $mode ) {
			return $empty;
		}

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

		$event['taint_match'] = array(
			'classes' => $matches,
			'mode'    => $mode,
		);

		return array(
			'active'  => true,
			'prevent' => ( self::MODE_DENY === $mode ),
			'mode'    => $mode,
			'matches' => $matches,
		);
	}

	/**
	 * Warn-mode alert after the row is retained. Never embeds matched text.
	 *
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 * @return array{alerted:bool,reason:string}
	 */
	public static function maybe_alert( array $event, array $policy ): array {
		$match = isset( $event['taint_match'] ) && is_array( $event['taint_match'] ) ? $event['taint_match'] : null;
		if ( null === $match ) {
			return array( 'alerted' => false, 'reason' => 'no_match' );
		}

		$channel = isset( $event['channel'] ) ? (string) $event['channel'] : '';
		if ( self::CHANNEL === $channel ) {
			return array( 'alerted' => false, 'reason' => 'skip_channel' );
		}

		$mode = self::sanitize_mode( $match['mode'] ?? '' );
		if ( self::MODE_WARN !== $mode ) {
			return array( 'alerted' => false, 'reason' => 'not_warn' );
		}

		$classes = isset( $match['classes'] ) && is_array( $match['classes'] ) ? $match['classes'] : array();
		$classes = self::sanitize_match_classes( $classes );
		if ( empty( $classes ) ) {
			return array( 'alerted' => false, 'reason' => 'empty_classes' );
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

		$subject = self::build_subject( $plugin );
		$body    = self::build_body( $plugin, $classes, self::MODE_WARN );
		$ok      = Alerts::safe_wp_mail( $to, $subject, $body );

		$webhook = isset( $policy['alert_webhook_url'] ) ? Alerts::sanitize_webhook_url( (string) $policy['alert_webhook_url'] ) : '';
		if ( '' !== $webhook ) {
			$hook_ok = Alerts::safe_wp_remote_post(
				$webhook,
				array(
					'type'    => 'handl_aicac_taint_warn',
					'plugin'  => $plugin,
					'mode'    => self::MODE_WARN,
					'classes' => $classes,
					'site'    => function_exists( 'home_url' ) ? home_url( '/' ) : '',
				),
				'taint_warn'
			);
			$ok = $ok || $hook_ok;
		}

		if ( ! $ok ) {
			return array( 'alerted' => false, 'reason' => 'delivery_failed' );
		}

		return array( 'alerted' => true, 'reason' => 'alerted' );
	}

	/**
	 * @param array<string,mixed> $classes
	 * @return array<string,int>
	 */
	public static function sanitize_match_classes( array $classes ): array {
		$table   = self::pattern_table();
		$allowed = array_fill_keys( array_keys( $table ), true );
		$out     = array();
		foreach ( $classes as $class => $count ) {
			$class = sanitize_key( (string) $class );
			if ( ! isset( $allowed[ $class ] ) ) {
				continue;
			}
			$count = (int) $count;
			if ( $count > 0 ) {
				$out[ $class ] = $count;
			}
		}

		return $out;
	}

	public static function class_label( string $class ): string {
		$map = array(
			self::CLASS_INSTRUCTION => __( 'Instruction override', 'handl-ai-connector-access-control' ),
			self::CLASS_ROLE        => __( 'Role reassignment', 'handl-ai-connector-access-control' ),
			self::CLASS_EXFIL       => __( 'Secret-prompt bait', 'handl-ai-connector-access-control' ),
			self::CLASS_OBFUSCATION => __( 'Hidden characters or mixed alphabets', 'handl-ai-connector-access-control' ),
		);
		$class = sanitize_key( $class );

		return $map[ $class ] ?? $class;
	}

	/**
	 * Receipt line: pattern classes only, never matched text.
	 *
	 * @param array<string,int> $classes
	 */
	public static function receipt_summary( array $classes ): string {
		$classes = self::sanitize_match_classes( $classes );
		if ( empty( $classes ) ) {
			return '';
		}
		$parts = array();
		foreach ( $classes as $class => $count ) {
			$parts[] = sprintf( '%s (%d)', self::class_label( $class ), (int) $count );
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
			__( '[%1$s] Possible prompt injection in an AI call by %2$s', 'handl-ai-connector-access-control' ),
			$site,
			$label
		);
	}

	/**
	 * @param array<string,int> $classes
	 */
	public static function build_body( string $plugin, array $classes, string $mode ): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control found text that matches a possible prompt-injection pattern in this plugin\'s AI request.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: plugin basename or label */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			self::plugin_label( $plugin )
		);
		if ( self::MODE_WARN === self::sanitize_mode( $mode ) ) {
			$lines[] = __( 'Screen result: Warn (this check did not block the request).', 'handl-ai-connector-access-control' );
		}
		$lines[] = __( 'Pattern types and match counts (matching text is not included in this alert):', 'handl-ai-connector-access-control' );
		$summary = self::receipt_summary( $classes );
		if ( '' !== $summary ) {
			$lines[] = $summary;
		}
		$lines[] = '';
		$lines[] = __( 'To block requests that match these patterns, set this plugin\'s injection screen to Deny and turn off Learn mode.', 'handl-ai-connector-access-control' );

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
		self::$registered = false;
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
			__( 'Injection screen', 'handl-ai-connector-access-control' ),
			__( 'Injection screen', 'handl-ai-connector-access-control' ),
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
		$modes      = self::sanitize_plugin_modes( $policy['taint_screen'] ?? array() );
		$can_manage = class_exists( Caps::class, false ) && Caps::user_can_manage();
		$plugins    = self::candidate_plugins( $policy );

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Injection screen', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Check each plugin\'s AI Client requests for text that may try to change the AI\'s instructions. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p class="description">' . esc_html__( 'Pattern checks can flag harmless text and miss attacks.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( empty( $modes ) ) {
			echo '<p>' . esc_html__( 'Injection screen is off.', 'handl-ai-connector-access-control' ) . '</p>';
		}

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
			$current = $modes[ $basename ] ?? self::MODE_OFF;
			echo '<tr><td>' . esc_html( $label ) . '<br /><code>' . esc_html( $basename ) . '</code></td><td>';
			if ( $can_manage ) {
				echo '<select name="handl_aicac_taint_modes[' . esc_attr( $basename ) . ']">';
				foreach ( self::mode_choices() as $value => $choice_label ) {
					echo '<option value="' . esc_attr( $value ) . '"' . selected( $current, $value, false ) . '>' . esc_html( $choice_label ) . '</option>';
				}
				echo '</select>';
			} else {
				echo esc_html( self::mode_choices()[ $current ] ?? $current );
			}
			echo '</td></tr>';
		}
		echo '</tbody></table>';
		echo '<p class="description">' . esc_html__( 'Off skips this check. Warn flags matches without blocking them. Deny blocks matching requests unless Learn mode is on. Other rules still apply.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p class="description">' . esc_html__( 'Match details show pattern types and counts, not matching text.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			if ( function_exists( 'submit_button' ) ) {
				submit_button( __( 'Save injection screen', 'handl-ai-connector-access-control' ) );
			} else {
				echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Save injection screen', 'handl-ai-connector-access-control' ) . '</button></p>';
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
		$raw   = isset( $_POST['handl_aicac_taint_modes'] ) && is_array( $_POST['handl_aicac_taint_modes'] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing
			? wp_unslash( $_POST['handl_aicac_taint_modes'] ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			: array();
		$modes = self::sanitize_plugin_modes( is_array( $raw ) ? $raw : array() );

		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' ) && method_exists( Policy::class, 'save_policy' ) ) {
			$policy                 = Policy::get_policy();
			$policy['taint_screen'] = $modes;
			Policy::save_policy( $policy );
		}

		self::redirect();
	}

	/**
	 * @return array<string,string>
	 */
	private static function mode_choices(): array {
		return array(
			self::MODE_OFF  => __( 'Off', 'handl-ai-connector-access-control' ),
			self::MODE_WARN => __( 'Warn', 'handl-ai-connector-access-control' ),
			self::MODE_DENY => __( 'Deny', 'handl-ai-connector-access-control' ),
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
				$label = is_array( $info ) && isset( $info['Name'] ) ? (string) $info['Name'] : $plugin;
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

	private static function count_matches( string $rx, string $text ): int {
		$n = preg_match_all( $rx, $text, $m );
		if ( ! is_int( $n ) || $n < 1 ) {
			return 0;
		}

		return $n;
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
