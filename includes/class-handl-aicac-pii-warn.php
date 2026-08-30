<?php
/**
 * AICAC-PII-WARN: opt-in outbound payload PII screen (#230).
 *
 * Per-plugin modes ride the policy option (same storage as other rules):
 * off (default) / warn (log + alert, allow) / deny (block with reason pii).
 * Logs MATCH TYPE + count only — never the matched text.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Lightweight regex screen of outbound prompt/payload text.
 */
final class Pii_Warn {

	public const MODE_OFF  = 'off';
	public const MODE_WARN = 'warn';
	public const MODE_DENY = 'deny';

	public const PATTERN_EMAIL       = 'email';
	public const PATTERN_PHONE       = 'phone';
	public const PATTERN_CARD        = 'card';
	public const PATTERN_NATIONAL_ID = 'national_id';

	public const CHANNEL = 'pii';

	/**
	 * @return list<string>
	 */
	public static function all_patterns(): array {
		return array(
			self::PATTERN_EMAIL,
			self::PATTERN_PHONE,
			self::PATTERN_CARD,
			self::PATTERN_NATIONAL_ID,
		);
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
	 * Per-plugin mode map. Absent / invalid → omitted (treated as off).
	 *
	 * @param mixed $raw
	 * @return array<string,string> plugin => off|warn|deny
	 */
	public static function sanitize_plugin_modes( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $plugin => $mode ) {
			$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
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
	 * Enabled pattern list. Empty / absent → all patterns.
	 *
	 * @param mixed $raw
	 * @return list<string>
	 */
	public static function sanitize_patterns( $raw ): array {
		if ( null === $raw || false === $raw || '' === $raw ) {
			return self::all_patterns();
		}
		if ( is_string( $raw ) ) {
			$raw = preg_split( '/[\s,;]+/', $raw ) ?: array();
		}
		if ( ! is_array( $raw ) ) {
			return self::all_patterns();
		}

		$allowed = array_fill_keys( self::all_patterns(), true );
		$out     = array();
		foreach ( $raw as $pat ) {
			$pat = sanitize_key( (string) $pat );
			if ( isset( $allowed[ $pat ] ) ) {
				$out[] = $pat;
			}
		}
		$out = array_values( array_unique( $out ) );

		return empty( $out ) ? self::all_patterns() : $out;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function mode_for_plugin( array $policy, ?string $plugin ): string {
		$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
		if ( '' === $plugin ) {
			return self::MODE_OFF;
		}
		$map = self::sanitize_plugin_modes( $policy['pii_screen'] ?? array() );
		if ( ! isset( $map[ $plugin ] ) ) {
			return self::MODE_OFF;
		}

		return self::sanitize_mode( $map[ $plugin ] );
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return list<string>
	 */
	public static function enabled_patterns( array $policy ): array {
		return self::sanitize_patterns( $policy['pii_patterns'] ?? null );
	}

	/**
	 * Screen text for high-confidence PII patterns.
	 *
	 * @param list<string>|null $patterns
	 * @return array<string,int> pattern => count (never includes matched text)
	 */
	public static function screen( string $text, ?array $patterns = null ): array {
		if ( '' === $text ) {
			return array();
		}
		$patterns = null === $patterns ? self::all_patterns() : self::sanitize_patterns( $patterns );
		$counts   = array();

		foreach ( $patterns as $pat ) {
			$n = 0;
			switch ( $pat ) {
				case self::PATTERN_EMAIL:
					$n = self::count_emails( $text );
					break;
				case self::PATTERN_PHONE:
					$n = self::count_phones( $text );
					break;
				case self::PATTERN_CARD:
					$n = self::count_cards( $text );
					break;
				case self::PATTERN_NATIONAL_ID:
					$n = self::count_national_ids( $text );
					break;
			}
			if ( $n > 0 ) {
				$counts[ $pat ] = $n;
			}
		}

		return $counts;
	}

	/**
	 * Replace matched substrings with type tokens so logged previews cannot leak.
	 *
	 * @param list<string>|null $patterns
	 */
	public static function redact( string $text, ?array $patterns = null ): string {
		if ( '' === $text ) {
			return $text;
		}
		$patterns = null === $patterns ? self::all_patterns() : self::sanitize_patterns( $patterns );

		if ( in_array( self::PATTERN_EMAIL, $patterns, true ) ) {
			$text = (string) preg_replace(
				'/\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b/i',
				'[redacted-email]',
				$text
			);
		}
		if ( in_array( self::PATTERN_NATIONAL_ID, $patterns, true ) ) {
			$text = (string) preg_replace(
				'/\b\d{3}-\d{2}-\d{4}\b/',
				'[redacted-national_id]',
				$text
			);
		}
		if ( in_array( self::PATTERN_CARD, $patterns, true ) ) {
			$text = self::redact_cards( $text );
		}
		if ( in_array( self::PATTERN_PHONE, $patterns, true ) ) {
			$text = self::redact_phones( $text );
		}

		return $text;
	}

	/**
	 * Best-effort full payload text from a prompt builder (never logged as-is).
	 *
	 * @param mixed $builder WP_AI_Client_Prompt_Builder or null.
	 */
	public static function payload_text_from_builder( $builder ): string {
		if ( ! is_object( $builder ) ) {
			return '';
		}

		try {
			$ref = new \ReflectionClass( $builder );
			$inner = null;
			if ( $ref->hasProperty( 'builder' ) ) {
				$prop = $ref->getProperty( 'builder' );
				$prop->setAccessible( true );
				$candidate = $prop->getValue( $builder );
				if ( is_object( $candidate ) ) {
					$inner = $candidate;
				}
			}
			if ( null === $inner ) {
				$inner = $builder;
			}

			$iref = new \ReflectionClass( $inner );
			if ( ! $iref->hasProperty( 'messages' ) ) {
				return '';
			}
			$mprop = $iref->getProperty( 'messages' );
			$mprop->setAccessible( true );
			$messages = $mprop->getValue( $inner );
			if ( ! is_array( $messages ) ) {
				return '';
			}

			$chunks = array();
			foreach ( $messages as $message ) {
				if ( ! is_object( $message ) || ! method_exists( $message, 'getParts' ) ) {
					continue;
				}
				$parts = $message->getParts();
				if ( ! is_array( $parts ) ) {
					continue;
				}
				foreach ( $parts as $part ) {
					if ( ! is_object( $part ) || ! method_exists( $part, 'getText' ) ) {
						continue;
					}
					$text = $part->getText();
					if ( is_string( $text ) && '' !== trim( $text ) ) {
						$chunks[] = trim( $text );
					}
				}
			}

			return implode( "\n", $chunks );
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			return '';
		}
	}

	/**
	 * Apply screen to an Activity event + decide prevent override.
	 *
	 * Zero work when mode is off. Mutates $event in place (pii_match, redacted preview).
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

		$patterns = self::enabled_patterns( $policy );
		$text     = self::payload_text_from_builder( $builder );
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

		$matches = self::screen( $text, $patterns );
		if ( empty( $matches ) ) {
			return array(
				'active'  => true,
				'prevent' => false,
				'mode'    => $mode,
				'matches' => array(),
			);
		}

		// Never persist matched text — scrub preview before the row is logged.
		if ( isset( $event['prompt_preview'] ) && is_string( $event['prompt_preview'] ) ) {
			$event['prompt_preview'] = self::redact( (string) $event['prompt_preview'], array_keys( $matches ) );
		}

		$event['pii_match'] = array(
			'types' => $matches,
			'mode'  => $mode,
		);

		// Caller applies decision / denial_reason (audit-only must stay observation-only).
		return array(
			'active'  => true,
			'prevent' => ( self::MODE_DENY === $mode ),
			'mode'    => $mode,
			'matches' => $matches,
		);
	}

	/**
	 * Warn-mode (and deny-mode companion) alert after the row is retained.
	 * Respects snooze + quiet hours. Never embeds matched text.
	 *
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 * @return array{alerted:bool,reason:string}
	 */
	public static function maybe_alert( array $event, array $policy ): array {
		$match = isset( $event['pii_match'] ) && is_array( $event['pii_match'] ) ? $event['pii_match'] : null;
		if ( null === $match ) {
			return array( 'alerted' => false, 'reason' => 'no_match' );
		}

		$channel = isset( $event['channel'] ) ? (string) $event['channel'] : '';
		if ( self::CHANNEL === $channel ) {
			return array( 'alerted' => false, 'reason' => 'skip_channel' );
		}

		$mode = self::sanitize_mode( $match['mode'] ?? '' );
		// Deny rows already go through Alerts::maybe_notify_denial; warn needs this path.
		if ( self::MODE_WARN !== $mode ) {
			return array( 'alerted' => false, 'reason' => 'not_warn' );
		}

		$types = isset( $match['types'] ) && is_array( $match['types'] ) ? $match['types'] : array();
		$types = self::sanitize_match_types( $types );
		if ( empty( $types ) ) {
			return array( 'alerted' => false, 'reason' => 'empty_types' );
		}

		$plugin = isset( $event['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $event['plugin'] ) : '';
		$ts     = isset( $event['ts'] ) ? (int) $event['ts'] : time();
		if ( $ts <= 0 ) {
			$ts = time();
		}

		if ( null !== Quiet_Hours::active_window( $policy, $ts ) ) {
			return array( 'alerted' => false, 'reason' => 'quiet_hours' );
		}

		if ( '' !== $plugin && Alert_Snooze::should_suppress( $plugin, 'pii', $ts ) ) {
			return array( 'alerted' => false, 'reason' => 'suppressed' );
		}

		$to = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return array( 'alerted' => false, 'reason' => 'no_recipient' );
		}

		$subject = self::build_subject( $plugin );
		$body    = self::build_body( $plugin, $types, self::MODE_WARN );
		$ok      = Alerts::safe_wp_mail( $to, $subject, $body );

		$webhook = isset( $policy['alert_webhook_url'] ) ? Alerts::sanitize_webhook_url( (string) $policy['alert_webhook_url'] ) : '';
		if ( '' !== $webhook ) {
			$hook_ok = Alerts::safe_wp_remote_post(
				$webhook,
				array(
					'type'   => 'handl_aicac_pii_warn',
					'plugin' => $plugin,
					'mode'   => self::MODE_WARN,
					'types'  => $types,
					'site'   => function_exists( 'home_url' ) ? home_url( '/' ) : '',
				),
				'pii_warn'
			);
			$ok = $ok || $hook_ok;
		}

		if ( ! $ok ) {
			return array( 'alerted' => false, 'reason' => 'delivery_failed' );
		}

		return array( 'alerted' => true, 'reason' => 'alerted' );
	}

	/**
	 * @param array<string,mixed> $types
	 * @return array<string,int>
	 */
	public static function sanitize_match_types( array $types ): array {
		$allowed = array_fill_keys( self::all_patterns(), true );
		$out     = array();
		foreach ( $types as $pat => $count ) {
			$pat = sanitize_key( (string) $pat );
			if ( ! isset( $allowed[ $pat ] ) ) {
				continue;
			}
			$count = (int) $count;
			if ( $count > 0 ) {
				$out[ $pat ] = $count;
			}
		}

		return $out;
	}

	public static function build_subject( string $plugin ): string {
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$label = self::plugin_label( $plugin );

		return sprintf(
			/* translators: 1: site name, 2: plugin label */
			__( '[%1$s] Possible personal information sent to AI by %2$s', 'handl-ai-connector-access-control' ),
			$site,
			$label
		);
	}

	/**
	 * Reader-facing label for a stored pattern key (keys stay email|phone|card|national_id).
	 */
	public static function pattern_label( string $pattern ): string {
		$map = array(
			self::PATTERN_EMAIL       => __( 'Email address', 'handl-ai-connector-access-control' ),
			self::PATTERN_PHONE       => __( 'Phone number', 'handl-ai-connector-access-control' ),
			self::PATTERN_CARD        => __( 'Payment card number', 'handl-ai-connector-access-control' ),
			self::PATTERN_NATIONAL_ID => __( 'U.S. Social Security number', 'handl-ai-connector-access-control' ),
		);
		$pattern = sanitize_key( $pattern );

		return $map[ $pattern ] ?? $pattern;
	}

	/**
	 * @param array<string,int> $types
	 */
	public static function build_body( string $plugin, array $types, string $mode ): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control found possible personal information in a request sent to an AI provider.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: plugin basename or label */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			self::plugin_label( $plugin )
		);
		if ( self::MODE_WARN === self::sanitize_mode( $mode ) ) {
			$lines[] = __( 'Result: Allowed and logged', 'handl-ai-connector-access-control' );
		}
		$lines[] = __( 'Possible information found (counts only; HandL does not save or email the matching text):', 'handl-ai-connector-access-control' );
		foreach ( self::sanitize_match_types( $types ) as $pat => $count ) {
			$lines[] = sprintf( '- %s: %d', self::pattern_label( $pat ), (int) $count );
		}
		$lines[] = '';
		$lines[] = __( 'To block future requests like this, set this plugin’s personal information policy to Deny.', 'handl-ai-connector-access-control' );

		return implode( "\n", $lines );
	}

	private static function plugin_label( string $plugin ): string {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
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

	private static function count_emails( string $text ): int {
		if ( ! preg_match_all( '/\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b/i', $text, $m ) ) {
			return 0;
		}

		return count( $m[0] );
	}

	private static function count_phones( string $text ): int {
		// Prefer explicit phone shapes; skip digit runs that are card-shaped (Luhn).
		if ( ! preg_match_all(
			'/(?<![0-9])(?:\+\d{1,3}[\s.\-]*)?(?:\(?\d{2,4}\)?[\s.\-]*)?\d{3,4}[\s.\-]*\d{4}(?![0-9])/',
			$text,
			$m
		) ) {
			return 0;
		}
		$n = 0;
		foreach ( $m[0] as $raw ) {
			$digits = preg_replace( '/\D+/', '', (string) $raw );
			$len    = strlen( (string) $digits );
			if ( $len < 10 || $len > 15 ) {
				continue;
			}
			// Card PANs are 13–19 digits; never count a Luhn-valid PAN as a phone.
			if ( $len >= 13 && self::luhn_ok( (string) $digits ) ) {
				continue;
			}
			// Space/dash grouped 4×4 looks like a card fragment, not a phone.
			if ( preg_match( '/^(?:\d{4}[\s\-]){2,}\d{4}$/', trim( (string) $raw ) ) ) {
				continue;
			}
			++$n;
		}

		return $n;
	}

	private static function count_cards( string $text ): int {
		if ( ! preg_match_all( '/(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)/', $text, $m ) ) {
			return 0;
		}
		$n = 0;
		foreach ( $m[0] as $raw ) {
			$digits = preg_replace( '/\D+/', '', (string) $raw );
			$len    = strlen( (string) $digits );
			if ( $len < 13 || $len > 19 ) {
				continue;
			}
			if ( self::luhn_ok( (string) $digits ) ) {
				++$n;
			}
		}

		return $n;
	}

	private static function count_national_ids( string $text ): int {
		// High-confidence US SSN shape only (XXX-XX-XXXX). Broader IDs wait for curated lists.
		if ( ! preg_match_all( '/\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/', $text, $m ) ) {
			return 0;
		}

		return count( $m[0] );
	}

	private static function redact_cards( string $text ): string {
		return (string) preg_replace_callback(
			'/(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)/',
			static function ( array $m ): string {
				$digits = preg_replace( '/\D+/', '', (string) $m[0] );
				$len    = strlen( (string) $digits );
				if ( $len < 13 || $len > 19 || ! self::luhn_ok( (string) $digits ) ) {
					return (string) $m[0];
				}

				return '[redacted-card]';
			},
			$text
		);
	}

	private static function redact_phones( string $text ): string {
		return (string) preg_replace_callback(
			'/(?<![0-9])(?:\+\d{1,3}[\s.\-]*)?(?:\(?\d{2,4}\)?[\s.\-]*)?\d{3,4}[\s.\-]*\d{4}(?![0-9])/',
			static function ( array $m ): string {
				$raw    = (string) $m[0];
				$digits = preg_replace( '/\D+/', '', $raw );
				$len    = strlen( (string) $digits );
				if ( $len < 10 || $len > 15 ) {
					return $raw;
				}
				if ( $len >= 13 && self::luhn_ok( (string) $digits ) ) {
					return $raw;
				}
				if ( preg_match( '/^(?:\d{4}[\s\-]){2,}\d{4}$/', trim( $raw ) ) ) {
					return $raw;
				}

				return '[redacted-phone]';
			},
			$text
		);
	}

	/**
	 * Luhn check for card-shaped digit strings.
	 */
	public static function luhn_ok( string $digits ): bool {
		if ( ! ctype_digit( $digits ) ) {
			return false;
		}
		$sum    = 0;
		$alt    = false;
		$length = strlen( $digits );
		for ( $i = $length - 1; $i >= 0; $i-- ) {
			$n = (int) $digits[ $i ];
			if ( $alt ) {
				$n *= 2;
				if ( $n > 9 ) {
					$n -= 9;
				}
			}
			$sum += $n;
			$alt  = ! $alt;
		}

		return 0 === ( $sum % 10 );
	}
}
