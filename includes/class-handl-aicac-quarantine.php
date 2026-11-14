<?php
/**
 * AICAC-QUARANTINE (#512): inbound response active-content screen.
 *
 * Screens AI HTTP replies for script tags, event handlers, javascript:/data
 * URIs, iframe/object/embed. Default WARN: log kinds + count, alert, leave
 * the reply unchanged. Per-plugin HARD replaces the response with WP_Error
 * reason `quarantine` so a renderer never sees the body. Never stores the
 * reply text. Response-side only (http_api_debug + http_response).
 *
 * README-FREE. Own options (handl_aicac_quarantine*). Own admin screen.
 * Zero policy.php / tripwire.php / optout.php / admin.php / readme.txt edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Screen inbound AI replies for active content.
 */
final class Quarantine {

	public const SETTINGS_OPTION = 'handl_aicac_quarantine';

	public const PAGE_SLUG = 'handl-aicac-quarantine';

	public const ACTION_SAVE = 'handl_aicac_quarantine_save';

	public const POST_PRESENT = 'handl_aicac_quarantine_present';

	public const POST_ENABLED = 'handl_aicac_quarantine_enabled';

	public const POST_MODES = 'handl_aicac_quarantine_modes';

	public const FILTER = 'handl_aicac_quarantine_patterns';

	public const REASON = 'quarantine';

	public const CHANNEL = 'quarantine';

	public const ERROR_CODE = 'quarantine';

	public const MODE_OFF = 'off';

	public const MODE_WARN = 'warn';

	public const MODE_HARD = 'hard';

	public const KIND_SCRIPT = 'script-tag';

	public const KIND_EVENT = 'event-handler';

	public const KIND_JS_URI = 'javascript-uri';

	public const KIND_DATA_HTML = 'data-html';

	public const KIND_IFRAME = 'iframe';

	public const KIND_OBJECT = 'object';

	public const KIND_EMBED = 'embed';

	public const FRAMING = 'screens_inbound_replies_never_mutates_requests';

	public const MAX_EVENTS = 50;

	public const MAX_HAYSTACK = 524288;

	/** @var bool */
	private static $registered = false;

	/** @var int|null */
	private static $test_now = null;

	/** @var string|null */
	private static $test_plugin = null;

	/** @var string|null */
	private static $test_provider = null;

	/**
	 * Request-local HARD block. Never persisted.
	 *
	 * @var array{url:string,plugin:string,provider:string,host:string,kinds:array<string,int>}|null
	 */
	private static $pending_hard = null;

	/**
	 * URL already screened this request (debug then response).
	 *
	 * @var string|null
	 */
	private static $processed_url = null;

	/**
	 * @var list<array<string,mixed>>
	 */
	private static $last_events = array();

	/**
	 * @var list<array{to:string,subject:string,body:string}>
	 */
	private static $test_mails = array();

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_action( 'http_api_debug', array( self::class, 'on_http_api_debug' ), 10, 5 );
		add_filter( 'http_response', array( self::class, 'on_http_response' ), 10, 3 );
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
	}

	public static function reset_for_tests(): void {
		self::$registered    = false;
		self::$test_now      = null;
		self::$test_plugin   = null;
		self::$test_provider = null;
		self::$pending_hard  = null;
		self::$processed_url = null;
		self::$last_events   = array();
		self::$test_mails    = array();
		delete_option( self::SETTINGS_OPTION );
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	public static function set_test_plugin( ?string $plugin ): void {
		self::$test_plugin = ( is_string( $plugin ) && '' !== $plugin ) ? $plugin : null;
	}

	public static function set_test_provider( ?string $provider ): void {
		self::$test_provider = ( is_string( $provider ) && '' !== $provider ) ? sanitize_key( $provider ) : null;
	}

	public static function now(): int {
		if ( null !== self::$test_now ) {
			return (int) self::$test_now;
		}
		if ( class_exists( Clock::class, false ) && method_exists( Clock::class, 'now' ) ) {
			return (int) Clock::now();
		}

		return time();
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function last_events(): array {
		return self::$last_events;
	}

	/**
	 * @return list<array{to:string,subject:string,body:string}>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	/**
	 * @return array{url:string,plugin:string,provider:string,host:string,kinds:array<string,int>}|null
	 */
	public static function pending_hard(): ?array {
		return self::$pending_hard;
	}

	/**
	 * @return array{enabled:bool,plugin_modes:array<string,string>}
	 */
	public static function defaults(): array {
		return array(
			'enabled'      => false,
			'plugin_modes' => array(),
		);
	}

	/**
	 * @return array{enabled:bool,plugin_modes:array<string,string>}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,plugin_modes:array<string,string>}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled'      => ! empty( $raw['enabled'] ),
			'plugin_modes' => self::sanitize_plugin_modes( $raw['plugin_modes'] ?? array() ),
		);
	}

	/**
	 * @param mixed $raw Raw map.
	 * @return array<string,string> plugin => warn|hard|off
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
			if ( self::MODE_WARN !== $mode && self::MODE_HARD !== $mode && self::MODE_OFF !== $mode ) {
				continue;
			}
			$out[ $plugin ] = $mode;
		}

		return $out;
	}

	/**
	 * @param mixed $raw Raw mode.
	 */
	public static function sanitize_mode( $raw ): string {
		$mode = sanitize_key( (string) $raw );
		if ( self::MODE_HARD === $mode ) {
			return self::MODE_HARD;
		}
		if ( self::MODE_OFF === $mode ) {
			return self::MODE_OFF;
		}
		if ( self::MODE_WARN === $mode ) {
			return self::MODE_WARN;
		}

		return '';
	}

	public static function sanitize_plugin( string $raw ): string {
		if ( class_exists( Plugin_Profile::class, false ) && method_exists( Plugin_Profile::class, 'sanitize_plugin' ) ) {
			return Plugin_Profile::sanitize_plugin( $raw );
		}
		$plugin = sanitize_text_field( $raw );
		$plugin = str_replace( '\\', '/', $plugin );
		if ( '' === $plugin || false !== strpos( $plugin, '..' ) ) {
			return '';
		}

		return $plugin;
	}

	/**
	 * @param array<string,mixed> $settings Incoming.
	 */
	public static function save_settings( array $settings ): bool {
		$clean  = self::sanitize_settings( $settings );
		$before = self::get_settings();
		if ( $clean === $before ) {
			return false;
		}
		if ( $clean === self::defaults() ) {
			delete_option( self::SETTINGS_OPTION );

			return true;
		}
		update_option( self::SETTINGS_OPTION, $clean, false );

		return true;
	}

	public static function is_enabled(): bool {
		return ! empty( self::get_settings()['enabled'] );
	}

	public static function mode_for_plugin( ?string $plugin ): string {
		$settings = self::get_settings();
		$plugin   = self::sanitize_plugin( (string) $plugin );
		if ( '' !== $plugin && isset( $settings['plugin_modes'][ $plugin ] ) ) {
			return $settings['plugin_modes'][ $plugin ];
		}
		if ( ! empty( $settings['enabled'] ) ) {
			return self::MODE_WARN;
		}

		return self::MODE_OFF;
	}

	/**
	 * Bundled active-content shapes. Filterable: `handl_aicac_quarantine_patterns`.
	 *
	 * @return array<string,list<string>>
	 */
	public static function pattern_table(): array {
		$table = array(
			self::KIND_SCRIPT    => array( '/<\s*script\b/i' ),
			self::KIND_EVENT     => array( '/\son[a-z]{2,}\s*=/i' ),
			self::KIND_JS_URI    => array( '/javascript\s*:/i' ),
			self::KIND_DATA_HTML => array( '/data\s*:\s*text\s*\/\s*html/i' ),
			self::KIND_IFRAME    => array( '/<\s*iframe\b/i' ),
			self::KIND_OBJECT    => array( '/<\s*object\b/i' ),
			self::KIND_EMBED     => array( '/<\s*embed\b/i' ),
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
	 * @param mixed $raw Raw table.
	 * @return array<string,list<string>>
	 */
	public static function sanitize_pattern_table( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $kind => $regexes ) {
			$kind = sanitize_key( (string) $kind );
			if ( '' === $kind ) {
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
				$out[ $kind ] = array_values( array_unique( $list ) );
			}
		}

		return $out;
	}

	/**
	 * @return array<string,int> kind => count (never includes matched text)
	 */
	public static function screen( string $text ): array {
		if ( '' === $text ) {
			return array();
		}
		if ( strlen( $text ) > self::MAX_HAYSTACK ) {
			$text = substr( $text, 0, self::MAX_HAYSTACK );
		}
		$counts = array();
		foreach ( self::pattern_table() as $kind => $regexes ) {
			$n = 0;
			foreach ( $regexes as $rx ) {
				$found = preg_match_all( $rx, $text );
				if ( is_int( $found ) && $found > 0 ) {
					$n += $found;
				}
			}
			if ( $n > 0 ) {
				$counts[ $kind ] = $n;
			}
		}

		return $counts;
	}

	/**
	 * Haystack from an HTTP response. JSON string values are included so
	 * `\u003cscript` is visible. The raw body is never stored.
	 *
	 * @param mixed $response Response or WP_Error.
	 */
	public static function body_text( $response ): string {
		if ( is_wp_error( $response ) ) {
			return '';
		}
		$body = '';
		if ( is_array( $response ) ) {
			$body = $response['body'] ?? '';
		} elseif ( is_string( $response ) ) {
			$body = $response;
		}
		if ( is_array( $body ) ) {
			return self::flatten_strings( $body );
		}
		if ( ! is_string( $body ) || '' === $body ) {
			return '';
		}
		$decoded = json_decode( $body, true );
		if ( is_array( $decoded ) ) {
			$flat = self::flatten_strings( $decoded );

			return '' !== $flat ? $flat : $body;
		}

		return $body;
	}

	/**
	 * @param mixed $value Nested JSON.
	 */
	public static function flatten_strings( $value ): string {
		if ( is_string( $value ) ) {
			return $value;
		}
		if ( ! is_array( $value ) ) {
			return '';
		}
		$parts = array();
		foreach ( $value as $item ) {
			$chunk = self::flatten_strings( $item );
			if ( '' !== $chunk ) {
				$parts[] = $chunk;
			}
			if ( strlen( implode( "\n", $parts ) ) > self::MAX_HAYSTACK ) {
				break;
			}
		}

		return implode( "\n", $parts );
	}

	/**
	 * Volume-path observer. Read-only: never mutates the response.
	 *
	 * @param mixed               $response Response or WP_Error.
	 * @param mixed               $context  Hook context.
	 * @param mixed               $class    Transport class.
	 * @param mixed               $args     Request args.
	 * @param mixed               $url      Request URL.
	 */
	public static function on_http_api_debug( $response, $context, $class, $args, $url ): void {
		unset( $class );
		if ( 'response' !== (string) $context ) {
			return;
		}
		self::consider( $response, is_array( $args ) ? $args : array(), is_string( $url ) ? $url : '', false );
	}

	/**
	 * HARD mutation point. WARN returns the response unchanged.
	 *
	 * @param mixed $response Response or WP_Error.
	 * @param mixed $args     Request args.
	 * @param mixed $url      Request URL.
	 * @return mixed
	 */
	public static function on_http_response( $response, $args, $url ) {
		return self::consider( $response, is_array( $args ) ? $args : array(), is_string( $url ) ? $url : '', true );
	}

	/**
	 * @param mixed               $response Response.
	 * @param array<string,mixed> $args     Args (never mutated).
	 * @param string              $url      URL.
	 * @param bool                $mutate   Whether HARD may replace the response.
	 * @return mixed
	 */
	public static function consider( $response, array $args, string $url, bool $mutate ) {
		unset( $args );
		if ( $mutate && null !== self::$pending_hard && self::$pending_hard['url'] === $url ) {
			$pending            = self::$pending_hard;
			self::$pending_hard = null;

			return self::hard_error( $pending['kinds'] );
		}

		if ( null !== self::$processed_url && self::$processed_url === $url ) {
			return $response;
		}

		$plugin = self::caller_plugin();
		$mode   = self::mode_for_plugin( $plugin );
		if ( self::MODE_OFF === $mode ) {
			return $response;
		}

		$match = self::match_provider( $url );
		if ( null === $match ) {
			return $response;
		}

		self::$processed_url = $url;
		$text                = self::body_text( $response );
		$kinds               = self::screen( $text );
		if ( array() === $kinds ) {
			return $response;
		}

		$event = array(
			'decision' => self::MODE_HARD === $mode ? 'deny' : 'warn',
			'plugin'   => $plugin,
			'provider' => $match['id'],
			'host'     => $match['host'],
			'detail'   => self::receipt_summary( $kinds ),
			'quarantine' => array(
				'kinds' => $kinds,
				'mode'  => $mode,
			),
		);
		if ( self::MODE_HARD === $mode ) {
			$event['denial_reason']  = self::REASON;
			$event['returned_error'] = self::block_message( $kinds );
			if ( class_exists( Deny_Receipt::class, false ) && method_exists( Deny_Receipt::class, 'stamp' ) ) {
				Deny_Receipt::stamp( $event );
			}
		}
		self::record_event( $event );
		self::maybe_alert( $event );

		if ( self::MODE_HARD === $mode ) {
			self::$pending_hard = array(
				'url'      => $url,
				'plugin'   => $plugin,
				'provider' => $match['id'],
				'host'     => $match['host'],
				'kinds'    => $kinds,
			);
			if ( $mutate ) {
				self::$pending_hard = null;

				return self::hard_error( $kinds );
			}
		}

		return $response;
	}

	/**
	 * @param array<string,int> $kinds Kinds.
	 * @return mixed
	 */
	public static function hard_error( array $kinds ) {
		$message = self::block_message( $kinds );
		if ( class_exists( '\WP_Error' ) ) {
			return new \WP_Error( self::ERROR_CODE, $message );
		}

		return array(
			'body'     => '',
			'response' => array(
				'code'    => 403,
				'message' => $message,
			),
		);
	}

	/**
	 * @param array<string,int> $kinds Kinds.
	 */
	public static function block_message( array $kinds ): string {
		$summary = self::receipt_summary( $kinds );
		if ( '' === $summary ) {
			return __( 'This AI reply was blocked because it contained active content.', 'handl-ai-connector-access-control' );
		}

		return sprintf(
			/* translators: %s: kind labels and counts */
			__( 'This AI reply was blocked because it contained active content: %s.', 'handl-ai-connector-access-control' ),
			$summary
		);
	}

	/**
	 * @param array<string,int> $kinds Kinds.
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

	/**
	 * @param array<string,mixed> $kinds Raw.
	 * @return array<string,int>
	 */
	public static function sanitize_match_kinds( array $kinds ): array {
		$table   = self::pattern_table();
		$allowed = array_fill_keys( array_keys( $table ), true );
		$out     = array();
		foreach ( $kinds as $kind => $count ) {
			$kind = sanitize_key( (string) $kind );
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
		$map  = array(
			self::KIND_SCRIPT    => __( 'Script tag', 'handl-ai-connector-access-control' ),
			self::KIND_EVENT     => __( 'Event handler', 'handl-ai-connector-access-control' ),
			self::KIND_JS_URI    => __( 'javascript: URL', 'handl-ai-connector-access-control' ),
			self::KIND_DATA_HTML => __( 'data:text/html', 'handl-ai-connector-access-control' ),
			self::KIND_IFRAME    => __( 'iframe', 'handl-ai-connector-access-control' ),
			self::KIND_OBJECT    => __( 'object', 'handl-ai-connector-access-control' ),
			self::KIND_EMBED     => __( 'embed', 'handl-ai-connector-access-control' ),
		);
		$kind = sanitize_key( $kind );

		return $map[ $kind ] ?? $kind;
	}

	/**
	 * Host match against Provider_Map::endpoint_signatures() hosts only.
	 *
	 * @return array{id:string,label:string,host:string}|null
	 */
	public static function match_provider( string $url ): ?array {
		if ( null !== self::$test_provider && '' !== self::$test_provider ) {
			$host = strtolower( (string) ( function_exists( 'wp_parse_url' ) ? wp_parse_url( $url, PHP_URL_HOST ) : parse_url( $url, PHP_URL_HOST ) ) );

			return array(
				'id'    => self::$test_provider,
				'label' => self::$test_provider,
				'host'  => $host,
			);
		}
		if ( '' === $url ) {
			return null;
		}
		$host = strtolower( (string) ( function_exists( 'wp_parse_url' ) ? wp_parse_url( $url, PHP_URL_HOST ) : parse_url( $url, PHP_URL_HOST ) ) );
		if ( '' === $host ) {
			return null;
		}
		if ( ! class_exists( Provider_Map::class, false ) || ! method_exists( Provider_Map::class, 'endpoint_signatures' ) ) {
			return null;
		}
		foreach ( Provider_Map::endpoint_signatures() as $id => $sig ) {
			if ( ! is_array( $sig ) ) {
				continue;
			}
			$hosts = isset( $sig['hosts'] ) && is_array( $sig['hosts'] ) ? $sig['hosts'] : array();
			foreach ( $hosts as $sig_host ) {
				$sig_host = strtolower( trim( (string) $sig_host ) );
				if ( '' === $sig_host ) {
					continue;
				}
				$suffix = '.' . $sig_host;
				if ( $host === $sig_host || ( strlen( $host ) > strlen( $suffix ) && substr( $host, -strlen( $suffix ) ) === $suffix ) ) {
					$label = isset( $sig['label'] ) && '' !== (string) $sig['label'] ? (string) $sig['label'] : (string) $id;

					return array(
						'id'    => (string) $id,
						'label' => $label,
						'host'  => $host,
					);
				}
			}
		}

		return null;
	}

	private static function caller_plugin(): string {
		if ( null !== self::$test_plugin ) {
			return self::$test_plugin;
		}
		if ( class_exists( Attribution::class, false ) ) {
			$resolved = Attribution::resolve_from_backtrace();
			if ( is_array( $resolved ) && ! empty( $resolved['plugin'] ) && is_string( $resolved['plugin'] ) ) {
				return $resolved['plugin'];
			}
		}

		return 'unknown';
	}

	/**
	 * @param array<string,mixed> $event Event.
	 */
	private static function record_event( array $event ): void {
		$event['ts']      = isset( $event['ts'] ) ? (int) $event['ts'] : self::now();
		$event['channel'] = self::CHANNEL;
		if ( ! isset( $event['decision'] ) ) {
			$event['decision'] = 'warn';
		}
		self::$last_events[] = $event;
		if ( count( self::$last_events ) > self::MAX_EVENTS ) {
			self::$last_events = array_slice( self::$last_events, -self::MAX_EVENTS );
		}
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'append_log_event' ) ) {
			Policy::append_log_event( $event );
		}
	}

	/**
	 * @param array<string,mixed> $event Event.
	 * @return array{alerted:bool,reason:string}
	 */
	public static function maybe_alert( array $event ): array {
		$match = isset( $event['quarantine'] ) && is_array( $event['quarantine'] ) ? $event['quarantine'] : null;
		if ( null === $match ) {
			return array( 'alerted' => false, 'reason' => 'no_match' );
		}
		$kinds = isset( $match['kinds'] ) && is_array( $match['kinds'] ) ? self::sanitize_match_kinds( $match['kinds'] ) : array();
		if ( empty( $kinds ) ) {
			return array( 'alerted' => false, 'reason' => 'empty_kinds' );
		}

		$plugin = isset( $event['plugin'] ) ? self::sanitize_plugin( (string) $event['plugin'] ) : '';
		$mode   = self::sanitize_mode( $match['mode'] ?? '' );
		$ts     = isset( $event['ts'] ) ? (int) $event['ts'] : self::now();
		$policy = array();
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' ) ) {
			$got = Policy::get_policy();
			if ( is_array( $got ) ) {
				$policy = $got;
			}
		}

		if ( class_exists( Quiet_Hours::class, false ) && method_exists( Quiet_Hours::class, 'active_window' ) && null !== Quiet_Hours::active_window( $policy, $ts ) ) {
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
		$body    = self::build_body( $plugin, $kinds, $mode );
		$ok      = Alerts::safe_wp_mail( $to, $subject, $body );
		self::$test_mails[] = array(
			'to'      => $to,
			'subject' => $subject,
			'body'    => $body,
		);

		$webhook = isset( $policy['alert_webhook_url'] ) ? Alerts::sanitize_webhook_url( (string) $policy['alert_webhook_url'] ) : '';
		if ( '' !== $webhook ) {
			$hook_ok = Alerts::safe_wp_remote_post(
				$webhook,
				array(
					'type'   => 'handl_aicac_quarantine',
					'plugin' => $plugin,
					'mode'   => $mode,
					'kinds'  => $kinds,
					'site'   => function_exists( 'home_url' ) ? home_url( '/' ) : '',
				),
				'quarantine'
			);
			$ok = $ok || $hook_ok;
		}

		if ( ! $ok ) {
			return array( 'alerted' => false, 'reason' => 'delivery_failed' );
		}

		return array( 'alerted' => true, 'reason' => 'alerted' );
	}

	public static function build_subject( string $plugin ): string {
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$label = self::plugin_label( $plugin );

		return sprintf(
			/* translators: 1: site name, 2: plugin label */
			__( '[%1$s] Active content in an AI reply from %2$s', 'handl-ai-connector-access-control' ),
			$site,
			$label
		);
	}

	/**
	 * @param array<string,int> $kinds Kinds.
	 */
	public static function build_body( string $plugin, array $kinds, string $mode ): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control found active content in this plugin\'s AI reply.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: plugin basename or label */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			self::plugin_label( $plugin )
		);
		if ( self::MODE_HARD === self::sanitize_mode( $mode ) ) {
			$lines[] = __( 'Screen result: Hard (the reply was blocked).', 'handl-ai-connector-access-control' );
		} else {
			$lines[] = __( 'Screen result: Warn (the reply was not changed).', 'handl-ai-connector-access-control' );
		}
		$lines[] = __( 'Pattern types and match counts (matching text is not included in this alert):', 'handl-ai-connector-access-control' );
		$summary = self::receipt_summary( $kinds );
		if ( '' !== $summary ) {
			$lines[] = $summary;
		}
		$lines[] = '';
		$lines[] = __( 'Review this plugin\'s renderer. This alert does not include the reply text.', 'handl-ai-connector-access-control' );

		return implode( "\n", $lines );
	}

	public static function plugin_label( string $plugin ): string {
		$plugin = self::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return __( 'Unknown plugin', 'handl-ai-connector-access-control' );
		}
		if ( function_exists( 'get_plugins' ) ) {
			$all = get_plugins();
			if ( isset( $all[ $plugin ] ) && is_array( $all[ $plugin ] ) && ! empty( $all[ $plugin ]['Name'] ) ) {
				return (string) $all[ $plugin ]['Name'];
			}
		}

		return $plugin;
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
			__( 'Response quarantine', 'handl-ai-connector-access-control' ),
			__( 'Response quarantine', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		$settings   = self::get_settings();
		$can_manage = Caps::user_can_manage();
		$plugins    = self::candidate_plugins();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Response quarantine', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Check AI replies for script tags and other active content before a plugin can add them to the site. Warn is the default, so the reply is not changed. Hard mode blocks the reply for that plugin. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( empty( $settings['enabled'] ) && array() === $settings['plugin_modes'] ) {
			echo '<p>' . esc_html__( 'Response quarantine is off. AI replies are not checked.', 'handl-ai-connector-access-control' ) . '</p>';
		}

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Response quarantine', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Check AI replies for active content.', 'handl-ai-connector-access-control' );
			echo '</label>';
			echo '<p class="description">' . esc_html__( 'Warn logs the pattern type and count. The matching text is never stored. Hard replaces the reply with an error so a plugin cannot echo it.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
		}

		echo '<h2>' . esc_html__( 'What this checks', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<ul>';
		foreach ( array_keys( self::pattern_table() ) as $kind ) {
			echo '<li>' . esc_html( self::kind_label( $kind ) ) . '</li>';
		}
		echo '</ul>';

		if ( array() !== $plugins ) {
			echo '<h2>' . esc_html__( 'Per-plugin mode', 'handl-ai-connector-access-control' ) . '</h2>';
			echo '<p class="description">' . esc_html__( 'Plugins without a setting use Warn when this feature is on.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '<table class="widefat striped" style="max-width:52em;"><thead><tr>';
			echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Mode', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $plugins as $basename => $label ) {
				$current = $settings['plugin_modes'][ $basename ] ?? '';
				if ( '' === $current ) {
					$current = ! empty( $settings['enabled'] ) ? self::MODE_WARN : self::MODE_OFF;
				}
				echo '<tr><td>' . esc_html( $label ) . '<br /><code>' . esc_html( $basename ) . '</code></td><td>';
				if ( $can_manage ) {
					echo '<select name="' . esc_attr( self::POST_MODES ) . '[' . esc_attr( $basename ) . ']">';
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
		}

		if ( $can_manage ) {
			if ( function_exists( 'submit_button' ) ) {
				submit_button( __( 'Save response quarantine', 'handl-ai-connector-access-control' ) );
			} else {
				echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Save response quarantine', 'handl-ai-connector-access-control' ) . '</button></p>';
			}
			echo '</form>';
		}

		echo '</div>';
	}

	/**
	 * @return array<string,string>
	 */
	public static function mode_choices(): array {
		return array(
			self::MODE_WARN => __( 'Warn', 'handl-ai-connector-access-control' ),
			self::MODE_HARD => __( 'Hard', 'handl-ai-connector-access-control' ),
			self::MODE_OFF  => __( 'Off', 'handl-ai-connector-access-control' ),
		);
	}

	/**
	 * @return array<string,string>
	 */
	public static function candidate_plugins(): array {
		$out = array();
		if ( function_exists( 'get_plugins' ) ) {
			foreach ( get_plugins() as $basename => $info ) {
				$plugin = self::sanitize_plugin( (string) $basename );
				if ( '' === $plugin ) {
					continue;
				}
				$label          = is_array( $info ) && isset( $info['Name'] ) ? (string) $info['Name'] : $plugin;
				$out[ $plugin ] = '' !== $label ? $label : $plugin;
			}
		}
		foreach ( array_keys( self::get_settings()['plugin_modes'] ) as $basename ) {
			$plugin = self::sanitize_plugin( (string) $basename );
			if ( '' !== $plugin && ! isset( $out[ $plugin ] ) ) {
				$out[ $plugin ] = $plugin;
			}
		}
		ksort( $out );

		return $out;
	}

	public static function handle_save(): void {
		$back = class_exists( Halt::class, false ) ? Halt::admin_page_url( self::PAGE_SLUG ) : '';
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_manage() ) {
			if ( class_exists( Halt::class, false ) ) {
				Halt::permission_denied( __( 'You do not have permission to save these settings.', 'handl-ai-connector-access-control' ), $back );
			}

			return;
		}
		if ( function_exists( 'check_admin_referer' ) ) {
			check_admin_referer( self::ACTION_SAVE );
		}
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			if ( class_exists( Halt::class, false ) ) {
				Halt::security_check_failed( $back );
			}

			return;
		}
		$raw_modes = isset( $_POST[ self::POST_MODES ] ) && is_array( $_POST[ self::POST_MODES ] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing
			? wp_unslash( $_POST[ self::POST_MODES ] ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			: array();
		self::save_settings(
			array(
				'enabled'      => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'plugin_modes' => is_array( $raw_modes ) ? $raw_modes : array(),
			)
		);
		if ( class_exists( Halt::class, false ) ) {
			Halt::saved( __( 'Response quarantine saved.', 'handl-ai-connector-access-control' ), $back );
		}
	}
}
