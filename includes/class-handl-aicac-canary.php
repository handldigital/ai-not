<?php
/**
 * AICAC-CANARY: honeytoken AI API key (#233).
 *
 * Plants one decoy credential in a provider-looking option. Outbound HTTP that
 * carries the decoy is blocked pre-flight so the fake key never reaches a
 * provider. Trips are high-severity Alert_Routing mail, audit rows, and a
 * dedicated Site Health test.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Credential scrape tripwire.
 */
final class Canary {

	/** Internal registry (token + planted option name). Prefixed so uninstall purge removes it. */
	public const REGISTRY_OPTION = 'handl_aicac_canary';

	/** Last trip payload (no full token). Prefixed. */
	public const LAST_TRIP_OPTION = 'handl_aicac_canary_last_trip';

	/** Transient prefix for per-plugin alert dedupe. */
	public const DEDUPE_TRANSIENT_PREFIX = 'handl_aicac_canary_alert_';

	/** WP_Error code when a decoy-bearing request is blocked. */
	public const BLOCK_ERROR_CODE = 'handl_aicac_canary_blocked';

	/** Activity-log channel. */
	public const CHANNEL = 'canary';

	/** Site Health test slug (registered here; does not edit Site_Health). */
	public const SITE_HEALTH_SLUG = 'handl_aicac_canary';

	/**
	 * Provider-looking option names, first unused wins.
	 * Never overwrite a non-empty option that is not already our decoy.
	 *
	 * @var list<string>
	 */
	public const PLANTED_CANDIDATES = array(
		'openai_api_key',
		'openai_key',
		'openai_api_secret_key',
	);

	/** Fallback planted option if every candidate is occupied by a foreign value. */
	public const PLANTED_FALLBACK = 'wp_openai_live_api_key';

	private static ?Canary $instance = null;

	public static function instance(): Canary {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function init(): void {
		self::ensure_seeded();
		add_filter( 'site_status_tests', array( $this, 'register_site_health_test' ) );
	}

	/**
	 * Fresh install / first boot: exactly one decoy. Idempotent.
	 *
	 * @return array{token:string,option:string,created:int}
	 */
	public static function ensure_seeded(): array {
		$existing = self::registry();
		if ( '' !== $existing['token'] && '' !== $existing['option'] ) {
			return self::replant_if_missing( $existing );
		}

		$token  = self::generate_token();
		$option = self::choose_planted_option( $token );
		$now    = time();

		$state = array(
			'token'   => $token,
			'option'  => $option,
			'created' => $now,
		);
		update_option( self::REGISTRY_OPTION, $state, false );
		self::plant_token( $option, $token );

		return $state;
	}

	/**
	 * @return array{token:string,option:string,created:int}
	 */
	public static function registry(): array {
		$raw = get_option( self::REGISTRY_OPTION, null );
		if ( ! is_array( $raw ) ) {
			return array(
				'token'   => '',
				'option'  => '',
				'created' => 0,
			);
		}

		return array(
			'token'   => is_string( $raw['token'] ?? null ) ? (string) $raw['token'] : '',
			'option'  => is_string( $raw['option'] ?? null ) ? (string) $raw['option'] : '',
			'created' => isset( $raw['created'] ) ? (int) $raw['created'] : 0,
		);
	}

	public static function token(): string {
		return self::registry()['token'];
	}

	public static function planted_option(): string {
		return self::registry()['option'];
	}

	/**
	 * Last-4 mask used in logs, mail, and Site Health. Never the full token.
	 */
	public static function masked_token( ?string $token = null ): string {
		$token = is_string( $token ) ? $token : self::token();
		if ( strlen( $token ) < 8 ) {
			return '••••';
		}
		return substr( $token, 0, 3 ) . '…' . substr( $token, -4 );
	}

	/**
	 * Replace every occurrence of the decoy in a display string.
	 */
	public static function mask_text( string $text ): string {
		$token = self::token();
		if ( '' === $token || false === strpos( $text, $token ) ) {
			return $text;
		}
		return str_replace( $token, self::masked_token( $token ), $text );
	}

	/**
	 * Pre-flight choke point. Returns WP_Error to short-circuit wp_remote_*;
	 * null means "not a canary trip — continue shadow-AI handling".
	 *
	 * @param array<string,mixed> $args wp_remote_* args.
	 * @return \WP_Error|null
	 */
	public static function intercept( array $args, string $url ) {
		$state = self::ensure_seeded();
		$token = $state['token'];
		if ( '' === $token ) {
			return null;
		}

		if ( ! self::payload_contains_token( $args, $url, $token ) ) {
			return null;
		}

		$attrib = class_exists( Attribution::class )
			? Attribution::resolve_from_backtrace()
			: array();
		$plugin = is_string( $attrib['plugin'] ?? null ) ? (string) $attrib['plugin'] : '';

		if ( self::plugin_is_self( $plugin ) ) {
			return null;
		}

		self::record_trip( $plugin, $url, $attrib );
		return self::block_error();
	}

	/**
	 * @return \WP_Error
	 */
	public static function block_error() {
		$message = __(
			'HandL blocked this request because it used a trap AI API key.',
			'handl-ai-connector-access-control'
		);
		return new \WP_Error( self::BLOCK_ERROR_CODE, $message );
	}

	/**
	 * @param array<string,mixed> $tests
	 * @return array<string,mixed>
	 */
	public function register_site_health_test( array $tests ): array {
		if ( ! isset( $tests['direct'] ) || ! is_array( $tests['direct'] ) ) {
			$tests['direct'] = array();
		}
		$tests['direct'][ self::SITE_HEALTH_SLUG ] = array(
			'label' => __( 'HandL AI Access: trap AI key', 'handl-ai-connector-access-control' ),
			'test'  => array( $this, 'run_site_health_test' ),
		);
		return $tests;
	}

	/**
	 * @return array<string,mixed>
	 */
	public function run_site_health_test(): array {
		$trip = self::last_trip();
		$url  = admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=log' );

		if ( ! empty( $trip['ts'] ) ) {
			$plugin = sanitize_text_field( (string) ( $trip['plugin'] ?? '' ) );
			$host   = sanitize_text_field( (string) ( $trip['host'] ?? '' ) );
			$when   = self::format_ts( (int) $trip['ts'] );
			$bits   = array(
				__( 'A plugin sent the trap AI API key HandL planted. The request was blocked and never reached an AI provider.', 'handl-ai-connector-access-control' ),
			);
			if ( '' !== $plugin ) {
				$bits[] = sprintf(
					/* translators: %s: plugin basename */
					__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
					$plugin
				);
			}
			if ( '' !== $host ) {
				$bits[] = sprintf(
					/* translators: %s: request host */
					__( 'Host: %s', 'handl-ai-connector-access-control' ),
					$host
				);
			}
			if ( '' !== $when ) {
				$bits[] = sprintf(
					/* translators: %s: datetime */
					__( 'When: %s', 'handl-ai-connector-access-control' ),
					$when
				);
			}

			return array(
				'label'       => __( 'A plugin used a trap AI API key', 'handl-ai-connector-access-control' ),
				'status'      => 'critical',
				'badge'       => array(
					'label' => __( 'Security', 'handl-ai-connector-access-control' ),
					'color' => 'red',
				),
				'description' => '<p>' . esc_html( implode( ' ', $bits ) ) . '</p>',
				'actions'     => sprintf(
					'<a href="%s">%s</a>',
					esc_url( $url ),
					esc_html__( 'Open HandL AI Access activity', 'handl-ai-connector-access-control' )
				),
				'test'        => self::SITE_HEALTH_SLUG,
			);
		}

		return array(
			'label'       => __( 'Trap AI key has not been used', 'handl-ai-connector-access-control' ),
			'status'      => 'good',
			'badge'       => array(
				'label' => __( 'Security', 'handl-ai-connector-access-control' ),
				'color' => 'blue',
			),
			'description' => '<p>' . esc_html__( 'HandL planted a fake AI API key. No plugin has sent it out.', 'handl-ai-connector-access-control' ) . '</p>',
			'actions'     => '',
			'test'        => self::SITE_HEALTH_SLUG,
		);
	}

	/**
	 * @return array{ts:int,plugin:string,host:string,masked:string}
	 */
	public static function last_trip(): array {
		$raw = get_option( self::LAST_TRIP_OPTION, null );
		if ( ! is_array( $raw ) ) {
			return array(
				'ts'     => 0,
				'plugin' => '',
				'host'   => '',
				'masked' => '',
			);
		}
		return array(
			'ts'     => isset( $raw['ts'] ) ? (int) $raw['ts'] : 0,
			'plugin' => is_string( $raw['plugin'] ?? null ) ? sanitize_text_field( (string) $raw['plugin'] ) : '',
			'host'   => is_string( $raw['host'] ?? null ) ? sanitize_text_field( (string) $raw['host'] ) : '',
			'masked' => is_string( $raw['masked'] ?? null ) ? sanitize_text_field( (string) $raw['masked'] ) : '',
		);
	}

	/**
	 * Planted option name for uninstall purge (not handl_aicac_-prefixed).
	 */
	public static function uninstall_planted_option_key(): string {
		$option = self::planted_option();
		if ( '' === $option ) {
			$raw = get_option( self::REGISTRY_OPTION, null );
			if ( is_array( $raw ) && is_string( $raw['option'] ?? null ) ) {
				$option = (string) $raw['option'];
			}
		}
		if ( '' === $option || 0 === strpos( $option, 'handl_aicac_' ) ) {
			return '';
		}
		return $option;
	}

	/**
	 * Realistic OpenAI-shaped decoy. Never a real credential.
	 */
	public static function generate_token(): string {
		$rand = function_exists( 'wp_generate_password' )
			? wp_generate_password( 32, false, false )
			: bin2hex( random_bytes( 16 ) );
		$rand = preg_replace( '/[^a-zA-Z0-9]/', 'a', (string) $rand );
		if ( ! is_string( $rand ) || strlen( $rand ) < 24 ) {
			$rand = bin2hex( random_bytes( 16 ) );
		}
		return 'sk-htlcan' . $rand;
	}

	/**
	 * @param array<string,mixed> $args
	 */
	public static function payload_contains_token( array $args, string $url, string $token ): bool {
		if ( '' === $token ) {
			return false;
		}

		$haystack = self::flatten_payload( $args, $url );
		return false !== strpos( $haystack, $token );
	}

	/**
	 * @param array<string,mixed>               $args
	 * @param array<string,mixed>               $attrib
	 */
	private static function record_trip( string $plugin, string $url, array $attrib ): void {
		$parsed = function_exists( 'wp_parse_url' ) ? wp_parse_url( $url ) : parse_url( $url );
		$host   = '';
		$path   = '/';
		if ( is_array( $parsed ) ) {
			$host = isset( $parsed['host'] ) ? strtolower( rtrim( (string) $parsed['host'], '.' ) ) : '';
			$path = isset( $parsed['path'] ) && '' !== (string) $parsed['path'] ? (string) $parsed['path'] : '/';
		}

		$now    = time();
		$masked = self::masked_token();

		$trip = array(
			'ts'     => $now,
			'plugin' => $plugin,
			'host'   => $host,
			'masked' => $masked,
		);
		update_option( self::LAST_TRIP_OPTION, $trip, false );

		$event = array(
			'channel'        => self::CHANNEL,
			'ts'             => $now,
			'plugin'         => '' !== $plugin ? $plugin : null,
			'file'           => $attrib['file'] ?? null,
			'caller'         => $attrib['method'] ?? null,
			'host'           => $host,
			'decision'       => 'deny',
			'denial_reason'  => 'canary_trip',
			'operation'      => 'direct_http',
			'uri'            => $path,
			'user_id'        => function_exists( 'get_current_user_id' ) ? get_current_user_id() : 0,
			'count'          => 1,
			'canary_masked'  => $masked,
		);

		if ( class_exists( Policy::class ) ) {
			Policy::append_log_event( $event );
		}

		self::maybe_alert( $plugin, $host, $now, $masked );
	}

	private static function maybe_alert( string $plugin, string $host, int $now, string $masked ): void {
		$dedupe_key = self::DEDUPE_TRANSIENT_PREFIX . md5( '' !== $plugin ? $plugin : '__unknown__' );
		if ( false !== get_transient( $dedupe_key ) ) {
			return;
		}

		$ttl = defined( 'HOUR_IN_SECONDS' ) ? HOUR_IN_SECONDS : 3600;
		set_transient( $dedupe_key, $now, $ttl );

		if ( ! class_exists( Alerts::class ) || ! class_exists( Alert_Routing::class ) ) {
			return;
		}

		$policy = class_exists( Policy::class ) ? Policy::get_policy() : array();
		$to     = Alert_Routing::resolve_email( is_array( $policy ) ? $policy : array(), 'canary' );
		if ( '' === $to ) {
			return;
		}

		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';

		$subject = sprintf(
			/* translators: %s: site name */
			__( '[%s] HandL blocked a trap AI key', 'handl-ai-connector-access-control' ),
			$site
		);

		$lines   = array();
		$lines[] = __( 'A plugin sent a fake AI API key that HandL planted as a trap. The request was blocked and never reached an AI provider.', 'handl-ai-connector-access-control' );
		if ( '' !== $plugin ) {
			$lines[] = sprintf(
				/* translators: %s: plugin basename */
				__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
				$plugin
			);
		}
		if ( '' !== $host ) {
			$lines[] = sprintf(
				/* translators: %s: request host */
				__( 'Host: %s', 'handl-ai-connector-access-control' ),
				$host
			);
		}
		$lines[] = sprintf(
			/* translators: %s: datetime */
			__( 'When: %s', 'handl-ai-connector-access-control' ),
			self::format_ts( $now )
		);
		$lines[] = sprintf(
			/* translators: %s: masked trap key */
			__( 'Trap key: %s', 'handl-ai-connector-access-control' ),
			$masked
		);

		Alerts::safe_wp_mail( $to, $subject, implode( "\n", $lines ) );
	}

	/**
	 * @param array<string,mixed> $args
	 */
	private static function flatten_payload( array $args, string $url ): string {
		$parts = array();
		if ( '' !== $url ) {
			$parts[] = $url;
		}

		if ( isset( $args['headers'] ) ) {
			$parts[] = self::stringify( $args['headers'] );
		}
		if ( isset( $args['body'] ) ) {
			$parts[] = self::stringify( $args['body'] );
		}
		if ( isset( $args['cookies'] ) ) {
			$parts[] = self::stringify( $args['cookies'] );
		}

		$hay = implode( "\n", $parts );
		if ( strlen( $hay ) > 65536 ) {
			$hay = substr( $hay, 0, 65536 );
		}
		return $hay;
	}

	/**
	 * @param mixed $value
	 */
	private static function stringify( $value ): string {
		if ( is_string( $value ) ) {
			return $value;
		}
		if ( is_array( $value ) ) {
			$chunks = array();
			foreach ( $value as $k => $v ) {
				$chunks[] = (string) $k . ':' . self::stringify( $v );
			}
			return implode( "\n", $chunks );
		}
		if ( is_scalar( $value ) ) {
			return (string) $value;
		}
		return '';
	}

	/**
	 * Re-plant the existing decoy if the option was deleted. Never overwrite a
	 * foreign value (a real plugin key that landed in the same option name).
	 *
	 * @param array{token:string,option:string,created:int} $state
	 * @return array{token:string,option:string,created:int}
	 */
	private static function replant_if_missing( array $state ): array {
		$token  = $state['token'];
		$option = $state['option'];
		if ( '' === $token || '' === $option ) {
			return $state;
		}

		$current = get_option( $option, null );
		if ( false === $current || null === $current || '' === $current ) {
			update_option( $option, $token, false );
			return $state;
		}
		if ( $current === $token ) {
			return $state;
		}

		if ( $option === self::PLANTED_FALLBACK ) {
			return $state;
		}

		$fallback = get_option( self::PLANTED_FALLBACK, null );
		if ( false !== $fallback && null !== $fallback && '' !== $fallback && $fallback !== $token ) {
			return $state;
		}

		$state['option'] = self::PLANTED_FALLBACK;
		update_option( self::REGISTRY_OPTION, $state, false );
		update_option( self::PLANTED_FALLBACK, $token, false );
		return $state;
	}

	private static function plant_token( string $option, string $token ): void {
		if ( '' === $option || '' === $token ) {
			return;
		}
		$current = get_option( $option, null );
		if ( false !== $current && null !== $current && '' !== $current && $current !== $token ) {
			return;
		}
		if ( $current === $token ) {
			return;
		}
		update_option( $option, $token, false );
	}

	private static function choose_planted_option( string $token ): string {
		foreach ( self::PLANTED_CANDIDATES as $candidate ) {
			$current = get_option( $candidate, null );
			if ( false === $current || null === $current || '' === $current || $current === $token ) {
				return $candidate;
			}
		}
		return self::PLANTED_FALLBACK;
	}

	private static function plugin_is_self( string $plugin ): bool {
		if ( '' === $plugin ) {
			return false;
		}
		$self = 'handl-ai-connector-access-control/handl-ai-connector-access-control.php';
		if ( defined( 'HANDL_AICAC_FILE' ) && function_exists( 'plugin_basename' ) ) {
			$base = plugin_basename( HANDL_AICAC_FILE );
			if ( is_string( $base ) && '' !== $base ) {
				$self = $base;
			}
		}
		return $plugin === $self;
	}

	private static function format_ts( int $ts ): string {
		if ( $ts <= 0 ) {
			return '';
		}
		if ( function_exists( 'wp_date' ) ) {
			$format = trim(
				(string) get_option( 'date_format', 'Y-m-d' ) . ' ' . (string) get_option( 'time_format', 'H:i' )
			);
			$label = wp_date( $format, $ts );
			if ( is_string( $label ) && '' !== $label ) {
				return $label;
			}
		}
		return gmdate( 'Y-m-d H:i', $ts ) . ' UTC';
	}
}
