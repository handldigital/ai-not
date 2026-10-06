<?php
/**
 * AICAC-THREAT-FEED (#295): signed advisory feed marks Allow rules review-due.
 *
 * Daily cron fetch of a HandL-published signed JSON feed. Matches against
 * installed plugins and observed endpoints/models. Observability only —
 * never mutates allow/deny. Unreachable or invalid feeds leave policy
 * unchanged and record health on this class's option.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Subscribed advisory feed.
 */
final class Threat_Feed {

	public const OPTION_KEY = 'handl_aicac_threat_feed';

	public const CRON_HOOK = 'handl_aicac_threat_feed_daily';

	public const FILTER_URL = 'handl_aicac_threat_feed_url';

	public const FILTER_PUBKEY = 'handl_aicac_threat_feed_pubkey';

	public const FILTER_DISABLED = 'handl_aicac_threat_feed_disabled';

	public const ALERT_KIND = 'threat_feed';

	public const DISABLE_CONSTANT = 'HANDL_AICAC_DISABLE_THREAT_FEED';

	public const DEFAULT_URL = 'https://handldigital.com/advisories/aicac-threat-feed.v1.json';

	/** Pinned Ed25519 public key (hex). Production private key is not in this repo. */
	public const DEFAULT_PUBKEY = 'b13bd60a2b93083e1b23e0e87276e9f82ff0a78ee20c4f8510f01058a2a2e1d1';

	/** Stamp that makes Review_Due treat the rule as immediately due (ts<=0 is dropped). */
	public const DUE_STAMP = 1;

	public const SIGN_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;

	public const HTTP_TIMEOUT = 8;

	public const APPLIED_CAP = 200;

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_action( self::CRON_HOOK, array( self::class, 'cron_fetch' ) );
		self::maybe_schedule();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		delete_option( self::OPTION_KEY );
		unset( $GLOBALS['handl_aicac_threat_feed_http'] );
	}

	public static function maybe_schedule(): void {
		if ( self::is_fetch_disabled() ) {
			return;
		}
		if ( ! function_exists( 'wp_next_scheduled' ) || ! function_exists( 'wp_schedule_event' ) ) {
			return;
		}
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	public static function clear_schedule(): void {
		if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
			wp_clear_scheduled_hook( self::CRON_HOOK );
		}
	}

	public static function cron_fetch(): void {
		self::run();
	}

	public static function is_fetch_disabled(): bool {
		$constant = defined( self::DISABLE_CONSTANT ) && constant( self::DISABLE_CONSTANT );

		return (bool) apply_filters( self::FILTER_DISABLED, $constant );
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::OPTION_KEY, array() ) );
	}

	/**
	 * @param array<string,mixed> $state
	 */
	public static function put_state( array $state ): void {
		update_option( self::OPTION_KEY, self::sanitize_state( $state ), false );
	}

	/**
	 * Fetch, verify, and apply the advisory feed.
	 *
	 * @return array{fetched:bool,not_modified:bool,applied:int,alerted:int,error:string}
	 */
	public static function run( ?int $now = null ): array {
		$now    = null !== $now && $now > 0 ? $now : time();
		$empty  = array(
			'fetched'      => false,
			'not_modified' => false,
			'applied'      => 0,
			'alerted'      => 0,
			'error'        => '',
		);
		$state  = self::get_state();
		$policy = Policy::get_policy();

		if ( self::is_fetch_disabled() ) {
			$state['last_error'] = 'disabled';
			self::put_state( $state );
			$empty['error'] = 'disabled';
			return $empty;
		}

		if ( (int) $state['backoff_until'] > $now ) {
			$empty['error'] = 'backoff';
			return $empty;
		}

		$url = self::feed_url();
		if ( '' === $url ) {
			self::record_failure( $state, $now, 'invalid_url' );
			$empty['error'] = 'invalid_url';
			return $empty;
		}

		$headers = array();
		if ( '' !== $state['etag'] ) {
			$headers['If-None-Match'] = $state['etag'];
		}

		$http = self::http_get( $url, $headers );
		if ( ! $http['ok'] ) {
			self::record_failure( $state, $now, '' !== $http['error'] ? $http['error'] : 'unreachable' );
			$empty['error'] = 'unreachable';
			return $empty;
		}

		if ( 304 === $http['code'] ) {
			self::record_success( $state, $now, $http['etag'] );
			$empty['fetched']      = true;
			$empty['not_modified'] = true;
			return $empty;
		}

		if ( 200 !== $http['code'] || '' === $http['body'] ) {
			self::record_failure( $state, $now, 'unreachable' );
			$empty['error'] = 'unreachable';
			return $empty;
		}

		$verified = self::verify_body( $http['body'] );
		if ( ! $verified['ok'] ) {
			self::record_failure( $state, $now, $verified['error'] );
			$empty['error'] = $verified['error'];
			return $empty;
		}

		self::record_success( $state, $now, $http['etag'] );
		$empty['fetched'] = true;

		$applied_ids = isset( $state['applied_ids'] ) && is_array( $state['applied_ids'] )
			? $state['applied_ids']
			: array();
		$stamps      = Review_Due::get_stamps();
		$stamped     = false;

		foreach ( $verified['advisories'] as $advisory ) {
			$id = (string) $advisory['id'];
			if ( isset( $applied_ids[ $id ] ) ) {
				continue;
			}
			$matched = self::matching_allow_plugins( $policy, $advisory );
			if ( empty( $matched ) ) {
				continue;
			}
			foreach ( $matched as $basename ) {
				$stamps[ $basename ] = self::DUE_STAMP;
				$stamped             = true;
			}
			Review_Due::put_stamps( Review_Due::normalize_stamps( $policy, $stamps ) );
			$fired = self::fire_alert( $policy, $advisory, $matched, $now );
			++$empty['applied'];
			if ( $fired ) {
				++$empty['alerted'];
			}
			$applied_ids[ $id ] = $now;
		}

		if ( $stamped ) {
			Review_Due::put_stamps( Review_Due::normalize_stamps( $policy, $stamps ) );
		}

		$state                = self::get_state();
		$state['applied_ids'] = self::cap_applied_ids( $applied_ids );
		self::put_state( $state );

		return $empty;
	}

	/**
	 * @param mixed $raw
	 * @return array<string,mixed>
	 */
	public static function sanitize_state( $raw ): array {
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}
		$applied = array();
		if ( isset( $raw['applied_ids'] ) && is_array( $raw['applied_ids'] ) ) {
			foreach ( $raw['applied_ids'] as $id => $ts ) {
				$id = sanitize_text_field( (string) $id );
				$ts = (int) $ts;
				if ( '' === $id || $ts <= 0 ) {
					continue;
				}
				$applied[ $id ] = $ts;
			}
		}

		return array(
			'etag'                 => sanitize_text_field( (string) ( $raw['etag'] ?? '' ) ),
			'backoff_until'        => max( 0, (int) ( $raw['backoff_until'] ?? 0 ) ),
			'last_fetch_at'        => max( 0, (int) ( $raw['last_fetch_at'] ?? 0 ) ),
			'last_error'           => sanitize_text_field( (string) ( $raw['last_error'] ?? '' ) ),
			'consecutive_failures' => max( 0, (int) ( $raw['consecutive_failures'] ?? 0 ) ),
			'applied_ids'          => $applied,
		);
	}

	public static function feed_url(): string {
		$url = apply_filters( self::FILTER_URL, self::DEFAULT_URL );
		$url = esc_url_raw( (string) $url, array( 'http', 'https' ) );

		return is_string( $url ) ? $url : '';
	}

	public static function pinned_pubkey(): string {
		$hex = strtolower( preg_replace( '/[^0-9a-f]/', '', (string) apply_filters( self::FILTER_PUBKEY, self::DEFAULT_PUBKEY ) ) ?? '' );
		if ( 64 !== strlen( $hex ) ) {
			return self::DEFAULT_PUBKEY;
		}

		return $hex;
	}

	/**
	 * @return array{ok:bool,advisories:list<array<string,mixed>>,error:string}
	 */
	public static function verify_body( string $body ): array {
		$fail = array(
			'ok'         => false,
			'advisories' => array(),
			'error'      => 'invalid_signature',
		);
		$decoded = json_decode( $body, true );
		if ( ! is_array( $decoded ) ) {
			$fail['error'] = 'invalid_json';
			return $fail;
		}
		$payload = $decoded['payload'] ?? null;
		$sig_hex = isset( $decoded['signature'] ) ? strtolower( (string) $decoded['signature'] ) : '';
		if ( ! is_array( $payload ) || '' === $sig_hex || ! ctype_xdigit( $sig_hex ) ) {
			return $fail;
		}
		$canonical = json_encode( $payload, self::SIGN_FLAGS );
		$pk        = hex2bin( self::pinned_pubkey() );
		$sig       = hex2bin( $sig_hex );
		if ( ! is_string( $canonical ) || ! is_string( $pk ) || ! is_string( $sig ) ) {
			return $fail;
		}
		if ( SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen( $pk ) || SODIUM_CRYPTO_SIGN_BYTES !== strlen( $sig ) ) {
			return $fail;
		}
		if ( ! sodium_crypto_sign_verify_detached( $sig, $canonical, $pk ) ) {
			return $fail;
		}

		$advisories = array();
		$raw_list   = isset( $payload['advisories'] ) && is_array( $payload['advisories'] )
			? $payload['advisories']
			: array();
		foreach ( $raw_list as $row ) {
			$item = self::sanitize_advisory( $row );
			if ( null !== $item ) {
				$advisories[] = $item;
			}
		}

		return array(
			'ok'         => true,
			'advisories' => $advisories,
			'error'      => '',
		);
	}

	/**
	 * @param mixed $raw
	 * @return array<string,mixed>|null
	 */
	public static function sanitize_advisory( $raw ): ?array {
		if ( ! is_array( $raw ) ) {
			return null;
		}
		$id = sanitize_text_field( (string) ( $raw['id'] ?? '' ) );
		if ( '' === $id ) {
			return null;
		}
		$severity = sanitize_key( (string) ( $raw['severity'] ?? 'medium' ) );
		if ( ! in_array( $severity, array( 'low', 'medium', 'high', 'critical' ), true ) ) {
			$severity = 'medium';
		}
		$url = '';
		if ( ! empty( $raw['url'] ) ) {
			$maybe = esc_url_raw( (string) $raw['url'], array( 'http', 'https' ) );
			$url   = is_string( $maybe ) ? $maybe : '';
		}

		return array(
			'id'        => $id,
			'plugins'   => self::sanitize_string_list( $raw['plugins'] ?? array() ),
			'endpoints' => self::sanitize_string_list( $raw['endpoints'] ?? array() ),
			'models'    => self::sanitize_string_list( $raw['models'] ?? array() ),
			'reason'    => sanitize_textarea_field( (string) ( $raw['reason'] ?? '' ) ),
			'severity'  => $severity,
			'url'       => $url,
		);
	}

	/**
	 * @param mixed $raw
	 * @return list<string>
	 */
	private static function sanitize_string_list( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out  = array();
		$seen = array();
		foreach ( $raw as $item ) {
			$value = sanitize_text_field( (string) $item );
			if ( '' === $value ) {
				continue;
			}
			$key = strtolower( $value );
			if ( isset( $seen[ $key ] ) ) {
				continue;
			}
			$seen[ $key ] = true;
			$out[]        = $value;
		}

		return $out;
	}

	/**
	 * Allow-rule plugins affected by this advisory (installed slug and/or observed host/model).
	 *
	 * @param array<string,mixed> $policy
	 * @param array<string,mixed> $advisory
	 * @return list<string>
	 */
	public static function matching_allow_plugins( array $policy, array $advisory ): array {
		$rules = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();
		$observed = self::observed_from_log();
		$matched  = array();

		foreach ( $rules as $basename => $rule ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			if ( '' === $basename || 'allow' !== (string) $rule ) {
				continue;
			}
			$hit = false;
			if ( self::plugin_tokens_hit( $advisory['plugins'], $basename ) ) {
				$hit = true;
			}
			if ( ! $hit && isset( $observed[ $basename ] ) ) {
				if ( self::hosts_hit( $advisory['endpoints'], $observed[ $basename ]['hosts'] ) ) {
					$hit = true;
				} elseif ( self::models_hit( $advisory['models'], $observed[ $basename ]['models'] ) ) {
					$hit = true;
				}
			}
			if ( $hit ) {
				$matched[] = $basename;
			}
		}

		return $matched;
	}

	/**
	 * @param list<string> $tokens
	 */
	public static function plugin_token_matches( string $token, string $basename ): bool {
		$token    = strtolower( str_replace( '\\', '/', trim( $token ) ) );
		$basename = strtolower( str_replace( '\\', '/', $basename ) );
		if ( '' === $token || '' === $basename ) {
			return false;
		}
		if ( $token === $basename ) {
			return true;
		}
		$dir = dirname( $basename );
		if ( '.' !== $dir && $dir === $token ) {
			return true;
		}
		if ( 0 === strpos( $basename, $token . '/' ) ) {
			return true;
		}
		$file = basename( $basename, '.php' );
		if ( $file === $token ) {
			return true;
		}

		return false;
	}

	/**
	 * @param list<string> $tokens
	 */
	private static function plugin_tokens_hit( array $tokens, string $basename ): bool {
		foreach ( $tokens as $token ) {
			if ( self::plugin_token_matches( (string) $token, $basename ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @param list<string> $needles
	 * @param list<string> $haystack
	 */
	private static function hosts_hit( array $needles, array $haystack ): bool {
		$set = array();
		foreach ( $haystack as $host ) {
			$norm = self::normalize_host( (string) $host );
			if ( '' !== $norm ) {
				$set[ $norm ] = true;
			}
		}
		foreach ( $needles as $needle ) {
			$norm = self::normalize_host( (string) $needle );
			if ( '' !== $norm && isset( $set[ $norm ] ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @param list<string> $needles
	 * @param list<string> $haystack
	 */
	private static function models_hit( array $needles, array $haystack ): bool {
		$set = array();
		foreach ( $haystack as $model ) {
			$norm = strtolower( trim( (string) $model ) );
			if ( '' !== $norm ) {
				$set[ $norm ] = true;
			}
		}
		foreach ( $needles as $needle ) {
			$norm = strtolower( trim( (string) $needle ) );
			if ( '' !== $norm && isset( $set[ $norm ] ) ) {
				return true;
			}
		}

		return false;
	}

	public static function normalize_host( string $raw ): string {
		$raw = strtolower( trim( $raw ) );
		if ( '' === $raw ) {
			return '';
		}
		$raw = preg_replace( '#^https?://#', '', $raw ) ?? $raw;
		$raw = explode( '/', $raw )[0];
		$raw = explode( ':', $raw )[0];

		return $raw;
	}

	/**
	 * @return array<string,array{hosts:list<string>,models:list<string>}>
	 */
	public static function observed_from_log(): array {
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		if ( ! is_array( $log ) ) {
			return array();
		}
		$out = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$plugin = Plugin_Profile::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) );
			if ( '' === $plugin ) {
				continue;
			}
			if ( ! isset( $out[ $plugin ] ) ) {
				$out[ $plugin ] = array(
					'hosts'  => array(),
					'models' => array(),
				);
			}
			$host = self::normalize_host( (string) ( $row['host'] ?? '' ) );
			if ( '' !== $host && ! in_array( $host, $out[ $plugin ]['hosts'], true ) ) {
				$out[ $plugin ]['hosts'][] = $host;
			}
			foreach ( array( 'model', 'pin_model', 'forced_model' ) as $field ) {
				$model = strtolower( trim( (string) ( $row[ $field ] ?? '' ) ) );
				if ( '' !== $model && ! in_array( $model, $out[ $plugin ]['models'], true ) ) {
					$out[ $plugin ]['models'][] = $model;
				}
			}
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param array<string,mixed> $advisory
	 * @param list<string>        $matched
	 */
	private static function fire_alert( array $policy, array $advisory, array $matched, int $now ): bool {
		$plugin = $matched[0];
		$to     = Alert_Routing::resolve_email( $policy, '' );
		$ok     = false;
		if ( '' !== $to ) {
			$ok = Alerts::safe_wp_mail(
				$to,
				self::build_subject( $plugin ),
				self::build_body( $plugin, $advisory, $matched )
			);
		}

		$hook_url = Alerts::resolve_webhook( $policy );
		if ( '' !== $hook_url ) {
			Alerts::safe_wp_remote_post(
				$hook_url,
				array(
					'type'        => 'handl_aicac_advisory_alert',
					'advisory_id' => $advisory['id'],
					'plugins'     => $matched,
					'severity'    => $advisory['severity'],
					'reason'      => $advisory['reason'],
					'url'         => $advisory['url'],
					'rules'       => Plugin_Profile::rules_url( $plugin ),
					'site'        => function_exists( 'home_url' ) ? home_url( '/' ) : '',
				),
				self::ALERT_KIND
			);
		}

		Policy::append_log_event(
			array(
				'ts'          => $now,
				'decision'    => 'advisory_match',
				'channel'     => self::ALERT_KIND,
				'plugin'      => $plugin,
				'advisory_id' => $advisory['id'],
				'severity'    => $advisory['severity'],
			)
		);

		return $ok;
	}

	public static function build_subject( string $plugin ): string {
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$label = self::plugin_label( $plugin );

		return sprintf(
			/* translators: 1: site name, 2: plugin name */
			__( '[%1$s] HandL: Review an Allow rule (%2$s)', 'handl-ai-connector-access-control' ),
			$site,
			$label
		);
	}

	/**
	 * @param array<string,mixed> $advisory
	 * @param list<string>        $matched
	 */
	public static function build_body( string $plugin, array $advisory, array $matched ): string {
		$reason = (string) ( $advisory['reason'] ?? '' );
		if ( '' === $reason ) {
			$reason = __( 'Not recorded', 'handl-ai-connector-access-control' );
		}
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control: review your Allow rules', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: plugin display name or basename */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			self::plugin_label( $plugin )
		);
		if ( count( $matched ) > 1 ) {
			$labels = array();
			foreach ( $matched as $basename ) {
				$labels[] = self::plugin_label( $basename );
			}
			$lines[] = sprintf(
				/* translators: %s: comma-separated plugin names, including the first */
				__( 'Plugins to review: %s', 'handl-ai-connector-access-control' ),
				implode( ', ', $labels )
			);
		}
		$lines[] = sprintf(
			/* translators: %s: advisory identifier */
			__( 'Advisory: %s', 'handl-ai-connector-access-control' ),
			(string) ( $advisory['id'] ?? '' )
		);
		$lines[] = sprintf(
			/* translators: %s: severity label */
			__( 'Severity: %s', 'handl-ai-connector-access-control' ),
			(string) ( $advisory['severity'] ?? '' )
		);
		$lines[] = sprintf(
			/* translators: %s: advisory reason */
			__( 'Reason: %s', 'handl-ai-connector-access-control' ),
			$reason
		);
		if ( ! empty( $advisory['url'] ) ) {
			$lines[] = sprintf(
				/* translators: %s: advisory URL */
				__( 'Advisory URL: %s', 'handl-ai-connector-access-control' ),
				(string) $advisory['url']
			);
		}
		$lines[] = '';
		$lines[] = __( 'This plugin has an Allow rule. Review whether it should still be allowed. Your access rules have not changed.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = __( 'Review this plugin’s rules:', 'handl-ai-connector-access-control' );
		$lines[] = Plugin_Profile::rules_url( $plugin );

		return implode( "\n", $lines ) . "\n";
	}

	private static function plugin_label( string $basename ): string {
		if ( function_exists( 'get_plugins' ) ) {
			$plugins = get_plugins();
			if ( isset( $plugins[ $basename ]['Name'] ) && is_string( $plugins[ $basename ]['Name'] ) && '' !== $plugins[ $basename ]['Name'] ) {
				return $plugins[ $basename ]['Name'];
			}
		}

		return $basename;
	}

	/**
	 * @param array<string,mixed> $state
	 */
	private static function record_success( array $state, int $now, string $etag ): void {
		$state['last_fetch_at']        = $now;
		$state['last_error']           = '';
		$state['consecutive_failures'] = 0;
		$state['backoff_until']        = 0;
		if ( '' !== $etag ) {
			$state['etag'] = $etag;
		}
		self::put_state( $state );
	}

	/**
	 * @param array<string,mixed> $state
	 */
	private static function record_failure( array $state, int $now, string $error ): void {
		$fails = (int) $state['consecutive_failures'] + 1;
		$delay = (int) min( DAY_IN_SECONDS, HOUR_IN_SECONDS * ( 2 ** min( $fails - 1, 8 ) ) );
		$state['consecutive_failures'] = $fails;
		$state['last_error']           = '' !== $error ? $error : 'unreachable';
		$state['backoff_until']        = $now + $delay;
		$state['last_fetch_at']        = $now;
		self::put_state( $state );
	}

	/**
	 * @param array<string,int> $applied
	 * @return array<string,int>
	 */
	private static function cap_applied_ids( array $applied ): array {
		if ( count( $applied ) <= self::APPLIED_CAP ) {
			return $applied;
		}
		asort( $applied, SORT_NUMERIC );
		return array_slice( $applied, -1 * self::APPLIED_CAP, null, true );
	}

	/**
	 * @param array<string,string> $headers
	 * @return array{ok:bool,code:int,body:string,etag:string,error:string}
	 */
	private static function http_get( string $url, array $headers ): array {
		$fail = array(
			'ok'    => false,
			'code'  => 0,
			'body'  => '',
			'etag'  => '',
			'error' => 'unreachable',
		);
		if ( isset( $GLOBALS['handl_aicac_threat_feed_http'] ) && is_callable( $GLOBALS['handl_aicac_threat_feed_http'] ) ) {
			$res = call_user_func( $GLOBALS['handl_aicac_threat_feed_http'], $url, array( 'headers' => $headers ) );
		} elseif ( function_exists( 'wp_remote_get' ) ) {
			$res = wp_remote_get(
				$url,
				array(
					'timeout'     => self::HTTP_TIMEOUT,
					'redirection' => 0,
					'headers'     => $headers,
					'user-agent'  => 'HandL-AICAC/' . ( defined( 'HANDL_AICAC_VERSION' ) ? HANDL_AICAC_VERSION : '1' ),
				)
			);
		} else {
			$fail['error'] = 'http_unavailable';
			return $fail;
		}

		if ( is_wp_error( $res ) ) {
			$fail['error'] = $res->get_error_message();
			return $fail;
		}
		if ( ! is_array( $res ) ) {
			return $fail;
		}
		$code = isset( $res['response']['code'] ) ? (int) $res['response']['code'] : 0;
		$body = isset( $res['body'] ) && is_string( $res['body'] ) ? $res['body'] : '';
		$etag = self::header_value( $res['headers'] ?? array(), 'etag' );

		return array(
			'ok'    => true,
			'code'  => $code,
			'body'  => $body,
			'etag'  => $etag,
			'error' => '',
		);
	}

	/**
	 * @param mixed $headers
	 */
	private static function header_value( $headers, string $name ): string {
		$want = strtolower( $name );
		if ( is_object( $headers ) && method_exists( $headers, 'offsetGet' ) ) {
			$val = $headers[ $name ] ?? $headers[ $want ] ?? '';
			return is_string( $val ) ? $val : '';
		}
		if ( ! is_array( $headers ) ) {
			return '';
		}
		foreach ( $headers as $key => $val ) {
			if ( strtolower( (string) $key ) === $want ) {
				if ( is_array( $val ) ) {
					return (string) ( $val[0] ?? '' );
				}
				return (string) $val;
			}
		}

		return '';
	}
}
