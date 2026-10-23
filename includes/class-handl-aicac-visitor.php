<?php
/**
 * AICAC-VISITOR (#373): anonymous (logged-out) visitor AI caps.
 *
 * Throttles or blocks governed AI Client calls made on behalf of logged-out
 * visitors (chat widgets, public forms, front-end generators). Identity is a
 * salted daily hash of client IP + user-agent family: the raw IP is never
 * stored, and the salt rotates every site-local day so buckets cannot be
 * linked across days. Per-bucket hour/day counters, an optional block-all
 * switch, soft-warn at 80%, roster + CSV + WP-CLI. Logged-in users are exempt
 * (their limits are USER-QUOTA / policy). OFF by default.
 * Deny at the shared pre-flight gate (priority 2).
 * No admin.php / policy.php / cost.php / rate-cap.php edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Anonymous visitor caps + hashed bucket identity + roster.
 */
final class Visitor {

	public const REASON = 'visitor_limit';

	public const REASON_BLOCK_ALL = 'anonymous_blocked';

	public const SETTINGS_OPTION = 'handl_aicac_visitor';

	/** Daily salt: array{day_key:string,salt:string}. */
	public const SALT_OPTION = 'handl_aicac_visitor_salt';

	/** Durable counters: "{bucket}|hour|{YmdH}" / "{bucket}|day|{Ymd}" => int. */
	public const COUNTS_OPTION = 'handl_aicac_visitor_counts';

	/** Per-bucket roster stats: bucket => calls/denies/tokens/est_usd/last_ts/last_provider. */
	public const STATS_OPTION = 'handl_aicac_visitor_stats';

	/** Fired soft-warns: "{bucket}|hour|{YmdH}" / "{bucket}|day|{Ymd}" => meta. */
	public const WARNED_OPTION = 'handl_aicac_visitor_warned';

	public const FILTER_PRIORITY = 2;

	public const SOFT_WARN_RATIO = 0.8;

	public const MAX_CAP = 1000000;

	public const PAGE_SLUG = 'handl-aicac-visitor';

	public const CHANNEL = 'visitor';

	public const CHANNEL_WARN = 'visitor_warn';

	/** Filter: name of the $_SERVER key that carries the client IP (default REMOTE_ADDR). */
	public const FILTER_IP_HEADER = 'handl_aicac_visitor_ip_header';

	public const STATS_CAP = 500;

	/** Hard ceiling on counter-map entries so an IP flood cannot bloat the option. */
	public const COUNTS_CAP = 5000;

	public const POST_PRESENT = 'handl_aicac_visitor_present';

	public const POST_ENABLED = 'handl_aicac_visitor_enabled';

	public const POST_BLOCK_ALL = 'handl_aicac_visitor_block_anonymous';

	public const POST_CAP_HOUR = 'handl_aicac_visitor_cap_hour';

	public const POST_CAP_DAY = 'handl_aicac_visitor_cap_day';

	public const ACTION_SAVE = 'handl_aicac_visitor_save';

	public const ACTION_RESET = 'handl_aicac_visitor_reset';

	public const WINDOW_HOUR = 'hour';

	public const WINDOW_DAY = 'day';

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_filter( 'wp_ai_client_prevent_prompt', array( self::class, 'maybe_prevent_prompt' ), self::FILTER_PRIORITY, 2 );
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_RESET, array( self::class, 'handle_reset' ) );
		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::SALT_OPTION );
		delete_option( self::COUNTS_OPTION );
		delete_option( self::STATS_OPTION );
		delete_option( self::WARNED_OPTION );
		unset(
			$GLOBALS['handl_aicac_test_visitor_ip'],
			$GLOBALS['handl_aicac_test_visitor_ua'],
			$GLOBALS['handl_aicac_test_visitor_salt']
		);
	}

	/**
	 * Test helper: pin the anonymous identity inputs.
	 */
	public static function set_test_identity( string $ip, string $ua = '' ): void {
		$GLOBALS['handl_aicac_test_visitor_ip'] = $ip;
		$GLOBALS['handl_aicac_test_visitor_ua'] = $ua;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{enabled:bool,block_anonymous:bool,cap_hour:?int,cap_day:?int}
	 */
	public static function defaults(): array {
		return array(
			'enabled'         => false,
			'block_anonymous' => false,
			'cap_hour'        => null,
			'cap_day'         => null,
		);
	}

	/**
	 * @return array{enabled:bool,block_anonymous:bool,cap_hour:?int,cap_day:?int}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,block_anonymous:bool,cap_hour:?int,cap_day:?int}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled'         => ! empty( $raw['enabled'] ),
			'block_anonymous' => ! empty( $raw['block_anonymous'] ),
			'cap_hour'        => self::sanitize_cap( $raw['cap_hour'] ?? null ),
			'cap_day'         => self::sanitize_cap( $raw['cap_day'] ?? null ),
		);
	}

	/**
	 * Empty / non-positive → unlimited (null). Positive int capped at MAX_CAP.
	 *
	 * @param mixed $raw Raw cap.
	 */
	public static function sanitize_cap( $raw ): ?int {
		if ( null === $raw || false === $raw ) {
			return null;
		}
		if ( is_string( $raw ) ) {
			$raw = trim( $raw );
			if ( '' === $raw ) {
				return null;
			}
		}
		if ( ! is_numeric( $raw ) ) {
			return null;
		}
		$v = (int) $raw;
		if ( $v <= 0 ) {
			return null;
		}
		if ( $v > self::MAX_CAP ) {
			$v = self::MAX_CAP;
		}

		return $v;
	}

	/**
	 * @param array<string,mixed> $settings Settings.
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

	/**
	 * Gate is live only when switched on AND something would actually act.
	 *
	 * @param array<string,mixed>|null $settings Optional settings override.
	 */
	public static function is_enabled( ?array $settings = null ): bool {
		$settings = is_array( $settings ) ? self::sanitize_settings( $settings ) : self::get_settings();
		if ( empty( $settings['enabled'] ) ) {
			return false;
		}

		return ! empty( $settings['block_anonymous'] )
			|| null !== $settings['cap_hour']
			|| null !== $settings['cap_day'];
	}

	/* ---------------------------------------------------------------------
	 * Identity (salted daily hash — raw IP never persisted)
	 * ------------------------------------------------------------------ */

	/**
	 * Client IP for this request. Header is filterable for sites behind a proxy / CDN.
	 */
	public static function resolve_client_ip(): string {
		$raw = '';
		if ( isset( $GLOBALS['handl_aicac_test_visitor_ip'] ) && is_string( $GLOBALS['handl_aicac_test_visitor_ip'] ) ) {
			$raw = $GLOBALS['handl_aicac_test_visitor_ip'];
		} else {
			$header = apply_filters( self::FILTER_IP_HEADER, 'REMOTE_ADDR' );
			$header = is_string( $header ) ? preg_replace( '/[^A-Za-z0-9_]/', '', $header ) : '';
			if ( null === $header || '' === $header ) {
				$header = 'REMOTE_ADDR';
			}
			if ( isset( $_SERVER[ $header ] ) && is_string( $_SERVER[ $header ] ) ) {
				$raw = (string) wp_unslash( $_SERVER[ $header ] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized below.
			} elseif ( isset( $_SERVER['REMOTE_ADDR'] ) && is_string( $_SERVER['REMOTE_ADDR'] ) ) {
				$raw = (string) wp_unslash( $_SERVER['REMOTE_ADDR'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized below.
			}
		}

		// X-Forwarded-For style lists: the left-most entry is the original client.
		$parts = explode( ',', $raw );
		$ip    = trim( (string) $parts[0] );
		$ip    = sanitize_text_field( $ip );
		if ( strlen( $ip ) > 64 ) {
			$ip = substr( $ip, 0, 64 );
		}

		return '' === $ip ? '0.0.0.0' : $ip;
	}

	/**
	 * Raw user-agent for this request (test-overridable).
	 */
	public static function resolve_user_agent(): string {
		if ( isset( $GLOBALS['handl_aicac_test_visitor_ua'] ) && is_string( $GLOBALS['handl_aicac_test_visitor_ua'] ) ) {
			return $GLOBALS['handl_aicac_test_visitor_ua'];
		}
		if ( isset( $_SERVER['HTTP_USER_AGENT'] ) && is_string( $_SERVER['HTTP_USER_AGENT'] ) ) {
			return sanitize_text_field( (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) );
		}

		return '';
	}

	/**
	 * Coarse UA family: "bot" for crawlers / scripted clients, else the first product token.
	 */
	public static function ua_family( ?string $ua = null ): string {
		$ua = null !== $ua ? $ua : self::resolve_user_agent();
		$ua = strtolower( trim( $ua ) );
		if ( '' === $ua ) {
			return 'unknown';
		}
		if ( 1 === preg_match( '/bot|crawl|spider|slurp|curl|wget|python-requests/', $ua ) ) {
			return 'bot';
		}
		if ( 1 === preg_match( '/^([a-z0-9._+-]+)/', $ua, $m ) ) {
			return substr( $m[1], 0, 32 );
		}

		return 'unknown';
	}

	/**
	 * Per-day random salt. Regenerated when the site-local day changes.
	 */
	public static function daily_salt( ?int $now = null ): string {
		$now     = null !== $now ? (int) $now : Clock::now();
		$bounds  = Rate_Cap::window_bounds( Rate_Cap::WINDOW_DAY, $now );
		$day_key = (string) $bounds['key'];

		$stored = get_option( self::SALT_OPTION, array() );
		if ( is_array( $stored )
			&& isset( $stored['day_key'], $stored['salt'] )
			&& (string) $stored['day_key'] === $day_key
			&& is_string( $stored['salt'] )
			&& '' !== $stored['salt'] ) {
			return $stored['salt'];
		}

		if ( isset( $GLOBALS['handl_aicac_test_visitor_salt'] ) && is_string( $GLOBALS['handl_aicac_test_visitor_salt'] ) && '' !== $GLOBALS['handl_aicac_test_visitor_salt'] ) {
			$salt = $GLOBALS['handl_aicac_test_visitor_salt'];
		} else {
			$salt = bin2hex( random_bytes( 32 ) );
		}

		update_option(
			self::SALT_OPTION,
			array(
				'day_key' => $day_key,
				'salt'    => $salt,
			),
			false
		);

		return $salt;
	}

	/**
	 * Opaque bucket id: 16 hex of HMAC(ip|ua_family, daily salt).
	 */
	public static function bucket_hash( ?int $now = null, ?string $ip = null, ?string $ua = null ): string {
		$now    = null !== $now ? (int) $now : Clock::now();
		$ip     = null !== $ip ? $ip : self::resolve_client_ip();
		$family = self::ua_family( $ua );

		return substr( hash_hmac( 'sha256', $ip . '|' . $family, self::daily_salt( $now ) ), 0, 16 );
	}

	public static function sanitize_bucket( string $bucket ): string {
		$bucket = strtolower( trim( $bucket ) );
		$bucket = preg_replace( '/[^a-f0-9]/', '', $bucket ) ?? '';

		return substr( $bucket, 0, 16 );
	}

	/* ---------------------------------------------------------------------
	 * Durable counters (same shape as Rate_Cap, keyed by bucket)
	 * ------------------------------------------------------------------ */

	public static function count_key( string $bucket, string $window, string $window_key ): string {
		$bucket = self::sanitize_bucket( $bucket );
		$window = self::WINDOW_DAY === $window ? self::WINDOW_DAY : self::WINDOW_HOUR;

		return $bucket . '|' . $window . '|' . sanitize_text_field( $window_key );
	}

	/**
	 * @return array<string,int>
	 */
	public static function get_counts_map(): array {
		return self::sanitize_counts_map( get_option( self::COUNTS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw map.
	 * @return array<string,int>
	 */
	public static function sanitize_counts_map( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $key => $n ) {
			$key = sanitize_text_field( (string) $key );
			if ( '' === $key || ! is_numeric( $n ) ) {
				continue;
			}
			$v = (int) $n;
			if ( $v < 0 ) {
				$v = 0;
			}
			$out[ $key ] = $v;
		}

		return $out;
	}

	/**
	 * @param array<string,int> $map Counter map.
	 */
	public static function save_counts_map( array $map, ?int $now = null ): void {
		$map = self::sanitize_counts_map( $map );
		$map = self::prune_counts_map( $map, $now );
		if ( empty( $map ) ) {
			delete_option( self::COUNTS_OPTION );
			return;
		}
		update_option( self::COUNTS_OPTION, $map, false );
	}

	/**
	 * Drop stale window keys when the map grows large; hard-bound what remains.
	 *
	 * @param array<string,int> $map Counter map.
	 * @return array<string,int>
	 */
	public static function prune_counts_map( array $map, ?int $now = null ): array {
		if ( count( $map ) <= 500 ) {
			return $map;
		}
		$now  = null !== $now ? (int) $now : Clock::now();
		$hour = Rate_Cap::window_bounds( Rate_Cap::WINDOW_HOUR, $now );
		$day  = Rate_Cap::window_bounds( Rate_Cap::WINDOW_DAY, $now );
		$keep = array();
		foreach ( $map as $key => $n ) {
			$parts = explode( '|', (string) $key );
			if ( count( $parts ) < 3 ) {
				continue;
			}
			$window = $parts[ count( $parts ) - 2 ];
			$suffix = $parts[ count( $parts ) - 1 ];
			if ( self::WINDOW_HOUR === $window && $suffix === $hour['key'] ) {
				$keep[ $key ] = $n;
				continue;
			}
			if ( self::WINDOW_DAY === $window && $suffix === $day['key'] ) {
				$keep[ $key ] = $n;
			}
		}

		if ( count( $keep ) > self::COUNTS_CAP ) {
			arsort( $keep );
			$keep = array_slice( $keep, 0, self::COUNTS_CAP, true );
		}

		return $keep;
	}

	public static function get_window_count( string $bucket, string $window, string $window_key ): int {
		$key = self::count_key( $bucket, $window, $window_key );
		$map = self::get_counts_map();

		return isset( $map[ $key ] ) ? (int) $map[ $key ] : 0;
	}

	/**
	 * Test helper: set an absolute window count.
	 */
	public static function set_window_count( string $bucket, string $window, string $window_key, int $count ): void {
		$bucket = self::sanitize_bucket( $bucket );
		if ( '' === $bucket ) {
			return;
		}
		$map = self::get_counts_map();
		$key = self::count_key( $bucket, $window, $window_key );
		if ( $count <= 0 ) {
			unset( $map[ $key ] );
		} else {
			$map[ $key ] = $count;
		}
		self::save_counts_map( $map );
	}

	/**
	 * Increment durable hour + day counters for one allowed anonymous attempt.
	 *
	 * @return array{hour:int,day:int}
	 */
	public static function record_attempt( string $bucket, ?int $now = null ): array {
		$bucket = self::sanitize_bucket( $bucket );
		if ( '' === $bucket ) {
			return array(
				'hour' => 0,
				'day'  => 0,
			);
		}
		$now  = null !== $now ? (int) $now : Clock::now();
		$hour = Rate_Cap::window_bounds( Rate_Cap::WINDOW_HOUR, $now );
		$day  = Rate_Cap::window_bounds( Rate_Cap::WINDOW_DAY, $now );
		$map  = self::get_counts_map();

		$hour_key         = self::count_key( $bucket, self::WINDOW_HOUR, $hour['key'] );
		$day_key          = self::count_key( $bucket, self::WINDOW_DAY, $day['key'] );
		$map[ $hour_key ] = ( isset( $map[ $hour_key ] ) ? (int) $map[ $hour_key ] : 0 ) + 1;
		$map[ $day_key ]  = ( isset( $map[ $day_key ] ) ? (int) $map[ $day_key ] : 0 ) + 1;
		self::save_counts_map( $map, $now );

		return array(
			'hour' => (int) ( $map[ $hour_key ] ?? 0 ),
			'day'  => (int) ( $map[ $day_key ] ?? 0 ),
		);
	}

	public static function clear_counts(): void {
		delete_option( self::COUNTS_OPTION );
	}

	/**
	 * Evaluate hour + day caps for one bucket against durable counters.
	 *
	 * @param array<string,mixed> $settings Visitor settings.
	 * @return array{
	 *   prevent:bool,
	 *   reason:string,
	 *   window:string,
	 *   limit:?int,
	 *   count:int,
	 *   soft_warn:bool,
	 *   soft_window:string,
	 *   soft_limit:?int,
	 *   soft_count:int,
	 *   hour:array{limit:?int,count:int,key:string,start:int,end:int},
	 *   day:array{limit:?int,count:int,key:string,start:int,end:int}
	 * }
	 */
	public static function evaluate( array $settings, string $bucket, ?int $now = null ): array {
		$settings = self::sanitize_settings( $settings );
		$bucket   = self::sanitize_bucket( $bucket );
		$now      = null !== $now ? (int) $now : Clock::now();

		$hour_bounds = Rate_Cap::window_bounds( Rate_Cap::WINDOW_HOUR, $now );
		$day_bounds  = Rate_Cap::window_bounds( Rate_Cap::WINDOW_DAY, $now );

		$hour_count = '' !== $bucket
			? self::get_window_count( $bucket, self::WINDOW_HOUR, $hour_bounds['key'] )
			: 0;
		$day_count  = '' !== $bucket
			? self::get_window_count( $bucket, self::WINDOW_DAY, $day_bounds['key'] )
			: 0;

		$hour = array(
			'limit' => $settings['cap_hour'],
			'count' => $hour_count,
			'key'   => $hour_bounds['key'],
			'start' => $hour_bounds['start'],
			'end'   => $hour_bounds['end'],
		);
		$day  = array(
			'limit' => $settings['cap_day'],
			'count' => $day_count,
			'key'   => $day_bounds['key'],
			'start' => $day_bounds['start'],
			'end'   => $day_bounds['end'],
		);

		$out = array(
			'prevent'     => false,
			'reason'      => '',
			'window'      => '',
			'limit'       => null,
			'count'       => 0,
			'soft_warn'   => false,
			'soft_window' => '',
			'soft_limit'  => null,
			'soft_count'  => 0,
			'hour'        => $hour,
			'day'         => $day,
		);

		if ( '' === $bucket ) {
			return $out;
		}

		foreach ( array( self::WINDOW_HOUR => $hour, self::WINDOW_DAY => $day ) as $window => $snap ) {
			$limit = $snap['limit'];
			if ( null === $limit ) {
				continue;
			}
			$count = (int) $snap['count'];
			if ( $count >= $limit ) {
				$out['prevent'] = true;
				$out['reason']  = self::REASON;
				$out['window']  = $window;
				$out['limit']   = $limit;
				$out['count']   = $count;

				return $out;
			}
		}

		foreach ( array( self::WINDOW_HOUR => $hour, self::WINDOW_DAY => $day ) as $window => $snap ) {
			$limit = $snap['limit'];
			if ( null === $limit ) {
				continue;
			}
			$count = (int) $snap['count'];
			if ( $count >= Rate_Cap::soft_warn_threshold( (int) $limit ) ) {
				$out['soft_warn']   = true;
				$out['soft_window'] = $window;
				$out['soft_limit']  = $limit;
				$out['soft_count']  = $count;
				break;
			}
		}

		return $out;
	}

	/* ---------------------------------------------------------------------
	 * Per-bucket stats (roster)
	 * ------------------------------------------------------------------ */

	/**
	 * @return array<string,array{calls:int,denies:int,input_tokens:int,output_tokens:int,est_usd:float,last_ts:int,last_provider:string}>
	 */
	public static function get_stats_map(): array {
		return self::sanitize_stats_map( get_option( self::STATS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw stats.
	 * @return array<string,array{calls:int,denies:int,input_tokens:int,output_tokens:int,est_usd:float,last_ts:int,last_provider:string}>
	 */
	public static function sanitize_stats_map( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $bucket => $row ) {
			$bucket = self::sanitize_bucket( (string) $bucket );
			if ( '' === $bucket || ! is_array( $row ) ) {
				continue;
			}
			$out[ $bucket ] = array(
				'calls'         => isset( $row['calls'] ) ? max( 0, (int) $row['calls'] ) : 0,
				'denies'        => isset( $row['denies'] ) ? max( 0, (int) $row['denies'] ) : 0,
				'input_tokens'  => isset( $row['input_tokens'] ) ? max( 0, (int) $row['input_tokens'] ) : 0,
				'output_tokens' => isset( $row['output_tokens'] ) ? max( 0, (int) $row['output_tokens'] ) : 0,
				'est_usd'       => isset( $row['est_usd'] ) ? max( 0.0, (float) $row['est_usd'] ) : 0.0,
				'last_ts'       => isset( $row['last_ts'] ) ? max( 0, (int) $row['last_ts'] ) : 0,
				'last_provider' => isset( $row['last_provider'] ) ? sanitize_key( (string) $row['last_provider'] ) : '',
			);
		}

		return $out;
	}

	/**
	 * @param array<string,array<string,mixed>> $map Stats map.
	 */
	public static function save_stats_map( array $map ): void {
		$map = self::sanitize_stats_map( $map );
		if ( count( $map ) > self::STATS_CAP ) {
			uasort(
				$map,
				static function ( array $a, array $b ): int {
					return ( (int) $b['last_ts'] ) <=> ( (int) $a['last_ts'] );
				}
			);
			$map = array_slice( $map, 0, self::STATS_CAP, true );
		}
		if ( empty( $map ) ) {
			delete_option( self::STATS_OPTION );
			return;
		}
		update_option( self::STATS_OPTION, $map, false );
	}

	/**
	 * Record one allowed call for the roster. Tokens/cost accumulate when the snapshot carries them.
	 *
	 * @param array<string,mixed> $snapshot Prompt_Snapshot fields (may be empty).
	 */
	public static function touch_stats( string $bucket, array $snapshot = array(), ?int $now = null ): void {
		$bucket = self::sanitize_bucket( $bucket );
		if ( '' === $bucket ) {
			return;
		}
		$now = null !== $now ? (int) $now : Clock::now();
		$map = self::get_stats_map();
		$row = $map[ $bucket ] ?? self::empty_stats_row();

		++$row['calls'];
		$row['last_ts'] = $now;
		$provider       = isset( $snapshot['provider'] ) && is_string( $snapshot['provider'] ) ? sanitize_key( $snapshot['provider'] ) : '';
		if ( '' !== $provider ) {
			$row['last_provider'] = $provider;
		}

		$in  = isset( $snapshot['input_tokens'] ) && is_numeric( $snapshot['input_tokens'] ) ? max( 0, (int) $snapshot['input_tokens'] ) : 0;
		$out = isset( $snapshot['output_tokens'] ) && is_numeric( $snapshot['output_tokens'] ) ? max( 0, (int) $snapshot['output_tokens'] ) : 0;
		if ( $in > 0 || $out > 0 ) {
			$row['input_tokens']  += $in;
			$row['output_tokens'] += $out;
			$usd                   = self::estimate_usd( $in, $out, '' !== $provider ? $provider : $row['last_provider'] );
			if ( null !== $usd ) {
				$row['est_usd'] += $usd;
			}
		}

		$map[ $bucket ] = $row;
		self::save_stats_map( $map );
	}

	/**
	 * Record one denied call for the roster.
	 *
	 * @param array<string,mixed> $snapshot Prompt_Snapshot fields (may be empty).
	 */
	public static function touch_deny_stats( string $bucket, array $snapshot = array(), ?int $now = null ): void {
		$bucket = self::sanitize_bucket( $bucket );
		if ( '' === $bucket ) {
			return;
		}
		$now = null !== $now ? (int) $now : Clock::now();
		$map = self::get_stats_map();
		$row = $map[ $bucket ] ?? self::empty_stats_row();

		++$row['denies'];
		$row['last_ts'] = $now;
		$provider       = isset( $snapshot['provider'] ) && is_string( $snapshot['provider'] ) ? sanitize_key( $snapshot['provider'] ) : '';
		if ( '' !== $provider ) {
			$row['last_provider'] = $provider;
		}

		$map[ $bucket ] = $row;
		self::save_stats_map( $map );
	}

	/**
	 * @return array{calls:int,denies:int,input_tokens:int,output_tokens:int,est_usd:float,last_ts:int,last_provider:string}
	 */
	private static function empty_stats_row(): array {
		return array(
			'calls'         => 0,
			'denies'        => 0,
			'input_tokens'  => 0,
			'output_tokens' => 0,
			'est_usd'       => 0.0,
			'last_ts'       => 0,
			'last_provider' => '',
		);
	}

	/**
	 * Estimated USD for a token pair via the shared Cost rates (null when Cost is unavailable).
	 */
	private static function estimate_usd( int $input_tokens, int $output_tokens, string $provider = '' ): ?float {
		if ( ! class_exists( Cost::class, false ) ) {
			return null;
		}
		$policy = Policy::get_policy();
		$rates  = Cost::rates_from_policy( $policy, '' !== $provider ? $provider : null );

		return Cost::estimate_usd( $input_tokens, $output_tokens, $rates );
	}

	/**
	 * Roster rows for the current window, busiest first.
	 *
	 * @param string                   $window   'hour' or 'day'.
	 * @param array<string,mixed>|null $settings Optional settings override.
	 * @return list<array{bucket:string,calls:int,hour_count:int,day_count:int,hour_limit:?int,day_limit:?int,denies:int,input_tokens:int,output_tokens:int,est_usd:float,last_ts:int,last_provider:string}>
	 */
	public static function roster( string $window = self::WINDOW_DAY, ?array $settings = null, ?int $now = null ): array {
		$window   = self::WINDOW_HOUR === $window ? self::WINDOW_HOUR : self::WINDOW_DAY;
		$settings = is_array( $settings ) ? self::sanitize_settings( $settings ) : self::get_settings();
		$now      = null !== $now ? (int) $now : Clock::now();
		$hour     = Rate_Cap::window_bounds( Rate_Cap::WINDOW_HOUR, $now );
		$day      = Rate_Cap::window_bounds( Rate_Cap::WINDOW_DAY, $now );
		$bounds   = self::WINDOW_HOUR === $window ? $hour : $day;

		$hour_counts = array();
		$day_counts  = array();
		foreach ( self::get_counts_map() as $key => $n ) {
			$parts = explode( '|', (string) $key );
			if ( 3 !== count( $parts ) ) {
				continue;
			}
			$bucket = self::sanitize_bucket( $parts[0] );
			if ( '' === $bucket ) {
				continue;
			}
			if ( self::WINDOW_HOUR === $parts[1] && $parts[2] === $hour['key'] ) {
				$hour_counts[ $bucket ] = (int) $n;
			} elseif ( self::WINDOW_DAY === $parts[1] && $parts[2] === $day['key'] ) {
				$day_counts[ $bucket ] = (int) $n;
			}
		}

		$stats   = self::get_stats_map();
		$buckets = array();
		$active  = self::WINDOW_HOUR === $window ? $hour_counts : $day_counts;
		foreach ( array_keys( $active ) as $bucket ) {
			$buckets[ $bucket ] = true;
		}
		foreach ( $stats as $bucket => $row ) {
			if ( $row['last_ts'] >= $bounds['start'] && $row['last_ts'] < $bounds['end'] ) {
				$buckets[ $bucket ] = true;
			}
		}

		$rows = array();
		foreach ( array_keys( $buckets ) as $bucket ) {
			$bucket     = (string) $bucket;
			$row        = $stats[ $bucket ] ?? self::empty_stats_row();
			$hour_count = $hour_counts[ $bucket ] ?? 0;
			$day_count  = $day_counts[ $bucket ] ?? 0;
			$calls      = isset( $stats[ $bucket ] )
				? (int) $row['calls']
				: ( self::WINDOW_HOUR === $window ? $hour_count : $day_count );

			$est = (float) $row['est_usd'];
			if ( $est <= 0.0 && ( $row['input_tokens'] > 0 || $row['output_tokens'] > 0 ) ) {
				$computed = self::estimate_usd( (int) $row['input_tokens'], (int) $row['output_tokens'], (string) $row['last_provider'] );
				$est      = null !== $computed ? (float) $computed : 0.0;
			}

			$rows[] = array(
				'bucket'        => $bucket,
				'calls'         => $calls,
				'hour_count'    => $hour_count,
				'day_count'     => $day_count,
				'hour_limit'    => $settings['cap_hour'],
				'day_limit'     => $settings['cap_day'],
				'denies'        => (int) $row['denies'],
				'input_tokens'  => (int) $row['input_tokens'],
				'output_tokens' => (int) $row['output_tokens'],
				'est_usd'       => $est,
				'last_ts'       => (int) $row['last_ts'],
				'last_provider' => (string) $row['last_provider'],
			);
		}

		usort(
			$rows,
			static function ( array $a, array $b ): int {
				$by_calls = ( (int) $b['calls'] ) <=> ( (int) $a['calls'] );
				if ( 0 !== $by_calls ) {
					return $by_calls;
				}
				$by_usd = ( (float) $b['est_usd'] ) <=> ( (float) $a['est_usd'] );
				if ( 0 !== $by_usd ) {
					return $by_usd;
				}

				return strcmp( (string) $a['bucket'], (string) $b['bucket'] );
			}
		);

		return $rows;
	}

	public static function csv_for_roster( string $window = self::WINDOW_DAY ): string {
		$rows  = self::roster( $window );
		$lines = array(
			self::csv_line(
				array(
					'bucket',
					'calls',
					'hour_count',
					'day_count',
					'hour_limit',
					'day_limit',
					'denies',
					'input_tokens',
					'output_tokens',
					'est_usd',
					'last_ts',
					'last_provider',
				)
			),
		);
		foreach ( $rows as $r ) {
			$lines[] = self::csv_line(
				array(
					(string) $r['bucket'],
					(string) (int) $r['calls'],
					(string) (int) $r['hour_count'],
					(string) (int) $r['day_count'],
					null !== $r['hour_limit'] ? (string) (int) $r['hour_limit'] : '',
					null !== $r['day_limit'] ? (string) (int) $r['day_limit'] : '',
					(string) (int) $r['denies'],
					(string) (int) $r['input_tokens'],
					(string) (int) $r['output_tokens'],
					number_format( (float) $r['est_usd'], 6, '.', '' ),
					(string) (int) $r['last_ts'],
					(string) $r['last_provider'],
				)
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param list<string> $fields Fields.
	 */
	private static function csv_line( array $fields ): string {
		$out = array();
		foreach ( $fields as $f ) {
			$f = str_replace( '"', '""', (string) $f );
			if ( preg_match( '/[",\n\r]/', $f ) ) {
				$out[] = '"' . $f . '"';
			} else {
				$out[] = $f;
			}
		}

		return implode( ',', $out );
	}

	/**
	 * Forget one bucket (counters, stats, warn markers).
	 */
	public static function reset_bucket( string $bucket ): bool {
		$bucket = self::sanitize_bucket( $bucket );
		if ( '' === $bucket ) {
			return false;
		}
		$found  = false;
		$prefix = $bucket . '|';

		$counts = self::get_counts_map();
		foreach ( array_keys( $counts ) as $key ) {
			if ( 0 === strpos( (string) $key, $prefix ) ) {
				unset( $counts[ $key ] );
				$found = true;
			}
		}
		self::save_counts_map( $counts );

		$stats = self::get_stats_map();
		if ( isset( $stats[ $bucket ] ) ) {
			unset( $stats[ $bucket ] );
			$found = true;
		}
		self::save_stats_map( $stats );

		$warned = self::get_warned_map();
		foreach ( array_keys( $warned ) as $key ) {
			if ( 0 === strpos( (string) $key, $prefix ) ) {
				unset( $warned[ $key ] );
			}
		}
		if ( empty( $warned ) ) {
			delete_option( self::WARNED_OPTION );
		} else {
			update_option( self::WARNED_OPTION, $warned, false );
		}

		return $found;
	}

	/**
	 * Forget every bucket (the daily salt is left alone).
	 */
	public static function reset_all(): void {
		delete_option( self::COUNTS_OPTION );
		delete_option( self::STATS_OPTION );
		delete_option( self::WARNED_OPTION );
	}

	/* ---------------------------------------------------------------------
	 * Gate
	 * ------------------------------------------------------------------ */

	/**
	 * Gate filter at priority 2 (same slot as USER-QUOTA / AUP / CIRCUIT-BREAKER).
	 *
	 * @param mixed $prevent Prior filter result.
	 * @param mixed $builder Prompt builder.
	 */
	public static function maybe_prevent_prompt( $prevent, $builder ): bool {
		if ( $prevent ) {
			return true;
		}
		$settings = self::get_settings();
		if ( ! self::is_enabled( $settings ) ) {
			return false;
		}

		$policy = Policy::get_policy();
		if ( ! empty( $policy['audit_only'] ) ) {
			return false;
		}
		if ( class_exists( Break_Glass::class, false ) && method_exists( Break_Glass::class, 'is_active' ) && Break_Glass::is_active() ) {
			return false;
		}

		// Logged-in users are exempt: their limits belong to USER-QUOTA / policy.
		if ( Policy::current_user_id_for_gate() > 0 ) {
			return false;
		}

		$now    = Clock::now();
		$bucket = self::bucket_hash( $now );

		if ( ! empty( $settings['block_anonymous'] ) ) {
			$eval = self::evaluate( $settings, $bucket, $now );

			return self::deny( self::REASON_BLOCK_ALL, $bucket, $settings, $policy, $builder, $eval, $now );
		}

		$eval = self::evaluate( $settings, $bucket, $now );
		if ( ! empty( $eval['prevent'] ) ) {
			return self::deny( self::REASON, $bucket, $settings, $policy, $builder, $eval, $now );
		}

		self::record_attempt( $bucket, $now );
		$snapshot = class_exists( Prompt_Snapshot::class, false ) ? Prompt_Snapshot::from_builder( $builder ) : array();
		self::touch_stats( $bucket, is_array( $snapshot ) ? $snapshot : array(), $now );

		$after = self::evaluate( $settings, $bucket, $now );
		if ( ! empty( $after['soft_warn'] ) ) {
			self::maybe_fire_soft_warn( $policy, $bucket, $after, $now );
		}

		return false;
	}

	/**
	 * @param array<string,mixed> $settings Visitor settings.
	 * @param array<string,mixed> $policy   Policy.
	 * @param mixed               $builder  Prompt builder.
	 * @param array<string,mixed> $eval     evaluate() result.
	 */
	private static function deny( string $reason, string $bucket, array $settings, array $policy, $builder, array $eval, int $now ): bool {
		$attrib    = Attribution::resolve_from_backtrace();
		$plugin    = is_string( $attrib['plugin'] ?? null ) ? (string) $attrib['plugin'] : null;
		$snapshot  = class_exists( Prompt_Snapshot::class, false ) ? Prompt_Snapshot::from_builder( $builder ) : array();
		$snapshot  = is_array( $snapshot ) ? $snapshot : array();
		$operation = isset( $snapshot['operation'] ) ? (string) $snapshot['operation'] : '';
		$family    = isset( $snapshot['capability_family'] ) && is_string( $snapshot['capability_family'] )
			? (string) $snapshot['capability_family']
			: ( class_exists( Operations::class, false ) ? Operations::family_from_operation( $operation ) : '' );

		$block_all = self::REASON_BLOCK_ALL === $reason;

		$event = array_merge(
			array(
				'ts'                 => $now,
				'plugin'             => $plugin,
				'file'               => $attrib['file'] ?? null,
				'caller'             => $attrib['method'] ?? null,
				'decision'           => 'deny',
				'would_decision'     => 'deny',
				'capability_family'  => $family,
				'denial_reason'      => $reason,
				'decision_source'    => $reason,
				'user_id'            => 0,
				'user_role'          => '',
				'channel'            => self::CHANNEL,
				'visitor'            => true,
				'visitor_bucket'     => $bucket,
				'visitor_block_all'  => $block_all,
				'visitor_hour_limit' => $eval['hour']['limit'] ?? null,
				'visitor_hour_count' => (int) ( $eval['hour']['count'] ?? 0 ),
				'visitor_day_limit'  => $eval['day']['limit'] ?? null,
				'visitor_day_count'  => (int) ( $eval['day']['count'] ?? 0 ),
				'uri'                => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) ) : null,
			),
			$snapshot
		);
		if ( ! $block_all && ! empty( $eval['prevent'] ) ) {
			$event['visitor_window'] = (string) $eval['window'];
			$event['visitor_limit']  = $eval['limit'];
			$event['visitor_count']  = (int) $eval['count'];
		}

		self::touch_deny_stats( $bucket, $snapshot, $now );
		self::reclassify_latest_allow( $event );

		$soft = false;
		if ( class_exists( Soft_Deny::class, false ) && method_exists( Soft_Deny::class, 'maybe_arm_from_deny' ) ) {
			$soft = Soft_Deny::maybe_arm_from_deny(
				true,
				$event,
				$policy,
				is_string( $plugin ) ? $plugin : null,
				$operation,
				$family
			);
		}

		Policy::append_log_event( $event );

		$suppress = class_exists( Retry_Storm::class, false ) && method_exists( Retry_Storm::class, 'should_suppress_deny_alert' )
			&& Retry_Storm::should_suppress_deny_alert( $event, $policy );
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'maybe_notify_denial' ) && ! $suppress ) {
			Alerts::maybe_notify_denial( $event, $policy );
		}
		if ( class_exists( Access_Request::class, false ) && method_exists( Access_Request::class, 'note_deny' ) ) {
			Access_Request::note_deny( $event );
		}

		return $soft ? false : true;
	}

	/**
	 * Drop the allow row the shared logger just wrote for this same call so the
	 * deny is the only record.
	 *
	 * @param array<string,mixed> $event Deny event.
	 */
	public static function reclassify_latest_allow( array $event ): void {
		$policy = Policy::get_policy();
		if ( empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] ) ) {
			return;
		}
		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) || empty( $log ) ) {
			return;
		}
		$i    = count( $log ) - 1;
		$last = $log[ $i ];
		if ( ! is_array( $last ) ) {
			return;
		}
		if ( 'allow' !== (string) ( $last['decision'] ?? '' ) ) {
			return;
		}

		$last_bucket  = isset( $last['visitor_bucket'] ) ? (string) $last['visitor_bucket'] : '';
		$event_bucket = isset( $event['visitor_bucket'] ) ? (string) $event['visitor_bucket'] : '';
		if ( '' !== $last_bucket ) {
			// Prefer the explicit bucket match when the row carries one.
			if ( $last_bucket !== $event_bucket ) {
				return;
			}
		} elseif ( 0 !== (int) ( $last['user_id'] ?? 0 ) || 0 !== (int) ( $event['user_id'] ?? 0 ) ) {
			return;
		}

		$last_ts  = (int) ( $last['ts'] ?? 0 );
		$event_ts = (int) ( $event['ts'] ?? 0 );
		if ( $last_ts > 0 && $event_ts > 0 && abs( $last_ts - $event_ts ) > 5 ) {
			return;
		}
		array_pop( $log );
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
	}

	/* ---------------------------------------------------------------------
	 * Soft-warn
	 * ------------------------------------------------------------------ */

	/**
	 * @return array<string,array{at:int,limit:int,count:int}>
	 */
	public static function get_warned_map(): array {
		return self::sanitize_warned_map( get_option( self::WARNED_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw map.
	 * @return array<string,array{at:int,limit:int,count:int}>
	 */
	public static function sanitize_warned_map( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $key => $meta ) {
			$key = sanitize_text_field( (string) $key );
			if ( '' === $key || ! is_array( $meta ) ) {
				continue;
			}
			$out[ $key ] = array(
				'at'    => isset( $meta['at'] ) ? (int) $meta['at'] : 0,
				'limit' => isset( $meta['limit'] ) ? (int) $meta['limit'] : 0,
				'count' => isset( $meta['count'] ) ? (int) $meta['count'] : 0,
			);
		}

		return $out;
	}

	public static function already_warned( string $fired_key ): bool {
		$map = self::get_warned_map();

		return isset( $map[ $fired_key ] );
	}

	public static function record_warning( string $fired_key, int $limit, int $count, int $now ): void {
		$map               = self::get_warned_map();
		$map[ $fired_key ] = array(
			'at'    => $now,
			'limit' => $limit,
			'count' => $count,
		);
		if ( count( $map ) > 200 ) {
			uasort(
				$map,
				static function ( array $a, array $b ): int {
					return ( (int) ( $b['at'] ?? 0 ) ) <=> ( (int) ( $a['at'] ?? 0 ) );
				}
			);
			$map = array_slice( $map, 0, 200, true );
		}
		update_option( self::WARNED_OPTION, $map, false );
	}

	public static function clear_warned(): void {
		delete_option( self::WARNED_OPTION );
	}

	/**
	 * Fire soft-warn once per bucket + window key: audit row + alert email.
	 *
	 * @param array<string,mixed> $policy Policy.
	 * @param array<string,mixed> $eval   evaluate() result.
	 */
	public static function maybe_fire_soft_warn( array $policy, string $bucket, array $eval, ?int $now = null ): bool {
		$bucket = self::sanitize_bucket( $bucket );
		$window = (string) ( $eval['soft_window'] ?? '' );
		$limit  = isset( $eval['soft_limit'] ) ? (int) $eval['soft_limit'] : 0;
		$count  = isset( $eval['soft_count'] ) ? (int) $eval['soft_count'] : 0;
		if ( '' === $bucket || ( self::WINDOW_HOUR !== $window && self::WINDOW_DAY !== $window ) || $limit <= 0 ) {
			return false;
		}

		$key_suffix = self::WINDOW_HOUR === $window
			? (string) ( $eval['hour']['key'] ?? '' )
			: (string) ( $eval['day']['key'] ?? '' );
		if ( '' === $key_suffix ) {
			return false;
		}

		$fired_key = $bucket . '|' . $window . '|' . $key_suffix;
		if ( self::already_warned( $fired_key ) ) {
			return false;
		}

		$now = null !== $now ? (int) $now : Clock::now();
		self::record_warning( $fired_key, $limit, $count, $now );
		self::append_warn_audit_row( $policy, $bucket, $window, $limit, $count, $now );
		self::maybe_notify_soft_warn( $policy, $bucket, $window, $limit, $count );

		return true;
	}

	/**
	 * @param array<string,mixed> $policy Policy.
	 */
	private static function maybe_notify_soft_warn( array $policy, string $bucket, string $window, int $limit, int $count ): void {
		if ( empty( $policy['alert_on_deny'] ) ) {
			return;
		}
		if ( ! class_exists( Alerts::class, false ) || ! method_exists( Alerts::class, 'resolve_email' ) ) {
			return;
		}
		$email = Alerts::resolve_email( $policy );
		if ( '' === $email ) {
			return;
		}

		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$win  = self::WINDOW_HOUR === $window
			? __( 'this hour', 'handl-ai-connector-access-control' )
			: __( 'today', 'handl-ai-connector-access-control' );

		$subject = sprintf(
			/* translators: %s: site name */
			__( '[%s] HandL visitor-cap warning', 'handl-ai-connector-access-control' ),
			$site
		);

		$body = implode(
			"\n",
			array(
				__( 'Anonymous visitor AI call limit warning', 'handl-ai-connector-access-control' ),
				'',
				sprintf(
					/* translators: %s: anonymous visitor bucket id */
					__( 'Visitor bucket: %s', 'handl-ai-connector-access-control' ),
					$bucket
				),
				sprintf(
					/* translators: 1: call count, 2: cap, 3: window label */
					__( 'Usage: %1$d of %2$d calls %3$s.', 'handl-ai-connector-access-control' ),
					$count,
					$limit,
					$win
				),
				'',
				__( 'New calls from this visitor will be blocked when the cap is reached.', 'handl-ai-connector-access-control' ),
			)
		);

		if ( method_exists( Alerts::class, 'safe_wp_mail' ) ) {
			Alerts::safe_wp_mail( $email, $subject, $body );
			return;
		}
		if ( isset( $GLOBALS['handl_aicac_wp_mail'] ) && is_callable( $GLOBALS['handl_aicac_wp_mail'] ) ) {
			call_user_func( $GLOBALS['handl_aicac_wp_mail'], $email, $subject, $body );
		}
	}

	/**
	 * @param array<string,mixed> $policy Policy.
	 */
	private static function append_warn_audit_row( array $policy, string $bucket, string $window, int $limit, int $count, int $now ): void {
		if ( empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] ) ) {
			return;
		}

		Policy::append_log_event(
			array(
				'ts'             => $now,
				'decision'       => self::CHANNEL_WARN,
				'channel'        => self::CHANNEL_WARN,
				'plugin'         => '',
				'operation'      => '',
				'provider'       => '',
				'model'          => '',
				'user_id'        => 0,
				'visitor'        => true,
				'visitor_bucket' => $bucket,
				'visitor_window' => $window,
				'visitor_limit'  => $limit,
				'visitor_count'  => $count,
				'denial_reason'  => '',
			)
		);
	}

	/* ---------------------------------------------------------------------
	 * Admin
	 * ------------------------------------------------------------------ */

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Visitor AI caps', 'handl-ai-connector-access-control' ),
			__( 'Visitor caps', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$settings   = self::get_settings();
		$can_manage = Caps::user_can_manage();
		$csv        = add_query_arg(
			array(
				'page'                    => self::PAGE_SLUG,
				'handl_aicac_visitor_csv' => '1',
				'_wpnonce'                => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_visitor_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Visitor AI caps', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Limit or block governed AI calls made on behalf of logged-out visitors. Visitors are tracked by a salted hash of IP and browser family that rotates every day; raw IP addresses are never stored. Logged-in users are not affected. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';

			echo '<tr><th scope="row">' . esc_html__( 'Enable visitor caps', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Apply the limits below to logged-out visitors (needs block-all or at least one cap)', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';

			echo '<tr><th scope="row">' . esc_html__( 'Block all anonymous AI', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_BLOCK_ALL ) . '" value="1" ' . checked( ! empty( $settings['block_anonymous'] ), true, false ) . ' /> ';
			echo esc_html__( 'Deny every AI call made without a logged-in user', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';

			echo '<tr><th scope="row"><label for="' . esc_attr( self::POST_CAP_HOUR ) . '">' . esc_html__( 'Calls per visitor per hour', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input type="number" min="0" max="' . esc_attr( (string) self::MAX_CAP ) . '" class="small-text" id="' . esc_attr( self::POST_CAP_HOUR ) . '" name="' . esc_attr( self::POST_CAP_HOUR ) . '" value="' . esc_attr( null !== $settings['cap_hour'] ? (string) (int) $settings['cap_hour'] : '' ) . '" />';
			echo '<p class="description">' . esc_html__( 'Empty or 0 = unlimited.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr>';

			echo '<tr><th scope="row"><label for="' . esc_attr( self::POST_CAP_DAY ) . '">' . esc_html__( 'Calls per visitor per day', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input type="number" min="0" max="' . esc_attr( (string) self::MAX_CAP ) . '" class="small-text" id="' . esc_attr( self::POST_CAP_DAY ) . '" name="' . esc_attr( self::POST_CAP_DAY ) . '" value="' . esc_attr( null !== $settings['cap_day'] ? (string) (int) $settings['cap_day'] : '' ) . '" />';
			echo '<p class="description">' . esc_html__( 'Empty or 0 = unlimited. You get one warning at 80% of a cap.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr>';

			echo '</tbody></table>';
			submit_button( __( 'Save visitor caps', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		echo '<h2>' . esc_html__( 'Visitors today', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p><a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a>';
		if ( $can_manage ) {
			$reset_all = wp_nonce_url(
				admin_url( 'admin-post.php?action=' . self::ACTION_RESET ),
				self::ACTION_RESET . '_all'
			);
			echo ' <a class="button" href="' . esc_url( $reset_all ) . '">' . esc_html__( 'Reset all visitors', 'handl-ai-connector-access-control' ) . '</a>';
		}
		echo '</p>';

		$rows = self::roster();
		if ( empty( $rows ) ) {
			echo '<p>' . esc_html__( 'No anonymous visitor AI calls yet today.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Visitor', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'This hour', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Today', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Denied', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Est. cost', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Last seen', 'handl-ai-connector-access-control' ) . '</th>';
			if ( $can_manage ) {
				echo '<th>' . esc_html__( 'Reset', 'handl-ai-connector-access-control' ) . '</th>';
			}
			echo '</tr></thead><tbody>';
			foreach ( $rows as $r ) {
				echo '<tr><td><code>' . esc_html( (string) $r['bucket'] ) . '</code></td>';
				echo '<td>' . esc_html( (string) (int) $r['calls'] ) . '</td>';
				echo '<td>' . esc_html( self::format_usage( (int) $r['hour_count'], $r['hour_limit'] ) ) . '</td>';
				echo '<td>' . esc_html( self::format_usage( (int) $r['day_count'], $r['day_limit'] ) ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $r['denies'] ) . '</td>';
				echo '<td>' . esc_html( self::format_cost( (float) $r['est_usd'] ) ) . '</td>';
				echo '<td>' . esc_html( self::format_ts( (int) $r['last_ts'] ) ) . '</td>';
				if ( $can_manage ) {
					$reset = wp_nonce_url(
						admin_url( 'admin-post.php?action=' . self::ACTION_RESET . '&bucket=' . rawurlencode( (string) $r['bucket'] ) ),
						self::ACTION_RESET . '_' . (string) $r['bucket']
					);
					echo '<td><a href="' . esc_url( $reset ) . '">' . esc_html__( 'Reset', 'handl-ai-connector-access-control' ) . '</a></td>';
				}
				echo '</tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';
	}

	private static function format_usage( int $count, ?int $limit ): string {
		if ( null === $limit ) {
			return (string) $count;
		}

		return $count . ' / ' . $limit;
	}

	private static function format_cost( float $usd ): string {
		if ( $usd <= 0.0 ) {
			return '—';
		}
		if ( class_exists( Cost::class, false ) && method_exists( Cost::class, 'format_usd' ) ) {
			return Cost::format_usd( $usd );
		}

		return '$' . number_format( $usd, 4, '.', '' );
	}

	private static function format_ts( int $ts ): string {
		if ( $ts <= 0 ) {
			return '—';
		}
		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( 'Y-m-d H:i', $ts );
		}

		return gmdate( 'Y-m-d H:i', $ts );
	}

	public static function maybe_handle_csv(): void {
		if ( function_exists( 'is_admin' ) && ! is_admin() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action = isset( $_GET['handl_aicac_visitor_csv'] ) ? sanitize_key( wp_unslash( (string) $_GET['handl_aicac_visitor_csv'] ) ) : '';
		if ( '1' !== $action ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'You do not have permission to export this list.', 'handl-ai-connector-access-control' ) );
			}
			return;
		}
		check_admin_referer( 'handl_aicac_visitor_csv' );
		$csv = self::csv_for_roster();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( function_exists( 'header' ) ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename="handl-aicac-visitor-roster.csv"' );
		}
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- raw CSV download body.
		echo $csv;
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'You do not have permission to save this setting.', 'handl-ai-connector-access-control' ) );
			}
			return;
		}
		check_admin_referer( self::ACTION_SAVE );
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$enabled   = ! empty( $_POST[ self::POST_ENABLED ] );
		$block_all = ! empty( $_POST[ self::POST_BLOCK_ALL ] );
		$cap_hour  = isset( $_POST[ self::POST_CAP_HOUR ] ) ? wp_unslash( $_POST[ self::POST_CAP_HOUR ] ) : '';
		$cap_day   = isset( $_POST[ self::POST_CAP_DAY ] ) ? wp_unslash( $_POST[ self::POST_CAP_DAY ] ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		self::save_settings(
			array(
				'enabled'         => $enabled,
				'block_anonymous' => $block_all,
				'cap_hour'        => $cap_hour,
				'cap_day'         => $cap_day,
			)
		);
		$redirect = add_query_arg(
			array(
				'page'    => self::PAGE_SLUG,
				'updated' => '1',
			),
			admin_url( 'admin.php' )
		);
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $redirect );
			exit;
		}
	}

	public static function handle_reset(): void {
		if ( ! Caps::user_can_manage() ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'You do not have permission to reset visitor counters.', 'handl-ai-connector-access-control' ) );
			}
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$bucket = isset( $_GET['bucket'] ) ? self::sanitize_bucket( sanitize_text_field( wp_unslash( (string) $_GET['bucket'] ) ) ) : '';
		check_admin_referer( self::ACTION_RESET . '_' . ( '' !== $bucket ? $bucket : 'all' ) );
		if ( '' !== $bucket ) {
			self::reset_bucket( $bucket );
		} else {
			self::reset_all();
		}
		$redirect = add_query_arg(
			array(
				'page'  => self::PAGE_SLUG,
				'reset' => '1',
			),
			admin_url( 'admin.php' )
		);
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $redirect );
			exit;
		}
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac visitor', CLI_Visitor::class );
	}
}

/**
 * WP-CLI: wp handl-aicac visitor status|top|reset
 */
final class CLI_Visitor {

	/**
	 * Show visitor-cap status.
	 *
	 * ## OPTIONS
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		$settings = Visitor::get_settings();
		$salt     = get_option( Visitor::SALT_OPTION, array() );
		$day_key  = is_array( $salt ) && isset( $salt['day_key'] ) ? (string) $salt['day_key'] : '(none)';
		\WP_CLI::log(
			sprintf(
				'enabled=%s active=%s block_anonymous=%s cap_hour=%s cap_day=%s salt_day_key=%s',
				! empty( $settings['enabled'] ) ? 'yes' : 'no',
				Visitor::is_enabled( $settings ) ? 'yes' : 'no',
				! empty( $settings['block_anonymous'] ) ? 'yes' : 'no',
				null !== $settings['cap_hour'] ? (string) $settings['cap_hour'] : 'unlimited',
				null !== $settings['cap_day'] ? (string) $settings['cap_day'] : 'unlimited',
				$day_key
			)
		);
		if ( Policy::current_user_id_for_gate() <= 0 ) {
			\WP_CLI::log( 'current_bucket=' . Visitor::bucket_hash() );
		}
	}

	/**
	 * List the busiest anonymous visitors in the current window.
	 *
	 * ## OPTIONS
	 *
	 * [--window=<window>]
	 * : hour or day. Default day.
	 *
	 * [--format=<format>]
	 * : table, json, csv, or yaml.
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function top( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$window = isset( $assoc_args['window'] ) && 'hour' === (string) $assoc_args['window'] ? Visitor::WINDOW_HOUR : Visitor::WINDOW_DAY;
		if ( 'csv' === $format ) {
			\WP_CLI::print_value( Visitor::csv_for_roster( $window ), array( 'format' => 'csv' ) );
			return;
		}
		$table = array();
		foreach ( Visitor::roster( $window ) as $r ) {
			$table[] = array(
				'bucket'     => (string) $r['bucket'],
				'calls'      => (int) $r['calls'],
				'hour_count' => (int) $r['hour_count'],
				'day_count'  => (int) $r['day_count'],
				'denies'     => (int) $r['denies'],
				'est_usd'    => number_format( (float) $r['est_usd'], 6, '.', '' ),
				'last_ts'    => (int) $r['last_ts'],
			);
		}
		if ( empty( $table ) ) {
			\WP_CLI::log( 'No anonymous visitor activity.' );
			return;
		}
		\WP_CLI\Utils\format_items( $format, $table, array( 'bucket', 'calls', 'hour_count', 'day_count', 'denies', 'est_usd', 'last_ts' ) );
	}

	/**
	 * Clear visitor counters (one bucket, or everything when omitted).
	 *
	 * ## OPTIONS
	 *
	 * [<bucket>]
	 * : Optional bucket id from `top`.
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function reset( $args, $assoc_args ): void {
		unset( $assoc_args );
		if ( isset( $args[0] ) && '' !== (string) $args[0] ) {
			$bucket = Visitor::sanitize_bucket( (string) $args[0] );
			if ( '' === $bucket ) {
				\WP_CLI::error( 'Invalid bucket id.' );
			}
			if ( ! Visitor::reset_bucket( $bucket ) ) {
				\WP_CLI::warning( 'No data found for bucket ' . $bucket . '.' );
				return;
			}
			\WP_CLI::success( 'Cleared visitor bucket ' . $bucket . '.' );
			return;
		}
		Visitor::reset_all();
		\WP_CLI::success( 'Cleared all visitor counters.' );
	}
}
