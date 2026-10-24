<?php
/**
 * AICAC-SUNDIAL (#417): clock-sanity watchdog (report-only).
 *
 * Every time-based governance control in this plugin (temporary allows,
 * freeze windows, break-glass expiry, log retention, recertification, SLA
 * clocks) trusts PHP's idea of "now". When that clock is wrong, those controls
 * silently misbehave: grants expire early or late, retention prunes the wrong
 * rows, recerts fire prematurely, and the activity ledger records timestamps
 * that cannot be ordered. This class cross-checks the clock three ways and
 * reports what it finds in plain language.
 *
 * Checks:
 * - PHP vs database wall clock (one prepared read-only query).
 * - PHP default timezone and the WordPress timezone options.
 * - Ledger sanity: future-dated rows and rows out of append order.
 *
 * Design rules:
 * - Report only. It never adjusts a clock, a timestamp, or any option outside
 *   its own two. The ledger is read, never written.
 * - Detection runs on a throttled admin_init (and on demand from WP-CLI),
 *   never from a cron hook. This class schedules nothing.
 * - Exactly one re-arming [SUNDIAL] alert (0 -> findings), latched until clean.
 * - Own two options. OFF by default.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Clock-sanity watchdog.
 */
final class Sundial {

	public const SETTINGS_OPTION = 'handl_aicac_sundial';

	public const STATE_OPTION = 'handl_aicac_sundial_state';

	public const PAGE_SLUG = 'handl-aicac-sundial';

	public const ALERT_KIND = 'sundial';

	public const FRAMING = 'report_only_never_adjusts_clock';

	public const FILTER_SKEW_THRESHOLD = 'handl_aicac_sundial_skew_threshold';

	public const POST_PRESENT = 'handl_aicac_sundial_present';

	public const POST_ENABLED = 'handl_aicac_sundial_enabled';

	public const POST_SKEW_THRESHOLD = 'handl_aicac_sundial_skew_threshold';

	public const POST_FUTURE_TOLERANCE = 'handl_aicac_sundial_future_tolerance';

	public const ACTION_SAVE = 'handl_aicac_sundial_save';

	public const DEFAULT_SKEW_THRESHOLD = 120;

	public const MIN_SKEW_THRESHOLD = 30;

	public const MAX_SKEW_THRESHOLD = 3600;

	public const DEFAULT_FUTURE_TOLERANCE = 60;

	public const MIN_FUTURE_TOLERANCE = 0;

	public const MAX_FUTURE_TOLERANCE = 3600;

	/** Out-of-order rows closer than this are concurrent writes, not regressions. */
	public const ORDER_TOLERANCE_SEC = 2;

	/** WordPress timezone options may legitimately differ by a DST hour. */
	public const GMT_OFFSET_TOLERANCE_SEC = 3600;

	/** Maximum anomalous ledger rows reported per finding. */
	public const ANOMALY_CAP = 20;

	/** Admin check throttle in seconds (5 minutes). */
	public const CHECK_THROTTLE_SECONDS = 300;

	public const HISTORY_CAP = 40;

	public const CODE_SKEW            = 'php_db_skew';
	public const CODE_TZ_NOT_UTC      = 'timezone_not_utc';
	public const CODE_TZ_MISMATCH     = 'timezone_option_mismatch';
	public const CODE_FUTURE_ROWS     = 'future_rows';
	public const CODE_ORDER_REGRESSION = 'order_regression';

	public const DIRECTION_PHP_FAST        = 'php_fast';
	public const DIRECTION_PHP_SLOW        = 'php_slow';
	public const DIRECTION_DISAGREEMENT    = 'php_db_disagreement';
	public const DIRECTION_TZ_NOT_UTC      = 'timezone_not_utc';
	public const DIRECTION_FUTURE_ROWS     = 'future_rows';
	public const DIRECTION_ORDER_REGRESSION = 'order_regression';

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	/** @var int|null */
	private static $test_now = null;

	/** @var bool */
	private static $test_db_time_set = false;

	/** @var int|null */
	private static $test_db_time = null;

	/** @var bool */
	private static $test_log_set = false;

	/** @var array<int,mixed>|null */
	private static $test_log = null;

	/** @var string|null */
	private static $test_php_timezone = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_print' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );

		if ( self::is_enabled() ) {
			// Detection rides a throttled admin request, never a cron hook.
			add_action( 'admin_init', array( self::class, 'maybe_check' ), 30 );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered        = false;
		self::$test_mails        = array();
		self::$test_now          = null;
		self::$test_db_time_set  = false;
		self::$test_db_time      = null;
		self::$test_log_set      = false;
		self::$test_log          = null;
		self::$test_php_timezone = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATE_OPTION );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	/**
	 * Inject the database wall clock (unix seconds) for unit tests. Passing
	 * null simulates "database time unavailable"; use reset_for_tests() to go
	 * back to reading the real database.
	 *
	 * @param int|null $db_time Unix timestamp or null (unavailable).
	 */
	public static function set_test_db_time( ?int $db_time ): void {
		self::$test_db_time_set = true;
		self::$test_db_time     = $db_time;
	}

	/**
	 * Inject the activity ledger for unit tests. Null reads the real option.
	 *
	 * @param array<int,mixed>|null $log Ledger rows (append order) or null.
	 */
	public static function set_test_log( ?array $log ): void {
		self::$test_log_set = null !== $log;
		self::$test_log     = $log;
	}

	/**
	 * Inject date_default_timezone_get() for unit tests. Null reads PHP.
	 */
	public static function set_test_php_timezone( ?string $timezone ): void {
		self::$test_php_timezone = $timezone;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{enabled:bool,skew_threshold_sec:int,future_tolerance_sec:int}
	 */
	public static function defaults(): array {
		return array(
			'enabled'              => false,
			'skew_threshold_sec'   => self::DEFAULT_SKEW_THRESHOLD,
			'future_tolerance_sec' => self::DEFAULT_FUTURE_TOLERANCE,
		);
	}

	/**
	 * @return array{enabled:bool,skew_threshold_sec:int,future_tolerance_sec:int}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,skew_threshold_sec:int,future_tolerance_sec:int}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled'              => ! empty( $raw['enabled'] ),
			'skew_threshold_sec'   => self::sanitize_skew_threshold( $raw['skew_threshold_sec'] ?? $defaults['skew_threshold_sec'] ),
			'future_tolerance_sec' => self::sanitize_future_tolerance( $raw['future_tolerance_sec'] ?? $defaults['future_tolerance_sec'] ),
		);
	}

	/**
	 * @param mixed $raw Raw threshold seconds.
	 */
	public static function sanitize_skew_threshold( $raw ): int {
		if ( is_string( $raw ) ) {
			$raw = trim( $raw );
		}
		if ( ! is_numeric( $raw ) || ! is_finite( (float) $raw ) ) {
			return self::DEFAULT_SKEW_THRESHOLD;
		}

		return max( self::MIN_SKEW_THRESHOLD, min( self::MAX_SKEW_THRESHOLD, (int) round( (float) $raw ) ) );
	}

	/**
	 * @param mixed $raw Raw tolerance seconds.
	 */
	public static function sanitize_future_tolerance( $raw ): int {
		if ( is_string( $raw ) ) {
			$raw = trim( $raw );
		}
		if ( ! is_numeric( $raw ) || ! is_finite( (float) $raw ) ) {
			return self::DEFAULT_FUTURE_TOLERANCE;
		}

		return max( self::MIN_FUTURE_TOLERANCE, min( self::MAX_FUTURE_TOLERANCE, (int) round( (float) $raw ) ) );
	}

	/**
	 * Effective skew threshold after filter.
	 */
	public static function skew_threshold(): int {
		$base = (int) self::get_settings()['skew_threshold_sec'];
		if ( function_exists( 'apply_filters' ) ) {
			return self::sanitize_skew_threshold( apply_filters( self::FILTER_SKEW_THRESHOLD, $base ) );
		}

		return $base;
	}

	public static function future_tolerance(): int {
		return (int) self::get_settings()['future_tolerance_sec'];
	}

	/**
	 * @param array<string,mixed> $settings Settings.
	 * @return bool True when the stored value changed.
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
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] );
	}

	/* ---------------------------------------------------------------------
	 * State
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{alerted:bool,last_check_ts:int,history:list<array<string,mixed>>}
	 */
	public static function defaults_state(): array {
		return array(
			'alerted'       => false,
			'last_check_ts' => 0,
			'history'       => array(),
		);
	}

	/**
	 * @return array{alerted:bool,last_check_ts:int,history:list<array<string,mixed>>}
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw state.
	 * @return array{alerted:bool,last_check_ts:int,history:list<array<string,mixed>>}
	 */
	public static function sanitize_state( $raw ): array {
		$defaults = self::defaults_state();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		$history = array();
		if ( isset( $raw['history'] ) && is_array( $raw['history'] ) ) {
			foreach ( $raw['history'] as $row ) {
				$clean = self::sanitize_history_entry( $row );
				if ( null !== $clean ) {
					$history[] = $clean;
				}
			}
		}
		if ( count( $history ) > self::HISTORY_CAP ) {
			$history = array_slice( $history, -self::HISTORY_CAP );
		}

		return array(
			'alerted'       => ! empty( $raw['alerted'] ),
			'last_check_ts' => max( 0, (int) ( $raw['last_check_ts'] ?? 0 ) ),
			'history'       => $history,
		);
	}

	/**
	 * @param mixed $row Raw history row.
	 * @return array{ts:int,finding_count:int,codes:string,skew_sec:int}|null
	 */
	public static function sanitize_history_entry( $row ): ?array {
		if ( ! is_array( $row ) ) {
			return null;
		}
		$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		if ( $ts <= 0 ) {
			return null;
		}

		return array(
			'ts'            => $ts,
			'finding_count' => max( 0, (int) ( $row['finding_count'] ?? 0 ) ),
			'codes'         => sanitize_text_field( (string) ( $row['codes'] ?? '' ) ),
			'skew_sec'      => (int) ( $row['skew_sec'] ?? 0 ),
		);
	}

	/**
	 * @param array<string,mixed> $state State.
	 */
	public static function put_state( array $state ): void {
		$clean = self::sanitize_state( $state );
		if ( $clean === self::defaults_state() ) {
			delete_option( self::STATE_OPTION );

			return;
		}
		update_option( self::STATE_OPTION, $clean, false );
	}

	public static function is_alerted(): bool {
		$state = self::get_state();

		return ! empty( $state['alerted'] );
	}

	public static function set_alerted( bool $alerted ): void {
		$state            = self::get_state();
		$state['alerted'] = $alerted;
		self::put_state( $state );
	}

	/* ---------------------------------------------------------------------
	 * Clock sources (all read-only)
	 * ------------------------------------------------------------------ */

	private static function resolve_now( ?int $now ): int {
		if ( null !== $now && $now > 0 ) {
			return $now;
		}
		if ( null !== self::$test_now ) {
			return self::$test_now;
		}

		return class_exists( Clock::class, false ) ? Clock::now() : time();
	}

	/**
	 * Database wall clock as unix seconds, or null when unavailable.
	 *
	 * This is the only database access in the class: a single prepared,
	 * read-only SELECT. UNIX_TIMESTAMP() with no argument is the true epoch and
	 * does not depend on the session time zone.
	 *
	 * @return int|null
	 */
	public static function db_time(): ?int {
		if ( self::$test_db_time_set ) {
			return self::$test_db_time;
		}
		if ( ! isset( $GLOBALS['wpdb'] ) || ! is_object( $GLOBALS['wpdb'] ) ) {
			return null;
		}
		$wpdb = $GLOBALS['wpdb'];
		if ( ! method_exists( $wpdb, 'prepare' ) || ! method_exists( $wpdb, 'get_var' ) ) {
			return null;
		}
		$sql = $wpdb->prepare( 'SELECT UNIX_TIMESTAMP() + %d', 0 );
		if ( ! is_string( $sql ) || '' === $sql ) {
			return null;
		}
		$value = $wpdb->get_var( $sql );

		return ( is_numeric( $value ) && (int) $value > 0 ) ? (int) $value : null;
	}

	public static function php_timezone(): string {
		if ( null !== self::$test_php_timezone ) {
			return self::$test_php_timezone;
		}

		return date_default_timezone_get();
	}

	/**
	 * @return array<int,mixed>
	 */
	public static function ledger(): array {
		if ( self::$test_log_set && is_array( self::$test_log ) ) {
			return self::$test_log;
		}
		$log = get_option( class_exists( Plugin::class, false ) ? Plugin::LOG_OPTION_KEY : 'handl_aicac_recent_calls', array() );

		return is_array( $log ) ? $log : array();
	}

	/* ---------------------------------------------------------------------
	 * Plain-language direction
	 * ------------------------------------------------------------------ */

	/**
	 * Time-based controls named in explanations (plain strings; the classes
	 * need not exist).
	 *
	 * @return list<array{name:string,screen:string}>
	 */
	public static function affected_controls(): array {
		return array(
			array(
				'name'   => 'Temp_Allow',
				'screen' => 'rules',
			),
			array(
				'name'   => 'Freeze',
				'screen' => 'protections',
			),
			array(
				'name'   => 'Break_Glass',
				'screen' => 'protections',
			),
			array(
				'name'   => 'Log_Retention',
				'screen' => 'activity',
			),
			array(
				'name'   => 'Recert',
				'screen' => 'policy-tools',
			),
		);
	}

	/**
	 * Plain-language impact for each direction key.
	 *
	 * @return array<string,string>
	 */
	public static function direction_text(): array {
		return array(
			self::DIRECTION_PHP_FAST         => __( 'The PHP clock is ahead of the database clock. Time-limited controls fire early: temporary allows, freezes and break-glass windows can expire too soon, and recertifications can come due prematurely.', 'handl-ai-connector-access-control' ),
			self::DIRECTION_PHP_SLOW         => __( 'The PHP clock is behind the database clock. Time-limited controls fire late: log retention overshoots its limit and SLA clocks undercount elapsed time, so overdue items look on time.', 'handl-ai-connector-access-control' ),
			self::DIRECTION_DISAGREEMENT     => __( 'PHP and the database disagree about the time, so ledger ordering is untrustworthy: rows written from the two clocks cannot be reliably sequenced.', 'handl-ai-connector-access-control' ),
			self::DIRECTION_TZ_NOT_UTC       => __( 'PHP is not running in UTC. WordPress expects UTC internally, so stored timestamps can be corrupted relative to WordPress expectations (shifted by the zone offset).', 'handl-ai-connector-access-control' ),
			self::DIRECTION_FUTURE_ROWS      => __( 'Ledger rows are dated in the future. This raises ledger integrity questions: the clock was ahead when they were written, or the ledger was altered.', 'handl-ai-connector-access-control' ),
			self::DIRECTION_ORDER_REGRESSION => __( 'Ledger timestamps move backwards against append order. This raises ledger integrity questions: the clock stepped back, or rows were inserted out of sequence.', 'handl-ai-connector-access-control' ),
		);
	}

	public static function direction_explanation( string $direction ): string {
		$map = self::direction_text();

		return $map[ $direction ] ?? '';
	}

	/**
	 * Affected controls with deep links where the admin helper exists.
	 *
	 * @return list<array{name:string,url:string}>
	 */
	public static function controls_for( string $direction ): array {
		$names = array();
		if ( self::DIRECTION_PHP_FAST === $direction ) {
			$names = array( 'Temp_Allow', 'Freeze', 'Break_Glass', 'Log_Retention', 'Recert' );
		} elseif ( self::DIRECTION_PHP_SLOW === $direction ) {
			$names = array( 'Log_Retention', 'Temp_Allow', 'Freeze', 'Break_Glass', 'Recert' );
		} else {
			return array();
		}
		$by_name = array();
		foreach ( self::affected_controls() as $control ) {
			$by_name[ $control['name'] ] = $control['screen'];
		}
		$out = array();
		foreach ( $names as $name ) {
			$url = '';
			if ( isset( $by_name[ $name ] ) && class_exists( Admin::class, false ) && method_exists( Admin::class, 'screen_url' ) ) {
				$url = (string) Admin::screen_url( $by_name[ $name ] );
			}
			$out[] = array(
				'name' => $name,
				'url'  => $url,
			);
		}

		return $out;
	}

	/* ---------------------------------------------------------------------
	 * Checks
	 * ------------------------------------------------------------------ */

	/**
	 * Build a finding row.
	 *
	 * @param array<string,mixed> $extra Extra fields.
	 * @return array<string,mixed>
	 */
	private static function finding( string $code, string $direction, string $summary, string $impact, array $extra = array() ): array {
		return array_merge(
			array(
				'code'      => $code,
				'direction' => $direction,
				'summary'   => $summary,
				'impact'    => $impact,
				'controls'  => self::controls_for( $direction ),
				'delta_sec' => 0,
				'count'     => 0,
				'samples'   => array(),
			),
			$extra
		);
	}

	/**
	 * PHP vs database clock.
	 *
	 * @return array<string,mixed>|null Finding or null.
	 */
	public static function check_skew( int $php_time, ?int $db_time, int $threshold ): ?array {
		if ( null === $db_time ) {
			return null;
		}
		$delta = $php_time - $db_time;
		if ( abs( $delta ) < $threshold ) {
			return null;
		}
		$direction = $delta > 0 ? self::DIRECTION_PHP_FAST : self::DIRECTION_PHP_SLOW;
		$summary   = sprintf(
			/* translators: 1: seconds, 2: "ahead of" or "behind", 3: threshold seconds */
			__( 'PHP clock is %1$ds %2$s the database clock (threshold %3$ds).', 'handl-ai-connector-access-control' ),
			abs( $delta ),
			$delta > 0 ? __( 'ahead of', 'handl-ai-connector-access-control' ) : __( 'behind', 'handl-ai-connector-access-control' ),
			$threshold
		);

		return self::finding(
			self::CODE_SKEW,
			$direction,
			$summary,
			self::direction_explanation( $direction ) . ' ' . self::direction_explanation( self::DIRECTION_DISAGREEMENT ),
			array( 'delta_sec' => $delta )
		);
	}

	/**
	 * Timezone findings (PHP default zone, WordPress timezone options).
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function check_timezone( int $now ): array {
		$out  = array();
		$zone = trim( self::php_timezone() );
		if ( ! in_array( strtolower( $zone ), array( 'utc', 'etc/utc' ), true ) ) {
			$out[] = self::finding(
				self::CODE_TZ_NOT_UTC,
				self::DIRECTION_TZ_NOT_UTC,
				sprintf(
					/* translators: %s: PHP timezone identifier */
					__( 'PHP default timezone is "%s", not UTC.', 'handl-ai-connector-access-control' ),
					'' !== $zone ? $zone : '?'
				),
				self::direction_explanation( self::DIRECTION_TZ_NOT_UTC )
			);
		}

		$mismatch = self::timezone_option_mismatch( $now );
		if ( null !== $mismatch ) {
			$out[] = self::finding(
				self::CODE_TZ_MISMATCH,
				self::DIRECTION_TZ_NOT_UTC,
				$mismatch['summary'],
				self::direction_explanation( self::DIRECTION_TZ_NOT_UTC ),
				array( 'delta_sec' => $mismatch['delta_sec'] )
			);
		}

		return $out;
	}

	/**
	 * Simple heuristics for inconsistent timezone_string / gmt_offset options.
	 *
	 * @return array{summary:string,delta_sec:int}|null
	 */
	public static function timezone_option_mismatch( int $now ): ?array {
		$tz_string = trim( (string) get_option( 'timezone_string', '' ) );
		$raw_off   = get_option( 'gmt_offset', 0 );
		$offset    = is_numeric( $raw_off ) ? (float) $raw_off : 0.0;
		$off_sec   = (int) round( $offset * 3600 );

		if ( '' !== $tz_string ) {
			try {
				$zone     = new \DateTimeZone( $tz_string );
				$expected = $zone->getOffset( ( new \DateTimeImmutable( '@' . $now ) ) );
			} catch ( \Exception $e ) {
				return array(
					'summary'   => sprintf(
						/* translators: %s: timezone string */
						__( 'WordPress timezone_string "%s" is not a valid timezone.', 'handl-ai-connector-access-control' ),
						$tz_string
					),
					'delta_sec' => 0,
				);
			}
			$diff = $off_sec - (int) $expected;
			if ( abs( $diff ) > self::GMT_OFFSET_TOLERANCE_SEC ) {
				return array(
					'summary'   => sprintf(
						/* translators: 1: timezone string, 2: expected offset hours, 3: stored gmt_offset hours */
						__( 'WordPress timezone_string "%1$s" implies UTC%2$+g but gmt_offset is %3$+g.', 'handl-ai-connector-access-control' ),
						$tz_string,
						round( $expected / 3600, 2 ),
						round( $offset, 2 )
					),
					'delta_sec' => $diff,
				);
			}

			return null;
		}

		// No timezone_string: a manual UTC offset. Real offsets are within
		// UTC-12..UTC+14 and sit on 15-minute boundaries.
		if ( 0 === $off_sec ) {
			return null;
		}
		if ( $off_sec < -12 * 3600 || $off_sec > 14 * 3600 || 0 !== $off_sec % 900 ) {
			return array(
				'summary'   => sprintf(
					/* translators: %s: gmt_offset hours */
					__( 'WordPress gmt_offset %s is not a plausible UTC offset and no timezone_string is set.', 'handl-ai-connector-access-control' ),
					(string) round( $offset, 2 )
				),
				'delta_sec' => $off_sec,
			);
		}

		return null;
	}

	/**
	 * Ledger anomalies. The ledger is stored oldest-first: new rows are
	 * appended at the tail and the ring buffer drops from the head, so
	 * timestamps must be non-decreasing in array order.
	 *
	 * @param array<int,mixed> $log       Ledger rows.
	 * @param int              $now       PHP now.
	 * @param int              $tolerance Future tolerance seconds.
	 * @return list<array<string,mixed>>
	 */
	public static function check_ledger( array $log, int $now, int $tolerance ): array {
		$future       = array();
		$future_count = 0;
		$order        = array();
		$order_count  = 0;
		$max_ahead    = 0;
		$max_back     = 0;
		$prev_ts      = 0;
		$prev_idx     = -1;

		foreach ( array_values( $log ) as $idx => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) && is_numeric( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				continue;
			}
			if ( $ts > $now + $tolerance ) {
				++$future_count;
				$ahead     = $ts - $now;
				$max_ahead = max( $max_ahead, $ahead );
				if ( count( $future ) < self::ANOMALY_CAP ) {
					$future[] = array(
						'index'     => $idx,
						'ts'        => $ts,
						'ahead_sec' => $ahead,
					);
				}
			}
			if ( $prev_idx >= 0 && $ts < $prev_ts - self::ORDER_TOLERANCE_SEC ) {
				++$order_count;
				$back     = $prev_ts - $ts;
				$max_back = max( $max_back, $back );
				if ( count( $order ) < self::ANOMALY_CAP ) {
					$order[] = array(
						'index'     => $idx,
						'ts'        => $ts,
						'prev_ts'   => $prev_ts,
						'prev_index' => $prev_idx,
						'back_sec'  => $back,
					);
				}
			}
			$prev_ts  = $ts;
			$prev_idx = $idx;
		}

		$out = array();
		if ( $future_count > 0 ) {
			$out[] = self::finding(
				self::CODE_FUTURE_ROWS,
				self::DIRECTION_FUTURE_ROWS,
				sprintf(
					/* translators: 1: row count, 2: max seconds ahead, 3: tolerance seconds */
					__( '%1$d ledger row(s) are dated in the future (up to %2$ds ahead; tolerance %3$ds).', 'handl-ai-connector-access-control' ),
					$future_count,
					$max_ahead,
					$tolerance
				),
				self::direction_explanation( self::DIRECTION_FUTURE_ROWS ),
				array(
					'delta_sec' => $max_ahead,
					'count'     => $future_count,
					'samples'   => $future,
				)
			);
		}
		if ( $order_count > 0 ) {
			$out[] = self::finding(
				self::CODE_ORDER_REGRESSION,
				self::DIRECTION_ORDER_REGRESSION,
				sprintf(
					/* translators: 1: regression count, 2: max seconds backwards */
					__( '%1$d ledger row(s) are older than the row before them (up to %2$ds backwards against append order).', 'handl-ai-connector-access-control' ),
					$order_count,
					$max_back
				),
				self::direction_explanation( self::DIRECTION_ORDER_REGRESSION ),
				array(
					'delta_sec' => -$max_back,
					'count'     => $order_count,
					'samples'   => $order,
				)
			);
		}

		return $out;
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function snapshot( ?int $now = null ): array {
		$now       = self::resolve_now( $now );
		$state     = self::get_state();
		$settings  = self::get_settings();
		$threshold = self::skew_threshold();
		$tolerance = (int) $settings['future_tolerance_sec'];
		$db_time   = self::db_time();
		$ledger    = self::ledger();

		$findings = array();
		$skew     = self::check_skew( $now, $db_time, $threshold );
		if ( null !== $skew ) {
			$findings[] = $skew;
		}
		foreach ( self::check_timezone( $now ) as $row ) {
			$findings[] = $row;
		}
		foreach ( self::check_ledger( $ledger, $now, $tolerance ) as $row ) {
			$findings[] = $row;
		}

		return array(
			'enabled'              => self::is_enabled(),
			'skew_threshold_sec'   => $threshold,
			'future_tolerance_sec' => $tolerance,
			'findings'             => $findings,
			'finding_count'        => count( $findings ),
			'php_time'             => $now,
			'db_time'              => $db_time,
			'skew_sec'             => null !== $db_time ? $now - $db_time : null,
			'php_timezone'         => self::php_timezone(),
			'wp_timezone_string'   => (string) get_option( 'timezone_string', '' ),
			'wp_gmt_offset'        => (string) get_option( 'gmt_offset', '0' ),
			'ledger_rows'          => count( $ledger ),
			'disable_flags'        => array(
				'db_time_unavailable' => null === $db_time,
				'ledger_empty'        => 0 === count( $ledger ),
			),
			'alerted'              => ! empty( $state['alerted'] ),
			'last_check_ts'        => (int) $state['last_check_ts'],
			'history'              => $state['history'],
			'framing'              => self::FRAMING,
		);
	}

	/**
	 * Compact "2h 5m" duration for humans.
	 */
	public static function format_duration( int $seconds ): string {
		$seconds = abs( $seconds );
		if ( $seconds < 60 ) {
			return $seconds . 's';
		}
		if ( $seconds < 3600 ) {
			return (int) floor( $seconds / 60 ) . 'm';
		}
		if ( $seconds < 86400 ) {
			$h = (int) floor( $seconds / 3600 );
			$m = (int) floor( ( $seconds % 3600 ) / 60 );

			return $h . 'h' . ( $m > 0 ? ' ' . $m . 'm' : '' );
		}
		$d = (int) floor( $seconds / 86400 );
		$h = (int) floor( ( $seconds % 86400 ) / 3600 );

		return $d . 'd' . ( $h > 0 ? ' ' . $h . 'h' : '' );
	}

	/* ---------------------------------------------------------------------
	 * Throttled admin_init check
	 * ------------------------------------------------------------------ */

	/**
	 * Throttled clock check, wired to admin_init (never to a cron hook).
	 *
	 * @param int|null $now   Optional timestamp.
	 * @param bool     $force Skip the throttle.
	 * @return bool True when a check ran.
	 */
	public static function maybe_check( ?int $now = null, bool $force = false ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now   = self::resolve_now( is_int( $now ) ? $now : null );
		$state = self::get_state();
		$last  = (int) $state['last_check_ts'];
		if ( ! $force && $last > 0 && $now >= $last && ( $now - $last ) < self::CHECK_THROTTLE_SECONDS ) {
			return false;
		}
		$state['last_check_ts'] = $now;
		self::put_state( $state );
		self::maybe_fire_alerts( $now );

		return true;
	}

	/* ---------------------------------------------------------------------
	 * Alerts (guarded reuse of Alerts; zero edits to it)
	 * ------------------------------------------------------------------ */

	/**
	 * @param int|null                 $now  Timestamp.
	 * @param array<string,mixed>|null $snap Optional precomputed snapshot.
	 * @return bool True when a new alert was sent.
	 */
	public static function maybe_fire_alerts( ?int $now = null, ?array $snap = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now           = self::resolve_now( $now );
		$snap          = null !== $snap ? $snap : self::snapshot( $now );
		$finding_count = (int) $snap['finding_count'];

		if ( $finding_count <= 0 ) {
			if ( self::is_alerted() ) {
				self::set_alerted( false );
			}

			return false;
		}

		if ( self::is_alerted() ) {
			return false;
		}

		if ( ! self::fire_alert( $snap, $now ) ) {
			return false;
		}

		$codes = array();
		foreach ( (array) $snap['findings'] as $row ) {
			if ( is_array( $row ) ) {
				$codes[] = (string) ( $row['code'] ?? '' );
			}
		}
		$state              = self::get_state();
		$state['alerted']   = true;
		$state['history'][] = array(
			'ts'            => $now,
			'finding_count' => $finding_count,
			'codes'         => implode( ',', $codes ),
			'skew_sec'      => (int) ( $snap['skew_sec'] ?? 0 ),
		);
		self::put_state( $state );

		return true;
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	private static function fire_alert( array $snap, int $now ): bool {
		$policy = class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}

		$email = '';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		}
		if ( '' === $email ) {
			$email = function_exists( 'sanitize_email' )
				? sanitize_email( (string) get_option( 'admin_email' ) )
				: (string) get_option( 'admin_email' );
		}
		if ( '' === $email ) {
			return false;
		}

		$subject = self::build_subject( $snap );
		$body    = self::build_body( $snap );
		$ok      = false;
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'safe_wp_mail' ) ) {
			$ok = (bool) Alerts::safe_wp_mail( $email, $subject, $body );
		} elseif ( function_exists( 'wp_mail' ) ) {
			$ok = (bool) wp_mail( $email, $subject, $body );
		}
		self::$test_mails[] = array(
			'to'      => $email,
			'subject' => $subject,
			'body'    => $body,
		);

		if ( $ok && class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
				$codes = array();
				foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
					if ( is_array( $row ) ) {
						$codes[] = (string) ( $row['code'] ?? '' );
					}
				}
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'          => 'handl_aicac_sundial',
						'finding_count' => (int) ( $snap['finding_count'] ?? 0 ),
						'codes'         => $codes,
						'skew_sec'      => $snap['skew_sec'] ?? null,
						'site'          => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'            => $now,
					)
				);
			}
		}

		return $ok;
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_subject( array $snap ): string {
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$first = '';
		foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
			if ( is_array( $row ) ) {
				$first = (string) ( $row['code'] ?? '' );
				break;
			}
		}

		return sprintf(
			/* translators: 1: site name, 2: finding count, 3: first finding code */
			__( '[%1$s] [SUNDIAL] %2$d clock-sanity finding(s) (first: %3$s)', 'handl-ai-connector-access-control' ),
			$site,
			(int) ( $snap['finding_count'] ?? 0 ),
			$first
		);
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_body( array $snap ): string {
		$lines   = array();
		$lines[] = __( 'The clock-sanity check found problems. Time-based governance controls trust the PHP clock, so these can make them misbehave.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$lines[] = '- ' . (string) ( $row['summary'] ?? '' );
			$lines[] = '  ' . (string) ( $row['impact'] ?? '' );
		}
		$lines[] = '';
		$lines[] = __( 'Report only — never adjusts any clock, timestamp, or setting. This check runs on admin page loads, not on cron.', 'handl-ai-connector-access-control' );
		$url     = self::admin_url();
		if ( '' !== $url ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Open sundial: %s', 'handl-ai-connector-access-control' ),
				$url
			);
		}

		return implode( "\n", $lines );
	}

	public static function admin_url(): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg( 'page', self::PAGE_SLUG, admin_url( 'admin.php' ) );
	}

	/* ---------------------------------------------------------------------
	 * CSV + print
	 * ------------------------------------------------------------------ */

	/**
	 * @param array<string,mixed>|null $snap Optional snapshot.
	 */
	public static function csv_for_snapshot( ?array $snap = null ): string {
		if ( null === $snap ) {
			$snap = self::snapshot();
		}
		$lines   = array();
		$lines[] = self::csv_line(
			array(
				'section',
				'code',
				'direction',
				'delta_sec',
				'count',
				'summary',
				'impact',
				'controls',
				'framing',
			)
		);
		$lines[] = self::csv_line(
			array(
				'summary',
				'',
				'',
				null !== ( $snap['skew_sec'] ?? null ) ? (string) (int) $snap['skew_sec'] : '',
				(string) (int) ( $snap['finding_count'] ?? 0 ),
				'findings=' . (string) (int) ( $snap['finding_count'] ?? 0 ) . ' threshold=' . (string) (int) ( $snap['skew_threshold_sec'] ?? 0 ),
				'',
				'',
				self::FRAMING,
			)
		);
		$lines[] = self::csv_line(
			array(
				'environment',
				'clocks',
				'',
				null !== ( $snap['skew_sec'] ?? null ) ? (string) (int) $snap['skew_sec'] : '',
				'',
				'php_time=' . self::utc( (int) ( $snap['php_time'] ?? 0 ) )
					. ' db_time=' . ( null !== ( $snap['db_time'] ?? null ) ? self::utc( (int) $snap['db_time'] ) : 'unavailable' )
					. ' php_timezone=' . (string) ( $snap['php_timezone'] ?? '' )
					. ' wp_timezone_string=' . (string) ( $snap['wp_timezone_string'] ?? '' )
					. ' wp_gmt_offset=' . (string) ( $snap['wp_gmt_offset'] ?? '' ),
				'',
				'',
				self::FRAMING,
			)
		);
		foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$names = array();
			foreach ( (array) ( $row['controls'] ?? array() ) as $control ) {
				if ( is_array( $control ) ) {
					$names[] = (string) ( $control['name'] ?? '' );
				}
			}
			$lines[] = self::csv_line(
				array(
					'finding',
					(string) ( $row['code'] ?? '' ),
					(string) ( $row['direction'] ?? '' ),
					(string) (int) ( $row['delta_sec'] ?? 0 ),
					(string) (int) ( $row['count'] ?? 0 ),
					(string) ( $row['summary'] ?? '' ),
					(string) ( $row['impact'] ?? '' ),
					implode( ' ', $names ),
					self::FRAMING,
				)
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

	private static function utc( int $ts ): string {
		return $ts > 0 ? gmdate( 'Y-m-d H:i:s', $ts ) . ' UTC' : '';
	}

	/**
	 * @param list<string> $cols Columns.
	 */
	public static function csv_line( array $cols ): string {
		$out = array();
		foreach ( $cols as $col ) {
			$col = (string) $col;
			// Neutralize spreadsheet formula injection.
			if ( '' !== $col && in_array( $col[0], array( '=', '+', '-', '@', "\t", "\r" ), true ) ) {
				$col = "'" . $col;
			}
			$needs = str_contains( $col, ',' ) || str_contains( $col, '"' ) || str_contains( $col, "\n" );
			$col   = str_replace( '"', '""', $col );
			$out[] = $needs ? '"' . $col . '"' : $col;
		}

		return implode( ',', $out );
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_print_html( array $snap ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
		$html .= esc_html__( 'AI Connector sundial', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%;margin-bottom:24px}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f6f7f7}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'AI Connector sundial', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Report only — never adjusts any clock, timestamp, or setting.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<ul>';
		$html .= '<li>' . esc_html( sprintf( 'PHP time: %s', self::utc( (int) ( $snap['php_time'] ?? 0 ) ) ) ) . '</li>';
		$html .= '<li>' . esc_html( sprintf( 'Database time: %s', null !== ( $snap['db_time'] ?? null ) ? self::utc( (int) $snap['db_time'] ) : 'unavailable' ) ) . '</li>';
		$html .= '<li>' . esc_html( sprintf( 'Skew (PHP minus database): %s', null !== ( $snap['skew_sec'] ?? null ) ? (string) (int) $snap['skew_sec'] . 's' : 'n/a' ) ) . '</li>';
		$html .= '<li>' . esc_html( sprintf( 'PHP timezone: %s', (string) ( $snap['php_timezone'] ?? '' ) ) ) . '</li>';
		$html .= '<li>' . esc_html( sprintf( 'Findings: %d (skew threshold %ds)', (int) ( $snap['finding_count'] ?? 0 ), (int) ( $snap['skew_threshold_sec'] ?? 0 ) ) ) . '</li>';
		$html .= '</ul>';
		$html .= '<h2>' . esc_html__( 'Findings', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= self::table_html( (array) ( $snap['findings'] ?? array() ) );
		$html .= '</body></html>';

		return $html;
	}

	/**
	 * @param list<array<string,mixed>> $rows Findings.
	 */
	private static function table_html( array $rows ): string {
		$html  = '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Finding', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Direction', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'What it means', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Controls affected', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		$shown = 0;
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			++$shown;
			$names = array();
			foreach ( (array) ( $row['controls'] ?? array() ) as $control ) {
				if ( is_array( $control ) ) {
					$names[] = (string) ( $control['name'] ?? '' );
				}
			}
			$html .= '<tr>';
			$html .= '<td><strong>' . esc_html( (string) ( $row['summary'] ?? '' ) ) . '</strong><br /><code>' . esc_html( (string) ( $row['code'] ?? '' ) ) . '</code></td>';
			$html .= '<td>' . esc_html( (string) ( $row['direction'] ?? '' ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) ( $row['impact'] ?? '' ) ) . '</td>';
			$html .= '<td>' . esc_html( implode( ', ', $names ) ) . '</td>';
			$html .= '</tr>';
		}
		if ( 0 === $shown ) {
			$html .= '<tr><td colspan="4">' . esc_html__( 'No clock-sanity findings.', 'handl-ai-connector-access-control' ) . '</td></tr>';
		}
		$html .= '</tbody></table>';

		return $html;
	}

	/* ---------------------------------------------------------------------
	 * Admin UI
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
			__( 'Sundial', 'handl-ai-connector-access-control' ),
			__( 'Sundial', 'handl-ai-connector-access-control' ),
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
		$enabled    = self::is_enabled();
		$snap       = $enabled ? self::snapshot() : null;
		$csv        = add_query_arg(
			array(
				'page'                  => self::PAGE_SLUG,
				'handl_aicac_sundial_csv' => '1',
				'_wpnonce'              => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_sundial_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print = add_query_arg(
			array(
				'page'                     => self::PAGE_SLUG,
				'handl_aicac_sundial_print' => '1',
				'_wpnonce'                 => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_sundial_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Sundial', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Cross-check the clock that time-based controls trust: PHP vs database, timezone settings, and ledger timestamps. Report only — never adjusts any clock. Checks run on admin page loads, not on cron. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable sundial', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Check the clock and alert when it looks wrong', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-sundial-skew">' . esc_html__( 'Skew threshold (seconds)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_SKEW_THRESHOLD ) . '" id="handl-aicac-sundial-skew" type="number" min="' . esc_attr( (string) self::MIN_SKEW_THRESHOLD ) . '" max="' . esc_attr( (string) self::MAX_SKEW_THRESHOLD ) . '" step="1" value="' . esc_attr( (string) $settings['skew_threshold_sec'] ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'Default 120. Flag when PHP and the database clock differ by at least this many seconds.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-sundial-future">' . esc_html__( 'Future-row tolerance (seconds)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_FUTURE_TOLERANCE ) . '" id="handl-aicac-sundial-future" type="number" min="' . esc_attr( (string) self::MIN_FUTURE_TOLERANCE ) . '" max="' . esc_attr( (string) self::MAX_FUTURE_TOLERANCE ) . '" step="1" value="' . esc_attr( (string) $settings['future_tolerance_sec'] ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'Default 60. Ledger rows dated further ahead than this are flagged.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save sundial settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled || ! is_array( $snap ) ) {
			echo '<p>' . esc_html__( 'Sundial is off. Enable it to cross-check the clock.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Report only — never adjusts any clock, timestamp, or setting.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		echo '<ul>';
		echo '<li>' . esc_html( sprintf( 'PHP time: %s', self::utc( (int) $snap['php_time'] ) ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( 'Database time: %s', null !== $snap['db_time'] ? self::utc( (int) $snap['db_time'] ) : 'unavailable' ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( 'Skew (PHP minus database): %s', null !== $snap['skew_sec'] ? (string) (int) $snap['skew_sec'] . 's' : 'n/a' ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( 'Findings: %d', (int) $snap['finding_count'] ) ) . '</li>';
		echo '</ul>';

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Findings', 'handl-ai-connector-access-control' ) . '</h2>';
		echo str_replace( '<table>', '<table class="widefat striped">', self::table_html( (array) $snap['findings'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.

		echo '</div>';
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_sundial_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? (string) wp_unslash( $_GET['_wpnonce'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_sundial_csv' ) ) {
			return;
		}
		$csv = self::csv_for_snapshot();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=handl-aicac-sundial.csv' );
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		if ( empty( $_GET['handl_aicac_sundial_print'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? (string) wp_unslash( $_GET['_wpnonce'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_sundial_print' ) ) {
			return;
		}
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		echo self::build_print_html( self::snapshot() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save sundial settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );
		}
		$skew_raw   = isset( $_POST[ self::POST_SKEW_THRESHOLD ] ) ? wp_unslash( (string) $_POST[ self::POST_SKEW_THRESHOLD ] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		$future_raw = isset( $_POST[ self::POST_FUTURE_TOLERANCE ] ) ? wp_unslash( (string) $_POST[ self::POST_FUTURE_TOLERANCE ] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		self::save_settings(
			array(
				'enabled'              => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'skew_threshold_sec'   => self::sanitize_skew_threshold( '' !== $skew_raw ? $skew_raw : self::DEFAULT_SKEW_THRESHOLD ),
				'future_tolerance_sec' => self::sanitize_future_tolerance( '' !== $future_raw ? $future_raw : self::DEFAULT_FUTURE_TOLERANCE ),
			)
		);
		$redirect = self::admin_url();
		if ( '' === $redirect && function_exists( 'admin_url' ) ) {
			$redirect = admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac sundial', CLI_Sundial::class );
	}
}

/**
 * WP-CLI: wp handl-aicac sundial status|export
 */
final class CLI_Sundial {

	/**
	 * Show clock sanity. Exits non-zero when any finding exists (while enabled).
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table or json. Default table.
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';

		if ( ! Sundial::is_enabled() ) {
			\WP_CLI::log(
				sprintf(
					'enabled=no skew_threshold_sec=%d framing=%s',
					(int) Sundial::get_settings()['skew_threshold_sec'],
					Sundial::FRAMING
				)
			);
			\WP_CLI::log( 'Sundial is disabled.' );

			return;
		}

		$snap = Sundial::snapshot();

		\WP_CLI::log(
			sprintf(
				'enabled=yes skew_threshold_sec=%d findings=%d php_time=%d db_time=%s skew_sec=%s alerted=%s framing=%s',
				(int) $snap['skew_threshold_sec'],
				(int) $snap['finding_count'],
				(int) $snap['php_time'],
				null !== $snap['db_time'] ? (string) (int) $snap['db_time'] : 'unavailable',
				null !== $snap['skew_sec'] ? (string) (int) $snap['skew_sec'] : 'n/a',
				! empty( $snap['alerted'] ) ? 'yes' : 'no',
				Sundial::FRAMING
			)
		);

		$display = array();
		foreach ( (array) $snap['findings'] as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$display[] = array(
				'code'      => (string) ( $row['code'] ?? '' ),
				'direction' => (string) ( $row['direction'] ?? '' ),
				'delta_sec' => (int) ( $row['delta_sec'] ?? 0 ),
				'summary'   => (string) ( $row['summary'] ?? '' ),
			);
		}
		if ( ! empty( $display ) ) {
			if ( 'json' === $format ) {
				\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			} elseif ( class_exists( '\\WP_CLI\\Utils' ) ) {
				\WP_CLI\Utils\format_items( 'table', $display, array( 'code', 'direction', 'delta_sec', 'summary' ) );
			} else {
				foreach ( $display as $row ) {
					\WP_CLI::log( implode( "\t", $row ) );
				}
			}
		}

		if ( (int) $snap['finding_count'] > 0 ) {
			// Default exit=true: a wrong clock must fail the command (non-zero).
			\WP_CLI::error( 'Clock-sanity findings present.' );
		}
	}

	/**
	 * Export the sundial report as CSV.
	 *
	 * ## OPTIONS
	 *
	 * [--porcelain]
	 * : Print CSV only.
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function export( $args, $assoc_args ): void {
		unset( $args );
		$csv = Sundial::csv_for_snapshot();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
