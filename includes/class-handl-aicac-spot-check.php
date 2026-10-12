<?php
/**
 * AICAC-SPOT-CHECK (#381): human review sampling of ALLOWED traffic.
 *
 * Deterministic salted-hash daily sample of the activity log (reproducible,
 * un-gameable; raw content never duplicated). Review queue with looks-right /
 * concern verdicts in own option. Concern is informational: LOG_OPTION_KEY
 * append (`spot_check=concern`) + one alert per fingerprint via Alerts.
 * Never a deny — read-only against the gate. Coverage ledger with print + CSV.
 * OFF by default. No admin.php/policy.php/cost.php/logger edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Human oversight sampling + review ledger.
 */
final class Spot_Check {

	public const SETTINGS_OPTION = 'handl_aicac_spot_check';

	public const QUEUE_OPTION = 'handl_aicac_spot_check_queue';

	public const ALERTED_OPTION = 'handl_aicac_spot_check_alerted';

	public const PAGE_SLUG = 'handl-aicac-spot-check';

	public const VERDICT_LOOKS_RIGHT = 'looks_right';

	public const VERDICT_CONCERN = 'concern';

	public const ALERT_KIND = 'spot_check';

	public const DEFAULT_SAMPLE_RATE = 0.01;

	public const DEFAULT_ROWS_PER_DAY = 50;

	public const STALE_AFTER_DAYS = 3;

	public const QUEUE_CAP = 500;

	public const POST_PRESENT = 'handl_aicac_spot_check_present';

	public const POST_ENABLED = 'handl_aicac_spot_check_enabled';

	public const POST_SAMPLE_RATE = 'handl_aicac_spot_check_sample_rate';

	public const POST_ROWS_PER_DAY = 'handl_aicac_spot_check_rows_per_day';

	public const ACTION_SAVE = 'handl_aicac_spot_check_save';

	public const ACTION_VERDICT = 'handl_aicac_spot_check_verdict';

	/** @var bool */
	private static $registered = false;

	/** @var list<array{to:string,subject:string,body:string}> */
	private static $test_mails = array();

	/** @var string|null */
	private static $test_salt = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_print' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_VERDICT, array( self::class, 'handle_verdict' ) );
		if ( ! ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			add_action( 'init', array( self::class, 'maybe_sample' ), 35 );
			if ( function_exists( 'is_admin' ) && is_admin() ) {
				add_action( 'admin_notices', array( self::class, 'maybe_staleness_notice' ) );
			}
		}
		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$test_mails = array();
		self::$test_salt  = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::QUEUE_OPTION );
		delete_option( self::ALERTED_OPTION );
	}

	/**
	 * @return list<array{to:string,subject:string,body:string}>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	public static function set_test_salt( string $salt ): void {
		self::$test_salt = $salt;
	}

	/**
	 * @return array{enabled:bool,sample_rate:float,rows_per_day:int}
	 */
	public static function defaults(): array {
		return array(
			'enabled'       => false,
			'sample_rate'   => self::DEFAULT_SAMPLE_RATE,
			'rows_per_day'  => self::DEFAULT_ROWS_PER_DAY,
		);
	}

	/**
	 * @return array{enabled:bool,sample_rate:float,rows_per_day:int}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,sample_rate:float,rows_per_day:int}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled'      => ! empty( $raw['enabled'] ),
			'sample_rate'  => self::sanitize_sample_rate( $raw['sample_rate'] ?? $defaults['sample_rate'] ),
			'rows_per_day' => self::sanitize_rows_per_day( $raw['rows_per_day'] ?? $defaults['rows_per_day'] ),
		);
	}

	/**
	 * @param mixed $raw Rate as fraction (0.01) or percent (1).
	 */
	public static function sanitize_sample_rate( $raw ): float {
		if ( is_string( $raw ) ) {
			$raw = trim( $raw );
			if ( '' !== $raw && '%' === substr( $raw, -1 ) ) {
				$raw = (float) substr( $raw, 0, -1 ) / 100.0;
			}
		}
		$rate = is_numeric( $raw ) ? (float) $raw : self::DEFAULT_SAMPLE_RATE;
		if ( $rate > 1.0 ) {
			$rate = $rate / 100.0;
		}
		if ( $rate < 0.0 ) {
			$rate = 0.0;
		}
		if ( $rate > 1.0 ) {
			$rate = 1.0;
		}

		return round( $rate, 6 );
	}

	/**
	 * @param mixed $raw Cap.
	 */
	public static function sanitize_rows_per_day( $raw ): int {
		$n = is_numeric( $raw ) ? (int) $raw : self::DEFAULT_ROWS_PER_DAY;
		if ( $n < 1 ) {
			$n = 1;
		}
		if ( $n > 500 ) {
			$n = 500;
		}

		return $n;
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

	public static function is_enabled(): bool {
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] );
	}

	public static function site_salt(): string {
		if ( null !== self::$test_salt && '' !== self::$test_salt ) {
			return self::$test_salt;
		}
		if ( function_exists( 'wp_salt' ) ) {
			return (string) wp_salt( 'auth' );
		}

		return 'handl-aicac-spot-check-fallback-salt';
	}

	public static function day_key( ?int $ts = null ): string {
		$ts = null !== $ts && $ts > 0 ? $ts : Clock::now();
		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( 'Y-m-d', $ts );
		}

		return gmdate( 'Y-m-d', $ts );
	}

	/**
	 * Stable identity for a log row (no payload / raw content).
	 *
	 * @param array<string,mixed> $row Log row.
	 */
	public static function entry_id( array $row ): string {
		$parts = array(
			(string) (int) ( $row['ts'] ?? 0 ),
			(string) ( $row['plugin'] ?? '' ),
			Cost::normalize_provider_id( (string) ( $row['provider'] ?? '' ) ),
			(string) ( $row['model'] ?? '' ),
			(string) ( $row['decision'] ?? '' ),
			(string) ( $row['operation'] ?? '' ),
			(string) ( $row['capability_family'] ?? '' ),
			(string) (int) ( $row['user_id'] ?? 0 ),
			(string) (int) ( $row['count'] ?? 1 ),
		);
		$raw = implode( '|', $parts );

		return substr( hash_hmac( 'sha256', $raw, self::site_salt() ), 0, 32 );
	}

	/**
	 * Score in [0, 9999]. Lower scores are preferred when capping.
	 */
	public static function sample_score( string $day_key, string $entry_id ): int {
		$hex = substr( hash_hmac( 'sha256', $day_key . '|' . $entry_id, self::site_salt() ), 0, 8 );

		return (int) ( hexdec( $hex ) % 10000 );
	}

	public static function is_selected( int $score, float $sample_rate ): bool {
		$threshold = (int) round( max( 0.0, min( 1.0, $sample_rate ) ) * 10000 );

		return $score < $threshold;
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function get_queue(): array {
		return self::sanitize_queue( get_option( self::QUEUE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Queue.
	 * @return list<array<string,mixed>>
	 */
	public static function sanitize_queue( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$clean = self::sanitize_queue_row( $row );
			if ( null !== $clean ) {
				$out[] = $clean;
			}
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $row Raw row.
	 * @return array<string,mixed>|null
	 */
	public static function sanitize_queue_row( array $row ): ?array {
		$id = isset( $row['id'] ) ? sanitize_key( (string) $row['id'] ) : '';
		if ( '' === $id ) {
			$id = isset( $row['entry_id'] ) ? sanitize_key( (string) $row['entry_id'] ) : '';
		}
		if ( '' === $id ) {
			return null;
		}
		$day = isset( $row['day_key'] ) ? (string) $row['day_key'] : '';
		if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $day ) ) {
			return null;
		}
		$verdict = self::sanitize_verdict( (string) ( $row['verdict'] ?? '' ) );

		return array(
			'id'                => $id,
			'day_key'           => $day,
			'sampled_at'        => max( 0, (int) ( $row['sampled_at'] ?? 0 ) ),
			'score'             => max( 0, min( 9999, (int) ( $row['score'] ?? 0 ) ) ),
			'ts'                => max( 0, (int) ( $row['ts'] ?? 0 ) ),
			'plugin'            => self::sanitize_note( (string) ( $row['plugin'] ?? '' ), 200 ),
			'provider'          => Cost::normalize_provider_id( (string) ( $row['provider'] ?? '' ) ),
			'model'             => self::sanitize_note( (string) ( $row['model'] ?? '' ), 200 ),
			'decision'          => self::sanitize_note( (string) ( $row['decision'] ?? '' ), 64 ),
			'operation'         => self::sanitize_note( (string) ( $row['operation'] ?? '' ), 120 ),
			'capability_family' => self::sanitize_note( (string) ( $row['capability_family'] ?? '' ), 64 ),
			'estimated_usd'     => self::sanitize_usd( $row['estimated_usd'] ?? null ),
			'pii_flagged'       => ! empty( $row['pii_flagged'] ),
			'verdict'           => $verdict,
			'note'              => self::sanitize_note( (string) ( $row['note'] ?? '' ), 500 ),
			'reviewed_at'       => max( 0, (int) ( $row['reviewed_at'] ?? 0 ) ),
			'reviewer_id'       => max( 0, (int) ( $row['reviewer_id'] ?? 0 ) ),
		);
	}

	/**
	 * @param mixed $raw USD or null.
	 */
	public static function sanitize_usd( $raw ): ?float {
		if ( null === $raw || '' === $raw ) {
			return null;
		}
		if ( ! is_numeric( $raw ) ) {
			return null;
		}

		return round( (float) $raw, 6 );
	}

	public static function sanitize_verdict( string $verdict ): string {
		$verdict = sanitize_key( $verdict );
		if ( self::VERDICT_LOOKS_RIGHT === $verdict || self::VERDICT_CONCERN === $verdict ) {
			return $verdict;
		}

		return '';
	}

	public static function sanitize_note( string $note, int $max = 2000 ): string {
		$note = trim( $note );
		if ( function_exists( 'sanitize_text_field' ) ) {
			$note = sanitize_text_field( $note );
		} else {
			$note = strip_tags( $note );
		}
		if ( strlen( $note ) > $max ) {
			$note = substr( $note, 0, $max );
		}

		return $note;
	}

	/**
	 * @param list<array<string,mixed>> $queue Queue.
	 */
	public static function save_queue( array $queue ): void {
		$clean = self::sanitize_queue( $queue );
		if ( count( $clean ) > self::QUEUE_CAP ) {
			usort(
				$clean,
				static function ( array $a, array $b ): int {
					return ( (int) $b['sampled_at'] ) <=> ( (int) $a['sampled_at'] );
				}
			);
			$clean = array_slice( $clean, 0, self::QUEUE_CAP );
		}
		if ( array() === $clean ) {
			delete_option( self::QUEUE_OPTION );

			return;
		}
		update_option( self::QUEUE_OPTION, array_values( $clean ), false );
	}

	/**
	 * @return array<string,bool>
	 */
	public static function get_alerted(): array {
		$raw = get_option( self::ALERTED_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $fp => $v ) {
			$key = sanitize_key( (string) $fp );
			if ( '' !== $key && $v ) {
				$out[ $key ] = true;
			}
		}

		return $out;
	}

	/**
	 * @param array<string,bool> $map Fingerprints.
	 */
	public static function put_alerted( array $map ): void {
		$clean = array();
		foreach ( $map as $fp => $v ) {
			$key = sanitize_key( (string) $fp );
			if ( '' !== $key && $v ) {
				$clean[ $key ] = true;
			}
		}
		if ( array() === $clean ) {
			delete_option( self::ALERTED_OPTION );

			return;
		}
		update_option( self::ALERTED_OPTION, $clean, false );
	}

	public static function alert_fingerprint( string $id ): string {
		return sanitize_key( 'sc_' . substr( hash( 'sha256', $id ), 0, 24 ) );
	}

	/**
	 * @param array<string,mixed>|null $log Log.
	 * @return list<array<string,mixed>>
	 */
	public static function activity_rows( ?array $log = null ): array {
		if ( null === $log ) {
			$log = class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_retained_log' )
				? Policy::get_retained_log()
				: get_option( Plugin::LOG_OPTION_KEY, array() );
		}
		if ( ! is_array( $log ) ) {
			return array();
		}
		if ( class_exists( Demo_Mode::class, false ) && method_exists( Demo_Mode::class, 'without_demo' ) ) {
			$log = Demo_Mode::without_demo( $log );
		}
		$out = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( class_exists( Selftest::class, false ) && Selftest::is_synthetic_row( $row ) ) {
				continue;
			}
			if ( class_exists( Usage_Trends::class, false ) && ! Usage_Trends::is_activity_row( $row ) ) {
				continue;
			}
			// Spot-check is for oversight of what the gate waved through.
			if ( 'deny' === (string) ( $row['decision'] ?? '' ) ) {
				continue;
			}
			if ( isset( $row['spot_check'] ) ) {
				continue;
			}
			if ( isset( $row['channel'] ) && 'spot_check' === (string) $row['channel'] ) {
				continue;
			}
			$out[] = $row;
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $row Log row.
	 */
	public static function estimate_row_usd( array $row ): ?float {
		if ( array_key_exists( 'estimated_usd', $row ) && is_numeric( $row['estimated_usd'] ) ) {
			return round( (float) $row['estimated_usd'], 6 );
		}
		$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
		$out = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
		if ( null === $in && null === $out ) {
			return null;
		}
		$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}
		$rates = Cost::rates_from_policy( $policy, isset( $row['provider'] ) ? (string) $row['provider'] : null );

		return Cost::estimate_usd( $in, $out, $rates );
	}

	/**
	 * @param array<string,mixed> $row Log row.
	 * @return array<string,mixed>
	 */
	public static function snapshot_from_log_row( array $row, string $day_key, int $score, int $sampled_at ): array {
		$family = isset( $row['capability_family'] ) ? (string) $row['capability_family'] : '';
		$op     = isset( $row['operation'] ) ? (string) $row['operation'] : '';
		if ( '' === $family && '' !== $op && class_exists( Operations::class, false ) ) {
			$family = Operations::family_from_operation( $op );
		}
		$pii = false;
		if ( isset( $row['pii_match'] ) && is_array( $row['pii_match'] ) ) {
			$pii = true;
		} elseif ( isset( $row['denial_reason'] ) && 'pii' === (string) $row['denial_reason'] ) {
			$pii = true;
		}

		return array(
			'id'                => self::entry_id( $row ),
			'day_key'           => $day_key,
			'sampled_at'        => $sampled_at,
			'score'             => $score,
			'ts'                => max( 0, (int) ( $row['ts'] ?? 0 ) ),
			'plugin'            => (string) ( $row['plugin'] ?? '' ),
			'provider'          => Cost::normalize_provider_id( (string) ( $row['provider'] ?? '' ) ),
			'model'             => (string) ( $row['model'] ?? '' ),
			'decision'          => (string) ( $row['decision'] ?? '' ),
			'operation'         => $op,
			'capability_family' => $family,
			'estimated_usd'     => self::estimate_row_usd( $row ),
			'pii_flagged'       => $pii,
			'verdict'           => '',
			'note'              => '',
			'reviewed_at'       => 0,
			'reviewer_id'       => 0,
		);
	}

	/**
	 * Run daily sampling. Idempotent for already-queued entry ids.
	 *
	 * @param array<string,mixed>|null $log Log.
	 * @return array{added:int,candidates:int,selected:int}
	 */
	public static function maybe_sample( ?array $log = null, ?int $now = null ): array {
		$result = array(
			'added'      => 0,
			'candidates' => 0,
			'selected'   => 0,
		);
		if ( ! self::is_enabled() ) {
			return $result;
		}
		$now      = null !== $now && $now > 0 ? $now : Clock::now();
		$settings = self::get_settings();
		$day_key  = self::day_key( $now );
		$rows     = self::activity_rows( $log );
		$queue    = self::get_queue();
		$existing = array();
		foreach ( $queue as $q ) {
			$existing[ (string) $q['id'] ] = true;
		}

		$picked = array();
		foreach ( $rows as $row ) {
			$row_day = self::day_key( (int) ( $row['ts'] ?? 0 ) );
			if ( $row_day !== $day_key ) {
				continue;
			}
			++$result['candidates'];
			$entry_id = self::entry_id( $row );
			if ( isset( $existing[ $entry_id ] ) ) {
				continue;
			}
			$score = self::sample_score( $day_key, $entry_id );
			if ( ! self::is_selected( $score, (float) $settings['sample_rate'] ) ) {
				continue;
			}
			$picked[] = array(
				'score' => $score,
				'row'   => $row,
				'id'    => $entry_id,
			);
		}

		usort(
			$picked,
			static function ( array $a, array $b ): int {
				$cmp = $a['score'] <=> $b['score'];
				if ( 0 !== $cmp ) {
					return $cmp;
				}

				return strcmp( (string) $a['id'], (string) $b['id'] );
			}
		);
		$cap = (int) $settings['rows_per_day'];
		if ( count( $picked ) > $cap ) {
			$picked = array_slice( $picked, 0, $cap );
		}
		$result['selected'] = count( $picked );

		foreach ( $picked as $item ) {
			$queue[] = self::snapshot_from_log_row( $item['row'], $day_key, (int) $item['score'], $now );
			$existing[ (string) $item['id'] ] = true;
			++$result['added'];
		}
		if ( $result['added'] > 0 ) {
			self::save_queue( $queue );
		}

		return $result;
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function pending_queue( ?array $queue = null ): array {
		if ( null === $queue ) {
			$queue = self::get_queue();
		}
		$out = array();
		foreach ( $queue as $row ) {
			if ( '' === (string) ( $row['verdict'] ?? '' ) ) {
				$out[] = $row;
			}
		}

		return $out;
	}

	/**
	 * @return array{
	 *   days_sampled:int,
	 *   sampled:int,
	 *   reviewed:int,
	 *   pending:int,
	 *   looks_right:int,
	 *   concern:int,
	 *   coverage_pct:float|null,
	 *   reviewed_pct:float|null,
	 *   median_lag_seconds:int|null,
	 *   candidates_today:int,
	 *   sample_rate:float
	 * }
	 */
	public static function coverage_ledger( ?array $log = null, ?array $queue = null, ?int $now = null ): array {
		$settings = self::get_settings();
		$now      = null !== $now && $now > 0 ? $now : Clock::now();
		if ( null === $queue ) {
			$queue = self::get_queue();
		}
		$days         = array();
		$sampled      = count( $queue );
		$reviewed     = 0;
		$looks_right  = 0;
		$concern      = 0;
		$pending      = 0;
		$lags         = array();
		foreach ( $queue as $row ) {
			$days[ (string) $row['day_key'] ] = true;
			$verdict = (string) ( $row['verdict'] ?? '' );
			if ( '' === $verdict ) {
				++$pending;
				continue;
			}
			++$reviewed;
			if ( self::VERDICT_LOOKS_RIGHT === $verdict ) {
				++$looks_right;
			} elseif ( self::VERDICT_CONCERN === $verdict ) {
				++$concern;
			}
			$sampled_at  = (int) ( $row['sampled_at'] ?? 0 );
			$reviewed_at = (int) ( $row['reviewed_at'] ?? 0 );
			if ( $sampled_at > 0 && $reviewed_at >= $sampled_at ) {
				$lags[] = $reviewed_at - $sampled_at;
			}
		}

		$candidates_today = 0;
		$day_key          = self::day_key( $now );
		foreach ( self::activity_rows( $log ) as $row ) {
			if ( self::day_key( (int) ( $row['ts'] ?? 0 ) ) === $day_key ) {
				++$candidates_today;
			}
		}

		$median = null;
		if ( ! empty( $lags ) ) {
			sort( $lags, SORT_NUMERIC );
			$mid = (int) floor( count( $lags ) / 2 );
			if ( 0 === count( $lags ) % 2 ) {
				$median = (int) round( ( $lags[ $mid - 1 ] + $lags[ $mid ] ) / 2 );
			} else {
				$median = (int) $lags[ $mid ];
			}
		}

		$coverage = null;
		if ( $candidates_today > 0 ) {
			$today_sampled = 0;
			foreach ( $queue as $row ) {
				if ( (string) $row['day_key'] === $day_key ) {
					++$today_sampled;
				}
			}
			$coverage = round( ( $today_sampled / $candidates_today ) * 100, 2 );
		}

		$reviewed_pct = null;
		if ( $sampled > 0 ) {
			$reviewed_pct = round( ( $reviewed / $sampled ) * 100, 2 );
		}

		return array(
			'days_sampled'        => count( $days ),
			'sampled'             => $sampled,
			'reviewed'            => $reviewed,
			'pending'             => $pending,
			'looks_right'         => $looks_right,
			'concern'             => $concern,
			'coverage_pct'        => $coverage,
			'reviewed_pct'        => $reviewed_pct,
			'median_lag_seconds'  => $median,
			'candidates_today'    => $candidates_today,
			'sample_rate'         => (float) $settings['sample_rate'],
		);
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function stale_pending( ?array $queue = null, ?int $now = null ): array {
		if ( null === $queue ) {
			$queue = self::get_queue();
		}
		$now   = null !== $now && $now > 0 ? $now : Clock::now();
		$cut   = $now - ( self::STALE_AFTER_DAYS * DAY_IN_SECONDS );
		$stale = array();
		foreach ( $queue as $row ) {
			if ( '' !== (string) ( $row['verdict'] ?? '' ) ) {
				continue;
			}
			$sampled_at = (int) ( $row['sampled_at'] ?? 0 );
			if ( $sampled_at > 0 && $sampled_at <= $cut ) {
				$stale[] = $row;
			}
		}

		return $stale;
	}

	/**
	 * Record a verdict. Concern fires informational log + one alert per fingerprint.
	 *
	 * @return array{ok:bool,error?:string,row?:array<string,mixed>}
	 */
	public static function record_verdict( string $id, string $verdict, string $note = '', ?int $reviewer_id = null, ?int $now = null ): array {
		$id      = sanitize_key( $id );
		$verdict = self::sanitize_verdict( $verdict );
		if ( '' === $id || '' === $verdict ) {
			return array(
				'ok'    => false,
				'error' => 'invalid',
			);
		}
		$now = null !== $now && $now > 0 ? $now : Clock::now();
		if ( null === $reviewer_id ) {
			$reviewer_id = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
		}
		$queue = self::get_queue();
		$found = null;
		foreach ( $queue as $i => $row ) {
			if ( (string) $row['id'] !== $id ) {
				continue;
			}
			if ( '' !== (string) ( $row['verdict'] ?? '' ) ) {
				return array(
					'ok'    => false,
					'error' => 'already_reviewed',
					'row'   => $row,
				);
			}
			$queue[ $i ]['verdict']     = $verdict;
			$queue[ $i ]['note']        = self::sanitize_note( $note, 500 );
			$queue[ $i ]['reviewed_at'] = $now;
			$queue[ $i ]['reviewer_id'] = max( 0, (int) $reviewer_id );
			$found                      = $queue[ $i ];
			break;
		}
		if ( null === $found ) {
			return array(
				'ok'    => false,
				'error' => 'not_found',
			);
		}
		self::save_queue( $queue );

		if ( self::VERDICT_CONCERN === $verdict ) {
			self::emit_concern( $found, $now );
		}

		return array(
			'ok'  => true,
			'row' => $found,
		);
	}

	/**
	 * @param array<string,mixed> $row Queue row.
	 */
	public static function emit_concern( array $row, ?int $now = null ): void {
		$now = null !== $now && $now > 0 ? $now : Clock::now();
		$fp  = self::alert_fingerprint( (string) $row['id'] );

		self::append_activity(
			array(
				'ts'                => $now,
				'decision'          => 'spot_check_concern',
				'channel'           => 'spot_check',
				'spot_check'        => 'concern',
				'plugin'            => (string) ( $row['plugin'] ?? '' ),
				'provider'          => (string) ( $row['provider'] ?? '' ),
				'model'             => (string) ( $row['model'] ?? '' ),
				'operation'         => (string) ( $row['operation'] ?? '' ),
				'capability_family' => (string) ( $row['capability_family'] ?? '' ),
				'queue_id'          => (string) ( $row['id'] ?? '' ),
				'reviewer_id'       => (int) ( $row['reviewer_id'] ?? 0 ),
				'note'              => (string) ( $row['note'] ?? '' ),
			)
		);

		$alerted = self::get_alerted();
		if ( isset( $alerted[ $fp ] ) ) {
			return;
		}
		$plugin_for_snooze = (string) ( $row['plugin'] ?? '' );
		if ( '' !== $plugin_for_snooze
			&& class_exists( Alert_Snooze::class, false )
			&& Alert_Snooze::should_suppress( $plugin_for_snooze, self::ALERT_KIND, $now ) ) {
			return;
		}
		if ( self::fire_alert( $row, $now ) ) {
			$alerted[ $fp ] = true;
			self::put_alerted( $alerted );
		}
	}

	/**
	 * @param array<string,mixed> $event Event.
	 */
	public static function append_activity( array $event ): void {
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'append_log_event' ) ) {
			Policy::append_log_event( $event );

			return;
		}
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}
		$log[] = $event;
		if ( count( $log ) > 200 ) {
			$log = array_slice( $log, -200 );
		}
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
	}

	/**
	 * @param array<string,mixed> $row Queue row.
	 */
	private static function fire_alert( array $row, int $now ): bool {
		$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}
		$email = '';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		}
		if ( '' === $email ) {
			return false;
		}

		$subject = self::build_subject( $row );
		$body    = self::build_body( $row );

		$ok = false;
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

		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'       => 'handl_aicac_spot_check_concern',
						'queue_id'   => (string) ( $row['id'] ?? '' ),
						'plugin'     => (string) ( $row['plugin'] ?? '' ),
						'provider'   => (string) ( $row['provider'] ?? '' ),
						'model'      => (string) ( $row['model'] ?? '' ),
						'decision'   => (string) ( $row['decision'] ?? '' ),
						'note'       => (string) ( $row['note'] ?? '' ),
						'reviewer'   => (int) ( $row['reviewer_id'] ?? 0 ),
						'site'       => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'         => $now,
					)
				);
			}
		}

		return $ok;
	}

	/**
	 * @param array<string,mixed> $row Queue row.
	 */
	public static function build_subject( array $row ): string {
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';

		return sprintf(
			/* translators: 1: site name, 2: plugin basename */
			__( '[%1$s] Spot-check concern: %2$s', 'handl-ai-connector-access-control' ),
			$site,
			'' !== (string) ( $row['plugin'] ?? '' ) ? (string) $row['plugin'] : __( '(unknown plugin)', 'handl-ai-connector-access-control' )
		);
	}

	/**
	 * @param array<string,mixed> $row Queue row.
	 */
	public static function build_body( array $row ): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control — spot-check concern (informational; no deny).', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: plugin */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			(string) ( $row['plugin'] ?? '' )
		);
		$lines[] = sprintf(
			/* translators: %s: provider */
			__( 'Provider: %s', 'handl-ai-connector-access-control' ),
			(string) ( $row['provider'] ?? '' )
		);
		$lines[] = sprintf(
			/* translators: %s: model */
			__( 'Model: %s', 'handl-ai-connector-access-control' ),
			(string) ( $row['model'] ?? '' )
		);
		$lines[] = sprintf(
			/* translators: %s: decision */
			__( 'Decision: %s', 'handl-ai-connector-access-control' ),
			(string) ( $row['decision'] ?? '' )
		);
		if ( '' !== (string) ( $row['note'] ?? '' ) ) {
			$lines[] = sprintf(
				/* translators: %s: reviewer note */
				__( 'Note: %s', 'handl-ai-connector-access-control' ),
				(string) $row['note']
			);
		}
		$lines[] = '';
		$lines[] = __( 'Review the spot-check queue:', 'handl-ai-connector-access-control' );
		$lines[] = self::admin_url();

		return implode( "\n", $lines );
	}

	public static function admin_url(): string {
		if ( function_exists( 'admin_url' ) ) {
			return (string) admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		}

		return 'admin.php?page=' . self::PAGE_SLUG;
	}

	public static function format_ts( int $ts ): string {
		if ( $ts <= 0 ) {
			return '—';
		}
		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( 'Y-m-d H:i', $ts );
		}

		return gmdate( 'Y-m-d H:i', $ts );
	}

	public static function format_usd( ?float $usd ): string {
		if ( null === $usd ) {
			return '—';
		}
		if ( class_exists( Cost::class, false ) && method_exists( Cost::class, 'format_usd' ) ) {
			return '$' . Cost::format_usd( $usd );
		}

		return '$' . number_format( $usd, 4, '.', '' );
	}

	/**
	 * @param list<array<string,mixed>>|null $queue Queue.
	 */
	public static function csv_for_queue( ?array $queue = null ): string {
		if ( null === $queue ) {
			$queue = self::get_queue();
		}
		$lines   = array();
		$lines[] = self::csv_line(
			array(
				'id',
				'day_key',
				'sampled_at',
				'ts',
				'plugin',
				'provider',
				'model',
				'decision',
				'operation',
				'capability_family',
				'estimated_usd',
				'pii_flagged',
				'verdict',
				'note',
				'reviewed_at',
				'reviewer_id',
			)
		);
		foreach ( $queue as $row ) {
			$lines[] = self::csv_line(
				array(
					(string) $row['id'],
					(string) $row['day_key'],
					self::format_ts( (int) $row['sampled_at'] ),
					self::format_ts( (int) $row['ts'] ),
					(string) $row['plugin'],
					(string) $row['provider'],
					(string) $row['model'],
					(string) $row['decision'],
					(string) $row['operation'],
					(string) $row['capability_family'],
					null !== $row['estimated_usd'] ? (string) $row['estimated_usd'] : '',
					! empty( $row['pii_flagged'] ) ? 'yes' : 'no',
					(string) $row['verdict'],
					(string) $row['note'],
					self::format_ts( (int) $row['reviewed_at'] ),
					(string) (int) $row['reviewer_id'],
				)
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param list<string|int|float> $fields Fields.
	 */
	private static function csv_line( array $fields ): string {
		$out = array();
		foreach ( $fields as $field ) {
			$f = str_replace( '"', '""', (string) $field );
			if ( preg_match( '/[",\n\r]/', $f ) ) {
				$out[] = '"' . $f . '"';
			} else {
				$out[] = $f;
			}
		}

		return implode( ',', $out );
	}

	/**
	 * @param array<string,mixed>          $ledger Ledger.
	 * @param list<array<string,mixed>>    $queue  Queue.
	 */
	public static function build_print_html( array $ledger, array $queue ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8" />';
		$html .= '<title>' . esc_html__( 'Spot-check coverage ledger', 'handl-ai-connector-access-control' ) . '</title>';
		$html .= '<style>body{font-family:system-ui,sans-serif;margin:24px;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;}th{background:#f6f7f7;}</style>';
		$html .= '</head><body>';
		$html .= '<h1>' . esc_html__( 'Spot-check coverage ledger', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Human oversight sample of allowed AI traffic. Informational — never denies.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<ul>';
		$html .= '<li>' . esc_html(
			sprintf(
				/* translators: %s: sample rate percent */
				__( 'Configured sample rate: %s%%', 'handl-ai-connector-access-control' ),
				(string) round( (float) $ledger['sample_rate'] * 100, 4 )
			)
		) . '</li>';
		$html .= '<li>' . esc_html(
			sprintf(
				/* translators: 1: days, 2: sampled, 3: reviewed, 4: pending */
				__( 'Days sampled: %1$d. Sampled: %2$d. Reviewed: %3$d. Pending: %4$d.', 'handl-ai-connector-access-control' ),
				(int) $ledger['days_sampled'],
				(int) $ledger['sampled'],
				(int) $ledger['reviewed'],
				(int) $ledger['pending']
			)
		) . '</li>';
		$html .= '<li>' . esc_html(
			sprintf(
				/* translators: 1: looks-right count, 2: concern count */
				__( 'Looks right: %1$d. Concern: %2$d.', 'handl-ai-connector-access-control' ),
				(int) $ledger['looks_right'],
				(int) $ledger['concern']
			)
		) . '</li>';
		if ( null !== $ledger['reviewed_pct'] ) {
			$html .= '<li>' . esc_html(
				sprintf(
					/* translators: %s: percent */
					__( 'Queue reviewed: %s%%', 'handl-ai-connector-access-control' ),
					(string) $ledger['reviewed_pct']
				)
			) . '</li>';
		}
		if ( null !== $ledger['median_lag_seconds'] ) {
			$html .= '<li>' . esc_html(
				sprintf(
					/* translators: %d: seconds */
					__( 'Median review lag: %d seconds', 'handl-ai-connector-access-control' ),
					(int) $ledger['median_lag_seconds']
				)
			) . '</li>';
		}
		$html .= '</ul>';
		$html .= '<table><thead><tr>';
		foreach ( array( 'Day', 'Plugin', 'Provider', 'Model', 'Decision', 'Verdict', 'Reviewer', 'Note' ) as $h ) {
			$html .= '<th>' . esc_html( $h ) . '</th>';
		}
		$html .= '</tr></thead><tbody>';
		foreach ( $queue as $row ) {
			$html .= '<tr>';
			$html .= '<td>' . esc_html( (string) $row['day_key'] ) . '</td>';
			$html .= '<td>' . esc_html( (string) $row['plugin'] ) . '</td>';
			$html .= '<td>' . esc_html( (string) $row['provider'] ) . '</td>';
			$html .= '<td>' . esc_html( (string) $row['model'] ) . '</td>';
			$html .= '<td>' . esc_html( (string) $row['decision'] ) . '</td>';
			$html .= '<td>' . esc_html( '' !== (string) $row['verdict'] ? (string) $row['verdict'] : 'pending' ) . '</td>';
			$html .= '<td>' . esc_html( (string) (int) $row['reviewer_id'] ) . '</td>';
			$html .= '<td>' . esc_html( (string) $row['note'] ) . '</td>';
			$html .= '</tr>';
		}
		$html .= '</tbody></table></body></html>';

		return $html;
	}

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Spot-check reviews', 'handl-ai-connector-access-control' ),
			__( 'Spot-check', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( self::is_enabled() ) {
			self::maybe_sample();
		}
		$settings   = self::get_settings();
		$can_manage = Caps::user_can_manage();
		$queue      = self::get_queue();
		$ledger     = self::coverage_ledger( null, $queue );
		$csv        = add_query_arg(
			array(
				'page'                       => self::PAGE_SLUG,
				'handl_aicac_spot_check_csv' => '1',
				'_wpnonce'                   => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_spot_check_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print = add_query_arg(
			array(
				'page'                         => self::PAGE_SLUG,
				'handl_aicac_spot_check_print' => '1',
				'_wpnonce'                     => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_spot_check_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Spot-check reviews', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Deterministic daily sample of allowed AI calls for human oversight. Concern is informational and never denies. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable spot-check', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Sample allowed traffic into a human review queue', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-spot-check-rate">' . esc_html__( 'Sample rate (%)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_SAMPLE_RATE ) . '" id="handl-aicac-spot-check-rate" type="number" min="0" max="100" step="0.01" value="' . esc_attr( (string) round( (float) $settings['sample_rate'] * 100, 4 ) ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'Default 1%. Selection uses a salted hash so the sample is reproducible and not gameable.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-spot-check-cap">' . esc_html__( 'Max rows per day', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_ROWS_PER_DAY ) . '" id="handl-aicac-spot-check-cap" type="number" min="1" max="500" step="1" value="' . esc_attr( (string) (int) $settings['rows_per_day'] ) . '" class="small-text" />';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save spot-check settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		echo '<h2>' . esc_html__( 'Coverage ledger', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<ul>';
		echo '<li>' . esc_html(
			sprintf(
				/* translators: 1: sampled, 2: reviewed, 3: pending, 4: looks-right, 5: concern */
				__( 'Sampled %1$d · reviewed %2$d · pending %3$d · looks right %4$d · concern %5$d', 'handl-ai-connector-access-control' ),
				(int) $ledger['sampled'],
				(int) $ledger['reviewed'],
				(int) $ledger['pending'],
				(int) $ledger['looks_right'],
				(int) $ledger['concern']
			)
		) . '</li>';
		if ( null !== $ledger['reviewed_pct'] ) {
			echo '<li>' . esc_html(
				sprintf(
					/* translators: %s: percent */
					__( 'Queue reviewed: %s%%', 'handl-ai-connector-access-control' ),
					(string) $ledger['reviewed_pct']
				)
			) . '</li>';
		}
		if ( null !== $ledger['coverage_pct'] ) {
			echo '<li>' . esc_html(
				sprintf(
					/* translators: %s: percent of today's allowed traffic sampled */
					__( 'Today sampled vs allowed traffic: %s%%', 'handl-ai-connector-access-control' ),
					(string) $ledger['coverage_pct']
				)
			) . '</li>';
		}
		echo '</ul>';
		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Review queue', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $queue ) ) {
			echo '<p>' . esc_html__( 'No sampled rows yet. Enable spot-check and wait for allowed AI traffic today.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'When', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Plugin / provider', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Model / family', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Outcome / cost / PII', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Verdict', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';

		foreach ( $queue as $row ) {
			echo '<tr>';
			echo '<td>' . esc_html( self::format_ts( (int) $row['ts'] ) );
			echo '<br /><span class="description">' . esc_html( (string) $row['day_key'] ) . '</span></td>';
			echo '<td><code>' . esc_html( (string) $row['plugin'] ) . '</code><br />' . esc_html( (string) $row['provider'] ) . '</td>';
			echo '<td>' . esc_html( (string) $row['model'] );
			if ( '' !== (string) $row['capability_family'] ) {
				echo '<br /><span class="description">' . esc_html( (string) $row['capability_family'] ) . '</span>';
			}
			echo '</td>';
			echo '<td>' . esc_html( (string) $row['decision'] );
			echo '<br />' . esc_html( self::format_usd( $row['estimated_usd'] ?? null ) );
			echo '<br />' . esc_html( ! empty( $row['pii_flagged'] ) ? __( 'PII flagged', 'handl-ai-connector-access-control' ) : __( 'No PII signal', 'handl-ai-connector-access-control' ) );
			echo '</td><td>';
			if ( '' !== (string) $row['verdict'] ) {
				echo esc_html( (string) $row['verdict'] );
				if ( '' !== (string) $row['note'] ) {
					echo '<br /><span class="description">' . esc_html( (string) $row['note'] ) . '</span>';
				}
				if ( (int) $row['reviewer_id'] > 0 ) {
					echo '<br /><span class="description">' . esc_html(
						sprintf(
							/* translators: %d: user id */
							__( 'Reviewer #%d', 'handl-ai-connector-access-control' ),
							(int) $row['reviewer_id']
						)
					) . '</span>';
				}
			} elseif ( $can_manage ) {
				$action = admin_url( 'admin-post.php' );
				echo '<form method="post" action="' . esc_url( $action ) . '" style="margin:0;">';
				echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_VERDICT ) . '" />';
				echo '<input type="hidden" name="queue_id" value="' . esc_attr( (string) $row['id'] ) . '" />';
				if ( function_exists( 'wp_nonce_field' ) ) {
					wp_nonce_field( self::ACTION_VERDICT );
				}
				echo '<label class="screen-reader-text" for="note-' . esc_attr( (string) $row['id'] ) . '">' . esc_html__( 'Note', 'handl-ai-connector-access-control' ) . '</label>';
				echo '<input type="text" class="regular-text" name="note" id="note-' . esc_attr( (string) $row['id'] ) . '" placeholder="' . esc_attr__( 'Optional one-line note', 'handl-ai-connector-access-control' ) . '" /> ';
				echo '<button type="submit" name="verdict" value="' . esc_attr( self::VERDICT_LOOKS_RIGHT ) . '" class="button">' . esc_html__( 'Looks right', 'handl-ai-connector-access-control' ) . '</button> ';
				echo '<button type="submit" name="verdict" value="' . esc_attr( self::VERDICT_CONCERN ) . '" class="button">' . esc_html__( 'Concern', 'handl-ai-connector-access-control' ) . '</button>';
				echo '</form>';
			} else {
				echo esc_html__( 'Pending', 'handl-ai-connector-access-control' );
			}
			echo '</td></tr>';
		}
		echo '</tbody></table></div>';
	}

	public static function maybe_staleness_notice(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! self::is_enabled() ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$stale = self::stale_pending();
		if ( empty( $stale ) ) {
			return;
		}
		echo '<div class="notice notice-warning"><p>';
		echo esc_html(
			sprintf(
				/* translators: %d: pending unreviewed count */
				_n(
					'%d sampled call has been waiting for review for more than %d days.',
					'%d sampled calls have been waiting for review for more than %d days.',
					count( $stale ),
					'handl-ai-connector-access-control'
				),
				count( $stale ),
				self::STALE_AFTER_DAYS
			)
		);
		echo '</p></div>';
	}

	public static function maybe_handle_csv(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_spot_check_csv'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_spot_check_csv' );
		$csv = self::csv_for_queue();
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=handl-aicac-spot-check.csv' );
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_spot_check_print'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_spot_check_print' );
		$queue  = self::get_queue();
		$ledger = self::coverage_ledger( null, $queue );
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		echo self::build_print_html( $ledger, $queue ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside builder.
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'You do not have permission to save spot-check settings.', 'handl-ai-connector-access-control' ) );
			}
			return;
		}
		check_admin_referer( self::ACTION_SAVE );

		$enabled = ! empty( $_POST[ self::POST_ENABLED ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$rate_raw = isset( $_POST[ self::POST_SAMPLE_RATE ] ) ? wp_unslash( (string) $_POST[ self::POST_SAMPLE_RATE ] ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$cap_raw = isset( $_POST[ self::POST_ROWS_PER_DAY ] ) ? wp_unslash( (string) $_POST[ self::POST_ROWS_PER_DAY ] ) : '';

		self::save_settings(
			array(
				'enabled'      => $enabled,
				'sample_rate'  => self::sanitize_sample_rate( $rate_raw !== '' ? ( (float) $rate_raw ) / 100.0 : self::DEFAULT_SAMPLE_RATE ),
				'rows_per_day' => self::sanitize_rows_per_day( $cap_raw ),
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

	public static function handle_verdict(): void {
		if ( ! Caps::user_can_manage() ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'You do not have permission to record a spot-check verdict.', 'handl-ai-connector-access-control' ) );
			}
			return;
		}
		check_admin_referer( self::ACTION_VERDICT );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$id = isset( $_POST['queue_id'] ) ? sanitize_key( wp_unslash( (string) $_POST['queue_id'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$verdict = isset( $_POST['verdict'] ) ? sanitize_key( wp_unslash( (string) $_POST['verdict'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$note = isset( $_POST['note'] ) ? wp_unslash( (string) $_POST['note'] ) : '';

		self::record_verdict( $id, $verdict, $note );

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

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac spot-check', CLI_Spot_Check::class );
	}
}

/**
 * WP-CLI: wp handl-aicac spot-check status|queue|verdict|export
 */
final class CLI_Spot_Check {

	/**
	 * Show spot-check status.
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
		if ( Spot_Check::is_enabled() ) {
			Spot_Check::maybe_sample();
		}
		$settings = Spot_Check::get_settings();
		$ledger   = Spot_Check::coverage_ledger();
		\WP_CLI::log(
			sprintf(
				'enabled=%s sample_rate=%s rows_per_day=%d days_sampled=%d sampled=%d reviewed=%d pending=%d looks_right=%d concern=%d',
				! empty( $settings['enabled'] ) ? 'yes' : 'no',
				(string) round( (float) $settings['sample_rate'] * 100, 4 ) . '%',
				(int) $settings['rows_per_day'],
				(int) $ledger['days_sampled'],
				(int) $ledger['sampled'],
				(int) $ledger['reviewed'],
				(int) $ledger['pending'],
				(int) $ledger['looks_right'],
				(int) $ledger['concern']
			)
		);
	}

	/**
	 * List the review queue.
	 *
	 * ## OPTIONS
	 *
	 * [--status=<status>]
	 * : pending, reviewed, or all. Default pending.
	 *
	 * [--format=<format>]
	 * : table, json, csv, or yaml. Default table.
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function queue( $args, $assoc_args ): void {
		unset( $args );
		if ( Spot_Check::is_enabled() ) {
			Spot_Check::maybe_sample();
		}
		$status = isset( $assoc_args['status'] ) ? sanitize_key( (string) $assoc_args['status'] ) : 'pending';
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$queue  = Spot_Check::get_queue();
		$rows   = array();
		foreach ( $queue as $row ) {
			$verdict = (string) ( $row['verdict'] ?? '' );
			if ( 'pending' === $status && '' !== $verdict ) {
				continue;
			}
			if ( 'reviewed' === $status && '' === $verdict ) {
				continue;
			}
			$rows[] = array(
				'id'       => (string) $row['id'],
				'day_key'  => (string) $row['day_key'],
				'plugin'   => (string) $row['plugin'],
				'provider' => (string) $row['provider'],
				'model'    => (string) $row['model'],
				'decision' => (string) $row['decision'],
				'verdict'  => '' !== $verdict ? $verdict : 'pending',
				'note'     => (string) $row['note'],
			);
		}
		if ( empty( $rows ) ) {
			\WP_CLI::log( 'No queue rows.' );
			return;
		}
		\WP_CLI\Utils\format_items(
			$format,
			$rows,
			array( 'id', 'day_key', 'plugin', 'provider', 'model', 'decision', 'verdict', 'note' )
		);
	}

	/**
	 * Record a verdict for a queue id.
	 *
	 * ## OPTIONS
	 *
	 * <id>
	 * : Queue entry id.
	 *
	 * <verdict>
	 * : looks_right or concern.
	 *
	 * [--note=<note>]
	 * : Optional one-line note.
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function verdict( $args, $assoc_args ): void {
		$id      = isset( $args[0] ) ? sanitize_key( (string) $args[0] ) : '';
		$verdict = isset( $args[1] ) ? sanitize_key( (string) $args[1] ) : '';
		$note    = isset( $assoc_args['note'] ) ? (string) $assoc_args['note'] : '';
		$result  = Spot_Check::record_verdict( $id, $verdict, $note );
		if ( empty( $result['ok'] ) ) {
			\WP_CLI::error( 'Could not record verdict: ' . (string) ( $result['error'] ?? 'unknown' ) );
		}
		\WP_CLI::success( 'Recorded verdict ' . $verdict . ' for ' . $id );
	}

	/**
	 * Export the coverage ledger / queue.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table, json, csv, or yaml. Default csv.
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function export( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'csv';
		$queue  = Spot_Check::get_queue();
		if ( 'csv' === $format ) {
			\WP_CLI::print_value( Spot_Check::csv_for_queue( $queue ), array( 'format' => 'csv' ) );
			return;
		}
		$table = array();
		foreach ( $queue as $row ) {
			$table[] = array(
				'id'       => (string) $row['id'],
				'day_key'  => (string) $row['day_key'],
				'plugin'   => (string) $row['plugin'],
				'provider' => (string) $row['provider'],
				'verdict'  => '' !== (string) $row['verdict'] ? (string) $row['verdict'] : 'pending',
				'reviewer' => (int) $row['reviewer_id'],
			);
		}
		if ( empty( $table ) ) {
			\WP_CLI::log( 'No queue rows.' );
			return;
		}
		\WP_CLI\Utils\format_items(
			$format,
			$table,
			array( 'id', 'day_key', 'plugin', 'provider', 'verdict', 'reviewer' )
		);
	}
}
