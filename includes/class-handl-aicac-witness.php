<?php
/**
 * AICAC-WITNESS (#419): activity-log continuity attestation (report-only).
 *
 * The activity log is the evidence trail for every governance decision. This
 * class keeps a salted, tamper-evident fingerprint ("checkpoint") of the log on
 * a throttled admin request and, on the next check, explains any shrinkage: was
 * it an expected retention prune / ring-buffer rollover, or did rows vanish
 * without a recorded reason?
 *
 * Checkpoint digest format (version 1). The digest never contains bodies,
 * prompts, plugin slugs or paths — only timestamps:
 *
 *   summary = "v1|n=<rows>|t=<timed rows>|d=<Y-m-d:count,...>|r=<rolling>"
 *   d       = per-UTC-day row counts, sorted by date ascending
 *   r       = sha256 chain over the ascending timestamps:
 *             r0 = ''; r(i) = sha256( r(i-1) . '|' . ts(i) )
 *   digest  = hash_hmac( 'sha256', summary, secret )
 *
 * The secret is site-local: wp_salt('auth') when available, else a random salt
 * stored once in this class's own state. It is never exported. The
 * `handl_aicac_witness_secret` filter may override it (tests). A secret change
 * silently re-baselines instead of raising a finding.
 *
 * Design rules:
 * - Report only. It never writes, repairs or restores a log row; the log
 *   option is read, never written. Writes are confined to its own two options.
 * - Detection runs on a throttled admin_init (and on demand from WP-CLI),
 *   never from a cron hook. This class schedules nothing.
 * - Retention evidence (Log_Retention meta, Policy window, Legal_Hold) is read
 *   through class_exists / method_exists guards only. Missing classes mean
 *   "no evidence"; Legal_Hold absent means "no hold info".
 * - Exactly one re-arming [WITNESS] alert (0 -> unsanctioned findings),
 *   latched until the open unsanctioned count returns to zero.
 * - Own two options. OFF by default.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Activity-log continuity attestation.
 */
final class Witness {

	public const SETTINGS_OPTION = 'handl_aicac_witness';

	public const STATE_OPTION = 'handl_aicac_witness_state';

	public const PAGE_SLUG = 'handl-aicac-witness';

	public const ALERT_KIND = 'witness';

	public const FRAMING = 'report_only_never_repairs_log';

	public const FILTER_SECRET = 'handl_aicac_witness_secret';

	public const POST_PRESENT = 'handl_aicac_witness_present';

	public const POST_ENABLED = 'handl_aicac_witness_enabled';

	public const ACTION_SAVE = 'handl_aicac_witness_save';

	/** Admin check throttle in seconds (5 minutes). */
	public const CHECK_THROTTLE_SECONDS = 300;

	/** Checkpoints kept in the ledger. */
	public const HISTORY_CAP = 40;

	/** Findings kept in the ledger. */
	public const FINDINGS_CAP = 40;

	/** An unsanctioned finding stays "open" (alert latched) this long. */
	public const FINDING_OPEN_SECONDS = 604800;

	/** Most timestamps a checkpoint may carry (log limit is at most 1000). */
	public const STAMP_CAP = 2000;

	/** Rows dated this far before the previous newest row are "back-dated". */
	public const BACKDATE_TOLERANCE_SEC = 120;

	public const DEFAULT_LOG_LIMIT = 200;

	public const CLASS_SANCTIONED   = 'sanctioned';
	public const CLASS_UNSANCTIONED = 'unsanctioned';

	public const CODE_RETENTION_PRUNE    = 'retention_prune';
	public const CODE_TTL_ON_WRITE       = 'ttl_on_write';
	public const CODE_RING_CAP           = 'ring_cap';
	public const CODE_ROWS_REMOVED       = 'rows_removed_unexplained';
	public const CODE_ROWS_MISSING       = 'rows_missing_in_window';
	public const CODE_NEWEST_REGRESSED   = 'newest_regressed';
	public const CODE_CONTENT_REWRITE    = 'content_rewrite';
	public const CODE_BACKDATED          = 'backdated_rows';
	public const CODE_LEGAL_HOLD_PRUNED  = 'prune_despite_legal_hold';

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	/** @var int|null */
	private static $test_now = null;

	/** @var bool */
	private static $test_log_set = false;

	/** @var array<int,mixed>|null */
	private static $test_log = null;

	/** @var bool */
	private static $test_meta_set = false;

	/** @var array<string,mixed>|null */
	private static $test_meta = null;

	/** @var callable|null */
	private static $test_hold_check = null;

	/** @var bool */
	private static $test_force_stored_salt = false;

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
		self::$registered             = false;
		self::$test_mails             = array();
		self::$test_now               = null;
		self::$test_log_set           = false;
		self::$test_log               = null;
		self::$test_meta_set          = false;
		self::$test_meta              = null;
		self::$test_hold_check        = null;
		self::$test_force_stored_salt = false;
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
	 * Inject the activity log for unit tests. Null reads the real option.
	 *
	 * @param array<int,mixed>|null $log Log rows or null.
	 */
	public static function set_test_log( ?array $log ): void {
		self::$test_log_set = null !== $log;
		self::$test_log     = $log;
	}

	/**
	 * Inject Log_Retention meta for unit tests (same shape as
	 * Log_Retention::meta(): last_prune_ts, export_pending, export_period_days).
	 * Null reads the real source.
	 *
	 * @param array<string,mixed>|null $meta Meta or null.
	 */
	public static function set_test_retention_meta( ?array $meta ): void {
		self::$test_meta_set = null !== $meta;
		self::$test_meta     = $meta;
	}

	/**
	 * Inject a Legal_Hold row check for unit tests: callable( array $row ): bool.
	 *
	 * @param callable|null $check Callback or null.
	 */
	public static function set_test_hold_check( ?callable $check ): void {
		self::$test_hold_check = $check;
	}

	/**
	 * Force the stored-salt secret path (as when wp_salt() is unavailable).
	 */
	public static function set_test_force_stored_salt( bool $force ): void {
		self::$test_force_stored_salt = $force;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{enabled:bool}
	 */
	public static function defaults(): array {
		return array(
			'enabled' => false,
		);
	}

	/**
	 * @return array{enabled:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return self::defaults();
		}

		return array(
			'enabled' => ! empty( $raw['enabled'] ),
		);
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
	 * @return array<string,mixed>
	 */
	public static function defaults_state(): array {
		return array(
			'alerted'       => false,
			'last_check_ts' => 0,
			'salt'          => '',
			'last'          => null,
			'history'       => array(),
			'findings'      => array(),
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw state.
	 * @return array<string,mixed>
	 */
	public static function sanitize_state( $raw ): array {
		$state = self::defaults_state();
		if ( ! is_array( $raw ) ) {
			return $state;
		}

		$history = array();
		if ( isset( $raw['history'] ) && is_array( $raw['history'] ) ) {
			foreach ( $raw['history'] as $row ) {
				$clean = self::sanitize_checkpoint( $row, false );
				if ( null !== $clean ) {
					$history[] = $clean;
				}
			}
		}
		if ( count( $history ) > self::HISTORY_CAP ) {
			$history = array_slice( $history, -self::HISTORY_CAP );
		}

		$findings = array();
		if ( isset( $raw['findings'] ) && is_array( $raw['findings'] ) ) {
			foreach ( $raw['findings'] as $row ) {
				$clean = self::sanitize_finding( $row );
				if ( null !== $clean ) {
					$findings[] = $clean;
				}
			}
		}
		if ( count( $findings ) > self::FINDINGS_CAP ) {
			$findings = array_slice( $findings, -self::FINDINGS_CAP );
		}

		$salt = isset( $raw['salt'] ) ? preg_replace( '/[^a-f0-9]/', '', strtolower( (string) $raw['salt'] ) ) : '';

		$state['alerted']       = ! empty( $raw['alerted'] );
		$state['last_check_ts'] = max( 0, (int) ( $raw['last_check_ts'] ?? 0 ) );
		$state['salt']          = substr( (string) $salt, 0, 64 );
		$state['last']          = self::sanitize_checkpoint( $raw['last'] ?? null, true );
		$state['history']       = $history;
		$state['findings']      = $findings;

		return $state;
	}

	/**
	 * @param mixed $row        Raw checkpoint.
	 * @param bool  $with_stamps Keep the timestamp list (only the `last` pointer does).
	 * @return array<string,mixed>|null
	 */
	public static function sanitize_checkpoint( $row, bool $with_stamps ): ?array {
		if ( ! is_array( $row ) ) {
			return null;
		}
		$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		if ( $ts <= 0 ) {
			return null;
		}
		$out = array(
			'ts'        => $ts,
			'row_count' => max( 0, (int) ( $row['row_count'] ?? 0 ) ),
			'newest_ts' => max( 0, (int) ( $row['newest_ts'] ?? 0 ) ),
			'oldest_ts' => max( 0, (int) ( $row['oldest_ts'] ?? 0 ) ),
			'digest'    => substr( (string) preg_replace( '/[^a-f0-9]/', '', strtolower( (string) ( $row['digest'] ?? '' ) ) ), 0, 64 ),
			'secret_fp' => substr( (string) preg_replace( '/[^a-f0-9]/', '', strtolower( (string) ( $row['secret_fp'] ?? '' ) ) ), 0, 16 ),
		);
		if ( $with_stamps && isset( $row['stamps'] ) && is_array( $row['stamps'] ) && count( $row['stamps'] ) <= self::STAMP_CAP ) {
			$stamps = array();
			foreach ( $row['stamps'] as $stamp ) {
				if ( is_numeric( $stamp ) && (int) $stamp > 0 ) {
					$stamps[] = (int) $stamp;
				}
			}
			sort( $stamps );
			$out['stamps'] = $stamps;
		}

		return $out;
	}

	/**
	 * @param mixed $row Raw finding.
	 * @return array<string,mixed>|null
	 */
	public static function sanitize_finding( $row ): ?array {
		if ( ! is_array( $row ) ) {
			return null;
		}
		$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		if ( $ts <= 0 ) {
			return null;
		}
		$class = (string) ( $row['classification'] ?? '' );
		if ( ! in_array( $class, array( self::CLASS_SANCTIONED, self::CLASS_UNSANCTIONED ), true ) ) {
			return null;
		}

		return array(
			'ts'             => $ts,
			'code'           => sanitize_key( (string) ( $row['code'] ?? '' ) ),
			'classification' => $class,
			'summary'        => sanitize_text_field( (string) ( $row['summary'] ?? '' ) ),
			'window_start'   => max( 0, (int) ( $row['window_start'] ?? 0 ) ),
			'window_end'     => max( 0, (int) ( $row['window_end'] ?? 0 ) ),
			'row_delta'      => (int) ( $row['row_delta'] ?? 0 ),
			'rows_removed'   => max( 0, (int) ( $row['rows_removed'] ?? 0 ) ),
			'rows_added'     => max( 0, (int) ( $row['rows_added'] ?? 0 ) ),
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
	 * Sources (all read-only)
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
	 * The activity log, read-only.
	 *
	 * @return array<int,mixed>
	 */
	public static function ledger(): array {
		if ( self::$test_log_set && is_array( self::$test_log ) ) {
			return self::$test_log;
		}
		$log = get_option( class_exists( Plugin::class, false ) ? Plugin::LOG_OPTION_KEY : 'handl_aicac_recent_calls', array() );

		return is_array( $log ) ? $log : array();
	}

	/**
	 * Site-local HMAC secret. May write the stored salt into $state (own state
	 * option) the first time it is needed.
	 *
	 * @param array<string,mixed> $state State (by reference).
	 */
	private static function secret_for( array &$state ): string {
		$secret = '';
		if ( ! self::$test_force_stored_salt && function_exists( 'wp_salt' ) ) {
			$secret = (string) wp_salt( 'auth' );
		}
		if ( '' === $secret ) {
			if ( '' === (string) $state['salt'] ) {
				try {
					$state['salt'] = bin2hex( random_bytes( 32 ) );
				} catch ( \Exception $e ) {
					$state['salt'] = hash( 'sha256', uniqid( '', true ) . wp_generate_password( 32, true, true ) );
				}
			}
			$secret = (string) $state['salt'];
		}
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( self::FILTER_SECRET, $secret );
			if ( is_string( $filtered ) && '' !== $filtered ) {
				$secret = $filtered;
			}
		}

		return $secret;
	}

	/**
	 * Retention evidence, read-only and guarded.
	 *
	 * @return array{last_prune_ts:int,days:?int,log_limit:int}
	 */
	public static function retention_evidence(): array {
		$meta = array();
		if ( self::$test_meta_set && is_array( self::$test_meta ) ) {
			$meta = self::$test_meta;
		} elseif ( class_exists( Log_Retention::class, false ) && method_exists( Log_Retention::class, 'meta' ) ) {
			$meta = Log_Retention::meta();
		} else {
			$raw  = get_option( 'handl_aicac_log_retention_meta', array() );
			$meta = is_array( $raw ) ? $raw : array();
		}

		$policy = array();
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' ) ) {
			$policy = Policy::get_policy();
			if ( ! is_array( $policy ) ) {
				$policy = array();
			}
		}

		$days = null;
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'sanitize_log_max_age_days' ) ) {
			$days = Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null );
			if ( null === $days ) {
				$days = Policy::sanitize_log_max_age_days( $meta['export_period_days'] ?? null );
			}
		} elseif ( isset( $meta['export_period_days'] ) && (int) $meta['export_period_days'] > 0 ) {
			$days = (int) $meta['export_period_days'];
		}

		$limit = (int) ( $policy['log_limit'] ?? self::DEFAULT_LOG_LIMIT );
		$limit = max( 20, min( 1000, $limit ) );

		return array(
			'last_prune_ts' => isset( $meta['last_prune_ts'] ) ? max( 0, (int) $meta['last_prune_ts'] ) : 0,
			'days'          => $days,
			'log_limit'     => $limit,
		);
	}

	/**
	 * How many of the removed timestamps a legal hold would have protected.
	 * Read-only; Legal_Hold may not exist, in which case there is no hold info.
	 *
	 * @param list<int> $removed Removed timestamps.
	 */
	private static function held_count( array $removed ): int {
		$held = 0;
		if ( null !== self::$test_hold_check ) {
			foreach ( $removed as $ts ) {
				if ( (bool) call_user_func( self::$test_hold_check, array( 'ts' => $ts ) ) ) {
					++$held;
				}
			}

			return $held;
		}
		$class = __NAMESPACE__ . '\\Legal_Hold';
		if ( ! class_exists( $class, false ) || ! method_exists( $class, 'has_active_holds' ) || ! method_exists( $class, 'row_is_held' ) ) {
			return 0;
		}
		if ( ! $class::has_active_holds() ) {
			return 0;
		}
		foreach ( $removed as $ts ) {
			if ( $class::row_is_held( array( 'ts' => $ts ) ) ) {
				++$held;
			}
		}

		return $held;
	}

	/* ---------------------------------------------------------------------
	 * Checkpoint computation
	 * ------------------------------------------------------------------ */

	/**
	 * Summarize a log into a checkpoint (without `ts`). Only timestamps are read.
	 *
	 * @param array<int,mixed> $log    Log rows.
	 * @param string           $secret HMAC secret.
	 * @return array<string,mixed>
	 */
	public static function summarize( array $log, string $secret ): array {
		$rows   = 0;
		$stamps = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			++$rows;
			$ts = isset( $row['ts'] ) && is_numeric( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts > 0 ) {
				$stamps[] = $ts;
			}
		}
		sort( $stamps );

		$days = array();
		$roll = '';
		foreach ( $stamps as $ts ) {
			$day          = gmdate( 'Y-m-d', $ts );
			$days[ $day ] = ( $days[ $day ] ?? 0 ) + 1;
			$roll         = hash( 'sha256', $roll . '|' . $ts );
		}
		ksort( $days );
		$buckets = array();
		foreach ( $days as $day => $count ) {
			$buckets[] = $day . ':' . $count;
		}

		$summary = 'v1|n=' . $rows . '|t=' . count( $stamps ) . '|d=' . implode( ',', $buckets ) . '|r=' . $roll;

		return array(
			'row_count' => $rows,
			'newest_ts' => empty( $stamps ) ? 0 : (int) end( $stamps ),
			'oldest_ts' => empty( $stamps ) ? 0 : (int) $stamps[0],
			'digest'    => hash_hmac( 'sha256', $summary, $secret ),
			'secret_fp' => substr( hash( 'sha256', 'witness-fp|' . $secret ), 0, 8 ),
			'stamps'    => $stamps,
		);
	}

	/**
	 * Values present more often in $a than in $b (multiset difference), sorted.
	 *
	 * @param list<int> $a Left.
	 * @param list<int> $b Right.
	 * @return list<int>
	 */
	private static function multiset_diff( array $a, array $b ): array {
		$have = array_count_values( $b );
		$out  = array();
		foreach ( $a as $value ) {
			if ( ! empty( $have[ $value ] ) ) {
				--$have[ $value ];
				continue;
			}
			$out[] = $value;
		}
		sort( $out );

		return $out;
	}

	/* ---------------------------------------------------------------------
	 * Classification
	 * ------------------------------------------------------------------ */

	private static function utc( int $ts ): string {
		return $ts > 0 ? gmdate( 'Y-m-d H:i:s', $ts ) . ' UTC' : '';
	}

	/**
	 * @param array<string,mixed> $prev Previous checkpoint.
	 * @return array<string,mixed>
	 */
	private static function finding( string $class, string $code, string $summary, array $prev, int $now, int $delta, int $removed, int $added ): array {
		return array(
			'ts'             => $now,
			'code'           => $code,
			'classification' => $class,
			'summary'        => $summary,
			'window_start'   => (int) $prev['ts'],
			'window_end'     => $now,
			'row_delta'      => $delta,
			'rows_removed'   => $removed,
			'rows_added'     => $added,
		);
	}

	/**
	 * Compare the live log summary with the previous checkpoint.
	 *
	 * @param array<string,mixed> $prev Previous checkpoint (the `last` pointer).
	 * @param array<string,mixed> $live Live summary from summarize().
	 * @param int                 $now  Now.
	 * @return array<string,mixed>|null Finding (sanctioned or unsanctioned) or null when clean.
	 */
	public static function classify( array $prev, array $live, int $now ): ?array {
		$prev_n = (int) $prev['row_count'];
		$live_n = (int) $live['row_count'];
		$delta  = $live_n - $prev_n;

		if ( $prev_n === $live_n && hash_equals( (string) $prev['digest'], (string) $live['digest'] ) ) {
			return null;
		}

		$evidence = self::retention_evidence();

		if ( ! isset( $prev['stamps'] ) || ! is_array( $prev['stamps'] ) || ! isset( $live['stamps'] ) ) {
			return self::classify_coarse( $prev, $live, $now, $delta, $evidence );
		}

		$removed = self::multiset_diff( $prev['stamps'], $live['stamps'] );
		$added   = self::multiset_diff( $live['stamps'], $prev['stamps'] );
		$r       = count( $removed );
		$a       = count( $added );

		if ( 0 === $r ) {
			$late = 0;
			$cut  = (int) $prev['newest_ts'] - self::BACKDATE_TOLERANCE_SEC;
			foreach ( $added as $ts ) {
				if ( $ts < $cut ) {
					++$late;
				}
			}
			if ( $late > 0 ) {
				return self::finding(
					self::CLASS_UNSANCTIONED,
					self::CODE_BACKDATED,
					sprintf(
						/* translators: 1: window start, 2: window end, 3: rows, 4: previous newest */
						__( 'Between %1$s and %2$s, %3$d log row(s) appeared dated before the previous newest entry (%4$s). Rows may have been inserted into the past.', 'handl-ai-connector-access-control' ),
						self::utc( (int) $prev['ts'] ),
						self::utc( $now ),
						$late,
						self::utc( (int) $prev['newest_ts'] )
					),
					$prev,
					$now,
					$delta,
					0,
					$a
				);
			}
			if ( $delta < 0 ) {
				// Untimed rows disappeared: nothing to prove they were pruned.
				return self::unexplained( $prev, $now, $delta, 0, 0 );
			}
			if ( 0 === $delta ) {
				return self::rewrite_finding( $prev, $now, 0, 0 );
			}

			return null; // Growth.
		}

		$is_prefix = $removed === array_slice( $prev['stamps'], 0, $r );
		if ( ! $is_prefix ) {
			if ( (int) $live['newest_ts'] < (int) $prev['newest_ts'] ) {
				return self::finding(
					self::CLASS_UNSANCTIONED,
					self::CODE_NEWEST_REGRESSED,
					sprintf(
						/* translators: 1: window start, 2: window end, 3: previous newest, 4: live newest, 5: previous rows, 6: live rows */
						__( 'Between %1$s and %2$s the newest log entry moved backwards from %3$s to %4$s (%5$d to %6$d rows). Recent rows were removed.', 'handl-ai-connector-access-control' ),
						self::utc( (int) $prev['ts'] ),
						self::utc( $now ),
						self::utc( (int) $prev['newest_ts'] ),
						self::utc( (int) $live['newest_ts'] ),
						$prev_n,
						$live_n
					),
					$prev,
					$now,
					$delta,
					$r,
					$a
				);
			}
			if ( $delta < 0 ) {
				return self::finding(
					self::CLASS_UNSANCTIONED,
					self::CODE_ROWS_MISSING,
					sprintf(
						/* translators: 1: window start, 2: window end, 3: rows lost, 4: previous rows, 5: live rows */
						__( 'Between %1$s and %2$s the log lost %3$d row(s) from inside the retained window (%4$d to %5$d rows) while newer rows are still present. Retention does not explain this.', 'handl-ai-connector-access-control' ),
						self::utc( (int) $prev['ts'] ),
						self::utc( $now ),
						$r - $a,
						$prev_n,
						$live_n
					),
					$prev,
					$now,
					$delta,
					$r,
					$a
				);
			}

			return self::rewrite_finding( $prev, $now, $r, $a );
		}

		// Only the oldest rows are gone: look for a legitimate reason.
		$day_sec    = self::day_seconds();
		$prune_ts   = $evidence['last_prune_ts'];
		$in_window  = $prune_ts > 0 && $prune_ts >= (int) $prev['ts'] && $prune_ts <= $now;
		$days       = $evidence['days'];
		$newest_gone = max( $removed );

		if ( $in_window && null !== $days && $newest_gone < $prune_ts - ( $days * $day_sec ) ) {
			return self::sanction_or_hold(
				self::CODE_RETENTION_PRUNE,
				sprintf(
					/* translators: 1: window start, 2: window end, 3: prune time, 4: rows removed, 5: days */
					__( 'Between %1$s and %2$s a retention prune ran at %3$s and removed %4$d row(s) older than the %5$d-day window. Expected.', 'handl-ai-connector-access-control' ),
					self::utc( (int) $prev['ts'] ),
					self::utc( $now ),
					self::utc( $prune_ts ),
					$r,
					$days
				),
				$removed,
				$prev,
				$now,
				$delta,
				$a
			);
		}

		if ( $a > 0 && null !== $days && $newest_gone < $now - ( $days * $day_sec ) ) {
			return self::sanction_or_hold(
				self::CODE_TTL_ON_WRITE,
				sprintf(
					/* translators: 1: window start, 2: window end, 3: rows removed, 4: days */
					__( 'Between %1$s and %2$s, %3$d row(s) older than the %4$d-day retention window aged out when new entries were written. Expected.', 'handl-ai-connector-access-control' ),
					self::utc( (int) $prev['ts'] ),
					self::utc( $now ),
					$r,
					$days
				),
				$removed,
				$prev,
				$now,
				$delta,
				$a
			);
		}

		$limit = $evidence['log_limit'];
		if ( $live_n >= $limit && $a > 0 && $r <= $a + max( 0, $prev_n - $limit ) ) {
			return self::finding(
				self::CLASS_SANCTIONED,
				self::CODE_RING_CAP,
				sprintf(
					/* translators: 1: window start, 2: window end, 3: rows rolled off, 4: log limit */
					__( 'Between %1$s and %2$s the %3$d oldest row(s) rolled off because the log is at its %4$d-entry limit. Expected.', 'handl-ai-connector-access-control' ),
					self::utc( (int) $prev['ts'] ),
					self::utc( $now ),
					$r,
					$limit
				),
				$prev,
				$now,
				$delta,
				$r,
				$a
			);
		}

		if ( $in_window ) {
			return self::finding(
				self::CLASS_UNSANCTIONED,
				self::CODE_ROWS_MISSING,
				sprintf(
					/* translators: 1: window start, 2: window end, 3: prune time, 4: rows removed, 5: previous rows, 6: live rows */
					__( 'Between %1$s and %2$s a prune was recorded at %3$s, but the %4$d row(s) missing (%5$d to %6$d rows) were inside the retention window, or no window is configured.', 'handl-ai-connector-access-control' ),
					self::utc( (int) $prev['ts'] ),
					self::utc( $now ),
					self::utc( $prune_ts ),
					$r,
					$prev_n,
					$live_n
				),
				$prev,
				$now,
				$delta,
				$r,
				$a
			);
		}

		if ( $delta >= 0 ) {
			// Oldest rows replaced without a reason and the count did not fall.
			return self::rewrite_finding( $prev, $now, $r, $a );
		}

		return self::unexplained( $prev, $now, $delta, $r, $a );
	}

	/**
	 * Fallback when the previous checkpoint carries no timestamp list.
	 *
	 * @param array<string,mixed>                                $prev     Previous.
	 * @param array<string,mixed>                                $live     Live.
	 * @param array{last_prune_ts:int,days:?int,log_limit:int}   $evidence Evidence.
	 * @return array<string,mixed>|null
	 */
	private static function classify_coarse( array $prev, array $live, int $now, int $delta, array $evidence ): ?array {
		$live_n = (int) $live['row_count'];
		$prev_n = (int) $prev['row_count'];

		if ( $live_n > 0 && (int) $live['newest_ts'] < (int) $prev['newest_ts'] ) {
			return self::finding(
				self::CLASS_UNSANCTIONED,
				self::CODE_NEWEST_REGRESSED,
				sprintf(
					/* translators: 1: window start, 2: window end, 3: previous newest, 4: live newest */
					__( 'Between %1$s and %2$s the newest log entry moved backwards from %3$s to %4$s.', 'handl-ai-connector-access-control' ),
					self::utc( (int) $prev['ts'] ),
					self::utc( $now ),
					self::utc( (int) $prev['newest_ts'] ),
					self::utc( (int) $live['newest_ts'] )
				),
				$prev,
				$now,
				$delta,
				0,
				0
			);
		}
		if ( $delta < 0 ) {
			$prune_ts = $evidence['last_prune_ts'];
			$days     = $evidence['days'];
			if (
				null !== $days
				&& $prune_ts > 0 && $prune_ts >= (int) $prev['ts'] && $prune_ts <= $now
				&& (int) $prev['oldest_ts'] > 0
				&& (int) $prev['oldest_ts'] < $prune_ts - ( $days * self::day_seconds() )
				&& (int) $live['oldest_ts'] >= (int) $prev['oldest_ts']
			) {
				return self::finding(
					self::CLASS_SANCTIONED,
					self::CODE_RETENTION_PRUNE,
					sprintf(
						/* translators: 1: window start, 2: window end, 3: prune time, 4: rows removed, 5: days */
						__( 'Between %1$s and %2$s a retention prune ran at %3$s and the log dropped %4$d row(s) past the %5$d-day window. Expected.', 'handl-ai-connector-access-control' ),
						self::utc( (int) $prev['ts'] ),
						self::utc( $now ),
						self::utc( $prune_ts ),
						-$delta,
						$days
					),
					$prev,
					$now,
					$delta,
					-$delta,
					0
				);
			}

			return self::unexplained( $prev, $now, $delta, -$delta, 0 );
		}
		if ( 0 === $delta && ( (int) $live['newest_ts'] <= (int) $prev['newest_ts'] || (int) $live['oldest_ts'] < (int) $prev['oldest_ts'] ) ) {
			return self::rewrite_finding( $prev, $now, 0, 0 );
		}

		return null;
	}

	/**
	 * @param array<string,mixed> $prev Previous.
	 * @return array<string,mixed>
	 */
	private static function unexplained( array $prev, int $now, int $delta, int $removed, int $added ): array {
		return self::finding(
			self::CLASS_UNSANCTIONED,
			self::CODE_ROWS_REMOVED,
			sprintf(
				/* translators: 1: window start, 2: window end, 3: rows lost, 4: previous rows, 5: live rows */
				__( 'Between %1$s and %2$s the log lost %3$d row(s) (%4$d to %5$d rows) and no retention prune or log-limit rollover explains it.', 'handl-ai-connector-access-control' ),
				self::utc( (int) $prev['ts'] ),
				self::utc( $now ),
				max( 0, -$delta ),
				(int) $prev['row_count'],
				(int) $prev['row_count'] + $delta
			),
			$prev,
			$now,
			$delta,
			$removed,
			$added
		);
	}

	/**
	 * @param array<string,mixed> $prev Previous.
	 * @return array<string,mixed>
	 */
	private static function rewrite_finding( array $prev, int $now, int $removed, int $added ): array {
		return self::finding(
			self::CLASS_UNSANCTIONED,
			self::CODE_CONTENT_REWRITE,
			sprintf(
				/* translators: 1: window start, 2: window end, 3: row count */
				__( 'Between %1$s and %2$s the log still has %3$d row(s) but its timestamp fingerprint changed. Entries were altered or replaced.', 'handl-ai-connector-access-control' ),
				self::utc( (int) $prev['ts'] ),
				self::utc( $now ),
				(int) $prev['row_count']
			),
			$prev,
			$now,
			0,
			$removed,
			$added
		);
	}

	/**
	 * A prune is only sanctioned when no legal hold would have blocked it.
	 *
	 * @param list<int>           $removed Removed timestamps.
	 * @param array<string,mixed> $prev    Previous checkpoint.
	 * @return array<string,mixed>
	 */
	private static function sanction_or_hold( string $code, string $summary, array $removed, array $prev, int $now, int $delta, int $added ): array {
		$held = self::held_count( $removed );
		if ( $held > 0 ) {
			return self::finding(
				self::CLASS_UNSANCTIONED,
				self::CODE_LEGAL_HOLD_PRUNED,
				sprintf(
					/* translators: 1: window start, 2: window end, 3: rows removed, 4: rows under hold */
					__( 'Between %1$s and %2$s retention removed %3$d row(s), but %4$d of them fall under an active legal hold that should have blocked the prune.', 'handl-ai-connector-access-control' ),
					self::utc( (int) $prev['ts'] ),
					self::utc( $now ),
					count( $removed ),
					$held
				),
				$prev,
				$now,
				$delta,
				count( $removed ),
				$added
			);
		}

		return self::finding( self::CLASS_SANCTIONED, $code, $summary, $prev, $now, $delta, count( $removed ), $added );
	}

	private static function day_seconds(): int {
		return defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
	}

	/* ---------------------------------------------------------------------
	 * Throttled admin_init check
	 * ------------------------------------------------------------------ */

	/**
	 * Throttled continuity check, wired to admin_init (never to a cron hook).
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

		$secret = self::secret_for( $state );
		$live   = self::summarize( self::ledger(), $secret );
		$prev   = $state['last'];

		if ( is_array( $prev ) && (string) $prev['secret_fp'] === (string) $live['secret_fp'] ) {
			$finding = self::classify( $prev, $live, $now );
			if ( null !== $finding ) {
				$state['findings'][] = $finding;
			}
		}

		$checkpoint = array(
			'ts'        => $now,
			'row_count' => $live['row_count'],
			'newest_ts' => $live['newest_ts'],
			'oldest_ts' => $live['oldest_ts'],
			'digest'    => $live['digest'],
			'secret_fp' => $live['secret_fp'],
		);
		$changed    = ! is_array( $prev )
			|| (string) $prev['digest'] !== (string) $live['digest']
			|| (int) $prev['row_count'] !== (int) $live['row_count']
			|| (string) $prev['secret_fp'] !== (string) $live['secret_fp'];
		if ( $changed ) {
			$state['history'][] = $checkpoint;
		}
		$checkpoint['stamps']   = $live['stamps'];
		$state['last']          = $checkpoint;
		$state['last_check_ts'] = $now;
		self::put_state( $state );
		self::maybe_fire_alerts( $now );

		return true;
	}

	/* ---------------------------------------------------------------------
	 * Snapshot
	 * ------------------------------------------------------------------ */

	public static function retention_url(): string {
		if ( class_exists( Admin::class, false ) && method_exists( Admin::class, 'screen_url' ) ) {
			return (string) Admin::screen_url( 'activity' );
		}

		return '';
	}

	/**
	 * Read-only view of the stored ledger (does not run a check).
	 *
	 * @return array<string,mixed>
	 */
	public static function snapshot( ?int $now = null ): array {
		$now      = self::resolve_now( $now );
		$state    = self::get_state();
		$url      = self::retention_url();
		$findings = array();
		$open     = 0;
		$sanction = 0;
		foreach ( $state['findings'] as $row ) {
			$row['retention_url'] = $url;
			$row['open']          = self::CLASS_UNSANCTIONED === $row['classification'] && self::is_open( $row, $now );
			if ( $row['open'] ) {
				++$open;
			}
			if ( self::CLASS_SANCTIONED === $row['classification'] ) {
				++$sanction;
			}
			$findings[] = $row;
		}
		$last = $state['last'];

		return array(
			'enabled'            => self::is_enabled(),
			'now'                => $now,
			'checkpoints'        => $state['history'],
			'last'               => is_array( $last ) ? array_diff_key( $last, array( 'stamps' => true ) ) : null,
			'findings'           => $findings,
			'unsanctioned_count' => $open,
			'sanctioned_count'   => $sanction,
			'finding_count'      => count( $findings ),
			'alerted'            => ! empty( $state['alerted'] ),
			'last_check_ts'      => (int) $state['last_check_ts'],
			'retention_url'      => $url,
			'framing'            => self::FRAMING,
		);
	}

	/**
	 * @param array<string,mixed> $finding Finding.
	 */
	private static function is_open( array $finding, int $now ): bool {
		return ( $now - (int) $finding['ts'] ) <= self::FINDING_OPEN_SECONDS;
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
		$now  = self::resolve_now( $now );
		$snap = null !== $snap ? $snap : self::snapshot( $now );

		if ( (int) $snap['unsanctioned_count'] <= 0 ) {
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
		self::set_alerted( true );

		return true;
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 * @return list<array<string,mixed>>
	 */
	private static function open_findings( array $snap ): array {
		$out = array();
		foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
			if ( is_array( $row ) && ! empty( $row['open'] ) ) {
				$out[] = $row;
			}
		}

		return $out;
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
				foreach ( self::open_findings( $snap ) as $row ) {
					$codes[] = (string) ( $row['code'] ?? '' );
				}
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'               => 'handl_aicac_witness',
						'unsanctioned_count' => (int) ( $snap['unsanctioned_count'] ?? 0 ),
						'codes'              => $codes,
						'site'               => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'                 => $now,
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
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$first = '';
		foreach ( self::open_findings( $snap ) as $row ) {
			$first = (string) ( $row['code'] ?? '' );
			break;
		}

		return sprintf(
			/* translators: 1: site name, 2: finding count, 3: first finding code */
			__( '[%1$s] [WITNESS] %2$d unsanctioned activity-log change(s) (first: %3$s)', 'handl-ai-connector-access-control' ),
			$site,
			(int) ( $snap['unsanctioned_count'] ?? 0 ),
			$first
		);
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_body( array $snap ): string {
		$lines   = array();
		$lines[] = __( 'The activity log changed in a way that retention or the log limit does not explain. The log is the evidence trail for governance decisions, so please look into it.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		foreach ( self::open_findings( $snap ) as $row ) {
			$lines[] = '- ' . (string) ( $row['summary'] ?? '' );
			$lines[] = '  ' . sprintf(
				/* translators: 1: row delta, 2: window start, 3: window end */
				__( 'Row change: %1$+d (window %2$s to %3$s).', 'handl-ai-connector-access-control' ),
				(int) ( $row['row_delta'] ?? 0 ),
				self::utc( (int) ( $row['window_start'] ?? 0 ) ),
				self::utc( (int) ( $row['window_end'] ?? 0 ) )
			);
		}
		$lines[] = '';
		$lines[] = __( 'Report only — never writes, repairs or restores the log. This check runs on admin page loads, not on cron.', 'handl-ai-connector-access-control' );
		$retention = (string) ( $snap['retention_url'] ?? '' );
		if ( '' !== $retention ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Review retention settings: %s', 'handl-ai-connector-access-control' ),
				$retention
			);
		}
		$url = self::admin_url();
		if ( '' !== $url ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Open witness: %s', 'handl-ai-connector-access-control' ),
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
				'classification',
				'ts',
				'window_start',
				'window_end',
				'row_count',
				'row_delta',
				'newest_ts',
				'oldest_ts',
				'digest',
				'summary',
				'retention_url',
				'framing',
			)
		);
		$lines[] = self::csv_line(
			array(
				'summary',
				'',
				'',
				self::utc( (int) ( $snap['now'] ?? 0 ) ),
				'',
				'',
				(string) (int) ( $snap['last']['row_count'] ?? 0 ),
				'',
				'',
				'',
				'',
				'checkpoints=' . (string) count( (array) ( $snap['checkpoints'] ?? array() ) )
					. ' findings=' . (string) (int) ( $snap['finding_count'] ?? 0 )
					. ' unsanctioned=' . (string) (int) ( $snap['unsanctioned_count'] ?? 0 )
					. ' sanctioned=' . (string) (int) ( $snap['sanctioned_count'] ?? 0 ),
				'',
				self::FRAMING,
			)
		);
		foreach ( (array) ( $snap['checkpoints'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$lines[] = self::csv_line(
				array(
					'checkpoint',
					'',
					'',
					self::utc( (int) $row['ts'] ),
					'',
					'',
					(string) (int) $row['row_count'],
					'',
					self::utc( (int) $row['newest_ts'] ),
					self::utc( (int) $row['oldest_ts'] ),
					(string) $row['digest'],
					'',
					'',
					self::FRAMING,
				)
			);
		}
		foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$lines[] = self::csv_line(
				array(
					'finding',
					(string) $row['code'],
					(string) $row['classification'],
					self::utc( (int) $row['ts'] ),
					self::utc( (int) $row['window_start'] ),
					self::utc( (int) $row['window_end'] ),
					'',
					(string) (int) $row['row_delta'],
					'',
					'',
					'',
					(string) $row['summary'],
					(string) ( $row['retention_url'] ?? '' ),
					self::FRAMING,
				)
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param list<string> $cols Columns.
	 */
	public static function csv_line( array $cols ): string {
		$out = array();
		foreach ( $cols as $col ) {
			$col = (string) $col;
			// Neutralize spreadsheet formula injection (plain signed integers are safe).
			if ( '' !== $col && ! preg_match( '/^-\d+$/', $col ) && in_array( $col[0], array( '=', '+', '-', '@', "\t", "\r" ), true ) ) {
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
		$html .= esc_html__( 'AI Connector witness', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%;margin-bottom:24px}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f6f7f7}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'AI Connector witness', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Report only — never writes, repairs or restores the activity log.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<ul>';
		$html .= '<li>' . esc_html( sprintf( 'Checkpoints: %d', count( (array) ( $snap['checkpoints'] ?? array() ) ) ) ) . '</li>';
		$html .= '<li>' . esc_html( sprintf( 'Unsanctioned findings: %d', (int) ( $snap['unsanctioned_count'] ?? 0 ) ) ) . '</li>';
		$html .= '<li>' . esc_html( sprintf( 'Sanctioned findings: %d', (int) ( $snap['sanctioned_count'] ?? 0 ) ) ) . '</li>';
		$html .= '</ul>';
		$html .= '<h2>' . esc_html__( 'Findings', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= self::findings_table_html( (array) ( $snap['findings'] ?? array() ) );
		$html .= '<h2>' . esc_html__( 'Checkpoint ledger', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= self::checkpoints_table_html( (array) ( $snap['checkpoints'] ?? array() ) );
		$html .= '</body></html>';

		return $html;
	}

	/**
	 * @param list<array<string,mixed>> $rows Findings.
	 */
	private static function findings_table_html( array $rows ): string {
		$html  = '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Finding', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Verdict', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Row change', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Window', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		$shown = 0;
		foreach ( array_reverse( $rows ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			++$shown;
			$html .= '<tr>';
			$html .= '<td><strong>' . esc_html( (string) $row['summary'] ) . '</strong><br /><code>' . esc_html( (string) $row['code'] ) . '</code></td>';
			$html .= '<td>' . esc_html( (string) $row['classification'] ) . '</td>';
			$html .= '<td>' . esc_html( sprintf( '%+d', (int) $row['row_delta'] ) ) . '</td>';
			$html .= '<td>' . esc_html( self::utc( (int) $row['window_start'] ) . ' → ' . self::utc( (int) $row['window_end'] ) ) . '</td>';
			$html .= '</tr>';
		}
		if ( 0 === $shown ) {
			$html .= '<tr><td colspan="4">' . esc_html__( 'No continuity findings.', 'handl-ai-connector-access-control' ) . '</td></tr>';
		}
		$html .= '</tbody></table>';

		return $html;
	}

	/**
	 * @param list<array<string,mixed>> $rows Checkpoints.
	 */
	private static function checkpoints_table_html( array $rows ): string {
		$html  = '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Checkpoint', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Rows', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Oldest', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Newest', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Digest', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		$shown = 0;
		foreach ( array_reverse( $rows ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			++$shown;
			$html .= '<tr>';
			$html .= '<td>' . esc_html( self::utc( (int) $row['ts'] ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) (int) $row['row_count'] ) . '</td>';
			$html .= '<td>' . esc_html( self::utc( (int) $row['oldest_ts'] ) ) . '</td>';
			$html .= '<td>' . esc_html( self::utc( (int) $row['newest_ts'] ) ) . '</td>';
			$html .= '<td><code>' . esc_html( substr( (string) $row['digest'], 0, 16 ) ) . '</code></td>';
			$html .= '</tr>';
		}
		if ( 0 === $shown ) {
			$html .= '<tr><td colspan="5">' . esc_html__( 'No checkpoints recorded yet.', 'handl-ai-connector-access-control' ) . '</td></tr>';
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
			__( 'Witness', 'handl-ai-connector-access-control' ),
			__( 'Witness', 'handl-ai-connector-access-control' ),
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
				'page'                   => self::PAGE_SLUG,
				'handl_aicac_witness_csv' => '1',
				'_wpnonce'               => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_witness_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print      = add_query_arg(
			array(
				'page'                      => self::PAGE_SLUG,
				'handl_aicac_witness_print' => '1',
				'_wpnonce'                  => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_witness_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Witness', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Keeps salted fingerprints of the activity log and explains any shrinkage: expected retention, or rows that vanished without a reason. Report only — never writes, repairs or restores the log. Checks run on admin page loads, not on cron. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable witness', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Fingerprint the activity log and alert on unexplained shrinkage', 'handl-ai-connector-access-control' );
			echo '</label></td></tr></tbody></table>';
			submit_button( __( 'Save witness settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled || ! is_array( $snap ) ) {
			echo '<p>' . esc_html__( 'Witness is off. Enable it to attest activity-log continuity.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Report only — never writes, repairs or restores the log.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		echo '<ul>';
		echo '<li>' . esc_html( sprintf( 'Unsanctioned findings (open): %d', (int) $snap['unsanctioned_count'] ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( 'Sanctioned findings: %d', (int) $snap['sanctioned_count'] ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( 'Last check: %s', self::utc( (int) $snap['last_check_ts'] ) ) ) . '</li>';
		echo '</ul>';
		if ( '' !== (string) $snap['retention_url'] ) {
			echo '<p><a href="' . esc_url( (string) $snap['retention_url'] ) . '">' . esc_html__( 'Open retention settings', 'handl-ai-connector-access-control' ) . '</a></p>';
		}

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Findings', 'handl-ai-connector-access-control' ) . '</h2>';
		echo str_replace( '<table>', '<table class="widefat striped">', self::findings_table_html( (array) $snap['findings'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.
		echo '<h2>' . esc_html__( 'Checkpoint ledger', 'handl-ai-connector-access-control' ) . '</h2>';
		echo str_replace( '<table>', '<table class="widefat striped">', self::checkpoints_table_html( (array) $snap['checkpoints'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.

		echo '</div>';
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_witness_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
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
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_witness_csv' ) ) {
			return;
		}
		$csv = self::csv_for_snapshot();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=handl-aicac-witness.csv' );
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		if ( empty( $_GET['handl_aicac_witness_print'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
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
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_witness_print' ) ) {
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
			wp_die( esc_html__( 'You do not have permission to save witness settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Invalid form', 'handl-ai-connector-access-control' ) );
		}
		self::save_settings(
			array(
				'enabled' => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
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
		\WP_CLI::add_command( 'handl-aicac witness', CLI_Witness::class );
	}
}

/**
 * WP-CLI: wp handl-aicac witness status|export
 */
final class CLI_Witness {

	/**
	 * Run a continuity check now and show the ledger. Exits non-zero while any
	 * unsanctioned finding is open (while enabled).
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

		if ( ! Witness::is_enabled() ) {
			\WP_CLI::log( 'enabled=no framing=' . Witness::FRAMING );
			\WP_CLI::log( 'Witness is disabled.' );

			return;
		}

		Witness::maybe_check( null, true );
		$snap = Witness::snapshot();

		\WP_CLI::log(
			sprintf(
				'enabled=yes checkpoints=%d rows=%d unsanctioned=%d sanctioned=%d alerted=%s framing=%s',
				count( (array) $snap['checkpoints'] ),
				(int) ( $snap['last']['row_count'] ?? 0 ),
				(int) $snap['unsanctioned_count'],
				(int) $snap['sanctioned_count'],
				! empty( $snap['alerted'] ) ? 'yes' : 'no',
				Witness::FRAMING
			)
		);

		$display = array();
		foreach ( (array) $snap['findings'] as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$display[] = array(
				'code'           => (string) $row['code'],
				'classification' => (string) $row['classification'],
				'row_delta'      => (int) $row['row_delta'],
				'summary'        => (string) $row['summary'],
			);
		}
		if ( ! empty( $display ) ) {
			if ( 'json' === $format ) {
				\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			} elseif ( class_exists( '\\WP_CLI\\Utils' ) ) {
				\WP_CLI\Utils\format_items( 'table', $display, array( 'code', 'classification', 'row_delta', 'summary' ) );
			} else {
				foreach ( $display as $row ) {
					\WP_CLI::log( implode( "\t", $row ) );
				}
			}
		}

		if ( (int) $snap['unsanctioned_count'] > 0 ) {
			// Default exit=true: unexplained log shrinkage must fail the command.
			\WP_CLI::error( 'Unsanctioned activity-log changes present.' );
		}
	}

	/**
	 * Export the witness ledger as CSV.
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
		$csv = Witness::csv_for_snapshot();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
