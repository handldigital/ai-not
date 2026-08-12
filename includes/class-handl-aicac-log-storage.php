<?php
/**
 * AICAC-STORAGE: Activity-log footprint + retention tuning hints.
 *
 * The log lives in the options table (Plugin::LOG_OPTION_KEY). Figures are
 * derived from the retained ring buffer; approximate size matches LENGTH of
 * the serialized option_value (or strlen(serialize($log)) in unit tests).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Storage footprint and "if retention were N days" estimator for Settings.
 */
final class Log_Storage {

	/** Days covering the Insights weekly window (Usage_Trends::WEEK_COUNT). */
	public const SUGGESTED_RETENTION_DAYS = 56;

	/** Estimator sentences shown for these day values (plain language, not a calculator). */
	public const ESTIMATE_DAY_OPTIONS = array( 7, 14, 30, 56 );

	/**
	 * Serialized byte length of the log option as WordPress stores it.
	 *
	 * Prefer a live LENGTH(option_value) query when $wpdb is available; otherwise
	 * fall back to strlen(serialize($log)), which matches PHP's option encoding
	 * for arrays in unit tests and when the row is missing.
	 *
	 * @param array<int,mixed> $log Retained log (same shape as get_retained_log).
	 */
	public static function approx_bytes( array $log ): int {
		$db_bytes = self::option_value_length_from_db();
		if ( null !== $db_bytes ) {
			return $db_bytes;
		}

		return self::serialized_bytes( $log );
	}

	/**
	 * strlen(serialize($log)) — matches wp_options storage for PHP arrays.
	 *
	 * @param array<int,mixed> $log
	 */
	public static function serialized_bytes( array $log ): int {
		return strlen( serialize( $log ) );
	}

	/**
	 * Direct options-table LENGTH query. null when DB is unavailable (unit tests).
	 */
	public static function option_value_length_from_db(): ?int {
		global $wpdb;
		if ( ! isset( $wpdb ) || ! is_object( $wpdb ) || ! method_exists( $wpdb, 'get_var' ) || ! method_exists( $wpdb, 'prepare' ) ) {
			return null;
		}
		if ( empty( $wpdb->options ) || ! is_string( $wpdb->options ) ) {
			return null;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- read-only size probe for Settings.
		$len = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT LENGTH(option_value) FROM {$wpdb->options} WHERE option_name = %s LIMIT 1",
				Plugin::LOG_OPTION_KEY
			)
		);

		if ( null === $len || false === $len ) {
			return null;
		}

		return (int) $len;
	}

	/**
	 * Footprint summary for the Settings retention section.
	 *
	 * @param array<int,mixed> $log
	 * @return array{
	 *   row_count:int,
	 *   approx_bytes:int,
	 *   oldest_ts:?int,
	 *   oldest_age_days:?float,
	 *   rows_per_week:float|null,
	 *   weeks_spanned:int,
	 *   weekly_rows:list<array{key:string,rows:int,start_ts:int,end_ts:int}>
	 * }
	 */
	public static function footprint( array $log, ?int $now = null ): array {
		$now = null !== $now ? $now : time();
		if ( $now <= 0 ) {
			$now = time();
		}

		$row_count = 0;
		$oldest_ts = null;
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			++$row_count;
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts > 0 && ( null === $oldest_ts || $ts < $oldest_ts ) ) {
				$oldest_ts = $ts;
			}
		}

		$weekly = self::weekly_row_buckets( $log, $now );
		$weeks_with_rows = 0;
		$total_bucketed  = 0;
		foreach ( $weekly as $bucket ) {
			$n = (int) $bucket['rows'];
			if ( $n > 0 ) {
				++$weeks_with_rows;
				$total_bucketed += $n;
			}
		}

		$oldest_age_days = null;
		if ( null !== $oldest_ts && $oldest_ts <= $now ) {
			$oldest_age_days = ( $now - $oldest_ts ) / (float) Policy::day_in_seconds();
		}

		$rows_per_week = null;
		if ( $weeks_with_rows > 0 ) {
			$rows_per_week = $total_bucketed / (float) $weeks_with_rows;
		}

		return array(
			'row_count'       => $row_count,
			'approx_bytes'    => self::approx_bytes( $log ),
			'oldest_ts'       => $oldest_ts,
			'oldest_age_days' => $oldest_age_days,
			'rows_per_week'   => $rows_per_week,
			'weeks_spanned'   => $weeks_with_rows,
			'weekly_rows'     => $weekly,
		);
	}

	/**
	 * Estimate retained size if a max-age TTL of $days were applied now.
	 *
	 * Uses the current log's timestamps (exact subset). Approximation note for
	 * UI: byte savings assume proportional serialized size of the kept rows.
	 *
	 * @param array<int,mixed> $log
	 * @return array{
	 *   days:int,
	 *   rows_kept:int,
	 *   rows_purged:int,
	 *   approx_bytes_kept:int,
	 *   approx_bytes_saved:int
	 * }
	 */
	public static function estimate_if_retention_days( array $log, int $days, ?int $now = null ): array {
		$days = max( 1, min( 3650, $days ) );
		$now  = null !== $now ? $now : time();
		if ( $now <= 0 ) {
			$now = time();
		}

		$cutoff = $now - ( $days * Policy::day_in_seconds() );
		$kept   = array();
		$purged = 0;
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			// Untimestamped rows are kept (same rule as Policy::apply_log_retention).
			if ( $ts > 0 && $ts < $cutoff ) {
				++$purged;
				continue;
			}
			$kept[] = $row;
		}

		$total_bytes = self::serialized_bytes( $log );
		$kept_bytes  = self::serialized_bytes( $kept );
		$saved       = max( 0, $total_bytes - $kept_bytes );

		return array(
			'days'               => $days,
			'rows_kept'          => count( $kept ),
			'rows_purged'        => $purged,
			'approx_bytes_kept'  => $kept_bytes,
			'approx_bytes_saved' => $saved,
		);
	}

	/**
	 * Suggested TTL: Insights window (56 days) when applying it would drop rows.
	 * null when there is nothing useful to suggest (empty log, or already ≤56).
	 *
	 * @param array<int,mixed>    $log
	 * @param array<string,mixed> $policy
	 */
	public static function suggested_retention_days( array $log, array $policy, ?int $now = null ): ?int {
		$now = null !== $now ? $now : time();
		$est = self::estimate_if_retention_days( $log, self::SUGGESTED_RETENTION_DAYS, $now );
		if ( $est['rows_purged'] < 1 ) {
			return null;
		}

		$current = Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null );
		if ( null !== $current && $current <= self::SUGGESTED_RETENTION_DAYS ) {
			return null;
		}

		return self::SUGGESTED_RETENTION_DAYS;
	}

	/**
	 * Whether applying $proposed_days would purge rows that currently feed Insights.
	 *
	 * Fires only when Insights already has usable weeks AND the proposed TTL would
	 * turn at least one current data week into a knowledge gap (or drop below the
	 * minimum weeks-with-data threshold).
	 *
	 * @param array<int,mixed>    $log
	 * @param array<string,mixed> $policy
	 * @return array{would_purge:bool,rows_purged_in_window:int,weeks_with_data_before:int,weeks_with_data_after:int}|null
	 *         null when no warning applies.
	 */
	public static function insights_purge_warning( array $log, array $policy, int $proposed_days, ?int $now = null ): ?array {
		$proposed_days = max( 1, min( 3650, $proposed_days ) );
		$now           = null !== $now ? $now : time();

		$plugins = array();
		$before  = Usage_Trends::compute( $log, $policy, $plugins, $now );
		if ( null === $before ) {
			return null;
		}

		$weeks_before = (int) $before['weeks_with_data'];
		if ( $weeks_before < Usage_Trends::MIN_WEEKS_WITH_DATA ) {
			return null;
		}

		$cutoff = $now - ( $proposed_days * Policy::day_in_seconds() );
		$pruned = array();
		$purged_in_window = 0;
		$window_start     = 0;
		if ( ! empty( $before['weeks'] ) && is_array( $before['weeks'] ) ) {
			$first = $before['weeks'][0];
			$window_start = isset( $first['start_ts'] ) ? (int) $first['start_ts'] : 0;
		}

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts > 0 && $ts < $cutoff ) {
				if ( $window_start > 0 && $ts >= $window_start && Usage_Trends::is_activity_row( $row ) ) {
					++$purged_in_window;
				}
				continue;
			}
			$pruned[] = $row;
		}

		if ( $purged_in_window < 1 ) {
			return null;
		}

		$policy_after = $policy;
		$policy_after['log_max_age_days'] = $proposed_days;
		$after = Usage_Trends::compute( $pruned, $policy_after, $plugins, $now );
		$weeks_after = null === $after ? 0 : (int) $after['weeks_with_data'];

		if ( $weeks_after >= $weeks_before && $weeks_after >= Usage_Trends::MIN_WEEKS_WITH_DATA ) {
			// Still fully covered — no gap risk to call out.
			return null;
		}

		return array(
			'would_purge'             => true,
			'rows_purged_in_window'   => $purged_in_window,
			'weeks_with_data_before'  => $weeks_before,
			'weeks_with_data_after'   => $weeks_after,
		);
	}

	/**
	 * Human-readable byte size (plain language for Settings).
	 */
	public static function format_bytes( int $bytes ): string {
		$bytes = max( 0, $bytes );
		if ( $bytes < 1024 ) {
			return (string) $bytes . ' B';
		}
		if ( $bytes < 1024 * 1024 ) {
			$kb = $bytes / 1024;
			$rounded = $kb >= 10 ? (string) (int) round( $kb ) : (string) round( $kb, 1 );
			return $rounded . ' KB';
		}
		$mb = $bytes / ( 1024 * 1024 );
		$rounded = $mb >= 10 ? (string) (int) round( $mb ) : (string) round( $mb, 1 );
		return $rounded . ' MB';
	}

	/**
	 * Calendar-week row counts ending at $now (up to Usage_Trends::WEEK_COUNT weeks).
	 *
	 * @param array<int,mixed> $log
	 * @return list<array{key:string,rows:int,start_ts:int,end_ts:int}>
	 */
	public static function weekly_row_buckets( array $log, int $now ): array {
		$tz = new \DateTimeZone( 'UTC' );
		if ( function_exists( 'wp_timezone' ) ) {
			$candidate = wp_timezone();
			if ( $candidate instanceof \DateTimeZone ) {
				$tz = $candidate;
			}
		}
		$weeks = Usage_Trends::week_windows( $now, Usage_Trends::WEEK_COUNT, $tz );
		$out   = array();
		foreach ( $weeks as $def ) {
			$out[ $def['key'] ] = array(
				'key'      => $def['key'],
				'rows'     => 0,
				'start_ts' => (int) $def['start_ts'],
				'end_ts'   => (int) $def['end_ts'],
			);
		}

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				continue;
			}
			$key = ( new \DateTimeImmutable( '@' . $ts ) )->setTimezone( $tz )->format( 'o-\WW' );
			if ( isset( $out[ $key ] ) ) {
				++$out[ $key ]['rows'];
			}
		}

		return array_values( $out );
	}
}
