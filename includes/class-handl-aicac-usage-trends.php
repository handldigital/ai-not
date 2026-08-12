<?php
/**
 * AICAC-TRENDS: per-plugin weekly usage / estimated-spend history for Insights.
 *
 * Aggregates the retained activity log only. No new collection. Weeks with no
 * retained rows (including TTL-purged edges) are gaps — never fabricated zeros.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Weekly call + estimated-spend trends (site + per plugin).
 */
final class Usage_Trends {

	/** Number of calendar weeks shown (oldest → newest, including the current week). */
	public const WEEK_COUNT = 8;

	/** Minimum weeks that contain retained activity before the UI renders. */
	public const MIN_WEEKS_WITH_DATA = 2;

	/**
	 * Build site + per-plugin weekly trends from the retained log.
	 *
	 * Returns null when fewer than {@see MIN_WEEKS_WITH_DATA} weeks have any
	 * retained AI Client activity (no empty chrome).
	 *
	 * @param array<int,mixed>                  $log     Retained log (Policy::get_retained_log).
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $plugins Installed plugin map (basename → headers).
	 * @param int|null                          $now     Injectable clock.
	 * @return array{
	 *   weeks: list<array{key:string,label:string,start_ts:int,end_ts:int}>,
	 *   site: array{
	 *     weeks: list<array{key:string,status:string,calls:int|null,spend:float|null}>,
	 *     calls_delta_pct: float|null,
	 *     spend_delta_pct: float|null
	 *   },
	 *   plugins: list<array{
	 *     plugin:string,
	 *     label:string,
	 *     weeks: list<array{key:string,status:string,calls:int|null,spend:float|null}>,
	 *     calls_delta_pct: float|null,
	 *     spend_delta_pct: float|null
	 *   }>,
	 *   knowledge_start_ts: int,
	 *   weeks_with_data: int
	 * }|null
	 */
	public static function compute( array $log, array $policy, array $plugins = array(), ?int $now = null ): ?array {
		$now = null !== $now ? $now : time();
		$tz  = self::timezone();

		$week_defs = self::week_windows( $now, self::WEEK_COUNT, $tz );
		$knowledge = self::knowledge_start_ts( $log, $policy, $now );

		$site_buckets   = array();
		$plugin_buckets = array();
		foreach ( $week_defs as $def ) {
			$site_buckets[ $def['key'] ] = array(
				'calls' => 0,
				'spend' => 0.0,
				'rows'  => 0,
			);
		}

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) || ! self::is_activity_row( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				continue;
			}

			$week_key = self::week_key_for_ts( $ts, $tz );
			if ( ! isset( $site_buckets[ $week_key ] ) ) {
				continue;
			}

			$plugin = isset( $row['plugin'] ) ? trim( (string) $row['plugin'] ) : '';
			if ( '' === $plugin ) {
				$plugin = Analytics::UNKNOWN_KEY;
			}

			$usd = self::row_spend_usd( $row, $policy );

			++$site_buckets[ $week_key ]['calls'];
			++$site_buckets[ $week_key ]['rows'];
			if ( null !== $usd ) {
				$site_buckets[ $week_key ]['spend'] += $usd;
			}

			if ( ! isset( $plugin_buckets[ $plugin ] ) ) {
				$plugin_buckets[ $plugin ] = array();
				foreach ( $week_defs as $def ) {
					$plugin_buckets[ $plugin ][ $def['key'] ] = array(
						'calls' => 0,
						'spend' => 0.0,
						'rows'  => 0,
					);
				}
			}
			++$plugin_buckets[ $plugin ][ $week_key ]['calls'];
			++$plugin_buckets[ $plugin ][ $week_key ]['rows'];
			if ( null !== $usd ) {
				$plugin_buckets[ $plugin ][ $week_key ]['spend'] += $usd;
			}
		}

		$site_weeks = self::finalize_series( $week_defs, $site_buckets, $knowledge );
		$weeks_with_data = self::count_data_weeks( $site_weeks );
		if ( $weeks_with_data < self::MIN_WEEKS_WITH_DATA ) {
			return null;
		}

		$site_deltas = self::delta_pct_pair( $site_weeks );

		$plugin_rows = array();
		foreach ( $plugin_buckets as $basename => $buckets ) {
			$series = self::finalize_series( $week_defs, $buckets, $knowledge );
			if ( self::count_data_weeks( $series ) < 1 ) {
				continue;
			}
			$deltas        = self::delta_pct_pair( $series );
			$plugin_rows[] = array(
				'plugin'          => $basename,
				'label'           => self::plugin_label( $basename, $plugins ),
				'weeks'           => $series,
				'calls_delta_pct' => $deltas['calls'],
				'spend_delta_pct' => $deltas['spend'],
			);
		}

		usort(
			$plugin_rows,
			static function ( array $a, array $b ): int {
				$a_calls = self::latest_data_calls( $a['weeks'] );
				$b_calls = self::latest_data_calls( $b['weeks'] );
				$cmp     = $b_calls <=> $a_calls;
				if ( 0 !== $cmp ) {
					return $cmp;
				}
				return strcmp( (string) $a['plugin'], (string) $b['plugin'] );
			}
		);

		return array(
			'weeks'               => $week_defs,
			'site'                => array(
				'weeks'           => $site_weeks,
				'calls_delta_pct' => $site_deltas['calls'],
				'spend_delta_pct' => $site_deltas['spend'],
			),
			'plugins'             => $plugin_rows,
			'knowledge_start_ts'  => $knowledge,
			'weeks_with_data'     => $weeks_with_data,
		);
	}

	/**
	 * Count AI Client calls in [start_ts, end_ts) — same inclusion rules as Activity.
	 *
	 * @param array<int,mixed> $log
	 */
	public static function count_activity_calls_in_window( array $log, int $start_ts, int $end_ts ): int {
		$n = 0;
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) || ! self::is_activity_row( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts < $start_ts || $ts >= $end_ts ) {
				continue;
			}
			++$n;
		}

		return $n;
	}

	/**
	 * Sum estimated spend in [start_ts, end_ts) using Activity/Cost rules.
	 *
	 * @param array<int,mixed>    $log
	 * @param array<string,mixed> $policy
	 */
	public static function sum_activity_spend_in_window( array $log, array $policy, int $start_ts, int $end_ts ): float {
		$total = 0.0;
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) || ! self::is_activity_row( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts < $start_ts || $ts >= $end_ts ) {
				continue;
			}
			$usd = self::row_spend_usd( $row, $policy );
			if ( null !== $usd ) {
				$total += $usd;
			}
		}

		return $total;
	}

	/**
	 * Percent change current vs prior. null when either side is a gap or prior is 0.
	 *
	 * @param float|int|null $current
	 * @param float|int|null $prior
	 */
	public static function delta_pct( $current, $prior ): ?float {
		if ( null === $current || null === $prior ) {
			return null;
		}
		$prior = (float) $prior;
		if ( abs( $prior ) < 0.0000001 ) {
			return null;
		}

		return ( ( (float) $current - $prior ) / $prior ) * 100.0;
	}

	/**
	 * Human label for a delta (plain language for Insights).
	 */
	public static function format_delta_label( ?float $pct ): string {
		if ( null === $pct ) {
			return __( 'Not enough data', 'handl-ai-connector-access-control' );
		}
		$rounded = (int) round( $pct );
		if ( 0 === $rounded ) {
			return __( 'About the same', 'handl-ai-connector-access-control' );
		}
		if ( $rounded > 0 ) {
			return '+' . number_format_i18n( $rounded ) . '%';
		}

		return number_format_i18n( $rounded ) . '%';
	}

	/**
	 * Compact SVG sparkline. Gap weeks are skipped (broken series, not zeros).
	 *
	 * @param list<array{status:string,calls:int|null,spend:float|null}> $weeks
	 * @param 'calls'|'spend'                                            $metric
	 */
	public static function sparkline_svg( array $weeks, string $metric = 'calls', int $width = 120, int $height = 28 ): string {
		$points = array();
		foreach ( $weeks as $w ) {
			if ( 'data' !== ( $w['status'] ?? '' ) ) {
				continue;
			}
			$val = 'spend' === $metric ? (float) ( $w['spend'] ?? 0 ) : (float) ( $w['calls'] ?? 0 );
			$points[] = $val;
		}
		if ( count( $points ) < 2 ) {
			return '';
		}

		$max = max( $points );
		$min = min( $points );
		$span = $max - $min;
		if ( $span < 0.0000001 ) {
			$span = 1.0;
		}

		$n     = count( $points );
		$pad_y = 2.0;
		$inner_h = max( 1.0, (float) $height - ( 2 * $pad_y ) );
		$coords  = array();
		for ( $i = 0; $i < $n; $i++ ) {
			$x = $n === 1 ? $width / 2 : ( $i / ( $n - 1 ) ) * ( $width - 2 ) + 1;
			$norm = ( $points[ $i ] - $min ) / $span;
			$y    = $pad_y + $inner_h * ( 1.0 - $norm );
			$coords[] = round( $x, 2 ) . ',' . round( $y, 2 );
		}

		$polyline = esc_attr( implode( ' ', $coords ) );

		return sprintf(
			'<svg class="handl-aicac-trend-spark" width="%1$d" height="%2$d" viewBox="0 0 %1$d %2$d" role="img" aria-hidden="true" focusable="false"><polyline fill="none" stroke="currentColor" stroke-width="1.5" points="%3$s" /></svg>',
			$width,
			$height,
			$polyline
		);
	}

	/**
	 * Monday-start week windows ending with the week that contains $now.
	 *
	 * @return list<array{key:string,label:string,start_ts:int,end_ts:int}>
	 */
	public static function week_windows( int $now, int $count, ?\DateTimeZone $tz = null ): array {
		$tz  = $tz instanceof \DateTimeZone ? $tz : self::timezone();
		$now_dt = ( new \DateTimeImmutable( '@' . $now ) )->setTimezone( $tz );

		// Start of the current ISO-like week: Monday 00:00 in site TZ.
		$dow = (int) $now_dt->format( 'N' ); // 1=Mon .. 7=Sun
		$current_monday = $now_dt->setTime( 0, 0, 0 )->modify( '-' . ( $dow - 1 ) . ' days' );

		$out = array();
		for ( $i = $count - 1; $i >= 0; $i-- ) {
			$start = $current_monday->modify( '-' . $i . ' weeks' );
			$end   = $start->modify( '+1 week' );
			$key   = $start->format( 'o-\WW' );
			$out[] = array(
				'key'      => $key,
				'label'    => $start->format( 'M j' ),
				'start_ts' => $start->getTimestamp(),
				'end_ts'   => $end->getTimestamp(),
			);
		}

		return $out;
	}

	/**
	 * Earliest timestamp we still have retained coverage for.
	 *
	 * TTL cutoff when configured; when the entry-count cap is saturated, also
	 * the oldest retained timestamp (older weeks were pushed out).
	 *
	 * @param array<int,mixed>    $log
	 * @param array<string,mixed> $policy
	 */
	public static function knowledge_start_ts( array $log, array $policy, int $now ): int {
		$start = 0;
		$max_age = Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null );
		if ( null !== $max_age ) {
			$start = $now - ( $max_age * Policy::day_in_seconds() );
		}

		$limit = (int) ( $policy['log_limit'] ?? 200 );
		if ( $limit < 20 ) {
			$limit = 20;
		}
		if ( count( $log ) >= $limit ) {
			$oldest = 0;
			foreach ( $log as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
				if ( $ts > 0 && ( 0 === $oldest || $ts < $oldest ) ) {
					$oldest = $ts;
				}
			}
			if ( $oldest > 0 ) {
				$start = max( $start, $oldest );
			}
		}

		return $start;
	}

	/**
	 * Rows that count toward Activity call/spend totals (exclude shadow + alert audits).
	 *
	 * @param array<string,mixed> $row
	 */
	public static function is_activity_row( array $row ): bool {
		$channel = isset( $row['channel'] ) ? (string) $row['channel'] : '';
		if ( 'direct_http' === $channel
			|| 'spend_threshold' === $channel
			|| 'budget' === $channel
			|| 'drift' === $channel
			|| 'alert_snooze' === $channel
			|| 'anomaly' === $channel
			|| 'forecast_warn' === $channel ) {
			return false;
		}

		return true;
	}

	/**
	 * @param array<string,mixed> $row
	 * @param array<string,mixed> $policy
	 */
	private static function row_spend_usd( array $row, array $policy ): ?float {
		$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
		$out = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
		$rates = Cost::rates_from_policy( $policy, isset( $row['provider'] ) ? (string) $row['provider'] : null );

		return Cost::estimate_usd( $in, $out, $rates );
	}

	/**
	 * @param list<array{key:string,label:string,start_ts:int,end_ts:int}> $week_defs
	 * @param array<string,array{calls:int,spend:float,rows:int}>          $buckets
	 * @return list<array{key:string,status:string,calls:int|null,spend:float|null}>
	 */
	private static function finalize_series( array $week_defs, array $buckets, int $knowledge_start ): array {
		$out = array();
		foreach ( $week_defs as $def ) {
			$key = $def['key'];
			$b   = $buckets[ $key ] ?? array(
				'calls' => 0,
				'spend' => 0.0,
				'rows'  => 0,
			);

			// Entire week before retention knowledge → gap (TTL / ring-buffer edge).
			if ( $knowledge_start > 0 && $def['end_ts'] <= $knowledge_start ) {
				$out[] = array(
					'key'    => $key,
					'status' => 'gap',
					'calls'  => null,
					'spend'  => null,
				);
				continue;
			}

			// No retained rows in this week → gap (never invent zeros).
			if ( (int) $b['rows'] < 1 ) {
				$out[] = array(
					'key'    => $key,
					'status' => 'gap',
					'calls'  => null,
					'spend'  => null,
				);
				continue;
			}

			$out[] = array(
				'key'    => $key,
				'status' => 'data',
				'calls'  => (int) $b['calls'],
				'spend'  => round( (float) $b['spend'], 6 ),
			);
		}

		return $out;
	}

	/**
	 * @param list<array{status:string,calls:int|null,spend:float|null}> $weeks
	 * @return array{calls:float|null,spend:float|null}
	 */
	private static function delta_pct_pair( array $weeks ): array {
		$n = count( $weeks );
		if ( $n < 2 ) {
			return array(
				'calls' => null,
				'spend' => null,
			);
		}
		$current = $weeks[ $n - 1 ];
		$prior   = $weeks[ $n - 2 ];
		if ( 'data' !== ( $current['status'] ?? '' ) || 'data' !== ( $prior['status'] ?? '' ) ) {
			return array(
				'calls' => null,
				'spend' => null,
			);
		}

		return array(
			'calls' => self::delta_pct( $current['calls'], $prior['calls'] ),
			'spend' => self::delta_pct( $current['spend'], $prior['spend'] ),
		);
	}

	/**
	 * @param list<array{status:string}> $weeks
	 */
	private static function count_data_weeks( array $weeks ): int {
		$n = 0;
		foreach ( $weeks as $w ) {
			if ( 'data' === ( $w['status'] ?? '' ) ) {
				++$n;
			}
		}

		return $n;
	}

	/**
	 * @param list<array{status:string,calls:int|null}> $weeks
	 */
	private static function latest_data_calls( array $weeks ): int {
		for ( $i = count( $weeks ) - 1; $i >= 0; $i-- ) {
			if ( 'data' === ( $weeks[ $i ]['status'] ?? '' ) ) {
				return (int) ( $weeks[ $i ]['calls'] ?? 0 );
			}
		}

		return 0;
	}

	/**
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private static function plugin_label( string $basename, array $plugins ): string {
		if ( Analytics::UNKNOWN_KEY === $basename ) {
			return __( '(unknown plugin)', 'handl-ai-connector-access-control' );
		}
		if ( isset( $plugins[ $basename ]['Name'] ) && is_string( $plugins[ $basename ]['Name'] ) ) {
			return (string) $plugins[ $basename ]['Name'];
		}

		return $basename;
	}

	private static function week_key_for_ts( int $ts, \DateTimeZone $tz ): string {
		$dt = ( new \DateTimeImmutable( '@' . $ts ) )->setTimezone( $tz );

		return $dt->format( 'o-\WW' );
	}

	private static function timezone(): \DateTimeZone {
		if ( function_exists( 'wp_timezone' ) ) {
			$tz = wp_timezone();
			if ( $tz instanceof \DateTimeZone ) {
				return $tz;
			}
		}

		return new \DateTimeZone( 'UTC' );
	}
}
