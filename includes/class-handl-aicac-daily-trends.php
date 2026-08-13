<?php
/**
 * AICAC-TREND (#184): 30-day daily sparklines for Insights (calls, estimated spend, blocks).
 *
 * Aggregates saved Activity only. Short retention shortens the labeled window —
 * never invents days before knowledge starts. Inline SVG only (no chart library).
 *
 * Distinct from weekly Usage_Trends (AICAC-TRENDS / #134).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Daily_Trends {

	/** Ideal lookback in calendar days (including today). */
	public const DAY_COUNT = 30;

	/** Minimum calendar days in the retained window before charts render. */
	public const MIN_WINDOW_DAYS = 2;

	/**
	 * @param array<int,mixed>                  $log
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $plugins
	 * @return array{
	 *   days: list<array{key:string,label:string,start_ts:int,end_ts:int}>,
	 *   window_days: int,
	 *   full_window: bool,
	 *   window_label: string,
	 *   site: array{days: list<array{key:string,calls:int,spend:float,blocks:int}>},
	 *   plugins: array<string,array{label:string,days: list<array{key:string,calls:int,spend:float,blocks:int}>}>,
	 *   has_activity: bool
	 * }|null
	 */
	public static function compute( array $log, array $policy, array $plugins = array(), ?int $now = null ): ?array {
		$now = null !== $now ? $now : time();
		$tz  = self::timezone();

		$day_defs = self::day_windows( $now, self::DAY_COUNT, $tz, Usage_Trends::knowledge_start_ts( $log, $policy, $now ) );
		$window_days = count( $day_defs );
		if ( $window_days < self::MIN_WINDOW_DAYS ) {
			return null;
		}

		/** @var array<string,array{calls:int,spend:float,blocks:int}> $site */
		$site = array();
		/** @var array<string,array<string,array{calls:int,spend:float,blocks:int}>> $by_plugin */
		$by_plugin = array();
		foreach ( $day_defs as $def ) {
			$site[ $def['key'] ] = array(
				'calls'  => 0,
				'spend'  => 0.0,
				'blocks' => 0,
			);
		}

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) || ! Usage_Trends::is_activity_row( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				continue;
			}
			$day_key = self::day_key_for_ts( $ts, $tz );
			if ( ! isset( $site[ $day_key ] ) ) {
				continue;
			}

			$plugin = isset( $row['plugin'] ) ? trim( (string) $row['plugin'] ) : '';
			if ( '' === $plugin ) {
				$plugin = Analytics::UNKNOWN_KEY;
			}

			++$site[ $day_key ]['calls'];
			$decision = isset( $row['decision'] ) ? (string) $row['decision'] : '';
			if ( 'deny' === $decision ) {
				++$site[ $day_key ]['blocks'];
			}

			$usd = self::row_spend_usd( $row, $policy );
			if ( null !== $usd ) {
				$site[ $day_key ]['spend'] += $usd;
			}

			if ( ! isset( $by_plugin[ $plugin ] ) ) {
				$by_plugin[ $plugin ] = array();
				foreach ( $day_defs as $def ) {
					$by_plugin[ $plugin ][ $def['key'] ] = array(
						'calls'  => 0,
						'spend'  => 0.0,
						'blocks' => 0,
					);
				}
			}
			++$by_plugin[ $plugin ][ $day_key ]['calls'];
			if ( 'deny' === $decision ) {
				++$by_plugin[ $plugin ][ $day_key ]['blocks'];
			}
			if ( null !== $usd ) {
				$by_plugin[ $plugin ][ $day_key ]['spend'] += $usd;
			}
		}

		$site_days = self::series_from_buckets( $day_defs, $site );
		$has_activity = false;
		foreach ( $site_days as $d ) {
			if ( (int) $d['calls'] > 0 || (int) $d['blocks'] > 0 ) {
				$has_activity = true;
				break;
			}
		}

		$plugin_out = array();
		foreach ( $by_plugin as $basename => $buckets ) {
			$plugin_out[ $basename ] = array(
				'label' => self::plugin_label( $basename, $plugins ),
				'days'  => self::series_from_buckets( $day_defs, $buckets ),
			);
		}

		$full = $window_days >= self::DAY_COUNT;

		return array(
			'days'          => $day_defs,
			'window_days'   => $window_days,
			'full_window'   => $full,
			'window_label'  => self::window_label( $window_days, $full ),
			'site'          => array( 'days' => $site_days ),
			'plugins'       => $plugin_out,
			'has_activity'  => $has_activity,
		);
	}

	/**
	 * Calendar day windows ending with today, clipped to retention knowledge.
	 *
	 * @return list<array{key:string,label:string,start_ts:int,end_ts:int}>
	 */
	public static function day_windows( int $now, int $ideal_count, ?\DateTimeZone $tz = null, int $knowledge_start = 0 ): array {
		$tz  = $tz instanceof \DateTimeZone ? $tz : self::timezone();
		$now_dt = ( new \DateTimeImmutable( '@' . $now ) )->setTimezone( $tz )->setTime( 0, 0, 0 );
		$ideal_start = $now_dt->modify( '-' . max( 0, $ideal_count - 1 ) . ' days' );

		$start = $ideal_start;
		if ( $knowledge_start > 0 ) {
			$know_day = ( new \DateTimeImmutable( '@' . $knowledge_start ) )->setTimezone( $tz )->setTime( 0, 0, 0 );
			if ( $know_day > $start ) {
				$start = $know_day;
			}
		}

		$out = array();
		$cursor = $start;
		while ( $cursor <= $now_dt ) {
			$end = $cursor->modify( '+1 day' );
			$out[] = array(
				'key'      => $cursor->format( 'Y-m-d' ),
				'label'    => $cursor->format( 'M j' ),
				'start_ts' => $cursor->getTimestamp(),
				'end_ts'   => $end->getTimestamp(),
			);
			$cursor = $end;
		}

		return $out;
	}

	/**
	 * Compact SVG sparkline from daily series (zeros included — quiet days are real).
	 *
	 * @param list<array{calls?:int,spend?:float,blocks?:int}> $days
	 * @param 'calls'|'spend'|'blocks'                         $metric
	 */
	public static function sparkline_svg( array $days, string $metric = 'calls', int $width = 180, int $height = 36 ): string {
		$points = array();
		foreach ( $days as $d ) {
			if ( 'spend' === $metric ) {
				$points[] = (float) ( $d['spend'] ?? 0 );
			} elseif ( 'blocks' === $metric ) {
				$points[] = (float) ( $d['blocks'] ?? 0 );
			} else {
				$points[] = (float) ( $d['calls'] ?? 0 );
			}
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

		$n       = count( $points );
		$pad_y   = 2.0;
		$inner_h = max( 1.0, (float) $height - ( 2 * $pad_y ) );
		$coords  = array();
		for ( $i = 0; $i < $n; $i++ ) {
			$x    = $n === 1 ? $width / 2 : ( $i / ( $n - 1 ) ) * ( $width - 2 ) + 1;
			$norm = ( $points[ $i ] - $min ) / $span;
			$y    = $pad_y + $inner_h * ( 1.0 - $norm );
			$coords[] = round( $x, 2 ) . ',' . round( $y, 2 );
		}

		$polyline = esc_attr( implode( ' ', $coords ) );

		return sprintf(
			'<svg class="handl-aicac-daily-spark" width="%1$d" height="%2$d" viewBox="0 0 %1$d %2$d" role="img" aria-hidden="true" focusable="false"><polyline fill="none" stroke="currentColor" stroke-width="1.5" points="%3$s" /></svg>',
			$width,
			$height,
			$polyline
		);
	}

	public static function window_label( int $window_days, bool $full_window ): string {
		if ( $full_window ) {
			return sprintf(
				/* translators: %d: number of days (usually 30) */
				__( 'Last %d days from saved Activity', 'handl-ai-connector-access-control' ),
				self::DAY_COUNT
			);
		}

		return sprintf(
			/* translators: %d: number of days retained */
			__( 'Last %d days from saved Activity (not a full 30 days — older days were not kept)', 'handl-ai-connector-access-control' ),
			max( 0, $window_days )
		);
	}

	/**
	 * @param list<array{key:string,label:string,start_ts:int,end_ts:int}> $day_defs
	 * @param array<string,array{calls:int,spend:float,blocks:int}>          $buckets
	 * @return list<array{key:string,calls:int,spend:float,blocks:int}>
	 */
	private static function series_from_buckets( array $day_defs, array $buckets ): array {
		$out = array();
		foreach ( $day_defs as $def ) {
			$key = $def['key'];
			$b   = $buckets[ $key ] ?? array(
				'calls'  => 0,
				'spend'  => 0.0,
				'blocks' => 0,
			);
			$out[] = array(
				'key'    => $key,
				'calls'  => (int) $b['calls'],
				'spend'  => round( (float) $b['spend'], 6 ),
				'blocks' => (int) $b['blocks'],
			);
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $row
	 * @param array<string,mixed> $policy
	 */
	private static function row_spend_usd( array $row, array $policy ): ?float {
		$in    = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
		$out   = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
		$rates = Cost::rates_from_policy( $policy, isset( $row['provider'] ) ? (string) $row['provider'] : null );

		return Cost::estimate_usd( $in, $out, $rates );
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

	private static function day_key_for_ts( int $ts, \DateTimeZone $tz ): string {
		$dt = ( new \DateTimeImmutable( '@' . $ts ) )->setTimezone( $tz );

		return $dt->format( 'Y-m-d' );
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
