<?php
/**
 * AICAC-PROVIDER-MAP: plugin → provider → model traffic map for Insights.
 *
 * Aggregates the retained activity log only. No new collection. Providers
 * without a configured rate-table entry show "spend unknown" — never invent
 * spend from the global fallback for share percentages.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Who-talks-to-whom grouping (plugin → provider → model) with call counts
 * and estimated-spend share over the current retention window.
 */
final class Provider_Map {

	/** Minimum distinct calendar days with retained activity before the UI renders. */
	public const MIN_DAYS_WITH_DATA = 7;

	/**
	 * Build the map from the retained log.
	 *
	 * Returns null when fewer than {@see MIN_DAYS_WITH_DATA} distinct days have
	 * any retained AI Client activity (no empty chrome).
	 *
	 * @param array<int,mixed>                  $log     Retained log (Policy::get_retained_log).
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $plugins Installed plugin map (basename → headers).
	 * @param int|null                          $now     Injectable clock.
	 * @return array{
	 *   plugins: list<array{
	 *     plugin:string,
	 *     label:string,
	 *     calls:int,
	 *     known_spend:float,
	 *     unknown_spend_calls:int,
	 *     spend_share_pct:float|null,
	 *     providers: list<array{
	 *       provider:string,
	 *       label:string,
	 *       calls:int,
	 *       spend_status:string,
	 *       known_spend:float|null,
	 *       spend_share_pct:float|null,
	 *       models: list<array{
	 *         model:string,
	 *         label:string,
	 *         calls:int,
	 *         spend_status:string,
	 *         known_spend:float|null,
	 *         spend_share_pct:float|null
	 *       }>
	 *     }>
	 *   }>,
	 *   totals: array{
	 *     calls:int,
	 *     known_spend:float,
	 *     unknown_spend_calls:int,
	 *     known_spend_providers:int,
	 *     unknown_spend_providers:int
	 *   },
	 *   window: array{
	 *     start_ts:int,
	 *     end_ts:int,
	 *     days_with_data:int,
	 *     knowledge_start_ts:int,
	 *     gap_label:string|null
	 *   }
	 * }|null
	 */
	public static function compute( array $log, array $policy, array $plugins = array(), ?int $now = null ): ?array {
		$now       = null !== $now ? $now : time();
		$knowledge = Usage_Trends::knowledge_start_ts( $log, $policy, $now );
		$end_ts    = $now + 1;

		$rate_map = Cost::sanitize_provider_rates( $policy['est_usd_provider_rates'] ?? array() );

		/** @var array<string,array{calls:int,known_spend:float,unknown_spend_calls:int,providers:array<string,array{calls:int,known_spend:float,unknown_spend_calls:int,has_rate:bool,models:array<string,array{calls:int,known_spend:float,unknown_spend_calls:int,has_rate:bool}>}>}> $tree */
		$tree = array();
		$days_with_data = array();
		$total_calls    = 0;
		$total_known    = 0.0;
		$total_unknown_calls = 0;

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) || ! Usage_Trends::is_activity_row( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				continue;
			}
			if ( $knowledge > 0 && $ts < $knowledge ) {
				continue;
			}
			if ( $ts >= $end_ts ) {
				continue;
			}

			$plugin = isset( $row['plugin'] ) ? trim( (string) $row['plugin'] ) : '';
			if ( '' === $plugin ) {
				$plugin = Analytics::UNKNOWN_KEY;
			}
			$provider_raw = isset( $row['provider'] ) ? trim( (string) $row['provider'] ) : '';
			$provider     = '' !== $provider_raw
				? Cost::normalize_provider_id( $provider_raw )
				: '';
			if ( '' === $provider ) {
				$provider = Analytics::UNKNOWN_KEY;
			}
			$model = isset( $row['model'] ) ? trim( (string) $row['model'] ) : '';
			if ( '' === $model ) {
				$model = Analytics::UNKNOWN_KEY;
			}

			$day_key                  = gmdate( 'Y-m-d', $ts );
			$days_with_data[ $day_key ] = true;

			$has_rate = self::provider_has_rate_table_entry( $provider, $rate_map );
			$usd      = null;
			if ( $has_rate ) {
				$usd = self::row_spend_usd_with_table_rate( $row, $rate_map[ $provider ] );
			} else {
				// Still detect "has tokens but no rate" vs "no token data".
				$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
				$out = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
				if ( null !== $in || null !== $out ) {
					$usd = null; // unknown rate — do not fabricate from fallback.
				}
			}

			if ( ! isset( $tree[ $plugin ] ) ) {
				$tree[ $plugin ] = array(
					'calls'                => 0,
					'known_spend'          => 0.0,
					'unknown_spend_calls'  => 0,
					'providers'            => array(),
				);
			}
			if ( ! isset( $tree[ $plugin ]['providers'][ $provider ] ) ) {
				$tree[ $plugin ]['providers'][ $provider ] = array(
					'calls'               => 0,
					'known_spend'         => 0.0,
					'unknown_spend_calls' => 0,
					'has_rate'            => $has_rate,
					'models'              => array(),
				);
			}
			if ( ! isset( $tree[ $plugin ]['providers'][ $provider ]['models'][ $model ] ) ) {
				$tree[ $plugin ]['providers'][ $provider ]['models'][ $model ] = array(
					'calls'               => 0,
					'known_spend'         => 0.0,
					'unknown_spend_calls' => 0,
					'has_rate'            => $has_rate,
				);
			}

			++$tree[ $plugin ]['calls'];
			++$tree[ $plugin ]['providers'][ $provider ]['calls'];
			++$tree[ $plugin ]['providers'][ $provider ]['models'][ $model ]['calls'];
			++$total_calls;

			if ( $has_rate && null !== $usd ) {
				$tree[ $plugin ]['known_spend'] += $usd;
				$tree[ $plugin ]['providers'][ $provider ]['known_spend'] += $usd;
				$tree[ $plugin ]['providers'][ $provider ]['models'][ $model ]['known_spend'] += $usd;
				$total_known += $usd;
			} elseif ( ! $has_rate && ( array_key_exists( 'input_tokens', $row ) || array_key_exists( 'output_tokens', $row ) ) ) {
				++$tree[ $plugin ]['unknown_spend_calls'];
				++$tree[ $plugin ]['providers'][ $provider ]['unknown_spend_calls'];
				++$tree[ $plugin ]['providers'][ $provider ]['models'][ $model ]['unknown_spend_calls'];
				++$total_unknown_calls;
			}
		}

		$days_count = count( $days_with_data );
		if ( $days_count < self::MIN_DAYS_WITH_DATA ) {
			return null;
		}

		$start_ts = $knowledge > 0 ? $knowledge : self::oldest_activity_ts( $log, $end_ts );
		$gap_label = self::gap_label( $knowledge, $start_ts, $now );

		$plugin_rows = array();
		$known_provider_count   = 0;
		$unknown_provider_count = 0;
		$seen_providers         = array();

		foreach ( $tree as $basename => $node ) {
			$provider_rows = array();
			foreach ( $node['providers'] as $provider_id => $pnode ) {
				$spend_status = self::spend_status_for_node( $pnode );
				if ( ! isset( $seen_providers[ $provider_id ] ) ) {
					$seen_providers[ $provider_id ] = true;
					if ( 'known' === $spend_status ) {
						++$known_provider_count;
					} elseif ( 'unknown' === $spend_status ) {
						++$unknown_provider_count;
					}
				}

				$model_rows = array();
				foreach ( $pnode['models'] as $model_id => $mnode ) {
					$model_status = self::spend_status_for_node( $mnode );
					$model_rows[] = array(
						'model'         => $model_id,
						'label'         => self::model_label( $model_id ),
						'calls'         => (int) $mnode['calls'],
						'spend_status'  => $model_status,
						'known_spend'   => 'known' === $model_status ? round( (float) $mnode['known_spend'], 6 ) : null,
						'spend_share_pct' => self::share_pct(
							'known' === $model_status ? (float) $mnode['known_spend'] : null,
							$total_known
						),
					);
				}
				usort(
					$model_rows,
					static function ( array $a, array $b ): int {
						$cmp = $b['calls'] <=> $a['calls'];
						return 0 !== $cmp ? $cmp : strcmp( (string) $a['model'], (string) $b['model'] );
					}
				);

				$provider_rows[] = array(
					'provider'        => $provider_id,
					'label'           => self::provider_label( $provider_id ),
					'calls'           => (int) $pnode['calls'],
					'spend_status'    => $spend_status,
					'known_spend'     => 'known' === $spend_status ? round( (float) $pnode['known_spend'], 6 ) : null,
					'spend_share_pct' => self::share_pct(
						'known' === $spend_status ? (float) $pnode['known_spend'] : null,
						$total_known
					),
					'models'          => $model_rows,
				);
			}
			usort(
				$provider_rows,
				static function ( array $a, array $b ): int {
					$cmp = $b['calls'] <=> $a['calls'];
					return 0 !== $cmp ? $cmp : strcmp( (string) $a['provider'], (string) $b['provider'] );
				}
			);

			$plugin_rows[] = array(
				'plugin'              => $basename,
				'label'               => self::plugin_label( $basename, $plugins ),
				'calls'               => (int) $node['calls'],
				'known_spend'         => round( (float) $node['known_spend'], 6 ),
				'unknown_spend_calls' => (int) $node['unknown_spend_calls'],
				'spend_share_pct'     => self::share_pct( (float) $node['known_spend'], $total_known ),
				'providers'           => $provider_rows,
			);
		}

		usort(
			$plugin_rows,
			static function ( array $a, array $b ): int {
				$cmp = $b['calls'] <=> $a['calls'];
				return 0 !== $cmp ? $cmp : strcmp( (string) $a['plugin'], (string) $b['plugin'] );
			}
		);

		return array(
			'plugins' => $plugin_rows,
			'totals'  => array(
				'calls'                   => $total_calls,
				'known_spend'             => round( $total_known, 6 ),
				'unknown_spend_calls'     => $total_unknown_calls,
				'known_spend_providers'   => $known_provider_count,
				'unknown_spend_providers' => $unknown_provider_count,
			),
			'window'  => array(
				'start_ts'            => $start_ts,
				'end_ts'              => $end_ts,
				'days_with_data'      => $days_count,
				'knowledge_start_ts'  => $knowledge,
				'gap_label'           => $gap_label,
			),
		);
	}

	/**
	 * Activity URL filtered to one provider (same query args Activity CSV uses).
	 */
	public static function activity_url_for_provider( string $provider ): string {
		$provider = Cost::normalize_provider_id( $provider );
		if ( '' === $provider || Analytics::UNKNOWN_KEY === $provider ) {
			return Admin::screen_url( 'activity' ) . '#handl-aicac-log-wrap';
		}

		return Admin::screen_url(
			'activity',
			array(
				'handl_aicac_log_provider' => $provider,
			)
		) . '#handl-aicac-log-wrap';
	}

	/**
	 * True when the provider id has a configured pair in est_usd_provider_rates.
	 *
	 * @param array<string,array{input_per_m:float,output_per_m:float}> $rate_map
	 */
	public static function provider_has_rate_table_entry( string $provider, array $rate_map ): bool {
		if ( '' === $provider || Analytics::UNKNOWN_KEY === $provider ) {
			return false;
		}
		$id = Cost::normalize_provider_id( $provider );

		return isset( $rate_map[ $id ] );
	}

	/**
	 * Share of known spend (null when numerator unknown or denominator is 0).
	 */
	public static function share_pct( ?float $part, float $known_total ): ?float {
		if ( null === $part ) {
			return null;
		}
		if ( $known_total <= 0.0 ) {
			return null;
		}

		return round( ( $part / $known_total ) * 100.0, 2 );
	}

	/**
	 * Plain-language label for spend cells.
	 */
	public static function format_spend_cell( string $status, ?float $known_spend, ?float $share_pct ): string {
		if ( 'unknown' === $status ) {
			return __( 'Spend unknown', 'handl-ai-connector-access-control' );
		}
		if ( 'known' !== $status || null === $known_spend ) {
			return '—';
		}
		$amount = Cost::format_usd( $known_spend );
		if ( null === $share_pct ) {
			return $amount;
		}

		return sprintf(
			/* translators: 1: dollar amount, 2: percentage of known spend */
			__( '%1$s (%2$s%%)', 'handl-ai-connector-access-control' ),
			$amount,
			number_format_i18n( $share_pct, 1 )
		);
	}

	/**
	 * @param array{calls:int,known_spend:float,unknown_spend_calls:int,has_rate?:bool} $node
	 * @return 'known'|'unknown'|'none'
	 */
	private static function spend_status_for_node( array $node ): string {
		if ( (int) ( $node['unknown_spend_calls'] ?? 0 ) > 0 && (float) ( $node['known_spend'] ?? 0 ) <= 0.0 ) {
			return 'unknown';
		}
		if ( (float) ( $node['known_spend'] ?? 0 ) > 0.0 || ! empty( $node['has_rate'] ) ) {
			// has_rate with zero tokens still "known" rate path (spend $0).
			if ( ! empty( $node['has_rate'] ) ) {
				return 'known';
			}
		}
		if ( (float) ( $node['known_spend'] ?? 0 ) > 0.0 ) {
			return 'known';
		}
		if ( (int) ( $node['unknown_spend_calls'] ?? 0 ) > 0 ) {
			return 'unknown';
		}

		return 'none';
	}

	/**
	 * @param array{input_per_m:float,output_per_m:float} $rates
	 * @param array<string,mixed>                        $row
	 */
	private static function row_spend_usd_with_table_rate( array $row, array $rates ): ?float {
		$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
		$out = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;

		return Cost::estimate_usd( $in, $out, $rates );
	}

	/**
	 * @param array<int,mixed> $log
	 */
	private static function oldest_activity_ts( array $log, int $end_ts ): int {
		$oldest = 0;
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) || ! Usage_Trends::is_activity_row( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 || $ts >= $end_ts ) {
				continue;
			}
			if ( 0 === $oldest || $ts < $oldest ) {
				$oldest = $ts;
			}
		}

		return $oldest;
	}

	private static function gap_label( int $knowledge, int $start_ts, int $now ): ?string {
		unset( $start_ts, $now );
		if ( $knowledge <= 0 ) {
			return null;
		}

		// Retention truncates older history — same plain-language pattern as weekly trends.
		return __( 'Older days: No data kept (outside the saved log window).', 'handl-ai-connector-access-control' );
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

	private static function provider_label( string $provider ): string {
		if ( Analytics::UNKNOWN_KEY === $provider || '' === $provider ) {
			return __( '(unknown provider)', 'handl-ai-connector-access-control' );
		}

		return $provider;
	}

	private static function model_label( string $model ): string {
		if ( Analytics::UNKNOWN_KEY === $model || '' === $model ) {
			return __( '(unknown model)', 'handl-ai-connector-access-control' );
		}

		return $model;
	}
}
