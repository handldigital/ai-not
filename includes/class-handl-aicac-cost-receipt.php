<?php
/**
 * AICAC-COST-RECEIPT: calendar-month estimated-spend receipt (#263).
 *
 * Display-only. Uses a bundled provider/model price table plus optional
 * site overrides. Unknown rates render as n/a — never invent $0.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Monthly cost receipt from the retained activity log.
 */
final class Cost_Receipt {

	/**
	 * Bundled USD per 1M token rates by provider (ESTIMATE placeholders).
	 *
	 * @var array<string,array{input_per_m:float,output_per_m:float}>
	 */
	public const BUNDLED_PROVIDER_RATES = array(
		'openai'     => array( 'input_per_m' => 2.50, 'output_per_m' => 10.00 ),
		'anthropic'  => array( 'input_per_m' => 3.00, 'output_per_m' => 15.00 ),
		'google'     => array( 'input_per_m' => 0.35, 'output_per_m' => 1.05 ),
		'cohere'     => array( 'input_per_m' => 1.00, 'output_per_m' => 2.00 ),
		'mistral'    => array( 'input_per_m' => 1.00, 'output_per_m' => 3.00 ),
		'groq'       => array( 'input_per_m' => 0.05, 'output_per_m' => 0.08 ),
		'together'   => array( 'input_per_m' => 0.20, 'output_per_m' => 0.20 ),
		'fireworks'  => array( 'input_per_m' => 0.20, 'output_per_m' => 0.20 ),
		'perplexity' => array( 'input_per_m' => 1.00, 'output_per_m' => 1.00 ),
		'xai'        => array( 'input_per_m' => 5.00, 'output_per_m' => 15.00 ),
		'deepseek'   => array( 'input_per_m' => 0.27, 'output_per_m' => 1.10 ),
		'openrouter' => array( 'input_per_m' => 2.50, 'output_per_m' => 10.00 ),
	);

	/**
	 * Bundled USD per 1M token rates by normalized model id (ESTIMATE placeholders).
	 *
	 * @var array<string,array{input_per_m:float,output_per_m:float}>
	 */
	public const BUNDLED_MODEL_RATES = array(
		'gpt-4o'              => array( 'input_per_m' => 2.50, 'output_per_m' => 10.00 ),
		'gpt-4o-mini'         => array( 'input_per_m' => 0.15, 'output_per_m' => 0.60 ),
		'gpt-4.1'             => array( 'input_per_m' => 2.00, 'output_per_m' => 8.00 ),
		'gpt-4.1-mini'        => array( 'input_per_m' => 0.40, 'output_per_m' => 1.60 ),
		'o3-mini'             => array( 'input_per_m' => 1.10, 'output_per_m' => 4.40 ),
		'claude-3-5-sonnet'   => array( 'input_per_m' => 3.00, 'output_per_m' => 15.00 ),
		'claude-3-5-haiku'    => array( 'input_per_m' => 0.80, 'output_per_m' => 4.00 ),
		'claude-3-opus'       => array( 'input_per_m' => 15.00, 'output_per_m' => 75.00 ),
		'claude-sonnet-4'     => array( 'input_per_m' => 3.00, 'output_per_m' => 15.00 ),
		'gemini-1.5-pro'      => array( 'input_per_m' => 1.25, 'output_per_m' => 5.00 ),
		'gemini-1.5-flash'    => array( 'input_per_m' => 0.075, 'output_per_m' => 0.30 ),
		'gemini-2.0-flash'    => array( 'input_per_m' => 0.10, 'output_per_m' => 0.40 ),
		'command-r-plus'      => array( 'input_per_m' => 2.50, 'output_per_m' => 10.00 ),
		'mistral-large'       => array( 'input_per_m' => 2.00, 'output_per_m' => 6.00 ),
		'llama-3.1-70b'       => array( 'input_per_m' => 0.59, 'output_per_m' => 0.79 ),
	);

	/**
	 * Filter: `handl_aicac_cost_receipt_table` — merge/replace bundled rates.
	 *
	 * @return array{
	 *   providers: array<string,array{input_per_m:float,output_per_m:float}>,
	 *   models: array<string,array{input_per_m:float,output_per_m:float}>
	 * }
	 */
	public static function bundled_table(): array {
		$table = array(
			'providers' => self::BUNDLED_PROVIDER_RATES,
			'models'    => self::BUNDLED_MODEL_RATES,
		);

		/**
		 * Filter the bundled cost-receipt price table (no HTTP — local only).
		 *
		 * @param array{providers:array<string,array{input_per_m:float,output_per_m:float}>,models:array<string,array{input_per_m:float,output_per_m:float}>} $table
		 */
		$filtered = apply_filters( 'handl_aicac_cost_receipt_table', $table );
		if ( ! is_array( $filtered ) ) {
			return $table;
		}

		$providers = isset( $filtered['providers'] ) && is_array( $filtered['providers'] )
			? self::sanitize_rate_map( $filtered['providers'], true )
			: self::BUNDLED_PROVIDER_RATES;
		$models = isset( $filtered['models'] ) && is_array( $filtered['models'] )
			? self::sanitize_rate_map( $filtered['models'], false )
			: self::BUNDLED_MODEL_RATES;

		return array(
			'providers' => $providers,
			'models'    => $models,
		);
	}

	/**
	 * Resolve rates for one log row. Null = n/a (never invent $0 from global fallback).
	 *
	 * Priority: model override → bundled model → provider override → bundled provider.
	 *
	 * @param array<string,mixed> $policy
	 * @return array{input_per_m:float,output_per_m:float}|null
	 */
	public static function rates_for_row( array $policy, ?string $provider, ?string $model ): ?array {
		$table         = self::bundled_table();
		$model_id      = self::normalize_model_id( (string) ( $model ?? '' ) );
		$provider_id   = Cost::normalize_provider_id( (string) ( $provider ?? '' ) );
		$model_over    = self::sanitize_model_rates( $policy['est_usd_model_rates'] ?? array() );
		$provider_over = Cost::sanitize_provider_rates( $policy['est_usd_provider_rates'] ?? array() );

		if ( '' !== $model_id && isset( $model_over[ $model_id ] ) ) {
			return $model_over[ $model_id ];
		}
		if ( '' !== $model_id && isset( $table['models'][ $model_id ] ) ) {
			return $table['models'][ $model_id ];
		}
		if ( '' !== $provider_id && isset( $provider_over[ $provider_id ] ) ) {
			return $provider_over[ $provider_id ];
		}
		if ( '' !== $provider_id && isset( $table['providers'][ $provider_id ] ) ) {
			return $table['providers'][ $provider_id ];
		}

		return null;
	}

	/**
	 * Estimate USD for a retained log row using receipt rates only.
	 *
	 * @param array<string,mixed> $row
	 * @param array<string,mixed> $policy
	 */
	public static function row_spend_usd( array $row, array $policy ): ?float {
		if ( ! self::is_receipt_row( $row ) ) {
			return null;
		}
		$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
		$out = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
		if ( null === $in && null === $out ) {
			return null;
		}
		$rates = self::rates_for_row(
			$policy,
			isset( $row['provider'] ) ? (string) $row['provider'] : null,
			isset( $row['model'] ) ? (string) $row['model'] : null
		);
		if ( null === $rates ) {
			return null;
		}

		return Cost::estimate_usd( $in, $out, $rates );
	}

	/**
	 * Build current-month + last-month receipt from the retained log.
	 *
	 * @param array<int,mixed>                  $log
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $plugins
	 * @return array{
	 *   current_ym:string,
	 *   previous_ym:string,
	 *   plugins: list<array{
	 *     plugin:string,
	 *     label:string,
	 *     current:float|null,
	 *     previous:float|null,
	 *     current_calls:int,
	 *     previous_calls:int,
	 *     current_na_calls:int,
	 *     previous_na_calls:int
	 *   }>,
	 *   totals: array{
	 *     current:float,
	 *     previous:float,
	 *     current_plugins:int,
	 *     previous_plugins:int,
	 *     current_na_calls:int,
	 *     previous_na_calls:int
	 *   },
	 *   top_current: array{plugin:string,label:string,usd:float}|null
	 * }
	 */
	public static function compute( array $log, array $policy, array $plugins = array(), ?int $now = null ): array {
		$now = null !== $now ? $now : ( class_exists( Clock::class ) ? Clock::now() : time() );
		$tz  = self::timezone();

		$now_dt       = ( new \DateTimeImmutable( '@' . $now ) )->setTimezone( $tz );
		$current_ym   = $now_dt->format( 'Y-m' );
		$previous_ym  = $now_dt->modify( 'first day of last month' )->format( 'Y-m' );

		/** @var array<string,array{current:float,previous:float,current_calls:int,previous_calls:int,current_na:int,previous_na:int}> $tree */
		$tree = array();
		$total_current  = 0.0;
		$total_previous = 0.0;
		$na_current     = 0;
		$na_previous    = 0;

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) || ! self::is_receipt_row( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				continue;
			}
			$row_ym = ( new \DateTimeImmutable( '@' . $ts ) )->setTimezone( $tz )->format( 'Y-m' );
			if ( $row_ym !== $current_ym && $row_ym !== $previous_ym ) {
				continue;
			}

			$has_tokens = array_key_exists( 'input_tokens', $row ) || array_key_exists( 'output_tokens', $row );
			if ( ! $has_tokens ) {
				continue;
			}

			$plugin = isset( $row['plugin'] ) ? trim( (string) $row['plugin'] ) : '';
			if ( '' === $plugin ) {
				$plugin = Analytics::UNKNOWN_KEY;
			}
			if ( ! isset( $tree[ $plugin ] ) ) {
				$tree[ $plugin ] = array(
					'current'         => 0.0,
					'previous'        => 0.0,
					'current_calls'   => 0,
					'previous_calls'  => 0,
					'current_na'      => 0,
					'previous_na'     => 0,
				);
			}

			$usd = self::row_spend_usd( $row, $policy );
			$is_current = ( $row_ym === $current_ym );

			if ( $is_current ) {
				++$tree[ $plugin ]['current_calls'];
			} else {
				++$tree[ $plugin ]['previous_calls'];
			}

			if ( null === $usd ) {
				if ( $is_current ) {
					++$tree[ $plugin ]['current_na'];
					++$na_current;
				} else {
					++$tree[ $plugin ]['previous_na'];
					++$na_previous;
				}
				continue;
			}

			if ( $is_current ) {
				$tree[ $plugin ]['current'] += $usd;
				$total_current += $usd;
			} else {
				$tree[ $plugin ]['previous'] += $usd;
				$total_previous += $usd;
			}
		}

		$plugins_out = array();
		$current_with_spend = 0;
		$previous_with_spend = 0;
		foreach ( $tree as $basename => $node ) {
			$current_val  = ( $node['current_calls'] - $node['current_na'] ) > 0 ? (float) $node['current'] : null;
			$previous_val = ( $node['previous_calls'] - $node['previous_na'] ) > 0 ? (float) $node['previous'] : null;
			// All-na month with calls → explicit null (n/a), not $0.
			if ( $node['current_calls'] > 0 && $node['current_na'] === $node['current_calls'] ) {
				$current_val = null;
			}
			if ( $node['previous_calls'] > 0 && $node['previous_na'] === $node['previous_calls'] ) {
				$previous_val = null;
			}
			if ( null !== $current_val && $current_val > 0 ) {
				++$current_with_spend;
			}
			if ( null !== $previous_val && $previous_val > 0 ) {
				++$previous_with_spend;
			}
			$plugins_out[] = array(
				'plugin'            => (string) $basename,
				'label'             => self::plugin_label( (string) $basename, $plugins ),
				'current'           => null !== $current_val ? round( $current_val, 6 ) : null,
				'previous'          => null !== $previous_val ? round( $previous_val, 6 ) : null,
				'current_calls'     => (int) $node['current_calls'],
				'previous_calls'    => (int) $node['previous_calls'],
				'current_na_calls'  => (int) $node['current_na'],
				'previous_na_calls' => (int) $node['previous_na'],
			);
		}

		usort(
			$plugins_out,
			static function ( array $a, array $b ): int {
				$ac = null !== $a['current'] ? (float) $a['current'] : -1.0;
				$bc = null !== $b['current'] ? (float) $b['current'] : -1.0;
				if ( $ac === $bc ) {
					return strcmp( (string) $a['label'], (string) $b['label'] );
				}

				return $bc <=> $ac;
			}
		);

		$top = null;
		foreach ( $plugins_out as $row ) {
			if ( null !== $row['current'] && (float) $row['current'] > 0 ) {
				$top = array(
					'plugin' => (string) $row['plugin'],
					'label'  => (string) $row['label'],
					'usd'    => (float) $row['current'],
				);
				break;
			}
		}

		return array(
			'current_ym'  => $current_ym,
			'previous_ym' => $previous_ym,
			'plugins'     => $plugins_out,
			'totals'      => array(
				'current'           => round( $total_current, 6 ),
				'previous'          => round( $total_previous, 6 ),
				'current_plugins'   => $current_with_spend,
				'previous_plugins'  => $previous_with_spend,
				'current_na_calls'  => $na_current,
				'previous_na_calls' => $na_previous,
			),
			'top_current' => $top,
		);
	}

	/**
	 * Keep only sane model-id → rate pairs from settings POST / policy.
	 *
	 * @param mixed $raw
	 * @return array<string,array{input_per_m:float,output_per_m:float}>
	 */
	public static function sanitize_model_rates( $raw ): array {
		return self::sanitize_rate_map( is_array( $raw ) ? $raw : array(), false );
	}

	public static function normalize_model_id( string $model ): string {
		$model = strtolower( trim( $model ) );

		// Strip vendor prefixes before char filtering so "Anthropic/claude-…" keeps the slash long enough to match.
		foreach ( array( 'openai/', 'anthropic/', 'google/', 'models/' ) as $prefix ) {
			if ( 0 === strpos( $model, $prefix ) ) {
				$model = substr( $model, strlen( $prefix ) );
				break;
			}
		}

		return preg_replace( '/[^a-z0-9._+-]/', '', $model ) ?? '';
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function is_receipt_row( array $row ): bool {
		$channel = isset( $row['channel'] ) ? (string) $row['channel'] : '';
		if ( in_array(
			$channel,
			array(
				'direct_http',
				'spend_threshold',
				'anomaly',
				'forecast_warn',
				'drift',
				'budget',
				'selftest',
				'pii',
				'retry_storm',
				'mcp',
			),
			true
		) ) {
			return false;
		}

		return Usage_Trends::is_activity_row( $row );
	}

	/**
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private static function plugin_label( string $basename, array $plugins ): string {
		if ( '' === $basename || Analytics::UNKNOWN_KEY === $basename ) {
			return __( '(unknown plugin)', 'handl-ai-connector-access-control' );
		}
		if ( isset( $plugins[ $basename ]['Name'] ) && is_string( $plugins[ $basename ]['Name'] ) ) {
			return (string) $plugins[ $basename ]['Name'];
		}

		return $basename;
	}

	/**
	 * @param array<string,mixed> $raw
	 * @return array<string,array{input_per_m:float,output_per_m:float}>
	 */
	private static function sanitize_rate_map( array $raw, bool $providers_only ): array {
		$out = array();
		foreach ( $raw as $id => $row ) {
			if ( ! is_string( $id ) || ! is_array( $row ) ) {
				continue;
			}
			$key = $providers_only
				? Cost::normalize_provider_id( $id )
				: self::normalize_model_id( $id );
			if ( '' === $key ) {
				continue;
			}
			if ( $providers_only && ! Cost::is_known_provider( $key ) ) {
				continue;
			}
			$in_raw  = $row['input_per_m'] ?? $row['input'] ?? null;
			$out_raw = $row['output_per_m'] ?? $row['output'] ?? null;
			if ( self::is_blank( $in_raw ) && self::is_blank( $out_raw ) ) {
				continue;
			}
			$out[ $key ] = array(
				'input_per_m'  => Cost::sanitize_rate( $in_raw, 0.0 ),
				'output_per_m' => Cost::sanitize_rate( $out_raw, 0.0 ),
			);
		}

		return $out;
	}

	/**
	 * @param mixed $raw
	 */
	private static function is_blank( $raw ): bool {
		if ( null === $raw ) {
			return true;
		}
		if ( is_string( $raw ) ) {
			return '' === trim( $raw );
		}

		return false;
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
