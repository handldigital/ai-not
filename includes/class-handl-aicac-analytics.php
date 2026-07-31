<?php
/**
 * Aggregated usage stats from the recent-call log.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Analytics {
	public const UNKNOWN_KEY = '__unknown__';

	/**
	 * @param array<int,mixed> $log
	 * @param array<string,array<string,mixed>> $plugins
	 * @return array{
	 *   summary: array{
	 *     calls:int,
	 *     calls_with_tokens:int,
	 *     sum_input:int,
	 *     sum_output:int,
	 *     sum_total:int,
	 *     max_input:int,
	 *     max_output:int,
	 *     max_total:int,
	 *     first_ts:int,
	 *     last_ts:int
	 *   },
	 *   dimensions: array{
	 *     provider: list<array<string,mixed>>,
	 *     model: list<array<string,mixed>>,
	 *     plugin: list<array<string,mixed>>,
	 *     operation: list<array<string,mixed>>
	 *   }
	 * }
	 */
	public static function aggregate_from_log( array $log, array $plugins ): array {
		$summary = array(
			'calls'             => 0,
			'calls_with_tokens' => 0,
			'sum_input'         => 0,
			'sum_output'        => 0,
			'sum_total'         => 0,
			'max_input'         => 0,
			'max_output'        => 0,
			'max_total'         => 0,
			'first_ts'          => 0,
			'last_ts'           => 0,
		);

		$buckets = array(
			'provider'  => array(),
			'model'     => array(),
			'plugin'    => array(),
			'operation' => array(),
		);

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}

			// F6 direct_http rows widen "known AI activity" for F5; they must not
			// inflate AI Client spend/token aggregates or mint a second coverage %.
			// Insights shows a separate one-line count for these observations.
			if ( isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'] ) {
				continue;
			}

			$tokens = self::tokens_from_row( $row );
			$ts     = isset( $row['ts'] ) ? (int) $row['ts'] : 0;

			++$summary['calls'];
			if ( $ts > 0 ) {
				if ( 0 === $summary['first_ts'] || $ts < $summary['first_ts'] ) {
					$summary['first_ts'] = $ts;
				}
				if ( $ts > $summary['last_ts'] ) {
					$summary['last_ts'] = $ts;
				}
			}

			if ( null !== $tokens ) {
				++$summary['calls_with_tokens'];
				$summary['sum_input']  += $tokens['input'];
				$summary['sum_output'] += $tokens['output'];
				$summary['sum_total']  += $tokens['total'];
				$summary['max_input']   = max( $summary['max_input'], $tokens['input'] );
				$summary['max_output']  = max( $summary['max_output'], $tokens['output'] );
				$summary['max_total']   = max( $summary['max_total'], $tokens['total'] );
			}

			$dims = array(
				'provider'  => self::field_key( $row, 'provider' ),
				'model'     => self::model_key( $row ),
				'plugin'    => self::field_key( $row, 'plugin' ),
				'operation' => self::field_key( $row, 'operation' ),
			);

			foreach ( $dims as $dimension => $key ) {
				self::accumulate_bucket( $buckets[ $dimension ], $key, $tokens, $ts );
			}
		}

		$dimensions = array();
		foreach ( $buckets as $dimension => $map ) {
			$dimensions[ $dimension ] = self::finalize_buckets( $map, $dimension, $plugins );
		}

		return array(
			'summary'    => $summary,
			'dimensions' => $dimensions,
		);
	}

	/**
	 * @param array<string,mixed> $row
	 * @return array{input:int,output:int,total:int}|null
	 */
	private static function tokens_from_row( array $row ): ?array {
		$has_input  = array_key_exists( 'input_tokens', $row );
		$has_output = array_key_exists( 'output_tokens', $row );
		$has_total  = array_key_exists( 'total_tokens', $row );

		if ( ! $has_input && ! $has_output && ! $has_total ) {
			return null;
		}

		$input  = $has_input ? (int) $row['input_tokens'] : 0;
		$output = $has_output ? (int) $row['output_tokens'] : 0;
		$total  = $has_total ? (int) $row['total_tokens'] : ( $input + $output );

		if ( 0 === $input && 0 === $output && 0 === $total ) {
			return null;
		}

		return array(
			'input'  => $input,
			'output' => $output,
			'total'  => $total,
		);
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function field_key( array $row, string $field ): string {
		$value = isset( $row[ $field ] ) ? trim( (string) $row[ $field ] ) : '';
		return '' === $value ? self::UNKNOWN_KEY : $value;
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function model_key( array $row ): string {
		$model = isset( $row['model'] ) ? trim( (string) $row['model'] ) : '';
		if ( '' === $model && ! empty( $row['model_preferences'] ) && is_array( $row['model_preferences'] ) ) {
			$model = implode( ', ', array_map( 'strval', $row['model_preferences'] ) );
		}

		return '' === $model ? self::UNKNOWN_KEY : $model;
	}

	/**
	 * @param array<string,array<string,mixed>> $map
	 * @param array{input:int,output:int,total:int}|null $tokens
	 */
	private static function accumulate_bucket( array &$map, string $key, ?array $tokens, int $ts ): void {
		if ( ! isset( $map[ $key ] ) ) {
			$map[ $key ] = array(
				'key'               => $key,
				'calls'             => 0,
				'calls_with_tokens' => 0,
				'sum_input'         => 0,
				'sum_output'        => 0,
				'sum_total'         => 0,
				'max_input'         => 0,
				'max_output'        => 0,
				'max_total'         => 0,
				'last_ts'           => 0,
			);
		}

		++$map[ $key ]['calls'];

		if ( $ts > $map[ $key ]['last_ts'] ) {
			$map[ $key ]['last_ts'] = $ts;
		}

		if ( null === $tokens ) {
			return;
		}

		++$map[ $key ]['calls_with_tokens'];
		$map[ $key ]['sum_input']  += $tokens['input'];
		$map[ $key ]['sum_output'] += $tokens['output'];
		$map[ $key ]['sum_total']  += $tokens['total'];
		$map[ $key ]['max_input']   = max( $map[ $key ]['max_input'], $tokens['input'] );
		$map[ $key ]['max_output']  = max( $map[ $key ]['max_output'], $tokens['output'] );
		$map[ $key ]['max_total']   = max( $map[ $key ]['max_total'], $tokens['total'] );
	}

	/**
	 * @param array<string,array<string,mixed>> $map
	 * @param array<string,array<string,mixed>> $plugins
	 * @return list<array<string,mixed>>
	 */
	private static function finalize_buckets( array $map, string $dimension, array $plugins ): array {
		$rows = array_values( $map );

		foreach ( $rows as &$row ) {
			$row['label'] = self::label_for_key( (string) $row['key'], $dimension, $plugins );
		}
		unset( $row );

		usort(
			$rows,
			static function ( array $a, array $b ): int {
				return $b['calls'] <=> $a['calls'];
			}
		);

		return $rows;
	}

	/**
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private static function label_for_key( string $key, string $dimension, array $plugins ): string {
		if ( self::UNKNOWN_KEY === $key ) {
			return __( '(unknown)', 'handl-ai-connector-access-control' );
		}

		if ( 'plugin' === $dimension && isset( $plugins[ $key ]['Name'] ) ) {
			return (string) $plugins[ $key ]['Name'];
		}

		return $key;
	}
}
