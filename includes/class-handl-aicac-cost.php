<?php
/**
 * Cheap estimated-USD helpers from token counts (observability only).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Rough token → USD estimates for the audit UI.
 *
 * Never used for enforcement. Defaults are placeholders, not live market rates.
 */
final class Cost {
	/** Default USD per 1M input (prompt) tokens — rough placeholder. */
	public const DEFAULT_INPUT_PER_M = 2.50;

	/** Default USD per 1M output (completion) tokens — rough placeholder. */
	public const DEFAULT_OUTPUT_PER_M = 10.00;

	/**
	 * @param array<string,mixed> $policy
	 * @return array{input_per_m:float,output_per_m:float}
	 */
	public static function rates_from_policy( array $policy ): array {
		$in  = isset( $policy['est_usd_input_per_m'] ) ? (float) $policy['est_usd_input_per_m'] : self::DEFAULT_INPUT_PER_M;
		$out = isset( $policy['est_usd_output_per_m'] ) ? (float) $policy['est_usd_output_per_m'] : self::DEFAULT_OUTPUT_PER_M;
		if ( $in < 0 ) {
			$in = 0.0;
		}
		if ( $out < 0 ) {
			$out = 0.0;
		}
		// Cap absurd config typos.
		if ( $in > 10000 ) {
			$in = 10000.0;
		}
		if ( $out > 10000 ) {
			$out = 10000.0;
		}

		return array(
			'input_per_m'  => $in,
			'output_per_m' => $out,
		);
	}

	/**
	 * @param array{input_per_m:float,output_per_m:float}|null $rates
	 */
	public static function estimate_usd( ?int $input_tokens, ?int $output_tokens, ?array $rates = null ): ?float {
		if ( null === $input_tokens && null === $output_tokens ) {
			return null;
		}

		if ( null === $rates ) {
			$rates = array(
				'input_per_m'  => self::DEFAULT_INPUT_PER_M,
				'output_per_m' => self::DEFAULT_OUTPUT_PER_M,
			);
		}

		$in  = max( 0, (int) ( $input_tokens ?? 0 ) );
		$out = max( 0, (int) ( $output_tokens ?? 0 ) );
		if ( 0 === $in && 0 === $out ) {
			return 0.0;
		}

		return ( $in / 1_000_000 ) * (float) $rates['input_per_m']
			+ ( $out / 1_000_000 ) * (float) $rates['output_per_m'];
	}

	/**
	 * Format a USD estimate for display (always labeled est. by callers).
	 */
	public static function format_usd( float $amount ): string {
		if ( $amount > 0 && $amount < 0.01 ) {
			return '<$0.01';
		}

		$formatted = function_exists( 'number_format_i18n' )
			? number_format_i18n( $amount, 2 )
			: number_format( $amount, 2, '.', ',' );

		return '$' . $formatted;
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_rate( $raw, float $default ): float {
		if ( ! is_numeric( $raw ) ) {
			return $default;
		}
		$v = (float) $raw;
		if ( $v < 0 ) {
			return 0.0;
		}
		if ( $v > 10000 ) {
			return 10000.0;
		}

		return $v;
	}
}
