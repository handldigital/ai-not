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
	 * Known provider ids that accept an optional per-provider rate pair (AICAC-24).
	 *
	 * @var list<string>
	 */
	public const KNOWN_PROVIDERS = array(
		'openai',
		'anthropic',
		'google',
		'cohere',
		'mistral',
		'groq',
		'together',
		'fireworks',
		'perplexity',
		'xai',
		'deepseek',
		'openrouter',
	);

	/**
	 * Global fallback rates from policy (ignores per-provider overrides).
	 *
	 * @param array<string,mixed> $policy
	 * @return array{input_per_m:float,output_per_m:float}
	 */
	public static function fallback_rates_from_policy( array $policy ): array {
		$in  = isset( $policy['est_usd_input_per_m'] ) ? (float) $policy['est_usd_input_per_m'] : self::DEFAULT_INPUT_PER_M;
		$out = isset( $policy['est_usd_output_per_m'] ) ? (float) $policy['est_usd_output_per_m'] : self::DEFAULT_OUTPUT_PER_M;

		return array(
			'input_per_m'  => self::clamp_rate( $in ),
			'output_per_m' => self::clamp_rate( $out ),
		);
	}

	/**
	 * Resolve rates for an optional provider id.
	 *
	 * Unknown/missing provider → global fallback. Known provider with no
	 * configured pair → global fallback. Configured pair → that pair only.
	 *
	 * @param array<string,mixed> $policy
	 * @param string|null         $provider Log-row provider id (may be empty).
	 * @return array{input_per_m:float,output_per_m:float}
	 */
	public static function rates_from_policy( array $policy, ?string $provider = null ): array {
		$fallback = self::fallback_rates_from_policy( $policy );
		$id       = self::normalize_provider_id( (string) ( $provider ?? '' ) );
		if ( '' === $id || ! self::is_known_provider( $id ) ) {
			return $fallback;
		}

		$map = self::sanitize_provider_rates( $policy['est_usd_provider_rates'] ?? array() );
		if ( ! isset( $map[ $id ] ) ) {
			return $fallback;
		}

		return $map[ $id ];
	}

	/**
	 * True when global rates match built-in placeholders and no per-provider overrides exist.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function using_default_rates( array $policy ): bool {
		$rates = self::fallback_rates_from_policy( $policy );
		if ( abs( $rates['input_per_m'] - self::DEFAULT_INPUT_PER_M ) >= 0.00001
			|| abs( $rates['output_per_m'] - self::DEFAULT_OUTPUT_PER_M ) >= 0.00001 ) {
			return false;
		}

		return empty( self::sanitize_provider_rates( $policy['est_usd_provider_rates'] ?? array() ) );
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
				'output_per_m'  => self::DEFAULT_OUTPUT_PER_M,
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

		return self::clamp_rate( (float) $raw );
	}

	/**
	 * Keep only known provider ids with a sanitized input/output pair.
	 *
	 * Empty / non-array input → empty map (no overrides). Unknown ids dropped.
	 *
	 * @param mixed $raw
	 * @return array<string,array{input_per_m:float,output_per_m:float}>
	 */
	public static function sanitize_provider_rates( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}

		$out = array();
		foreach ( self::KNOWN_PROVIDERS as $id ) {
			if ( ! isset( $raw[ $id ] ) || ! is_array( $raw[ $id ] ) ) {
				continue;
			}
			$row = $raw[ $id ];
			$in_raw  = $row['input_per_m'] ?? $row['input'] ?? null;
			$out_raw = $row['output_per_m'] ?? $row['output'] ?? null;
			// Both empty → not configured for this provider.
			if ( self::is_blank_rate( $in_raw ) && self::is_blank_rate( $out_raw ) ) {
				continue;
			}
			$out[ $id ] = array(
				'input_per_m'  => self::sanitize_rate( $in_raw, self::DEFAULT_INPUT_PER_M ),
				'output_per_m' => self::sanitize_rate( $out_raw, self::DEFAULT_OUTPUT_PER_M ),
			);
		}

		return $out;
	}

	public static function is_known_provider( string $id ): bool {
		return in_array( $id, self::KNOWN_PROVIDERS, true );
	}

	public static function normalize_provider_id( string $provider ): string {
		$provider = strtolower( trim( $provider ) );
		// Strip accidental whitespace / casing only — ids are lowercase snake-ish.
		return preg_replace( '/[^a-z0-9_-]/', '', $provider ) ?? '';
	}

	/**
	 * @param mixed $raw
	 */
	private static function is_blank_rate( $raw ): bool {
		if ( null === $raw ) {
			return true;
		}
		if ( is_string( $raw ) ) {
			return '' === trim( $raw );
		}

		return false;
	}

	private static function clamp_rate( float $v ): float {
		if ( $v < 0 ) {
			return 0.0;
		}
		if ( $v > 10000 ) {
			return 10000.0;
		}

		return $v;
	}
}
