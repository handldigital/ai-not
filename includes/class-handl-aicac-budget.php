<?php
/**
 * AICAC-BUDGET-A: per-plugin estimated-spend accounting + calendar-month periods (#166).
 *
 * Accumulates estimated USD (rate table) keyed by period id (Y-m) in the site
 * timezone. Period key is authoritative — a mid-month timezone change cannot
 * double-count already-recorded spend. No enforcement and no UI (B/C).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Spend accumulator + budget value storage (observability / accounting only).
 */
final class Budget {

	/** period_id => [ plugin_basename => estimated_usd ]. */
	public const SPEND_OPTION_KEY = 'handl_aicac_budget_spend';

	/** Keep a few past months so B/C can report; drop older keys on write. */
	public const RETAIN_PERIODS = 6;

	/**
	 * Calendar-month period id in site timezone (e.g. 2026-08).
	 */
	public static function period_id( ?int $ts = null, ?\DateTimeZone $tz = null ): string {
		$ts = null !== $ts ? (int) $ts : time();
		if ( $ts <= 0 ) {
			$ts = time();
		}
		$tz = Quiet_Hours::timezone( $tz );
		return ( new \DateTimeImmutable( '@' . $ts ) )->setTimezone( $tz )->format( 'Y-m' );
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_period_id( $raw ): string {
		$key = (string) $raw;
		if ( ! preg_match( '/^\d{4}-(0[1-9]|1[0-2])$/', $key ) ) {
			return '';
		}
		return $key;
	}

	/**
	 * Empty / non-positive → unlimited (omit). Positive USD capped.
	 *
	 * @param mixed $raw
	 */
	public static function sanitize_budget_amount( $raw ): ?float {
		if ( null === $raw || false === $raw ) {
			return null;
		}
		if ( is_string( $raw ) ) {
			$raw = trim( $raw );
			if ( '' === $raw ) {
				return null;
			}
		}
		if ( ! is_numeric( $raw ) ) {
			return null;
		}
		$v = (float) $raw;
		if ( $v <= 0 ) {
			return null;
		}
		if ( $v > 1000000 ) {
			$v = 1000000.0;
		}

		return round( $v, 4 );
	}

	/**
	 * @param mixed $raw basename => amount map
	 * @return array<string,float>
	 */
	public static function sanitize_plugin_budgets( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $basename => $amount ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			if ( '' === $basename ) {
				continue;
			}
			$budget = self::sanitize_budget_amount( $amount );
			if ( null === $budget ) {
				continue;
			}
			$out[ $basename ] = $budget;
		}

		return $out;
	}

	/**
	 * Configured budget for a plugin, or null when unlimited.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function get_budget( array $policy, string $plugin ): ?float {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return null;
		}
		$map = self::sanitize_plugin_budgets( $policy['plugin_budgets'] ?? array() );

		return $map[ $plugin ] ?? null;
	}

	/**
	 * @return array<string,array<string,float>>
	 */
	public static function get_spend_map(): array {
		return self::sanitize_spend_map( get_option( self::SPEND_OPTION_KEY, array() ) );
	}

	/**
	 * @param mixed $raw
	 * @return array<string,array<string,float>>
	 */
	public static function sanitize_spend_map( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $period => $plugins ) {
			$period = self::sanitize_period_id( $period );
			if ( '' === $period || ! is_array( $plugins ) ) {
				continue;
			}
			$clean = array();
			foreach ( $plugins as $plugin => $usd ) {
				$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
				if ( '' === $plugin || ! is_numeric( $usd ) ) {
					continue;
				}
				$amount = round( (float) $usd, 6 );
				if ( $amount < 0 ) {
					$amount = 0.0;
				}
				$clean[ $plugin ] = $amount;
			}
			if ( ! empty( $clean ) ) {
				$out[ $period ] = $clean;
			}
		}

		return $out;
	}

	/**
	 * @param array<string,array<string,float>> $map
	 */
	public static function save_spend_map( array $map ): void {
		$map = self::sanitize_spend_map( $map );
		$map = self::prune_old_periods( $map );
		if ( empty( $map ) ) {
			delete_option( self::SPEND_OPTION_KEY );
			return;
		}
		update_option( self::SPEND_OPTION_KEY, $map, false );
	}

	/**
	 * Drop periods older than RETAIN_PERIODS (by Y-m string order).
	 *
	 * @param array<string,array<string,float>> $map
	 * @return array<string,array<string,float>>
	 */
	public static function prune_old_periods( array $map, ?string $current_period = null ): array {
		if ( count( $map ) <= self::RETAIN_PERIODS ) {
			return $map;
		}
		$keys = array_keys( $map );
		rsort( $keys, SORT_STRING );
		$keep = array_slice( $keys, 0, self::RETAIN_PERIODS );
		$out  = array();
		foreach ( $keep as $k ) {
			$out[ $k ] = $map[ $k ];
		}
		// Prefer retaining the current period even if somehow outside the newest N.
		if ( null !== $current_period && isset( $map[ $current_period ] ) && ! isset( $out[ $current_period ] ) ) {
			$out[ $current_period ] = $map[ $current_period ];
		}

		return $out;
	}

	/**
	 * Add estimated USD to the period bucket for $plugin.
	 * Period id is taken from $ts in $tz (defaults: now / site timezone).
	 */
	public static function add_estimated_spend( string $plugin, float $usd, ?int $ts = null, ?\DateTimeZone $tz = null ): void {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		if ( '' === $plugin || $usd <= 0.0 ) {
			return;
		}
		$period = self::period_id( $ts, $tz );
		$map    = self::get_spend_map();
		if ( ! isset( $map[ $period ] ) ) {
			$map[ $period ] = array();
		}
		$prior = isset( $map[ $period ][ $plugin ] ) ? (float) $map[ $period ][ $plugin ] : 0.0;
		$map[ $period ][ $plugin ] = round( $prior + $usd, 6 );
		self::save_spend_map( self::prune_old_periods( $map, $period ) );
	}

	/**
	 * Estimated spend for a plugin in a period (0 when none).
	 */
	public static function period_spend( string $plugin, string $period ): float {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		$period = self::sanitize_period_id( $period );
		if ( '' === $plugin || '' === $period ) {
			return 0.0;
		}
		$map = self::get_spend_map();

		return isset( $map[ $period ][ $plugin ] ) ? (float) $map[ $period ][ $plugin ] : 0.0;
	}

	/**
	 * Current-period spend for a plugin.
	 */
	public static function current_period_spend( string $plugin, ?int $now = null, ?\DateTimeZone $tz = null ): float {
		return self::period_spend( $plugin, self::period_id( $now, $tz ) );
	}

	/**
	 * Read API for parts B and C.
	 *
	 * @param array<string,mixed> $policy
	 * @return array{
	 *   plugin:string,
	 *   period:string,
	 *   spend:float,
	 *   budget:float|null,
	 *   percent_used:float|null,
	 *   unlimited:bool
	 * }
	 */
	public static function status( array $policy, string $plugin, ?int $now = null, ?\DateTimeZone $tz = null ): array {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		$period = self::period_id( $now, $tz );
		$spend  = self::period_spend( $plugin, $period );
		$budget = self::get_budget( $policy, $plugin );
		$unlimited = null === $budget;
		$percent   = null;
		if ( ! $unlimited && $budget > 0.0 ) {
			$percent = round( 100.0 * ( $spend / $budget ), 2 );
			if ( $percent > 9999.99 ) {
				$percent = 9999.99;
			}
		}

		return array(
			'plugin'       => $plugin,
			'period'       => $period,
			'spend'        => $spend,
			'budget'       => $budget,
			'percent_used' => $percent,
			'unlimited'    => $unlimited,
		);
	}

	/**
	 * Record estimated-spend delta when a log row gains or increases tokens.
	 *
	 * @param array<string,mixed> $before Row before patch (may lack tokens).
	 * @param array<string,mixed> $after  Row after patch.
	 * @param array<string,mixed> $policy
	 */
	public static function maybe_record_from_row( array $before, array $after, array $policy ): void {
		$channel = isset( $after['channel'] ) ? (string) $after['channel'] : '';
		if ( in_array( $channel, array( 'direct_http', 'anomaly', 'spend_threshold', 'drift', 'alert_snooze' ), true ) ) {
			return;
		}
		$plugin = isset( $after['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $after['plugin'] ) : '';
		if ( '' === $plugin ) {
			return;
		}

		$before_usd = self::estimate_row_usd( $before, $policy );
		$after_usd  = self::estimate_row_usd( $after, $policy );
		if ( null === $after_usd ) {
			return;
		}
		$prior = null !== $before_usd ? $before_usd : 0.0;
		$delta = $after_usd - $prior;
		if ( $delta <= 0.0 ) {
			return;
		}

		$ts = isset( $after['ts'] ) ? (int) $after['ts'] : time();
		self::add_estimated_spend( $plugin, $delta, $ts );
	}

	/**
	 * @param array<string,mixed> $row
	 * @param array<string,mixed> $policy
	 */
	public static function estimate_row_usd( array $row, array $policy ): ?float {
		$has_in  = array_key_exists( 'input_tokens', $row );
		$has_out = array_key_exists( 'output_tokens', $row );
		if ( ! $has_in && ! $has_out ) {
			return null;
		}
		$in  = $has_in ? (int) $row['input_tokens'] : null;
		$out = $has_out ? (int) $row['output_tokens'] : null;
		$rates = Cost::rates_from_policy( $policy, isset( $row['provider'] ) ? (string) $row['provider'] : null );

		return Cost::estimate_usd( $in, $out, $rates );
	}
}
