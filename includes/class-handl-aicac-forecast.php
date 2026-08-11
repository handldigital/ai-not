<?php
/**
 * AICAC-FORECAST: Month-end estimated-spend projection (linear run-rate).
 *
 * Uses the retained activity log only. No new collection. Estimates are not bills.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Calendar-month spend forecast and one-shot projection warnings.
 */
final class Spend_Forecast {

	/** Fired-state option: period + threshold per site/plugin key. */
	public const WARNED_OPTION_KEY = 'handl_aicac_forecast_warned';

	/** Minimum distinct calendar days with token activity before showing a projection. */
	public const MIN_ACTIVE_DAYS = 3;

	/**
	 * Build month-to-date + projected month-end totals from the retained log.
	 *
	 * Returns null when fewer than {@see MIN_ACTIVE_DAYS} distinct days of
	 * token-bearing activity exist in the current calendar month (no fabricated
	 * projection). Injectable $now supports month-boundary tests.
	 *
	 * @param array<int,mixed>    $log
	 * @param array<string,mixed> $policy
	 * @return array{
	 *   period_ym:string,
	 *   days_elapsed:int,
	 *   days_in_month:int,
	 *   days_remaining:int,
	 *   active_days:int,
	 *   mtd_site:float,
	 *   projected_site:float,
	 *   plugins:array<string,array{mtd:float,projected:float,active_days:int}>,
	 *   warnings:list<array{scope:string,plugin:?string,threshold:float,projected:float,mtd:float}>
	 * }|null
	 */
	public static function compute( array $log, array $policy, ?int $now = null ): ?array {
		$now = null !== $now ? $now : time();
		$tz  = self::timezone();

		$now_dt         = ( new \DateTimeImmutable( '@' . $now ) )->setTimezone( $tz );
		$period_ym      = $now_dt->format( 'Y-m' );
		$days_in_month  = (int) $now_dt->format( 't' );
		$days_elapsed   = (int) $now_dt->format( 'j' );
		$days_remaining = max( 0, $days_in_month - $days_elapsed );

		$mtd_site     = 0.0;
		$plugin_mtd   = array();
		$active_days  = array();
		$plugin_days  = array();

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$channel = isset( $row['channel'] ) ? (string) $row['channel'] : '';
			if ( 'direct_http' === $channel || 'spend_threshold' === $channel || 'anomaly' === $channel || 'forecast_warn' === $channel ) {
				continue;
			}

			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				continue;
			}
			$row_dt = ( new \DateTimeImmutable( '@' . $ts ) )->setTimezone( $tz );
			if ( $row_dt->format( 'Y-m' ) !== $period_ym ) {
				continue;
			}

			$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
			$out = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
			if ( null === $in && null === $out ) {
				continue;
			}
			$rates = Cost::rates_from_policy( $policy, isset( $row['provider'] ) ? (string) $row['provider'] : null );
			$usd   = Cost::estimate_usd( $in, $out, $rates );
			if ( null === $usd ) {
				continue;
			}

			$day = $row_dt->format( 'Y-m-d' );
			$active_days[ $day ] = true;

			$mtd_site += $usd;
			$p         = isset( $row['plugin'] ) && is_string( $row['plugin'] ) ? (string) $row['plugin'] : '';
			if ( '' === $p ) {
				$p = Analytics::UNKNOWN_KEY;
			}
			if ( ! isset( $plugin_mtd[ $p ] ) ) {
				$plugin_mtd[ $p ]  = 0.0;
				$plugin_days[ $p ] = array();
			}
			$plugin_mtd[ $p ]         += $usd;
			$plugin_days[ $p ][ $day ] = true;
		}

		$active_count = count( $active_days );
		if ( $active_count < self::MIN_ACTIVE_DAYS || $days_elapsed < 1 ) {
			return null;
		}

		$daily_rate      = $mtd_site / (float) $days_elapsed;
		$projected_site  = $daily_rate * (float) $days_in_month;
		$plugins_out     = array();

		foreach ( $plugin_mtd as $basename => $mtd ) {
			$plugins_out[ $basename ] = array(
				'mtd'         => $mtd,
				'projected'   => ( $mtd / (float) $days_elapsed ) * (float) $days_in_month,
				'active_days' => count( $plugin_days[ $basename ] ?? array() ),
			);
		}

		uasort(
			$plugins_out,
			static function ( array $a, array $b ): int {
				return $b['projected'] <=> $a['projected'];
			}
		);

		$warnings = self::build_warnings( $policy, $projected_site, $plugins_out, $mtd_site );

		return array(
			'period_ym'      => $period_ym,
			'days_elapsed'   => $days_elapsed,
			'days_in_month'  => $days_in_month,
			'days_remaining' => $days_remaining,
			'active_days'    => $active_count,
			'mtd_site'       => $mtd_site,
			'projected_site' => $projected_site,
			'plugins'        => $plugins_out,
			'warnings'       => $warnings,
		);
	}

	/**
	 * Evaluate projection vs configured spend thresholds; email at most once per
	 * calendar month per threshold key when an alert recipient is configured.
	 *
	 * @param array<string,mixed>|null $policy
	 */
	public static function maybe_evaluate( ?array $policy = null, ?int $now = null ): void {
		$policy = is_array( $policy ) ? $policy : Policy::get_policy();
		if ( empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] ) ) {
			return;
		}
		if ( ! Spend_Threshold::has_any_threshold( $policy ) ) {
			return;
		}

		$now      = null !== $now ? $now : time();
		$forecast = self::compute( Policy::get_retained_log(), $policy, $now );
		if ( null === $forecast || empty( $forecast['warnings'] ) ) {
			return;
		}

		$to = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return;
		}

		foreach ( $forecast['warnings'] as $warn ) {
			self::maybe_fire_warning( $policy, $to, $warn, $forecast, $now );
		}
	}

	/**
	 * Active projection warnings for admin UI (no email side effects).
	 *
	 * @param array<string,mixed> $policy
	 * @return list<array{scope:string,plugin:?string,threshold:float,projected:float,mtd:float}>
	 */
	public static function active_warnings( array $log, array $policy, ?int $now = null ): array {
		$forecast = self::compute( $log, $policy, $now );
		if ( null === $forecast ) {
			return array();
		}

		return $forecast['warnings'];
	}

	/**
	 * @param array<string,mixed>                                                         $policy
	 * @param array<string,array{mtd:float,projected:float,active_days:int}>              $plugins
	 * @return list<array{scope:string,plugin:?string,threshold:float,projected:float,mtd:float}>
	 */
	private static function build_warnings( array $policy, float $projected_site, array $plugins, float $mtd_site ): array {
		$out = array();

		$site_threshold = Spend_Threshold::sanitize_threshold( $policy['spend_threshold_site'] ?? null );
		if ( null !== $site_threshold && $projected_site >= $site_threshold ) {
			$out[] = array(
				'scope'      => 'site',
				'plugin'     => null,
				'threshold'  => $site_threshold,
				'projected'  => $projected_site,
				'mtd'        => $mtd_site,
			);
		}

		$plugin_thresholds = Spend_Threshold::sanitize_plugin_thresholds( $policy['spend_threshold_plugins'] ?? array() );
		foreach ( $plugin_thresholds as $basename => $threshold ) {
			if ( ! isset( $plugins[ $basename ] ) ) {
				continue;
			}
			$row = $plugins[ $basename ];
			if ( (float) $row['projected'] < $threshold ) {
				continue;
			}
			$out[] = array(
				'scope'      => 'plugin',
				'plugin'     => $basename,
				'threshold'  => $threshold,
				'projected'  => (float) $row['projected'],
				'mtd'        => (float) $row['mtd'],
			);
		}

		return $out;
	}

	/**
	 * @param array<string,mixed>                                                          $policy
	 * @param array{scope:string,plugin:?string,threshold:float,projected:float,mtd:float} $warn
	 * @param array<string,mixed>                                                          $forecast
	 */
	private static function maybe_fire_warning( array $policy, string $to, array $warn, array $forecast, int $now ): void {
		$key = 'site' === $warn['scope']
			? 'site'
			: ( 'plugin:' . (string) $warn['plugin'] );

		$period_ym = (string) $forecast['period_ym'];
		$threshold = (float) $warn['threshold'];
		if ( self::already_warned( $key, $period_ym, $threshold ) ) {
			return;
		}

		$subject = self::build_subject( $warn );
		$body    = self::build_body( $warn, $forecast );
		$ok      = self::safe_wp_mail( $to, $subject, $body );
		if ( ! $ok ) {
			return;
		}

		self::record_warning( $key, $period_ym, $threshold, $now );
		self::append_audit_row( $warn, $forecast );
	}

	/**
	 * @param array{scope:string,plugin:?string,threshold:float,projected:float,mtd:float} $warn
	 */
	public static function build_subject( array $warn ): string {
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		if ( 'plugin' === $warn['scope'] ) {
			return sprintf(
				/* translators: 1: site name, 2: plugin label, 3: threshold USD */
				__( '[%1$s] HandL spend forecast: %2$s may cross $%3$s this month', 'handl-ai-connector-access-control' ),
				$site,
				self::plugin_label( (string) $warn['plugin'] ),
				Spend_Threshold::format_amount( (float) $warn['threshold'] )
			);
		}

		return sprintf(
			/* translators: 1: site name, 2: threshold USD */
			__( '[%1$s] HandL spend forecast: Site estimate may cross $%2$s this month', 'handl-ai-connector-access-control' ),
			$site,
			Spend_Threshold::format_amount( (float) $warn['threshold'] )
		);
	}

	/**
	 * @param array{scope:string,plugin:?string,threshold:float,projected:float,mtd:float} $warn
	 * @param array<string,mixed>                                                          $forecast
	 */
	public static function build_body( array $warn, array $forecast ): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control spend forecast warning', 'handl-ai-connector-access-control' );
		$lines[] = '';

		if ( 'plugin' === $warn['scope'] ) {
			$lines[] = sprintf(
				/* translators: %s: plugin display name or basename */
				__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
				self::plugin_label( (string) $warn['plugin'] )
			);
		} else {
			$lines[] = __( 'Scope: Site-wide estimate', 'handl-ai-connector-access-control' );
		}

		$lines[] = sprintf(
			/* translators: %s: threshold amount */
			__( 'Alert threshold: $%s', 'handl-ai-connector-access-control' ),
			Spend_Threshold::format_amount( (float) $warn['threshold'] )
		);
		$lines[] = sprintf(
			/* translators: %s: month-to-date estimated spend */
			__( 'Estimated spend so far this month: $%s', 'handl-ai-connector-access-control' ),
			Spend_Threshold::format_amount( (float) $warn['mtd'] )
		);
		$lines[] = sprintf(
			/* translators: %s: projected month-end estimated spend */
			__( 'Estimated month-end (current run rate): $%s', 'handl-ai-connector-access-control' ),
			Spend_Threshold::format_amount( (float) $warn['projected'] )
		);
		$lines[] = sprintf(
			/* translators: 1: days elapsed, 2: days in month */
			__( 'Based on %1$d of %2$d days this month.', 'handl-ai-connector-access-control' ),
			(int) $forecast['days_elapsed'],
			(int) $forecast['days_in_month']
		);
		$lines[] = '';
		$lines[] = __( 'This projection uses logged token usage and your rate table. It is an estimate, not a bill, and does not block AI Client calls.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = __( 'Open the Dashboard:', 'handl-ai-connector-access-control' );
		$lines[] = admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=dashboard' );

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Plain-language admin notice line for one warning.
	 *
	 * @param array{scope:string,plugin:?string,threshold:float,projected:float,mtd:float} $warn
	 */
	public static function notice_text( array $warn ): string {
		if ( 'plugin' === $warn['scope'] ) {
			return sprintf(
				/* translators: 1: plugin label, 2: projected USD, 3: threshold USD */
				__( 'At the current rate, estimated spend for %1$s may reach about $%2$s by month end, above your $%3$s alert threshold. This is an estimate, not a bill.', 'handl-ai-connector-access-control' ),
				self::plugin_label( (string) $warn['plugin'] ),
				Spend_Threshold::format_amount( (float) $warn['projected'] ),
				Spend_Threshold::format_amount( (float) $warn['threshold'] )
			);
		}

		return sprintf(
			/* translators: 1: projected USD, 2: threshold USD */
			__( 'At the current rate, estimated site spend may reach about $%1$s by month end, above your $%2$s alert threshold. This is an estimate, not a bill.', 'handl-ai-connector-access-control' ),
			Spend_Threshold::format_amount( (float) $warn['projected'] ),
			Spend_Threshold::format_amount( (float) $warn['threshold'] )
		);
	}

	private static function already_warned( string $key, string $period_ym, float $threshold ): bool {
		$state = get_option( self::WARNED_OPTION_KEY, array() );
		if ( ! is_array( $state ) || ! isset( $state[ $key ] ) || ! is_array( $state[ $key ] ) ) {
			return false;
		}
		$row = $state[ $key ];
		$ym  = isset( $row['period'] ) ? (string) $row['period'] : '';
		$th  = isset( $row['threshold'] ) ? (float) $row['threshold'] : 0.0;
		if ( $ym !== $period_ym ) {
			return false;
		}
		if ( abs( $th - $threshold ) >= 0.0001 ) {
			return false;
		}

		return true;
	}

	private static function record_warning( string $key, string $period_ym, float $threshold, int $now ): void {
		$state = get_option( self::WARNED_OPTION_KEY, array() );
		if ( ! is_array( $state ) ) {
			$state = array();
		}
		$state[ $key ] = array(
			'period'    => $period_ym,
			'threshold' => $threshold,
			'at'        => $now,
		);
		update_option( self::WARNED_OPTION_KEY, $state, false );
	}

	/**
	 * @param array{scope:string,plugin:?string,threshold:float,projected:float,mtd:float} $warn
	 * @param array<string,mixed>                                                          $forecast
	 */
	private static function append_audit_row( array $warn, array $forecast ): void {
		$event = array(
			'ts'           => time(),
			'decision'     => 'forecast_warn',
			'channel'      => 'forecast_warn',
			'threshold'    => (float) $warn['threshold'],
			'est_usd'      => (float) $warn['projected'],
			'mtd_usd'      => (float) $warn['mtd'],
			'period_ym'    => (string) $forecast['period_ym'],
			'scope'        => (string) $warn['scope'],
		);
		if ( 'plugin' === $warn['scope'] && is_string( $warn['plugin'] ) && '' !== $warn['plugin'] ) {
			$event['plugin'] = $warn['plugin'];
		}
		Policy::append_log_event( $event );
	}

	private static function plugin_label( string $basename ): string {
		if ( '' === $basename || Analytics::UNKNOWN_KEY === $basename ) {
			return __( '(unknown plugin)', 'handl-ai-connector-access-control' );
		}
		if ( ! function_exists( 'get_plugins' ) ) {
			$plugin_php = ABSPATH . 'wp-admin/includes/plugin.php';
			if ( is_string( $plugin_php ) && is_readable( $plugin_php ) ) {
				require_once $plugin_php;
			}
		}
		if ( function_exists( 'get_plugins' ) ) {
			$plugins = get_plugins();
			if ( isset( $plugins[ $basename ]['Name'] ) && is_string( $plugins[ $basename ]['Name'] ) ) {
				return (string) $plugins[ $basename ]['Name'];
			}
		}

		return $basename;
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

	private static function safe_wp_mail( string $to, string $subject, string $body ): bool {
		try {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.wp_mail -- intentional notification path.
			return (bool) wp_mail( $to, $subject, $body );
		} catch ( \Throwable $e ) {
			return false;
		}
	}
}
