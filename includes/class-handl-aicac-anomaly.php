<?php
/**
 * AICAC-ANOMALY: per-plugin baseline-deviation alerts for call volume and spend.
 *
 * Opt-in (default off). Compares today's AI Client activity to a trailing 7-day
 * daily mean from the retained log. Reuses denial-alert recipient + optional
 * webhook; 24h per-plugin per-metric dedupe (same idea as spend thresholds).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Anomaly {

	public const FIRED_OPTION_KEY = 'handl_aicac_anomaly_fired';

	public const DEDUPE_SECONDS = 86400;

	/** Trailing calendar days used for the baseline mean (excludes today). */
	public const BASELINE_DAYS = 7;

	public const DEFAULT_MULTIPLIER = 3.0;

	public const DEFAULT_FLOOR_CALLS = 20;

	public const DEFAULT_FLOOR_SPEND = 1.0;

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_multiplier( $raw ): float {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_MULTIPLIER;
		}
		$v = (float) $raw;
		if ( $v < 1.5 ) {
			return 1.5;
		}
		if ( $v > 50 ) {
			return 50.0;
		}

		return round( $v, 2 );
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_floor_calls( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_FLOOR_CALLS;
		}
		$n = (int) $raw;
		if ( $n < 1 ) {
			return 1;
		}
		if ( $n > 100000 ) {
			return 100000;
		}

		return $n;
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_floor_spend( $raw ): float {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_FLOOR_SPEND;
		}
		$v = (float) $raw;
		if ( $v < 0.01 ) {
			return 0.01;
		}
		if ( $v > 1000000 ) {
			return 1000000.0;
		}

		return round( $v, 4 );
	}

	/**
	 * Whether evaluation may run (policy + logging + retention depth).
	 *
	 * @param array<string,mixed> $policy
	 * @return array{ok:bool,reason:string}
	 */
	public static function readiness( array $policy ): array {
		if ( empty( $policy['anomaly_alert_enabled'] ) ) {
			return array(
				'ok'     => false,
				'reason' => 'disabled',
			);
		}
		if ( empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] ) ) {
			return array(
				'ok'     => false,
				'reason' => 'logging_off',
			);
		}
		$max_age = Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null );
		if ( null !== $max_age && $max_age < self::BASELINE_DAYS ) {
			return array(
				'ok'     => false,
				'reason' => 'ttl_too_short',
			);
		}

		return array(
			'ok'     => true,
			'reason' => '',
		);
	}

	/**
	 * Plain-language admin notice for degraded states (never silent).
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function degradation_notice( array $policy ): string {
		$ready = self::readiness( $policy );
		if ( $ready['ok'] ) {
			return '';
		}
		if ( 'disabled' === $ready['reason'] ) {
			return '';
		}
		if ( 'logging_off' === $ready['reason'] ) {
			return __(
				'Usage spike alerts are paused because activity logging and Learn mode are off. Turn on either one, or turn off spike alerts. No alerts will be sent.',
				'handl-ai-connector-access-control'
			);
		}
		if ( 'ttl_too_short' === $ready['reason'] ) {
			return sprintf(
				/* translators: %d: required baseline days */
				__(
					'Usage spike alerts need at least %d days of saved activity. Increase the activity time limit or turn off spike alerts. No alerts will be sent until the time limit is long enough.',
					'handl-ai-connector-access-control'
				),
				self::BASELINE_DAYS
			);
		}

		return '';
	}

	/**
	 * @param array<string,mixed>|null $policy
	 * @param int|null                 $now Injectable unix time for tests.
	 */
	public static function maybe_evaluate( ?array $policy = null, ?int $now = null ): void {
		$policy = is_array( $policy ) ? $policy : Policy::get_policy();
		$ready  = self::readiness( $policy );
		if ( ! $ready['ok'] ) {
			return;
		}

		$now = null !== $now ? $now : time();
		$to  = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return;
		}

		$log     = Policy::get_retained_log( $now );
		$buckets = self::build_daily_buckets( $log, $policy, $now );
		$cfg     = self::config_from_policy( $policy );

		foreach ( $buckets as $plugin => $series ) {
			self::evaluate_plugin_metric(
				$policy,
				$to,
				$plugin,
				'calls',
				$series,
				$cfg,
				$now
			);
			self::evaluate_plugin_metric(
				$policy,
				$to,
				$plugin,
				'spend',
				$series,
				$cfg,
				$now
			);
		}
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array{multiplier:float,floor_calls:int,floor_spend:float}
	 */
	public static function config_from_policy( array $policy ): array {
		return array(
			'multiplier'  => self::sanitize_multiplier( $policy['anomaly_multiplier'] ?? self::DEFAULT_MULTIPLIER ),
			'floor_calls' => self::sanitize_floor_calls( $policy['anomaly_floor_calls'] ?? self::DEFAULT_FLOOR_CALLS ),
			'floor_spend' => self::sanitize_floor_spend( $policy['anomaly_floor_spend'] ?? self::DEFAULT_FLOOR_SPEND ),
		);
	}

	/**
	 * Pure decision for one metric.
	 *
	 * @param list<float|int> $baseline_daily Values for the 7 days before today (oldest first).
	 * @return array{
	 *   alert:bool,
	 *   cold_start:bool,
	 *   baseline:float,
	 *   observed:float,
	 *   threshold:float
	 * }
	 */
	public static function decide_spike(
		array $baseline_daily,
		float $observed_today,
		float $multiplier,
		float $floor
	): array {
		$has_history = false;
		$sum         = 0.0;
		foreach ( $baseline_daily as $v ) {
			$sum += (float) $v;
			if ( (float) $v > 0 ) {
				$has_history = true;
			}
		}

		if ( ! $has_history ) {
			return array(
				'alert'      => false,
				'cold_start' => true,
				'baseline'   => 0.0,
				'observed'   => $observed_today,
				'threshold'  => $floor,
			);
		}

		$n        = count( $baseline_daily );
		$baseline = $n > 0 ? ( $sum / $n ) : 0.0;
		$threshold = max( $baseline * $multiplier, $floor );
		$alert     = $observed_today >= $threshold && $observed_today > 0;

		return array(
			'alert'      => $alert,
			'cold_start' => false,
			'baseline'   => $baseline,
			'observed'   => $observed_today,
			'threshold'  => $threshold,
		);
	}

	/**
	 * @param array<int,mixed>    $log
	 * @param array<string,mixed> $policy
	 * @return array<string,array{days:array<string,array{calls:int,spend:float}>,today:string,baseline_keys:list<string>}>
	 */
	public static function build_daily_buckets( array $log, array $policy, int $now ): array {
		$tz      = function_exists( 'wp_timezone' ) ? wp_timezone() : new \DateTimeZone( 'UTC' );
		$today_dt = ( new \DateTimeImmutable( '@' . $now ) )->setTimezone( $tz )->setTime( 0, 0, 0 );
		$today    = $today_dt->format( 'Y-m-d' );

		$baseline_keys = array();
		for ( $i = self::BASELINE_DAYS; $i >= 1; $i-- ) {
			$baseline_keys[] = $today_dt->modify( '-' . $i . ' day' )->format( 'Y-m-d' );
		}

		/** @var array<string,array<string,array{calls:int,spend:float}>> $by_plugin */
		$by_plugin = array();

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$channel = isset( $row['channel'] ) ? (string) $row['channel'] : '';
			if ( 'direct_http' === $channel || 'spend_threshold' === $channel || 'anomaly' === $channel ) {
				continue;
			}

			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				continue;
			}
			$day = ( new \DateTimeImmutable( '@' . $ts ) )->setTimezone( $tz )->format( 'Y-m-d' );
			// Only keep today + baseline window.
			if ( $day !== $today && ! in_array( $day, $baseline_keys, true ) ) {
				continue;
			}

			$plugin = isset( $row['plugin'] ) && is_string( $row['plugin'] ) ? (string) $row['plugin'] : '';
			if ( '' === $plugin ) {
				$plugin = Analytics::UNKNOWN_KEY;
			}

			if ( ! isset( $by_plugin[ $plugin ] ) ) {
				$by_plugin[ $plugin ] = array();
			}
			if ( ! isset( $by_plugin[ $plugin ][ $day ] ) ) {
				$by_plugin[ $plugin ][ $day ] = array(
					'calls' => 0,
					'spend' => 0.0,
				);
			}
			++$by_plugin[ $plugin ][ $day ]['calls'];

			$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
			$out = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
			if ( null !== $in || null !== $out ) {
				$rates = Cost::rates_from_policy( $policy, isset( $row['provider'] ) ? (string) $row['provider'] : null );
				$usd   = Cost::estimate_usd( $in, $out, $rates );
				if ( null !== $usd ) {
					$by_plugin[ $plugin ][ $day ]['spend'] += $usd;
				}
			}
		}

		$out = array();
		foreach ( $by_plugin as $plugin => $days ) {
			$out[ $plugin ] = array(
				'days'          => $days,
				'today'         => $today,
				'baseline_keys' => $baseline_keys,
			);
		}

		return $out;
	}

	/**
	 * Activity tab URL filtered to a plugin basename.
	 */
	public static function activity_url_for_plugin( string $plugin_basename ): string {
		$args = array(
			'page'                 => 'handl-ai-connector-access-control',
			'handl_aicac_tab'      => 'activity',
			'handl_aicac_log_plugin' => $plugin_basename,
		);

		return admin_url( 'options-general.php?' . http_build_query( $args ) );
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param array{days:array<string,array{calls:int,spend:float}>,today:string,baseline_keys:list<string>} $series
	 * @param array{multiplier:float,floor_calls:int,floor_spend:float} $cfg
	 * @param 'calls'|'spend' $metric
	 */
	private static function evaluate_plugin_metric(
		array $policy,
		string $to,
		string $plugin,
		string $metric,
		array $series,
		array $cfg,
		int $now
	): void {
		$baseline_daily = array();
		foreach ( $series['baseline_keys'] as $day ) {
			$cell = $series['days'][ $day ] ?? array( 'calls' => 0, 'spend' => 0.0 );
			$baseline_daily[] = 'calls' === $metric
				? (int) $cell['calls']
				: (float) $cell['spend'];
		}

		$today_cell = $series['days'][ $series['today'] ] ?? array( 'calls' => 0, 'spend' => 0.0 );
		$observed   = 'calls' === $metric
			? (float) $today_cell['calls']
			: (float) $today_cell['spend'];
		$floor = 'calls' === $metric
			? (float) $cfg['floor_calls']
			: (float) $cfg['floor_spend'];

		$decision = self::decide_spike( $baseline_daily, $observed, $cfg['multiplier'], $floor );
		if ( ! $decision['alert'] ) {
			if ( ! $decision['cold_start'] && $observed < $decision['threshold'] ) {
				self::clear_fire_key( self::fire_key( $plugin, $metric ) );
			}
			return;
		}

		self::maybe_fire(
			$policy,
			$to,
			$plugin,
			$metric,
			$decision['baseline'],
			$decision['observed'],
			$decision['threshold'],
			$now
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param 'calls'|'spend'     $metric
	 */
	private static function maybe_fire(
		array $policy,
		string $to,
		string $plugin,
		string $metric,
		float $baseline,
		float $observed,
		float $threshold,
		int $now
	): void {
		$key = self::fire_key( $plugin, $metric );
		if ( self::is_deduped( $key, $threshold, $now ) ) {
			return;
		}

		$subject = self::build_subject( $plugin, $metric, $observed, $baseline );
		$body    = self::build_body( $plugin, $metric, $baseline, $observed, $threshold );
		$ok      = self::safe_wp_mail( $to, $subject, $body );

		// Optional webhook when configured (same URL as denial alerts).
		$hook_url = Alerts::resolve_webhook( $policy );
		if ( '' !== $hook_url ) {
			$payload = array(
				'type'       => 'handl_aicac_anomaly_alert',
				'plugin'     => $plugin,
				'metric'     => $metric,
				'baseline'   => $baseline,
				'observed'   => $observed,
				'threshold'  => $threshold,
				'activity'   => self::activity_url_for_plugin( $plugin ),
				'site'       => function_exists( 'home_url' ) ? home_url( '/' ) : '',
			);
			// Contained; failure does not block email mark.
			Alerts::safe_wp_remote_post( $hook_url, $payload );
		}

		if ( ! $ok ) {
			return;
		}

		self::record_fire( $key, $threshold, $now );
		self::append_audit_row( $plugin, $metric, $baseline, $observed, $threshold );
	}

	/**
	 * @param 'calls'|'spend' $metric
	 */
	public static function build_subject( string $plugin, string $metric, float $observed, float $baseline ): string {
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$label = self::plugin_label( $plugin );

		if ( 'spend' === $metric ) {
			return sprintf(
				/* translators: 1: site name, 2: plugin name */
				__( '[%1$s] HandL usage spike: %2$s estimated spend is above its recent average', 'handl-ai-connector-access-control' ),
				$site,
				$label
			);
		}

		return sprintf(
			/* translators: 1: site name, 2: plugin name */
			__( '[%1$s] HandL usage spike: %2$s call volume is above its recent average', 'handl-ai-connector-access-control' ),
			$site,
			$label
		);
	}

	/**
	 * @param 'calls'|'spend' $metric
	 */
	public static function build_body(
		string $plugin,
		string $metric,
		float $baseline,
		float $observed,
		float $threshold
	): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control usage spike alert', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: plugin display name or basename */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			self::plugin_label( $plugin )
		);

		if ( 'spend' === $metric ) {
			$lines[] = sprintf(
				/* translators: %s: USD amount */
				__( '7-day daily average (estimated spend): $%s', 'handl-ai-connector-access-control' ),
				self::format_amount( $baseline )
			);
			$lines[] = sprintf(
				/* translators: %s: USD amount */
				__( 'Today so far (estimated spend): $%s', 'handl-ai-connector-access-control' ),
				self::format_amount( $observed )
			);
			$lines[] = sprintf(
				/* translators: %s: USD amount */
				__( 'Alert threshold: $%s', 'handl-ai-connector-access-control' ),
				self::format_amount( $threshold )
			);
		} else {
			$lines[] = sprintf(
				/* translators: %s: call count */
				__( '7-day daily average (calls): %s', 'handl-ai-connector-access-control' ),
				self::format_calls( $baseline )
			);
			$lines[] = sprintf(
				/* translators: %s: call count */
				__( 'Today so far (calls): %s', 'handl-ai-connector-access-control' ),
				self::format_calls( $observed )
			);
			$lines[] = sprintf(
				/* translators: %s: call count */
				__( 'Alert threshold: %s calls', 'handl-ai-connector-access-control' ),
				self::format_calls( $threshold )
			);
		}

		$lines[] = '';
		$lines[] = __( 'This compares today’s AI Client activity with the daily average for the previous 7 days. Estimated spend is not billing. This alert does not block calls.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = __( 'View this plugin’s activity:', 'handl-ai-connector-access-control' );
		$lines[] = self::activity_url_for_plugin( $plugin );
		$lines[] = '';
		$lines[] = __( 'Manage usage spike alerts:', 'handl-ai-connector-access-control' );
		$lines[] = admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=activity' );

		return implode( "\n", $lines ) . "\n";
	}

	public static function format_amount( float $amount ): string {
		if ( $amount > 0 && $amount < 0.01 ) {
			return '0.01';
		}

		return function_exists( 'number_format_i18n' )
			? number_format_i18n( $amount, 2 )
			: number_format( $amount, 2, '.', '' );
	}

	public static function format_calls( float $n ): string {
		$rounded = round( $n, 1 );
		if ( abs( $rounded - (int) $rounded ) < 0.05 ) {
			return (string) (int) round( $rounded );
		}

		return function_exists( 'number_format_i18n' )
			? number_format_i18n( $rounded, 1 )
			: number_format( $rounded, 1, '.', '' );
	}

	public static function fire_key( string $plugin, string $metric ): string {
		return $metric . ':' . $plugin;
	}

	private static function plugin_label( string $basename ): string {
		if ( '' === $basename || Analytics::UNKNOWN_KEY === $basename ) {
			return __( 'Unknown plugin', 'handl-ai-connector-access-control' );
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

	private static function is_deduped( string $key, float $threshold, int $now ): bool {
		$state = get_option( self::FIRED_OPTION_KEY, array() );
		if ( ! is_array( $state ) || ! isset( $state[ $key ] ) || ! is_array( $state[ $key ] ) ) {
			return false;
		}
		$row = $state[ $key ];
		$at  = isset( $row['at'] ) ? (int) $row['at'] : 0;
		$th  = isset( $row['threshold'] ) ? (float) $row['threshold'] : 0.0;
		if ( $at <= 0 ) {
			return false;
		}
		if ( abs( $th - $threshold ) >= 0.0001 ) {
			return false;
		}

		return ( $now - $at ) < self::DEDUPE_SECONDS;
	}

	private static function record_fire( string $key, float $threshold, int $now ): void {
		$state = get_option( self::FIRED_OPTION_KEY, array() );
		if ( ! is_array( $state ) ) {
			$state = array();
		}
		$state[ $key ] = array(
			'at'        => $now,
			'threshold' => $threshold,
		);
		update_option( self::FIRED_OPTION_KEY, $state, false );
	}

	private static function clear_fire_key( string $key ): void {
		$state = get_option( self::FIRED_OPTION_KEY, array() );
		if ( ! is_array( $state ) || ! isset( $state[ $key ] ) ) {
			return;
		}
		unset( $state[ $key ] );
		update_option( self::FIRED_OPTION_KEY, $state, false );
	}

	/**
	 * @param 'calls'|'spend' $metric
	 */
	private static function append_audit_row(
		string $plugin,
		string $metric,
		float $baseline,
		float $observed,
		float $threshold
	): void {
		Policy::append_log_event(
			array(
				'ts'         => time(),
				'decision'   => 'anomaly_alert',
				'channel'    => 'anomaly',
				'plugin'     => $plugin,
				'metric'     => $metric,
				'baseline'   => $baseline,
				'observed'   => $observed,
				'threshold'  => $threshold,
			)
		);
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
