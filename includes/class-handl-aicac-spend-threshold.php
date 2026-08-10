<?php
/**
 * S-103: Configurable estimated-spend threshold email alerts (opt-in, off by default).
 *
 * Fires when retained-log estimated $ first crosses a site-wide or per-plugin
 * threshold. Reuses denial-alert recipient and Cost rates. No enforcement.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Estimated-spend threshold alerts (observability only).
 */
final class Spend_Threshold {

	/** Fired-state option: per-key last send metadata for 24h / threshold dedupe. */
	public const FIRED_OPTION_KEY = 'handl_aicac_spend_threshold_fired';

	/** Rolling window (seconds) — no duplicate for same key+threshold within this span. */
	public const DEDUPE_SECONDS = 86400;

	/**
	 * Sanitize a single threshold field. Empty / non-positive → null (off).
	 *
	 * @param mixed $raw
	 */
	public static function sanitize_threshold( $raw ): ?float {
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
		// Hard cap avoids absurd config; still observability-only.
		if ( $v > 1000000 ) {
			$v = 1000000.0;
		}

		return round( $v, 4 );
	}

	/**
	 * @param mixed $raw basename => amount map
	 * @return array<string,float>
	 */
	public static function sanitize_plugin_thresholds( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $basename => $amount ) {
			$basename = sanitize_text_field( (string) $basename );
			if ( '' === $basename ) {
				continue;
			}
			$t = self::sanitize_threshold( $amount );
			if ( null === $t ) {
				continue;
			}
			$out[ $basename ] = $t;
		}

		return $out;
	}

	/**
	 * True when any site or plugin threshold is configured.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function has_any_threshold( array $policy ): bool {
		if ( null !== self::sanitize_threshold( $policy['spend_threshold_site'] ?? null ) ) {
			return true;
		}

		return ! empty( self::sanitize_plugin_thresholds( $policy['spend_threshold_plugins'] ?? array() ) );
	}

	/**
	 * Evaluate retained-log spend against configured thresholds; send emails when crossed.
	 *
	 * Safe to call often: empty thresholds and missing logging exit quickly.
	 * Logging off mid-window stops further evaluation (AC).
	 *
	 * @param array<string,mixed>|null $policy Optional preloaded policy.
	 */
	public static function maybe_evaluate( ?array $policy = null ): void {
		$policy = is_array( $policy ) ? $policy : Policy::get_policy();
		if ( empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] ) ) {
			return;
		}
		if ( ! self::has_any_threshold( $policy ) ) {
			return;
		}

		$log   = Policy::get_retained_log();
		$spend = self::compute_spend_totals( $log, $policy );
		$to    = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return;
		}

		$site_threshold = self::sanitize_threshold( $policy['spend_threshold_site'] ?? null );
		if ( null !== $site_threshold && (float) $spend['site'] >= $site_threshold ) {
			self::maybe_fire(
				$policy,
				$to,
				'site',
				null,
				$site_threshold,
				(float) $spend['site'],
				(string) $spend['window_label']
			);
		}

		$plugin_thresholds = self::sanitize_plugin_thresholds( $policy['spend_threshold_plugins'] ?? array() );
		foreach ( $plugin_thresholds as $basename => $threshold ) {
			$plugin_total = (float) ( $spend['plugins'][ $basename ] ?? 0.0 );
			if ( $plugin_total < $threshold ) {
				// Below threshold again → clear fire state so a later re-cross can alert.
				self::clear_fire_key( 'plugin:' . $basename );
				continue;
			}
			self::maybe_fire(
				$policy,
				$to,
				'plugin',
				$basename,
				$threshold,
				$plugin_total,
				(string) $spend['window_label']
			);
		}

		// Site total dropped back below → allow a later re-cross.
		if ( null !== $site_threshold && (float) $spend['site'] < $site_threshold ) {
			self::clear_fire_key( 'site' );
		}
	}

	/**
	 * Site total + per-plugin totals from retained log (AI Client rows with tokens only).
	 *
	 * @param array<int,mixed>    $log
	 * @param array<string,mixed> $policy
	 * @return array{site:float,plugins:array<string,float>,window_label:string,min_ts:int,max_ts:int}
	 */
	public static function compute_spend_totals( array $log, array $policy ): array {
		$site    = 0.0;
		$plugins = array();
		$min_ts  = 0;
		$max_ts  = 0;

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'] ) {
				continue;
			}
			// Skip our own alert audit rows if present.
			if ( isset( $row['channel'] ) && 'spend_threshold' === (string) $row['channel'] ) {
				continue;
			}

			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts > 0 ) {
				if ( 0 === $min_ts || $ts < $min_ts ) {
					$min_ts = $ts;
				}
				if ( $ts > $max_ts ) {
					$max_ts = $ts;
				}
			}

			$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
			$out = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
			// Only count rows that actually carry token usage.
			if ( null === $in && null === $out ) {
				continue;
			}
			$rates = Cost::rates_from_policy( $policy, isset( $row['provider'] ) ? (string) $row['provider'] : null );
			$usd   = Cost::estimate_usd( $in, $out, $rates );
			if ( null === $usd ) {
				continue;
			}
			$site += $usd;
			$p     = isset( $row['plugin'] ) && is_string( $row['plugin'] ) ? (string) $row['plugin'] : '';
			if ( '' === $p ) {
				$p = Analytics::UNKNOWN_KEY;
			}
			if ( ! isset( $plugins[ $p ] ) ) {
				$plugins[ $p ] = 0.0;
			}
			$plugins[ $p ] += $usd;
		}

		return array(
			'site'         => $site,
			'plugins'      => $plugins,
			'window_label' => Weekly_Report::format_window_label( $min_ts, $max_ts ),
			'min_ts'       => $min_ts,
			'max_ts'       => $max_ts,
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param 'site'|'plugin'     $scope
	 */
	private static function maybe_fire(
		array $policy,
		string $to,
		string $scope,
		?string $plugin_basename,
		float $threshold,
		float $current_total,
		string $window_label
	): void {
		$key = 'site' === $scope ? 'site' : ( 'plugin:' . (string) $plugin_basename );
		if ( self::is_deduped( $key, $threshold ) ) {
			return;
		}

		$subject = self::build_subject( $scope, $plugin_basename, $threshold, $current_total );
		$body    = self::build_body( $scope, $plugin_basename, $threshold, $current_total, $window_label );
		$ok      = self::safe_wp_mail( $to, $subject, $body );
		if ( ! $ok ) {
			// Contained failure — do not mark fired so a later attempt can retry.
			return;
		}

		self::record_fire( $key, $threshold );
		self::append_audit_row( $scope, $plugin_basename, $threshold, $current_total, $window_label );
	}

	/**
	 * @param 'site'|'plugin' $scope
	 */
	public static function build_subject( string $scope, ?string $plugin_basename, float $threshold, float $current_total ): string {
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		if ( 'plugin' === $scope ) {
			$label = self::plugin_label( (string) $plugin_basename );

			return sprintf(
				/* translators: 1: site name, 2: plugin name, 3: threshold USD */
				__( '[%1$s] HandL estimated spend alert: %2$s crossed $%3$s', 'handl-ai-connector-access-control' ),
				$site,
				$label,
				self::format_amount( $threshold )
			);
		}

		return sprintf(
			/* translators: 1: site name, 2: threshold USD */
			__( '[%1$s] HandL estimated spend alert: site total crossed $%2$s', 'handl-ai-connector-access-control' ),
			$site,
			self::format_amount( $threshold )
		);
	}

	/**
	 * @param 'site'|'plugin' $scope
	 */
	public static function build_body(
		string $scope,
		?string $plugin_basename,
		float $threshold,
		float $current_total,
		string $window_label
	): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control estimated spend alert', 'handl-ai-connector-access-control' );
		$lines[] = '';

		if ( 'plugin' === $scope ) {
			$lines[] = sprintf(
				/* translators: %s: plugin display name or basename */
				__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
				self::plugin_label( (string) $plugin_basename )
			);
		} else {
			$lines[] = __( 'Scope: site-wide estimated total', 'handl-ai-connector-access-control' );
		}

		$lines[] = sprintf(
			/* translators: %s: threshold amount with $ */
			__( 'Threshold: $%s', 'handl-ai-connector-access-control' ),
			self::format_amount( $threshold )
		);
		$lines[] = sprintf(
			/* translators: %s: current estimated total with $ */
			__( 'Current estimated total: $%s', 'handl-ai-connector-access-control' ),
			self::format_amount( $current_total )
		);
		$lines[] = sprintf(
			/* translators: %s: dated retained-log window label */
			__( 'Log window: %s', 'handl-ai-connector-access-control' ),
			$window_label
		);
		$lines[] = '';
		$lines[] = __( 'This amount is estimated (token × rate placeholder), not billing. It does not block AI Client calls.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = __( 'Manage estimated spend alerts:', 'handl-ai-connector-access-control' );
		$lines[] = admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=activity' );

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Public format helper for tests.
	 */
	public static function format_amount( float $amount ): string {
		if ( $amount > 0 && $amount < 0.01 ) {
			return '0.01';
		}

		return function_exists( 'number_format_i18n' )
			? number_format_i18n( $amount, 2 )
			: number_format( $amount, 2, '.', '' );
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

	private static function is_deduped( string $key, float $threshold ): bool {
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
		// Threshold change → allow a fresh alert.
		if ( abs( $th - $threshold ) >= 0.0001 ) {
			return false;
		}
		// Rolling 24h dedupe for same key+threshold.
		return ( time() - $at ) < self::DEDUPE_SECONDS;
	}

	private static function record_fire( string $key, float $threshold ): void {
		$state = get_option( self::FIRED_OPTION_KEY, array() );
		if ( ! is_array( $state ) ) {
			$state = array();
		}
		$state[ $key ] = array(
			'at'        => time(),
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
	 * @param 'site'|'plugin' $scope
	 */
	private static function append_audit_row(
		string $scope,
		?string $plugin_basename,
		float $threshold,
		float $current_total,
		string $window_label
	): void {
		$event = array(
			'ts'           => time(),
			'decision'     => 'spend_alert',
			'channel'      => 'spend_threshold',
			'threshold'    => $threshold,
			'est_usd'      => $current_total,
			'window_label' => $window_label,
			'scope'        => $scope,
		);
		if ( 'plugin' === $scope && is_string( $plugin_basename ) && '' !== $plugin_basename ) {
			$event['plugin'] = $plugin_basename;
		}
		// Direct write path — do not re-enter evaluate from here.
		Policy::append_log_event( $event );
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
