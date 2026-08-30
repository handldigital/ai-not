<?php
/**
 * AICAC-RETRY-STORM (#240): collapse deny retry loops so blocked plugins cannot
 * flood Activity rows and denial alerts.
 *
 * Observability only — never changes allow/deny. Default ON at conservative
 * values (30s window, threshold 5). Off-switch restores per-deny rows/alerts.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Per plugin + capability/operation family: after threshold denies in the window,
 * subsequent denies merge into one storm row and skip per-deny emails. One storm
 * alert per plugin per hour.
 */
final class Retry_Storm {

	public const STATE_OPTION_KEY = 'handl_aicac_retry_storm_state';

	public const DEFAULT_WINDOW_SECONDS = 30;

	public const DEFAULT_THRESHOLD = 5;

	public const ALERT_COOLDOWN_SECONDS = 3600;

	public const MIN_WINDOW_SECONDS = 5;

	public const MAX_WINDOW_SECONDS = 600;

	public const MIN_THRESHOLD = 2;

	public const MAX_THRESHOLD = 100;

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_window_seconds( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_WINDOW_SECONDS;
		}
		$n = (int) $raw;
		if ( $n < self::MIN_WINDOW_SECONDS ) {
			return self::MIN_WINDOW_SECONDS;
		}
		if ( $n > self::MAX_WINDOW_SECONDS ) {
			return self::MAX_WINDOW_SECONDS;
		}

		return $n;
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_threshold( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_THRESHOLD;
		}
		$n = (int) $raw;
		if ( $n < self::MIN_THRESHOLD ) {
			return self::MIN_THRESHOLD;
		}
		if ( $n > self::MAX_THRESHOLD ) {
			return self::MAX_THRESHOLD;
		}

		return $n;
	}

	/**
	 * Default ON when the key is absent.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function is_enabled( array $policy ): bool {
		return (bool) ( $policy['retry_storm_enabled'] ?? true );
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array<string,mixed>
	 */
	public static function normalize_policy( array $policy ): array {
		$policy['retry_storm_enabled']        = self::is_enabled( $policy );
		$policy['retry_storm_window_seconds'] = self::sanitize_window_seconds(
			$policy['retry_storm_window_seconds'] ?? self::DEFAULT_WINDOW_SECONDS
		);
		$policy['retry_storm_threshold']      = self::sanitize_threshold(
			$policy['retry_storm_threshold'] ?? self::DEFAULT_THRESHOLD
		);

		return $policy;
	}

	/**
	 * Operation family for bucketing (capability_family preferred).
	 *
	 * @param array<string,mixed> $event
	 */
	public static function operation_family( array $event ): string {
		$family = isset( $event['capability_family'] ) ? sanitize_key( (string) $event['capability_family'] ) : '';
		if ( '' !== $family ) {
			return $family;
		}
		$operation = isset( $event['operation'] ) ? (string) $event['operation'] : '';
		if ( '' !== $operation && class_exists( Operations::class ) ) {
			$family = sanitize_key( Operations::family_from_operation( $operation ) );
			if ( '' !== $family ) {
				return $family;
			}
		}
		$operation_key = sanitize_key( $operation );

		return '' !== $operation_key ? $operation_key : 'unknown';
	}

	/**
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 */
	public static function should_suppress_deny_alert( array $event, array $policy ): bool {
		if ( ! self::is_enabled( $policy ) ) {
			return false;
		}
		if ( ( $event['decision'] ?? '' ) !== 'deny' ) {
			return false;
		}
		if ( ! empty( $event['retry_storm_collapsed'] ) || ! empty( $event['retry_storm'] ) ) {
			return true;
		}

		$plugin = isset( $event['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $event['plugin'] ) : '';
		if ( '' === $plugin ) {
			return false;
		}
		$family = self::operation_family( $event );
		$key    = self::bucket_key( $plugin, $family );
		$state  = self::get_state();
		$bucket = isset( $state['buckets'][ $key ] ) && is_array( $state['buckets'][ $key ] )
			? $state['buckets'][ $key ]
			: array();

		return ! empty( $bucket['storm'] );
	}

	/**
	 * Process a deny before it is appended to the Activity ring buffer.
	 *
	 * @param array<int,mixed>    $log    Retained log (mutated on collapse).
	 * @param array<string,mixed> $event  Incoming deny row (may be tagged).
	 * @param array<string,mixed> $policy Current policy.
	 * @return 'pass'|'threshold'|'collapse'|'skip'
	 */
	public static function process_deny( array &$log, array &$event, array $policy ): string {
		if ( ! self::is_enabled( $policy ) ) {
			return 'skip';
		}
		if ( ( $event['decision'] ?? '' ) !== 'deny' ) {
			return 'skip';
		}
		$channel = isset( $event['channel'] ) ? (string) $event['channel'] : '';
		if ( in_array( $channel, array( 'direct_http', 'anomaly', 'spend_threshold', 'drift', 'budget', 'selftest', 'pii', 'retry_storm' ), true ) ) {
			return 'skip';
		}
		if ( class_exists( Selftest::class ) && Selftest::is_synthetic_row( $event ) ) {
			return 'skip';
		}

		$plugin = isset( $event['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $event['plugin'] ) : '';
		if ( '' === $plugin || ( class_exists( Analytics::class ) && Analytics::UNKNOWN_KEY === $plugin ) ) {
			return 'skip';
		}

		$family    = self::operation_family( $event );
		$key       = self::bucket_key( $plugin, $family );
		$now       = isset( $event['ts'] ) ? (int) $event['ts'] : time();
		if ( $now <= 0 ) {
			$now = time();
		}
		$window    = self::sanitize_window_seconds( $policy['retry_storm_window_seconds'] ?? self::DEFAULT_WINDOW_SECONDS );
		$threshold = self::sanitize_threshold( $policy['retry_storm_threshold'] ?? self::DEFAULT_THRESHOLD );

		$state  = self::get_state();
		$bucket = isset( $state['buckets'][ $key ] ) && is_array( $state['buckets'][ $key ] )
			? $state['buckets'][ $key ]
			: array();

		$window_start = isset( $bucket['window_start'] ) ? (int) $bucket['window_start'] : 0;
		$count        = isset( $bucket['count'] ) ? (int) $bucket['count'] : 0;
		$storm        = ! empty( $bucket['storm'] );
		$log_key      = isset( $bucket['log_key'] ) ? (string) $bucket['log_key'] : '';

		if ( $window_start <= 0 || ( $now - $window_start ) > $window ) {
			$window_start = $now;
			$count        = 0;
			$storm        = false;
			$log_key      = '';
		}

		++$count;

		if ( $storm && '' !== $log_key && self::collapse_into_log( $log, $log_key, $now ) ) {
			$event['retry_storm_collapsed'] = true;
			$state['buckets'][ $key ]       = array(
				'window_start' => $window_start,
				'count'        => $count,
				'storm'        => true,
				'log_key'      => $log_key,
				'plugin'       => $plugin,
				'family'       => $family,
			);
			self::save_state( $state );
			return 'collapse';
		}

		if ( $count < $threshold ) {
			$state['buckets'][ $key ] = array(
				'window_start' => $window_start,
				'count'        => $count,
				'storm'        => false,
				'log_key'      => '',
				'plugin'       => $plugin,
				'family'       => $family,
			);
			self::save_state( $state );
			return 'pass';
		}

		// Threshold hit (or storm row was evicted): emit one storm marker row.
		if ( empty( $event['log_key'] ) || ! is_string( $event['log_key'] ) ) {
			$event['log_key'] = self::generate_log_key();
		}
		$event['retry_storm'] = true;
		$event['count']       = 1;
		if ( ! isset( $event['first_ts'] ) ) {
			$event['first_ts'] = $now;
		}

		$state['buckets'][ $key ] = array(
			'window_start' => $window_start,
			'count'        => $count,
			'storm'        => true,
			'log_key'      => (string) $event['log_key'],
			'plugin'       => $plugin,
			'family'       => $family,
		);
		self::save_state( $state );

		return 'threshold';
	}

	/**
	 * One storm alert per plugin per hour when a threshold row is retained.
	 *
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 */
	public static function maybe_alert( array $event, array $policy ): void {
		if ( empty( $event['retry_storm'] ) ) {
			return;
		}
		if ( ! self::is_enabled( $policy ) ) {
			return;
		}
		if ( empty( $policy['alert_on_deny'] ) ) {
			return;
		}
		if ( ! empty( $policy['audit_only'] ) ) {
			return;
		}

		$plugin = isset( $event['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $event['plugin'] ) : '';
		if ( '' === $plugin ) {
			return;
		}
		$now = isset( $event['ts'] ) ? (int) $event['ts'] : time();
		if ( $now <= 0 ) {
			$now = time();
		}

		if ( class_exists( Alert_Snooze::class ) && Alert_Snooze::should_suppress( $plugin, 'denial', $now ) ) {
			return;
		}

		$state  = self::get_state();
		$alerts = isset( $state['alerts'] ) && is_array( $state['alerts'] ) ? $state['alerts'] : array();
		$last   = isset( $alerts[ $plugin ] ) ? (int) $alerts[ $plugin ] : 0;
		if ( $last > 0 && ( $now - $last ) < self::ALERT_COOLDOWN_SECONDS ) {
			return;
		}

		$to = '';
		if ( class_exists( Alerts::class ) ) {
			$to = Alerts::resolve_email( $policy );
		}
		if ( '' === $to ) {
			return;
		}

		$family = self::operation_family( $event );
		$label  = self::plugin_label( $plugin );
		$site   = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';

		$subject = sprintf(
			/* translators: 1: site name, 2: plugin name */
			__( '[%1$s] HandL: %2$s keeps retrying a blocked AI request', 'handl-ai-connector-access-control' ),
			$site,
			$label
		);

		$lines   = array();
		$lines[] = __( 'HandL AI Access alert', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: plugin display name or basename */
			__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
			$label
		);
		$lines[] = sprintf(
			/* translators: %s: capability / request-type key */
			__( 'Request type: %s', 'handl-ai-connector-access-control' ),
			$family
		);
		$lines[] = __( 'HandL blocked this AI request, but the plugin kept trying again.', 'handl-ai-connector-access-control' );
		$lines[] = __( 'To reduce repeat emails and Activity clutter, HandL groups these retries into one Activity entry for a short time.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: site home URL */
			__( 'Site: %s', 'handl-ai-connector-access-control' ),
			function_exists( 'home_url' ) ? home_url( '/' ) : ''
		);
		$body = implode( "\n", $lines );

		$ok = Alerts::safe_wp_mail( $to, $subject, $body );
		if ( ! $ok ) {
			return;
		}

		$hook_url = Alerts::resolve_webhook( $policy );
		if ( '' !== $hook_url ) {
			Alerts::safe_wp_remote_post(
				$hook_url,
				array(
					'type'              => 'handl_aicac_retry_storm_alert',
					'plugin'            => $plugin,
					'capability_family' => $family,
					'site'              => function_exists( 'home_url' ) ? home_url( '/' ) : '',
				)
			);
		}

		$alerts[ $plugin ] = $now;
		$state['alerts']   = $alerts;
		self::save_state( $state );
	}

	/**
	 * @return array{
	 *   enabled:bool,
	 *   window_seconds:int,
	 *   threshold:int,
	 *   live_storms:list<array{plugin:string,family:string,count:int,window_start:int}>,
	 *   alert_cooldowns:array<string,int>
	 * }
	 */
	public static function status( ?array $policy = null ): array {
		if ( null === $policy ) {
			$policy = class_exists( Policy::class ) ? Policy::get_policy() : array();
		}
		$policy = self::normalize_policy( $policy );
		$state  = self::get_state();
		$now    = time();
		$window = (int) $policy['retry_storm_window_seconds'];
		$live   = array();

		$buckets = isset( $state['buckets'] ) && is_array( $state['buckets'] ) ? $state['buckets'] : array();
		foreach ( $buckets as $bucket ) {
			if ( ! is_array( $bucket ) || empty( $bucket['storm'] ) ) {
				continue;
			}
			$start = isset( $bucket['window_start'] ) ? (int) $bucket['window_start'] : 0;
			if ( $start <= 0 || ( $now - $start ) > $window ) {
				continue;
			}
			$live[] = array(
				'plugin'       => (string) ( $bucket['plugin'] ?? '' ),
				'family'       => (string) ( $bucket['family'] ?? '' ),
				'count'        => (int) ( $bucket['count'] ?? 0 ),
				'window_start' => $start,
			);
		}

		$alerts_out = array();
		$alerts     = isset( $state['alerts'] ) && is_array( $state['alerts'] ) ? $state['alerts'] : array();
		foreach ( $alerts as $plugin => $ts ) {
			$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
			$ts     = (int) $ts;
			if ( '' === $plugin || $ts <= 0 ) {
				continue;
			}
			$alerts_out[ $plugin ] = $ts;
		}

		return array(
			'enabled'         => self::is_enabled( $policy ),
			'window_seconds'  => $window,
			'threshold'       => (int) $policy['retry_storm_threshold'],
			'live_storms'     => $live,
			'alert_cooldowns' => $alerts_out,
		);
	}

	/**
	 * @param array{enabled?:bool,window_seconds?:int,threshold?:int} $changes
	 * @return array<string,mixed>
	 */
	public static function apply_settings( array $changes ): array {
		$raw = get_option( Plugin::OPTION_KEY, array() );
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}
		if ( array_key_exists( 'enabled', $changes ) ) {
			$raw['retry_storm_enabled'] = ! empty( $changes['enabled'] );
		}
		if ( array_key_exists( 'window_seconds', $changes ) ) {
			$raw['retry_storm_window_seconds'] = self::sanitize_window_seconds( $changes['window_seconds'] );
		}
		if ( array_key_exists( 'threshold', $changes ) ) {
			$raw['retry_storm_threshold'] = self::sanitize_threshold( $changes['threshold'] );
		}
		update_option( Plugin::OPTION_KEY, $raw, false );

		return self::status( self::normalize_policy( $raw ) );
	}

	/**
	 * @return array{buckets:array<string,array<string,mixed>>,alerts:array<string,int>}
	 */
	public static function get_state(): array {
		$raw = get_option( self::STATE_OPTION_KEY, array() );
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}
		$buckets = isset( $raw['buckets'] ) && is_array( $raw['buckets'] ) ? $raw['buckets'] : array();
		$alerts  = isset( $raw['alerts'] ) && is_array( $raw['alerts'] ) ? $raw['alerts'] : array();

		return array(
			'buckets' => $buckets,
			'alerts'  => $alerts,
		);
	}

	/**
	 * @param array{buckets?:array<string,array<string,mixed>>,alerts?:array<string,int>} $state
	 */
	public static function save_state( array $state ): void {
		$buckets = isset( $state['buckets'] ) && is_array( $state['buckets'] ) ? $state['buckets'] : array();
		$alerts  = isset( $state['alerts'] ) && is_array( $state['alerts'] ) ? $state['alerts'] : array();
		if ( empty( $buckets ) && empty( $alerts ) ) {
			delete_option( self::STATE_OPTION_KEY );
			return;
		}
		update_option(
			self::STATE_OPTION_KEY,
			array(
				'buckets' => $buckets,
				'alerts'  => $alerts,
			),
			false
		);
	}

	public static function reset_state(): void {
		delete_option( self::STATE_OPTION_KEY );
	}

	public static function bucket_key( string $plugin, string $family ): string {
		return $plugin . '|' . $family;
	}

	/**
	 * @param array<int,mixed> $log
	 */
	private static function collapse_into_log( array &$log, string $log_key, int $now ): bool {
		if ( '' === $log_key ) {
			return false;
		}
		for ( $i = count( $log ) - 1; $i >= 0; $i-- ) {
			if ( ! is_array( $log[ $i ] ) ) {
				continue;
			}
			if ( (string) ( $log[ $i ]['log_key'] ?? '' ) !== $log_key ) {
				continue;
			}
			$row   = $log[ $i ];
			$prior = isset( $row['count'] ) ? (int) $row['count'] : 1;
			if ( $prior < 1 ) {
				$prior = 1;
			}
			$row['count'] = $prior + 1;
			if ( ! isset( $row['first_ts'] ) ) {
				$row_ts = isset( $row['ts'] ) ? (int) $row['ts'] : $now;
				$row['first_ts'] = $row_ts > 0 ? $row_ts : $now;
			}
			$row['ts']          = $now;
			$row['retry_storm'] = true;

			array_splice( $log, $i, 1 );
			$log[] = $row;
			return true;
		}

		return false;
	}

	private static function generate_log_key(): string {
		if ( function_exists( 'wp_generate_uuid4' ) ) {
			return 'aicac_rs_' . wp_generate_uuid4();
		}

		return 'aicac_rs_' . uniqid( '', true );
	}

	private static function plugin_label( string $plugin ): string {
		if ( class_exists( Plugin_Profile::class ) && method_exists( Plugin_Profile::class, 'display_name' ) ) {
			$label = Plugin_Profile::display_name( $plugin );
			if ( is_string( $label ) && '' !== $label ) {
				return $label;
			}
		}

		return $plugin;
	}
}
