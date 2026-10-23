<?php
/**
 * AICAC-CIRCUIT-BREAKER (#361): per-provider fail-fast when AI providers degrade.
 *
 * Counts call outcomes via wp_ai_client_after_generate_result (hooks-only).
 * Optional p95 pressure via Latency::provider_stats() (read-only). Trips to OPEN,
 * cools down to HALF-OPEN for one probe, closes on success. Fail-fast deny on
 * wp_ai_client_prevent_prompt at priority 2 (same slot as USER-QUOTA / DORMANT).
 * One transition alert via Alerts::safe_wp_mail. OFF by default. No site-health edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Per-provider circuit breaker.
 */
final class Circuit_Breaker {

	public const REASON = 'circuit_breaker';

	public const SETTINGS_OPTION = 'handl_aicac_circuit_breaker';

	public const STATE_OPTION = 'handl_aicac_circuit_breaker_state';

	public const FIRED_OPTION = 'handl_aicac_circuit_breaker_fired';

	public const FILTER_PRIORITY = 2;

	public const POST_PRESENT = 'handl_aicac_circuit_breaker_present';

	public const POST_ENABLED = 'handl_aicac_circuit_breaker_enabled';

	public const POST_FAILURE_THRESHOLD = 'handl_aicac_circuit_breaker_failure_threshold';

	public const POST_ERROR_RATE = 'handl_aicac_circuit_breaker_error_rate';

	public const POST_WINDOW = 'handl_aicac_circuit_breaker_window';

	public const POST_COOLDOWN = 'handl_aicac_circuit_breaker_cooldown';

	public const POST_USE_LATENCY = 'handl_aicac_circuit_breaker_use_latency';

	public const ACTION_TRIP = 'handl_aicac_circuit_breaker_trip';

	public const ACTION_RESET = 'handl_aicac_circuit_breaker_reset';

	public const STATE_CLOSED = 'closed';

	public const STATE_OPEN = 'open';

	public const STATE_HALF_OPEN = 'half_open';

	public const DEFAULT_FAILURE_THRESHOLD = 5;

	public const DEFAULT_ERROR_RATE_PCT = 0;

	public const DEFAULT_WINDOW_SECONDS = 300;

	public const DEFAULT_COOLDOWN_SECONDS = 60;

	public const ALERT_DEDUPE_SECONDS = 3600;

	public const CHANNEL = 'circuit_breaker';

	/** @var bool */
	private static $registered = false;

	/**
	 * In-flight allowed calls awaiting after_generate_result.
	 *
	 * @var list<array{provider:string,probe:bool}>
	 */
	private static $pending = array();

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_filter( 'wp_ai_client_prevent_prompt', array( self::class, 'maybe_prevent_prompt' ), self::FILTER_PRIORITY, 2 );
		add_action( 'wp_ai_client_after_generate_result', array( self::class, 'maybe_record_outcome' ), 12, 1 );
		add_action( 'handl_aicac_protections_settings', array( self::class, 'render_settings' ) );
		add_filter( 'pre_update_option_' . Plugin::OPTION_KEY, array( self::class, 'capture_settings_on_policy_save' ), 10, 2 );
		add_action( 'admin_post_' . self::ACTION_TRIP, array( self::class, 'handle_trip' ) );
		add_action( 'admin_post_' . self::ACTION_RESET, array( self::class, 'handle_reset' ) );
		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$pending    = array();
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATE_OPTION );
		delete_option( self::FIRED_OPTION );
	}

	/**
	 * @return array{
	 *   enabled:bool,
	 *   failure_threshold:int,
	 *   error_rate_pct:int,
	 *   window_seconds:int,
	 *   cooldown_seconds:int,
	 *   use_latency_p95:bool
	 * }
	 */
	public static function defaults(): array {
		return array(
			'enabled'            => false,
			'failure_threshold'  => self::DEFAULT_FAILURE_THRESHOLD,
			'error_rate_pct'     => self::DEFAULT_ERROR_RATE_PCT,
			'window_seconds'     => self::DEFAULT_WINDOW_SECONDS,
			'cooldown_seconds'   => self::DEFAULT_COOLDOWN_SECONDS,
			'use_latency_p95'    => false,
		);
	}

	/**
	 * @return array{
	 *   enabled:bool,
	 *   failure_threshold:int,
	 *   error_rate_pct:int,
	 *   window_seconds:int,
	 *   cooldown_seconds:int,
	 *   use_latency_p95:bool
	 * }
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{
	 *   enabled:bool,
	 *   failure_threshold:int,
	 *   error_rate_pct:int,
	 *   window_seconds:int,
	 *   cooldown_seconds:int,
	 *   use_latency_p95:bool
	 * }
	 */
	public static function sanitize_settings( $raw ): array {
		$d = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $d;
		}
		$d['enabled']           = ! empty( $raw['enabled'] );
		$d['failure_threshold'] = self::sanitize_int_range( $raw['failure_threshold'] ?? $d['failure_threshold'], 1, 100, self::DEFAULT_FAILURE_THRESHOLD );
		$d['error_rate_pct']    = self::sanitize_int_range( $raw['error_rate_pct'] ?? $d['error_rate_pct'], 0, 100, self::DEFAULT_ERROR_RATE_PCT );
		$d['window_seconds']    = self::sanitize_int_range( $raw['window_seconds'] ?? $d['window_seconds'], 30, 86400, self::DEFAULT_WINDOW_SECONDS );
		$d['cooldown_seconds']  = self::sanitize_int_range( $raw['cooldown_seconds'] ?? $d['cooldown_seconds'], 10, 86400, self::DEFAULT_COOLDOWN_SECONDS );
		$d['use_latency_p95']   = ! empty( $raw['use_latency_p95'] );

		return $d;
	}

	/**
	 * @param mixed $raw Raw.
	 */
	private static function sanitize_int_range( $raw, int $min, int $max, int $fallback ): int {
		if ( ! is_numeric( $raw ) ) {
			return $fallback;
		}
		$n = (int) $raw;
		if ( $n < $min ) {
			return $min;
		}
		if ( $n > $max ) {
			return $max;
		}

		return $n;
	}

	/**
	 * @param array<string,mixed> $settings Settings.
	 */
	public static function save_settings( array $settings ): bool {
		$clean  = self::sanitize_settings( $settings );
		$before = self::get_settings();
		if ( $clean === $before ) {
			return false;
		}
		if ( $clean === self::defaults() ) {
			delete_option( self::SETTINGS_OPTION );

			return true;
		}
		update_option( self::SETTINGS_OPTION, $clean, false );

		return true;
	}

	public static function is_enabled(): bool {
		return ! empty( self::get_settings()['enabled'] );
	}

	/**
	 * @return array<string,array<string,mixed>>
	 */
	public static function get_state_map(): array {
		return self::sanitize_state_map( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw map.
	 * @return array<string,array<string,mixed>>
	 */
	public static function sanitize_state_map( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $provider => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$id = class_exists( Latency::class, false )
				? Latency::sanitize_provider( (string) $provider )
				: strtolower( preg_replace( '/[^a-z0-9_\-\.]/', '', (string) $provider ) ?? '' );
			if ( '' === $id || 'unknown' === $id ) {
				continue;
			}
			$state = (string) ( $row['state'] ?? self::STATE_CLOSED );
			if ( ! in_array( $state, array( self::STATE_CLOSED, self::STATE_OPEN, self::STATE_HALF_OPEN ), true ) ) {
				$state = self::STATE_CLOSED;
			}
			$outcomes = array();
			if ( isset( $row['outcomes'] ) && is_array( $row['outcomes'] ) ) {
				foreach ( $row['outcomes'] as $o ) {
					if ( ! is_array( $o ) ) {
						continue;
					}
					$ts = isset( $o['ts'] ) ? (int) $o['ts'] : 0;
					$ok = ! empty( $o['ok'] );
					if ( $ts > 0 ) {
						$outcomes[] = array(
							'ts' => $ts,
							'ok' => $ok,
						);
					}
				}
			}
			$out[ $id ] = array(
				'state'                => $state,
				'consecutive_failures' => max( 0, (int) ( $row['consecutive_failures'] ?? 0 ) ),
				'opened_ts'            => max( 0, (int) ( $row['opened_ts'] ?? 0 ) ),
				'probe_in_flight'      => ! empty( $row['probe_in_flight'] ),
				'outcomes'             => $outcomes,
				'manual'               => ! empty( $row['manual'] ),
			);
		}

		return $out;
	}

	/**
	 * @param array<string,array<string,mixed>> $map State map.
	 */
	public static function save_state_map( array $map ): void {
		$map = self::sanitize_state_map( $map );
		if ( empty( $map ) ) {
			delete_option( self::STATE_OPTION );
			return;
		}
		update_option( self::STATE_OPTION, $map, false );
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function provider_row( string $provider ): array {
		$id  = class_exists( Latency::class, false ) ? Latency::sanitize_provider( $provider ) : strtolower( $provider );
		$map = self::get_state_map();
		if ( isset( $map[ $id ] ) ) {
			return $map[ $id ];
		}

		return array(
			'state'                => self::STATE_CLOSED,
			'consecutive_failures' => 0,
			'opened_ts'            => 0,
			'probe_in_flight'      => false,
			'outcomes'             => array(),
			'manual'               => false,
		);
	}

	public static function provider_state( string $provider, ?int $now = null ): string {
		$now = null === $now ? Clock::now() : $now;
		$row = self::maybe_advance_open_to_half_open( $provider, $now );

		return (string) ( $row['state'] ?? self::STATE_CLOSED );
	}

	/**
	 * Advance OPEN → HALF_OPEN after cooldown (non-manual trips).
	 *
	 * @return array<string,mixed>
	 */
	public static function maybe_advance_open_to_half_open( string $provider, int $now ): array {
		$id      = class_exists( Latency::class, false ) ? Latency::sanitize_provider( $provider ) : strtolower( $provider );
		$map     = self::get_state_map();
		$row     = $map[ $id ] ?? self::provider_row( $id );
		$settings = self::get_settings();

		if ( self::STATE_OPEN === ( $row['state'] ?? '' ) && empty( $row['manual'] ) ) {
			$opened = (int) ( $row['opened_ts'] ?? 0 );
			if ( $opened > 0 && ( $now - $opened ) >= (int) $settings['cooldown_seconds'] ) {
				$row['state']           = self::STATE_HALF_OPEN;
				$row['probe_in_flight'] = false;
				$map[ $id ]             = $row;
				self::save_state_map( $map );
				self::audit_transition( $id, 'half_open', 'cooldown', $now );
			}
		}

		return $row;
	}

	/**
	 * Human Activity reason for an OPEN deny.
	 */
	public static function open_reason_string( string $provider, ?int $opened_ts = null ): string {
		$ts = null === $opened_ts ? (int) ( self::provider_row( $provider )['opened_ts'] ?? 0 ) : (int) $opened_ts;
		$hhmm = $ts > 0 ? gmdate( 'H:i', $ts ) : '--:--';

		return sprintf(
			/* translators: %s: HH:MM trip time (UTC) */
			__( 'provider circuit open — tripped %s, probing', 'handl-ai-connector-access-control' ),
			$hhmm
		);
	}

	/**
	 * @param mixed $prevent Prior filter result.
	 * @param mixed $builder Prompt builder.
	 */
	public static function maybe_prevent_prompt( $prevent, $builder ): bool {
		if ( $prevent ) {
			return true;
		}
		if ( ! self::is_enabled() ) {
			return false;
		}

		$policy = Policy::get_policy();
		if ( ! empty( $policy['audit_only'] ) ) {
			return false;
		}
		if ( class_exists( Break_Glass::class, false ) && Break_Glass::is_active() ) {
			return false;
		}

		$now      = Clock::now();
		$snapshot = class_exists( Prompt_Snapshot::class, false ) ? Prompt_Snapshot::from_builder( $builder ) : array();
		$provider = self::provider_from_snapshot( is_array( $snapshot ) ? $snapshot : array() );
		if ( function_exists( 'apply_filters' ) ) {
			$provider = self::provider_from_snapshot(
				array(
					'provider' => (string) apply_filters( 'handl_aicac_circuit_breaker_provider', $provider, $builder ),
				)
			);
		}
		if ( '' === $provider || 'unknown' === $provider ) {
			return false;
		}

		self::maybe_trip_from_latency( $provider, $now );

		$state = self::provider_state( $provider, $now );
		if ( self::STATE_CLOSED === $state ) {
			self::$pending[] = array(
				'provider' => $provider,
				'probe'    => false,
			);
			return false;
		}

		if ( self::STATE_HALF_OPEN === $state ) {
			$row = self::provider_row( $provider );
			if ( empty( $row['probe_in_flight'] ) ) {
				$map                        = self::get_state_map();
				$row['probe_in_flight']     = true;
				$map[ $provider ]           = $row;
				self::save_state_map( $map );
				self::$pending[] = array(
					'provider' => $provider,
					'probe'    => true,
				);
				return false;
			}
			// Probe already in flight — deny other callers.
		}

		// OPEN (or half-open with probe busy): fail fast.
		$attrib    = Attribution::resolve_from_backtrace();
		$plugin    = is_string( $attrib['plugin'] ?? null ) ? (string) $attrib['plugin'] : null;
		$operation = isset( $snapshot['operation'] ) ? (string) $snapshot['operation'] : '';
		$family    = isset( $snapshot['capability_family'] ) && is_string( $snapshot['capability_family'] )
			? (string) $snapshot['capability_family']
			: ( class_exists( Operations::class, false ) ? Operations::family_from_operation( $operation ) : '' );
		$row       = self::provider_row( $provider );
		$message   = self::open_reason_string( $provider, (int) ( $row['opened_ts'] ?? 0 ) );

		$event = array_merge(
			array(
				'ts'                => $now,
				'plugin'            => $plugin,
				'file'              => $attrib['file'] ?? null,
				'caller'            => $attrib['method'] ?? null,
				'decision'          => 'deny',
				'would_decision'    => 'deny',
				'capability_family' => $family,
				'denial_reason'     => $message,
				'decision_source'   => self::REASON,
				'user_id'           => Policy::current_user_id_for_gate(),
				'user_role'         => Policy::current_user_role_for_log(),
				'provider'          => $provider,
				'circuit_breaker'   => true,
				'circuit_state'     => $state,
				'uri'               => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) ) : null,
			),
			is_array( $snapshot ) ? $snapshot : array()
		);

		self::reclassify_latest_allow( $event );

		$soft = false;
		if ( class_exists( Soft_Deny::class, false ) ) {
			$soft = Soft_Deny::maybe_arm_from_deny(
				true,
				$event,
				$policy,
				is_string( $plugin ) ? $plugin : null,
				$operation,
				$family
			);
		}

		Policy::append_log_event( $event );

		// Per-call deny alerts suppressed — transition alerts only.
		if ( class_exists( Access_Request::class, false ) ) {
			Access_Request::note_deny( $event );
		}

		return $soft ? false : true;
	}

	/**
	 * @param object $event AfterGenerateResultEvent.
	 */
	public static function maybe_record_outcome( object $event ): void {
		if ( ! self::is_enabled() || empty( self::$pending ) ) {
			return;
		}

		$entry = array_pop( self::$pending );
		if ( ! is_array( $entry ) ) {
			return;
		}
		$provider = (string) ( $entry['provider'] ?? '' );
		$probe    = ! empty( $entry['probe'] );
		if ( '' === $provider ) {
			return;
		}

		$ok  = self::event_is_success( $event );
		$now = Clock::now();
		self::record_outcome( $provider, $ok, $probe, $now );
	}

	/**
	 * Public for tests / CLI.
	 */
	public static function record_outcome( string $provider, bool $success, bool $was_probe = false, ?int $now = null ): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		$now      = null === $now ? Clock::now() : $now;
		$id       = class_exists( Latency::class, false ) ? Latency::sanitize_provider( $provider ) : strtolower( $provider );
		$settings = self::get_settings();
		$map      = self::get_state_map();
		$row      = $map[ $id ] ?? self::provider_row( $id );

		$row['outcomes'][] = array(
			'ts' => $now,
			'ok' => $success,
		);
		$row['outcomes']   = self::prune_outcomes( $row['outcomes'], $now, (int) $settings['window_seconds'] );

		if ( $success ) {
			$row['consecutive_failures'] = 0;
		} else {
			$row['consecutive_failures'] = (int) ( $row['consecutive_failures'] ?? 0 ) + 1;
		}

		$state = (string) ( $row['state'] ?? self::STATE_CLOSED );

		if ( self::STATE_HALF_OPEN === $state || $was_probe ) {
			$row['probe_in_flight'] = false;
			if ( $success ) {
				$row['state']                = self::STATE_CLOSED;
				$row['opened_ts']            = 0;
				$row['manual']               = false;
				$row['consecutive_failures'] = 0;
				$map[ $id ]                  = $row;
				self::save_state_map( $map );
				self::audit_transition( $id, 'close', 'probe_success', $now );
				self::maybe_alert_transition( $id, 'recover', $now );
				return;
			}
			$row['state']     = self::STATE_OPEN;
			$row['opened_ts'] = $now;
			$row['manual']    = false;
			$map[ $id ]       = $row;
			self::save_state_map( $map );
			self::audit_transition( $id, 'open', 'probe_failure', $now );
			self::maybe_alert_transition( $id, 'trip', $now );
			return;
		}

		if ( self::STATE_OPEN === $state ) {
			$map[ $id ] = $row;
			self::save_state_map( $map );
			return;
		}

		// CLOSED: evaluate trip conditions.
		$should_trip = false;
		$why         = '';
		if ( (int) $row['consecutive_failures'] >= (int) $settings['failure_threshold'] ) {
			$should_trip = true;
			$why         = 'consecutive_failures';
		} elseif ( (int) $settings['error_rate_pct'] > 0 ) {
			$total = count( $row['outcomes'] );
			if ( $total >= (int) $settings['failure_threshold'] ) {
				$fails = 0;
				foreach ( $row['outcomes'] as $o ) {
					if ( empty( $o['ok'] ) ) {
						++$fails;
					}
				}
				$rate = (int) round( ( $fails / $total ) * 100 );
				if ( $rate >= (int) $settings['error_rate_pct'] ) {
					$should_trip = true;
					$why         = 'error_rate';
				}
			}
		}

		if ( $should_trip ) {
			$row['state']     = self::STATE_OPEN;
			$row['opened_ts'] = $now;
			$row['manual']    = false;
			$map[ $id ]       = $row;
			self::save_state_map( $map );
			self::audit_transition( $id, 'open', $why, $now );
			self::maybe_alert_transition( $id, 'trip', $now );
			return;
		}

		$map[ $id ] = $row;
		self::save_state_map( $map );
	}

	/**
	 * Manual trip (admin / WP-CLI).
	 */
	public static function trip( string $provider, string $via = 'manual', ?int $actor = null, ?int $now = null ): bool {
		$now = null === $now ? Clock::now() : $now;
		$id  = class_exists( Latency::class, false ) ? Latency::sanitize_provider( $provider ) : strtolower( $provider );
		if ( '' === $id || 'unknown' === $id ) {
			return false;
		}
		$map              = self::get_state_map();
		$row              = $map[ $id ] ?? self::provider_row( $id );
		$row['state']     = self::STATE_OPEN;
		$row['opened_ts'] = $now;
		// Manual/admin/cli trips stay OPEN until reset; auto trips cool down to HALF_OPEN.
		$row['manual']          = in_array( $via, array( 'manual', 'admin', 'cli' ), true );
		$row['probe_in_flight'] = false;
		$map[ $id ]             = $row;
		self::save_state_map( $map );
		self::audit_transition( $id, 'open', $via, $now, $actor );
		self::maybe_alert_transition( $id, 'trip', $now );

		return true;
	}

	/**
	 * Manual reset / close (admin / WP-CLI).
	 */
	public static function reset_provider( string $provider, string $via = 'manual', ?int $actor = null, ?int $now = null ): bool {
		$now = null === $now ? Clock::now() : $now;
		$id  = class_exists( Latency::class, false ) ? Latency::sanitize_provider( $provider ) : strtolower( $provider );
		if ( '' === $id || 'unknown' === $id ) {
			return false;
		}
		$map = self::get_state_map();
		$row = $map[ $id ] ?? null;
		if ( null === $row ) {
			return false;
		}
		$was = (string) ( $row['state'] ?? self::STATE_CLOSED );
		$row = array(
			'state'                => self::STATE_CLOSED,
			'consecutive_failures' => 0,
			'opened_ts'            => 0,
			'probe_in_flight'      => false,
			'outcomes'             => array(),
			'manual'               => false,
		);
		$map[ $id ] = $row;
		self::save_state_map( $map );
		if ( self::STATE_CLOSED !== $was ) {
			self::audit_transition( $id, 'close', $via, $now, $actor );
			self::maybe_alert_transition( $id, 'recover', $now );
		}

		return true;
	}

	/**
	 * @return list<array{provider:string,state:string,opened_ts:int,consecutive_failures:int,manual:bool}>
	 */
	public static function status_rows( ?int $now = null ): array {
		$now  = null === $now ? Clock::now() : $now;
		$map  = self::get_state_map();
		$rows = array();
		foreach ( $map as $provider => $_ ) {
			$row    = self::maybe_advance_open_to_half_open( $provider, $now );
			$rows[] = array(
				'provider'             => $provider,
				'state'                => (string) ( $row['state'] ?? self::STATE_CLOSED ),
				'opened_ts'            => (int) ( $row['opened_ts'] ?? 0 ),
				'consecutive_failures' => (int) ( $row['consecutive_failures'] ?? 0 ),
				'manual'               => ! empty( $row['manual'] ),
			);
		}
		usort(
			$rows,
			static function ( $a, $b ) {
				return strcmp( (string) $a['provider'], (string) $b['provider'] );
			}
		);

		return $rows;
	}

	/**
	 * Optional Latency p95 pressure → trip.
	 */
	public static function maybe_trip_from_latency( string $provider, int $now ): void {
		$settings = self::get_settings();
		if ( empty( $settings['use_latency_p95'] ) || ! class_exists( Latency::class, false ) ) {
			return;
		}
		$row = self::provider_row( $provider );
		if ( self::STATE_CLOSED !== ( $row['state'] ?? self::STATE_CLOSED ) ) {
			return;
		}
		$policy    = Policy::get_policy();
		$threshold = Latency::threshold_ms( $policy );
		$min       = Latency::min_samples( $policy );
		foreach ( Latency::provider_stats( $now ) as $stat ) {
			if ( (string) ( $stat['provider'] ?? '' ) !== $provider ) {
				continue;
			}
			if ( (int) ( $stat['count'] ?? 0 ) < $min ) {
				return;
			}
			if ( (int) ( $stat['p95'] ?? 0 ) >= $threshold ) {
				self::trip( $provider, 'latency_p95', null, $now );
			}
			return;
		}
	}

	/**
	 * @param mixed $value New policy.
	 * @param mixed $old   Old policy.
	 * @return mixed
	 */
	public static function capture_settings_on_policy_save( $value, $old ) {
		unset( $old );
		if ( ! isset( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Admin save already verified the form nonce.
			return $value;
		}
		$settings = array(
			'enabled'           => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
			'failure_threshold' => isset( $_POST[ self::POST_FAILURE_THRESHOLD ] ) ? wp_unslash( $_POST[ self::POST_FAILURE_THRESHOLD ] ) : self::DEFAULT_FAILURE_THRESHOLD, // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			'error_rate_pct'    => isset( $_POST[ self::POST_ERROR_RATE ] ) ? wp_unslash( $_POST[ self::POST_ERROR_RATE ] ) : self::DEFAULT_ERROR_RATE_PCT, // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			'window_seconds'    => isset( $_POST[ self::POST_WINDOW ] ) ? wp_unslash( $_POST[ self::POST_WINDOW ] ) : self::DEFAULT_WINDOW_SECONDS, // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			'cooldown_seconds'  => isset( $_POST[ self::POST_COOLDOWN ] ) ? wp_unslash( $_POST[ self::POST_COOLDOWN ] ) : self::DEFAULT_COOLDOWN_SECONDS, // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			'use_latency_p95'   => ! empty( $_POST[ self::POST_USE_LATENCY ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
		);
		self::save_settings( $settings );

		return $value;
	}

	/**
	 * @param array<string,mixed> $policy Policy.
	 */
	public static function render_settings( $policy ): void {
		unset( $policy );
		$s = self::get_settings();
		echo '<tr id="handl-aicac-circuit-breaker">';
		echo '<th scope="row">' . esc_html__( 'Provider circuit breaker', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
		echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $s['enabled'] ), true, false ) . ' /> ';
		echo esc_html__( 'Fail fast when an AI provider is failing', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'Off by default. When on, consecutive provider errors trip a breaker so WordPress stops waiting on dead endpoints. One probe call recovers automatically.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p><label for="handl-aicac-cb-threshold">' . esc_html__( 'Consecutive failures to trip', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<input type="number" min="1" max="100" class="small-text" id="handl-aicac-cb-threshold" name="' . esc_attr( self::POST_FAILURE_THRESHOLD ) . '" value="' . esc_attr( (string) $s['failure_threshold'] ) . '" /></p>';
		echo '<p><label for="handl-aicac-cb-rate">' . esc_html__( 'Error rate % to trip (0 = off)', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<input type="number" min="0" max="100" class="small-text" id="handl-aicac-cb-rate" name="' . esc_attr( self::POST_ERROR_RATE ) . '" value="' . esc_attr( (string) $s['error_rate_pct'] ) . '" /></p>';
		echo '<p><label for="handl-aicac-cb-window">' . esc_html__( 'Rolling window (seconds)', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<input type="number" min="30" max="86400" class="small-text" id="handl-aicac-cb-window" name="' . esc_attr( self::POST_WINDOW ) . '" value="' . esc_attr( (string) $s['window_seconds'] ) . '" /></p>';
		echo '<p><label for="handl-aicac-cb-cooldown">' . esc_html__( 'Cooldown before probe (seconds)', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<input type="number" min="10" max="86400" class="small-text" id="handl-aicac-cb-cooldown" name="' . esc_attr( self::POST_COOLDOWN ) . '" value="' . esc_attr( (string) $s['cooldown_seconds'] ) . '" /></p>';
		echo '<p><label><input type="checkbox" name="' . esc_attr( self::POST_USE_LATENCY ) . '" value="1" ' . checked( ! empty( $s['use_latency_p95'] ), true, false ) . ' /> ';
		echo esc_html__( 'Also trip on sustained latency p95 breach (uses Latency samples)', 'handl-ai-connector-access-control' ) . '</label></p>';

		$rows = self::status_rows();
		if ( ! empty( $rows ) ) {
			echo '<table class="widefat striped" style="max-width:40em;margin-top:1em"><thead><tr>';
			echo '<th>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'State', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Actions', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $rows as $r ) {
				$trip_url  = wp_nonce_url(
					admin_url( 'admin-post.php?action=' . self::ACTION_TRIP . '&provider=' . rawurlencode( (string) $r['provider'] ) ),
					self::ACTION_TRIP
				);
				$reset_url = wp_nonce_url(
					admin_url( 'admin-post.php?action=' . self::ACTION_RESET . '&provider=' . rawurlencode( (string) $r['provider'] ) ),
					self::ACTION_RESET
				);
				echo '<tr><td>' . esc_html( (string) $r['provider'] ) . '</td>';
				echo '<td>' . esc_html( (string) $r['state'] ) . '</td>';
				echo '<td><a href="' . esc_url( $trip_url ) . '">' . esc_html__( 'Trip', 'handl-ai-connector-access-control' ) . '</a> · ';
				echo '<a href="' . esc_url( $reset_url ) . '">' . esc_html__( 'Reset', 'handl-ai-connector-access-control' ) . '</a></td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '</td></tr>';
	}

	public static function handle_trip(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You cannot trip this breaker.', 'handl-ai-connector-access-control' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION_TRIP );
		$provider = isset( $_GET['provider'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['provider'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$actor    = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
		self::trip( $provider, 'admin', $actor );
		self::redirect_settings();
	}

	public static function handle_reset(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You cannot reset this breaker.', 'handl-ai-connector-access-control' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION_RESET );
		$provider = isset( $_GET['provider'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['provider'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$actor    = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
		self::reset_provider( $provider, 'admin', $actor );
		self::redirect_settings();
	}

	private static function redirect_settings(): void {
		$url = admin_url( 'options-general.php?page=handl-aicac' );
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $url );
			exit;
		}
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac circuit-breaker', CLI_Circuit_Breaker::class );
	}

	/**
	 * @param array<string,mixed> $snapshot Prompt snapshot.
	 */
	private static function provider_from_snapshot( array $snapshot ): string {
		$raw = isset( $snapshot['provider'] ) ? (string) $snapshot['provider'] : '';
		if ( class_exists( Latency::class, false ) ) {
			return Latency::sanitize_provider( $raw );
		}
		$raw = strtolower( trim( $raw ) );
		$raw = preg_replace( '/[^a-z0-9_\-\.]/', '', $raw ) ?? '';

		return '' === $raw ? 'unknown' : $raw;
	}

	/**
	 * @param object $event AfterGenerateResultEvent.
	 */
	private static function event_is_success( object $event ): bool {
		if ( ! method_exists( $event, 'getResult' ) ) {
			return false;
		}
		$result = $event->getResult();
		if ( $result instanceof \WP_Error ) {
			return false;
		}
		if ( is_object( $result ) && method_exists( $result, 'get_error_code' ) && ! method_exists( $result, 'getTokenUsage' ) ) {
			// WP_Error stub without generation payload.
			return false;
		}
		if ( ! is_object( $result ) ) {
			return false;
		}

		return true;
	}

	/**
	 * @param list<array{ts:int,ok:bool}> $outcomes Outcomes.
	 * @return list<array{ts:int,ok:bool}>
	 */
	private static function prune_outcomes( array $outcomes, int $now, int $window ): array {
		$cutoff = $now - max( 1, $window );
		$out    = array();
		foreach ( $outcomes as $o ) {
			if ( (int) ( $o['ts'] ?? 0 ) >= $cutoff ) {
				$out[] = array(
					'ts' => (int) $o['ts'],
					'ok' => ! empty( $o['ok'] ),
				);
			}
		}
		if ( count( $out ) > 500 ) {
			$out = array_slice( $out, -500 );
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $event Deny event.
	 */
	private static function reclassify_latest_allow( array $event ): void {
		$policy = Policy::get_policy();
		if ( empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] ) ) {
			return;
		}
		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) || empty( $log ) ) {
			return;
		}
		$i    = count( $log ) - 1;
		$last = $log[ $i ];
		if ( ! is_array( $last ) ) {
			return;
		}
		if ( 'allow' !== (string) ( $last['decision'] ?? '' ) ) {
			return;
		}
		$last_prov  = (string) ( $last['provider'] ?? '' );
		$event_prov = (string) ( $event['provider'] ?? '' );
		if ( '' !== $last_prov && '' !== $event_prov && $last_prov !== $event_prov ) {
			return;
		}
		$last_ts  = (int) ( $last['ts'] ?? 0 );
		$event_ts = (int) ( $event['ts'] ?? 0 );
		if ( $last_ts > 0 && $event_ts > 0 && abs( $last_ts - $event_ts ) > 5 ) {
			return;
		}
		array_pop( $log );
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
	}

	private static function audit_transition( string $provider, string $action, string $via, int $now, ?int $actor = null ): void {
		$policy = Policy::get_policy();
		if ( empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] ) ) {
			// Still record when logging off? Match dormant — only when logging on.
			// Dormant always appends; keep that.
		}
		$event = array(
			'ts'              => $now,
			'decision'        => self::CHANNEL,
			'channel'         => self::CHANNEL,
			'circuit_action'  => $action,
			'circuit_via'     => $via,
			'provider'        => $provider,
			'circuit_breaker' => true,
			'actor_id'        => null === $actor ? 0 : (int) $actor,
		);
		Policy::append_log_event( $event );
	}

	/**
	 * One alert per trip / recover per provider per dedupe window.
	 *
	 * @param 'trip'|'recover' $kind Transition kind.
	 */
	private static function maybe_alert_transition( string $provider, string $kind, int $now ): void {
		if ( ! class_exists( Alerts::class, false ) ) {
			return;
		}
		$key   = $kind . ':' . $provider;
		$fired = get_option( self::FIRED_OPTION, array() );
		if ( ! is_array( $fired ) ) {
			$fired = array();
		}
		$at = isset( $fired[ $key ]['at'] ) ? (int) $fired[ $key ]['at'] : 0;
		if ( $at > 0 && ( $now - $at ) < self::ALERT_DEDUPE_SECONDS ) {
			return;
		}

		$policy = Policy::get_policy();
		$to     = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return;
		}

		if ( 'trip' === $kind ) {
			$subject = sprintf(
				/* translators: %s: provider id */
				__( '[HandL AI] Circuit open: %s', 'handl-ai-connector-access-control' ),
				$provider
			);
			$body = sprintf(
				/* translators: %s: provider id */
				__( "The circuit breaker tripped for provider %s.\nGoverned AI calls to that provider will fail fast until a probe succeeds or an admin resets the breaker.\n", 'handl-ai-connector-access-control' ),
				$provider
			);
		} else {
			$subject = sprintf(
				/* translators: %s: provider id */
				__( '[HandL AI] Circuit closed: %s', 'handl-ai-connector-access-control' ),
				$provider
			);
			$body = sprintf(
				/* translators: %s: provider id */
				__( "The circuit breaker recovered for provider %s.\nCalls to that provider are allowed again.\n", 'handl-ai-connector-access-control' ),
				$provider
			);
		}

		$ok = Alerts::safe_wp_mail( $to, $subject, $body );
		if ( ! $ok ) {
			return;
		}

		$fired[ $key ] = array(
			'at'    => $now,
			'state' => $kind,
		);
		update_option( self::FIRED_OPTION, $fired, false );

		$webhook = Alerts::resolve_webhook( $policy );
		if ( '' !== $webhook ) {
			Alerts::safe_wp_remote_post(
				$webhook,
				array(
					'type'     => 'handl_aicac_circuit_breaker_alert',
					'kind'     => $kind,
					'provider' => $provider,
					'ts'       => $now,
				),
				'circuit_breaker'
			);
		}
	}
}

/**
 * WP-CLI: `wp handl-aicac circuit-breaker` status|trip|reset.
 *
 * @package HandL_AICAC
 * @when after_wp_load
 */
final class CLI_Circuit_Breaker {

	/**
	 * List breaker states.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table or json.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac circuit-breaker status
	 *
	 * @subcommand status
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$rows   = Circuit_Breaker::status_rows();
		$settings = Circuit_Breaker::get_settings();
		if ( 'json' === $format ) {
			\WP_CLI::print_value(
				array(
					'enabled' => ! empty( $settings['enabled'] ),
					'providers' => $rows,
				),
				array( 'format' => 'json' )
			);
			return;
		}
		\WP_CLI::log( ! empty( $settings['enabled'] ) ? 'enabled' : 'disabled' );
		if ( empty( $rows ) ) {
			\WP_CLI::log( 'No provider state yet.' );
			return;
		}
		$table = array();
		foreach ( $rows as $r ) {
			$table[] = array(
				'provider'             => (string) $r['provider'],
				'state'                => (string) $r['state'],
				'consecutive_failures' => (string) (int) $r['consecutive_failures'],
				'manual'               => ! empty( $r['manual'] ) ? 'yes' : 'no',
			);
		}
		\WP_CLI\Utils\format_items( 'table', $table, array( 'provider', 'state', 'consecutive_failures', 'manual' ) );
	}

	/**
	 * Manually open the breaker for a provider.
	 *
	 * ## OPTIONS
	 *
	 * <provider>
	 * : Provider id (e.g. openai).
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac circuit-breaker trip openai
	 *
	 * @subcommand trip
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function trip( $args, $assoc_args ): void {
		unset( $assoc_args );
		$provider = isset( $args[0] ) ? (string) $args[0] : '';
		if ( '' === $provider ) {
			\WP_CLI::error( 'Need a provider id.' );
		}
		if ( ! Circuit_Breaker::trip( $provider, 'cli' ) ) {
			\WP_CLI::error( 'Could not trip provider.' );
		}
		\WP_CLI::success( 'Tripped: ' . $provider );
	}

	/**
	 * Manually close / reset the breaker for a provider.
	 *
	 * ## OPTIONS
	 *
	 * <provider>
	 * : Provider id (e.g. openai).
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac circuit-breaker reset openai
	 *
	 * @subcommand reset
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function reset( $args, $assoc_args ): void {
		unset( $assoc_args );
		$provider = isset( $args[0] ) ? (string) $args[0] : '';
		if ( '' === $provider ) {
			\WP_CLI::error( 'Need a provider id.' );
		}
		if ( ! Circuit_Breaker::reset_provider( $provider, 'cli' ) ) {
			\WP_CLI::error( 'Could not reset provider (unknown or already closed).' );
		}
		\WP_CLI::success( 'Reset: ' . $provider );
	}
}
