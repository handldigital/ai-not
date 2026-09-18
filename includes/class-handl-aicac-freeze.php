<?php
/**
 * AICAC-PANIC-FREEZE (#267): one-click temporary deny-all with auto-restore.
 *
 * Snapshots the live policy, applies the Strict lockdown preset, and restores
 * the snapshot when the timer ends, on manual Restore, or on reactivation
 * after a mid-freeze deactivation.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Freeze {

	public const OPTION_KEY = 'handl_aicac_freeze';

	public const CRON_HOOK = 'handl_aicac_freeze_expire';

	/** @var list<int> 15 min / 1 h / 4 h */
	public const ALLOWED_MINUTES = array( 15, 60, 240 );

	/**
	 * Wire scheduled expiry.
	 */
	public static function init(): void {
		add_action( self::CRON_HOOK, array( self::class, 'cron_expire' ) );
	}

	/**
	 * Classes needed from activation hooks (plugins_loaded may not have run).
	 */
	public static function bootstrap_for_hooks(): void {
		static $loaded = false;
		if ( $loaded ) {
			return;
		}
		$dir = HANDL_AICAC_DIR . '/includes/';
		require_once $dir . 'class-handl-aicac-clock.php';
		require_once $dir . 'class-handl-aicac-attribution.php';
		require_once $dir . 'class-handl-aicac-operations.php';
		require_once $dir . 'class-handl-aicac-cost.php';
		require_once $dir . 'class-handl-aicac-spend-threshold.php';
		require_once $dir . 'class-handl-aicac-budget.php';
		require_once $dir . 'class-handl-aicac-log-storage.php';
		require_once $dir . 'class-handl-aicac-log-retention.php';
		require_once $dir . 'class-handl-aicac-email-template.php';
		require_once $dir . 'class-handl-aicac-alert-health.php';
		require_once $dir . 'class-handl-aicac-webhook-delivery-log.php';
		require_once $dir . 'class-handl-aicac-alerts.php';
		require_once $dir . 'class-handl-aicac-alert-routing.php';
		require_once $dir . 'class-handl-aicac-quiet-hours.php';
		require_once $dir . 'class-handl-aicac-break-glass.php';
		require_once $dir . 'class-handl-aicac-temp-allow.php';
		require_once $dir . 'class-handl-aicac-rule-notes.php';
		require_once $dir . 'class-handl-aicac-policy.php';
		require_once $dir . 'class-handl-aicac-presets.php';
		require_once $dir . 'class-handl-aicac-policy-snapshots.php';
		require_once $dir . 'class-handl-aicac-plugin.php';
		$loaded = true;
	}

	/**
	 * Reactivation after a mid-freeze deactivation: restore snapshot so lockdown
	 * is not stuck on forever.
	 */
	public static function on_activate( ?int $now = null ): void {
		self::bootstrap_for_hooks();
		$now   = null !== $now ? (int) $now : time();
		$state = self::get_state();
		if ( empty( $state['active'] ) ) {
			return;
		}
		self::close( 'reactivated', $now );
	}

	/**
	 * @return list<int>
	 */
	public static function allowed_minutes(): array {
		return self::ALLOWED_MINUTES;
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function get_state(): array {
		$raw = get_option( self::OPTION_KEY, null );
		if ( ! is_array( $raw ) ) {
			return self::empty_state();
		}

		return self::sanitize_state( $raw );
	}

	/**
	 * Whether a freeze window is currently open (runs deadline fail-safe first).
	 */
	public static function is_active( ?int $now = null ): bool {
		self::ensure_closed_if_past( $now );
		$state = self::get_state();

		return ! empty( $state['active'] );
	}

	/**
	 * Fail-safe: close when past expires_ts even if cron never ran.
	 */
	public static function ensure_closed_if_past( ?int $now = null ): void {
		$now   = null !== $now ? (int) $now : time();
		$state = self::get_state();
		if ( empty( $state['active'] ) ) {
			return;
		}
		if ( $now < (int) $state['expires_ts'] ) {
			return;
		}
		self::close( 'expired', $now );
	}

	/**
	 * Start a freeze: snapshot → lockdown preset → countdown.
	 *
	 * @return array{ok:bool,error?:string,state?:array<string,mixed>}
	 */
	public static function start( int $minutes, string $reason = '', ?int $now = null ): array {
		$now = null !== $now ? (int) $now : time();
		self::ensure_closed_if_past( $now );

		if ( self::is_active( $now ) ) {
			return array(
				'ok'    => false,
				'error' => 'already_active',
			);
		}

		if ( ! in_array( $minutes, self::ALLOWED_MINUTES, true ) ) {
			return array(
				'ok'    => false,
				'error' => 'invalid_minutes',
			);
		}

		$reason = sanitize_text_field( $reason );

		// Panic freeze wins over an open break-glass allow window.
		if ( class_exists( Break_Glass::class ) && Break_Glass::is_active( $now ) ) {
			Break_Glass::cancel( $now );
		}

		$policy_before = get_option( Plugin::OPTION_KEY, null );
		if ( ! is_array( $policy_before ) ) {
			$policy_before = Policy::get_policy();
		}
		$current = Policy::get_policy();
		$target  = Presets::build_target( 'lockdown', $current );
		if ( null === $target ) {
			return array(
				'ok'    => false,
				'error' => 'lockdown_unavailable',
			);
		}

		$expires_ts = $now + ( $minutes * ( defined( 'MINUTE_IN_SECONDS' ) ? (int) MINUTE_IN_SECONDS : 60 ) );
		$actor      = Policy_Snapshots::detect_actor();

		$state = array(
			'active'        => true,
			'started_ts'    => $now,
			'expires_ts'    => $expires_ts,
			'minutes'       => $minutes,
			'reason'        => $reason,
			'actor'         => $actor,
			'policy_before' => $policy_before,
			'closed_cause'  => '',
		);
		update_option( self::OPTION_KEY, $state, false );
		self::schedule_expiry( $expires_ts );

		// Apply lockdown after state is persisted so a failed save can still restore.
		Policy::save_policy( $target );

		Policy_Snapshots::append_history(
			array(
				'ts'      => $now,
				'actor'   => $actor,
				'changes' => array(
					sprintf(
						'Panic freeze started (%d min)%s',
						$minutes,
						'' !== $reason ? ': ' . $reason : ''
					),
				),
				'summary' => sprintf( 'Panic freeze started (%d min)', $minutes ),
			)
		);

		self::append_audit( 'freeze_started', $now, $minutes, $reason );
		self::send_mail(
			'start',
			$state,
			sprintf(
				/* translators: %d: minutes */
				__( "AI is frozen (deny-all) for %d minutes.\n\nThe previous policy will restore when the timer ends or you choose Restore now.", 'handl-ai-connector-access-control' ),
				$minutes
			)
		);

		return array(
			'ok'    => true,
			'state' => self::get_state(),
		);
	}

	/**
	 * Manual restore (same path as timer end).
	 *
	 * @return array{ok:bool,error?:string,state?:array<string,mixed>}
	 */
	public static function end( ?int $now = null ): array {
		$now = null !== $now ? (int) $now : time();
		self::ensure_closed_if_past( $now );
		if ( ! self::is_active( $now ) ) {
			return array(
				'ok'    => false,
				'error' => 'not_active',
			);
		}
		self::close( 'manual', $now );

		return array(
			'ok'    => true,
			'state' => self::get_state(),
		);
	}

	/**
	 * Extend requires a fresh click with a new duration (no silent auto-extend).
	 *
	 * @return array{ok:bool,error?:string,state?:array<string,mixed>}
	 */
	public static function extend( int $minutes, ?int $now = null ): array {
		$now = null !== $now ? (int) $now : time();
		self::ensure_closed_if_past( $now );
		if ( ! self::is_active( $now ) ) {
			return array(
				'ok'    => false,
				'error' => 'not_active',
			);
		}
		if ( ! in_array( $minutes, self::ALLOWED_MINUTES, true ) ) {
			return array(
				'ok'    => false,
				'error' => 'invalid_minutes',
			);
		}

		$state              = self::get_state();
		$expires_ts         = $now + ( $minutes * ( defined( 'MINUTE_IN_SECONDS' ) ? (int) MINUTE_IN_SECONDS : 60 ) );
		$state['expires_ts'] = $expires_ts;
		$state['minutes']    = $minutes;
		update_option( self::OPTION_KEY, $state, false );
		self::schedule_expiry( $expires_ts );

		$actor = Policy_Snapshots::detect_actor();
		Policy_Snapshots::append_history(
			array(
				'ts'      => $now,
				'actor'   => $actor,
				'changes' => array(
					sprintf( 'Panic freeze extended (%d min)', $minutes ),
				),
				'summary' => sprintf( 'Panic freeze extended (%d min)', $minutes ),
			)
		);

		return array(
			'ok'    => true,
			'state' => self::get_state(),
		);
	}

	/**
	 * @return array{active:bool,remaining_seconds:int,expires_ts:int,minutes:int,reason:string}
	 */
	public static function status( ?int $now = null ): array {
		$now = null !== $now ? (int) $now : time();
		self::ensure_closed_if_past( $now );
		$state = self::get_state();
		if ( empty( $state['active'] ) ) {
			return array(
				'active'            => false,
				'remaining_seconds' => 0,
				'expires_ts'        => 0,
				'minutes'           => 0,
				'reason'            => '',
			);
		}

		return array(
			'active'            => true,
			'remaining_seconds' => max( 0, (int) $state['expires_ts'] - $now ),
			'expires_ts'        => (int) $state['expires_ts'],
			'minutes'           => (int) $state['minutes'],
			'reason'            => (string) $state['reason'],
		);
	}

	/**
	 * Human line for admin notices (null when inactive).
	 */
	public static function notice_text( ?int $now = null ): ?string {
		$st = self::status( $now );
		if ( empty( $st['active'] ) ) {
			return null;
		}
		$until = self::format_local_time( (int) $st['expires_ts'] );

		return sprintf(
			/* translators: %s: local end time (e.g. 14:32) */
			__( 'AI is frozen until %s — Restore now / Extend.', 'handl-ai-connector-access-control' ),
			$until
		);
	}

	/**
	 * Cron callback.
	 */
	public static function cron_expire(): void {
		self::ensure_closed_if_past( time() );
	}

	/**
	 * Close freeze: restore snapshotted policy, clear state, mail + audit.
	 *
	 * @param string $cause expired|manual|reactivated
	 */
	public static function close( string $cause, ?int $now = null ): void {
		$now   = null !== $now ? (int) $now : time();
		$state = self::get_state();
		if ( empty( $state['active'] ) ) {
			return;
		}

		$cause  = in_array( $cause, array( 'expired', 'manual', 'reactivated' ), true ) ? $cause : 'expired';
		$before = is_array( $state['policy_before'] ?? null ) ? $state['policy_before'] : array();

		self::unschedule_expiry();

		if ( ! empty( $before ) ) {
			Policy::save_policy( $before );
		}

		$actor = Policy_Snapshots::detect_actor();
		Policy_Snapshots::append_history(
			array(
				'ts'      => $now,
				'actor'   => $actor,
				'changes' => array(
					sprintf( 'Panic freeze ended (%s). Prior policy restored.', $cause ),
				),
				'summary' => sprintf( 'Panic freeze ended (%s)', $cause ),
			)
		);

		$state['active']       = false;
		$state['closed_cause'] = $cause;
		$state['closed_ts']    = $now;
		unset( $state['policy_before'] );
		update_option( self::OPTION_KEY, $state, false );

		self::append_audit( 'freeze_ended', $now, (int) ( $state['minutes'] ?? 0 ), (string) ( $state['reason'] ?? '' ), $cause );

		if ( 'reactivated' === $cause ) {
			$body = __( 'Panic freeze ended on plugin reactivation. The previous policy was restored so lockdown is not stuck on.', 'handl-ai-connector-access-control' );
		} elseif ( 'manual' === $cause ) {
			$body = __( 'Panic freeze was restored early. The previous policy was restored.', 'handl-ai-connector-access-control' );
		} else {
			$body = __( 'Panic freeze ended. The previous policy was restored automatically.', 'handl-ai-connector-access-control' );
		}
		self::send_mail( 'end', $state, $body );
	}

	/**
	 * @return array<string,mixed>
	 */
	private static function empty_state(): array {
		return array(
			'active'       => false,
			'started_ts'   => 0,
			'expires_ts'   => 0,
			'minutes'      => 0,
			'reason'       => '',
			'actor'        => array(),
			'closed_cause' => '',
		);
	}

	/**
	 * @param array<string,mixed> $raw
	 * @return array<string,mixed>
	 */
	private static function sanitize_state( array $raw ): array {
		$out                 = self::empty_state();
		$out['active']       = ! empty( $raw['active'] );
		$out['started_ts']   = isset( $raw['started_ts'] ) ? (int) $raw['started_ts'] : 0;
		$out['expires_ts']   = isset( $raw['expires_ts'] ) ? (int) $raw['expires_ts'] : 0;
		$out['minutes']      = isset( $raw['minutes'] ) ? (int) $raw['minutes'] : 0;
		$out['reason']       = isset( $raw['reason'] ) ? sanitize_text_field( (string) $raw['reason'] ) : '';
		$out['actor']        = is_array( $raw['actor'] ?? null ) ? $raw['actor'] : array();
		$out['closed_cause'] = isset( $raw['closed_cause'] ) ? sanitize_key( (string) $raw['closed_cause'] ) : '';
		if ( isset( $raw['policy_before'] ) && is_array( $raw['policy_before'] ) ) {
			$out['policy_before'] = $raw['policy_before'];
		}
		if ( isset( $raw['closed_ts'] ) ) {
			$out['closed_ts'] = (int) $raw['closed_ts'];
		}

		return $out;
	}

	private static function schedule_expiry( int $expires_ts ): void {
		self::unschedule_expiry();
		if ( function_exists( 'wp_schedule_single_event' ) ) {
			wp_schedule_single_event( $expires_ts, self::CRON_HOOK );
		}
	}

	private static function unschedule_expiry(): void {
		if ( function_exists( 'wp_next_scheduled' ) && function_exists( 'wp_unschedule_event' ) ) {
			$ts = wp_next_scheduled( self::CRON_HOOK );
			if ( $ts ) {
				wp_unschedule_event( (int) $ts, self::CRON_HOOK );
			}
		}
		if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
			wp_clear_scheduled_hook( self::CRON_HOOK );
		}
	}

	private static function append_audit( string $decision, int $now, int $minutes, string $reason, string $cause = '' ): void {
		$event = array(
			'ts'       => $now,
			'decision' => $decision,
			'channel'  => 'freeze',
			'minutes'  => $minutes,
		);
		if ( '' !== $reason ) {
			$event['reason'] = $reason;
		}
		if ( '' !== $cause ) {
			$event['closed_cause'] = $cause;
		}
		Policy::append_log_event( $event );
	}

	/**
	 * @param array<string,mixed> $state
	 */
	private static function send_mail( string $kind, array $state, string $body ): void {
		unset( $kind, $state );
		$policy = Policy::get_policy();
		$to     = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return;
		}
		$subject = __( 'HandL AI Connector Access Control: Panic freeze.', 'handl-ai-connector-access-control' );
		Alerts::safe_wp_mail( $to, $subject, $body );
	}

	private static function format_local_time( int $ts ): string {
		if ( $ts <= 0 ) {
			return '';
		}
		if ( function_exists( 'wp_date' ) ) {
			$formatted = wp_date( 'H:i', $ts );
			if ( is_string( $formatted ) && '' !== $formatted ) {
				return $formatted;
			}
		}

		return gmdate( 'H:i', $ts ) . ' UTC';
	}
}
