<?php
/**
 * AICAC-BREAKGLASS (#202) Phase 1: temporary global allow with auto-revert.
 *
 * Engine + WP-CLI only. No admin UI. Cron expiry plus an evaluation-time
 * fail-safe so a missed cron never leaves the window open.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Break_Glass {

	public const OPTION_KEY = 'handl_aicac_break_glass';

	public const CRON_HOOK = 'handl_aicac_break_glass_expire';

	/** @var list<int> */
	public const ALLOWED_MINUTES = array( 15, 30, 60 );

	/**
	 * Wire the scheduled expiry hook.
	 */
	public static function init(): void {
		add_action( self::CRON_HOOK, array( self::class, 'cron_expire' ) );
	}

	/**
	 * @return list<int>
	 */
	public static function allowed_minutes(): array {
		return self::ALLOWED_MINUTES;
	}

	/**
	 * Raw stored state (may be inactive / empty).
	 *
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
	 * Whether a break-glass window is currently open.
	 * Runs the deadline fail-safe before answering.
	 */
	public static function is_active( ?int $now = null ): bool {
		self::ensure_closed_if_past( $now );
		$state = self::get_state();

		return ! empty( $state['active'] );
	}

	/**
	 * Fail-safe: if the window is past expires_ts, close it even when cron never ran.
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
	 * Open a window. Snapshots the current policy for exact restore on close.
	 *
	 * @return array{ok:bool,error?:string,state?:array<string,mixed>}
	 */
	public static function start( int $minutes, string $reason, ?int $now = null ): array {
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
		if ( '' === $reason ) {
			return array(
				'ok'    => false,
				'error' => 'reason_required',
			);
		}

		$policy_before = Policy::get_policy();
		$expires_ts    = $now + ( $minutes * ( defined( 'MINUTE_IN_SECONDS' ) ? (int) MINUTE_IN_SECONDS : 60 ) );
		$actor         = Policy_Snapshots::detect_actor();

		$state = array(
			'active'         => true,
			'started_ts'     => $now,
			'expires_ts'     => $expires_ts,
			'minutes'        => $minutes,
			'reason'         => $reason,
			'actor'          => $actor,
			'policy_before'  => $policy_before,
			'closed_cause'   => '',
		);
		update_option( self::OPTION_KEY, $state, false );
		self::schedule_expiry( $expires_ts );

		Policy_Snapshots::append_history(
			array(
				'ts'      => $now,
				'actor'   => $actor,
				'changes' => array(
					sprintf(
						'Break glass started (%d min): %s',
						$minutes,
						$reason
					),
				),
				'summary' => sprintf( 'Break glass started (%d min)', $minutes ),
			)
		);

		self::send_mail(
			'start',
			$state,
			sprintf(
				/* translators: 1: minutes, 2: reason */
				__( "Break glass is on for %1\$d minutes.\n\nReason: %2\$s\n\nPolicy is not enforced until the window ends or you cancel it.", 'handl-ai-connector-access-control' ),
				$minutes,
				$reason
			)
		);

		return array(
			'ok'    => true,
			'state' => self::get_state(),
		);
	}

	/**
	 * Cancel early — same restore path as expiry.
	 *
	 * @return array{ok:bool,error?:string,state?:array<string,mixed>}
	 */
	public static function cancel( ?int $now = null ): array {
		$now = null !== $now ? (int) $now : time();
		self::ensure_closed_if_past( $now );
		if ( ! self::is_active( $now ) ) {
			return array(
				'ok'    => false,
				'error' => 'not_active',
			);
		}
		self::close( 'cancelled', $now );

		return array(
			'ok'    => true,
			'state' => self::get_state(),
		);
	}

	/**
	 * Status for CLI / Phase 2 UI.
	 *
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

		$remaining = max( 0, (int) $state['expires_ts'] - $now );

		return array(
			'active'            => true,
			'remaining_seconds' => $remaining,
			'expires_ts'        => (int) $state['expires_ts'],
			'minutes'           => (int) $state['minutes'],
			'reason'            => (string) $state['reason'],
		);
	}

	/**
	 * Cron callback.
	 */
	public static function cron_expire(): void {
		self::ensure_closed_if_past( time() );
	}

	/**
	 * Close the window: restore snapshotted policy, clear state, mail + history.
	 *
	 * @param string $cause expired|cancelled
	 */
	public static function close( string $cause, ?int $now = null ): void {
		$now   = null !== $now ? (int) $now : time();
		$state = self::get_state();
		if ( empty( $state['active'] ) ) {
			return;
		}

		$cause = in_array( $cause, array( 'expired', 'cancelled' ), true ) ? $cause : 'expired';
		$before = is_array( $state['policy_before'] ?? null ) ? $state['policy_before'] : array();

		self::unschedule_expiry();

		// Restore exact prior policy through the normal save funnel (snapshots undo-the-undo).
		if ( ! empty( $before ) ) {
			Policy::save_policy( $before );
		}

		$actor = Policy_Snapshots::detect_actor();
		Policy_Snapshots::append_history(
			array(
				'ts'      => $now,
				'actor'   => $actor,
				'changes' => array(
					sprintf(
						'Break glass ended (%s). Prior policy restored.',
						$cause
					),
				),
				'summary' => sprintf( 'Break glass ended (%s)', $cause ),
			)
		);

		$state['active']       = false;
		$state['closed_cause'] = $cause;
		$state['closed_ts']    = $now;
		// Keep last closed record briefly for status/debug; clear policy blob to shrink option.
		unset( $state['policy_before'] );
		update_option( self::OPTION_KEY, $state, false );

		$body = 'expired' === $cause
			? __( 'Break glass ended. The previous policy was restored automatically.', 'handl-ai-connector-access-control' )
			: __( 'Break glass was cancelled. The previous policy was restored.', 'handl-ai-connector-access-control' );
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
		$subject = __( 'HandL AI Connector Access Control — Break glass', 'handl-ai-connector-access-control' );
		Alerts::safe_wp_mail( $to, $subject, $body );
	}
}
