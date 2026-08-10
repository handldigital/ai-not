<?php
/**
 * First-run onboarding wizard (AICAC-ONBOARD).
 *
 * Guided path over existing policy setters — not a parallel settings store.
 * Wizard progress lives in a dedicated option; policy writes use Policy::save_policy().
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Onboarding {
	public const OPTION_KEY = 'handl_aicac_onboard';

	public const STATUS_ACTIVE    = 'active';
	public const STATUS_DISMISSED = 'dismissed';
	public const STATUS_COMPLETE  = 'complete';
	public const STATUS_INELIGIBLE = 'ineligible';

	public const MODE_OBSERVE = 'observe';
	public const MODE_ENFORCE = 'enforce';

	public const DEFAULT_OBSERVE_DAYS = 14;
	public const MIN_OBSERVE_DAYS     = 7;
	public const MAX_OBSERVE_DAYS     = 14;

	/**
	 * Raw policy option missing → fresh install (upgrade installs always have a stored option).
	 */
	public static function is_fresh_install(): bool {
		$raw = get_option( Plugin::OPTION_KEY, null );
		return null === $raw || false === $raw;
	}

	/**
	 * Multisite network-enforced policy (#84 readiness). Default false until network lock ships.
	 */
	public static function is_network_enforced(): bool {
		/**
		 * Filter whether site admins may change enforcement mode in the onboarding wizard.
		 *
		 * @param bool $enforced Whether network policy locks mode.
		 */
		return (bool) apply_filters( 'handl_aicac_onboard_network_enforced', false );
	}

	/**
	 * @return array{
	 *   status:string,
	 *   eligible:bool,
	 *   step:int,
	 *   mode:string,
	 *   observe_days:int,
	 *   review_due_ts:int
	 * }
	 */
	public static function get_state(): array {
		$raw = get_option( self::OPTION_KEY, null );
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}
		return self::sanitize_state( $raw );
	}

	/**
	 * @param array<string,mixed> $state
	 */
	public static function save_state( array $state ): void {
		update_option( self::OPTION_KEY, self::sanitize_state( $state ), false );
	}

	/**
	 * Ensure a durable eligibility decision exists (once).
	 *
	 * Fresh installs become eligible/active; upgrades are marked ineligible and never auto-show.
	 *
	 * @return array<string,mixed>
	 */
	public static function ensure_initialized(): array {
		$existing = get_option( self::OPTION_KEY, null );
		if ( is_array( $existing ) ) {
			return self::sanitize_state( $existing );
		}

		if ( self::is_fresh_install() ) {
			$state = self::sanitize_state(
				array(
					'status'   => self::STATUS_ACTIVE,
					'eligible' => true,
					'step'     => 1,
				)
			);
		} else {
			$state = self::sanitize_state(
				array(
					'status'   => self::STATUS_INELIGIBLE,
					'eligible' => false,
					'step'     => 1,
				)
			);
		}
		self::save_state( $state );
		return $state;
	}

	/**
	 * Auto-open wizard on Dashboard (fresh + active only).
	 */
	public static function should_auto_show( ?array $state = null ): bool {
		$state = $state ?? self::ensure_initialized();
		return ! empty( $state['eligible'] ) && self::STATUS_ACTIVE === (string) ( $state['status'] ?? '' );
	}

	/**
	 * Dashboard link to reopen after dismiss/complete (eligible installs only).
	 */
	public static function should_show_reentry( ?array $state = null ): bool {
		$state = $state ?? self::ensure_initialized();
		if ( empty( $state['eligible'] ) ) {
			return false;
		}
		$status = (string) ( $state['status'] ?? '' );
		return self::STATUS_DISMISSED === $status || self::STATUS_COMPLETE === $status;
	}

	/**
	 * @param array<string,mixed> $state
	 */
	public static function should_render_wizard( array $state, bool $force_reopen = false ): bool {
		if ( empty( $state['eligible'] ) ) {
			return false;
		}
		if ( $force_reopen ) {
			return true;
		}
		return self::STATUS_ACTIVE === (string) ( $state['status'] ?? '' );
	}

	/**
	 * Apply mode choice onto a policy array (caller saves via Policy::save_policy).
	 *
	 * @param array<string,mixed> $policy
	 * @return array<string,mixed>
	 */
	public static function apply_mode_to_policy( array $policy, string $mode, int $observe_days = self::DEFAULT_OBSERVE_DAYS ): array {
		$mode = self::sanitize_mode( $mode );
		$days = self::sanitize_observe_days( $observe_days );

		if ( self::MODE_OBSERVE === $mode ) {
			$policy['audit_only']       = true;
			$policy['log_enabled']      = true;
			$policy['log_max_age_days'] = $days;
			return $policy;
		}

		// Enforce now: turn off learn mode; keep logging on so Activity stays useful.
		$policy['audit_only']  = false;
		$policy['log_enabled'] = true;
		return $policy;
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array<string,mixed>
	 */
	public static function apply_alerts_to_policy( array $policy, string $email, bool $enable_deny_alerts ): array {
		$policy['alert_email']   = Alerts::sanitize_email( $email );
		$policy['alert_on_deny'] = $enable_deny_alerts;
		if ( $enable_deny_alerts && '' === (string) ( $policy['alert_mode'] ?? '' ) ) {
			$policy['alert_mode'] = 'immediate';
		}
		return $policy;
	}

	public static function review_due_timestamp( int $observe_days, ?int $now = null ): int {
		$now  = null === $now ? time() : $now;
		$days = self::sanitize_observe_days( $observe_days );
		return $now + ( $days * DAY_IN_SECONDS );
	}

	/**
	 * @param array<string,mixed> $state
	 */
	public static function should_show_review_notice( array $state, ?int $now = null ): bool {
		$now = null === $now ? time() : $now;
		if ( empty( $state['eligible'] ) ) {
			return false;
		}
		if ( self::STATUS_COMPLETE !== (string) ( $state['status'] ?? '' ) ) {
			return false;
		}
		$due = (int) ( $state['review_due_ts'] ?? 0 );
		return $due > 0 && $now >= $due;
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_mode( $raw ): string {
		$mode = sanitize_key( (string) $raw );
		return in_array( $mode, array( self::MODE_OBSERVE, self::MODE_ENFORCE ), true )
			? $mode
			: self::MODE_OBSERVE;
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_observe_days( $raw ): int {
		$n = (int) $raw;
		if ( $n < self::MIN_OBSERVE_DAYS ) {
			$n = self::DEFAULT_OBSERVE_DAYS;
		}
		if ( $n > self::MAX_OBSERVE_DAYS ) {
			$n = self::MAX_OBSERVE_DAYS;
		}
		return $n;
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_step( $raw ): int {
		$n = (int) $raw;
		if ( $n < 1 ) {
			$n = 1;
		}
		if ( $n > 3 ) {
			$n = 3;
		}
		return $n;
	}

	/**
	 * @param array<string,mixed> $raw
	 * @return array{
	 *   status:string,
	 *   eligible:bool,
	 *   step:int,
	 *   mode:string,
	 *   observe_days:int,
	 *   review_due_ts:int
	 * }
	 */
	public static function sanitize_state( array $raw ): array {
		$status = sanitize_key( (string) ( $raw['status'] ?? self::STATUS_INELIGIBLE ) );
		$allowed = array(
			self::STATUS_ACTIVE,
			self::STATUS_DISMISSED,
			self::STATUS_COMPLETE,
			self::STATUS_INELIGIBLE,
		);
		if ( ! in_array( $status, $allowed, true ) ) {
			$status = self::STATUS_INELIGIBLE;
		}

		$mode = sanitize_key( (string) ( $raw['mode'] ?? '' ) );
		if ( '' !== $mode && ! in_array( $mode, array( self::MODE_OBSERVE, self::MODE_ENFORCE ), true ) ) {
			$mode = '';
		}

		return array(
			'status'         => $status,
			'eligible'       => ! empty( $raw['eligible'] ),
			'step'           => self::sanitize_step( $raw['step'] ?? 1 ),
			'mode'           => $mode,
			'observe_days'   => self::sanitize_observe_days( $raw['observe_days'] ?? self::DEFAULT_OBSERVE_DAYS ),
			'review_due_ts'  => max( 0, (int) ( $raw['review_due_ts'] ?? 0 ) ),
		);
	}
}
