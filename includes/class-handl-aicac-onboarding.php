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

	public const STEP_COUNT = 4;

	public const STEP_SCAN = 4;

	public const SCAN_NONE = '';

	public const SCAN_RAN = 'ran';

	public const SCAN_SKIPPED = 'skipped';

	public const SCAN_ERROR = 'error';

	public const SCAN_HEADING = '4. Plugins that mention AI';

	public const SCAN_PROGRESS = 'Scanning installed plugins and themes…';

	public const SCAN_SKIP = 'Skip this scan';

	public const SCAN_ERROR_COPY = 'Could not read some plugin or theme files. You can finish setup anyway.';

	public const FILTER_SCAN_ERROR = 'handl_aicac_onboard_scan_error';

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
	 *   review_due_ts:int,
	 *   leads_consent:bool,
	 *   scan_status:string
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
		if ( $n > self::STEP_COUNT ) {
			$n = self::STEP_COUNT;
		}
		return $n;
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_scan_status( $raw ): string {
		$status = sanitize_key( (string) $raw );
		$ok     = array( self::SCAN_NONE, self::SCAN_RAN, self::SCAN_SKIPPED, self::SCAN_ERROR );
		if ( '' === $status ) {
			return self::SCAN_NONE;
		}

		return in_array( $status, $ok, true ) ? $status : self::SCAN_NONE;
	}

	/**
	 * @param array<string,mixed> $raw
	 * @return array{
	 *   status:string,
	 *   eligible:bool,
	 *   step:int,
	 *   mode:string,
	 *   observe_days:int,
	 *   review_due_ts:int,
	 *   leads_consent:bool,
	 *   scan_status:string
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
			// Opt-in product news / cross-promo (AICAC-LEADS). Never default true.
			'leads_consent'  => ! empty( $raw['leads_consent'] ),
			'scan_status'    => self::sanitize_scan_status( $raw['scan_status'] ?? self::SCAN_NONE ),
		);
	}

	/**
	 * Run or reuse the #305 bulk scanner. Never throws.
	 *
	 * @return array{ok:bool,reused:bool,error:string,run:array<string,mixed>}
	 */
	public static function run_site_scan(): array {
		$forced = function_exists( 'apply_filters' ) ? apply_filters( self::FILTER_SCAN_ERROR, false ) : false;
		if ( $forced ) {
			return array(
				'ok'     => false,
				'reused' => false,
				'error'  => self::SCAN_ERROR_COPY,
				'run'    => array(),
			);
		}
		if ( class_exists( Preflight_Scan::class ) && Preflight_Scan::has_last_run() ) {
			return array(
				'ok'     => true,
				'reused' => true,
				'error'  => '',
				'run'    => Preflight_Scan::last_run(),
			);
		}
		try {
			$run = class_exists( Preflight_Scan::class ) ? Preflight_Scan::scan_all() : array();
			return array(
				'ok'     => true,
				'reused' => false,
				'error'  => '',
				'run'    => is_array( $run ) ? $run : array(),
			);
		} catch ( \Throwable $e ) {
			unset( $e );
			return array(
				'ok'     => false,
				'reused' => false,
				'error'  => self::SCAN_ERROR_COPY,
				'run'    => array(),
			);
		}
	}

	/**
	 * Mark the wizard complete. Lead POST failures never block finish.
	 *
	 * @param array<string,mixed> $state
	 * @return array<string,mixed>
	 */
	public static function complete( array $state ): array {
		$state = self::sanitize_state( $state );
		$state['step']   = self::STEP_SCAN;
		$state['status'] = self::STATUS_COMPLETE;
		self::save_state( $state );
		if ( ! empty( $state['leads_consent'] ) && class_exists( Leads::class ) && class_exists( Policy::class ) && class_exists( Alerts::class ) ) {
			$policy = Policy::get_policy();
			$email  = Alerts::sanitize_email( $policy['alert_email'] ?? '' );
			Leads::maybe_register( $email, true );
		}

		return self::get_state();
	}

	/**
	 * @param array<string,mixed> $state
	 */
	public static function render_scan_step( array $state ): void {
		$status = self::sanitize_scan_status( $state['scan_status'] ?? self::SCAN_NONE );
		echo '<h3>' . esc_html__( '4. Plugins that mention AI', 'handl-ai-connector-access-control' ) . '</h3>';
		echo '<p class="description">' . esc_html__( 'Reads installed plugin and theme files for known AI endpoints. This scan does not change rules and does not confirm that data was sent.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( self::SCAN_ERROR === $status ) {
			echo '<div class="notice notice-warning inline" style="padding:8px 12px;"><p>' . esc_html__( 'Could not read some plugin or theme files. You can finish setup anyway.', 'handl-ai-connector-access-control' ) . '</p></div>';
		} elseif ( self::SCAN_NONE === $status ) {
			echo '<p id="handl-aicac-onboard-scan-progress">' . esc_html__( 'Scanning installed plugins and themes…', 'handl-ai-connector-access-control' ) . '</p>';
			echo '<form method="post" id="handl-aicac-onboard-scan-form">';
			wp_nonce_field( 'handl_aicac_onboard', 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_action" value="onboard_step" />';
			echo '<input type="hidden" name="handl_aicac_tab" value="dashboard" />';
			echo '<input type="hidden" name="handl_aicac_onboard_step" value="' . esc_attr( (string) self::STEP_SCAN ) . '" />';
			echo '<input type="hidden" name="handl_aicac_onboard_scan_intent" value="scan" />';
			submit_button( __( 'Scan now', 'handl-ai-connector-access-control' ), 'primary', 'submit', false );
			echo '</form>';
			echo '<script>document.getElementById("handl-aicac-onboard-scan-form")&&document.getElementById("handl-aicac-onboard-scan-form").submit();</script>';
		} else {
			$run = class_exists( Preflight_Scan::class ) ? Preflight_Scan::last_run() : array();
			if ( class_exists( Preflight_Scan::class ) ) {
				Preflight_Scan::render_scan_all_results( is_array( $run ) ? $run : array() );
			}
		}

		echo '<div style="margin-top:1em;">';
		if ( self::SCAN_RAN === $status || self::SCAN_ERROR === $status ) {
			echo '<form method="post" style="display:inline;">';
			wp_nonce_field( 'handl_aicac_onboard', 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_action" value="onboard_step" />';
			echo '<input type="hidden" name="handl_aicac_tab" value="dashboard" />';
			echo '<input type="hidden" name="handl_aicac_onboard_step" value="' . esc_attr( (string) self::STEP_SCAN ) . '" />';
			echo '<input type="hidden" name="handl_aicac_onboard_scan_intent" value="finish" />';
			submit_button( __( 'Finish setup', 'handl-ai-connector-access-control' ), 'primary', 'submit', false );
			echo '</form> ';
		}
		echo '<form method="post" style="display:inline;">';
		wp_nonce_field( 'handl_aicac_onboard', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="onboard_step" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="dashboard" />';
		echo '<input type="hidden" name="handl_aicac_onboard_step" value="' . esc_attr( (string) self::STEP_SCAN ) . '" />';
		echo '<input type="hidden" name="handl_aicac_onboard_scan_intent" value="skip" />';
		submit_button( __( 'Skip this scan', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
		echo '</form>';
		echo '</div>';
	}
}
