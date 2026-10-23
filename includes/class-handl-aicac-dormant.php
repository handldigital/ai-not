<?php
/**
 * AICAC-DORMANT (#353): suspend AI access for users with no AI activity in N days.
 *
 * Reads handl_aicac_recent_calls attribution read-only. Weekly sweep marks
 * dormant users; enforcement hooks wp_ai_client_prevent_prompt at the same
 * priority USER-QUOTA uses (after Policy). Suspended callers get Access_Request
 * note_deny so the existing re-request path works. Lift via admin action or when
 * an access request for that user is approved.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Per-user dormancy suspend / unsuspend.
 */
final class Dormant {

	public const REASON = 'dormant';

	public const CRON_HOOK = 'handl_aicac_dormant_sweep';

	/** user_id => { ts, days, who } */
	public const STATE_OPTION = 'handl_aicac_dormant_suspended';

	/** Positive int days; 0 = feature off. */
	public const DAYS_OPTION = 'handl_aicac_dormant_days';

	public const NOTICE_OPTION = 'handl_aicac_dormant_notice';

	public const DEFAULT_DAYS = 90;

	public const FILTER_PRIORITY = 2;

	public const POST_PRESENT = 'handl_aicac_dormant_present';

	public const POST_DAYS = 'handl_aicac_dormant_days';

	public const ACTION_DISMISS = 'handl_aicac_dormant_dismiss';

	public const ACTION_LIFT = 'handl_aicac_dormant_lift';

	public const CHANNEL = 'dormant';

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_filter( 'wp_ai_client_prevent_prompt', array( self::class, 'maybe_prevent_prompt' ), self::FILTER_PRIORITY, 2 );
		add_action( self::CRON_HOOK, array( self::class, 'cron_sweep' ) );
		add_action( 'init', array( self::class, 'maybe_schedule' ), 40 );
		add_action( 'handl_aicac_protections_settings', array( self::class, 'render_settings' ) );
		add_filter( 'pre_update_option_' . Plugin::OPTION_KEY, array( self::class, 'capture_days_on_policy_save' ), 10, 2 );
		add_action( 'updated_option_' . Access_Request::OPTION_KEY, array( self::class, 'on_access_requests_updated' ), 10, 2 );
		add_action( 'admin_post_' . self::ACTION_DISMISS, array( self::class, 'handle_dismiss' ) );
		add_action( 'admin_post_' . self::ACTION_LIFT, array( self::class, 'handle_lift' ) );
		if ( function_exists( 'is_admin' ) && is_admin() ) {
			add_action( 'admin_notices', array( self::class, 'maybe_render_notice' ) );
			add_action( 'admin_notices', array( self::class, 'maybe_render_suspended_user_notice' ) );
			add_filter( 'manage_users_columns', array( self::class, 'users_column' ) );
			add_filter( 'manage_users_custom_column', array( self::class, 'users_column_content' ), 10, 3 );
		}
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		delete_option( self::STATE_OPTION );
		delete_option( self::DAYS_OPTION );
		delete_option( self::NOTICE_OPTION );
		if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
			wp_clear_scheduled_hook( self::CRON_HOOK );
		}
	}

	public static function maybe_schedule(): void {
		if ( ! function_exists( 'wp_next_scheduled' ) || ! function_exists( 'wp_schedule_event' ) ) {
			return;
		}
		if ( wp_next_scheduled( self::CRON_HOOK ) ) {
			return;
		}
		wp_schedule_event( time() + HOUR_IN_SECONDS, 'weekly', self::CRON_HOOK );
	}

	/**
	 * Days window. 0 disables. Filterable.
	 */
	public static function days_window(): int {
		$stored = get_option( self::DAYS_OPTION, self::DEFAULT_DAYS );
		$days   = self::sanitize_days( $stored );
		if ( function_exists( 'apply_filters' ) ) {
			$days = self::sanitize_days( apply_filters( 'handl_aicac_dormant_days', $days ) );
		}

		return $days;
	}

	/**
	 * @param mixed $raw Raw days.
	 */
	public static function sanitize_days( $raw ): int {
		if ( null === $raw || false === $raw || '' === $raw ) {
			return self::DEFAULT_DAYS;
		}
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_DAYS;
		}
		$v = (int) $raw;
		if ( $v < 0 ) {
			$v = 0;
		}
		if ( $v > 3650 ) {
			$v = 3650;
		}

		return $v;
	}

	public static function save_days( int $days ): void {
		$days = self::sanitize_days( $days );
		if ( self::DEFAULT_DAYS === $days ) {
			delete_option( self::DAYS_OPTION );
			return;
		}
		update_option( self::DAYS_OPTION, $days, false );
	}

	/**
	 * @return array<int,array{ts:int,days:int,who:string}>
	 */
	public static function get_suspended_map(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw state.
	 * @return array<int,array{ts:int,days:int,who:string}>
	 */
	public static function sanitize_state( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $uid => $row ) {
			$uid = (int) $uid;
			if ( $uid <= 0 || ! is_array( $row ) ) {
				continue;
			}
			$out[ $uid ] = array(
				'ts'   => isset( $row['ts'] ) ? (int) $row['ts'] : 0,
				'days' => isset( $row['days'] ) ? (int) $row['days'] : 0,
				'who'  => sanitize_text_field( (string) ( $row['who'] ?? '' ) ),
			);
		}

		return $out;
	}

	/**
	 * @param array<int,array{ts:int,days:int,who:string}> $map State map.
	 */
	public static function save_suspended_map( array $map ): void {
		$map = self::sanitize_state( $map );
		if ( empty( $map ) ) {
			delete_option( self::STATE_OPTION );
			return;
		}
		update_option( self::STATE_OPTION, $map, false );
	}

	public static function is_suspended( int $user_id ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}
		$map = self::get_suspended_map();

		return isset( $map[ $user_id ] );
	}

	/**
	 * Last AI activity ts per user_id from recent_calls (read-only).
	 *
	 * @return array<int,int> user_id => last ts
	 */
	public static function last_activity_map( ?array $log = null ): array {
		if ( null === $log ) {
			$raw = get_option( Plugin::LOG_OPTION_KEY, array() );
			$log = is_array( $raw ) ? $raw : array();
		}
		$out = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$uid = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
			if ( $uid <= 0 ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				continue;
			}
			if ( ! isset( $out[ $uid ] ) || $ts > $out[ $uid ] ) {
				$out[ $uid ] = $ts;
			}
		}

		return $out;
	}

	/**
	 * Candidate user ids that currently hold AI grants (role gate) or appear in the log.
	 *
	 * @return list<int>
	 */
	public static function candidate_user_ids( ?array $policy = null ): array {
		$policy = is_array( $policy ) ? $policy : Policy::get_policy();
		$ids    = array();

		if ( ! empty( $policy['role_gate_enabled'] ) ) {
			$allowed = Policy::sanitize_allowed_roles( $policy['allowed_roles'] ?? array() );
			foreach ( self::users_with_roles( $allowed ) as $uid ) {
				$ids[ $uid ] = true;
			}
		}

		foreach ( array_keys( self::last_activity_map() ) as $uid ) {
			$ids[ (int) $uid ] = true;
		}
		foreach ( array_keys( self::get_suspended_map() ) as $uid ) {
			$ids[ (int) $uid ] = true;
		}

		if ( function_exists( 'apply_filters' ) ) {
			$extra = apply_filters( 'handl_aicac_dormant_candidate_user_ids', array_keys( $ids ), $policy );
			if ( is_array( $extra ) ) {
				$ids = array();
				foreach ( $extra as $uid ) {
					$uid = (int) $uid;
					if ( $uid > 0 ) {
						$ids[ $uid ] = true;
					}
				}
			}
		}

		$out = array_map( 'intval', array_keys( $ids ) );
		sort( $out );

		return $out;
	}

	/**
	 * @param list<string> $roles Role slugs.
	 * @return list<int>
	 */
	public static function users_with_roles( array $roles ): array {
		$roles = array_values(
			array_filter(
				array_map(
					static function ( $r ) {
						return sanitize_key( (string) $r );
					},
					$roles
				)
			)
		);
		if ( empty( $roles ) ) {
			return array();
		}

		if ( ! empty( $GLOBALS['handl_aicac_test_users'] ) && is_array( $GLOBALS['handl_aicac_test_users'] ) ) {
			$out = array();
			foreach ( $GLOBALS['handl_aicac_test_users'] as $uid => $row ) {
				if ( ! is_array( $row ) || empty( $row['roles'] ) || ! is_array( $row['roles'] ) ) {
					continue;
				}
				foreach ( $row['roles'] as $r ) {
					if ( in_array( sanitize_key( (string) $r ), $roles, true ) ) {
						$out[] = (int) $uid;
						break;
					}
				}
			}

			return $out;
		}

		if ( function_exists( 'get_users' ) ) {
			$users = get_users(
				array(
					'role__in' => $roles,
					'fields'   => 'ID',
					'number'   => 500,
				)
			);
			if ( is_array( $users ) ) {
				return array_map( 'intval', $users );
			}
		}

		return array();
	}

	/**
	 * Baseline ts when the log has no activity: user_registered, else 0 (skip).
	 */
	public static function baseline_ts( int $user_id ): int {
		if ( $user_id <= 0 ) {
			return 0;
		}
		if ( ! empty( $GLOBALS['handl_aicac_test_users'][ $user_id ]['user_registered'] ) ) {
			$raw = $GLOBALS['handl_aicac_test_users'][ $user_id ]['user_registered'];
			if ( is_numeric( $raw ) ) {
				return (int) $raw;
			}
			$parsed = strtotime( (string) $raw );
			return false !== $parsed ? $parsed : 0;
		}
		if ( function_exists( 'get_userdata' ) ) {
			$user = get_userdata( $user_id );
			if ( $user && ! empty( $user->user_registered ) ) {
				$parsed = strtotime( (string) $user->user_registered );
				return false !== $parsed ? $parsed : 0;
			}
		}

		return 0;
	}

	public static function cron_sweep(): void {
		self::sweep( time() );
	}

	/**
	 * @return array{suspended:list<int>,skipped:int}
	 */
	public static function sweep( ?int $now = null ): array {
		$now  = null !== $now ? (int) $now : time();
		$days = self::days_window();
		if ( $days <= 0 ) {
			return array(
				'suspended' => array(),
				'skipped'   => 0,
			);
		}

		$window    = $days * DAY_IN_SECONDS;
		$cutoff    = $now - $window;
		$activity  = self::last_activity_map();
		$suspended = array();
		$skipped   = 0;

		foreach ( self::candidate_user_ids() as $uid ) {
			if ( self::is_suspended( $uid ) ) {
				++$skipped;
				continue;
			}
			$last = isset( $activity[ $uid ] ) ? (int) $activity[ $uid ] : self::baseline_ts( $uid );
			if ( $last <= 0 ) {
				++$skipped;
				continue;
			}
			if ( $last > $cutoff ) {
				++$skipped;
				continue;
			}
			$idle_days = (int) floor( ( $now - $last ) / DAY_IN_SECONDS );
			if ( $idle_days < $days ) {
				$idle_days = $days;
			}
			$result = self::suspend_user( $uid, $idle_days, $now );
			if ( ! empty( $result['suspended'] ) ) {
				$suspended[] = $uid;
			} else {
				++$skipped;
			}
		}

		if ( ! empty( $suspended ) ) {
			self::store_notice( $suspended, $now );
		}

		return array(
			'suspended' => $suspended,
			'skipped'   => $skipped,
		);
	}

	/**
	 * @return array{suspended:bool,who:string,days:int}
	 */
	public static function suspend_user( int $user_id, int $days_idle, ?int $now = null ): array {
		$empty = array(
			'suspended' => false,
			'who'       => '',
			'days'      => 0,
		);
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return $empty;
		}
		if ( self::is_suspended( $user_id ) ) {
			$row = self::get_suspended_map()[ $user_id ];

			return array(
				'suspended' => false,
				'who'       => $row['who'],
				'days'      => $row['days'],
			);
		}

		$now  = null !== $now ? (int) $now : time();
		$who  = self::display_name_for( $user_id );
		$days = max( 0, (int) $days_idle );
		$map  = self::get_suspended_map();
		$map[ $user_id ] = array(
			'ts'   => $now,
			'days' => $days,
			'who'  => $who,
		);
		self::save_suspended_map( $map );

		self::append_audit(
			$user_id,
			$who,
			'suspend',
			sprintf( '%s dormant %d day%s — AI access suspended', $who !== '' ? $who : ( 'user#' . $user_id ), $days, 1 === $days ? '' : 's' ),
			$days,
			$now
		);

		return array(
			'suspended' => true,
			'who'       => $who,
			'days'      => $days,
		);
	}

	/**
	 * @return array{lifted:bool,who:string}
	 */
	public static function lift_user( int $user_id, string $via = 'admin', int $actor_id = 0, ?int $now = null ): array {
		$empty = array(
			'lifted' => false,
			'who'    => '',
		);
		$user_id = (int) $user_id;
		if ( $user_id <= 0 || ! self::is_suspended( $user_id ) ) {
			return $empty;
		}
		$now  = null !== $now ? (int) $now : time();
		$map  = self::get_suspended_map();
		$who  = $map[ $user_id ]['who'] !== '' ? $map[ $user_id ]['who'] : self::display_name_for( $user_id );
		$days = (int) $map[ $user_id ]['days'];
		unset( $map[ $user_id ] );
		self::save_suspended_map( $map );

		$via = sanitize_key( $via );
		if ( '' === $via ) {
			$via = 'admin';
		}

		self::append_audit(
			$user_id,
			$who,
			'lift',
			sprintf( '%s dormant suspension lifted (%s)', $who !== '' ? $who : ( 'user#' . $user_id ), $via ),
			$days,
			$now,
			$actor_id,
			$via
		);

		return array(
			'lifted' => true,
			'who'    => $who,
		);
	}

	/**
	 * Gate filter after Policy (priority 2).
	 *
	 * @param mixed $prevent Prior filter result.
	 * @param mixed $builder Prompt builder.
	 */
	public static function maybe_prevent_prompt( $prevent, $builder ): bool {
		if ( $prevent ) {
			return true;
		}
		if ( self::days_window() <= 0 ) {
			return false;
		}

		$policy = Policy::get_policy();
		if ( ! empty( $policy['audit_only'] ) ) {
			return false;
		}
		if ( class_exists( Break_Glass::class, false ) && Break_Glass::is_active() ) {
			return false;
		}

		$user_id = Policy::current_user_id_for_gate();
		if ( $user_id <= 0 || ! self::is_suspended( $user_id ) ) {
			return false;
		}

		$now      = Clock::now();
		$attrib   = Attribution::resolve_from_backtrace();
		$plugin   = is_string( $attrib['plugin'] ?? null ) ? (string) $attrib['plugin'] : null;
		$snapshot = class_exists( Prompt_Snapshot::class, false ) ? Prompt_Snapshot::from_builder( $builder ) : array();
		$operation = isset( $snapshot['operation'] ) ? (string) $snapshot['operation'] : '';
		$family    = isset( $snapshot['capability_family'] ) && is_string( $snapshot['capability_family'] )
			? (string) $snapshot['capability_family']
			: ( class_exists( Operations::class, false ) ? Operations::family_from_operation( $operation ) : '' );

		$row = self::get_suspended_map()[ $user_id ] ?? array();
		$event = array_merge(
			array(
				'ts'                => $now,
				'plugin'            => $plugin,
				'file'              => $attrib['file'] ?? null,
				'caller'            => $attrib['method'] ?? null,
				'decision'          => 'deny',
				'would_decision'    => 'deny',
				'capability_family' => $family,
				'denial_reason'     => self::REASON,
				'decision_source'   => self::REASON,
				'user_id'           => $user_id,
				'user_role'         => Policy::current_user_role_for_log(),
				'dormant'           => true,
				'dormant_days'      => isset( $row['days'] ) ? (int) $row['days'] : 0,
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

		$suppress = class_exists( Retry_Storm::class, false ) && Retry_Storm::should_suppress_deny_alert( $event, $policy );
		if ( class_exists( Alerts::class, false ) && ! $suppress ) {
			Alerts::maybe_notify_denial( $event, $policy );
		}
		if ( class_exists( Access_Request::class, false ) ) {
			Access_Request::note_deny( $event );
		}

		return $soft ? false : true;
	}

	/**
	 * @param array<string,mixed> $event Deny event.
	 */
	public static function reclassify_latest_allow( array $event ): void {
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
		if ( (int) ( $last['user_id'] ?? 0 ) !== (int) ( $event['user_id'] ?? 0 ) ) {
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

	/**
	 * When an access request is approved for a suspended user, lift them.
	 *
	 * @param mixed $old Previous option.
	 * @param mixed $new New option.
	 */
	public static function on_access_requests_updated( $old, $new ): void {
		if ( ! is_array( $new ) ) {
			return;
		}
		$old = is_array( $old ) ? $old : array();
		foreach ( $new as $id => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$status = (string) ( $row['status'] ?? '' );
			if ( Access_Request::STATUS_APPROVED !== $status ) {
				continue;
			}
			$prev = isset( $old[ $id ] ) && is_array( $old[ $id ] ) ? $old[ $id ] : array();
			if ( Access_Request::STATUS_APPROVED === (string) ( $prev['status'] ?? '' ) ) {
				continue;
			}
			$uid = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
			if ( $uid > 0 && self::is_suspended( $uid ) ) {
				$actor = isset( $row['resolved_by'] ) ? (int) $row['resolved_by'] : 0;
				self::lift_user( $uid, 'access_request', $actor, isset( $row['resolved_ts'] ) ? (int) $row['resolved_ts'] : time() );
			}
		}
	}

	/**
	 * @param mixed $value New policy value.
	 * @param mixed $old   Old policy value.
	 * @return mixed
	 */
	public static function capture_days_on_policy_save( $value, $old ) {
		unset( $old );
		if ( ! isset( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Admin save already verified the form nonce.
			return $value;
		}
		$raw = isset( $_POST[ self::POST_DAYS ] ) ? wp_unslash( $_POST[ self::POST_DAYS ] ) : self::DEFAULT_DAYS; // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		self::save_days( self::sanitize_days( $raw ) );

		return $value;
	}

	/**
	 * @param array<string,mixed> $policy Policy.
	 */
	public static function render_settings( $policy ): void {
		unset( $policy );
		$days = self::days_window();
		echo '<tr id="handl-aicac-dormant">';
		echo '<th scope="row">' . esc_html__( 'Dormant AI access', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
		echo '<label for="handl-aicac-dormant-days">' . esc_html__( 'Suspend after idle days', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<input type="number" min="0" max="3650" class="small-text" id="handl-aicac-dormant-days" name="' . esc_attr( self::POST_DAYS ) . '" value="' . esc_attr( (string) $days ) . '" />';
		echo '<p class="description">' . esc_html__( 'Users with no logged AI activity for this many days lose AI access until they re-request or an admin lifts the suspension. Set to 0 to disable.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td></tr>';
	}

	public static function maybe_render_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$raw = get_option( self::NOTICE_OPTION, null );
		if ( ! is_array( $raw ) || empty( $raw['summary'] ) ) {
			return;
		}
		$summary = sanitize_text_field( (string) $raw['summary'] );
		if ( '' === $summary ) {
			return;
		}
		$dismiss = wp_nonce_url(
			admin_url( 'admin-post.php?action=' . self::ACTION_DISMISS ),
			self::ACTION_DISMISS
		);
		echo '<div class="notice notice-warning is-dismissible"><p>';
		echo esc_html(
			sprintf(
				/* translators: %s: dormant summary */
				__( 'HandL dormant AI access: %s', 'handl-ai-connector-access-control' ),
				$summary
			)
		);
		echo '</p><p><a href="' . esc_url( $dismiss ) . '">' . esc_html__( 'Dismiss', 'handl-ai-connector-access-control' ) . '</a></p></div>';
	}

	public static function maybe_render_suspended_user_notice(): void {
		$user_id = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
		if ( $user_id <= 0 || ! self::is_suspended( $user_id ) ) {
			return;
		}
		if ( ! current_user_can( 'edit_posts' ) ) {
			return;
		}
		$row  = self::get_suspended_map()[ $user_id ];
		$days = (int) ( $row['days'] ?? 0 );
		echo '<div class="notice notice-warning"><p>';
		echo esc_html(
			sprintf(
				/* translators: %d: idle days */
				__( 'Your AI access is suspended after %d days without AI activity. Request access again from the next blocked AI notice, or ask an administrator to lift the suspension.', 'handl-ai-connector-access-control' ),
				$days
			)
		);
		echo '</p></div>';
	}

	public static function handle_dismiss(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You cannot dismiss this notice.', 'handl-ai-connector-access-control' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION_DISMISS );
		delete_option( self::NOTICE_OPTION );
		self::redirect_settings();
	}

	public static function handle_lift(): void {
		if ( ! current_user_can( Caps::MANAGE ) && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You cannot lift this suspension.', 'handl-ai-connector-access-control' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION_LIFT );
		$user_id = isset( $_GET['user_id'] ) ? (int) $_GET['user_id'] : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$actor   = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
		self::lift_user( $user_id, 'admin', $actor, time() );
		$dest = admin_url( 'users.php' );
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $dest );
			exit;
		}
		wp_redirect( $dest ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
		exit;
	}

	/**
	 * @param array<string,string> $columns Users columns.
	 * @return array<string,string>
	 */
	public static function users_column( $columns ) {
		if ( ! is_array( $columns ) ) {
			$columns = array();
		}
		if ( ! current_user_can( Caps::MANAGE ) && ! current_user_can( 'manage_options' ) ) {
			return $columns;
		}
		if ( empty( self::get_suspended_map() ) ) {
			return $columns;
		}
		$columns['handl_aicac_dormant'] = __( 'AI dormant', 'handl-ai-connector-access-control' );

		return $columns;
	}

	/**
	 * @param string $output      Column HTML.
	 * @param string $column_name Column key.
	 * @param int    $user_id     User ID.
	 */
	public static function users_column_content( $output, $column_name, $user_id ) {
		if ( 'handl_aicac_dormant' !== $column_name ) {
			return $output;
		}
		$user_id = (int) $user_id;
		if ( ! self::is_suspended( $user_id ) ) {
			return '—';
		}
		$lift = wp_nonce_url(
			admin_url( 'admin-post.php?action=' . self::ACTION_LIFT . '&user_id=' . $user_id ),
			self::ACTION_LIFT
		);

		return '<a href="' . esc_url( $lift ) . '">' . esc_html__( 'Suspended — lift', 'handl-ai-connector-access-control' ) . '</a>';
	}

	/**
	 * @param list<int> $user_ids Newly suspended.
	 */
	private static function store_notice( array $user_ids, int $now ): void {
		$names = array();
		foreach ( $user_ids as $uid ) {
			$map = self::get_suspended_map();
			$who = isset( $map[ $uid ]['who'] ) && '' !== $map[ $uid ]['who']
				? $map[ $uid ]['who']
				: ( 'user#' . (string) (int) $uid );
			$names[] = $who;
		}
		$summary = sprintf(
			'%d user%s suspended for dormant AI access (%s)',
			count( $names ),
			1 === count( $names ) ? '' : 's',
			implode( ', ', $names )
		);
		update_option(
			self::NOTICE_OPTION,
			array(
				'summary' => sanitize_text_field( $summary ),
				'ts'      => $now,
			),
			false
		);
	}

	private static function redirect_settings(): void {
		$dest = admin_url( 'options-general.php?page=handl-aicac' );
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $dest );
			exit;
		}
		wp_redirect( $dest ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
		exit;
	}

	private static function display_name_for( int $user_id ): string {
		if ( $user_id <= 0 ) {
			return '';
		}
		if ( ! empty( $GLOBALS['handl_aicac_test_users'][ $user_id ]['user_login'] ) ) {
			return sanitize_text_field( (string) $GLOBALS['handl_aicac_test_users'][ $user_id ]['user_login'] );
		}
		if ( function_exists( 'get_userdata' ) ) {
			$user = get_userdata( $user_id );
			if ( $user && ! empty( $user->user_login ) ) {
				return sanitize_text_field( (string) $user->user_login );
			}
		}

		return '';
	}

	private static function append_audit(
		int $user_id,
		string $who,
		string $action,
		string $summary,
		int $days,
		int $now,
		int $actor_id = 0,
		string $via = ''
	): void {
		Policy::append_log_event(
			array(
				'ts'             => $now,
				'plugin'         => '',
				'decision'       => 'dormant',
				'channel'        => self::CHANNEL,
				'source'         => 'system',
				'actor_id'       => $actor_id,
				'user_id'        => $user_id,
				'user_login'     => $who,
				'dormant_action' => sanitize_key( $action ),
				'dormant_days'   => $days,
				'dormant_via'    => sanitize_key( $via ),
				'summary'        => $summary,
				'operation'      => '',
				'provider'       => '',
			)
		);
	}
}
