<?php
/**
 * AICAC-OFFBOARD (#351): revoke AI grants when a user is deleted or demoted.
 *
 * Listens to deleted_user / set_user_role / remove_user_from_blog. Closes the
 * departed user's pending access requests, clears their request notice meta,
 * and drops temp-allows that were granted from their approved requests. Writes
 * one audit line naming exactly what they left with. Weekly orphan sweep cleans
 * access-request rows whose user_id no longer exists (plugin inactive at delete).
 *
 * Alert_Snooze is site-scoped (plugin → until), not per-user — cancel() is not
 * called on offboard (would unmute site-wide alerts for everyone). Orphan sweep
 * still runs Alert_Snooze::purge_expired() as hygiene.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Offboarding revocation + orphan sweep.
 */
final class Offboard {

	public const CRON_HOOK = 'handl_aicac_offboard_orphan_sweep';

	public const NOTICE_OPTION = 'handl_aicac_offboard_notice';

	public const ACTION_DISMISS = 'handl_aicac_offboard_dismiss';

	public const CHANNEL = 'offboard';

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'deleted_user', array( self::class, 'on_deleted_user' ), 20, 1 );
		add_action( 'set_user_role', array( self::class, 'on_set_user_role' ), 20, 3 );
		add_action( 'remove_user_from_blog', array( self::class, 'on_remove_user_from_blog' ), 20, 2 );
		add_action( self::CRON_HOOK, array( self::class, 'cron_orphan_sweep' ) );
		add_action( 'admin_post_' . self::ACTION_DISMISS, array( self::class, 'handle_dismiss' ) );
		if ( is_admin() ) {
			add_action( 'admin_notices', array( self::class, 'maybe_render_notice' ) );
		}
		add_action( 'init', array( self::class, 'maybe_schedule' ), 40 );
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
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
	 * @param int $user_id
	 */
	public static function on_deleted_user( $user_id ): void {
		self::revoke_user( (int) $user_id, 'deleted', null );
	}

	/**
	 * @param int    $user_id
	 * @param string $role
	 * @param array  $old_roles
	 */
	public static function on_set_user_role( $user_id, $role, $old_roles ): void {
		$user_id   = (int) $user_id;
		$role      = sanitize_key( (string) $role );
		$old_roles = is_array( $old_roles ) ? $old_roles : array();
		if ( $user_id <= 0 || ! self::is_demotion_losing_ai( $user_id, $role, $old_roles ) ) {
			return;
		}
		self::revoke_user( $user_id, 'demoted', self::display_name_for( $user_id ) );
	}

	/**
	 * @param int $user_id
	 * @param int $blog_id Unused.
	 */
	public static function on_remove_user_from_blog( $user_id, $blog_id ): void {
		unset( $blog_id );
		self::revoke_user( (int) $user_id, 'removed', self::display_name_for( (int) $user_id ) );
	}

	public static function cron_orphan_sweep(): void {
		self::sweep_orphans( time() );
	}

	/**
	 * Demotion only when role gate is on and the user lost every allowed role.
	 *
	 * @param list<string>|array<int|string,mixed> $old_roles
	 */
	public static function is_demotion_losing_ai( int $user_id, string $new_role, array $old_roles ): bool {
		unset( $new_role );
		if ( $user_id <= 0 ) {
			return false;
		}
		$policy = Policy::get_policy();
		if ( empty( $policy['role_gate_enabled'] ) ) {
			return false;
		}
		$allowed = Policy::sanitize_allowed_roles( $policy['allowed_roles'] ?? array() );
		if ( empty( $allowed ) ) {
			// Gate on with empty allow-list: nobody is allowed — revoke any lingering grants.
			return true;
		}

		if ( ! self::old_roles_had_ai( $old_roles, $allowed ) ) {
			return false;
		}

		$user = function_exists( 'get_userdata' ) ? get_userdata( $user_id ) : false;
		$now  = array();
		if ( $user && isset( $user->roles ) && is_array( $user->roles ) ) {
			foreach ( $user->roles as $r ) {
				$now[] = sanitize_key( (string) $r );
			}
		}

		foreach ( $now as $r ) {
			if ( in_array( $r, $allowed, true ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Collect + revoke. Quiet when nothing to revoke.
	 *
	 * @return array{
	 *   revoked:bool,
	 *   who:string,
	 *   pending:list<string>,
	 *   temp_allows:list<string>,
	 *   notice_cleared:bool,
	 *   summary:string
	 * }
	 */
	public static function revoke_user( int $user_id, string $reason, ?string $who = null, ?int $now = null ): array {
		$empty = array(
			'revoked'         => false,
			'who'             => '',
			'pending'         => array(),
			'temp_allows'     => array(),
			'notice_cleared'  => false,
			'summary'         => '',
		);
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return $empty;
		}
		$now    = null !== $now ? (int) $now : time();
		$reason = sanitize_key( $reason );
		if ( '' === $reason ) {
			$reason = 'offboard';
		}

		$inventory = self::inventory_for_user( $user_id, $now );
		$who       = null !== $who && '' !== $who
			? sanitize_text_field( $who )
			: ( '' !== $inventory['who'] ? $inventory['who'] : ( 'user#' . (string) $user_id ) );

		$pending_closed = array();
		foreach ( $inventory['pending_ids'] as $id ) {
			$result = Access_Request::deny( $id, 0, $now );
			if ( ! empty( $result['ok'] ) ) {
				$pending_closed[] = $id;
			}
		}

		$temp_revoked = array();
		if ( ! empty( $inventory['temp_plugins'] ) ) {
			$temp_revoked = self::clear_temp_allows( $inventory['temp_plugins'], $now );
		}

		$notice_cleared = false;
		if ( function_exists( 'delete_user_meta' ) && function_exists( 'get_user_meta' ) ) {
			$had = get_user_meta( $user_id, Access_Request::NOTICE_META, true );
			if ( ! empty( $had ) ) {
				delete_user_meta( $user_id, Access_Request::NOTICE_META );
				$notice_cleared = true;
			}
		}

		$pending_plugins = $inventory['pending_plugins'];
		$temp_labels     = array();
		foreach ( $temp_revoked as $plugin => $until ) {
			$temp_labels[] = $plugin . ' until ' . self::until_label( (int) $until );
		}

		$did = ! empty( $pending_closed ) || ! empty( $temp_revoked ) || $notice_cleared;
		if ( ! $did ) {
			return $empty;
		}

		$summary = self::build_summary( $who, $pending_plugins, $temp_labels, $notice_cleared );
		self::append_audit( $user_id, $who, $reason, $summary, $pending_plugins, array_keys( $temp_revoked ), $now );
		self::store_notice( $summary, $now );

		return array(
			'revoked'        => true,
			'who'            => $who,
			'pending'        => $pending_plugins,
			'temp_allows'    => array_keys( $temp_revoked ),
			'notice_cleared' => $notice_cleared,
			'summary'        => $summary,
		);
	}

	/**
	 * Weekly: close pending requests + drop temp-allows for users that no longer exist.
	 *
	 * @return array{closed:int,temp_cleared:int,purged_snoozes:int}
	 */
	public static function sweep_orphans( ?int $now = null ): array {
		$now = null !== $now ? (int) $now : time();
		$map = self::access_request_map();
		$closed = 0;
		$temp   = 0;

		$orphan_user_ids = array();
		foreach ( $map as $row ) {
			$uid = (int) ( $row['user_id'] ?? 0 );
			if ( $uid <= 0 ) {
				continue;
			}
			if ( self::user_exists( $uid ) ) {
				continue;
			}
			$orphan_user_ids[ $uid ] = true;
		}

		foreach ( array_keys( $orphan_user_ids ) as $uid ) {
			$result = self::revoke_user( (int) $uid, 'orphan', null, $now );
			if ( ! empty( $result['revoked'] ) ) {
				$closed += count( $result['pending'] );
				$temp   += count( $result['temp_allows'] );
			}
		}

		$purged = 0;
		if ( class_exists( Alert_Snooze::class, false ) ) {
			$ended  = Alert_Snooze::purge_expired( $now );
			$purged = is_array( $ended ) ? count( $ended ) : 0;
		}

		return array(
			'closed'         => $closed,
			'temp_cleared'   => $temp,
			'purged_snoozes' => $purged,
		);
	}

	/**
	 * @return array{
	 *   who:string,
	 *   pending_ids:list<string>,
	 *   pending_plugins:list<string>,
	 *   temp_plugins:array<string,int>
	 * }
	 */
	public static function inventory_for_user( int $user_id, ?int $now = null ): array {
		$now  = null !== $now ? (int) $now : time();
		$who  = '';
		$ids  = array();
		$pend = array();
		$temp = array();

		$map = self::access_request_map();
		foreach ( $map as $row ) {
			if ( (int) ( $row['user_id'] ?? 0 ) !== $user_id ) {
				continue;
			}
			if ( '' === $who && '' !== (string) ( $row['user_login'] ?? '' ) ) {
				$who = (string) $row['user_login'];
			}
			$status = (string) ( $row['status'] ?? '' );
			$plugin = Plugin_Profile::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) );
			if ( '' === $plugin ) {
				continue;
			}
			if ( Access_Request::STATUS_PENDING === $status ) {
				$ids[]  = (string) $row['id'];
				$pend[] = $plugin;
			}
			if ( Access_Request::STATUS_APPROVED === $status ) {
				$policy = Policy::get_policy();
				$until  = Temp_Allow::expires_at( $policy, $plugin );
				if ( null !== $until && $until > $now && ! Temp_Allow::is_expired( $policy, $plugin, $now ) ) {
					$temp[ $plugin ] = $until;
				}
			}
		}

		if ( '' === $who ) {
			$who = self::display_name_for( $user_id );
		}

		return array(
			'who'             => $who,
			'pending_ids'     => array_values( array_unique( $ids ) ),
			'pending_plugins' => array_values( array_unique( $pend ) ),
			'temp_plugins'    => $temp,
		);
	}

	/**
	 * Clear active temp-allows for plugins (mirror Temp_Allow::sweep_expired one-shot).
	 *
	 * @param array<string,int> $plugins plugin => until
	 * @return array<string,int> revoked plugin => until
	 */
	public static function clear_temp_allows( array $plugins, ?int $now = null ): array {
		$now = null !== $now ? (int) $now : time();
		if ( empty( $plugins ) ) {
			return array();
		}

		$policy  = Policy::get_policy();
		$rules   = isset( $policy['plugins'] ) && is_array( $policy['plugins'] ) ? $policy['plugins'] : array();
		$expires = Temp_Allow::sanitize_plugin_expires( $policy['plugin_expires'] ?? array() );
		$revoked = array();
		$dirty   = false;

		foreach ( $plugins as $plugin => $until ) {
			unset( $until );
			$plugin = Plugin_Profile::sanitize_plugin( (string) $plugin );
			if ( '' === $plugin ) {
				continue;
			}
			$rule = isset( $rules[ $plugin ] ) ? (string) $rules[ $plugin ] : '';
			if ( 'allow' === $rule && isset( $expires[ $plugin ] ) && (int) $expires[ $plugin ] > $now ) {
				$revoked[ $plugin ] = (int) $expires[ $plugin ];
				unset( $rules[ $plugin ], $expires[ $plugin ] );
				Temp_Allow::clear_warned( $plugin );
				if ( class_exists( Rule_Notes::class, false ) ) {
					$policy = Rule_Notes::clear_for_plugin( $policy, $plugin );
				}
				$dirty = true;
			} elseif ( isset( $expires[ $plugin ] ) ) {
				unset( $expires[ $plugin ] );
				Temp_Allow::clear_warned( $plugin );
				$dirty = true;
			}
		}

		if ( ! $dirty ) {
			return array();
		}

		$policy['plugins']        = $rules;
		$policy['plugin_expires'] = $expires;
		$policy                   = Temp_Allow::normalize_expires_against_plugins( $policy );
		if ( class_exists( Rule_Notes::class, false ) ) {
			$policy = Rule_Notes::normalize_against_plugins( $policy );
		}
		Policy::save_policy( $policy );
		Temp_Allow::maybe_schedule( Policy::get_policy() );

		return $revoked;
	}

	/**
	 * @param list<string> $pending
	 * @param list<string> $temp_labels
	 */
	public static function build_summary( string $who, array $pending, array $temp_labels, bool $notice_cleared ): string {
		$who  = '' !== $who ? $who : 'user';
		$bits = array();
		if ( ! empty( $pending ) ) {
			$bits[] = sprintf(
				'%d pending request%s (%s)',
				count( $pending ),
				1 === count( $pending ) ? '' : 's',
				implode( ', ', $pending )
			);
		}
		if ( ! empty( $temp_labels ) ) {
			$bits[] = sprintf(
				'%d temp-allow%s (%s)',
				count( $temp_labels ),
				1 === count( $temp_labels ) ? '' : 's',
				implode( ', ', $temp_labels )
			);
		}
		if ( $notice_cleared ) {
			$bits[] = 'request notice';
		}
		if ( empty( $bits ) ) {
			return $who . ' left with: nothing';
		}

		return $who . ' left with: ' . implode( '; ', $bits );
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
				/* translators: %s: offboard summary */
				__( 'HandL AI access offboard: %s', 'handl-ai-connector-access-control' ),
				$summary
			)
		);
		echo '</p><p><a href="' . esc_url( $dismiss ) . '">' . esc_html__( 'Dismiss', 'handl-ai-connector-access-control' ) . '</a></p></div>';
	}

	public static function handle_dismiss(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You cannot dismiss this notice.', 'handl-ai-connector-access-control' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION_DISMISS );
		delete_option( self::NOTICE_OPTION );
		$dest = admin_url( 'options-general.php?page=handl-aicac' );
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $dest );
			exit;
		}
		wp_redirect( $dest ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
		exit;
	}

	/**
	 * @param list<string>|array<int|string,mixed> $old_roles
	 * @param list<string>                         $allowed
	 */
	private static function old_roles_had_ai( array $old_roles, array $allowed ): bool {
		if ( empty( $allowed ) ) {
			// Empty allow-list with gate on → nobody has AI; treat any prior role as "had" for revoke.
			return ! empty( $old_roles );
		}
		foreach ( $old_roles as $r ) {
			if ( in_array( sanitize_key( (string) $r ), $allowed, true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @return array<string,array<string,mixed>>
	 */
	private static function access_request_map(): array {
		$raw = get_option( Access_Request::OPTION_KEY, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $id => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$id = strtolower( preg_replace( '/[^a-f0-9]/', '', (string) $id ) ?? '' );
			if ( 32 !== strlen( $id ) ) {
				continue;
			}
			$plugin = Plugin_Profile::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) );
			$status = sanitize_key( (string) ( $row['status'] ?? '' ) );
			$ok     = array(
				Access_Request::STATUS_PENDING,
				Access_Request::STATUS_APPROVED,
				Access_Request::STATUS_DENIED,
			);
			if ( '' === $plugin || ! in_array( $status, $ok, true ) ) {
				continue;
			}
			$out[ $id ] = array(
				'id'         => $id,
				'plugin'     => $plugin,
				'user_id'    => isset( $row['user_id'] ) ? (int) $row['user_id'] : 0,
				'user_login' => sanitize_text_field( (string) ( $row['user_login'] ?? '' ) ),
				'status'     => $status,
				'ts'         => isset( $row['ts'] ) ? (int) $row['ts'] : 0,
			);
		}

		return $out;
	}

	private static function user_exists( int $user_id ): bool {
		if ( $user_id <= 0 ) {
			return false;
		}
		if ( ! empty( $GLOBALS['handl_aicac_test_missing_users'] )
			&& is_array( $GLOBALS['handl_aicac_test_missing_users'] )
			&& in_array( $user_id, $GLOBALS['handl_aicac_test_missing_users'], true ) ) {
			return false;
		}
		if ( function_exists( 'get_userdata' ) ) {
			$user = get_userdata( $user_id );
			return (bool) $user;
		}

		return false;
	}

	private static function display_name_for( int $user_id ): string {
		if ( $user_id <= 0 ) {
			return '';
		}
		if ( ! empty( $GLOBALS['handl_aicac_test_user_login'] ) ) {
			return sanitize_text_field( (string) $GLOBALS['handl_aicac_test_user_login'] );
		}
		if ( function_exists( 'get_userdata' ) ) {
			$user = get_userdata( $user_id );
			if ( $user && ! empty( $user->user_login ) ) {
				return sanitize_text_field( (string) $user->user_login );
			}
		}

		return '';
	}

	private static function until_label( int $until ): string {
		if ( $until <= 0 ) {
			return '';
		}
		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( 'D', $until );
		}

		return gmdate( 'D', $until );
	}

	/**
	 * @param list<string> $pending
	 * @param list<string> $temp
	 */
	private static function append_audit(
		int $user_id,
		string $who,
		string $reason,
		string $summary,
		array $pending,
		array $temp,
		int $now
	): void {
		Policy::append_log_event(
			array(
				'ts'             => $now,
				'plugin'         => '',
				'decision'       => 'offboard',
				'channel'        => self::CHANNEL,
				'source'         => 'system',
				'actor_id'       => 0,
				'user_id'        => $user_id,
				'user_login'     => $who,
				'offboard_reason'=> $reason,
				'summary'        => $summary,
				'pending'        => array_values( $pending ),
				'temp_allows'    => array_values( $temp ),
				'operation'      => '',
				'provider'       => '',
			)
		);
	}

	private static function store_notice( string $summary, int $now ): void {
		update_option(
			self::NOTICE_OPTION,
			array(
				'summary' => sanitize_text_field( $summary ),
				'ts'      => $now,
			),
			false
		);
	}
}
