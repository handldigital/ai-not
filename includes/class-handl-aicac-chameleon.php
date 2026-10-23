<?php
/**
 * AICAC-CHAMELEON (#436): role-change grant drift — report only.
 *
 * Listens to set_user_role / add_user_role / remove_user_role. Compares the
 * user's effective AI posture to the NEW role baseline. Never auto-changes
 * grants. Own options OFF by default. README-FREE.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Event-driven role-transition review.
 */
final class Chameleon {

	public const SETTINGS_OPTION = 'handl_aicac_chameleon';

	public const STATE_OPTION = 'handl_aicac_chameleon_state';

	public const PAGE_SLUG = 'handl-aicac-chameleon';

	public const ALERT_KIND = 'chameleon';

	public const VERDICT_OVER = 'OVER-GRANTED';

	public const VERDICT_UNDER = 'UNDER-GRANTED';

	public const VERDICT_MATCH = 'MATCH';

	public const ACTION_SAVE = 'handl_aicac_chameleon_save';

	public const ACTION_ACK = 'handl_aicac_chameleon_ack';

	public const POST_PRESENT = 'handl_aicac_chameleon_present';

	public const POST_ENABLED = 'handl_aicac_chameleon_enabled';

	public const POST_OUTBOUND = 'handl_aicac_chameleon_outbound';

	public const POST_ACK_USER = 'handl_aicac_chameleon_ack_user';

	public const TRAIL_CAP = 200;

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_ACK, array( self::class, 'handle_ack' ) );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );

		if ( self::is_enabled() && ! self::is_network_context() ) {
			add_action( 'set_user_role', array( self::class, 'on_set_user_role' ), 20, 3 );
			add_action( 'add_user_role', array( self::class, 'on_add_user_role' ), 20, 2 );
			add_action( 'remove_user_role', array( self::class, 'on_remove_user_role' ), 20, 2 );
			add_action( 'admin_notices', array( self::class, 'maybe_render_notice' ) );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$test_mails = array();
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATE_OPTION );
		unset( $GLOBALS['handl_aicac_test_is_multisite'] );
	}

	/** @return list<array<string,mixed>> */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	public static function is_network_context(): bool {
		if ( ! empty( $GLOBALS['handl_aicac_test_is_multisite'] ) ) {
			return true;
		}
		if ( function_exists( 'is_network_admin' ) && is_network_admin() ) {
			return true;
		}

		return false;
	}

	/**
	 * @return array{enabled:bool,outbound_alert:bool}
	 */
	public static function defaults(): array {
		return array(
			'enabled'        => false,
			'outbound_alert' => false,
		);
	}

	/**
	 * @return array{enabled:bool,outbound_alert:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,outbound_alert:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		$out = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$out['enabled']        = ! empty( $raw['enabled'] );
		$out['outbound_alert'] = ! empty( $raw['outbound_alert'] );

		return $out;
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

	public static function is_outbound_enabled(): bool {
		return ! empty( self::get_settings()['outbound_alert'] );
	}

	/**
	 * @return array{trail:list<array<string,mixed>>,acks:array<string,int>,alerted:bool}
	 */
	public static function defaults_state(): array {
		return array(
			'trail'   => array(),
			'acks'    => array(),
			'alerted' => false,
		);
	}

	/**
	 * @return array{trail:list<array<string,mixed>>,acks:array<string,int>,alerted:bool}
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw state.
	 * @return array{trail:list<array<string,mixed>>,acks:array<string,int>,alerted:bool}
	 */
	public static function sanitize_state( $raw ): array {
		$out = self::defaults_state();
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$trail = array();
		if ( isset( $raw['trail'] ) && is_array( $raw['trail'] ) ) {
			foreach ( $raw['trail'] as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$clean = self::sanitize_trail_row( $row );
				if ( null !== $clean ) {
					$trail[] = $clean;
				}
			}
		}
		if ( count( $trail ) > self::TRAIL_CAP ) {
			$trail = array_slice( $trail, -1 * self::TRAIL_CAP );
		}
		$acks = array();
		if ( isset( $raw['acks'] ) && is_array( $raw['acks'] ) ) {
			foreach ( $raw['acks'] as $uid => $ts ) {
				$uid = (string) (int) $uid;
				if ( '0' === $uid ) {
					continue;
				}
				$acks[ $uid ] = max( 0, (int) $ts );
			}
		}
		$out['trail']   = $trail;
		$out['acks']    = $acks;
		$out['alerted'] = ! empty( $raw['alerted'] );

		return $out;
	}

	/**
	 * @param array<string,mixed> $row Raw trail row.
	 * @return array<string,mixed>|null
	 */
	public static function sanitize_trail_row( array $row ): ?array {
		$user_id = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
		if ( $user_id <= 0 ) {
			return null;
		}
		$verdict = (string) ( $row['verdict'] ?? self::VERDICT_MATCH );
		if ( self::VERDICT_OVER !== $verdict && self::VERDICT_UNDER !== $verdict ) {
			$verdict = self::VERDICT_MATCH;
		}

		return array(
			'ts'            => isset( $row['ts'] ) ? max( 0, (int) $row['ts'] ) : 0,
			'user_id'       => $user_id,
			'login'         => sanitize_text_field( (string) ( $row['login'] ?? '' ) ),
			'old_roles'     => self::sanitize_roles( $row['old_roles'] ?? array() ),
			'new_roles'     => self::sanitize_roles( $row['new_roles'] ?? array() ),
			'verdict'       => $verdict,
			'sentence'      => sanitize_text_field( (string) ( $row['sentence'] ?? '' ) ),
			'kept_quota'    => array_key_exists( 'kept_quota', $row ) && null !== $row['kept_quota'] ? (int) $row['kept_quota'] : null,
			'baseline_quota'=> array_key_exists( 'baseline_quota', $row ) && null !== $row['baseline_quota'] ? (int) $row['baseline_quota'] : null,
			'kept_allowed'  => ! empty( $row['kept_allowed'] ),
			'baseline_allowed' => ! empty( $row['baseline_allowed'] ),
		);
	}

	/**
	 * @param mixed $raw Roles.
	 * @return list<string>
	 */
	public static function sanitize_roles( $raw ): array {
		if ( ! is_array( $raw ) ) {
			$raw = array( $raw );
		}
		$out = array();
		foreach ( $raw as $role ) {
			$role = sanitize_key( (string) $role );
			if ( '' !== $role ) {
				$out[] = $role;
			}
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * @param array<string,mixed> $state State.
	 */
	public static function put_state( array $state ): void {
		$clean = self::sanitize_state( $state );
		if ( $clean === self::defaults_state() ) {
			delete_option( self::STATE_OPTION );

			return;
		}
		update_option( self::STATE_OPTION, $clean, false );
	}

	/**
	 * @param int                  $user_id   User.
	 * @param string               $new_role  New primary role (set_user_role).
	 * @param list<string>|mixed   $old_roles Prior roles.
	 */
	public static function on_set_user_role( $user_id, $new_role, $old_roles ): void {
		$user_id   = (int) $user_id;
		$new_roles = self::sanitize_roles( array( $new_role ) );
		$old_roles = self::sanitize_roles( $old_roles );
		self::record_transition( $user_id, $old_roles, $new_roles );
	}

	/**
	 * @param int    $user_id User.
	 * @param string $role    Added role.
	 */
	public static function on_add_user_role( $user_id, $role ): void {
		$user_id = (int) $user_id;
		$now     = self::roles_of_user( $user_id );
		$added   = self::sanitize_roles( array( $role ) );
		$old     = array_values( array_diff( $now, $added ) );
		self::record_transition( $user_id, $old, $now );
	}

	/**
	 * @param int    $user_id User.
	 * @param string $role    Removed role.
	 */
	public static function on_remove_user_role( $user_id, $role ): void {
		$user_id = (int) $user_id;
		$now     = self::roles_of_user( $user_id );
		$removed = self::sanitize_roles( array( $role ) );
		$old     = array_values( array_unique( array_merge( $now, $removed ) ) );
		self::record_transition( $user_id, $old, $now );
	}

	/**
	 * @param list<string> $old_roles Old roles.
	 * @param list<string> $new_roles New roles.
	 * @return array<string,mixed>|null Trail row, or null when skipped.
	 */
	public static function record_transition( int $user_id, array $old_roles, array $new_roles, ?int $now = null ): ?array {
		if ( ! self::is_enabled() || self::is_network_context() ) {
			return null;
		}
		if ( $user_id <= 0 ) {
			return null;
		}
		$old_roles = self::sanitize_roles( $old_roles );
		$new_roles = self::sanitize_roles( $new_roles );
		if ( $old_roles === $new_roles ) {
			return null;
		}
		$now     = null !== $now ? (int) $now : Clock::now();
		$finding = self::classify( $user_id, $old_roles, $new_roles );
		$row     = array(
			'ts'               => $now,
			'user_id'          => $user_id,
			'login'            => self::login_of( $user_id ),
			'old_roles'        => $old_roles,
			'new_roles'        => $new_roles,
			'verdict'          => $finding['verdict'],
			'sentence'         => $finding['sentence'],
			'kept_quota'       => $finding['kept_quota'],
			'baseline_quota'   => $finding['baseline_quota'],
			'kept_allowed'     => $finding['kept_allowed'],
			'baseline_allowed' => $finding['baseline_allowed'],
		);
		$state = self::get_state();
		$state['trail'][] = $row;
		if ( count( $state['trail'] ) > self::TRAIL_CAP ) {
			$state['trail'] = array_slice( $state['trail'], -1 * self::TRAIL_CAP );
		}
		unset( $state['acks'][ (string) $user_id ] );
		$state['alerted'] = false;
		self::put_state( $state );
		if ( self::VERDICT_MATCH !== $row['verdict'] ) {
			self::maybe_fire_alert( $now );
		}

		return $row;
	}

	/**
	 * Compare effective posture to the new-role baseline.
	 *
	 * @param list<string> $old_roles Old roles.
	 * @param list<string> $new_roles New roles.
	 * @return array{verdict:string,sentence:string,kept_quota:?int,baseline_quota:?int,kept_allowed:bool,baseline_allowed:bool}
	 */
	public static function classify( int $user_id, array $old_roles, array $new_roles ): array {
		$policy   = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		$policy   = is_array( $policy ) ? $policy : array();
		$kept     = self::posture_for_user( $user_id, $old_roles, $policy );
		$baseline = self::posture_for_roles( $new_roles, $policy );
		$verdict  = self::VERDICT_MATCH;
		if ( $kept['allowed'] && ! $baseline['allowed'] ) {
			$verdict = self::VERDICT_OVER;
		} elseif ( ! $kept['allowed'] && $baseline['allowed'] ) {
			$verdict = self::VERDICT_UNDER;
		} elseif ( $kept['allowed'] && $baseline['allowed'] ) {
			$kq = $kept['quota'];
			$bq = $baseline['quota'];
			if ( null !== $kq && null !== $bq && $kq > $bq ) {
				$verdict = self::VERDICT_OVER;
			} elseif ( null !== $kq && null !== $bq && $kq < $bq ) {
				$verdict = self::VERDICT_UNDER;
			} elseif ( null === $kq && null !== $bq ) {
				$verdict = self::VERDICT_OVER;
			} elseif ( null !== $kq && null === $bq ) {
				$verdict = self::VERDICT_UNDER;
			}
		}

		return array(
			'verdict'          => $verdict,
			'sentence'         => self::sentence( $user_id, $old_roles, $new_roles, $verdict, $kept, $baseline ),
			'kept_quota'       => $kept['quota'],
			'baseline_quota'   => $baseline['quota'],
			'kept_allowed'     => $kept['allowed'],
			'baseline_allowed' => $baseline['allowed'],
		);
	}

	/**
	 * @param array<string,mixed> $policy Policy.
	 * @param list<string>        $roles  Roles.
	 * @return array{allowed:bool,quota:?int}
	 */
	public static function posture_for_roles( array $roles, array $policy ): array {
		$allowed = self::roles_allowed( $roles, $policy );
		$quota   = self::role_quota( $roles, $policy );

		return array(
			'allowed' => $allowed,
			'quota'   => $quota,
		);
	}

	/**
	 * Effective posture after the transition (includes user quota override).
	 *
	 * @param array<string,mixed> $policy Policy.
	 * @param list<string>        $roles  Current roles.
	 * @return array{allowed:bool,quota:?int}
	 */
	public static function posture_for_user( int $user_id, array $roles, array $policy ): array {
		$allowed = self::roles_allowed( $roles, $policy );
		$quota   = self::role_quota( $roles, $policy );
		$fqcn    = __NAMESPACE__ . '\\User_Quota';
		if ( class_exists( $fqcn, false ) && method_exists( $fqcn, 'user_override' ) ) {
			$override = $fqcn::user_override( $user_id );
			if ( null !== $override ) {
				$quota = (int) $override;
			}
		} elseif ( class_exists( $fqcn, false ) && method_exists( $fqcn, 'effective_limit' ) ) {
			$quota = $fqcn::effective_limit( $policy, $user_id, $roles );
		}

		return array(
			'allowed' => $allowed,
			'quota'   => $quota,
		);
	}

	/**
	 * @param list<string>        $roles  Roles.
	 * @param array<string,mixed> $policy Policy.
	 */
	public static function roles_allowed( array $roles, array $policy ): bool {
		if ( empty( $policy['role_gate_enabled'] ) ) {
			return true;
		}
		$allowed = method_exists( Policy::class, 'sanitize_allowed_roles' )
			? Policy::sanitize_allowed_roles( $policy['allowed_roles'] ?? array() )
			: array();
		if ( empty( $allowed ) ) {
			return false;
		}
		foreach ( $roles as $role ) {
			if ( in_array( (string) $role, $allowed, true ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Max role quota among the given roles, or null when unlimited / unavailable.
	 *
	 * @param list<string>        $roles  Roles.
	 * @param array<string,mixed> $policy Policy.
	 */
	public static function role_quota( array $roles, array $policy ): ?int {
		$fqcn = __NAMESPACE__ . '\\User_Quota';
		if ( ! class_exists( $fqcn, false ) || ! method_exists( $fqcn, 'role_limits' ) ) {
			$raw = isset( $policy['user_quota_role_limits'] ) && is_array( $policy['user_quota_role_limits'] )
				? $policy['user_quota_role_limits']
				: array();
		} else {
			$raw = $fqcn::role_limits( $policy );
		}
		if ( ! is_array( $raw ) || empty( $raw ) ) {
			return null;
		}
		$max = null;
		foreach ( $roles as $role ) {
			$role = sanitize_key( (string) $role );
			if ( isset( $raw[ $role ] ) && is_numeric( $raw[ $role ] ) ) {
				$v = (int) $raw[ $role ];
				if ( null === $max || $v > $max ) {
					$max = $v;
				}
			}
		}

		return $max;
	}

	/**
	 * @param list<string>                 $old_roles Old.
	 * @param list<string>                 $new_roles New.
	 * @param array{allowed:bool,quota:?int} $kept     Effective.
	 * @param array{allowed:bool,quota:?int} $baseline New-role baseline.
	 */
	public static function sentence( int $user_id, array $old_roles, array $new_roles, string $verdict, array $kept, array $baseline ): string {
		$who = self::login_of( $user_id );
		$who = '' !== $who ? $who : ( 'user#' . (string) $user_id );
		$old = empty( $old_roles ) ? '—' : implode( ',', $old_roles );
		$new = empty( $new_roles ) ? '—' : implode( ',', $new_roles );
		if ( self::VERDICT_OVER === $verdict ) {
			if ( null !== $kept['quota'] && null !== $baseline['quota'] ) {
				return sprintf(
					/* translators: 1: user, 2: old roles, 3: new roles, 4: kept quota, 5: baseline quota */
					__( 'User %1$s moved from %2$s to %3$s and kept a %4$d-call quota. The new role baseline is %5$d.', 'handl-ai-connector-access-control' ),
					$who,
					$old,
					$new,
					(int) $kept['quota'],
					(int) $baseline['quota']
				);
			}

			return sprintf(
				/* translators: 1: user, 2: old roles, 3: new roles */
				__( 'User %1$s moved from %2$s to %3$s. The new role would not allow AI access; this user still has it.', 'handl-ai-connector-access-control' ),
				$who,
				$old,
				$new
			);
		}
		if ( self::VERDICT_UNDER === $verdict ) {
			if ( null !== $kept['quota'] && null !== $baseline['quota'] ) {
				return sprintf(
					/* translators: 1: user, 2: old roles, 3: new roles, 4: kept quota, 5: baseline quota */
					__( 'User %1$s moved from %2$s to %3$s and has a %4$d-call quota. The new role baseline is %5$d.', 'handl-ai-connector-access-control' ),
					$who,
					$old,
					$new,
					(int) $kept['quota'],
					(int) $baseline['quota']
				);
			}

			return sprintf(
				/* translators: 1: user, 2: old roles, 3: new roles */
				__( 'User %1$s moved from %2$s to %3$s. The new role would allow AI access; this user still has none.', 'handl-ai-connector-access-control' ),
				$who,
				$old,
				$new
			);
		}

		return sprintf(
			/* translators: 1: user, 2: old roles, 3: new roles */
			__( 'User %1$s moved from %2$s to %3$s. Access still matches the new role.', 'handl-ai-connector-access-control' ),
			$who,
			$old,
			$new
		);
	}

	/**
	 * Latest trail row per user that is still a finding.
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function findings(): array {
		$state = self::get_state();
		$latest = array();
		foreach ( $state['trail'] as $row ) {
			if ( self::VERDICT_MATCH === (string) ( $row['verdict'] ?? '' ) ) {
				continue;
			}
			$latest[ (string) (int) $row['user_id'] ] = $row;
		}

		return array_values( $latest );
	}

	/**
	 * @param array<string,mixed> $row Trail row.
	 */
	public static function is_acked( array $row ): bool {
		$state = self::get_state();
		$uid   = (string) (int) ( $row['user_id'] ?? 0 );
		if ( '0' === $uid ) {
			return false;
		}
		$ack_ts = isset( $state['acks'][ $uid ] ) ? (int) $state['acks'][ $uid ] : 0;
		$row_ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;

		return $ack_ts > 0 && $ack_ts >= $row_ts;
	}

	public static function ack_user( int $user_id, ?int $now = null ): bool {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return false;
		}
		$now           = null !== $now ? (int) $now : Clock::now();
		$state         = self::get_state();
		$state['acks'][ (string) $user_id ] = $now;
		self::put_state( $state );

		return true;
	}

	/**
	 * Unacked OVER-GRANTED rows (CLI non-zero).
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function unacked_over(): array {
		$out = array();
		foreach ( self::findings() as $row ) {
			if ( self::VERDICT_OVER !== (string) ( $row['verdict'] ?? '' ) ) {
				continue;
			}
			if ( self::is_acked( $row ) ) {
				continue;
			}
			$out[] = $row;
		}

		return $out;
	}

	public static function maybe_fire_alert( ?int $now = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$unacked = array();
		foreach ( self::findings() as $row ) {
			if ( ! self::is_acked( $row ) ) {
				$unacked[] = $row;
			}
		}
		if ( empty( $unacked ) ) {
			return false;
		}
		$state = self::get_state();
		if ( ! empty( $state['alerted'] ) ) {
			return false;
		}
		if ( self::is_outbound_enabled() ) {
			self::fire_outbound( $unacked );
		}
		$state['alerted'] = true;
		self::put_state( $state );

		return true;
	}

	/**
	 * @param list<array<string,mixed>> $findings Findings.
	 */
	private static function fire_outbound( array $findings ): void {
		$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		$policy = is_array( $policy ) ? $policy : array();
		$email  = '';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		}
		if ( '' === $email ) {
			$email = sanitize_email( (string) get_option( 'admin_email' ) );
		}
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$subject = sprintf(
			/* translators: %s: site name */
			__( '[CHAMELEON] [%s] AI access no longer matches a new role', 'handl-ai-connector-access-control' ),
			$site
		);
		$body = __( 'A user\'s role changed. Their AI access no longer matches the new role. Nothing was changed.', 'handl-ai-connector-access-control' ) . "\n\n";
		foreach ( $findings as $row ) {
			$body .= (string) ( $row['sentence'] ?? '' ) . "\n";
		}
		if ( '' !== $email ) {
			if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'safe_wp_mail' ) ) {
				Alerts::safe_wp_mail( $email, $subject, $body );
			} elseif ( function_exists( 'wp_mail' ) ) {
				wp_mail( $email, $subject, $body );
			}
			self::$test_mails[] = array(
				'to'      => $email,
				'subject' => $subject,
				'body'    => $body,
			);
		}
	}

	public static function maybe_render_notice(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$unacked = array();
		foreach ( self::findings() as $row ) {
			if ( ! self::is_acked( $row ) ) {
				$unacked[] = $row;
			}
		}
		if ( empty( $unacked ) ) {
			return;
		}
		$url = self::admin_url();
		echo '<div class="notice notice-warning"><p>';
		echo esc_html__( '[CHAMELEON] A user\'s AI access no longer matches their new role. Nothing was changed.', 'handl-ai-connector-access-control' );
		if ( '' !== $url ) {
			echo ' <a href="' . esc_url( $url ) . '">' . esc_html__( 'Review', 'handl-ai-connector-access-control' ) . '</a>';
		}
		echo '</p></div>';
	}

	public static function csv_census(): string {
		$state = self::get_state();
		$lines = array();
		$lines[] = self::csv_line( array( 'user', 'old_role', 'new_role', 'posture_delta', 'ack_state' ) );
		$latest  = array();
		foreach ( $state['trail'] as $row ) {
			$latest[ (string) (int) $row['user_id'] ] = $row;
		}
		foreach ( $latest as $row ) {
			$acked = self::is_acked( $row ) ? 'acked' : 'open';
			$lines[] = self::csv_line(
				array(
					'' !== (string) ( $row['login'] ?? '' ) ? (string) $row['login'] : ( 'user#' . (string) (int) $row['user_id'] ),
					implode( ',', self::sanitize_roles( $row['old_roles'] ?? array() ) ),
					implode( ',', self::sanitize_roles( $row['new_roles'] ?? array() ) ),
					(string) ( $row['verdict'] ?? self::VERDICT_MATCH ),
					$acked,
				)
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param list<string> $cols Columns.
	 */
	public static function csv_line( array $cols ): string {
		$out = array();
		foreach ( $cols as $col ) {
			$col = (string) $col;
			if ( strpbrk( $col, ",\"\n\r" ) !== false ) {
				$col = '"' . str_replace( '"', '""', $col ) . '"';
			}
			$out[] = $col;
		}

		return implode( ',', $out );
	}

	/**
	 * @return array{ok:bool,code:int,lines:list<string>}
	 */
	public static function cli_status(): array {
		$over  = self::unacked_over();
		$lines = array();
		if ( ! self::is_enabled() ) {
			$lines[] = __( 'Role-change review is off.', 'handl-ai-connector-access-control' );

			return array(
				'ok'    => true,
				'code'  => 0,
				'lines' => $lines,
			);
		}
		$findings = self::findings();
		$lines[]  = sprintf(
			/* translators: %d: finding count */
			__( 'Findings: %d', 'handl-ai-connector-access-control' ),
			count( $findings )
		);
		foreach ( $findings as $row ) {
			$ack     = self::is_acked( $row ) ? 'acked' : 'open';
			$lines[] = (string) ( $row['verdict'] ?? '' ) . ' ' . (string) ( $row['sentence'] ?? '' ) . ' [' . $ack . ']';
		}
		$code = empty( $over ) ? 0 : 1;

		return array(
			'ok'    => 0 === $code,
			'code'  => $code,
			'lines' => $lines,
		);
	}

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Role-change review', 'handl-ai-connector-access-control' ),
			__( 'Role-change review', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$settings   = self::get_settings();
		$can_manage = Caps::user_can_manage();
		$enabled    = ! empty( $settings['enabled'] );

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Role-change review', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'When a user\'s role changes, we check whether their AI access still matches the new role. We do not change access.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Role-change review', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( $enabled, true, false ) . ' /> ';
			echo esc_html__( 'Watch role changes', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row">' . esc_html__( 'Email', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_OUTBOUND ) . '" value="1" ' . checked( ! empty( $settings['outbound_alert'] ), true, false ) . ' /> ';
			echo esc_html__( 'Email when access no longer matches', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '</tbody></table>';
			if ( function_exists( 'submit_button' ) ) {
				submit_button( __( 'Save role-change review', 'handl-ai-connector-access-control' ) );
			} else {
				echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Save role-change review', 'handl-ai-connector-access-control' ) . '</button></p>';
			}
			echo '</form>';
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Role-change review is off.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		$findings = self::findings();
		if ( empty( $findings ) ) {
			echo '<p>' . esc_html__( 'No role-change findings.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'User', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Old role', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'New role', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Finding', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Ack', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $findings as $row ) {
				$acked = self::is_acked( $row );
				echo '<tr>';
				echo '<td>' . esc_html( '' !== (string) ( $row['login'] ?? '' ) ? (string) $row['login'] : ( 'user#' . (string) (int) $row['user_id'] ) ) . '</td>';
				echo '<td>' . esc_html( implode( ',', self::sanitize_roles( $row['old_roles'] ?? array() ) ) ) . '</td>';
				echo '<td>' . esc_html( implode( ',', self::sanitize_roles( $row['new_roles'] ?? array() ) ) ) . '</td>';
				echo '<td>' . esc_html( (string) ( $row['sentence'] ?? $row['verdict'] ) ) . '</td>';
				echo '<td>';
				if ( $acked ) {
					echo esc_html__( 'Acknowledged', 'handl-ai-connector-access-control' );
				} elseif ( $can_manage ) {
					echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
					echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_ACK ) . '" />';
					if ( function_exists( 'wp_nonce_field' ) ) {
						wp_nonce_field( self::ACTION_ACK );
					}
					echo '<input type="hidden" name="' . esc_attr( self::POST_ACK_USER ) . '" value="' . esc_attr( (string) (int) $row['user_id'] ) . '" />';
					echo '<button type="submit" class="button">' . esc_html__( 'Acknowledge', 'handl-ai-connector-access-control' ) . '</button>';
					echo '</form>';
				} else {
					echo esc_html__( 'Open', 'handl-ai-connector-access-control' );
				}
				echo '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		$csv = add_query_arg(
			array(
				'page'                    => self::PAGE_SLUG,
				'handl_aicac_chameleon_csv' => '1',
			),
			admin_url( 'admin.php' )
		);
		echo '<p><a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a></p>';
		echo '</div>';
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			return;
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			return;
		}
		self::save_settings(
			array(
				'enabled'        => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'outbound_alert' => ! empty( $_POST[ self::POST_OUTBOUND ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
			)
		);
		$redirect = add_query_arg(
			array(
				'page'    => self::PAGE_SLUG,
				'updated' => '1',
			),
			admin_url( 'admin.php' )
		);
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $redirect );
			exit;
		}
	}

	public static function handle_ack(): void {
		if ( ! Caps::user_can_manage() ) {
			return;
		}
		check_admin_referer( self::ACTION_ACK );
		$uid = isset( $_POST[ self::POST_ACK_USER ] ) ? (int) $_POST[ self::POST_ACK_USER ] : 0; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		self::ack_user( $uid );
		$redirect = add_query_arg(
			array(
				'page'    => self::PAGE_SLUG,
				'updated' => '1',
			),
			admin_url( 'admin.php' )
		);
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $redirect );
			exit;
		}
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_chameleon_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		$csv = self::csv_census();
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename="aicac-chameleon.csv"' );
		}
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac chameleon', CLI_Chameleon::class );
	}

	public static function admin_url(): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return add_query_arg( array( 'page' => self::PAGE_SLUG ), admin_url( 'admin.php' ) );
	}

	/**
	 * @return list<string>
	 */
	private static function roles_of_user( int $user_id ): array {
		if ( $user_id <= 0 || ! function_exists( 'get_userdata' ) ) {
			return array();
		}
		$user = get_userdata( $user_id );
		if ( ! $user || ! isset( $user->roles ) || ! is_array( $user->roles ) ) {
			return array();
		}

		return array_values( array_map( 'strval', $user->roles ) );
	}

	private static function login_of( int $user_id ): string {
		if ( $user_id <= 0 || ! function_exists( 'get_userdata' ) ) {
			return '';
		}
		$user = get_userdata( $user_id );
		if ( $user && isset( $user->user_login ) ) {
			return (string) $user->user_login;
		}

		return '';
	}
}

/**
 * WP-CLI: wp handl-aicac chameleon
 */
final class CLI_Chameleon {

	/**
	 * Show role-change findings. Exits non-zero on unacked OVER-GRANTED rows.
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		$out = Chameleon::cli_status();
		foreach ( $out['lines'] as $line ) {
			\WP_CLI::log( $line );
		}
		if ( (int) $out['code'] > 0 ) {
			\WP_CLI::error( __( 'Unacked OVER-GRANTED rows remain.', 'handl-ai-connector-access-control' ) );
		}
	}

	/**
	 * Print the role-change census as CSV.
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function csv( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		\WP_CLI::log( rtrim( Chameleon::csv_census(), "\n" ) );
	}
}
