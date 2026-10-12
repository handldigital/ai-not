<?php
/**
 * AICAC-GATEKEEPER (#421): administrator-roster watchdog (suggestion-only).
 *
 * Whoever can manage this plugin can rewrite every rule, so the list of people
 * who hold that power is part of the governance story. This class keeps an
 * acknowledged baseline of "who can manage the plugin, and by which path",
 * and on a throttled admin request reports what changed since: a new manager,
 * a manager that vanished, or a manager holding the capability directly on the
 * user account (a quiet backdoor no role screen shows).
 *
 * Grant path per user:
 * - role:   a role the user holds grants the manage capability.
 * - direct: the capability sits in the user's own capability list, or the
 *           user can manage while no role grants it.
 * - both:   a role grants it and the user also holds it directly.
 *
 * Design rules:
 * - Suggestion only. Acknowledging the baseline records a snapshot in this
 *   class's own state; it never adds, removes or edits a role, a capability or
 *   a user. The roster is read through get_users() and read-only role lookups.
 * - Writes are confined to the two own options (settings + state).
 * - Detection runs on a throttled admin_init (and on demand from WP-CLI),
 *   never from a cron hook. This class schedules nothing.
 * - No alert until a baseline exists. The first enable shows a pending
 *   baseline and an "acknowledge current roster" call to action. Findings and
 *   the alert latch re-arm only on the next change after an acknowledgement.
 * - Multisite: current-site roster only; no network-wide user queries.
 * - Alerts are reused through class_exists / method_exists guards only.
 * - wp_die is used only by this class's own saves (settings + acknowledge).
 * - Own two options. OFF by default.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Administrator-roster watchdog.
 */
final class Gatekeeper {

	public const SETTINGS_OPTION = 'handl_aicac_gatekeeper';

	public const STATE_OPTION = 'handl_aicac_gatekeeper_state';

	public const PAGE_SLUG = 'handl-aicac-gatekeeper';

	public const ALERT_KIND = 'gatekeeper';

	public const FRAMING = 'report_only_never_edits_roles';

	public const POST_PRESENT = 'handl_aicac_gatekeeper_present';

	public const POST_ENABLED = 'handl_aicac_gatekeeper_enabled';

	public const ACTION_SAVE = 'handl_aicac_gatekeeper_save';

	public const ACTION_ACK = 'handl_aicac_gatekeeper_ack';

	/** Admin check throttle in seconds (5 minutes). */
	public const CHECK_THROTTLE_SECONDS = 300;

	/** Most users read per scan. */
	public const ROSTER_CAP = 200;

	public const PATH_ROLE   = 'role';
	public const PATH_DIRECT = 'direct';
	public const PATH_BOTH   = 'both';

	public const CODE_NEW          = 'new';
	public const CODE_DEPARTED     = 'departed';
	public const CODE_DIRECT_GRANT = 'direct_grant';

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	/** @var int|null */
	private static $test_now = null;

	/** @var bool */
	private static $test_roster_set = false;

	/** @var array<int,mixed>|null */
	private static $test_roster = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_print' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_ACK, array( self::class, 'handle_ack' ) );

		if ( self::is_enabled() ) {
			// Detection rides a throttled admin request, never a cron hook.
			add_action( 'admin_init', array( self::class, 'maybe_check' ), 30 );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered      = false;
		self::$test_mails      = array();
		self::$test_now        = null;
		self::$test_roster_set = false;
		self::$test_roster     = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATE_OPTION );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	/**
	 * Inject the manager roster for unit tests. Null reads the live site.
	 *
	 * Each row: user_id, login, display_name, roles, and either grant_path
	 * (role|direct|both) or the raw flags role_grant / direct_cap.
	 *
	 * @param array<int,mixed>|null $rows Roster rows or null.
	 */
	public static function set_test_roster( ?array $rows ): void {
		self::$test_roster_set = null !== $rows;
		self::$test_roster     = $rows;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{enabled:bool}
	 */
	public static function defaults(): array {
		return array(
			'enabled' => false,
		);
	}

	/**
	 * @return array{enabled:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return self::defaults();
		}

		return array(
			'enabled' => ! empty( $raw['enabled'] ),
		);
	}

	/**
	 * @param array<string,mixed> $settings Settings.
	 * @return bool True when the stored value changed.
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
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] );
	}

	/* ---------------------------------------------------------------------
	 * State
	 * ------------------------------------------------------------------ */

	/**
	 * @return array<string,mixed>
	 */
	public static function defaults_state(): array {
		return array(
			'alerted'       => false,
			'last_check_ts' => 0,
			'acked_ts'      => 0,
			'baseline'      => array(),
			'first_seen'    => array(),
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw state.
	 * @return array<string,mixed>
	 */
	public static function sanitize_state( $raw ): array {
		$state = self::defaults_state();
		if ( ! is_array( $raw ) ) {
			return $state;
		}

		$baseline = array();
		if ( isset( $raw['baseline'] ) && is_array( $raw['baseline'] ) ) {
			foreach ( $raw['baseline'] as $row ) {
				$clean = self::sanitize_row( $row );
				if ( null !== $clean ) {
					$baseline[ $clean['user_id'] ] = $clean;
				}
			}
		}
		ksort( $baseline );
		if ( count( $baseline ) > self::ROSTER_CAP ) {
			$baseline = array_slice( $baseline, 0, self::ROSTER_CAP, true );
		}

		$first_seen = array();
		if ( isset( $raw['first_seen'] ) && is_array( $raw['first_seen'] ) ) {
			foreach ( $raw['first_seen'] as $uid => $ts ) {
				if ( (int) $uid > 0 && is_numeric( $ts ) && (int) $ts > 0 ) {
					$first_seen[ (int) $uid ] = (int) $ts;
				}
			}
		}
		ksort( $first_seen );
		if ( count( $first_seen ) > self::ROSTER_CAP * 2 ) {
			$first_seen = array_slice( $first_seen, 0, self::ROSTER_CAP * 2, true );
		}

		$state['alerted']       = ! empty( $raw['alerted'] );
		$state['last_check_ts'] = max( 0, (int) ( $raw['last_check_ts'] ?? 0 ) );
		$state['acked_ts']      = max( 0, (int) ( $raw['acked_ts'] ?? 0 ) );
		$state['baseline']      = $baseline;
		$state['first_seen']    = $first_seen;

		return $state;
	}

	/**
	 * @param mixed $row Raw roster row.
	 * @return array{user_id:int,login:string,display_name:string,roles:list<string>,grant_path:string,first_seen:int}|null
	 */
	public static function sanitize_row( $row ): ?array {
		if ( ! is_array( $row ) ) {
			return null;
		}
		$uid = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
		if ( $uid <= 0 ) {
			return null;
		}

		$roles = array();
		if ( isset( $row['roles'] ) && is_array( $row['roles'] ) ) {
			foreach ( $row['roles'] as $role ) {
				$key = sanitize_key( (string) $role );
				if ( '' !== $key ) {
					$roles[] = $key;
				}
			}
		}
		$roles = array_values( array_slice( array_unique( $roles ), 0, 10 ) );

		$path = (string) ( $row['grant_path'] ?? '' );
		if ( ! in_array( $path, array( self::PATH_ROLE, self::PATH_DIRECT, self::PATH_BOTH ), true ) ) {
			$path = self::classify_grant(
				! empty( $row['role_grant'] ),
				! empty( $row['direct_cap'] ),
				true
			);
		}

		return array(
			'user_id'      => $uid,
			'login'        => substr( sanitize_text_field( (string) ( $row['login'] ?? '' ) ), 0, 60 ),
			'display_name' => substr( sanitize_text_field( (string) ( $row['display_name'] ?? '' ) ), 0, 120 ),
			'roles'        => $roles,
			'grant_path'   => $path,
			'first_seen'   => max( 0, (int) ( $row['first_seen'] ?? 0 ) ),
		);
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

	public static function is_alerted(): bool {
		$state = self::get_state();

		return ! empty( $state['alerted'] );
	}

	public static function set_alerted( bool $alerted ): void {
		$state            = self::get_state();
		$state['alerted'] = $alerted;
		self::put_state( $state );
	}

	/* ---------------------------------------------------------------------
	 * Roster (read-only)
	 * ------------------------------------------------------------------ */

	private static function resolve_now( ?int $now ): int {
		if ( null !== $now && $now > 0 ) {
			return $now;
		}
		if ( null !== self::$test_now ) {
			return self::$test_now;
		}

		return class_exists( Clock::class, false ) ? Clock::now() : time();
	}

	/**
	 * The capability that makes someone a plugin manager.
	 */
	public static function manage_cap(): string {
		if ( class_exists( Caps::class, false ) && defined( Caps::class . '::MANAGE' ) ) {
			return (string) Caps::MANAGE;
		}

		return 'manage_options';
	}

	/**
	 * Grant-path classification.
	 *
	 * @param bool $role_grant A role the user holds grants the capability.
	 * @param bool $direct_cap The user's own capability list grants it.
	 * @param bool $can_manage The user can manage at all.
	 */
	public static function classify_grant( bool $role_grant, bool $direct_cap, bool $can_manage ): string {
		unset( $can_manage );
		if ( $role_grant && $direct_cap ) {
			return self::PATH_BOTH;
		}
		if ( $role_grant ) {
			return self::PATH_ROLE;
		}

		// Direct capability, or able to manage while no role grants it.
		return self::PATH_DIRECT;
	}

	/**
	 * Role lookup without any mutation.
	 *
	 * @return object|null
	 */
	private static function role_object( string $role_key ) {
		if ( isset( $GLOBALS['handl_aicac_test_roles'][ $role_key ] ) && is_object( $GLOBALS['handl_aicac_test_roles'][ $role_key ] ) ) {
			return $GLOBALS['handl_aicac_test_roles'][ $role_key ];
		}
		if ( ! function_exists( 'get_role' ) ) {
			return null;
		}
		$role = get_role( $role_key );

		return is_object( $role ) ? $role : null;
	}

	/**
	 * @param object $role Role object.
	 */
	private static function role_grants( $role, string $cap ): bool {
		if ( method_exists( $role, 'has_cap' ) ) {
			return (bool) $role->has_cap( $cap );
		}
		if ( isset( $role->capabilities ) && is_array( $role->capabilities ) ) {
			return ! empty( $role->capabilities[ $cap ] );
		}

		return false;
	}

	/**
	 * Convert a WP_User-like object into a roster row (read-only).
	 *
	 * @param object $user User.
	 * @return array{user_id:int,login:string,display_name:string,roles:list<string>,grant_path:string,first_seen:int}|null
	 */
	public static function row_from_user( $user ): ?array {
		if ( ! is_object( $user ) ) {
			return null;
		}
		$uid = (int) ( $user->ID ?? 0 );
		if ( $uid <= 0 ) {
			return null;
		}
		$cap   = self::manage_cap();
		$roles = array();
		if ( isset( $user->roles ) && is_array( $user->roles ) ) {
			foreach ( $user->roles as $role ) {
				$roles[] = (string) $role;
			}
		}

		$role_grant = false;
		foreach ( $roles as $role_key ) {
			$role = self::role_object( $role_key );
			if ( null !== $role && self::role_grants( $role, $cap ) ) {
				$role_grant = true;
				break;
			}
		}

		$direct_cap = isset( $user->caps ) && is_array( $user->caps ) && ! empty( $user->caps[ $cap ] );
		$can_manage = method_exists( $user, 'has_cap' ) ? (bool) $user->has_cap( $cap ) : true;

		return self::sanitize_row(
			array(
				'user_id'      => $uid,
				'login'        => (string) ( $user->user_login ?? '' ),
				'display_name' => (string) ( $user->display_name ?? '' ),
				'roles'        => $roles,
				'grant_path'   => self::classify_grant( $role_grant, $direct_cap, $can_manage ),
			)
		);
	}

	/**
	 * Current-site manager roster. Capped; never a network-wide query.
	 *
	 * @return array{rows:list<array<string,mixed>>,truncated:bool}
	 */
	public static function scan_roster(): array {
		$rows = array();
		if ( self::$test_roster_set && is_array( self::$test_roster ) ) {
			foreach ( self::$test_roster as $raw ) {
				$row = self::sanitize_row( $raw );
				if ( null !== $row ) {
					$rows[ $row['user_id'] ] = $row;
				}
			}
		} elseif ( function_exists( 'get_users' ) ) {
			$args = array(
				'capability' => self::manage_cap(),
				'orderby'    => 'ID',
				'order'      => 'ASC',
				'number'     => self::ROSTER_CAP + 1,
			);
			if ( function_exists( 'get_current_blog_id' ) ) {
				$args['blog_id'] = (int) get_current_blog_id();
			}
			$users = get_users( $args );
			if ( is_array( $users ) ) {
				foreach ( $users as $user ) {
					$row = self::row_from_user( $user );
					if ( null !== $row ) {
						$rows[ $row['user_id'] ] = $row;
					}
				}
			}
		}

		ksort( $rows );
		$truncated = count( $rows ) > self::ROSTER_CAP;
		if ( $truncated ) {
			$rows = array_slice( $rows, 0, self::ROSTER_CAP, true );
		}

		return array(
			'rows'      => array_values( $rows ),
			'truncated' => $truncated,
		);
	}

	/**
	 * Fill first_seen from state (falling back to now) and key rows by user id.
	 *
	 * @param list<array<string,mixed>> $rows       Rows.
	 * @param array<int,int>            $first_seen Stored first-seen map.
	 * @return array<int,array<string,mixed>>
	 */
	private static function with_first_seen( array $rows, array $first_seen, int $now ): array {
		$out = array();
		foreach ( $rows as $row ) {
			$uid               = (int) $row['user_id'];
			$row['first_seen'] = $first_seen[ $uid ] ?? $now;
			$out[ $uid ]       = $row;
		}

		return $out;
	}

	/**
	 * @param array<string,mixed>       $state State.
	 * @param list<array<string,mixed>> $rows  Live rows.
	 * @return array<int,int>
	 */
	private static function merged_first_seen( array $state, array $rows, bool $truncated, int $now ): array {
		$first_seen = $state['first_seen'];
		$live_ids   = array();
		foreach ( $rows as $row ) {
			$uid                = (int) $row['user_id'];
			$live_ids[ $uid ]   = true;
			$first_seen[ $uid ] = $first_seen[ $uid ] ?? $now;
		}
		if ( ! $truncated ) {
			foreach ( array_keys( $first_seen ) as $uid ) {
				if ( ! isset( $live_ids[ $uid ] ) && ! isset( $state['baseline'][ $uid ] ) ) {
					unset( $first_seen[ $uid ] );
				}
			}
		}

		return $first_seen;
	}

	/* ---------------------------------------------------------------------
	 * Deltas vs the acknowledged baseline
	 * ------------------------------------------------------------------ */

	private static function day( int $ts ): string {
		return $ts > 0 ? gmdate( 'Y-m-d', $ts ) . ' UTC' : __( 'an unknown date', 'handl-ai-connector-access-control' );
	}

	public static function path_phrase( string $path ): string {
		switch ( $path ) {
			case self::PATH_DIRECT:
				return __( 'a capability set directly on the user account, not through a role', 'handl-ai-connector-access-control' );
			case self::PATH_BOTH:
				return __( 'both a role and a capability set directly on the user account', 'handl-ai-connector-access-control' );
			default:
				return __( 'a role', 'handl-ai-connector-access-control' );
		}
	}

	/**
	 * @param array<string,mixed> $row Live or baseline row.
	 * @return array<string,mixed>
	 */
	private static function finding( string $code, array $row, string $summary, string $previous_path, bool $is_new ): array {
		return array(
			'code'                => $code,
			'user_id'             => (int) $row['user_id'],
			'login'               => (string) $row['login'],
			'display_name'        => (string) $row['display_name'],
			'grant_path'          => (string) $row['grant_path'],
			'previous_grant_path' => $previous_path,
			'first_seen'          => (int) $row['first_seen'],
			'is_new'              => $is_new,
			'summary'             => $summary,
		);
	}

	/**
	 * Unacknowledged deltas between the baseline and the live roster.
	 *
	 * One finding per user. A new manager who holds the capability directly is
	 * reported as `direct_grant` (flagged is_new); a plain new manager is `new`.
	 *
	 * @param array<int,array<string,mixed>> $baseline  Baseline rows keyed by user id.
	 * @param array<int,array<string,mixed>> $live      Live rows keyed by user id.
	 * @param bool                           $truncated Live roster hit the cap.
	 * @return list<array<string,mixed>>
	 */
	public static function compute_findings( array $baseline, array $live, bool $truncated = false ): array {
		$findings = array();

		foreach ( $live as $uid => $row ) {
			$base       = $baseline[ $uid ] ?? null;
			$has_direct = in_array( $row['grant_path'], array( self::PATH_DIRECT, self::PATH_BOTH ), true );

			if ( null === $base ) {
				$code    = $has_direct ? self::CODE_DIRECT_GRANT : self::CODE_NEW;
				$summary = sprintf(
					/* translators: 1: login, 2: user id, 3: grant path, 4: grant path in words, 5: first-seen date */
					__( 'New administrator "%1$s" (user #%2$d) appeared after the last acknowledged roster and can manage this plugin. Grant path: %3$s (%4$s). First seen %5$s.', 'handl-ai-connector-access-control' ),
					$row['login'],
					$uid,
					$row['grant_path'],
					self::path_phrase( (string) $row['grant_path'] ),
					self::day( (int) $row['first_seen'] )
				);
				if ( $has_direct ) {
					$summary .= ' ' . __( 'The capability is held directly on the account, which role screens do not show.', 'handl-ai-connector-access-control' );
				}
				$findings[] = self::finding( $code, $row, $summary, '', true );
				continue;
			}

			if ( $has_direct && self::PATH_ROLE === $base['grant_path'] ) {
				$summary    = sprintf(
					/* translators: 1: login, 2: user id, 3: grant path, 4: grant path in words, 5: first-seen date */
					__( '"%1$s" (user #%2$d) used to reach plugin management only through a role and now also holds it directly on the account. Grant path: %3$s (%4$s). First seen %5$s. This is how a quiet backdoor looks.', 'handl-ai-connector-access-control' ),
					$row['login'],
					$uid,
					$row['grant_path'],
					self::path_phrase( (string) $row['grant_path'] ),
					self::day( (int) $row['first_seen'] )
				);
				$findings[] = self::finding( self::CODE_DIRECT_GRANT, $row, $summary, (string) $base['grant_path'], false );
			}
		}

		$max_live = empty( $live ) ? 0 : (int) max( array_keys( $live ) );
		foreach ( $baseline as $uid => $row ) {
			if ( isset( $live[ $uid ] ) ) {
				continue;
			}
			if ( $truncated && $uid > $max_live ) {
				continue; // Beyond the capped window: cannot tell.
			}
			$summary    = sprintf(
				/* translators: 1: login, 2: user id, 3: grant path, 4: first-seen date */
				__( 'Administrator "%1$s" (user #%2$d) is no longer on the roster. At the last acknowledgement the grant path was %3$s; first seen %4$s.', 'handl-ai-connector-access-control' ),
				$row['login'],
				$uid,
				$row['grant_path'],
				self::day( (int) $row['first_seen'] )
			);
			$findings[] = self::finding( self::CODE_DEPARTED, $row, $summary, (string) $row['grant_path'], false );
		}

		return $findings;
	}

	/* ---------------------------------------------------------------------
	 * Snapshot
	 * ------------------------------------------------------------------ */

	/**
	 * @param array<string,mixed>                                          $state State.
	 * @param array{rows:list<array<string,mixed>>,truncated:bool}         $scan  Scan result.
	 * @return array<string,mixed>
	 */
	private static function build_snapshot( array $state, array $scan, int $now ): array {
		$live         = self::with_first_seen( $scan['rows'], $state['first_seen'], $now );
		$has_baseline = (int) $state['acked_ts'] > 0;
		$findings     = $has_baseline ? self::compute_findings( $state['baseline'], $live, (bool) $scan['truncated'] ) : array();

		$flag = array();
		foreach ( $findings as $finding ) {
			$flag[ (int) $finding['user_id'] ] = (string) $finding['code'];
		}
		$roster = array();
		foreach ( $live as $uid => $row ) {
			$row['flag'] = $flag[ $uid ] ?? '';
			$roster[]    = $row;
		}

		return array(
			'enabled'              => self::is_enabled(),
			'now'                  => $now,
			'roster'               => $roster,
			'roster_count'         => count( $roster ),
			'truncated'            => (bool) $scan['truncated'],
			'baseline_pending'     => ! $has_baseline,
			'baseline_count'       => count( $state['baseline'] ),
			'acked_ts'             => (int) $state['acked_ts'],
			'findings'             => $findings,
			'unacknowledged_count' => count( $findings ),
			'alerted'              => ! empty( $state['alerted'] ),
			'last_check_ts'        => (int) $state['last_check_ts'],
			'framing'              => self::FRAMING,
		);
	}

	/**
	 * Read-only view built from the live roster (does not write anything).
	 *
	 * @return array<string,mixed>
	 */
	public static function snapshot( ?int $now = null ): array {
		return self::build_snapshot( self::get_state(), self::scan_roster(), self::resolve_now( $now ) );
	}

	/* ---------------------------------------------------------------------
	 * Throttled admin_init check
	 * ------------------------------------------------------------------ */

	/**
	 * Throttled roster check, wired to admin_init (never to a cron hook).
	 *
	 * @param int|null $now   Optional timestamp.
	 * @param bool     $force Skip the throttle.
	 * @return bool True when a check ran.
	 */
	public static function maybe_check( ?int $now = null, bool $force = false ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now   = self::resolve_now( is_int( $now ) ? $now : null );
		$state = self::get_state();
		$last  = (int) $state['last_check_ts'];
		if ( ! $force && $last > 0 && $now >= $last && ( $now - $last ) < self::CHECK_THROTTLE_SECONDS ) {
			return false;
		}

		$scan                   = self::scan_roster();
		$state['first_seen']    = self::merged_first_seen( $state, $scan['rows'], (bool) $scan['truncated'], $now );
		$state['last_check_ts'] = $now;
		self::put_state( $state );

		self::maybe_fire_alerts( $now, self::build_snapshot( self::get_state(), $scan, $now ) );

		return true;
	}

	/* ---------------------------------------------------------------------
	 * Acknowledge (records a baseline; never touches roles or capabilities)
	 * ------------------------------------------------------------------ */

	/**
	 * Accept the current roster as the baseline.
	 *
	 * @return bool True when a baseline was recorded.
	 */
	public static function acknowledge( ?int $now = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now   = self::resolve_now( $now );
		$state = self::get_state();
		$scan  = self::scan_roster();

		$first_seen = self::merged_first_seen( $state, $scan['rows'], (bool) $scan['truncated'], $now );
		$baseline   = array();
		foreach ( $scan['rows'] as $row ) {
			$uid               = (int) $row['user_id'];
			$row['first_seen'] = $first_seen[ $uid ];
			$baseline[ $uid ]  = $row;
		}

		$state['baseline']      = $baseline;
		$state['first_seen']    = $first_seen;
		$state['acked_ts']      = $now;
		$state['alerted']       = false;
		$state['last_check_ts'] = $now;
		self::put_state( $state );

		return true;
	}

	/* ---------------------------------------------------------------------
	 * Alerts (guarded reuse of Alerts; zero edits to it)
	 * ------------------------------------------------------------------ */

	/**
	 * @param int|null                 $now  Timestamp.
	 * @param array<string,mixed>|null $snap Optional precomputed snapshot.
	 * @return bool True when a new alert was sent.
	 */
	public static function maybe_fire_alerts( ?int $now = null, ?array $snap = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now  = self::resolve_now( $now );
		$snap = null !== $snap ? $snap : self::snapshot( $now );

		if ( (int) $snap['unacknowledged_count'] <= 0 ) {
			if ( self::is_alerted() ) {
				self::set_alerted( false );
			}

			return false;
		}

		if ( self::is_alerted() ) {
			return false;
		}

		if ( ! self::fire_alert( $snap, $now ) ) {
			return false;
		}
		self::set_alerted( true );

		return true;
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	private static function fire_alert( array $snap, int $now ): bool {
		$policy = class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}

		$email = '';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		}
		if ( '' === $email ) {
			$email = function_exists( 'sanitize_email' )
				? sanitize_email( (string) get_option( 'admin_email' ) )
				: (string) get_option( 'admin_email' );
		}
		if ( '' === $email ) {
			return false;
		}

		$subject = self::build_subject( $snap );
		$body    = self::build_body( $snap );
		$ok      = false;
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'safe_wp_mail' ) ) {
			$ok = (bool) Alerts::safe_wp_mail( $email, $subject, $body );
		} elseif ( function_exists( 'wp_mail' ) ) {
			$ok = (bool) wp_mail( $email, $subject, $body );
		}
		self::$test_mails[] = array(
			'to'      => $email,
			'subject' => $subject,
			'body'    => $body,
		);

		if ( $ok && class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
				$codes = array();
				foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
					$codes[] = (string) ( $row['code'] ?? '' );
				}
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'                 => 'handl_aicac_gatekeeper',
						'unacknowledged_count' => (int) ( $snap['unacknowledged_count'] ?? 0 ),
						'codes'                => $codes,
						'site'                 => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'                   => $now,
					)
				);
			}
		}

		return $ok;
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_subject( array $snap ): string {
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$first = '';
		foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
			$first = (string) ( $row['code'] ?? '' );
			break;
		}

		return sprintf(
			/* translators: 1: site name, 2: finding count, 3: first finding code */
			__( '[%1$s] [GATEKEEPER] %2$d unacknowledged change(s) to who can manage AI Access Control (first: %3$s)', 'handl-ai-connector-access-control' ),
			$site,
			(int) ( $snap['unacknowledged_count'] ?? 0 ),
			$first
		);
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_body( array $snap ): string {
		$lines   = array();
		$lines[] = __( 'The list of people who can manage AI Access Control changed since it was last acknowledged. Whoever can manage the plugin can rewrite every rule, so please confirm each change below is expected.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
			$lines[] = '- ' . (string) ( $row['summary'] ?? '' );
		}
		$lines[] = '';
		$lines[] = __( 'Suggestion only: Gatekeeper never adds, removes or edits a role or capability. Review the account under Users, then acknowledge the roster to accept it. This check runs on admin page loads, not on cron.', 'handl-ai-connector-access-control' );
		if ( function_exists( 'admin_url' ) ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Review users: %s', 'handl-ai-connector-access-control' ),
				admin_url( 'users.php' )
			);
		}
		$url = self::admin_url();
		if ( '' !== $url ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Open gatekeeper: %s', 'handl-ai-connector-access-control' ),
				$url
			);
		}

		return implode( "\n", $lines );
	}

	public static function admin_url(): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg( 'page', self::PAGE_SLUG, admin_url( 'admin.php' ) );
	}

	/* ---------------------------------------------------------------------
	 * CSV + print
	 * ------------------------------------------------------------------ */

	private static function first_seen_label( int $ts ): string {
		return $ts > 0 ? gmdate( 'Y-m-d H:i:s', $ts ) . ' UTC' : '';
	}

	/**
	 * @param array<string,mixed>|null $snap Optional snapshot.
	 */
	public static function csv_for_snapshot( ?array $snap = null ): string {
		if ( null === $snap ) {
			$snap = self::snapshot();
		}
		$lines   = array();
		$lines[] = self::csv_line(
			array(
				'section',
				'code',
				'user_id',
				'login',
				'display_name',
				'roles',
				'grant_path',
				'first_seen',
				'summary',
				'framing',
			)
		);
		$lines[] = self::csv_line(
			array(
				'summary',
				'',
				'',
				'',
				'',
				'',
				'',
				self::first_seen_label( (int) ( $snap['now'] ?? 0 ) ),
				'roster=' . (string) (int) ( $snap['roster_count'] ?? 0 )
					. ' baseline=' . ( ! empty( $snap['baseline_pending'] ) ? 'pending' : (string) (int) ( $snap['baseline_count'] ?? 0 ) )
					. ' unacknowledged=' . (string) (int) ( $snap['unacknowledged_count'] ?? 0 ),
				self::FRAMING,
			)
		);
		foreach ( (array) ( $snap['roster'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$lines[] = self::csv_line(
				array(
					'roster',
					(string) ( $row['flag'] ?? '' ),
					(string) (int) $row['user_id'],
					(string) $row['login'],
					(string) $row['display_name'],
					implode( '|', (array) $row['roles'] ),
					(string) $row['grant_path'],
					self::first_seen_label( (int) $row['first_seen'] ),
					'',
					self::FRAMING,
				)
			);
		}
		foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$lines[] = self::csv_line(
				array(
					'finding',
					(string) $row['code'],
					(string) (int) $row['user_id'],
					(string) $row['login'],
					(string) $row['display_name'],
					'',
					(string) $row['grant_path'],
					self::first_seen_label( (int) $row['first_seen'] ),
					(string) $row['summary'],
					self::FRAMING,
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
			// Neutralize spreadsheet formula injection.
			if ( '' !== $col && in_array( $col[0], array( '=', '+', '-', '@', "\t", "\r" ), true ) ) {
				$col = "'" . $col;
			}
			$needs = str_contains( $col, ',' ) || str_contains( $col, '"' ) || str_contains( $col, "\n" );
			$col   = str_replace( '"', '""', $col );
			$out[] = $needs ? '"' . $col . '"' : $col;
		}

		return implode( ',', $out );
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_print_html( array $snap ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
		$html .= esc_html__( 'AI Connector gatekeeper', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%;margin-bottom:24px}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f6f7f7}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'AI Connector gatekeeper', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Report only — never adds, removes or edits a role or capability.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<ul>';
		$html .= '<li>' . esc_html( sprintf( 'Managers on the roster: %d', (int) ( $snap['roster_count'] ?? 0 ) ) ) . '</li>';
		$html .= '<li>' . esc_html( sprintf( 'Unacknowledged changes: %d', (int) ( $snap['unacknowledged_count'] ?? 0 ) ) ) . '</li>';
		$html .= '<li>' . esc_html( ! empty( $snap['baseline_pending'] ) ? 'Baseline: not acknowledged yet' : sprintf( 'Baseline acknowledged: %s', self::first_seen_label( (int) ( $snap['acked_ts'] ?? 0 ) ) ) ) . '</li>';
		$html .= '</ul>';
		$html .= '<h2>' . esc_html__( 'Findings', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= self::findings_table_html( (array) ( $snap['findings'] ?? array() ) );
		$html .= '<h2>' . esc_html__( 'Manager roster', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= self::roster_table_html( (array) ( $snap['roster'] ?? array() ) );
		$html .= '</body></html>';

		return $html;
	}

	/**
	 * @param list<array<string,mixed>> $rows Findings.
	 */
	private static function findings_table_html( array $rows ): string {
		$html  = '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Finding', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Login', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Grant path', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'First seen', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		$shown = 0;
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			++$shown;
			$html .= '<tr>';
			$html .= '<td><strong>' . esc_html( (string) $row['summary'] ) . '</strong><br /><code>' . esc_html( (string) $row['code'] ) . '</code></td>';
			$html .= '<td>' . esc_html( (string) $row['login'] ) . '</td>';
			$html .= '<td>' . esc_html( (string) $row['grant_path'] ) . '</td>';
			$html .= '<td>' . esc_html( self::first_seen_label( (int) $row['first_seen'] ) ) . '</td>';
			$html .= '</tr>';
		}
		if ( 0 === $shown ) {
			$html .= '<tr><td colspan="4">' . esc_html__( 'No unacknowledged roster changes.', 'handl-ai-connector-access-control' ) . '</td></tr>';
		}
		$html .= '</tbody></table>';

		return $html;
	}

	/**
	 * @param list<array<string,mixed>> $rows Roster.
	 */
	private static function roster_table_html( array $rows ): string {
		$html  = '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Login', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Name', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Roles', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Grant path', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'First seen', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Status', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		$shown = 0;
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			++$shown;
			$html .= '<tr>';
			$html .= '<td>' . esc_html( (string) $row['login'] ) . '</td>';
			$html .= '<td>' . esc_html( (string) $row['display_name'] ) . '</td>';
			$html .= '<td>' . esc_html( implode( ', ', (array) $row['roles'] ) ) . '</td>';
			$html .= '<td>' . esc_html( (string) $row['grant_path'] ) . '</td>';
			$html .= '<td>' . esc_html( self::first_seen_label( (int) $row['first_seen'] ) ) . '</td>';
			$html .= '<td>' . esc_html( '' !== (string) ( $row['flag'] ?? '' ) ? (string) $row['flag'] : 'ok' ) . '</td>';
			$html .= '</tr>';
		}
		if ( 0 === $shown ) {
			$html .= '<tr><td colspan="6">' . esc_html__( 'No managers found on this site.', 'handl-ai-connector-access-control' ) . '</td></tr>';
		}
		$html .= '</tbody></table>';

		return $html;
	}

	/* ---------------------------------------------------------------------
	 * Admin UI
	 * ------------------------------------------------------------------ */

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Gatekeeper', 'handl-ai-connector-access-control' ),
			__( 'Gatekeeper', 'handl-ai-connector-access-control' ),
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
		$enabled    = self::is_enabled();
		$snap       = $enabled ? self::snapshot() : null;
		$csv        = add_query_arg(
			array(
				'page'                       => self::PAGE_SLUG,
				'handl_aicac_gatekeeper_csv' => '1',
				'_wpnonce'                   => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_gatekeeper_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print      = add_query_arg(
			array(
				'page'                         => self::PAGE_SLUG,
				'handl_aicac_gatekeeper_print' => '1',
				'_wpnonce'                     => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_gatekeeper_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Gatekeeper', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Watches who can manage AI Access Control and how they got that power: through a role, directly on the user account, or both. Reports new managers, managers who disappeared, and quiet direct grants. Suggestion only — it never adds, removes or edits a role or capability. Checks run on admin page loads, not on cron. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable gatekeeper', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Watch the administrator roster and alert on unacknowledged changes', 'handl-ai-connector-access-control' );
			echo '</label></td></tr></tbody></table>';
			submit_button( __( 'Save gatekeeper settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled || ! is_array( $snap ) ) {
			echo '<p>' . esc_html__( 'Gatekeeper is off. Enable it to watch the administrator roster.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Report only — never adds, removes or edits a role or capability.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		if ( ! empty( $snap['baseline_pending'] ) ) {
			echo '<div class="notice notice-info inline"><p>' . esc_html__( 'No baseline yet, so nothing is flagged. Review the roster below and acknowledge it to start watching for changes.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		echo '<ul>';
		echo '<li>' . esc_html( sprintf( 'Managers on this site: %d', (int) $snap['roster_count'] ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( 'Unacknowledged changes: %d', (int) $snap['unacknowledged_count'] ) ) . '</li>';
		if ( (int) $snap['acked_ts'] > 0 ) {
			echo '<li>' . esc_html( sprintf( 'Baseline acknowledged: %s', self::first_seen_label( (int) $snap['acked_ts'] ) ) ) . '</li>';
		}
		if ( ! empty( $snap['truncated'] ) ) {
			echo '<li>' . esc_html( sprintf( 'Roster capped at %d users.', self::ROSTER_CAP ) ) . '</li>';
		}
		echo '</ul>';

		if ( $can_manage && ( ! empty( $snap['baseline_pending'] ) || (int) $snap['unacknowledged_count'] > 0 ) ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_ACK ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_ACK );
			}
			submit_button( __( 'Acknowledge current roster', 'handl-ai-connector-access-control' ), 'secondary' );
			echo '</form>';
		}

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Findings', 'handl-ai-connector-access-control' ) . '</h2>';
		echo str_replace( '<table>', '<table class="widefat striped">', self::findings_table_html( (array) $snap['findings'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.
		echo '<h2>' . esc_html__( 'Manager roster', 'handl-ai-connector-access-control' ) . '</h2>';
		echo str_replace( '<table>', '<table class="widefat striped">', self::roster_table_html( (array) $snap['roster'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.

		echo '</div>';
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_gatekeeper_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? (string) wp_unslash( $_GET['_wpnonce'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_gatekeeper_csv' ) ) {
			return;
		}
		$csv = self::csv_for_snapshot();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=handl-aicac-gatekeeper.csv' );
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		if ( empty( $_GET['handl_aicac_gatekeeper_print'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? (string) wp_unslash( $_GET['_wpnonce'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_gatekeeper_print' ) ) {
			return;
		}
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		echo self::build_print_html( self::snapshot() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.
		exit;
	}

	private static function redirect_to_page(): void {
		$redirect = self::admin_url();
		if ( '' === $redirect && function_exists( 'admin_url' ) ) {
			$redirect = admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save gatekeeper settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Invalid form', 'handl-ai-connector-access-control' ) );
		}
		self::save_settings(
			array(
				'enabled' => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
			)
		);
		self::redirect_to_page();
	}

	/**
	 * Accept the current roster as the baseline. Records a snapshot only.
	 */
	public static function handle_ack(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to acknowledge the roster.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_ACK );
		self::acknowledge();
		self::redirect_to_page();
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac gatekeeper', CLI_Gatekeeper::class );
	}
}

/**
 * WP-CLI: wp handl-aicac gatekeeper status|export
 */
final class CLI_Gatekeeper {

	/**
	 * Run a roster check now and show the manager roster. Exits non-zero while
	 * any unacknowledged roster change is present (while enabled).
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table or json. Default table.
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';

		if ( ! Gatekeeper::is_enabled() ) {
			\WP_CLI::log( 'enabled=no framing=' . Gatekeeper::FRAMING );
			\WP_CLI::log( 'Gatekeeper is disabled.' );

			return;
		}

		Gatekeeper::maybe_check( null, true );
		$snap = Gatekeeper::snapshot();

		\WP_CLI::log(
			sprintf(
				'enabled=yes managers=%d baseline=%s unacknowledged=%d alerted=%s framing=%s',
				(int) $snap['roster_count'],
				! empty( $snap['baseline_pending'] ) ? 'pending' : (string) (int) $snap['baseline_count'],
				(int) $snap['unacknowledged_count'],
				! empty( $snap['alerted'] ) ? 'yes' : 'no',
				Gatekeeper::FRAMING
			)
		);
		if ( ! empty( $snap['baseline_pending'] ) ) {
			\WP_CLI::log( 'No baseline yet: acknowledge the current roster on the Gatekeeper screen to start watching for changes.' );
		}

		$display = array();
		foreach ( (array) $snap['roster'] as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$display[] = array(
				'user_id'    => (int) $row['user_id'],
				'login'      => (string) $row['login'],
				'roles'      => implode( ',', (array) $row['roles'] ),
				'grant_path' => (string) $row['grant_path'],
				'first_seen' => $row['first_seen'] > 0 ? gmdate( 'Y-m-d', (int) $row['first_seen'] ) : '',
				'status'     => '' !== (string) $row['flag'] ? (string) $row['flag'] : 'ok',
			);
		}
		if ( ! empty( $display ) ) {
			if ( 'json' === $format ) {
				\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			} elseif ( class_exists( '\\WP_CLI\\Utils' ) ) {
				\WP_CLI\Utils\format_items( 'table', $display, array( 'user_id', 'login', 'roles', 'grant_path', 'first_seen', 'status' ) );
			} else {
				foreach ( $display as $row ) {
					\WP_CLI::log( implode( "\t", $row ) );
				}
			}
		}

		foreach ( (array) $snap['findings'] as $finding ) {
			if ( is_array( $finding ) ) {
				\WP_CLI::log( (string) $finding['summary'] );
			}
		}

		if ( (int) $snap['unacknowledged_count'] > 0 ) {
			// Default exit=true: an unacknowledged roster change must fail the command.
			\WP_CLI::error( 'Unacknowledged administrator roster changes present.' );
		}
	}

	/**
	 * Export the manager roster and findings as CSV.
	 *
	 * ## OPTIONS
	 *
	 * [--porcelain]
	 * : Print CSV only.
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function export( $args, $assoc_args ): void {
		unset( $args );
		$csv = Gatekeeper::csv_for_snapshot();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
