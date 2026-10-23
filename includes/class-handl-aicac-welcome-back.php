<?php
/**
 * AICAC-WELCOME-BACK (#438): returning-admin catch-up brief.
 *
 * Tracks per-admin last-seen and, after a qualifying absence gap, shows one
 * dismissible notice linking to a personal catch-up screen. Read-only joins
 * over sibling stores; the only new write is last-seen (+ dismiss) meta.
 *
 * Fences: UNATTENDED (during-absence failsafe), governance-digest (broadcast),
 * WHATS-NEW (release notes). Zero edits to those surfaces.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Returning-admin catch-up brief.
 */
final class Welcome_Back {

	public const SETTINGS_OPTION = 'handl_aicac_welcome_back';

	public const PAGE_SLUG = 'handl-aicac-welcome-back';

	public const META_LAST_SEEN = 'handl_aicac_welcome_back_last_seen';

	public const META_DISMISS_UNTIL_GAP = 'handl_aicac_welcome_back_dismissed_gap_start';

	public const FRAMING = 'on_return_personal_brief_read_only';

	public const DEFAULT_GAP_DAYS = 7;

	public const LAST_SEEN_THROTTLE_SECONDS = 300;

	public const ACTION_SAVE     = 'handl_aicac_welcome_back_save';
	public const ACTION_DISMISS  = 'handl_aicac_welcome_back_dismiss';

	public const POST_PRESENT = 'handl_aicac_welcome_back_present';
	public const POST_ENABLED = 'handl_aicac_welcome_back_enabled';
	public const POST_GAP     = 'handl_aicac_welcome_back_gap_days';

	/** @var bool */
	private static $registered = false;

	/** @var int|null */
	private static $test_now = null;

	/** @var list<array<string,mixed>>|null */
	private static $test_log = null;

	/** @var list<array<string,mixed>>|null */
	private static $test_history = null;

	/** @var list<array<string,mixed>>|null */
	private static $test_pending = null;

	/** @var array<string,int>|null */
	private static $test_findings = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_track_last_seen' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_DISMISS, array( self::class, 'handle_dismiss' ) );

		if ( self::is_enabled() ) {
			add_action( 'admin_notices', array( self::class, 'maybe_render_notice' ) );
			add_action( 'network_admin_notices', array( self::class, 'maybe_render_notice' ) );
		}
	}

	public static function reset_for_tests(): void {
		self::$registered     = false;
		self::$test_now       = null;
		self::$test_log       = null;
		self::$test_history   = null;
		self::$test_pending   = null;
		self::$test_findings  = null;
		delete_option( self::SETTINGS_OPTION );
		if ( isset( $GLOBALS['handl_aicac_test_user_meta'] ) && is_array( $GLOBALS['handl_aicac_test_user_meta'] ) ) {
			foreach ( $GLOBALS['handl_aicac_test_user_meta'] as $uid => $meta ) {
				if ( ! is_array( $meta ) ) {
					continue;
				}
				unset(
					$GLOBALS['handl_aicac_test_user_meta'][ $uid ][ self::META_LAST_SEEN ],
					$GLOBALS['handl_aicac_test_user_meta'][ $uid ][ self::META_DISMISS_UNTIL_GAP ]
				);
			}
		}
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	/**
	 * @param list<array<string,mixed>>|null $log Log.
	 */
	public static function set_test_log( ?array $log ): void {
		self::$test_log = $log;
	}

	/**
	 * @param list<array<string,mixed>>|null $history History.
	 */
	public static function set_test_history( ?array $history ): void {
		self::$test_history = $history;
	}

	/**
	 * @param list<array<string,mixed>>|null $pending Pending requests.
	 */
	public static function set_test_pending( ?array $pending ): void {
		self::$test_pending = $pending;
	}

	/**
	 * @param array<string,int>|null $findings Map of audit id => unacked count.
	 */
	public static function set_test_findings( ?array $findings ): void {
		self::$test_findings = $findings;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{enabled:bool,gap_days:int}
	 */
	public static function defaults(): array {
		return array(
			'enabled'  => false,
			'gap_days' => self::DEFAULT_GAP_DAYS,
		);
	}

	/**
	 * @return array{enabled:bool,gap_days:int}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw.
	 * @return array{enabled:bool,gap_days:int}
	 */
	public static function sanitize_settings( $raw ): array {
		$out = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$out['enabled'] = ! empty( $raw['enabled'] );
		$gap            = isset( $raw['gap_days'] ) ? (int) $raw['gap_days'] : self::DEFAULT_GAP_DAYS;
		if ( $gap < 1 ) {
			$gap = 1;
		}
		if ( $gap > 365 ) {
			$gap = 365;
		}
		$out['gap_days'] = $gap;

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
		} else {
			update_option( self::SETTINGS_OPTION, $clean, false );
		}

		return true;
	}

	public static function is_enabled(): bool {
		return ! empty( self::get_settings()['enabled'] );
	}

	public static function gap_days(): int {
		return (int) self::get_settings()['gap_days'];
	}

	public static function gap_seconds(): int {
		$day = defined( 'DAY_IN_SECONDS' ) ? DAY_IN_SECONDS : 86400;

		return self::gap_days() * $day;
	}

	/* ---------------------------------------------------------------------
	 * Time + last-seen
	 * ------------------------------------------------------------------ */

	public static function resolve_now( ?int $now = null ): int {
		if ( null !== self::$test_now ) {
			return (int) self::$test_now;
		}
		if ( null !== $now ) {
			return $now;
		}
		if ( class_exists( Clock::class, false ) && method_exists( Clock::class, 'now' ) ) {
			return (int) Clock::now();
		}

		return time();
	}

	public static function get_last_seen( int $user_id ): int {
		if ( $user_id <= 0 ) {
			return 0;
		}
		$raw = get_user_meta( $user_id, self::META_LAST_SEEN, true );

		return is_numeric( $raw ) ? max( 0, (int) $raw ) : 0;
	}

	public static function set_last_seen( int $user_id, int $ts ): void {
		if ( $user_id <= 0 ) {
			return;
		}
		update_user_meta( $user_id, self::META_LAST_SEEN, max( 0, $ts ) );
	}

	public static function get_dismissed_gap_start( int $user_id ): int {
		if ( $user_id <= 0 ) {
			return 0;
		}
		$raw = get_user_meta( $user_id, self::META_DISMISS_UNTIL_GAP, true );

		return is_numeric( $raw ) ? max( 0, (int) $raw ) : 0;
	}

	public static function set_dismissed_gap_start( int $user_id, int $gap_start ): void {
		if ( $user_id <= 0 ) {
			return;
		}
		update_user_meta( $user_id, self::META_DISMISS_UNTIL_GAP, max( 0, $gap_start ) );
	}

	public static function clear_dismiss( int $user_id ): void {
		if ( $user_id <= 0 ) {
			return;
		}
		delete_user_meta( $user_id, self::META_DISMISS_UNTIL_GAP );
	}

	/**
	 * Gap between last-seen and now. 0 when never seen or under threshold.
	 */
	public static function absence_gap_seconds( int $user_id, ?int $now = null ): int {
		$now  = self::resolve_now( $now );
		$last = self::get_last_seen( $user_id );
		if ( $last <= 0 || $now < $last ) {
			return 0;
		}

		return $now - $last;
	}

	public static function qualifies_for_notice( int $user_id, ?int $now = null ): bool {
		if ( ! self::is_enabled() || $user_id <= 0 ) {
			return false;
		}
		if ( ! Caps::user_can_view() ) {
			return false;
		}
		$now = self::resolve_now( $now );
		$gap = self::absence_gap_seconds( $user_id, $now );
		if ( $gap < self::gap_seconds() ) {
			return false;
		}
		$last     = self::get_last_seen( $user_id );
		$dismissed = self::get_dismissed_gap_start( $user_id );
		// Dismiss stays quiet until the next qualifying gap (new last-seen baseline).
		if ( $dismissed > 0 && $dismissed === $last ) {
			return false;
		}

		return true;
	}

	/**
	 * Throttled last-seen update on admin views. Does not clear a pending notice
	 * until the admin visits the catch-up page or dismisses.
	 */
	public static function maybe_track_last_seen( ?int $now = null, bool $force = false ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$user_id = (int) get_current_user_id();
		if ( $user_id <= 0 || ! Caps::user_can_view() ) {
			return false;
		}
		$now  = self::resolve_now( is_int( $now ) ? $now : null );
		$last = self::get_last_seen( $user_id );

		// If a catch-up notice is active, do not advance last-seen yet — the gap
		// must remain measurable until dismiss or catch-up visit.
		if ( self::qualifies_for_notice( $user_id, $now ) ) {
			return false;
		}

		if ( ! $force && $last > 0 && ( $now - $last ) < self::LAST_SEEN_THROTTLE_SECONDS ) {
			return false;
		}
		self::set_last_seen( $user_id, $now );

		return true;
	}

	/**
	 * Record presence after the admin has seen the catch-up (or dismissed).
	 */
	public static function mark_present( int $user_id, ?int $now = null ): void {
		$now = self::resolve_now( $now );
		self::set_last_seen( $user_id, $now );
		self::clear_dismiss( $user_id );
	}

	public static function dismiss_for_user( int $user_id, ?int $now = null ): void {
		$now  = self::resolve_now( $now );
		$last = self::get_last_seen( $user_id );
		if ( $last <= 0 ) {
			$last = $now - self::gap_seconds();
			self::set_last_seen( $user_id, $last );
		}
		self::set_dismissed_gap_start( $user_id, $last );
		// Advance last-seen so the next gap starts from now.
		self::set_last_seen( $user_id, $now );
	}

	/* ---------------------------------------------------------------------
	 * Catch-up brief (guarded reads)
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{rows:list<array<string,mixed>>,available:bool,notice:string}
	 */
	public static function read_activity_log(): array {
		if ( null !== self::$test_log ) {
			return array(
				'rows'      => array_values( self::$test_log ),
				'available' => true,
				'notice'    => '',
			);
		}
		if ( ! class_exists( Plugin::class, false ) ) {
			return array(
				'rows'      => array(),
				'available' => false,
				'notice'    => 'source unavailable',
			);
		}
		$raw = get_option( Plugin::LOG_OPTION_KEY, null );
		if ( null === $raw || false === $raw || ! is_array( $raw ) ) {
			return array(
				'rows'      => array(),
				'available' => false,
				'notice'    => 'source unavailable',
			);
		}
		$rows = array();
		foreach ( $raw as $row ) {
			if ( is_array( $row ) ) {
				$rows[] = $row;
			}
		}

		return array(
			'rows'      => $rows,
			'available' => true,
			'notice'    => '',
		);
	}

	/**
	 * @return array{rows:list<array<string,mixed>>,available:bool,notice:string}
	 */
	public static function read_change_history(): array {
		if ( null !== self::$test_history ) {
			return array(
				'rows'      => array_values( self::$test_history ),
				'available' => true,
				'notice'    => '',
			);
		}
		if ( ! class_exists( Policy_Snapshots::class, false ) || ! method_exists( Policy_Snapshots::class, 'history' ) ) {
			return array(
				'rows'      => array(),
				'available' => false,
				'notice'    => 'source unavailable',
			);
		}
		$raw = Policy_Snapshots::history();
		if ( ! is_array( $raw ) ) {
			return array(
				'rows'      => array(),
				'available' => false,
				'notice'    => 'source unavailable',
			);
		}

		return array(
			'rows'      => $raw,
			'available' => true,
			'notice'    => '',
		);
	}

	/**
	 * @return array{rows:list<array<string,mixed>>,available:bool,notice:string}
	 */
	public static function read_pending_requests(): array {
		if ( null !== self::$test_pending ) {
			return array(
				'rows'      => array_values( self::$test_pending ),
				'available' => true,
				'notice'    => '',
			);
		}
		if ( ! class_exists( Access_Request::class, false ) || ! method_exists( Access_Request::class, 'pending_rows' ) ) {
			return array(
				'rows'      => array(),
				'available' => false,
				'notice'    => 'source unavailable',
			);
		}
		$rows = Access_Request::pending_rows();

		return array(
			'rows'      => is_array( $rows ) ? $rows : array(),
			'available' => true,
			'notice'    => '',
		);
	}

	/**
	 * Unacked findings from optional sibling audits.
	 *
	 * @return array{counts:array<string,int>,available:bool,notice:string}
	 */
	public static function read_unacked_findings(): array {
		if ( null !== self::$test_findings ) {
			return array(
				'counts'    => self::$test_findings,
				'available' => true,
				'notice'    => '',
			);
		}
		$counts = array();
		$probes = array(
			'postcard'    => 'HandL\\AICAC\\Postcard',
			'sleepwalker' => 'HandL\\AICAC\\Sleepwalker',
			'dead_rules'  => 'HandL\\AICAC\\Dead_Rules',
			'keyscan'     => 'HandL\\AICAC\\Keyscan',
		);
		$any = false;
		foreach ( $probes as $id => $class ) {
			if ( ! class_exists( $class, false ) ) {
				continue;
			}
			$any = true;
			$n   = 0;
			if ( method_exists( $class, 'findings' ) ) {
				$found = $class::findings();
				$n     = is_array( $found ) ? count( $found ) : 0;
			} elseif ( method_exists( $class, 'unacknowledged_count' ) ) {
				$n = (int) $class::unacknowledged_count();
			}
			$counts[ $id ] = $n;
		}
		if ( ! $any ) {
			return array(
				'counts'    => array(),
				'available' => false,
				'notice'    => 'source unavailable',
			);
		}

		return array(
			'counts'    => $counts,
			'available' => true,
			'notice'    => '',
		);
	}

	/**
	 * Count deny/allow in [start, end).
	 *
	 * @param list<array<string,mixed>> $rows Log rows.
	 * @return array{deny:int,allow:int}
	 */
	public static function count_decisions_in_window( array $rows, int $start, int $end ): array {
		$deny  = 0;
		$allow = 0;
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts < $start || $ts >= $end ) {
				continue;
			}
			$decision = isset( $row['decision'] ) ? (string) $row['decision'] : '';
			if ( 'deny' === $decision ) {
				++$deny;
			} elseif ( 'allow' === $decision ) {
				++$allow;
			}
		}

		return array(
			'deny'  => $deny,
			'allow' => $allow,
		);
	}

	/**
	 * Alerts fired approximation: denial digest queue depth + log rows with alert-ish channels.
	 *
	 * @return array{count:int,available:bool,notice:string}
	 */
	public static function count_alerts_in_window( int $start, int $end ): array {
		$available = false;
		$count     = 0;
		if ( class_exists( Alerts::class, false ) ) {
			$available = true;
			$queue     = get_option( Alerts::DIGEST_OPTION_KEY, null );
			if ( is_array( $queue ) ) {
				foreach ( $queue as $row ) {
					if ( ! is_array( $row ) ) {
						continue;
					}
					$ts = isset( $row['ts'] ) ? (int) $row['ts'] : ( isset( $row['time'] ) ? (int) $row['time'] : 0 );
					if ( $ts >= $start && $ts < $end ) {
						++$count;
					}
				}
			}
		}
		$pack = self::read_activity_log();
		if ( $pack['available'] ) {
			$available = true;
			foreach ( $pack['rows'] as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
				if ( $ts < $start || $ts >= $end ) {
					continue;
				}
				$channel = isset( $row['channel'] ) ? (string) $row['channel'] : '';
				if ( '' !== $channel && false !== strpos( $channel, 'alert' ) ) {
					++$count;
				}
			}
		}
		if ( ! $available ) {
			return array(
				'count'     => 0,
				'available' => false,
				'notice'    => 'source unavailable',
			);
		}

		return array(
			'count'     => $count,
			'available' => true,
			'notice'    => '',
		);
	}

	/**
	 * Build the catch-up brief for an absence window ending at $now starting at $gap_start.
	 *
	 * @return array<string,mixed>
	 */
	public static function build_brief( int $user_id, ?int $now = null ): array {
		$now       = self::resolve_now( $now );
		$last      = self::get_last_seen( $user_id );
		$gap_start = $last > 0 ? $last : ( $now - self::gap_seconds() );
		$duration  = max( 0, $now - $gap_start );
		$prior_end = $gap_start;
		$prior_start = $gap_start - $duration;

		$history = self::read_change_history();
		$settings_changes = 0;
		if ( $history['available'] ) {
			foreach ( $history['rows'] as $row ) {
				$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
				if ( $ts >= $gap_start && $ts < $now ) {
					++$settings_changes;
				}
			}
		}

		$log_pack = self::read_activity_log();
		$absence  = array( 'deny' => 0, 'allow' => 0 );
		$prior    = array( 'deny' => 0, 'allow' => 0 );
		if ( $log_pack['available'] ) {
			$absence = self::count_decisions_in_window( $log_pack['rows'], $gap_start, $now );
			$prior   = self::count_decisions_in_window( $log_pack['rows'], $prior_start, $prior_end );
		}

		$alerts  = self::count_alerts_in_window( $gap_start, $now );
		$pending = self::read_pending_requests();
		$findings = self::read_unacked_findings();

		$sections = array(
			'settings_changes' => array(
				'available' => $history['available'],
				'notice'    => $history['notice'],
				'count'     => $settings_changes,
				'sentence'  => $history['available']
					? sprintf(
						/* translators: %d: change count */
						_n(
							'%d settings change while you were away.',
							'%d settings changes while you were away.',
							$settings_changes,
							'handl-ai-connector-access-control'
						),
						$settings_changes
					)
					: __( 'Settings changes: source unavailable.', 'handl-ai-connector-access-control' ),
			),
			'alerts'           => array(
				'available' => $alerts['available'],
				'notice'    => $alerts['notice'],
				'count'     => (int) $alerts['count'],
				'sentence'  => $alerts['available']
					? sprintf(
						/* translators: %d: alert count */
						_n(
							'%d alert fired while you were away.',
							'%d alerts fired while you were away.',
							(int) $alerts['count'],
							'handl-ai-connector-access-control'
						),
						(int) $alerts['count']
					)
					: __( 'Alerts: source unavailable.', 'handl-ai-connector-access-control' ),
			),
			'traffic'          => array(
				'available' => $log_pack['available'],
				'notice'    => $log_pack['notice'],
				'absence'   => $absence,
				'prior'     => $prior,
				'sentence'  => $log_pack['available']
					? sprintf(
						/* translators: 1: deny count absence, 2: allow count absence, 3: deny prior, 4: allow prior */
						__( 'While away: %1$d denies / %2$d allows. Prior equal window: %3$d denies / %4$d allows.', 'handl-ai-connector-access-control' ),
						(int) $absence['deny'],
						(int) $absence['allow'],
						(int) $prior['deny'],
						(int) $prior['allow']
					)
					: __( 'Deny/allow volume: source unavailable.', 'handl-ai-connector-access-control' ),
			),
			'pending_requests' => array(
				'available' => $pending['available'],
				'notice'    => $pending['notice'],
				'count'     => $pending['available'] ? count( $pending['rows'] ) : 0,
				'sentence'  => $pending['available']
					? sprintf(
						/* translators: %d: pending count */
						_n(
							'%d pending access request.',
							'%d pending access requests.',
							count( $pending['rows'] ),
							'handl-ai-connector-access-control'
						),
						count( $pending['rows'] )
					)
					: __( 'Pending access requests: source unavailable.', 'handl-ai-connector-access-control' ),
			),
			'findings'         => array(
				'available' => $findings['available'],
				'notice'    => $findings['notice'],
				'counts'    => $findings['counts'],
				'sentence'  => self::findings_sentence( $findings ),
			),
		);

		return array(
			'user_id'     => $user_id,
			'now'         => $now,
			'gap_start'   => $gap_start,
			'gap_seconds' => $duration,
			'gap_days'    => self::gap_days(),
			'sections'    => $sections,
			'framing'     => self::FRAMING,
		);
	}

	/**
	 * @param array{counts:array<string,int>,available:bool,notice:string} $findings Findings pack.
	 */
	private static function findings_sentence( array $findings ): string {
		if ( empty( $findings['available'] ) ) {
			return __( 'Unacked findings: source unavailable.', 'handl-ai-connector-access-control' );
		}
		$total = 0;
		foreach ( $findings['counts'] as $n ) {
			$total += (int) $n;
		}

		return sprintf(
			/* translators: %d: unacked findings */
			_n(
				'%d unacked audit finding across sibling checks.',
				'%d unacked audit findings across sibling checks.',
				$total,
				'handl-ai-connector-access-control'
			),
			$total
		);
	}

	/* ---------------------------------------------------------------------
	 * Admin UI
	 * ------------------------------------------------------------------ */

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) || ! class_exists( Admin::class, false ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Welcome back', 'handl-ai-connector-access-control' ),
			__( 'Welcome back', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function page_url(): string {
		return add_query_arg(
			array( 'page' => self::PAGE_SLUG ),
			admin_url( 'admin.php' )
		);
	}

	public static function maybe_render_notice(): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		$user_id = (int) get_current_user_id();
		if ( ! self::qualifies_for_notice( $user_id ) ) {
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG === $page ) {
			return;
		}
		$gap_days = (int) floor( self::absence_gap_seconds( $user_id ) / ( defined( 'DAY_IN_SECONDS' ) ? DAY_IN_SECONDS : 86400 ) );
		echo '<div class="notice notice-info handl-aicac-welcome-back-notice">';
		echo '<p><strong>' . esc_html__( 'Welcome back', 'handl-ai-connector-access-control' ) . '</strong> — ';
		echo esc_html(
			sprintf(
				/* translators: %d: days away */
				_n(
					'You were away about %d day. Review what changed in AI governance.',
					'You were away about %d days. Review what changed in AI governance.',
					max( 1, $gap_days ),
					'handl-ai-connector-access-control'
				),
				max( 1, $gap_days )
			)
		);
		echo ' <a href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Open catch-up brief', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';
		if ( Caps::user_can_manage() || Caps::user_can_view() ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline;">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_DISMISS ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_DISMISS );
			}
			submit_button( __( 'Dismiss', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
			echo '</form>';
		}
		echo '</div>';
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$settings   = self::get_settings();
		$can_manage = Caps::user_can_manage();
		$user_id    = (int) get_current_user_id();
		$enabled    = self::is_enabled();
		$notice     = isset( $_GET['wb_notice'] ) ? sanitize_key( (string) wp_unslash( $_GET['wb_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Welcome back', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'A personal catch-up brief after you have been away from wp-admin. Off by default. Read-only — it only stores your last-seen time.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( 'saved' === $notice ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Welcome-back settings saved.', 'handl-ai-connector-access-control' ) . '</p></div>';
		} elseif ( 'dismissed' === $notice ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Catch-up dismissed until your next qualifying absence.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable welcome back', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Show a catch-up notice after a long absence', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row">' . esc_html__( 'Gap threshold (days)', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<input type="number" min="1" max="365" name="' . esc_attr( self::POST_GAP ) . '" value="' . esc_attr( (string) (int) $settings['gap_days'] ) . '" />';
			echo '<p class="description">' . esc_html__( 'Minimum days away before the notice appears. Default 7.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save welcome-back settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Welcome back is off.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		$brief = self::build_brief( $user_id );
		// Visiting the catch-up screen marks presence (clears active notice).
		if ( self::qualifies_for_notice( $user_id ) ) {
			self::mark_present( $user_id );
		} else {
			self::maybe_track_last_seen( null, true );
		}

		$days = (int) floor( (int) $brief['gap_seconds'] / ( defined( 'DAY_IN_SECONDS' ) ? DAY_IN_SECONDS : 86400 ) );
		echo '<h2>' . esc_html__( 'Your catch-up brief', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p>' . esc_html(
			sprintf(
				/* translators: %d: days */
				_n(
					'Absence window: about %d day.',
					'Absence window: about %d days.',
					max( 0, $days ),
					'handl-ai-connector-access-control'
				),
				max( 0, $days )
			)
		) . '</p>';
		echo '<ul>';
		foreach ( (array) $brief['sections'] as $section ) {
			if ( ! is_array( $section ) ) {
				continue;
			}
			echo '<li>' . esc_html( (string) ( $section['sentence'] ?? '' ) ) . '</li>';
		}
		echo '</ul>';
		echo '</div>';
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'Forbidden.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		$enabled = isset( $_POST[ self::POST_ENABLED ] );
		$gap     = isset( $_POST[ self::POST_GAP ] ) ? (int) wp_unslash( $_POST[ self::POST_GAP ] ) : self::DEFAULT_GAP_DAYS;
		self::save_settings(
			array(
				'enabled'  => $enabled,
				'gap_days' => $gap,
			)
		);
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'      => self::PAGE_SLUG,
					'wb_notice' => 'saved',
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	public static function handle_dismiss(): void {
		if ( ! Caps::user_can_view() ) {
			wp_die( esc_html__( 'Forbidden.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_DISMISS );
		$user_id = (int) get_current_user_id();
		self::dismiss_for_user( $user_id );
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'      => self::PAGE_SLUG,
					'wb_notice' => 'dismissed',
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}
}
