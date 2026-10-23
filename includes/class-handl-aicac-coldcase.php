<?php
/**
 * AICAC-COLDCASE (#448): first-deny abandonment census.
 *
 * Daily cron soft-reads the activity log (and access-request map when present)
 * and lists users whose only AI event is a deny that is at least N days old —
 * the silent leavers COACH / FRICTION / LIMBO cannot see.
 *
 * README-FREE. Own option only. No edits to admin.php / policy / alerts / cost.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One-deny-then-silence churn census.
 */
final class Coldcase {

	public const OPTION_KEY = 'handl_aicac_coldcase';

	public const CRON_HOOK = 'handl_aicac_coldcase_scan';

	public const PAGE_SLUG = 'handl-aicac-coldcase';

	public const ACTION_SAVE = 'handl_aicac_coldcase_save';

	public const POST_PRESENT = 'handl_aicac_coldcase_present';

	public const POST_SILENT_DAYS = 'handl_aicac_coldcase_silent_days';

	public const DEFAULT_SILENT_DAYS = 14;

	public const MAX_CASES = 200;

	/** @var bool */
	private static $registered = false;

	/** @var int|null */
	private static $test_now = null;

	/** @var list<array<string,mixed>>|null */
	private static $test_log = null;

	/** @var array<string,array<string,mixed>>|null */
	private static $test_access_requests = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( self::CRON_HOOK, array( self::class, 'cron_run' ) );
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		self::maybe_schedule();
	}

	public static function reset_for_tests(): void {
		self::$registered           = false;
		self::$test_now             = null;
		self::$test_log             = null;
		self::$test_access_requests = null;
		delete_option( self::OPTION_KEY );
		if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
			wp_clear_scheduled_hook( self::CRON_HOOK );
		}
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	/**
	 * @param list<array<string,mixed>>|null $log Injected activity rows.
	 */
	public static function set_test_log( ?array $log ): void {
		self::$test_log = $log;
	}

	/**
	 * @param array<string,array<string,mixed>>|null $map Injected access-request map.
	 */
	public static function set_test_access_requests( ?array $map ): void {
		self::$test_access_requests = $map;
	}

	public static function now(): int {
		if ( null !== self::$test_now ) {
			return (int) self::$test_now;
		}
		if ( class_exists( Clock::class, false ) && method_exists( Clock::class, 'now' ) ) {
			return (int) Clock::now();
		}

		return time();
	}

	public static function maybe_schedule(): void {
		if ( ! function_exists( 'wp_next_scheduled' ) || ! function_exists( 'wp_schedule_event' ) ) {
			return;
		}
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			$day = defined( 'DAY_IN_SECONDS' ) ? DAY_IN_SECONDS : 86400;
			wp_schedule_event( time() + $day, 'daily', self::CRON_HOOK );
		}
	}

	public static function cron_run(): void {
		self::scan( self::now() );
	}

	/**
	 * @return array{silent_days:int,updated_at:int,cases:list<array<string,mixed>>}
	 */
	public static function defaults(): array {
		return array(
			'silent_days' => self::DEFAULT_SILENT_DAYS,
			'updated_at'  => 0,
			'cases'       => array(),
		);
	}

	/**
	 * @return array{silent_days:int,updated_at:int,cases:list<array<string,mixed>>}
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::OPTION_KEY, array() ) );
	}

	/**
	 * @param mixed $raw Raw option.
	 * @return array{silent_days:int,updated_at:int,cases:list<array<string,mixed>>}
	 */
	public static function sanitize_state( $raw ): array {
		$out = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$days = isset( $raw['silent_days'] ) ? (int) $raw['silent_days'] : self::DEFAULT_SILENT_DAYS;
		if ( $days < 1 ) {
			$days = 1;
		}
		if ( $days > 365 ) {
			$days = 365;
		}
		$out['silent_days'] = $days;
		$out['updated_at']  = max( 0, (int) ( $raw['updated_at'] ?? 0 ) );

		$cases = array();
		if ( isset( $raw['cases'] ) && is_array( $raw['cases'] ) ) {
			foreach ( $raw['cases'] as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$clean = self::sanitize_case( $row );
				if ( null !== $clean ) {
					$cases[] = $clean;
				}
				if ( count( $cases ) >= self::MAX_CASES ) {
					break;
				}
			}
		}
		$out['cases'] = $cases;

		return $out;
	}

	/**
	 * @param array<string,mixed> $row Case row.
	 * @return array{user_id:int,user_login:string,rule:string,plugin:string,deny_ts:int,days_silent:int,count:int}|null
	 */
	public static function sanitize_case( array $row ): ?array {
		$user_id = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
		if ( $user_id <= 0 ) {
			return null;
		}
		$deny_ts = isset( $row['deny_ts'] ) ? (int) $row['deny_ts'] : 0;
		if ( $deny_ts <= 0 ) {
			return null;
		}
		$rule = isset( $row['rule'] ) ? sanitize_key( (string) $row['rule'] ) : '';
		if ( '' === $rule ) {
			$rule = 'unknown';
		}
		$plugin = isset( $row['plugin'] ) ? sanitize_text_field( (string) $row['plugin'] ) : '';
		$login  = isset( $row['user_login'] ) ? sanitize_text_field( (string) $row['user_login'] ) : '';
		$days   = isset( $row['days_silent'] ) ? max( 0, (int) $row['days_silent'] ) : 0;
		$count  = isset( $row['count'] ) ? max( 1, (int) $row['count'] ) : 1;

		return array(
			'user_id'     => $user_id,
			'user_login'  => $login,
			'rule'        => $rule,
			'plugin'      => $plugin,
			'deny_ts'     => $deny_ts,
			'days_silent' => $days,
			'count'       => $count,
		);
	}

	/**
	 * Persist state. Returns false when the sanitized payload matches storage (no-op).
	 *
	 * @param array<string,mixed> $state State.
	 */
	public static function save_state( array $state ): bool {
		$clean  = self::sanitize_state( $state );
		$before = self::get_state();
		if ( $clean === $before ) {
			return false;
		}
		if ( $clean === self::defaults() ) {
			delete_option( self::OPTION_KEY );
		} else {
			update_option( self::OPTION_KEY, $clean, false );
		}

		return true;
	}

	/**
	 * Update silent_days only. No-op when unchanged.
	 */
	public static function save_silent_days( int $days ): bool {
		$state                = self::get_state();
		$state['silent_days'] = $days;

		return self::save_state( $state );
	}

	public static function silent_days(): int {
		return (int) self::get_state()['silent_days'];
	}

	/**
	 * Guarded activity-log soft-read.
	 *
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
		$key = class_exists( Plugin::class, false ) ? Plugin::LOG_OPTION_KEY : 'handl_aicac_recent_calls';
		$raw = get_option( $key, null );
		if ( null === $raw || false === $raw ) {
			return array(
				'rows'      => array(),
				'available' => false,
				'notice'    => 'Activity log source unavailable.',
			);
		}
		if ( ! is_array( $raw ) ) {
			return array(
				'rows'      => array(),
				'available' => true,
				'notice'    => '',
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
	 * Soft-read access-request map. Never hard-depends on Access_Request.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	public static function read_access_requests(): array {
		if ( null !== self::$test_access_requests ) {
			return self::$test_access_requests;
		}
		$key = 'handl_aicac_access_requests';
		if ( class_exists( Access_Request::class, false ) && defined( Access_Request::class . '::OPTION_KEY' ) ) {
			$key = Access_Request::OPTION_KEY;
		}
		$raw = get_option( $key, null );
		if ( null === $raw || false === $raw || ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $id => $row ) {
			if ( is_array( $row ) ) {
				$out[ (string) $id ] = $row;
			}
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $row Activity row.
	 */
	public static function rule_from_row( array $row ): string {
		$reason = isset( $row['denial_reason'] ) ? sanitize_key( (string) $row['denial_reason'] ) : '';
		if ( '' !== $reason ) {
			return $reason;
		}
		$plugin = isset( $row['plugin'] ) ? strtolower( trim( (string) $row['plugin'] ) ) : '';
		if ( '' !== $plugin ) {
			$plugin = preg_replace( '/[^a-z0-9._-]+/', '.', str_replace( '/', '.', $plugin ) ) ?? '';
			$plugin = trim( (string) $plugin, '.' );

			return '' !== $plugin ? 'plugin:' . $plugin : 'unknown';
		}

		return 'unknown';
	}

	/**
	 * Detect cold cases from soft-read sources (does not write).
	 *
	 * @return list<array{user_id:int,user_login:string,rule:string,plugin:string,deny_ts:int,days_silent:int,count:int}>
	 */
	public static function detect_cases( ?int $now = null, ?int $silent_days = null ): array {
		$now   = null !== $now && $now > 0 ? $now : self::now();
		$days  = null !== $silent_days && $silent_days > 0 ? $silent_days : self::silent_days();
		$day   = defined( 'DAY_IN_SECONDS' ) ? DAY_IN_SECONDS : 86400;
		$cutoff = $now - ( $days * $day );

		$pack = self::read_activity_log();
		/** @var array<int,list<array<string,mixed>>> $by_user */
		$by_user = array();
		foreach ( $pack['rows'] as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$user_id = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
			if ( $user_id <= 0 ) {
				continue;
			}
			$by_user[ $user_id ][] = $row;
		}

		$requests = self::read_access_requests();
		/** @var array<int,int> $request_ts_by_user earliest request ts per user */
		$request_ts_by_user = array();
		foreach ( $requests as $req ) {
			if ( ! is_array( $req ) ) {
				continue;
			}
			$uid = isset( $req['user_id'] ) ? (int) $req['user_id'] : 0;
			$ts  = isset( $req['ts'] ) ? (int) $req['ts'] : 0;
			if ( $uid <= 0 || $ts <= 0 ) {
				continue;
			}
			if ( ! isset( $request_ts_by_user[ $uid ] ) || $ts < $request_ts_by_user[ $uid ] ) {
				$request_ts_by_user[ $uid ] = $ts;
			}
		}

		$cases = array();
		foreach ( $by_user as $user_id => $rows ) {
			usort(
				$rows,
				static function ( array $a, array $b ): int {
					return ( (int) ( $a['ts'] ?? 0 ) ) <=> ( (int) ( $b['ts'] ?? 0 ) );
				}
			);
			// One-deny-then-silence: exactly one AI event, and it is a deny.
			if ( 1 !== count( $rows ) ) {
				continue;
			}
			$row = $rows[0];
			if ( 'deny' !== (string) ( $row['decision'] ?? '' ) ) {
				continue;
			}
			$deny_ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $deny_ts <= 0 || $deny_ts > $cutoff ) {
				continue;
			}
			if ( isset( $request_ts_by_user[ $user_id ] ) && $request_ts_by_user[ $user_id ] >= $deny_ts ) {
				continue;
			}

			$login = '';
			if ( function_exists( 'get_userdata' ) ) {
				$user = get_userdata( $user_id );
				if ( $user && isset( $user->user_login ) ) {
					$login = (string) $user->user_login;
				}
			}
			if ( '' === $login && ! empty( $GLOBALS['handl_aicac_test_users'][ $user_id ]['user_login'] ) ) {
				$login = (string) $GLOBALS['handl_aicac_test_users'][ $user_id ]['user_login'];
			}

			$cases[] = array(
				'user_id'     => $user_id,
				'user_login'  => $login,
				'rule'        => self::rule_from_row( $row ),
				'plugin'      => sanitize_text_field( (string) ( $row['plugin'] ?? '' ) ),
				'deny_ts'     => $deny_ts,
				'days_silent' => (int) floor( ( $now - $deny_ts ) / $day ),
				'count'       => 1,
			);
		}

		usort(
			$cases,
			static function ( array $a, array $b ): int {
				if ( $a['days_silent'] === $b['days_silent'] ) {
					return $a['user_id'] <=> $b['user_id'];
				}

				return $b['days_silent'] <=> $a['days_silent'];
			}
		);

		if ( count( $cases ) > self::MAX_CASES ) {
			$cases = array_slice( $cases, 0, self::MAX_CASES );
		}

		return $cases;
	}

	/**
	 * Run census and persist. Returns whether storage changed.
	 */
	public static function scan( ?int $now = null ): bool {
		$now    = null !== $now && $now > 0 ? $now : self::now();
		$before = self::get_state();
		$cases  = self::detect_cases( $now, (int) $before['silent_days'] );

		// No-op when the case list is unchanged (including empty never-written).
		if ( $cases === $before['cases'] ) {
			return false;
		}

		return self::save_state(
			array(
				'silent_days' => (int) $before['silent_days'],
				'updated_at'  => $now,
				'cases'       => $cases,
			)
		);
	}

	/**
	 * @return array{
	 *   silent_days:int,
	 *   updated_at:int,
	 *   count:int,
	 *   cases:list<array<string,mixed>>,
	 *   log_available:bool,
	 *   log_notice:string,
	 *   headline:string
	 * }
	 */
	public static function snapshot( ?int $now = null ): array {
		$now   = null !== $now && $now > 0 ? $now : self::now();
		$state = self::get_state();
		// Prefer live detect for display so UI matches current log without waiting on cron.
		$cases = self::detect_cases( $now, (int) $state['silent_days'] );
		$pack  = self::read_activity_log();
		$count = count( $cases );
		/* translators: %d: number of cold-case users */
		$headline = sprintf(
			_n(
				'%d user was turned away once and never tried again',
				'%d users were turned away once and never tried again',
				$count,
				'handl-ai-connector-access-control'
			),
			$count
		);

		return array(
			'silent_days'   => (int) $state['silent_days'],
			'updated_at'    => (int) $state['updated_at'],
			'count'         => $count,
			'cases'         => $cases,
			'log_available' => ! empty( $pack['available'] ),
			'log_notice'    => (string) $pack['notice'],
			'headline'      => $headline,
		);
	}

	public static function register_menu(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) || ! class_exists( Admin::class, false ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Cold cases', 'handl-ai-connector-access-control' ),
			__( 'Cold cases', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function handle_save(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'Forbidden', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		$days = isset( $_POST[ self::POST_SILENT_DAYS ] ) ? (int) $_POST[ self::POST_SILENT_DAYS ] : self::DEFAULT_SILENT_DAYS; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		self::save_silent_days( $days );
		self::scan( self::now() );
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'            => self::PAGE_SLUG,
					'coldcase_notice' => 'saved',
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	public static function render_page(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		$snap       = self::snapshot();
		$can_manage = Caps::user_can_manage();
		$notice     = isset( $_GET['coldcase_notice'] ) ? sanitize_key( (string) wp_unslash( $_GET['coldcase_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Cold cases', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Users who hit a deny once and never came back. Opposite of Coach (repeat deniers). Read-only census from the activity log.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( 'saved' === $notice ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Cold case settings saved.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Silent days', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<input type="number" min="1" max="365" name="' . esc_attr( self::POST_SILENT_DAYS ) . '" value="' . esc_attr( (string) (int) $snap['silent_days'] ) . '" /> ';
			echo '<p class="description">' . esc_html__( 'A single deny older than this many days with no later AI activity or access request becomes a cold case. Default 14.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save cold case settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		echo '<h2>' . esc_html( $snap['headline'] ) . '</h2>';
		if ( empty( $snap['log_available'] ) ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html( (string) $snap['log_notice'] ) . '</p></div>';
		}

		if ( empty( $snap['cases'] ) ) {
			echo '<p>' . esc_html__( 'No cold cases right now.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'User', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Rule', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Days silent', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Deny time', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $snap['cases'] as $row ) {
			$label = '' !== (string) $row['user_login']
				? (string) $row['user_login']
				: '#' . (int) $row['user_id'];
			$when = function_exists( 'wp_date' )
				? wp_date( 'Y-m-d H:i', (int) $row['deny_ts'] )
				: gmdate( 'Y-m-d H:i', (int) $row['deny_ts'] );
			echo '<tr>';
			echo '<td>' . esc_html( $label ) . '</td>';
			echo '<td>' . esc_html( (string) $row['rule'] ) . '</td>';
			echo '<td>' . esc_html( (string) $row['plugin'] ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $row['days_silent'] ) . '</td>';
			echo '<td>' . esc_html( (string) $when ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
		echo '</div>';
	}
}
