<?php
/**
 * AICAC-CHARGEBACK (#349): monthly per-user / per-role AI cost statements.
 *
 * Aggregates handl_aicac_recent_calls read-only, prices via Cost public methods,
 * registers its own statement screen + CSV (no admin.php edits), optional
 * monthly owner email OFF by default.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Showback / chargeback statements from retained activity.
 */
final class Chargeback {

	public const OPTION_KEY = 'handl_aicac_chargeback';

	public const SENT_OPTION_KEY = 'handl_aicac_chargeback_sent';

	public const CRON_HOOK = 'handl_aicac_chargeback_email';

	public const PAGE_SLUG = 'handl-aicac-chargeback';

	public const REMOVED_LABEL = '(removed users)';

	public const UNKNOWN_ROLE = '(unknown)';

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_init', array( self::class, 'maybe_save_settings' ), 6 );
		add_action( self::CRON_HOOK, array( self::class, 'cron_send' ) );
		add_action( 'init', array( self::class, 'maybe_self_heal_schedule' ), 23 );
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		delete_option( self::OPTION_KEY );
		delete_option( self::SENT_OPTION_KEY );
		$ts = wp_next_scheduled( self::CRON_HOOK );
		if ( $ts ) {
			wp_unschedule_event( $ts, self::CRON_HOOK );
		}
	}

	/**
	 * @return array{email_enabled:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::OPTION_KEY, array() ) );
	}

	/**
	 * @param mixed $raw
	 * @return array{email_enabled:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		$enabled = false;
		if ( is_array( $raw ) && ! empty( $raw['email_enabled'] ) ) {
			$enabled = true;
		}

		return array( 'email_enabled' => $enabled );
	}

	/**
	 * @param array<string,mixed> $settings
	 */
	public static function save_settings( array $settings ): bool {
		$clean  = self::sanitize_settings( $settings );
		$before = self::get_settings();
		if ( $clean === $before ) {
			return false;
		}
		update_option( self::OPTION_KEY, $clean, false );
		self::maybe_schedule();

		return true;
	}

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Cost statement', 'handl-ai-connector-access-control' ),
			__( 'Cost statement', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function maybe_self_heal_schedule(): void {
		self::maybe_schedule();
	}

	public static function maybe_schedule(): void {
		$want = ! empty( self::get_settings()['email_enabled'] );
		if ( $want ) {
			if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
				$delay = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
				wp_schedule_event( Clock::now() + $delay, 'daily', self::CRON_HOOK );
			}
			return;
		}
		$ts = wp_next_scheduled( self::CRON_HOOK );
		if ( $ts ) {
			wp_unschedule_event( $ts, self::CRON_HOOK );
		}
	}

	public static function cron_send(): void {
		self::send_if_due( Policy::get_policy(), Clock::now() );
	}

	/**
	 * Send prior calendar month statement once the current month has started.
	 *
	 * @param array<string,mixed> $policy
	 * @return array{sent:bool,status:string,period_ym:string}
	 */
	public static function send_if_due( array $policy, ?int $now = null ): array {
		$now = null !== $now ? $now : Clock::now();
		$tz  = self::timezone();
		$dt  = ( new \DateTimeImmutable( '@' . $now ) )->setTimezone( $tz );
		$period_ym = $dt->modify( 'first day of last month' )->format( 'Y-m' );

		$base = array(
			'sent'      => false,
			'status'    => 'skipped',
			'period_ym' => $period_ym,
		);

		if ( empty( self::get_settings()['email_enabled'] ) ) {
			$base['status'] = 'inactive';
			return $base;
		}

		if ( (string) get_option( self::SENT_OPTION_KEY, '' ) === $period_ym ) {
			$base['status'] = 'already_sent';
			return $base;
		}

		$to = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			$base['status'] = 'no_email';
			return $base;
		}

		$log       = self::read_log();
		$statement = self::build_statement( $log, $policy, $period_ym, $now );
		$prior_ym  = ( new \DateTimeImmutable( $period_ym . '-01' ) )->modify( '-1 month' )->format( 'Y-m' );
		$prior     = self::build_statement( $log, $policy, $prior_ym, $now );

		$subject = sprintf(
			/* translators: %s: YYYY-MM period */
			__( '[AI Access Control] Cost statement %s', 'handl-ai-connector-access-control' ),
			$period_ym
		);
		$body = self::format_email_body( $statement, $prior );
		$ok   = Alerts::safe_wp_mail( $to, $subject, $body );
		if ( $ok ) {
			update_option( self::SENT_OPTION_KEY, $period_ym, false );
			$base['sent']   = true;
			$base['status'] = 'sent';
		} else {
			$base['status'] = 'mail_failed';
		}

		return $base;
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function read_log(): array {
		$raw = get_option( Plugin::LOG_OPTION_KEY, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $row ) {
			if ( is_array( $row ) ) {
				$out[] = $row;
			}
		}

		return $out;
	}

	/**
	 * Calendar-month bounds in site timezone: [start_ts, end_ts) exclusive end.
	 *
	 * @return array{start_ts:int,end_ts:int,ym:string}|null
	 */
	public static function month_window( string $ym, ?\DateTimeZone $tz = null ): ?array {
		$ym = self::sanitize_month( $ym );
		if ( '' === $ym ) {
			return null;
		}
		$tz  = $tz ?: self::timezone();
		$start = \DateTimeImmutable::createFromFormat( '!Y-m-d H:i:s', $ym . '-01 00:00:00', $tz );
		if ( ! $start ) {
			return null;
		}
		$end = $start->modify( '+1 month' );

		return array(
			'start_ts' => $start->getTimestamp(),
			'end_ts'   => $end->getTimestamp(),
			'ym'       => $ym,
		);
	}

	public static function sanitize_month( string $ym ): string {
		$ym = trim( $ym );
		if ( 1 !== preg_match( '/^\d{4}-\d{2}$/', $ym ) ) {
			return '';
		}
		$y = (int) substr( $ym, 0, 4 );
		$m = (int) substr( $ym, 5, 2 );
		if ( $y < 2000 || $y > 2100 || $m < 1 || $m > 12 ) {
			return '';
		}

		return sprintf( '%04d-%02d', $y, $m );
	}

	public static function default_month( ?int $now = null ): string {
		$now = null !== $now ? $now : Clock::now();
		$dt  = ( new \DateTimeImmutable( '@' . $now ) )->setTimezone( self::timezone() );

		return $dt->format( 'Y-m' );
	}

	/**
	 * Price one activity row via Cost public APIs only.
	 *
	 * @param array<string,mixed> $row
	 * @param array<string,mixed> $policy
	 */
	public static function row_cost_usd( array $row, array $policy ): ?float {
		$has_in  = array_key_exists( 'input_tokens', $row );
		$has_out = array_key_exists( 'output_tokens', $row );
		if ( ! $has_in && ! $has_out ) {
			// Still count the call with $0 when no token fields — spend unknown.
			return null;
		}
		$in    = $has_in ? (int) $row['input_tokens'] : null;
		$out   = $has_out ? (int) $row['output_tokens'] : null;
		$rates = Cost::rates_from_policy( $policy, isset( $row['provider'] ) ? (string) $row['provider'] : null );

		return Cost::estimate_usd( $in, $out, $rates );
	}

	/**
	 * Aggregate retained calls for one calendar month.
	 *
	 * Optional $role_at(user_id, ts, row) injects role-at-call-time for tests /
	 * mid-month role changes. Rows may also carry a `role` string.
	 *
	 * @param list<array<string,mixed>> $log
	 * @param array<string,mixed>       $policy
	 * @param callable|null             $role_at fn(int $user_id, int $ts, array $row): string
	 * @return array{
	 *   ym:string,
	 *   start_ts:int,
	 *   end_ts:int,
	 *   total_cost:float,
	 *   total_calls:int,
	 *   users: list<array{user_id:int,label:string,role:string,calls:int,input_tokens:int,output_tokens:int,cost:float}>,
	 *   roles: list<array{role:string,calls:int,input_tokens:int,output_tokens:int,cost:float}>
	 * }
	 */
	public static function build_statement( array $log, array $policy, string $ym, ?int $now = null, ?callable $role_at = null ): array {
		$window = self::month_window( $ym );
		if ( null === $window ) {
			$ym     = self::default_month( $now );
			$window = self::month_window( $ym );
		}
		/** @var array{start_ts:int,end_ts:int,ym:string} $window */

		$user_buckets = array();
		$role_buckets = array();

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) || ! Usage_Trends::is_activity_row( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts < $window['start_ts'] || $ts >= $window['end_ts'] ) {
				continue;
			}

			$uid = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
			if ( $uid <= 0 ) {
				continue;
			}

			$role = '';
			if ( null !== $role_at ) {
				$role = sanitize_key( (string) $role_at( $uid, $ts, $row ) );
			} elseif ( isset( $row['role'] ) && is_string( $row['role'] ) && '' !== $row['role'] ) {
				$role = sanitize_key( $row['role'] );
			} else {
				$role = self::primary_role_for_user( $uid );
			}
			if ( '' === $role ) {
				$role = self::UNKNOWN_ROLE;
			}

			$label = self::user_label( $uid );
			$key   = $label === self::REMOVED_LABEL ? ( 'removed:' . $uid ) : ( 'u:' . $uid );

			if ( ! isset( $user_buckets[ $key ] ) ) {
				$user_buckets[ $key ] = array(
					'user_id'       => $label === self::REMOVED_LABEL ? 0 : $uid,
					'label'         => $label,
					'role'          => $role,
					'calls'         => 0,
					'input_tokens'  => 0,
					'output_tokens' => 0,
					'cost'          => 0.0,
				);
			}

			// Mid-month role change: keep first observed role on the user row;
			// role rollup still attributes each call to role-at-call-time.
			++$user_buckets[ $key ]['calls'];
			if ( array_key_exists( 'input_tokens', $row ) ) {
				$user_buckets[ $key ]['input_tokens'] += max( 0, (int) $row['input_tokens'] );
			}
			if ( array_key_exists( 'output_tokens', $row ) ) {
				$user_buckets[ $key ]['output_tokens'] += max( 0, (int) $row['output_tokens'] );
			}
			$usd = self::row_cost_usd( $row, $policy );
			if ( null !== $usd ) {
				$user_buckets[ $key ]['cost'] += $usd;
			}

			if ( ! isset( $role_buckets[ $role ] ) ) {
				$role_buckets[ $role ] = array(
					'role'          => $role,
					'calls'         => 0,
					'input_tokens'  => 0,
					'output_tokens' => 0,
					'cost'          => 0.0,
				);
			}
			++$role_buckets[ $role ]['calls'];
			if ( array_key_exists( 'input_tokens', $row ) ) {
				$role_buckets[ $role ]['input_tokens'] += max( 0, (int) $row['input_tokens'] );
			}
			if ( array_key_exists( 'output_tokens', $row ) ) {
				$role_buckets[ $role ]['output_tokens'] += max( 0, (int) $row['output_tokens'] );
			}
			if ( null !== $usd ) {
				$role_buckets[ $role ]['cost'] += $usd;
			}
		}

		// Fold all removed-user keys into one row.
		$removed = null;
		$users   = array();
		foreach ( $user_buckets as $row ) {
			if ( self::REMOVED_LABEL === $row['label'] ) {
				if ( null === $removed ) {
					$removed = $row;
					$removed['user_id'] = 0;
					$removed['role']    = self::REMOVED_LABEL;
				} else {
					$removed['calls']         += $row['calls'];
					$removed['input_tokens']  += $row['input_tokens'];
					$removed['output_tokens'] += $row['output_tokens'];
					$removed['cost']          += $row['cost'];
				}
				continue;
			}
			// AC: users with zero spend omitted.
			if ( (float) $row['cost'] <= 0.0 ) {
				continue;
			}
			$users[] = $row;
		}
		if ( null !== $removed && (float) $removed['cost'] > 0.0 ) {
			$users[] = $removed;
		}

		$roles = array();
		foreach ( $role_buckets as $row ) {
			if ( (float) $row['cost'] <= 0.0 ) {
				continue;
			}
			$roles[] = $row;
		}

		$users = self::sort_rows( $users, 'cost', 'desc' );
		$roles = self::sort_rows( $roles, 'cost', 'desc' );

		$total_cost  = 0.0;
		$total_calls = 0;
		foreach ( $users as $u ) {
			$total_cost  += (float) $u['cost'];
			$total_calls += (int) $u['calls'];
		}

		return array(
			'ym'          => $window['ym'],
			'start_ts'    => $window['start_ts'],
			'end_ts'      => $window['end_ts'],
			'total_cost'  => $total_cost,
			'total_calls' => $total_calls,
			'users'       => $users,
			'roles'       => $roles,
		);
	}

	/**
	 * @param list<array<string,mixed>> $rows
	 * @return list<array<string,mixed>>
	 */
	public static function sort_rows( array $rows, string $orderby, string $order ): array {
		$allowed = array( 'cost', 'calls', 'label', 'role', 'input_tokens', 'output_tokens' );
		if ( ! in_array( $orderby, $allowed, true ) ) {
			$orderby = 'cost';
		}
		$order = 'asc' === strtolower( $order ) ? 'asc' : 'desc';
		usort(
			$rows,
			static function ( array $a, array $b ) use ( $orderby, $order ): int {
				$av = $a[ $orderby ] ?? null;
				$bv = $b[ $orderby ] ?? null;
				if ( is_string( $av ) || is_string( $bv ) ) {
					$cmp = strcasecmp( (string) $av, (string) $bv );
				} else {
					$cmp = ( (float) $av <=> (float) $bv );
				}
				return 'asc' === $order ? $cmp : -$cmp;
			}
		);

		return $rows;
	}

	public static function primary_role_for_user( int $user_id ): string {
		if ( $user_id <= 0 ) {
			return '';
		}
		if ( array_key_exists( 'handl_aicac_test_users', $GLOBALS )
			&& isset( $GLOBALS['handl_aicac_test_users'][ $user_id ] ) ) {
			$roles = $GLOBALS['handl_aicac_test_users'][ $user_id ]['roles'] ?? array();
			if ( is_array( $roles ) && isset( $roles[0] ) ) {
				return sanitize_key( (string) $roles[0] );
			}
			return '';
		}
		$user = get_userdata( $user_id );
		if ( ! $user || empty( $user->roles ) || ! is_array( $user->roles ) ) {
			return '';
		}
		$roles = array_values( $user->roles );

		return sanitize_key( (string) ( $roles[0] ?? '' ) );
	}

	public static function user_label( int $user_id ): string {
		if ( $user_id <= 0 ) {
			return self::REMOVED_LABEL;
		}
		if ( array_key_exists( 'handl_aicac_test_users', $GLOBALS ) ) {
			if ( ! isset( $GLOBALS['handl_aicac_test_users'][ $user_id ] ) ) {
				return self::REMOVED_LABEL;
			}
			$u = $GLOBALS['handl_aicac_test_users'][ $user_id ];
			$login = isset( $u['user_login'] ) ? (string) $u['user_login'] : '';
			return '' !== $login ? $login : ( 'user#' . $user_id );
		}
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return self::REMOVED_LABEL;
		}
		$login = isset( $user->user_login ) ? (string) $user->user_login : '';

		return '' !== $login ? $login : ( 'user#' . $user_id );
	}

	public static function timezone(): \DateTimeZone {
		if ( function_exists( 'wp_timezone' ) ) {
			$tz = wp_timezone();
			if ( $tz instanceof \DateTimeZone ) {
				return $tz;
			}
		}
		$string = function_exists( 'wp_timezone_string' ) ? (string) wp_timezone_string() : 'UTC';
		try {
			return new \DateTimeZone( $string ?: 'UTC' );
		} catch ( \Exception $e ) {
			return new \DateTimeZone( 'UTC' );
		}
	}

	/**
	 * @param array<string,mixed> $statement
	 * @param array<string,mixed> $prior
	 */
	public static function format_email_body( array $statement, array $prior ): string {
		$ym     = (string) ( $statement['ym'] ?? '' );
		$total  = (float) ( $statement['total_cost'] ?? 0 );
		$prior_total = (float) ( $prior['total_cost'] ?? 0 );
		$delta  = $total - $prior_total;
		$lines  = array();
		$lines[] = sprintf(
			/* translators: 1: YYYY-MM, 2: formatted USD total */
			__( 'AI cost statement for %1$s — total est. %2$s', 'handl-ai-connector-access-control' ),
			$ym,
			Cost::format_usd( $total )
		);
		$lines[] = sprintf(
			/* translators: 1: formatted prior total, 2: signed delta */
			__( 'Prior month: %1$s (delta %2$s)', 'handl-ai-connector-access-control' ),
			Cost::format_usd( $prior_total ),
			( $delta >= 0 ? '+' : '' ) . Cost::format_usd( $delta )
		);
		$lines[] = '';
		$lines[] = __( 'Top spenders:', 'handl-ai-connector-access-control' );
		$users   = isset( $statement['users'] ) && is_array( $statement['users'] ) ? $statement['users'] : array();
		$top     = array_slice( $users, 0, 5 );
		if ( empty( $top ) ) {
			$lines[] = __( 'No AI spend this month.', 'handl-ai-connector-access-control' );
		} else {
			foreach ( $top as $u ) {
				$lines[] = sprintf(
					'- %s (%s): %s — %d calls',
					(string) ( $u['label'] ?? '' ),
					(string) ( $u['role'] ?? '' ),
					Cost::format_usd( (float) ( $u['cost'] ?? 0 ) ),
					(int) ( $u['calls'] ?? 0 )
				);
			}
		}
		$lines[] = '';
		$lines[] = __( 'Estimates use configured token rates. Not a billing invoice.', 'handl-ai-connector-access-control' );

		return implode( "\n", $lines );
	}

	public static function maybe_save_settings(): void {
		if ( ! is_admin() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified below.
		if ( empty( $_POST['handl_aicac_chargeback_save'] ) ) {
			return;
		}
		if ( ! Caps::user_can_manage() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_chargeback_settings', 'handl_aicac_chargeback_nonce' );
		$email = ! empty( $_POST['handl_aicac_chargeback_email'] );
		self::save_settings( array( 'email_enabled' => $email ) );
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'    => self::PAGE_SLUG,
					'updated' => '1',
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	public static function maybe_handle_csv(): void {
		if ( ! is_admin() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- verified below.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action = isset( $_GET['handl_aicac_chargeback_csv'] ) ? sanitize_key( wp_unslash( (string) $_GET['handl_aicac_chargeback_csv'] ) ) : '';
		if ( '1' !== $action && 'users' !== $action && 'roles' !== $action ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			wp_die( esc_html__( 'You do not have permission to export this statement.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( 'handl_aicac_chargeback_csv' );

		$ym = isset( $_GET['month'] ) ? self::sanitize_month( wp_unslash( (string) $_GET['month'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( '' === $ym ) {
			$ym = self::default_month();
		}
		$policy    = Policy::get_policy();
		$statement = self::build_statement( self::read_log(), $policy, $ym );
		$which     = ( 'roles' === $action ) ? 'roles' : 'users';
		$csv       = self::csv_for( $statement, $which );

		$filename = 'handl-aicac-chargeback-' . $ym . '-' . $which . '.csv';
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- raw CSV download body.
		echo $csv;
		exit;
	}

	/**
	 * @param array<string,mixed> $statement
	 */
	public static function csv_for( array $statement, string $which = 'users' ): string {
		$lines = array();
		if ( 'roles' === $which ) {
			$lines[] = 'role,calls,input_tokens,output_tokens,cost_usd';
			$rows    = isset( $statement['roles'] ) && is_array( $statement['roles'] ) ? $statement['roles'] : array();
			foreach ( $rows as $r ) {
				$lines[] = self::csv_line(
					array(
						(string) ( $r['role'] ?? '' ),
						(string) (int) ( $r['calls'] ?? 0 ),
						(string) (int) ( $r['input_tokens'] ?? 0 ),
						(string) (int) ( $r['output_tokens'] ?? 0 ),
						self::csv_money( (float) ( $r['cost'] ?? 0 ) ),
					)
				);
			}
		} else {
			$lines[] = 'user,user_id,role,calls,input_tokens,output_tokens,cost_usd';
			$rows    = isset( $statement['users'] ) && is_array( $statement['users'] ) ? $statement['users'] : array();
			foreach ( $rows as $r ) {
				$lines[] = self::csv_line(
					array(
						(string) ( $r['label'] ?? '' ),
						(string) (int) ( $r['user_id'] ?? 0 ),
						(string) ( $r['role'] ?? '' ),
						(string) (int) ( $r['calls'] ?? 0 ),
						(string) (int) ( $r['input_tokens'] ?? 0 ),
						(string) (int) ( $r['output_tokens'] ?? 0 ),
						self::csv_money( (float) ( $r['cost'] ?? 0 ) ),
					)
				);
			}
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param list<string> $cols
	 */
	private static function csv_line( array $cols ): string {
		$out = array();
		foreach ( $cols as $c ) {
			$c = str_replace( '"', '""', $c );
			$out[] = '"' . $c . '"';
		}

		return implode( ',', $out );
	}

	private static function csv_money( float $amount ): string {
		return number_format( $amount, 6, '.', '' );
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'handl-ai-connector-access-control' ) );
		}

		$ym = isset( $_GET['month'] ) ? self::sanitize_month( wp_unslash( (string) $_GET['month'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( '' === $ym ) {
			$ym = self::default_month();
		}
		$orderby = isset( $_GET['orderby'] ) ? sanitize_key( wp_unslash( (string) $_GET['orderby'] ) ) : 'cost'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$order   = isset( $_GET['order'] ) ? sanitize_key( wp_unslash( (string) $_GET['order'] ) ) : 'desc'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$policy    = Policy::get_policy();
		$statement = self::build_statement( self::read_log(), $policy, $ym );
		$statement['users'] = self::sort_rows( $statement['users'], $orderby, $order );
		$statement['roles'] = self::sort_rows( $statement['roles'], $orderby, $order );
		$settings  = self::get_settings();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'AI cost statement', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Estimated spend by user and role for one calendar month. Uses configured token rates — not a billing invoice.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( ! empty( $_GET['updated'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Settings saved.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}

		echo '<form method="get" action="' . esc_url( admin_url( 'admin.php' ) ) . '" style="margin:1em 0;">';
		echo '<input type="hidden" name="page" value="' . esc_attr( self::PAGE_SLUG ) . '" />';
		echo '<label for="handl-aicac-chargeback-month">' . esc_html__( 'Month', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<input type="month" id="handl-aicac-chargeback-month" name="month" value="' . esc_attr( $ym ) . '" /> ';
		submit_button( __( 'Show', 'handl-ai-connector-access-control' ), 'secondary', '', false );
		echo '</form>';

		echo '<p><strong>' . esc_html(
			sprintf(
				/* translators: 1: YYYY-MM, 2: USD total, 3: call count */
				__( '%1$s — total est. %2$s across %3$d calls', 'handl-ai-connector-access-control' ),
				$statement['ym'],
				Cost::format_usd( (float) $statement['total_cost'] ),
				(int) $statement['total_calls']
			)
		) . '</strong></p>';

		$csv_users = wp_nonce_url(
			add_query_arg(
				array(
					'page'                      => self::PAGE_SLUG,
					'month'                     => $ym,
					'handl_aicac_chargeback_csv' => 'users',
				),
				admin_url( 'admin.php' )
			),
			'handl_aicac_chargeback_csv'
		);
		$csv_roles = wp_nonce_url(
			add_query_arg(
				array(
					'page'                      => self::PAGE_SLUG,
					'month'                     => $ym,
					'handl_aicac_chargeback_csv' => 'roles',
				),
				admin_url( 'admin.php' )
			),
			'handl_aicac_chargeback_csv'
		);
		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv_users ) . '">' . esc_html__( 'Download users CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $csv_roles ) . '">' . esc_html__( 'Download roles CSV', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		self::render_table(
			__( 'By user', 'handl-ai-connector-access-control' ),
			$statement['users'],
			'user',
			$ym,
			$orderby,
			$order
		);
		self::render_table(
			__( 'By role', 'handl-ai-connector-access-control' ),
			$statement['roles'],
			'role',
			$ym,
			$orderby,
			$order
		);

		if ( Caps::user_can_manage() ) {
			echo '<h2>' . esc_html__( 'Monthly owner email', 'handl-ai-connector-access-control' ) . '</h2>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin.php?page=' . self::PAGE_SLUG ) ) . '">';
			wp_nonce_field( 'handl_aicac_chargeback_settings', 'handl_aicac_chargeback_nonce' );
			echo '<input type="hidden" name="handl_aicac_chargeback_save" value="1" />';
			echo '<label><input type="checkbox" name="handl_aicac_chargeback_email" value="1"' . checked( ! empty( $settings['email_enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Email the site owner a monthly statement (top spenders + month-over-month delta). Off by default.', 'handl-ai-connector-access-control' );
			echo '</label>';
			submit_button( __( 'Save email setting', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		echo '</div>';
	}

	/**
	 * @param list<array<string,mixed>> $rows
	 */
	private static function render_table( string $title, array $rows, string $kind, string $ym, string $orderby, string $order ): void {
		echo '<h2>' . esc_html( $title ) . '</h2>';
		if ( empty( $rows ) ) {
			echo '<p>' . esc_html__( 'No AI spend for this month.', 'handl-ai-connector-access-control' ) . '</p>';
			return;
		}
		echo '<table class="widefat striped"><thead><tr>';
		if ( 'user' === $kind ) {
			echo '<th>' . self::sort_link( __( 'User', 'handl-ai-connector-access-control' ), 'label', $ym, $orderby, $order ) . '</th>';
			echo '<th>' . self::sort_link( __( 'Role', 'handl-ai-connector-access-control' ), 'role', $ym, $orderby, $order ) . '</th>';
		} else {
			echo '<th>' . self::sort_link( __( 'Role', 'handl-ai-connector-access-control' ), 'role', $ym, $orderby, $order ) . '</th>';
		}
		echo '<th>' . self::sort_link( __( 'Calls', 'handl-ai-connector-access-control' ), 'calls', $ym, $orderby, $order ) . '</th>';
		echo '<th>' . self::sort_link( __( 'Input tokens', 'handl-ai-connector-access-control' ), 'input_tokens', $ym, $orderby, $order ) . '</th>';
		echo '<th>' . self::sort_link( __( 'Output tokens', 'handl-ai-connector-access-control' ), 'output_tokens', $ym, $orderby, $order ) . '</th>';
		echo '<th>' . self::sort_link( __( 'Est. cost', 'handl-ai-connector-access-control' ), 'cost', $ym, $orderby, $order ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $rows as $r ) {
			echo '<tr>';
			if ( 'user' === $kind ) {
				echo '<td>' . esc_html( (string) ( $r['label'] ?? '' ) ) . '</td>';
				echo '<td>' . esc_html( (string) ( $r['role'] ?? '' ) ) . '</td>';
			} else {
				echo '<td>' . esc_html( (string) ( $r['role'] ?? '' ) ) . '</td>';
			}
			echo '<td>' . esc_html( (string) (int) ( $r['calls'] ?? 0 ) ) . '</td>';
			echo '<td>' . esc_html( (string) (int) ( $r['input_tokens'] ?? 0 ) ) . '</td>';
			echo '<td>' . esc_html( (string) (int) ( $r['output_tokens'] ?? 0 ) ) . '</td>';
			echo '<td>' . esc_html( Cost::format_usd( (float) ( $r['cost'] ?? 0 ) ) ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
	}

	private static function sort_link( string $label, string $col, string $ym, string $orderby, string $order ): string {
		$next = ( $orderby === $col && 'asc' === $order ) ? 'desc' : 'asc';
		if ( $orderby !== $col ) {
			$next = 'desc';
		}
		$url = add_query_arg(
			array(
				'page'    => self::PAGE_SLUG,
				'month'   => $ym,
				'orderby' => $col,
				'order'   => $next,
			),
			admin_url( 'admin.php' )
		);

		return '<a href="' . esc_url( $url ) . '">' . esc_html( $label ) . '</a>';
	}
}
