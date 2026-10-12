<?php
/**
 * AICAC-UNATTENDED (#403): absent-owner failsafe (read-only).
 *
 * Attention ledger via wp_login for Caps::MANAGE users (timestamp + user_id only
 * in own state option). Unattended = no qualifying attention for N days (default
 * 21) AND AI activity (allow/deny/observe) in the window. Quiet sites never fire.
 * Exactly one re-arming [UNATTENDED] alert to backup_email (else admin_email).
 * Re-arms only on qualifying login. Optional Drill ack / policy_restored signals
 * (class_exists-guarded). Print + CSV + WP-CLI. Report only — never mutates policy.
 * OFF by default. Own two options.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Absent-owner attention ledger and unattended-site escalation.
 */
final class Unattended {

	public const SETTINGS_OPTION = 'handl_aicac_unattended';

	public const STATE_OPTION = 'handl_aicac_unattended_state';

	public const PAGE_SLUG = 'handl-aicac-unattended';

	public const ALERT_KIND = 'unattended';

	public const FRAMING = 'report_only_never_mutates_policy';

	public const FILTER_DAYS = 'handl_aicac_unattended_days';

	public const POST_PRESENT = 'handl_aicac_unattended_present';

	public const POST_ENABLED = 'handl_aicac_unattended_enabled';

	public const POST_DAYS = 'handl_aicac_unattended_days';

	public const POST_BACKUP_EMAIL = 'handl_aicac_unattended_backup_email';

	public const ACTION_SAVE = 'handl_aicac_unattended_save';

	public const DEFAULT_DAYS = 21;

	public const MIN_DAYS = 1;

	public const MAX_DAYS = 365;

	public const LEDGER_CAP = 200;

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
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_print' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );

		if ( self::is_enabled() ) {
			add_action( 'wp_login', array( self::class, 'on_wp_login' ), 10, 2 );
			add_action( 'init', array( self::class, 'maybe_fire_alerts' ), 30 );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$test_mails = array();
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATE_OPTION );
		unset( $GLOBALS['handl_aicac_unattended_test_log'] );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{enabled:bool,days:int,backup_email:string}
	 */
	public static function defaults(): array {
		return array(
			'enabled'      => false,
			'days'         => self::DEFAULT_DAYS,
			'backup_email' => '',
		);
	}

	/**
	 * @return array{enabled:bool,days:int,backup_email:string}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,days:int,backup_email:string}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}
		$email = '';
		if ( isset( $raw['backup_email'] ) ) {
			if ( function_exists( 'sanitize_email' ) ) {
				$email = sanitize_email( (string) $raw['backup_email'] );
			} else {
				$email = trim( (string) $raw['backup_email'] );
			}
			if ( '' !== $email && function_exists( 'is_email' ) && ! is_email( $email ) ) {
				$email = '';
			}
		}

		return array(
			'enabled'      => ! empty( $raw['enabled'] ),
			'days'         => self::sanitize_days( $raw['days'] ?? $defaults['days'] ),
			'backup_email' => $email,
		);
	}

	/**
	 * @param mixed $raw Raw days.
	 */
	public static function sanitize_days( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_DAYS;
		}
		$v = (int) $raw;
		if ( $v < self::MIN_DAYS ) {
			$v = self::MIN_DAYS;
		}
		if ( $v > self::MAX_DAYS ) {
			$v = self::MAX_DAYS;
		}

		return $v;
	}

	/**
	 * Effective days threshold after filter.
	 */
	public static function days(): int {
		$settings = self::get_settings();
		$base     = (int) $settings['days'];
		if ( function_exists( 'apply_filters' ) ) {
			return self::sanitize_days( apply_filters( self::FILTER_DAYS, $base ) );
		}

		return $base;
	}

	/**
	 * @param array<string,mixed> $settings Settings.
	 */
	public static function save_settings( array $settings ): bool {
		$clean       = self::sanitize_settings( $settings );
		$before      = self::get_settings();
		$was_enabled = ! empty( $before['enabled'] );
		if ( $clean === $before ) {
			return false;
		}
		if ( $clean === self::defaults() ) {
			delete_option( self::SETTINGS_OPTION );
			return true;
		}
		update_option( self::SETTINGS_OPTION, $clean, false );

		if ( ! empty( $clean['enabled'] ) && ! $was_enabled ) {
			$state                   = self::get_state();
			$state['watching_since'] = class_exists( Clock::class, false ) ? Clock::now() : time();
			self::put_state( $state );
		}

		return true;
	}

	public static function is_enabled(): bool {
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] );
	}

	/* ---------------------------------------------------------------------
	 * State (alerted + ledger + watching_since)
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{alerted:bool,ledger:array<string,array{user_id:int,ts:int}>,watching_since:int}
	 */
	public static function defaults_state(): array {
		return array(
			'alerted'         => false,
			'ledger'          => array(),
			'watching_since'  => 0,
		);
	}

	/**
	 * @return array{alerted:bool,ledger:array<string,array{user_id:int,ts:int}>,watching_since:int}
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw state.
	 * @return array{alerted:bool,ledger:array<string,array{user_id:int,ts:int}>,watching_since:int}
	 */
	public static function sanitize_state( $raw ): array {
		$defaults = self::defaults_state();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}
		$ledger = array();
		if ( isset( $raw['ledger'] ) && is_array( $raw['ledger'] ) ) {
			foreach ( $raw['ledger'] as $key => $entry ) {
				$clean = self::sanitize_ledger_entry( $entry );
				if ( null === $clean ) {
					continue;
				}
				$ledger[ (string) $clean['user_id'] ] = $clean;
			}
		}
		if ( count( $ledger ) > self::LEDGER_CAP ) {
			uasort(
				$ledger,
				static function ( array $a, array $b ): int {
					return ( (int) $a['ts'] <=> (int) $b['ts'] );
				}
			);
			$ledger = array_slice( $ledger, -self::LEDGER_CAP, null, true );
		}

		return array(
			'alerted'        => ! empty( $raw['alerted'] ),
			'ledger'         => $ledger,
			'watching_since' => max( 0, (int) ( $raw['watching_since'] ?? 0 ) ),
		);
	}

	/**
	 * @param mixed $raw Raw ledger entry.
	 * @return array{user_id:int,ts:int}|null
	 */
	public static function sanitize_ledger_entry( $raw ): ?array {
		if ( ! is_array( $raw ) ) {
			return null;
		}
		$user_id = (int) ( $raw['user_id'] ?? 0 );
		$ts      = (int) ( $raw['ts'] ?? 0 );
		if ( $user_id <= 0 || $ts <= 0 ) {
			return null;
		}

		return array(
			'user_id' => $user_id,
			'ts'      => $ts,
		);
	}

	/**
	 * @param array{alerted:bool,ledger:array<string,array{user_id:int,ts:int}>,watching_since:int} $state State.
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
		return ! empty( self::get_state()['alerted'] );
	}

	public static function set_alerted( bool $alerted ): void {
		$state            = self::get_state();
		$state['alerted'] = $alerted;
		self::put_state( $state );
	}

	/* ---------------------------------------------------------------------
	 * Attention ledger (wp_login)
	 * ------------------------------------------------------------------ */

	/**
	 * @param string        $user_login Login.
	 * @param object|null   $user       User object (WP_User).
	 */
	public static function on_wp_login( $user_login, $user = null ): void {
		unset( $user_login );
		if ( ! self::is_enabled() ) {
			return;
		}
		if ( ! is_object( $user ) || ! isset( $user->ID ) ) {
			return;
		}
		$uid = (int) $user->ID;
		if ( $uid <= 0 ) {
			return;
		}
		// Do NOT use Caps::user_can_manage() — that checks current_user mid-login.
		$can = method_exists( $user, 'has_cap' )
			? (bool) $user->has_cap( Caps::MANAGE )
			: false;
		if ( ! $can && function_exists( 'user_can' ) ) {
			$can = (bool) user_can( $user, Caps::MANAGE );
		}
		if ( ! $can ) {
			return;
		}

		$now = class_exists( Clock::class, false ) ? Clock::now() : time();
		self::stamp_attention( $uid, $now );

		if ( self::is_alerted() ) {
			self::set_alerted( false );
		}
	}

	public static function stamp_attention( int $user_id, int $ts ): void {
		if ( $user_id <= 0 || $ts <= 0 ) {
			return;
		}
		$state = self::get_state();
		$key   = (string) $user_id;
		$state['ledger'][ $key ] = array(
			'user_id' => $user_id,
			'ts'      => $ts,
		);
		self::put_state( $state );
	}

	/* ---------------------------------------------------------------------
	 * Optional attention signals (class_exists-guarded)
	 * ------------------------------------------------------------------ */

	public static function latest_drill_ack_ts(): int {
		if ( ! class_exists( Drill::class, false ) || ! method_exists( Drill::class, 'get_history' ) ) {
			return 0;
		}
		$max = 0;
		foreach ( Drill::get_history() as $run ) {
			if ( ! is_array( $run ) ) {
				continue;
			}
			$ts = (int) ( $run['ack_ts'] ?? 0 );
			if ( $ts > $max ) {
				$max = $ts;
			}
		}

		return $max;
	}

	/**
	 * @param list<array<string,mixed>>|null $log Optional log.
	 */
	public static function latest_rollback_ack_ts( ?array $log = null ): int {
		$max = 0;
		foreach ( self::load_log( $log ) as $row ) {
			if ( 'policy_restored' !== (string) ( $row['decision'] ?? '' ) ) {
				continue;
			}
			$ts = (int) ( $row['ts'] ?? 0 );
			if ( $ts > $max ) {
				$max = $ts;
			}
		}

		return $max;
	}

	/**
	 * Pure helper for combining optional signal timestamps with ledger max.
	 */
	public static function attention_from_signals( int $ledger_max, int $drill_ts = 0, int $restore_ts = 0 ): int {
		return max( 0, $ledger_max, $drill_ts, $restore_ts );
	}

	public static function last_attention_ts( ?int $now = null ): int {
		unset( $now );
		$max = 0;
		foreach ( self::get_state()['ledger'] as $entry ) {
			$ts = (int) ( $entry['ts'] ?? 0 );
			if ( $ts > $max ) {
				$max = $ts;
			}
		}

		return self::attention_from_signals(
			$max,
			self::latest_drill_ack_ts(),
			self::latest_rollback_ack_ts()
		);
	}

	/**
	 * Baseline for absence clock: max(last attention, watching_since).
	 */
	public static function attention_baseline_ts( ?int $now = null ): int {
		$last     = self::last_attention_ts( $now );
		$watching = (int) ( self::get_state()['watching_since'] ?? 0 );

		return max( $last, $watching );
	}

	/**
	 * @return int|null Days since baseline, or null when no baseline exists.
	 */
	public static function days_since_attention( ?int $now = null ): ?int {
		$now = null !== $now && $now > 0
			? $now
			: ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$baseline = self::attention_baseline_ts( $now );
		if ( $baseline <= 0 ) {
			return null;
		}
		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;

		return (int) floor( ( $now - $baseline ) / $day );
	}

	public static function days_since_watching( ?int $now = null ): ?int {
		$now = null !== $now && $now > 0
			? $now
			: ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$watching = (int) ( self::get_state()['watching_since'] ?? 0 );
		if ( $watching <= 0 ) {
			return null;
		}
		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;

		return (int) floor( ( $now - $watching ) / $day );
	}

	/* ---------------------------------------------------------------------
	 * Activity log (read-only)
	 * ------------------------------------------------------------------ */

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function load_log( ?array $log = null ): array {
		if ( null === $log ) {
			if ( isset( $GLOBALS['handl_aicac_unattended_test_log'] ) && is_array( $GLOBALS['handl_aicac_unattended_test_log'] ) ) {
				$log = $GLOBALS['handl_aicac_unattended_test_log'];
			} else {
				$log = class_exists( Policy::class, false ) ? Policy::get_retained_log() : array();
			}
		}
		if ( ! is_array( $log ) ) {
			return array();
		}
		if ( class_exists( Demo_Mode::class, false ) ) {
			$log = Demo_Mode::without_demo( $log );
		}
		$out = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( class_exists( Selftest::class, false ) && Selftest::is_synthetic_row( $row ) ) {
				continue;
			}
			$out[] = $row;
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $row Log row.
	 */
	public static function is_ai_activity_row( array $row ): bool {
		$decision = (string) ( $row['decision'] ?? '' );

		return in_array( $decision, array( 'allow', 'deny', 'observe' ), true );
	}

	/**
	 * @param list<array<string,mixed>>|null $log Optional log.
	 * @return array{
	 *   calls:int,
	 *   denies:int,
	 *   allows:int,
	 *   observes:int,
	 *   providers:array<string,int>,
	 *   top_plugins:array<string,int>,
	 *   has_activity:bool
	 * }
	 */
	public static function activity_in_window( int $window_days, ?array $log = null, ?int $now = null ): array {
		$window_days = self::sanitize_days( $window_days );
		$now         = null !== $now && $now > 0
			? $now
			: ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$day         = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
		$cut         = $now - ( ( $window_days - 1 ) * $day );
		$calls       = 0;
		$denies      = 0;
		$allows      = 0;
		$observes    = 0;
		$providers   = array();
		$plugins     = array();

		foreach ( self::load_log( $log ) as $row ) {
			if ( ! self::is_ai_activity_row( $row ) ) {
				continue;
			}
			$ts = (int) ( $row['ts'] ?? 0 );
			if ( $ts < $cut ) {
				continue;
			}
			$count = isset( $row['count'] ) ? max( 1, (int) $row['count'] ) : 1;
			$calls += $count;
			$decision = (string) ( $row['decision'] ?? '' );
			if ( 'deny' === $decision ) {
				$denies += $count;
			} elseif ( 'allow' === $decision ) {
				$allows += $count;
			} elseif ( 'observe' === $decision ) {
				$observes += $count;
			}
			$p = (string) ( $row['provider'] ?? '' );
			if ( '' !== $p ) {
				$providers[ $p ] = ( $providers[ $p ] ?? 0 ) + $count;
			}
			$plugin = (string) ( $row['plugin'] ?? '' );
			if ( '' !== $plugin ) {
				$plugins[ $plugin ] = ( $plugins[ $plugin ] ?? 0 ) + $count;
			}
		}

		arsort( $providers );
		arsort( $plugins );

		return array(
			'calls'        => $calls,
			'denies'       => $denies,
			'allows'       => $allows,
			'observes'     => $observes,
			'providers'    => $providers,
			'top_plugins'  => $plugins,
			'has_activity' => $calls > 0,
		);
	}

	/* ---------------------------------------------------------------------
	 * Detector
	 * ------------------------------------------------------------------ */

	/**
	 * @param list<array<string,mixed>>|null $log Optional log.
	 */
	public static function is_unattended( ?int $now = null, ?array $log = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$days = self::days();
		$act  = self::activity_in_window( $days, $log, $now );
		if ( empty( $act['has_activity'] ) ) {
			return false;
		}
		$since = self::days_since_attention( $now );
		if ( null === $since ) {
			$since = self::days_since_watching( $now );
		}
		if ( null === $since ) {
			return false;
		}

		return $since >= $days;
	}

	/**
	 * @param list<array<string,mixed>>|null $log Optional log.
	 * @return bool True when a new alert was sent.
	 */
	public static function maybe_fire_alerts( ?array $log = null, ?int $now = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		if ( ! self::is_unattended( $now, $log ) ) {
			// Do NOT clear alerted here — re-arm only on qualifying login.
			return false;
		}
		if ( self::is_alerted() ) {
			return false;
		}
		$payload = self::build_alert_payload( $log, $now );
		$now     = null !== $now && $now > 0
			? $now
			: ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		if ( ! self::fire_alert( $payload, $now ) ) {
			return false;
		}
		self::set_alerted( true );

		return true;
	}

	/**
	 * @param list<array<string,mixed>>|null $log Optional log.
	 * @return array<string,mixed>
	 */
	public static function build_alert_payload( ?array $log = null, ?int $now = null ): array {
		$now  = null !== $now && $now > 0
			? $now
			: ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$days = self::days();
		$act  = self::activity_in_window( $days, $log, $now );
		$since = self::days_since_attention( $now );
		if ( null === $since ) {
			$since = self::days_since_watching( $now );
		}

		return array(
			'days_since'     => null !== $since ? (int) $since : 0,
			'threshold_days' => $days,
			'calls'          => (int) $act['calls'],
			'denies'         => (int) $act['denies'],
			'allows'         => (int) $act['allows'],
			'observes'       => (int) $act['observes'],
			'providers'      => $act['providers'],
			'framing'        => self::FRAMING,
		);
	}

	/* ---------------------------------------------------------------------
	 * Alerts
	 * ------------------------------------------------------------------ */

	public static function resolve_backup_email(): string {
		$settings = self::get_settings();
		$email    = '';
		if ( function_exists( 'sanitize_email' ) ) {
			$email = sanitize_email( (string) ( $settings['backup_email'] ?? '' ) );
		} else {
			$email = trim( (string) ( $settings['backup_email'] ?? '' ) );
		}
		if ( '' !== $email && ( ! function_exists( 'is_email' ) || is_email( $email ) ) ) {
			return $email;
		}
		$admin = function_exists( 'sanitize_email' )
			? sanitize_email( (string) get_option( 'admin_email' ) )
			: (string) get_option( 'admin_email' );

		return ( function_exists( 'is_email' ) && is_email( $admin ) ) ? $admin : ( '' !== $admin ? $admin : '' );
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	private static function fire_alert( array $payload, int $now ): bool {
		$email = self::resolve_backup_email();
		if ( '' === $email ) {
			return false;
		}

		$subject = self::build_subject( $payload );
		$body    = self::build_body( $payload );
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

		$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}
		if ( $ok && class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'           => 'handl_aicac_unattended',
						'days_since'     => (int) ( $payload['days_since'] ?? 0 ),
						'threshold_days' => (int) ( $payload['threshold_days'] ?? 0 ),
						'calls'          => (int) ( $payload['calls'] ?? 0 ),
						'denies'         => (int) ( $payload['denies'] ?? 0 ),
						'site'           => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'             => $now,
					)
				);
			}
		}

		return $ok;
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	public static function build_subject( array $payload ): string {
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';

		return sprintf(
			/* translators: 1: site name, 2: days since attention */
			__( '[%1$s] [UNATTENDED] No admin attention for %2$d days while AI traffic continued', 'handl-ai-connector-access-control' ),
			$site,
			(int) ( $payload['days_since'] ?? 0 )
		);
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	public static function build_body( array $payload ): string {
		$lines   = array();
		$lines[] = __( 'No qualifying admin attention was recorded for the configured threshold while AI traffic continued on this site.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: 1: days since attention, 2: threshold days */
			__( 'Days since attention: %1$d (threshold %2$d)', 'handl-ai-connector-access-control' ),
			(int) ( $payload['days_since'] ?? 0 ),
			(int) ( $payload['threshold_days'] ?? self::DEFAULT_DAYS )
		);
		$lines[] = sprintf(
			/* translators: 1: calls, 2: denies, 3: allows, 4: observes */
			__( 'AI activity in window: %1$d calls (%2$d denies, %3$d allows, %4$d observes)', 'handl-ai-connector-access-control' ),
			(int) ( $payload['calls'] ?? 0 ),
			(int) ( $payload['denies'] ?? 0 ),
			(int) ( $payload['allows'] ?? 0 ),
			(int) ( $payload['observes'] ?? 0 )
		);
		$providers = is_array( $payload['providers'] ?? null ) ? (array) $payload['providers'] : array();
		if ( ! empty( $providers ) ) {
			$parts = array();
			$i     = 0;
			foreach ( $providers as $name => $count ) {
				$parts[] = (string) $name . '=' . (string) (int) $count;
				++$i;
				if ( $i >= 8 ) {
					break;
				}
			}
			$lines[] = sprintf(
				/* translators: %s: provider=count list */
				__( 'Providers: %s', 'handl-ai-connector-access-control' ),
				implode( ', ', $parts )
			);
		}
		$lines[] = '';
		$lines[] = __( 'Report only — never changes policy.', 'handl-ai-connector-access-control' );
		$url     = self::admin_url();
		if ( '' !== $url ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Open unattended status: %s', 'handl-ai-connector-access-control' ),
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
	 * Roster / snapshot
	 * ------------------------------------------------------------------ */

	/**
	 * Qualifying-admin roster from ledger (+ optional display names).
	 *
	 * @return list<array{user_id:int,login:string,display_name:string,last_seen_ts:int,last_seen_utc:string,source:string}>
	 */
	public static function roster(): array {
		$out = array();
		foreach ( self::get_state()['ledger'] as $entry ) {
			$uid  = (int) ( $entry['user_id'] ?? 0 );
			$ts   = (int) ( $entry['ts'] ?? 0 );
			$login = '';
			$name  = '';
			if ( $uid > 0 && function_exists( 'get_userdata' ) ) {
				$user = get_userdata( $uid );
				if ( is_object( $user ) ) {
					$login = isset( $user->user_login ) ? (string) $user->user_login : '';
					$name  = isset( $user->display_name ) ? (string) $user->display_name : '';
				}
			}
			$out[] = array(
				'user_id'        => $uid,
				'login'          => $login,
				'display_name'   => $name,
				'last_seen_ts'   => $ts,
				'last_seen_utc'  => $ts > 0 ? gmdate( 'Y-m-d H:i:s', $ts ) . ' UTC' : '',
				'source'         => 'login',
			);
		}

		$drill = self::latest_drill_ack_ts();
		if ( $drill > 0 ) {
			$ack_user = 0;
			if ( class_exists( Drill::class, false ) && method_exists( Drill::class, 'latest_run' ) ) {
				$run = Drill::latest_run();
				if ( is_array( $run ) ) {
					$ack_user = (int) ( $run['ack_user_id'] ?? 0 );
				}
			}
			$out[] = array(
				'user_id'       => $ack_user,
				'login'         => '',
				'display_name'  => '',
				'last_seen_ts'  => $drill,
				'last_seen_utc' => gmdate( 'Y-m-d H:i:s', $drill ) . ' UTC',
				'source'        => 'drill_ack',
			);
		}

		$restore = self::latest_rollback_ack_ts();
		if ( $restore > 0 ) {
			$out[] = array(
				'user_id'       => 0,
				'login'         => '',
				'display_name'  => '',
				'last_seen_ts'  => $restore,
				'last_seen_utc' => gmdate( 'Y-m-d H:i:s', $restore ) . ' UTC',
				'source'        => 'policy_restore',
			);
		}

		usort(
			$out,
			static function ( array $a, array $b ): int {
				if ( (int) $a['last_seen_ts'] !== (int) $b['last_seen_ts'] ) {
					return ( (int) $b['last_seen_ts'] <=> (int) $a['last_seen_ts'] );
				}

				return ( (int) $a['user_id'] <=> (int) $b['user_id'] );
			}
		);

		return $out;
	}

	/**
	 * @param list<array<string,mixed>>|null $log Optional log.
	 * @return array<string,mixed>
	 */
	public static function snapshot( ?int $now = null, ?array $log = null ): array {
		$now  = null !== $now && $now > 0
			? $now
			: ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$days = self::days();

		return array(
			'enabled'           => self::is_enabled(),
			'threshold_days'    => $days,
			'days_since'        => self::days_since_attention( $now ),
			'last_attention_ts' => self::last_attention_ts( $now ),
			'watching_since'    => (int) ( self::get_state()['watching_since'] ?? 0 ),
			'unattended'        => self::is_unattended( $now, $log ),
			'alerted'           => self::is_alerted(),
			'roster'            => self::roster(),
			'activity'          => self::activity_in_window( $days, $log, $now ),
			'backup_email'      => self::resolve_backup_email(),
			'framing'           => self::FRAMING,
		);
	}

	/* ---------------------------------------------------------------------
	 * CSV + print
	 * ------------------------------------------------------------------ */

	/**
	 * @param list<array<string,mixed>>|null $rows Optional roster rows.
	 */
	public static function csv_for_roster( ?array $rows = null ): string {
		if ( null === $rows ) {
			$rows = self::roster();
		}
		$lines   = array();
		$lines[] = self::csv_line(
			array(
				'user_id',
				'login',
				'last_seen_ts',
				'last_seen_utc',
				'source',
				'framing',
			)
		);
		foreach ( $rows as $row ) {
			$lines[] = self::csv_line(
				array(
					(string) (int) ( $row['user_id'] ?? 0 ),
					(string) ( $row['login'] ?? '' ),
					(string) (int) ( $row['last_seen_ts'] ?? 0 ),
					(string) ( $row['last_seen_utc'] ?? '' ),
					(string) ( $row['source'] ?? 'login' ),
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
			$col   = (string) $col;
			$needs = str_contains( $col, ',' ) || str_contains( $col, '"' ) || str_contains( $col, "\n" );
			$col   = str_replace( '"', '""', $col );
			$out[] = $needs ? '"' . $col . '"' : $col;
		}

		return implode( ',', $out );
	}

	/**
	 * @param list<array<string,mixed>> $rows Roster.
	 * @param array<string,mixed>       $snap Snapshot summary.
	 */
	public static function build_print_html( array $rows, array $snap = array() ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
		$html .= esc_html__( 'AI Connector unattended', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%;margin-bottom:24px}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f6f7f7}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'AI Connector unattended', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Report only — never changes policy.', 'handl-ai-connector-access-control' ) . '</p>';

		$days_since = $snap['days_since'] ?? null;
		$act        = is_array( $snap['activity'] ?? null ) ? (array) $snap['activity'] : array();
		$html      .= '<ul>';
		$html      .= '<li>' . esc_html(
			sprintf(
				/* translators: 1: days since, 2: threshold */
				__( 'Days since attention: %1$s (threshold %2$d)', 'handl-ai-connector-access-control' ),
				null === $days_since ? '—' : (string) (int) $days_since,
				(int) ( $snap['threshold_days'] ?? self::DEFAULT_DAYS )
			)
		) . '</li>';
		$html .= '<li>' . esc_html(
			sprintf(
				/* translators: 1: calls, 2: denies */
				__( 'AI activity in window: %1$d calls, %2$d denies', 'handl-ai-connector-access-control' ),
				(int) ( $act['calls'] ?? 0 ),
				(int) ( $act['denies'] ?? 0 )
			)
		) . '</li>';
		if ( ! empty( $snap['unattended'] ) ) {
			$html .= '<li><strong>' . esc_html__( 'Site is unattended.', 'handl-ai-connector-access-control' ) . '</strong></li>';
		}
		$html .= '</ul>';

		$html .= '<h2>' . esc_html__( 'Attention roster', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'User ID', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Login', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Last seen (UTC)', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Source', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		if ( empty( $rows ) ) {
			$html .= '<tr><td colspan="4">' . esc_html__( 'No qualifying attention recorded yet.', 'handl-ai-connector-access-control' ) . '</td></tr>';
		} else {
			foreach ( $rows as $row ) {
				$html .= '<tr>';
				$html .= '<td>' . esc_html( (string) (int) ( $row['user_id'] ?? 0 ) ) . '</td>';
				$html .= '<td>' . esc_html( (string) ( $row['login'] ?? '' ) ) . '</td>';
				$html .= '<td>' . esc_html( (string) ( $row['last_seen_utc'] ?? '' ) ) . '</td>';
				$html .= '<td>' . esc_html( (string) ( $row['source'] ?? '' ) ) . '</td>';
				$html .= '</tr>';
			}
		}
		$html .= '</tbody></table></body></html>';

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
			__( 'Unattended site', 'handl-ai-connector-access-control' ),
			__( 'Unattended', 'handl-ai-connector-access-control' ),
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
				'page'                        => self::PAGE_SLUG,
				'handl_aicac_unattended_csv'  => '1',
				'_wpnonce'                    => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_unattended_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print = add_query_arg(
			array(
				'page'                         => self::PAGE_SLUG,
				'handl_aicac_unattended_print' => '1',
				'_wpnonce'                     => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_unattended_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Unattended site', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Detect when no manage-capable admin has attended while AI traffic continued. Report only — never changes policy. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable unattended watch', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Alert when no qualifying admin attention is seen for N days while AI traffic continues', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-unattended-days">' . esc_html__( 'Absence threshold (days)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_DAYS ) . '" id="handl-aicac-unattended-days" type="number" min="' . esc_attr( (string) self::MIN_DAYS ) . '" max="' . esc_attr( (string) self::MAX_DAYS ) . '" step="1" value="' . esc_attr( (string) (int) $settings['days'] ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'Default 21. Quiet sites (no AI activity) never alert.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-unattended-backup">' . esc_html__( 'Backup email', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_BACKUP_EMAIL ) . '" id="handl-aicac-unattended-backup" type="email" value="' . esc_attr( (string) $settings['backup_email'] ) . '" class="regular-text" />';
			echo '<p class="description">' . esc_html__( 'Where to send the [UNATTENDED] alert when the site owner may be away. Falls back to the WordPress admin email.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save unattended settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled || ! is_array( $snap ) ) {
			echo '<p>' . esc_html__( 'Unattended watch is off. Enable it to track manage-capable logins and escalate when AI traffic continues without attention.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Report only — never changes policy.', 'handl-ai-connector-access-control' ) . '</strong></p>';

		$days_since = $snap['days_since'];
		$act        = (array) $snap['activity'];
		echo '<ul>';
		echo '<li>' . esc_html(
			sprintf(
				/* translators: 1: days since, 2: threshold */
				__( 'Days since attention: %1$s (threshold %2$d)', 'handl-ai-connector-access-control' ),
				null === $days_since ? '—' : (string) (int) $days_since,
				(int) $snap['threshold_days']
			)
		) . '</li>';
		echo '<li>' . esc_html(
			sprintf(
				/* translators: 1: calls, 2: denies, 3: provider count */
				__( 'AI activity in window: %1$d calls, %2$d denies, %3$d providers', 'handl-ai-connector-access-control' ),
				(int) ( $act['calls'] ?? 0 ),
				(int) ( $act['denies'] ?? 0 ),
				count( (array) ( $act['providers'] ?? array() ) )
			)
		) . '</li>';
		if ( ! empty( $snap['unattended'] ) ) {
			echo '<li><strong>' . esc_html__( 'Site is unattended.', 'handl-ai-connector-access-control' ) . '</strong></li>';
		}
		echo '<li>' . esc_html(
			sprintf(
				/* translators: %s: backup email */
				__( 'Alert destination: %s', 'handl-ai-connector-access-control' ),
				(string) $snap['backup_email']
			)
		) . '</li>';
		echo '</ul>';

		$activity_url = function_exists( 'admin_url' )
			? (string) add_query_arg( 'page', 'handl-aicac', admin_url( 'admin.php' ) )
			: '';
		$rules_url    = function_exists( 'admin_url' )
			? (string) add_query_arg( 'page', 'handl-aicac-protections', admin_url( 'admin.php' ) )
			: '';
		echo '<p>';
		if ( '' !== $activity_url ) {
			echo '<a href="' . esc_url( $activity_url ) . '">' . esc_html__( 'Activity log', 'handl-ai-connector-access-control' ) . '</a> ';
		}
		if ( '' !== $rules_url ) {
			echo '<a href="' . esc_url( $rules_url ) . '">' . esc_html__( 'Rules / protections', 'handl-ai-connector-access-control' ) . '</a> ';
		}
		echo '</p>';

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Attention roster', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $snap['roster'] ) ) {
			echo '<p>' . esc_html__( 'No qualifying attention recorded yet. Manage-capable logins will appear here.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'User ID', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Login', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Display name', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Last seen (UTC)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Source', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $snap['roster'] as $row ) {
				echo '<tr>';
				echo '<td>' . esc_html( (string) (int) $row['user_id'] ) . '</td>';
				echo '<td><code>' . esc_html( (string) $row['login'] ) . '</code></td>';
				echo '<td>' . esc_html( (string) $row['display_name'] ) . '</td>';
				echo '<td>' . esc_html( (string) $row['last_seen_utc'] ) . '</td>';
				echo '<td>' . esc_html( (string) $row['source'] ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '</div>';
	}

	public static function maybe_handle_csv(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_unattended_csv'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_unattended_csv' );
		$csv = self::csv_for_roster();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename=handl-aicac-unattended.csv' );
		}
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_unattended_print'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_unattended_print' );
		$snap = self::snapshot();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=utf-8' );
		}
		echo self::build_print_html( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside builder.
			(array) $snap['roster'],
			$snap
		);
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save unattended settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Invalid form', 'handl-ai-connector-access-control' ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$days_raw = isset( $_POST[ self::POST_DAYS ] ) ? wp_unslash( (string) $_POST[ self::POST_DAYS ] ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$email_raw = isset( $_POST[ self::POST_BACKUP_EMAIL ] ) ? wp_unslash( (string) $_POST[ self::POST_BACKUP_EMAIL ] ) : '';
		self::save_settings(
			array(
				'enabled'      => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'days'         => self::sanitize_days( '' !== $days_raw ? $days_raw : self::DEFAULT_DAYS ),
				'backup_email' => $email_raw,
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

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac unattended', CLI_Unattended::class );
	}
}

/**
 * WP-CLI: wp handl-aicac unattended status|export
 */
final class CLI_Unattended {

	/**
	 * Show unattended status. Exits non-zero only while unattended.
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
		$settings = Unattended::get_settings();
		$format   = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';

		if ( ! Unattended::is_enabled() ) {
			\WP_CLI::log(
				sprintf(
					'enabled=no days=%d framing=%s',
					(int) $settings['days'],
					Unattended::FRAMING
				)
			);
			\WP_CLI::log( 'Unattended watch is disabled.' );

			return;
		}

		$snap       = Unattended::snapshot();
		$unattended = ! empty( $snap['unattended'] );
		$days_since = $snap['days_since'];

		\WP_CLI::log(
			sprintf(
				'enabled=yes days=%d days_since=%s unattended=%s alerted=%s calls=%d denies=%d backup_email=%s framing=%s',
				(int) $snap['threshold_days'],
				null === $days_since ? 'n/a' : (string) (int) $days_since,
				$unattended ? 'yes' : 'no',
				! empty( $snap['alerted'] ) ? 'yes' : 'no',
				(int) ( $snap['activity']['calls'] ?? 0 ),
				(int) ( $snap['activity']['denies'] ?? 0 ),
				(string) $snap['backup_email'],
				Unattended::FRAMING
			)
		);

		$display = array();
		foreach ( (array) $snap['roster'] as $row ) {
			$display[] = array(
				'user_id'       => (int) $row['user_id'],
				'login'         => (string) $row['login'],
				'last_seen_utc' => (string) $row['last_seen_utc'],
				'source'        => (string) $row['source'],
			);
		}
		if ( ! empty( $display ) ) {
			if ( 'json' === $format ) {
				\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			} elseif ( class_exists( '\WP_CLI\Utils' ) ) {
				\WP_CLI\Utils\format_items( 'table', $display, array( 'user_id', 'login', 'last_seen_utc', 'source' ) );
			} else {
				foreach ( $display as $row ) {
					\WP_CLI::log( implode( "\t", $row ) );
				}
			}
		}

		if ( $unattended ) {
			\WP_CLI::error( 'Site is unattended beyond threshold with AI activity.', false );
		}
	}

	/**
	 * Export the attention roster as CSV.
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
		$csv = Unattended::csv_for_roster();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
