<?php
/**
 * AICAC-CRON-PULSE (#415): wp-cron liveness watchdog (report-only).
 *
 * Every scheduled governance job in this plugin (denial digest, weekly /
 * monthly reports, key scans, threat feed, rescans, backups, retention
 * pruning, temp-allow sweeps, demo expiry, ...) depends on wp-cron actually
 * running. When cron stalls (DISABLE_WP_CRON without a system cron, a
 * blocked loopback, a broken host) those jobs silently stop. This class
 * observes the schedule of each watched hook, records when each last fired,
 * and flags jobs that are overdue past a grace window.
 *
 * Design rules:
 * - The watchdog never depends on the thing it watches: detection runs on a
 *   throttled admin_init (and on demand from WP-CLI), never from a cron hook
 *   of its own. This class schedules nothing.
 * - Listener only: it adds low-priority callbacks to watched hooks to note a
 *   timestamp, and never edits or reschedules the owning classes' events.
 * - Exactly one re-arming [CRON-PULSE] alert. Print + CSV + WP-CLI.
 * - Own two options. OFF by default. Report only.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Cron liveness watchdog.
 */
final class Cron_Pulse {

	public const SETTINGS_OPTION = 'handl_aicac_cron_pulse';

	public const STATE_OPTION = 'handl_aicac_cron_pulse_state';

	public const PAGE_SLUG = 'handl-aicac-cron-pulse';

	public const ALERT_KIND = 'cron_pulse';

	public const FRAMING = 'report_only_never_depends_on_cron';

	public const FILTER_GRACE_MULTIPLIER = 'handl_aicac_cron_pulse_grace_multiplier';

	public const FILTER_HOOKS = 'handl_aicac_cron_pulse_hooks';

	public const POST_PRESENT = 'handl_aicac_cron_pulse_present';

	public const POST_ENABLED = 'handl_aicac_cron_pulse_enabled';

	public const POST_GRACE_MULTIPLIER = 'handl_aicac_cron_pulse_grace_multiplier';

	public const ACTION_SAVE = 'handl_aicac_cron_pulse_save';

	public const DEFAULT_GRACE_MULTIPLIER = 2.0;

	public const MIN_GRACE_MULTIPLIER = 1.0;

	public const MAX_GRACE_MULTIPLIER = 10.0;

	/** Minimum grace window in seconds (15 minutes). */
	public const MIN_GRACE_SECONDS = 900;

	/** Admin check throttle in seconds (5 minutes). */
	public const CHECK_THROTTLE_SECONDS = 300;

	public const HISTORY_CAP = 40;

	public const LAST_FIRED_CAP = 100;

	public const LISTENER_PRIORITY = 999;

	public const STATUS_OK         = 'ok';
	public const STATUS_OVERDUE    = 'overdue';
	public const STATUS_UNSCHEDULED = 'unscheduled';
	public const STATUS_IDLE       = 'idle';

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	/** @var array<string,int|false>|null */
	private static $test_next = null;

	/** @var int|null */
	private static $test_now = null;

	/** @var array<string,mixed>|null */
	private static $test_policy = null;

	/** @var bool|null */
	private static $test_disable_wp_cron = null;

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
			// Detection rides a throttled admin request, never a cron hook.
			add_action( 'admin_init', array( self::class, 'maybe_check' ), 30 );
			// Listeners resolve the registry after every plugin had a chance to filter it.
			if ( function_exists( 'did_action' ) && did_action( 'init' ) ) {
				self::register_listeners();
			} else {
				add_action( 'init', array( self::class, 'register_listeners' ), 0 );
			}
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered           = false;
		self::$test_mails           = array();
		self::$test_next            = null;
		self::$test_now             = null;
		self::$test_policy          = null;
		self::$test_disable_wp_cron = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATE_OPTION );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	/**
	 * Inject next-scheduled timestamps for unit tests (hook => ts|false).
	 * Hooks absent from the map read as unscheduled.
	 *
	 * @param array<string,int|false>|null $map Map or null to read wp_next_scheduled().
	 */
	public static function set_test_next_scheduled( ?array $map ): void {
		self::$test_next = $map;
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	/**
	 * Inject a policy for the "would the owning feature schedule this" check.
	 *
	 * @param array<string,mixed>|null $policy Policy or null to read Policy::get_policy().
	 */
	public static function set_test_policy( ?array $policy ): void {
		self::$test_policy = $policy;
	}

	public static function set_test_disable_wp_cron( ?bool $disabled ): void {
		self::$test_disable_wp_cron = $disabled;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{enabled:bool,grace_multiplier:float}
	 */
	public static function defaults(): array {
		return array(
			'enabled'          => false,
			'grace_multiplier' => self::DEFAULT_GRACE_MULTIPLIER,
		);
	}

	/**
	 * @return array{enabled:bool,grace_multiplier:float}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,grace_multiplier:float}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled'          => ! empty( $raw['enabled'] ),
			'grace_multiplier' => self::sanitize_grace_multiplier( $raw['grace_multiplier'] ?? $defaults['grace_multiplier'] ),
		);
	}

	/**
	 * @param mixed $raw Raw multiplier.
	 */
	public static function sanitize_grace_multiplier( $raw ): float {
		if ( is_string( $raw ) ) {
			$raw = str_replace( ',', '.', trim( $raw ) );
		}
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_GRACE_MULTIPLIER;
		}
		$v = (float) $raw;
		if ( ! is_finite( $v ) ) {
			return self::DEFAULT_GRACE_MULTIPLIER;
		}
		if ( $v < self::MIN_GRACE_MULTIPLIER ) {
			$v = self::MIN_GRACE_MULTIPLIER;
		}
		if ( $v > self::MAX_GRACE_MULTIPLIER ) {
			$v = self::MAX_GRACE_MULTIPLIER;
		}

		return round( $v, 2 );
	}

	/**
	 * Effective grace multiplier after filter.
	 */
	public static function grace_multiplier(): float {
		$base = (float) self::get_settings()['grace_multiplier'];
		if ( function_exists( 'apply_filters' ) ) {
			return self::sanitize_grace_multiplier( apply_filters( self::FILTER_GRACE_MULTIPLIER, $base ) );
		}

		return $base;
	}

	/**
	 * Grace window for a schedule interval: max(15 minutes, interval x multiplier).
	 */
	public static function grace_seconds( int $interval_seconds, ?float $multiplier = null ): int {
		$multiplier = null !== $multiplier ? self::sanitize_grace_multiplier( $multiplier ) : self::grace_multiplier();
		$grace      = (int) ceil( max( 0, $interval_seconds ) * $multiplier );

		return max( self::MIN_GRACE_SECONDS, $grace );
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
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] );
	}

	/* ---------------------------------------------------------------------
	 * State
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{alerted:bool,last_check_ts:int,last_fired:array<string,int>,history:list<array<string,mixed>>}
	 */
	public static function defaults_state(): array {
		return array(
			'alerted'       => false,
			'last_check_ts' => 0,
			'last_fired'    => array(),
			'history'       => array(),
		);
	}

	/**
	 * @return array{alerted:bool,last_check_ts:int,last_fired:array<string,int>,history:list<array<string,mixed>>}
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw state.
	 * @return array{alerted:bool,last_check_ts:int,last_fired:array<string,int>,history:list<array<string,mixed>>}
	 */
	public static function sanitize_state( $raw ): array {
		$defaults = self::defaults_state();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		$history = array();
		if ( isset( $raw['history'] ) && is_array( $raw['history'] ) ) {
			foreach ( $raw['history'] as $row ) {
				$clean = self::sanitize_history_entry( $row );
				if ( null !== $clean ) {
					$history[] = $clean;
				}
			}
		}
		if ( count( $history ) > self::HISTORY_CAP ) {
			$history = array_slice( $history, -self::HISTORY_CAP );
		}

		$fired = array();
		if ( isset( $raw['last_fired'] ) && is_array( $raw['last_fired'] ) ) {
			foreach ( $raw['last_fired'] as $hook => $ts ) {
				$key = self::sanitize_hook( (string) $hook );
				$ts  = is_numeric( $ts ) ? (int) $ts : 0;
				if ( '' === $key || $ts <= 0 ) {
					continue;
				}
				$fired[ $key ] = $ts;
			}
		}
		if ( count( $fired ) > self::LAST_FIRED_CAP ) {
			asort( $fired, SORT_NUMERIC );
			$fired = array_slice( $fired, -self::LAST_FIRED_CAP, null, true );
		}
		ksort( $fired );

		return array(
			'alerted'       => ! empty( $raw['alerted'] ),
			'last_check_ts' => max( 0, (int) ( $raw['last_check_ts'] ?? 0 ) ),
			'last_fired'    => $fired,
			'history'       => $history,
		);
	}

	/**
	 * @param mixed $row Raw history row.
	 * @return array{ts:int,overdue_count:int,oldest_hook:string,oldest_overdue_sec:int}|null
	 */
	public static function sanitize_history_entry( $row ): ?array {
		if ( ! is_array( $row ) ) {
			return null;
		}
		$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		if ( $ts <= 0 ) {
			return null;
		}

		return array(
			'ts'                 => $ts,
			'overdue_count'      => max( 0, (int) ( $row['overdue_count'] ?? 0 ) ),
			'oldest_hook'        => self::sanitize_hook( (string) ( $row['oldest_hook'] ?? '' ) ),
			'oldest_overdue_sec' => max( 0, (int) ( $row['oldest_overdue_sec'] ?? 0 ) ),
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

	public static function sanitize_hook( string $hook ): string {
		return sanitize_key( $hook );
	}

	/* ---------------------------------------------------------------------
	 * Last-fired listener (observation only)
	 * ------------------------------------------------------------------ */

	/**
	 * Attach a low-priority listener to every watched hook. The listener only
	 * records a timestamp; it never touches the owning class or its schedule.
	 */
	public static function register_listeners(): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		foreach ( self::registry() as $entry ) {
			$hook = (string) $entry['hook'];
			add_action(
				$hook,
				static function () use ( $hook ): void {
					Cron_Pulse::record_fire( $hook );
				},
				self::LISTENER_PRIORITY,
				0
			);
		}
	}

	/**
	 * Record that a watched hook fired.
	 *
	 * @return bool True when state changed.
	 */
	public static function record_fire( string $hook, ?int $now = null ): bool {
		$hook = self::sanitize_hook( $hook );
		if ( '' === $hook ) {
			return false;
		}
		$now = self::resolve_now( $now );
		$state = self::get_state();
		if ( isset( $state['last_fired'][ $hook ] ) && (int) $state['last_fired'][ $hook ] === $now ) {
			return false;
		}
		$state['last_fired'][ $hook ] = $now;
		self::put_state( $state );

		return true;
	}

	/* ---------------------------------------------------------------------
	 * Watched-hook registry
	 * ------------------------------------------------------------------ */

	/**
	 * Schedule name => default interval seconds.
	 *
	 * @return array<string,int>
	 */
	public static function schedule_intervals(): array {
		return array(
			'hourly'     => 3600,
			'twicedaily' => 43200,
			'daily'      => 86400,
			'weekly'     => 604800,
			'monthly'    => 2592000,
			'single'     => 3600,
		);
	}

	/**
	 * Resolve a CRON_HOOK constant from an owning class without loading it.
	 */
	private static function hook_name( string $class, string $fallback ): string {
		if ( class_exists( $class, false ) && defined( $class . '::CRON_HOOK' ) ) {
			$value = constant( $class . '::CRON_HOOK' );
			if ( is_string( $value ) && '' !== $value ) {
				return $value;
			}
		}

		return $fallback;
	}

	/**
	 * Bundled registry. Each row carries `expected`: whether the owning
	 * feature would currently have the event scheduled, so a feature the site
	 * turned off is idle rather than "unscheduled".
	 *
	 * Freeze and Break_Glass expiry hooks are one-shot events with a clear
	 * overdue rule (a pending single event whose time has long passed), so
	 * they are watched with schedule `single`, and are never "unscheduled"
	 * because no event is the normal state between freezes.
	 *
	 * Governance hooks without a CRON_HOOK constant on this branch (drill,
	 * dormant, recert, visitor) are deliberately not invented here; add them
	 * through the handl_aicac_cron_pulse_hooks filter.
	 *
	 * @param array<string,mixed> $policy Policy.
	 * @return list<array<string,mixed>>
	 */
	public static function bundled_registry( array $policy ): array {
		$rows = array();

		$rows[] = array(
			'hook'     => self::hook_name( Alerts::class, 'handl_aicac_send_denial_digest' ),
			'schedule' => 'hourly',
			'label'    => __( 'Denial / shadow alert digest', 'handl-ai-connector-access-control' ),
			'expected' => ! empty( $policy['alert_on_deny'] ) || ! empty( $policy['alert_on_shadow'] ),
		);
		$rows[] = array(
			'hook'     => self::hook_name( Weekly_Report::class, 'handl_aicac_send_weekly_report' ),
			'schedule' => 'weekly',
			'label'    => __( 'Weekly report email', 'handl-ai-connector-access-control' ),
			'expected' => self::policy_check( Weekly_Report::class, 'is_active', $policy ),
		);
		$rows[] = array(
			'hook'     => self::hook_name( Monthly_Report::class, 'handl_aicac_send_monthly_report' ),
			'schedule' => 'daily',
			'label'    => __( 'Monthly report check (daily)', 'handl-ai-connector-access-control' ),
			'expected' => self::policy_check( Monthly_Report::class, 'is_active', $policy ),
		);
		$rows[] = array(
			'hook'     => self::hook_name( Governance_Digest::class, 'handl_aicac_send_governance_digest' ),
			'schedule' => 'weekly',
			'label'    => __( 'Governance digest email', 'handl-ai-connector-access-control' ),
			'expected' => self::policy_check( Governance_Digest::class, 'is_active', $policy ),
		);
		$rows[] = array(
			'hook'     => self::hook_name( Keyscan::class, 'handl_aicac_keyscan_weekly' ),
			'schedule' => 'weekly',
			'label'    => __( 'Key scan', 'handl-ai-connector-access-control' ),
			'expected' => true,
		);
		$rows[] = array(
			'hook'     => self::hook_name( Threat_Feed::class, 'handl_aicac_threat_feed_daily' ),
			'schedule' => 'daily',
			'label'    => __( 'Threat feed refresh', 'handl-ai-connector-access-control' ),
			'expected' => ! self::static_flag( Threat_Feed::class, 'is_fetch_disabled', false ),
		);
		$rows[] = array(
			'hook'     => self::hook_name( Rescan_Schedule::class, 'handl_aicac_rescan_weekly' ),
			'schedule' => 'weekly',
			'label'    => __( 'Scheduled rescan', 'handl-ai-connector-access-control' ),
			'expected' => ! self::static_flag( Rescan_Schedule::class, 'is_disabled', false ),
		);
		$rows[] = array(
			'hook'     => self::hook_name( Policy_Backup::class, 'handl_aicac_send_policy_backup' ),
			'schedule' => 'weekly',
			'label'    => __( 'Policy backup email', 'handl-ai-connector-access-control' ),
			'expected' => self::policy_check( Policy_Backup::class, 'is_enabled', $policy ),
		);
		$rows[] = array(
			'hook'     => self::hook_name( Log_Retention::class, 'handl_aicac_prune_activity_log' ),
			'schedule' => 'daily',
			'label'    => __( 'Activity log retention prune', 'handl-ai-connector-access-control' ),
			'expected' => class_exists( Policy::class, false ) && method_exists( Policy::class, 'sanitize_log_max_age_days' )
				&& null !== Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null ),
		);
		$rows[] = array(
			'hook'     => self::hook_name( Temp_Allow::class, 'handl_aicac_sweep_expired_allows' ),
			'schedule' => 'hourly',
			'label'    => __( 'Temporary allow expiry sweep', 'handl-ai-connector-access-control' ),
			'expected' => class_exists( Temp_Allow::class, false ) && method_exists( Temp_Allow::class, 'sanitize_plugin_expires' )
				&& ! empty( Temp_Allow::sanitize_plugin_expires( $policy['plugin_expires'] ?? array() ) ),
		);
		$rows[] = array(
			'hook'     => self::hook_name( Demo_Mode::class, 'handl_aicac_demo_expire' ),
			'schedule' => 'daily',
			'label'    => __( 'Demo mode expiry', 'handl-ai-connector-access-control' ),
			'expected' => true,
		);
		$rows[] = array(
			'hook'     => self::hook_name( Freeze::class, 'handl_aicac_freeze_expire' ),
			'schedule' => 'single',
			'label'    => __( 'Freeze expiry (one-shot)', 'handl-ai-connector-access-control' ),
			'expected' => false,
		);
		$rows[] = array(
			'hook'     => self::hook_name( Break_Glass::class, 'handl_aicac_break_glass_expire' ),
			'schedule' => 'single',
			'label'    => __( 'Break-glass expiry (one-shot)', 'handl-ai-connector-access-control' ),
			'expected' => false,
		);

		return $rows;
	}

	/**
	 * @param array<string,mixed> $policy Policy.
	 */
	private static function policy_check( string $class, string $method, array $policy ): bool {
		if ( ! class_exists( $class, false ) || ! method_exists( $class, $method ) ) {
			return false;
		}

		return (bool) $class::$method( $policy );
	}

	private static function static_flag( string $class, string $method, bool $fallback ): bool {
		if ( ! class_exists( $class, false ) || ! method_exists( $class, $method ) ) {
			return $fallback;
		}

		return (bool) $class::$method();
	}

	/**
	 * @return array<string,mixed>
	 */
	private static function current_policy(): array {
		if ( null !== self::$test_policy ) {
			return self::$test_policy;
		}
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' ) ) {
			$policy = Policy::get_policy();

			return is_array( $policy ) ? $policy : array();
		}

		return array();
	}

	/**
	 * Normalize one registry row (bundled or filtered). Null when unusable.
	 *
	 * @param mixed $row Raw row.
	 * @return array{hook:string,schedule:string,label:string,interval_seconds:int,expected:bool}|null
	 */
	public static function sanitize_entry( $row ): ?array {
		if ( ! is_array( $row ) ) {
			return null;
		}
		$hook = self::sanitize_hook( (string) ( $row['hook'] ?? '' ) );
		if ( '' === $hook ) {
			return null;
		}
		$schedule = sanitize_key( (string) ( $row['schedule'] ?? '' ) );
		if ( '' === $schedule ) {
			$schedule = 'daily';
		}
		$interval = isset( $row['interval_seconds'] ) && is_numeric( $row['interval_seconds'] ) ? (int) $row['interval_seconds'] : 0;
		if ( $interval <= 0 ) {
			$interval = self::interval_for_schedule( $schedule );
		}
		$label = sanitize_text_field( (string) ( $row['label'] ?? '' ) );
		if ( '' === $label ) {
			$label = $hook;
		}
		$expected = array_key_exists( 'expected', $row ) ? ! empty( $row['expected'] ) : ( 'single' !== $schedule );

		return array(
			'hook'             => $hook,
			'schedule'         => $schedule,
			'label'            => $label,
			'interval_seconds' => $interval,
			'expected'         => $expected,
		);
	}

	public static function interval_for_schedule( string $schedule ): int {
		$known = self::schedule_intervals();
		if ( isset( $known[ $schedule ] ) ) {
			return $known[ $schedule ];
		}
		if ( function_exists( 'wp_get_schedules' ) ) {
			$schedules = wp_get_schedules();
			if ( is_array( $schedules ) && isset( $schedules[ $schedule ]['interval'] ) && (int) $schedules[ $schedule ]['interval'] > 0 ) {
				return (int) $schedules[ $schedule ]['interval'];
			}
		}

		return $known['daily'];
	}

	/**
	 * Final watched-hook list (bundled + filter), de-duplicated by hook; a
	 * later row for the same hook replaces the earlier one.
	 *
	 * @return list<array{hook:string,schedule:string,label:string,interval_seconds:int,expected:bool}>
	 */
	public static function registry(): array {
		$rows = self::bundled_registry( self::current_policy() );
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( self::FILTER_HOOKS, $rows );
			if ( is_array( $filtered ) ) {
				$rows = $filtered;
			}
		}
		$out = array();
		foreach ( $rows as $row ) {
			$clean = self::sanitize_entry( $row );
			if ( null === $clean ) {
				continue;
			}
			$out[ $clean['hook'] ] = $clean;
		}

		return array_values( $out );
	}

	/* ---------------------------------------------------------------------
	 * Detection (read-only observation of the cron schedule)
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
	 * @return int|false Next scheduled timestamp or false.
	 */
	public static function next_scheduled( string $hook ) {
		if ( null !== self::$test_next ) {
			$ts = self::$test_next[ $hook ] ?? false;

			return ( is_numeric( $ts ) && (int) $ts > 0 ) ? (int) $ts : false;
		}
		if ( ! function_exists( 'wp_next_scheduled' ) ) {
			return false;
		}
		$ts = wp_next_scheduled( $hook );

		return ( is_numeric( $ts ) && (int) $ts > 0 ) ? (int) $ts : false;
	}

	/**
	 * True when WordPress will not spawn cron on page loads.
	 */
	public static function disable_wp_cron(): bool {
		if ( null !== self::$test_disable_wp_cron ) {
			return self::$test_disable_wp_cron;
		}

		return defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;
	}

	public static function disable_wp_cron_advice(): string {
		return __( 'DISABLE_WP_CRON is set: WordPress will not run scheduled jobs on page loads. A real system cron must request wp-cron.php (or run "wp cron event run --due-now") at least every 5 minutes, otherwise every watched job will go overdue.', 'handl-ai-connector-access-control' );
	}

	/**
	 * Evaluate one registry row at a point in time.
	 *
	 * @param array{hook:string,schedule:string,label:string,interval_seconds:int,expected:bool} $entry Entry.
	 * @param array<string,int>                                                                  $last_fired Last-fired map.
	 * @return array<string,mixed>
	 */
	public static function evaluate_entry( array $entry, array $last_fired, int $now, float $multiplier ): array {
		$hook  = $entry['hook'];
		$next  = self::next_scheduled( $hook );
		$last  = (int) ( $last_fired[ $hook ] ?? 0 );
		$grace = self::grace_seconds( (int) $entry['interval_seconds'], $multiplier );

		$status     = self::STATUS_OK;
		$overdue_by = 0;
		$next_due   = 0;

		if ( false !== $next ) {
			$next_due = $next;
			$late     = $now - $next;
			if ( $late > $grace ) {
				$status     = self::STATUS_OVERDUE;
				$overdue_by = $late;
			}
		} elseif ( ! empty( $entry['expected'] ) ) {
			// Recurring job that should be scheduled but is not.
			$status     = self::STATUS_UNSCHEDULED;
			$overdue_by = $last > 0 && $now > $last ? $now - $last : 0;
		} else {
			$status = self::STATUS_IDLE;
		}

		return array(
			'hook'                 => $hook,
			'label'                => (string) $entry['label'],
			'schedule'             => (string) $entry['schedule'],
			'interval_seconds'     => (int) $entry['interval_seconds'],
			'grace_seconds'        => $grace,
			'expected'             => ! empty( $entry['expected'] ),
			'last_fired'           => $last,
			'last_fired_utc'       => $last > 0 ? gmdate( 'Y-m-d H:i:s', $last ) . ' UTC' : '',
			'next_due'             => $next_due,
			'next_due_utc'         => $next_due > 0 ? gmdate( 'Y-m-d H:i:s', $next_due ) . ' UTC' : '',
			'overdue_by_seconds'   => $overdue_by,
			'status'               => $status,
			'overdue'              => self::STATUS_OK !== $status && self::STATUS_IDLE !== $status,
		);
	}

	/**
	 * Overdue roster, oldest-overdue first.
	 *
	 * @param list<array<string,mixed>> $rows Evaluated rows.
	 * @return list<array<string,mixed>>
	 */
	public static function overdue_roster( array $rows ): array {
		$out = array();
		foreach ( $rows as $row ) {
			if ( ! empty( $row['overdue'] ) ) {
				$out[] = $row;
			}
		}
		usort(
			$out,
			static function ( array $a, array $b ): int {
				$cmp = (int) ( $b['overdue_by_seconds'] ?? 0 ) <=> (int) ( $a['overdue_by_seconds'] ?? 0 );
				if ( 0 !== $cmp ) {
					return $cmp;
				}

				return strcmp( (string) ( $a['hook'] ?? '' ), (string) ( $b['hook'] ?? '' ) );
			}
		);

		return $out;
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function snapshot( ?int $now = null ): array {
		$now        = self::resolve_now( $now );
		$state      = self::get_state();
		$multiplier = self::grace_multiplier();
		$rows       = array();
		foreach ( self::registry() as $entry ) {
			$rows[] = self::evaluate_entry( $entry, $state['last_fired'], $now, $multiplier );
		}
		$roster  = self::overdue_roster( $rows );
		$disable = self::disable_wp_cron();

		return array(
			'enabled'          => self::is_enabled(),
			'grace_multiplier' => $multiplier,
			'min_grace_seconds' => self::MIN_GRACE_SECONDS,
			'watched_count'    => count( $rows ),
			'overdue_count'    => count( $roster ),
			'oldest'           => ! empty( $roster ) ? $roster[0] : null,
			'roster'           => $roster,
			'hooks'            => $rows,
			'disable_wp_cron'  => $disable,
			'advice'           => $disable ? self::disable_wp_cron_advice() : '',
			'alerted'          => ! empty( $state['alerted'] ),
			'last_check_ts'    => (int) $state['last_check_ts'],
			'history'          => $state['history'],
			'framing'          => self::FRAMING,
			'now'              => $now,
		);
	}

	/**
	 * Compact "2h 5m" duration for humans.
	 */
	public static function format_duration( int $seconds ): string {
		$seconds = max( 0, $seconds );
		if ( $seconds < 60 ) {
			return $seconds . 's';
		}
		if ( $seconds < 3600 ) {
			return (int) floor( $seconds / 60 ) . 'm';
		}
		if ( $seconds < 86400 ) {
			$h = (int) floor( $seconds / 3600 );
			$m = (int) floor( ( $seconds % 3600 ) / 60 );

			return $h . 'h' . ( $m > 0 ? ' ' . $m . 'm' : '' );
		}
		$d = (int) floor( $seconds / 86400 );
		$h = (int) floor( ( $seconds % 86400 ) / 3600 );

		return $d . 'd' . ( $h > 0 ? ' ' . $h . 'h' : '' );
	}

	/* ---------------------------------------------------------------------
	 * Throttled admin_init check
	 * ------------------------------------------------------------------ */

	/**
	 * Throttled liveness check, wired to admin_init (never to a cron hook).
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
		$state['last_check_ts'] = $now;
		self::put_state( $state );
		self::maybe_fire_alerts( $now );

		return true;
	}

	/* ---------------------------------------------------------------------
	 * Alerts (guarded reuse of Alerts; zero edits to it)
	 * ------------------------------------------------------------------ */

	/**
	 * @return bool True when a new alert was sent.
	 */
	public static function maybe_fire_alerts( ?int $now = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now           = self::resolve_now( $now );
		$snap          = self::snapshot( $now );
		$overdue_count = (int) $snap['overdue_count'];

		if ( $overdue_count <= 0 ) {
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

		$oldest             = is_array( $snap['oldest'] ?? null ) ? (array) $snap['oldest'] : array();
		$state              = self::get_state();
		$state['alerted']   = true;
		$state['history'][] = array(
			'ts'                 => $now,
			'overdue_count'      => $overdue_count,
			'oldest_hook'        => (string) ( $oldest['hook'] ?? '' ),
			'oldest_overdue_sec' => (int) ( $oldest['overdue_by_seconds'] ?? 0 ),
		);
		self::put_state( $state );

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
				$oldest = is_array( $snap['oldest'] ?? null ) ? (array) $snap['oldest'] : array();
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'               => 'handl_aicac_cron_pulse',
						'overdue_count'      => (int) ( $snap['overdue_count'] ?? 0 ),
						'oldest_hook'        => (string) ( $oldest['hook'] ?? '' ),
						'oldest_overdue_sec' => (int) ( $oldest['overdue_by_seconds'] ?? 0 ),
						'disable_wp_cron'    => ! empty( $snap['disable_wp_cron'] ),
						'site'               => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'                 => $now,
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
		$site   = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$oldest = is_array( $snap['oldest'] ?? null ) ? (array) $snap['oldest'] : array();

		return sprintf(
			/* translators: 1: site name, 2: overdue count, 3: oldest hook, 4: overdue duration */
			__( '[%1$s] [CRON-PULSE] %2$d scheduled job(s) overdue (oldest: %3$s, %4$s late)', 'handl-ai-connector-access-control' ),
			$site,
			(int) ( $snap['overdue_count'] ?? 0 ),
			(string) ( $oldest['hook'] ?? '' ),
			self::format_duration( (int) ( $oldest['overdue_by_seconds'] ?? 0 ) )
		);
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_body( array $snap ): string {
		$lines   = array();
		$lines[] = __( 'One or more scheduled jobs are overdue past their grace window. wp-cron may be stalled.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: 1: overdue count, 2: watched count */
			__( 'Overdue: %1$d of %2$d watched jobs', 'handl-ai-connector-access-control' ),
			(int) ( $snap['overdue_count'] ?? 0 ),
			(int) ( $snap['watched_count'] ?? 0 )
		);
		$shown = 0;
		foreach ( (array) ( $snap['roster'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( $shown >= 10 ) {
				break;
			}
			++$shown;
			$lines[] = sprintf(
				/* translators: 1: hook, 2: schedule, 3: status, 4: overdue duration, 5: last fired */
				__( '- %1$s (%2$s, %3$s): %4$s late; last fired %5$s', 'handl-ai-connector-access-control' ),
				(string) ( $row['hook'] ?? '' ),
				(string) ( $row['schedule'] ?? '' ),
				(string) ( $row['status'] ?? '' ),
				self::format_duration( (int) ( $row['overdue_by_seconds'] ?? 0 ) ),
				'' !== (string) ( $row['last_fired_utc'] ?? '' ) ? (string) $row['last_fired_utc'] : __( 'never observed', 'handl-ai-connector-access-control' )
			);
		}
		if ( ! empty( $snap['advice'] ) ) {
			$lines[] = '';
			$lines[] = (string) $snap['advice'];
		}
		$lines[] = '';
		$lines[] = __( 'Report only — never runs, reschedules, or changes any job. This check runs on admin page loads, not on cron.', 'handl-ai-connector-access-control' );
		$url     = self::admin_url();
		if ( '' !== $url ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Open cron pulse: %s', 'handl-ai-connector-access-control' ),
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
				'hook',
				'label',
				'schedule',
				'interval_seconds',
				'grace_seconds',
				'last_fired_utc',
				'next_due_utc',
				'overdue_by_seconds',
				'status',
				'disable_wp_cron',
				'advice',
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
				'',
				'',
				'overdue=' . (string) (int) ( $snap['overdue_count'] ?? 0 ) . ' watched=' . (string) (int) ( $snap['watched_count'] ?? 0 ),
				! empty( $snap['disable_wp_cron'] ) ? 'yes' : 'no',
				'',
				self::FRAMING,
			)
		);

		$lines[] = self::csv_line(
			array(
				'environment',
				'DISABLE_WP_CRON',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				! empty( $snap['disable_wp_cron'] ) ? 'set' : 'not_set',
				! empty( $snap['disable_wp_cron'] ) ? 'yes' : 'no',
				(string) ( $snap['advice'] ?? '' ),
				self::FRAMING,
			)
		);

		foreach ( (array) ( $snap['roster'] ?? array() ) as $row ) {
			if ( is_array( $row ) ) {
				$lines[] = self::csv_row( 'overdue', $row, $snap );
			}
		}
		foreach ( (array) ( $snap['hooks'] ?? array() ) as $row ) {
			if ( is_array( $row ) && empty( $row['overdue'] ) ) {
				$lines[] = self::csv_row( 'watched', $row, $snap );
			}
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param array<string,mixed> $row  Evaluated row.
	 * @param array<string,mixed> $snap Snapshot.
	 */
	private static function csv_row( string $section, array $row, array $snap ): string {
		return self::csv_line(
			array(
				$section,
				(string) ( $row['hook'] ?? '' ),
				(string) ( $row['label'] ?? '' ),
				(string) ( $row['schedule'] ?? '' ),
				(string) (int) ( $row['interval_seconds'] ?? 0 ),
				(string) (int) ( $row['grace_seconds'] ?? 0 ),
				(string) ( $row['last_fired_utc'] ?? '' ),
				(string) ( $row['next_due_utc'] ?? '' ),
				(string) (int) ( $row['overdue_by_seconds'] ?? 0 ),
				(string) ( $row['status'] ?? '' ),
				! empty( $snap['disable_wp_cron'] ) ? 'yes' : 'no',
				'',
				self::FRAMING,
			)
		);
	}

	/**
	 * @param list<string> $cols Columns.
	 */
	public static function csv_line( array $cols ): string {
		$out = array();
		foreach ( $cols as $col ) {
			$col = (string) $col;
			// Neutralize spreadsheet formula injection (labels/hooks can come from a filter).
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
		$html .= esc_html__( 'AI Connector cron pulse', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%;margin-bottom:24px}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f6f7f7}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'AI Connector cron pulse', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Report only — never runs, reschedules, or changes any job.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<ul><li>' . esc_html(
			sprintf(
				/* translators: 1: overdue count, 2: watched count, 3: multiplier */
				__( 'Overdue: %1$d of %2$d watched jobs (grace x%3$s, min 15 minutes)', 'handl-ai-connector-access-control' ),
				(int) ( $snap['overdue_count'] ?? 0 ),
				(int) ( $snap['watched_count'] ?? 0 ),
				(string) ( $snap['grace_multiplier'] ?? self::DEFAULT_GRACE_MULTIPLIER )
			)
		) . '</li>';
		$html .= '<li>' . esc_html(
			! empty( $snap['disable_wp_cron'] )
				? __( 'DISABLE_WP_CRON: set', 'handl-ai-connector-access-control' )
				: __( 'DISABLE_WP_CRON: not set', 'handl-ai-connector-access-control' )
		) . '</li></ul>';
		if ( ! empty( $snap['advice'] ) ) {
			$html .= '<p><strong>' . esc_html( (string) $snap['advice'] ) . '</strong></p>';
		}

		$html  .= '<h2>' . esc_html__( 'Overdue jobs (oldest first)', 'handl-ai-connector-access-control' ) . '</h2>';
		$html  .= self::table_html( (array) ( $snap['roster'] ?? array() ), __( 'No overdue jobs.', 'handl-ai-connector-access-control' ) );
		$html  .= '<h2>' . esc_html__( 'All watched jobs', 'handl-ai-connector-access-control' ) . '</h2>';
		$html  .= self::table_html( (array) ( $snap['hooks'] ?? array() ), __( 'No watched jobs.', 'handl-ai-connector-access-control' ) );
		$html  .= '</body></html>';

		return $html;
	}

	/**
	 * @param list<array<string,mixed>> $rows  Rows.
	 * @param string                    $empty Empty message.
	 */
	private static function table_html( array $rows, string $empty ): string {
		$html  = '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Job', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Hook', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Schedule', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Last fired (UTC)', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Next due (UTC)', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Overdue by', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Status', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		if ( empty( $rows ) ) {
			$html .= '<tr><td colspan="7">' . esc_html( $empty ) . '</td></tr>';
		}
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$overdue = (int) ( $row['overdue_by_seconds'] ?? 0 );
			$html   .= '<tr>';
			$html   .= '<td>' . esc_html( (string) ( $row['label'] ?? '' ) ) . '</td>';
			$html   .= '<td><code>' . esc_html( (string) ( $row['hook'] ?? '' ) ) . '</code></td>';
			$html   .= '<td>' . esc_html( (string) ( $row['schedule'] ?? '' ) ) . '</td>';
			$html   .= '<td>' . esc_html( '' !== (string) ( $row['last_fired_utc'] ?? '' ) ? (string) $row['last_fired_utc'] : '—' ) . '</td>';
			$html   .= '<td>' . esc_html( '' !== (string) ( $row['next_due_utc'] ?? '' ) ? (string) $row['next_due_utc'] : '—' ) . '</td>';
			$html   .= '<td>' . esc_html( $overdue > 0 ? self::format_duration( $overdue ) : '—' ) . '</td>';
			$html   .= '<td>' . esc_html( (string) ( $row['status'] ?? '' ) ) . '</td>';
			$html   .= '</tr>';
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
			__( 'Cron pulse', 'handl-ai-connector-access-control' ),
			__( 'Cron pulse', 'handl-ai-connector-access-control' ),
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
				'page'                      => self::PAGE_SLUG,
				'handl_aicac_cron_pulse_csv' => '1',
				'_wpnonce'                  => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_cron_pulse_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print = add_query_arg(
			array(
				'page'                         => self::PAGE_SLUG,
				'handl_aicac_cron_pulse_print' => '1',
				'_wpnonce'                     => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_cron_pulse_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Cron pulse', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Watch whether the scheduled jobs this plugin depends on are still running. Report only — never runs or reschedules jobs. Checks run on admin page loads, not on cron. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable cron pulse', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Track when each scheduled job last fired and alert when one is overdue', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-cron-pulse-grace">' . esc_html__( 'Grace multiplier', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_GRACE_MULTIPLIER ) . '" id="handl-aicac-cron-pulse-grace" type="number" min="' . esc_attr( (string) self::MIN_GRACE_MULTIPLIER ) . '" max="' . esc_attr( (string) self::MAX_GRACE_MULTIPLIER ) . '" step="0.1" value="' . esc_attr( (string) $settings['grace_multiplier'] ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'Default 2.0. A job is overdue when it is later than its schedule interval times this value (never less than 15 minutes).', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save cron pulse settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled || ! is_array( $snap ) ) {
			echo '<p>' . esc_html__( 'Cron pulse is off. Enable it to watch scheduled-job liveness.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Report only — never runs or reschedules jobs.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		if ( ! empty( $snap['advice'] ) ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html( (string) $snap['advice'] ) . '</p></div>';
		}
		echo '<ul><li>' . esc_html(
			sprintf(
				/* translators: 1: overdue, 2: watched, 3: multiplier */
				__( 'Overdue: %1$d of %2$d watched jobs (grace x%3$s, min 15 minutes)', 'handl-ai-connector-access-control' ),
				(int) $snap['overdue_count'],
				(int) $snap['watched_count'],
				(string) $snap['grace_multiplier']
			)
		) . '</li></ul>';

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Overdue jobs (oldest first)', 'handl-ai-connector-access-control' ) . '</h2>';
		echo str_replace( '<table>', '<table class="widefat striped">', self::table_html( (array) $snap['roster'], __( 'No overdue jobs.', 'handl-ai-connector-access-control' ) ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.
		echo '<h2>' . esc_html__( 'All watched jobs', 'handl-ai-connector-access-control' ) . '</h2>';
		echo str_replace( '<table>', '<table class="widefat striped">', self::table_html( (array) $snap['hooks'], __( 'No watched jobs.', 'handl-ai-connector-access-control' ) ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.

		echo '</div>';
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_cron_pulse_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
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
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_cron_pulse_csv' ) ) {
			return;
		}
		$csv = self::csv_for_snapshot();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=handl-aicac-cron-pulse.csv' );
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		if ( empty( $_GET['handl_aicac_cron_pulse_print'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
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
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_cron_pulse_print' ) ) {
			return;
		}
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		echo self::build_print_html( self::snapshot() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save cron pulse settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );
		}
		$grace_raw = isset( $_POST[ self::POST_GRACE_MULTIPLIER ] ) ? wp_unslash( (string) $_POST[ self::POST_GRACE_MULTIPLIER ] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		self::save_settings(
			array(
				'enabled'          => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'grace_multiplier' => self::sanitize_grace_multiplier( '' !== $grace_raw ? $grace_raw : self::DEFAULT_GRACE_MULTIPLIER ),
			)
		);
		$redirect = self::admin_url();
		if ( '' === $redirect && function_exists( 'admin_url' ) ) {
			$redirect = admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac cron-pulse', CLI_Cron_Pulse::class );
	}
}

/**
 * WP-CLI: wp handl-aicac cron-pulse status|export
 */
final class CLI_Cron_Pulse {

	/**
	 * Show cron liveness. Exits non-zero when any watched job is overdue.
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

		if ( ! Cron_Pulse::is_enabled() ) {
			\WP_CLI::log(
				sprintf(
					'enabled=no grace_multiplier=%s framing=%s',
					(string) Cron_Pulse::get_settings()['grace_multiplier'],
					Cron_Pulse::FRAMING
				)
			);
			\WP_CLI::log( 'Cron pulse is disabled.' );

			return;
		}

		$snap   = Cron_Pulse::snapshot();
		$oldest = is_array( $snap['oldest'] ?? null ) ? (array) $snap['oldest'] : array();

		\WP_CLI::log(
			sprintf(
				'enabled=yes grace_multiplier=%s watched=%d overdue=%d disable_wp_cron=%s alerted=%s framing=%s',
				(string) $snap['grace_multiplier'],
				(int) $snap['watched_count'],
				(int) $snap['overdue_count'],
				! empty( $snap['disable_wp_cron'] ) ? 'yes' : 'no',
				! empty( $snap['alerted'] ) ? 'yes' : 'no',
				Cron_Pulse::FRAMING
			)
		);
		if ( ! empty( $snap['advice'] ) ) {
			\WP_CLI::warning( (string) $snap['advice'] );
		}
		if ( (int) $snap['overdue_count'] > 0 && ! empty( $oldest ) ) {
			\WP_CLI::log(
				sprintf(
					'oldest_hook=%s oldest_status=%s oldest_overdue_sec=%d',
					(string) ( $oldest['hook'] ?? '' ),
					(string) ( $oldest['status'] ?? '' ),
					(int) ( $oldest['overdue_by_seconds'] ?? 0 )
				)
			);
		}

		$display = array();
		foreach ( (array) $snap['roster'] as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$display[] = array(
				'hook'               => (string) ( $row['hook'] ?? '' ),
				'schedule'           => (string) ( $row['schedule'] ?? '' ),
				'last_fired'         => (string) ( $row['last_fired_utc'] ?? '' ),
				'next_due'           => (string) ( $row['next_due_utc'] ?? '' ),
				'overdue_by_seconds' => (int) ( $row['overdue_by_seconds'] ?? 0 ),
				'label'              => (string) ( $row['label'] ?? '' ),
			);
		}
		if ( ! empty( $display ) ) {
			if ( 'json' === $format ) {
				\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			} elseif ( class_exists( '\\WP_CLI\\Utils' ) ) {
				\WP_CLI\Utils\format_items( 'table', $display, array( 'hook', 'schedule', 'last_fired', 'next_due', 'overdue_by_seconds', 'label' ) );
			} else {
				foreach ( $display as $row ) {
					\WP_CLI::log( implode( "\t", $row ) );
				}
			}
		}

		if ( (int) $snap['overdue_count'] > 0 ) {
			// Default exit=true: a stalled cron must fail the command (non-zero).
			\WP_CLI::error( 'Overdue scheduled jobs present.' );
		}
	}

	/**
	 * Export the cron pulse report as CSV.
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
		$csv = Cron_Pulse::csv_for_snapshot();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
