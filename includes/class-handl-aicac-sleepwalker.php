<?php
/**
 * AICAC-SLEEPWALKER (#429): threshold-efficacy audit (suggestion-only).
 *
 * Compares configured thresholds on ENABLED controls to the observed
 * distribution over a trailing window. Two finding shapes:
 * - Sleepwalking: observed max is a small fraction of the threshold — the
 *   control cannot fire on this site's reality.
 * - Alarm-fatigued: threshold at or below the typical observed value — the
 *   control fires continuously.
 *
 * Design rules:
 * - Suggestion only. Zero edits to Policy, Alerts, Budget, Rate Cap, or peers.
 * - Writes confined to two own options (settings + state).
 * - Census runs on a throttled admin_init (and on demand from WP-CLI), never cron.
 * - Static registry + handl_aicac_sleepwalker_registry filter.
 * - Acknowledge-per-finding; re-arms when threshold or regime changes.
 * - Exactly one re-arming [SLEEPWALKER] alert via guarded Alerts reuse.
 * - Own two options. OFF by default. README-FREE.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Threshold-efficacy audit.
 */
final class Sleepwalker {

	public const SETTINGS_OPTION = 'handl_aicac_sleepwalker';

	public const STATE_OPTION = 'handl_aicac_sleepwalker_state';

	public const PAGE_SLUG = 'handl-aicac-sleepwalker';

	public const ALERT_KIND = 'sleepwalker';

	public const FRAMING = 'report_only_never_tunes_thresholds';

	public const FILTER_REGISTRY = 'handl_aicac_sleepwalker_registry';

	public const POST_PRESENT  = 'handl_aicac_sleepwalker_present';
	public const POST_ENABLED  = 'handl_aicac_sleepwalker_enabled';
	public const POST_OUTBOUND = 'handl_aicac_sleepwalker_outbound';
	public const POST_WINDOW   = 'handl_aicac_sleepwalker_window_days';

	public const ACTION_SAVE = 'handl_aicac_sleepwalker_save';
	public const ACTION_ACK  = 'handl_aicac_sleepwalker_ack';

	public const CHECK_THROTTLE_SECONDS = 300;

	public const DEFAULT_WINDOW_DAYS = 60;
	public const MIN_WINDOW_DAYS     = 7;
	public const MAX_WINDOW_DAYS     = 365;

	/** Observed max below this fraction of the threshold => sleepwalking. */
	public const SLEEPWALK_FRACTION = 0.1;

	public const CHANNEL_NOTICE   = 'notice';
	public const CHANNEL_OUTBOUND = 'notice+outbound';

	public const VERDICT_OK          = 'ok';
	public const VERDICT_SLEEPWALK   = 'sleepwalking';
	public const VERDICT_FATIGUE     = 'alarm_fatigued';
	public const VERDICT_INSUFFICIENT = 'insufficient_history';

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	/** @var list<string> */
	private static $test_notices = array();

	/** @var int|null */
	private static $test_now = null;

	/** @var array<string,mixed>|null */
	private static $test_policy = null;

	/** @var list<array<string,mixed>>|null Injected census rows for tests. */
	private static $test_census = null;

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
			add_action( 'admin_init', array( self::class, 'maybe_check' ), 30 );
			add_action( 'admin_notices', array( self::class, 'maybe_render_notice' ) );
			add_action( 'network_admin_notices', array( self::class, 'maybe_render_notice' ) );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered   = false;
		self::$test_mails   = array();
		self::$test_notices = array();
		self::$test_now     = null;
		self::$test_policy  = null;
		self::$test_census  = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATE_OPTION );
	}

	/** @return list<array<string,mixed>> */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	/** @return list<string> */
	public static function test_notices(): array {
		return self::$test_notices;
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	/** @param array<string,mixed>|null $policy Policy or null. */
	public static function set_test_policy( ?array $policy ): void {
		self::$test_policy = $policy;
	}

	/** @param list<array<string,mixed>>|null $rows Injected census. */
	public static function set_test_census( ?array $rows ): void {
		self::$test_census = $rows;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{enabled:bool,outbound_alert:bool,window_days:int}
	 */
	public static function defaults(): array {
		return array(
			'enabled'        => false,
			'outbound_alert' => false,
			'window_days'    => self::DEFAULT_WINDOW_DAYS,
		);
	}

	/**
	 * @return array{enabled:bool,outbound_alert:bool,window_days:int}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,outbound_alert:bool,window_days:int}
	 */
	public static function sanitize_settings( $raw ): array {
		$out = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$out['enabled']        = ! empty( $raw['enabled'] );
		$out['outbound_alert'] = ! empty( $raw['outbound_alert'] );
		$out['window_days']    = self::sanitize_window_days( $raw['window_days'] ?? self::DEFAULT_WINDOW_DAYS );

		return $out;
	}

	/**
	 * @param mixed $raw Days.
	 */
	public static function sanitize_window_days( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_WINDOW_DAYS;
		}
		$v = (int) $raw;
		if ( $v < self::MIN_WINDOW_DAYS ) {
			return self::MIN_WINDOW_DAYS;
		}
		if ( $v > self::MAX_WINDOW_DAYS ) {
			return self::MAX_WINDOW_DAYS;
		}

		return $v;
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

	public static function is_outbound_enabled(): bool {
		return ! empty( self::get_settings()['outbound_alert'] );
	}

	public static function window_days(): int {
		return (int) self::get_settings()['window_days'];
	}

	/* ---------------------------------------------------------------------
	 * State
	 * ------------------------------------------------------------------ */

	/**
	 * @return array<string,mixed>
	 */
	public static function defaults_state(): array {
		return array(
			'alerted'            => false,
			'last_check_ts'      => 0,
			'last_alert_ts'      => 0,
			'last_alert_channel' => '',
			'acknowledged'       => array(),
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
		$out = self::defaults_state();
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$out['alerted']            = ! empty( $raw['alerted'] );
		$out['last_check_ts']      = isset( $raw['last_check_ts'] ) ? max( 0, (int) $raw['last_check_ts'] ) : 0;
		$out['last_alert_ts']      = isset( $raw['last_alert_ts'] ) ? max( 0, (int) $raw['last_alert_ts'] ) : 0;
		$out['last_alert_channel'] = isset( $raw['last_alert_channel'] ) ? sanitize_key( (string) $raw['last_alert_channel'] ) : '';
		$ack                       = array();
		if ( isset( $raw['acknowledged'] ) && is_array( $raw['acknowledged'] ) ) {
			foreach ( $raw['acknowledged'] as $key ) {
				$key = sanitize_text_field( (string) $key );
				if ( '' !== $key ) {
					$ack[ $key ] = true;
				}
			}
		}
		$out['acknowledged'] = array_keys( $ack );

		return $out;
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
		return ! empty( self::get_state()['alerted'] );
	}

	/* ---------------------------------------------------------------------
	 * Registry
	 * ------------------------------------------------------------------ */

	/**
	 * Bundled static registry of threshold-bearing control families.
	 * Filter: handl_aicac_sleepwalker_registry.
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function bundled_registry(): array {
		$rows = array(
			array(
				'id'       => 'plugin_budget',
				'label'    => __( 'Monthly plugin budget', 'handl-ai-connector-access-control' ),
				'unit'     => 'usd',
				'observer' => 'plugin_budget',
			),
			array(
				'id'       => 'spend_threshold_site',
				'label'    => __( 'Site spend threshold', 'handl-ai-connector-access-control' ),
				'unit'     => 'usd',
				'observer' => 'spend_threshold_site',
			),
			array(
				'id'       => 'spend_threshold_plugin',
				'label'    => __( 'Plugin spend threshold', 'handl-ai-connector-access-control' ),
				'unit'     => 'usd',
				'observer' => 'spend_threshold_plugin',
			),
			array(
				'id'       => 'rate_cap_hour',
				'label'    => __( 'Plugin rate cap (hour)', 'handl-ai-connector-access-control' ),
				'unit'     => 'calls',
				'observer' => 'rate_cap_hour',
			),
			array(
				'id'       => 'rate_cap_day',
				'label'    => __( 'Plugin rate cap (day)', 'handl-ai-connector-access-control' ),
				'unit'     => 'calls',
				'observer' => 'rate_cap_day',
			),
			array(
				'id'       => 'anomaly_multiplier',
				'label'    => __( 'Anomaly multiplier', 'handl-ai-connector-access-control' ),
				'unit'     => 'ratio',
				'observer' => 'anomaly_multiplier',
			),
			array(
				'id'       => 'latency_p95',
				'label'    => __( 'Latency p95 threshold', 'handl-ai-connector-access-control' ),
				'unit'     => 'ms',
				'observer' => 'latency_p95',
			),
			array(
				'id'       => 'visitor_cap_hour',
				'label'    => __( 'Visitor hour cap', 'handl-ai-connector-access-control' ),
				'unit'     => 'visitors',
				'observer' => 'visitor_cap_hour',
			),
			array(
				'id'       => 'visitor_cap_day',
				'label'    => __( 'Visitor day cap', 'handl-ai-connector-access-control' ),
				'unit'     => 'visitors',
				'observer' => 'visitor_cap_day',
			),
			array(
				'id'       => 'user_quota',
				'label'    => __( 'User quota (role day limit)', 'handl-ai-connector-access-control' ),
				'unit'     => 'calls',
				'observer' => 'user_quota',
			),
			array(
				'id'       => 'key_age',
				'label'    => __( 'Key-age max days', 'handl-ai-connector-access-control' ),
				'unit'     => 'days',
				'observer' => 'key_age',
			),
			array(
				'id'       => 'limbo_sla',
				'label'    => __( 'Limbo SLA days', 'handl-ai-connector-access-control' ),
				'unit'     => 'days',
				'observer' => 'limbo_sla',
			),
			array(
				'id'       => 'noise_budget',
				'label'    => __( 'Noise weekly alert budget', 'handl-ai-connector-access-control' ),
				'unit'     => 'alerts',
				'observer' => 'noise_budget',
			),
		);

		/**
		 * Filter the SLEEPWALKER threshold registry.
		 *
		 * @param list<array<string,mixed>> $rows Registry rows.
		 */
		$filtered = apply_filters( self::FILTER_REGISTRY, $rows );
		if ( ! is_array( $filtered ) ) {
			return $rows;
		}

		$out = array();
		foreach ( $filtered as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$id = isset( $row['id'] ) ? sanitize_key( (string) $row['id'] ) : '';
			if ( '' === $id ) {
				continue;
			}
			$out[] = array(
				'id'       => $id,
				'label'    => isset( $row['label'] ) ? sanitize_text_field( (string) $row['label'] ) : $id,
				'unit'     => isset( $row['unit'] ) ? sanitize_key( (string) $row['unit'] ) : '',
				'observer' => isset( $row['observer'] ) ? sanitize_key( (string) $row['observer'] ) : $id,
			);
		}

		return $out;
	}

	/* ---------------------------------------------------------------------
	 * Policy / clock / math helpers
	 * ------------------------------------------------------------------ */

	/**
	 * @return array<string,mixed>
	 */
	public static function resolve_policy(): array {
		if ( null !== self::$test_policy ) {
			return self::$test_policy;
		}
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' ) ) {
			$policy = Policy::get_policy();
			return is_array( $policy ) ? $policy : array();
		}

		return array();
	}

	private static function resolve_now( ?int $now ): int {
		if ( null !== $now ) {
			return $now;
		}
		if ( null !== self::$test_now ) {
			return (int) self::$test_now;
		}
		if ( class_exists( Clock::class, false ) && method_exists( Clock::class, 'now' ) ) {
			return (int) Clock::now();
		}

		return time();
	}

	/**
	 * @param list<float|int> $values Values.
	 * @return array{min:float,median:float,max:float,count:int}|null
	 */
	public static function distribution( array $values ): ?array {
		$clean = array();
		foreach ( $values as $v ) {
			if ( is_numeric( $v ) ) {
				$clean[] = (float) $v;
			}
		}
		if ( empty( $clean ) ) {
			return null;
		}
		sort( $clean, SORT_NUMERIC );
		$n   = count( $clean );
		$mid = (int) floor( ( $n - 1 ) / 2 );
		if ( 0 === $n % 2 ) {
			$median = ( $clean[ $mid ] + $clean[ $mid + 1 ] ) / 2.0;
		} else {
			$median = $clean[ $mid ];
		}

		return array(
			'min'    => $clean[0],
			'median' => $median,
			'max'    => $clean[ $n - 1 ],
			'count'  => $n,
		);
	}

	/**
	 * Quantize a positive number for ack keys (2 significant figures).
	 */
	public static function sig( float $v ): string {
		if ( $v <= 0 ) {
			return '0';
		}
		$exp = (int) floor( log10( $v ) );
		$pow = pow( 10, $exp - 1 );
		$rounded = round( $v / $pow ) * $pow;

		return rtrim( rtrim( sprintf( '%.6F', $rounded ), '0' ), '.' );
	}

	public static function ratio_bucket( float $ratio ): string {
		if ( $ratio < 0.05 ) {
			return 'lt5';
		}
		if ( $ratio < 0.1 ) {
			return 'lt10';
		}
		if ( $ratio < 0.25 ) {
			return 'lt25';
		}
		if ( $ratio < 0.5 ) {
			return 'lt50';
		}
		if ( $ratio < 0.9 ) {
			return 'lt90';
		}
		if ( $ratio < 1.1 ) {
			return 'near';
		}
		if ( $ratio < 2.0 ) {
			return 'gt1';
		}

		return 'gt2';
	}

	public static function page_link( string $slug ): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) admin_url( 'admin.php?page=' . $slug );
	}

	public static function admin_url(): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg( 'page', self::PAGE_SLUG, admin_url( 'admin.php' ) );
	}

	/**
	 * @param array<string,mixed> $policy Policy.
	 */
	public static function resolve_email( array $policy ): string {
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			return (string) Alerts::resolve_email( $policy );
		}
		$email = isset( $policy['alert_email'] ) ? sanitize_email( (string) $policy['alert_email'] ) : '';
		if ( '' === $email ) {
			$email = sanitize_email( (string) get_option( 'admin_email' ) );
		}

		return $email;
	}

	/**
	 * @param array<string,mixed> $policy Policy.
	 */
	public static function resolve_webhook( array $policy ): string {
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			return (string) Alerts::resolve_webhook( $policy );
		}

		return '';
	}

	/* ---------------------------------------------------------------------
	 * Observers (read-only)
	 * ------------------------------------------------------------------ */

	/**
	 * Run one registry observer. Returns zero or more census rows.
	 *
	 * @param array<string,mixed> $entry Registry entry.
	 * @return list<array<string,mixed>>
	 */
	public static function observe_entry( array $entry, int $now, int $window_days ): array {
		$observer = (string) ( $entry['observer'] ?? $entry['id'] ?? '' );
		switch ( $observer ) {
			case 'plugin_budget':
				return self::observe_plugin_budgets( $entry, $now, $window_days );
			case 'spend_threshold_site':
				return self::observe_spend_threshold_site( $entry, $now, $window_days );
			case 'spend_threshold_plugin':
				return self::observe_spend_threshold_plugins( $entry, $now, $window_days );
			case 'rate_cap_hour':
				return self::observe_rate_caps( $entry, 'hour', $now, $window_days );
			case 'rate_cap_day':
				return self::observe_rate_caps( $entry, 'day', $now, $window_days );
			case 'anomaly_multiplier':
				return self::observe_anomaly_multiplier( $entry, $now, $window_days );
			case 'latency_p95':
				return self::observe_latency_p95( $entry, $now, $window_days );
			case 'visitor_cap_hour':
				return self::observe_visitor_cap( $entry, 'hour', $now, $window_days );
			case 'visitor_cap_day':
				return self::observe_visitor_cap( $entry, 'day', $now, $window_days );
			case 'user_quota':
				return self::observe_user_quota( $entry, $now, $window_days );
			case 'key_age':
				return self::observe_key_age( $entry, $now, $window_days );
			case 'limbo_sla':
				return self::observe_limbo_sla( $entry, $now, $window_days );
			case 'noise_budget':
				return self::observe_noise_budget( $entry, $now, $window_days );
			default:
				return array();
		}
	}

	/**
	 * @param array<string,mixed> $entry Entry.
	 * @return list<array<string,mixed>>
	 */
	private static function observe_plugin_budgets( array $entry, int $now, int $window_days ): array {
		if ( ! class_exists( Budget::class, false ) ) {
			return array();
		}
		$policy  = self::resolve_policy();
		$budgets = Budget::sanitize_plugin_budgets( $policy['plugin_budgets'] ?? array() );
		if ( empty( $budgets ) ) {
			return array();
		}
		$map    = Budget::get_spend_map();
		$cutoff = self::period_cutoff( $now, $window_days );
		$link   = self::page_link( 'handl-aicac' );
		$out    = array();
		foreach ( $budgets as $plugin => $threshold ) {
			$values = array();
			foreach ( $map as $period => $plugins ) {
				if ( (string) $period < $cutoff ) {
					continue;
				}
				if ( isset( $plugins[ $plugin ] ) && is_numeric( $plugins[ $plugin ] ) ) {
					$values[] = (float) $plugins[ $plugin ];
				}
			}
			$fires = self::count_fired_for_prefix( Budget::FIRED_OPTION_KEY, 'plugin:' . $plugin );
			$out[] = self::compose_row( $entry, $plugin, (float) $threshold, $values, $fires, $link, $window_days );
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $entry Entry.
	 * @return list<array<string,mixed>>
	 */
	private static function observe_spend_threshold_site( array $entry, int $now, int $window_days ): array {
		if ( ! class_exists( Spend_Threshold::class, false ) || ! class_exists( Budget::class, false ) ) {
			return array();
		}
		$policy = self::resolve_policy();
		$th     = Spend_Threshold::sanitize_threshold( $policy['spend_threshold_site'] ?? null );
		if ( null === $th ) {
			return array();
		}
		$map    = Budget::get_spend_map();
		$cutoff = self::period_cutoff( $now, $window_days );
		$values = array();
		foreach ( $map as $period => $plugins ) {
			if ( (string) $period < $cutoff || ! is_array( $plugins ) ) {
				continue;
			}
			$sum = 0.0;
			foreach ( $plugins as $usd ) {
				if ( is_numeric( $usd ) ) {
					$sum += (float) $usd;
				}
			}
			$values[] = $sum;
		}
		$fires = self::count_fired_for_prefix( Spend_Threshold::FIRED_OPTION_KEY, 'site' );

		return array(
			self::compose_row( $entry, 'site', (float) $th, $values, $fires, self::page_link( 'handl-aicac' ), $window_days ),
		);
	}

	/**
	 * @param array<string,mixed> $entry Entry.
	 * @return list<array<string,mixed>>
	 */
	private static function observe_spend_threshold_plugins( array $entry, int $now, int $window_days ): array {
		if ( ! class_exists( Spend_Threshold::class, false ) || ! class_exists( Budget::class, false ) ) {
			return array();
		}
		$policy = self::resolve_policy();
		$map_th = Spend_Threshold::sanitize_plugin_thresholds( $policy['spend_threshold_plugins'] ?? array() );
		if ( empty( $map_th ) ) {
			return array();
		}
		$spend  = Budget::get_spend_map();
		$cutoff = self::period_cutoff( $now, $window_days );
		$link   = self::page_link( 'handl-aicac' );
		$out    = array();
		foreach ( $map_th as $plugin => $threshold ) {
			$values = array();
			foreach ( $spend as $period => $plugins ) {
				if ( (string) $period < $cutoff ) {
					continue;
				}
				if ( isset( $plugins[ $plugin ] ) && is_numeric( $plugins[ $plugin ] ) ) {
					$values[] = (float) $plugins[ $plugin ];
				}
			}
			$fires = self::count_fired_for_prefix( Spend_Threshold::FIRED_OPTION_KEY, 'plugin:' . $plugin );
			$out[] = self::compose_row( $entry, $plugin, (float) $threshold, $values, $fires, $link, $window_days );
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $entry Entry.
	 * @return list<array<string,mixed>>
	 */
	private static function observe_rate_caps( array $entry, string $window, int $now, int $window_days ): array {
		if ( ! class_exists( Rate_Cap::class, false ) ) {
			return array();
		}
		$policy = self::resolve_policy();
		$key    = 'hour' === $window ? 'plugin_rate_caps_hour' : 'plugin_rate_caps_day';
		$caps   = Rate_Cap::sanitize_plugin_caps( $policy[ $key ] ?? array() );
		if ( empty( $caps ) ) {
			return array();
		}
		$counts = Rate_Cap::get_counts_map();
		$link   = self::page_link( 'handl-aicac' );
		$out    = array();
		foreach ( $caps as $plugin => $threshold ) {
			$values = array();
			foreach ( $counts as $ck => $n ) {
				$parts = explode( '|', (string) $ck );
				if ( count( $parts ) < 3 ) {
					continue;
				}
				$p = $parts[0];
				$w = $parts[ count( $parts ) - 2 ];
				if ( $p !== $plugin || $w !== $window ) {
					continue;
				}
				$values[] = (float) $n;
			}
			// Rate-cap counts rotate; require at least 3 samples else insufficient.
			$out[] = self::compose_row( $entry, $plugin, (float) $threshold, $values, 0, $link, $window_days, 3 );
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $entry Entry.
	 * @return list<array<string,mixed>>
	 */
	private static function observe_anomaly_multiplier( array $entry, int $now, int $window_days ): array {
		if ( ! class_exists( Anomaly::class, false ) ) {
			return array();
		}
		$policy = self::resolve_policy();
		if ( empty( $policy['anomaly_alert_enabled'] ) ) {
			return array();
		}
		$cfg        = Anomaly::config_from_policy( $policy );
		$multiplier = (float) $cfg['multiplier'];
		$ratios     = self::daily_call_totals( $now, $window_days );
		$ratios_list = array_values( $ratios );
		if ( count( $ratios_list ) < Anomaly::BASELINE_DAYS + 1 ) {
			return array(
				self::compose_row( $entry, 'site', $multiplier, array(), 0, self::page_link( 'handl-aicac' ), $window_days ),
			);
		}
		// Observed ratios: each day's calls / mean of prior BASELINE_DAYS.
		$ratios_keys = array_keys( $days );
		sort( $days_keys );
		$ratios_keys = array_values( $days_keys );
		$ratios_vals = array();
		foreach ( $days_keys as $k ) {
			$days_vals[] = (float) $days[ $k ];
		}
		$ratios = array();
		for ( $i = Anomaly::BASELINE_DAYS; $i < count( $days_vals ); $i++ ) {
			$slice = array_slice( $days_vals, $i - Anomaly::BASELINE_DAYS, Anomaly::BASELINE_DAYS );
			$sum   = array_sum( $slice );
			$mean  = $sum / Anomaly::BASELINE_DAYS;
			if ( $mean <= 0 ) {
				continue;
			}
			$ratios[] = $days_vals[ $i ] / $mean;
		}
		$fires = self::count_fired_keys( Anomaly::FIRED_OPTION_KEY );

		return array(
			self::compose_row( $entry, 'site', $multiplier, $ratios, $fires, self::page_link( 'handl-aicac' ), $window_days ),
		);
	}

	/**
	 * @param array<string,mixed> $entry Entry.
	 * @return list<array<string,mixed>>
	 */
	private static function observe_latency_p95( array $entry, int $now, int $window_days ): array {
		unset( $window_days );
		if ( ! class_exists( Latency::class, false ) ) {
			return array();
		}
		$policy = self::resolve_policy();
		if ( ! Latency::is_alert_enabled( $policy ) ) {
			return array();
		}
		$threshold = (float) Latency::threshold_ms( $policy );
		$stats     = Latency::provider_stats( $now );
		$values    = array();
		foreach ( $stats as $row ) {
			if ( isset( $row['p95'] ) && is_numeric( $row['p95'] ) && (int) ( $row['count'] ?? 0 ) > 0 ) {
				$values[] = (float) $row['p95'];
			}
		}
		$fires = self::count_fired_keys( Latency::FIRED_OPTION_KEY );
		// Only one hour of samples — require at least one provider with data.
		return array(
			self::compose_row( $entry, 'site', $threshold, $values, $fires, self::page_link( 'handl-aicac' ), 1, 1 ),
		);
	}

	/**
	 * @param array<string,mixed> $entry Entry.
	 * @return list<array<string,mixed>>
	 */
	private static function observe_visitor_cap( array $entry, string $window, int $now, int $window_days ): array {
		unset( $now, $window_days );
		if ( ! class_exists( Visitor::class, false ) || ! method_exists( Visitor::class, 'is_enabled' ) ) {
			return array();
		}
		if ( ! Visitor::is_enabled() ) {
			return array();
		}
		$settings = Visitor::get_settings();
		$cap_key  = 'hour' === $window ? 'cap_hour' : 'cap_day';
		$threshold = $settings[ $cap_key ] ?? null;
		if ( null === $threshold ) {
			return array();
		}
		$counts = method_exists( Visitor::class, 'get_counts_map' ) ? Visitor::get_counts_map() : array();
		$values = array();
		foreach ( $counts as $ck => $n ) {
			if ( ! is_numeric( $n ) ) {
				continue;
			}
			// Visitor count keys vary by implementation; keep values that look like this window.
			if ( false !== strpos( (string) $ck, $window ) || 'hour' === $window || 'day' === $window ) {
				$values[] = (float) $n;
			}
		}
		$link = defined( Visitor::class . '::PAGE_SLUG' ) ? self::page_link( (string) Visitor::PAGE_SLUG ) : self::page_link( 'handl-aicac' );

		return array(
			self::compose_row( $entry, $window, (float) $threshold, $values, 0, $link, 7, 3 ),
		);
	}

	/**
	 * @param array<string,mixed> $entry Entry.
	 * @return list<array<string,mixed>>
	 */
	private static function observe_user_quota( array $entry, int $now, int $window_days ): array {
		unset( $now, $window_days );
		if ( ! class_exists( User_Quota::class, false ) ) {
			return array();
		}
		$policy = self::resolve_policy();
		$limits = method_exists( User_Quota::class, 'sanitize_role_limits' )
			? User_Quota::sanitize_role_limits( $policy[ User_Quota::POLICY_ROLE_LIMITS ] ?? array() )
			: array();
		if ( empty( $limits ) ) {
			return array();
		}
		$counts = method_exists( User_Quota::class, 'get_counts_map' ) ? User_Quota::get_counts_map() : array();
		$link   = self::page_link( 'handl-aicac' );
		$out    = array();
		foreach ( $limits as $role => $threshold ) {
			$values = array();
			foreach ( $counts as $ck => $n ) {
				if ( ! is_numeric( $n ) ) {
					continue;
				}
				if ( 0 === strpos( (string) $ck, (string) $role . '|' ) || false !== strpos( (string) $ck, (string) $role ) ) {
					$values[] = (float) $n;
				}
			}
			$out[] = self::compose_row( $entry, (string) $role, (float) $threshold, $values, 0, $link, 7, 3 );
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $entry Entry.
	 * @return list<array<string,mixed>>
	 */
	private static function observe_key_age( array $entry, int $now, int $window_days ): array {
		unset( $now, $window_days );
		if ( ! class_exists( Key_Age::class, false ) || ! method_exists( Key_Age::class, 'is_enabled' ) ) {
			return array();
		}
		if ( ! Key_Age::is_enabled() ) {
			return array();
		}
		$settings = Key_Age::get_settings();
		$max_days = isset( $settings['max_days'] ) ? (int) $settings['max_days'] : (int) ( Key_Age::DEFAULT_MAX_DAYS ?? 90 );
		// Observed ages come from ledger when available; otherwise insufficient.
		$values = array();
		if ( method_exists( Key_Age::class, 'sanitize_ledger' ) && defined( Key_Age::class . '::VAULT_OPTION' ) ) {
			$vault = get_option( Key_Age::VAULT_OPTION, array() );
			$ledger = Key_Age::sanitize_ledger( is_array( $vault ) ? ( $vault['ledger'] ?? $vault ) : array() );
			foreach ( $ledger as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				if ( isset( $row['age_days'] ) && is_numeric( $row['age_days'] ) ) {
					$values[] = (float) $row['age_days'];
				} elseif ( isset( $row['seen_at'] ) && is_numeric( $row['seen_at'] ) ) {
					$age = max( 0, ( time() - (int) $row['seen_at'] ) / DAY_IN_SECONDS );
					$values[] = $age;
				}
			}
		}
		$link = defined( Key_Age::class . '::PAGE_SLUG' ) ? self::page_link( (string) Key_Age::PAGE_SLUG ) : self::page_link( 'handl-aicac' );

		return array(
			self::compose_row( $entry, 'site', (float) $max_days, $values, 0, $link, 30, 1 ),
		);
	}

	/**
	 * @param array<string,mixed> $entry Entry.
	 * @return list<array<string,mixed>>
	 */
	private static function observe_limbo_sla( array $entry, int $now, int $window_days ): array {
		unset( $now, $window_days );
		if ( ! class_exists( Limbo::class, false ) || ! method_exists( Limbo::class, 'is_enabled' ) ) {
			return array();
		}
		if ( ! Limbo::is_enabled() ) {
			return array();
		}
		$sla = method_exists( Limbo::class, 'sla_days' ) ? (float) Limbo::sla_days() : (float) ( Limbo::DEFAULT_SLA_DAYS ?? 7 );
		$values = array();
		if ( method_exists( Limbo::class, 'get_state' ) ) {
			$state = Limbo::get_state();
			$hist  = isset( $state['history'] ) && is_array( $state['history'] ) ? $state['history'] : array();
			foreach ( $hist as $row ) {
				if ( is_array( $row ) && isset( $row['age_days'] ) && is_numeric( $row['age_days'] ) ) {
					$values[] = (float) $row['age_days'];
				}
			}
		}
		$link = defined( Limbo::class . '::PAGE_SLUG' ) ? self::page_link( (string) Limbo::PAGE_SLUG ) : self::page_link( 'handl-aicac' );

		return array(
			self::compose_row( $entry, 'site', $sla, $values, 0, $link, 7, 1 ),
		);
	}

	/**
	 * @param array<string,mixed> $entry Entry.
	 * @return list<array<string,mixed>>
	 */
	private static function observe_noise_budget( array $entry, int $now, int $window_days ): array {
		unset( $now, $window_days );
		if ( ! class_exists( Noise::class, false ) || ! method_exists( Noise::class, 'is_enabled' ) ) {
			return array();
		}
		if ( ! Noise::is_enabled() ) {
			return array();
		}
		$settings = Noise::get_settings();
		$budget   = (float) ( $settings['budget_per_week'] ?? Noise::DEFAULT_BUDGET_PER_WEEK );
		$values   = array();
		if ( method_exists( Noise::class, 'get_state' ) ) {
			$state = Noise::get_state();
			$hist  = isset( $state['weekly'] ) && is_array( $state['weekly'] ) ? $state['weekly'] : ( isset( $state['history'] ) && is_array( $state['history'] ) ? $state['history'] : array() );
			foreach ( $hist as $row ) {
				if ( is_numeric( $row ) ) {
					$values[] = (float) $row;
				} elseif ( is_array( $row ) && isset( $row['count'] ) && is_numeric( $row['count'] ) ) {
					$values[] = (float) $row['count'];
				}
			}
		}
		$link = defined( Noise::class . '::PAGE_SLUG' ) ? self::page_link( (string) Noise::PAGE_SLUG ) : self::page_link( 'handl-aicac' );

		return array(
			self::compose_row( $entry, 'site', $budget, $values, 0, $link, 28, 2 ),
		);
	}

	/* ---------------------------------------------------------------------
	 * Census composition + verdicts
	 * ------------------------------------------------------------------ */

	private static function period_cutoff( int $now, int $window_days ): string {
		$ts = $now - ( $window_days * DAY_IN_SECONDS );
		if ( class_exists( Budget::class, false ) && method_exists( Budget::class, 'period_id' ) ) {
			return Budget::period_id( $ts );
		}

		return gmdate( 'Y-m', $ts );
	}

	/**
	 * @return array<string,int> Y-m-d => call count
	 */
	private static function daily_call_totals( int $now, int $window_days ): array {
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		if ( ! is_array( $log ) ) {
			return array();
		}
		$cutoff = $now - ( $window_days * DAY_IN_SECONDS );
		$out    = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts < $cutoff ) {
				continue;
			}
			$day = gmdate( 'Y-m-d', $ts );
			if ( ! isset( $out[ $day ] ) ) {
				$out[ $day ] = 0;
			}
			++$out[ $day ];
		}
		ksort( $out );

		return $out;
	}

	private static function count_fired_keys( string $option_key ): int {
		$state = get_option( $option_key, array() );
		if ( ! is_array( $state ) ) {
			return 0;
		}

		return count( $state );
	}

	private static function count_fired_for_prefix( string $option_key, string $prefix ): int {
		$state = get_option( $option_key, array() );
		if ( ! is_array( $state ) ) {
			return 0;
		}
		$n = 0;
		foreach ( $state as $key => $_ ) {
			if ( 0 === strpos( (string) $key, $prefix ) ) {
				++$n;
			}
		}

		return $n;
	}

	/**
	 * @param array<string,mixed> $entry Registry entry.
	 * @param list<float|int>     $values Observed samples.
	 * @return array<string,mixed>
	 */
	public static function compose_row(
		array $entry,
		string $scope,
		float $threshold,
		array $values,
		int $fire_count,
		string $deep_link,
		int $window_days,
		int $min_samples = 1
	): array {
		$dist    = self::distribution( $values );
		$samples = $dist ? (int) $dist['count'] : 0;
		$note    = '';
		$verdict = self::VERDICT_OK;
		$min     = null;
		$median  = null;
		$max     = null;

		if ( null === $dist || $samples < $min_samples ) {
			$verdict = self::VERDICT_INSUFFICIENT;
			$note    = __( 'Not enough history', 'handl-ai-connector-access-control' );
		} else {
			$min    = $dist['min'];
			$median = $dist['median'];
			$max    = $dist['max'];
			$verdict = self::evaluate_verdict( $threshold, $median, $max );
		}

		$id    = (string) ( $entry['id'] ?? '' );
		$label = (string) ( $entry['label'] ?? $id );
		$unit  = (string) ( $entry['unit'] ?? '' );
		$key   = self::finding_key( $id, $scope, $verdict, $threshold, $median, $max );

		$summary = self::build_summary( $label, $scope, $threshold, $unit, $verdict, $min, $median, $max, $fire_count, $window_days, $note );
		$suggestion = __( 'If that is intentional, acknowledge it; if not, open the control and adjust the threshold. Sleepwalker never suggests a specific number.', 'handl-ai-connector-access-control' );

		return array(
			'key'         => $key,
			'control_id'  => $id,
			'label'       => $label,
			'scope'       => $scope,
			'unit'        => $unit,
			'threshold'   => $threshold,
			'min'         => $min,
			'median'      => $median,
			'max'         => $max,
			'samples'     => $samples,
			'fire_count'  => $fire_count,
			'verdict'     => $verdict,
			'note'        => $note,
			'summary'     => $summary,
			'suggestion'  => $suggestion,
			'deep_link'   => $deep_link,
			'window_days' => $window_days,
		);
	}

	public static function evaluate_verdict( float $threshold, float $median, float $max ): string {
		if ( $threshold <= 0 ) {
			return self::VERDICT_OK;
		}
		if ( $median >= $threshold ) {
			return self::VERDICT_FATIGUE;
		}
		if ( $max < ( $threshold * self::SLEEPWALK_FRACTION ) ) {
			return self::VERDICT_SLEEPWALK;
		}

		return self::VERDICT_OK;
	}

	public static function finding_key(
		string $control_id,
		string $scope,
		string $verdict,
		float $threshold,
		?float $median,
		?float $max
	): string {
		$ratio = 0.0;
		if ( $threshold > 0 ) {
			if ( self::VERDICT_FATIGUE === $verdict && null !== $median ) {
				$ratio = $median / $threshold;
			} elseif ( null !== $max ) {
				$ratio = $max / $threshold;
			}
		}

		return sanitize_key( $control_id )
			. '|' . sanitize_text_field( $scope )
			. '|' . sanitize_key( $verdict )
			. '|t' . self::sig( $threshold )
			. '|r' . self::ratio_bucket( $ratio );
	}

	/**
	 * @param float|null $min Min.
	 * @param float|null $median Median.
	 * @param float|null $max Max.
	 */
	public static function build_summary(
		string $label,
		string $scope,
		float $threshold,
		string $unit,
		string $verdict,
		$min,
		$median,
		$max,
		int $fire_count,
		int $window_days,
		string $note
	): string {
		$scope_bit = ( 'site' === $scope || '' === $scope ) ? '' : ' (' . $scope . ')';
		$th_disp   = self::format_value( $threshold, $unit );

		if ( self::VERDICT_INSUFFICIENT === $verdict ) {
			return sprintf(
				/* translators: 1: control label, 2: scope, 3: threshold, 4: note */
				__( '%1$s%2$s threshold is %3$s — %4$s (skipped, not guessed).', 'handl-ai-connector-access-control' ),
				$label,
				$scope_bit,
				$th_disp,
				$note
			);
		}

		if ( self::VERDICT_SLEEPWALK === $verdict ) {
			return sprintf(
				/* translators: 1: control label, 2: scope, 3: threshold, 4: max observed, 5: window days */
				__( 'The %1$s%2$s is %3$s; the busiest period in %5$d days reached %4$s. This cap cannot fire.', 'handl-ai-connector-access-control' ),
				$label,
				$scope_bit,
				$th_disp,
				self::format_value( (float) $max, $unit ),
				$window_days
			);
		}

		if ( self::VERDICT_FATIGUE === $verdict ) {
			$fire_bit = $fire_count > 0
				? sprintf(
					/* translators: %d: fire count */
					__( ' and has fired %d times', 'handl-ai-connector-access-control' ),
					$fire_count
				)
				: '';

			return sprintf(
				/* translators: 1: control label, 2: scope, 3: threshold, 4: median, 5: optional fire clause */
				__( 'The %1$s%2$s is %3$s; the typical period sees %4$s. This alert fires repeatedly%5$s.', 'handl-ai-connector-access-control' ),
				$label,
				$scope_bit,
				$th_disp,
				self::format_value( (float) $median, $unit ),
				$fire_bit
			);
		}

		return sprintf(
			/* translators: 1: control label, 2: scope, 3: threshold, 4: min, 5: median, 6: max, 7: window days */
			__( '%1$s%2$s threshold %3$s looks effective over %7$d days (observed min/median/max: %4$s / %5$s / %6$s).', 'handl-ai-connector-access-control' ),
			$label,
			$scope_bit,
			$th_disp,
			self::format_value( (float) $min, $unit ),
			self::format_value( (float) $median, $unit ),
			self::format_value( (float) $max, $unit ),
			$window_days
		);
	}

	public static function format_value( float $v, string $unit ): string {
		switch ( $unit ) {
			case 'usd':
				return '$' . number_format( $v, $v >= 100 ? 0 : 2 );
			case 'ms':
				return number_format( $v, 0 ) . ' ms';
			case 'ratio':
				return number_format( $v, 2 ) . '×';
			case 'days':
				return number_format( $v, 0 ) . ' days';
			case 'visitors':
			case 'calls':
			case 'alerts':
				return number_format( $v, 0 );
			default:
				return number_format( $v, 2 );
		}
	}

	/**
	 * Full census (all enabled controls with enough/insufficient history).
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function census( ?int $now = null ): array {
		if ( null !== self::$test_census ) {
			return self::$test_census;
		}
		$now         = self::resolve_now( $now );
		$window_days = self::window_days();
		$out         = array();
		foreach ( self::bundled_registry() as $entry ) {
			foreach ( self::observe_entry( $entry, $now, $window_days ) as $row ) {
				$out[] = $row;
			}
		}

		return $out;
	}

	/**
	 * Actionable findings only (sleepwalking + alarm-fatigued), before ack filter.
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function all_findings( ?int $now = null ): array {
		$out = array();
		foreach ( self::census( $now ) as $row ) {
			$v = (string) ( $row['verdict'] ?? '' );
			if ( self::VERDICT_SLEEPWALK === $v || self::VERDICT_FATIGUE === $v ) {
				$out[] = $row;
			}
		}

		return $out;
	}

	/**
	 * Unacknowledged actionable findings.
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function findings( ?int $now = null ): array {
		$ack = array_fill_keys( (array) self::get_state()['acknowledged'], true );
		$out = array();
		foreach ( self::all_findings( $now ) as $row ) {
			$key = (string) ( $row['key'] ?? '' );
			if ( '' === $key || isset( $ack[ $key ] ) ) {
				continue;
			}
			$out[] = $row;
		}

		return $out;
	}

	/**
	 * Unacknowledged sleepwalking findings (CLI non-zero exit).
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function sleepwalking_findings( ?int $now = null ): array {
		$out = array();
		foreach ( self::findings( $now ) as $row ) {
			if ( self::VERDICT_SLEEPWALK === (string) ( $row['verdict'] ?? '' ) ) {
				$out[] = $row;
			}
		}

		return $out;
	}

	/**
	 * @param list<string> $keys Finding keys.
	 */
	public static function acknowledge( array $keys ): int {
		$state = self::get_state();
		$ack   = array_fill_keys( (array) $state['acknowledged'], true );
		$added = 0;
		foreach ( $keys as $key ) {
			$key = sanitize_text_field( (string) $key );
			if ( '' === $key || isset( $ack[ $key ] ) ) {
				continue;
			}
			$ack[ $key ] = true;
			++$added;
		}
		if ( $added <= 0 ) {
			return 0;
		}
		$state['acknowledged']       = array_keys( $ack );
		$state['alerted']            = false;
		$state['last_alert_ts']      = 0;
		$state['last_alert_channel'] = '';
		self::put_state( $state );

		return $added;
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function snapshot( ?int $now = null ): array {
		$now      = self::resolve_now( $now );
		$census   = self::census( $now );
		$findings = self::findings( $now );
		$state    = self::get_state();
		$sleep    = 0;
		$fatigue  = 0;
		foreach ( $findings as $row ) {
			if ( self::VERDICT_SLEEPWALK === (string) ( $row['verdict'] ?? '' ) ) {
				++$sleep;
			} elseif ( self::VERDICT_FATIGUE === (string) ( $row['verdict'] ?? '' ) ) {
				++$fatigue;
			}
		}

		return array(
			'enabled'                => self::is_enabled(),
			'outbound_alert'         => self::is_outbound_enabled(),
			'window_days'            => self::window_days(),
			'now'                    => $now,
			'census'                 => $census,
			'findings'               => $findings,
			'unacknowledged_count'   => count( $findings ),
			'sleepwalking_count'     => $sleep,
			'alarm_fatigued_count'   => $fatigue,
			'alerted'                => ! empty( $state['alerted'] ),
			'last_alert_ts'          => (int) $state['last_alert_ts'],
			'last_alert_channel'     => (string) $state['last_alert_channel'],
			'last_check_ts'          => (int) $state['last_check_ts'],
			'acknowledged_count'     => count( (array) $state['acknowledged'] ),
			'framing'                => self::FRAMING,
		);
	}

	/* ---------------------------------------------------------------------
	 * Throttled check + alerts
	 * ------------------------------------------------------------------ */

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

	public static function maybe_fire_alerts( ?int $now = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now      = self::resolve_now( $now );
		$findings = self::findings( $now );
		$state    = self::get_state();

		if ( empty( $findings ) ) {
			if ( ! empty( $state['alerted'] ) ) {
				$state['alerted']            = false;
				$state['last_alert_ts']      = 0;
				$state['last_alert_channel'] = '';
				self::put_state( $state );
			}

			return false;
		}

		if ( ! empty( $state['alerted'] ) ) {
			return false;
		}

		$channel = self::CHANNEL_NOTICE;
		if ( self::is_outbound_enabled() ) {
			if ( ! self::fire_outbound( $findings, $now ) ) {
				return false;
			}
			$channel = self::CHANNEL_OUTBOUND;
		}

		$state['alerted']            = true;
		$state['last_alert_ts']      = $now;
		$state['last_alert_channel'] = $channel;
		self::put_state( $state );

		return true;
	}

	/**
	 * @param list<array<string,mixed>> $findings Findings.
	 */
	private static function fire_outbound( array $findings, int $now ): bool {
		$policy = self::resolve_policy();
		$email  = self::resolve_email( $policy );
		if ( '' === $email ) {
			$email = sanitize_email( (string) get_option( 'admin_email' ) );
		}

		$ok = false;
		if ( '' !== $email ) {
			$subject = self::build_subject( $findings );
			$body    = self::build_body( $findings );
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
		}

		$hook_url = self::resolve_webhook( $policy );
		if ( '' !== $hook_url && class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
			$kinds = array();
			foreach ( $findings as $row ) {
				$kinds[ (string) ( $row['verdict'] ?? '' ) ] = true;
			}
			$posted = (bool) Alerts::safe_wp_remote_post(
				$hook_url,
				array(
					'type'                 => 'handl_aicac_sleepwalker',
					'unacknowledged_count' => count( $findings ),
					'verdicts'             => array_keys( $kinds ),
					'ts'                   => $now,
				)
			);
			$ok = $ok || $posted;
		}

		return $ok;
	}

	/**
	 * @param list<array<string,mixed>> $findings Findings.
	 */
	public static function build_subject( array $findings ): string {
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$sleep = 0;
		$fat   = 0;
		foreach ( $findings as $row ) {
			if ( self::VERDICT_SLEEPWALK === (string) ( $row['verdict'] ?? '' ) ) {
				++$sleep;
			} elseif ( self::VERDICT_FATIGUE === (string) ( $row['verdict'] ?? '' ) ) {
				++$fat;
			}
		}

		return sprintf(
			/* translators: 1: site name, 2: sleepwalking count, 3: fatigue count */
			__( '[%1$s] [SLEEPWALKER] Threshold efficacy: %2$d sleepwalking, %3$d alarm-fatigued', 'handl-ai-connector-access-control' ),
			$site,
			$sleep,
			$fat
		);
	}

	/**
	 * @param list<array<string,mixed>> $findings Findings.
	 */
	public static function build_body( array $findings ): string {
		$lines   = array();
		$lines[] = __( 'AI Access Control compared configured thresholds to observed usage. Suggestion only — no threshold was changed.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		foreach ( $findings as $row ) {
			$lines[] = '- ' . (string) ( $row['summary'] ?? '' );
		}
		$lines[] = '';
		$lines[] = __( 'Acknowledge findings you accept, or open the owning control to adjust the threshold yourself.', 'handl-ai-connector-access-control' );
		$url     = self::admin_url();
		if ( '' !== $url ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Open sleepwalker: %s', 'handl-ai-connector-access-control' ),
				$url
			);
		}

		return implode( "\n", $lines );
	}

	/* ---------------------------------------------------------------------
	 * Admin notice
	 * ------------------------------------------------------------------ */

	public static function maybe_render_notice(): void {
		if ( ! self::is_enabled() || ! Caps::user_can_view() ) {
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG === $page ) {
			return;
		}
		$findings = self::findings();
		if ( empty( $findings ) ) {
			return;
		}

		$html  = '<div class="notice notice-warning"><p><strong>' . esc_html__( 'AI Access Control — Sleepwalker:', 'handl-ai-connector-access-control' ) . '</strong> ';
		$html .= esc_html(
			sprintf(
				/* translators: %d: finding count */
				_n( '%d unacknowledged threshold-efficacy finding.', '%d unacknowledged threshold-efficacy findings.', count( $findings ), 'handl-ai-connector-access-control' ),
				count( $findings )
			)
		);
		$url = self::admin_url();
		if ( '' !== $url ) {
			$html .= ' <a href="' . esc_url( $url ) . '">' . esc_html__( 'Review', 'handl-ai-connector-access-control' ) . '</a>';
		}
		$html .= '</p></div>';

		self::$test_notices[] = $html;
		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped above.
	}

	/* ---------------------------------------------------------------------
	 * CSV + print
	 * ------------------------------------------------------------------ */

	/**
	 * @param array<string,mixed>|null $snap Snapshot.
	 */
	public static function csv_for_snapshot( ?array $snap = null ): string {
		if ( null === $snap ) {
			$snap = self::snapshot();
		}
		$lines   = array();
		$lines[] = self::csv_line( array( 'section', 'control', 'scope', 'threshold', 'min', 'median', 'max', 'verdict', 'summary', 'framing' ) );
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
				'checked=' . gmdate( 'Y-m-d H:i:s', (int) ( $snap['now'] ?? 0 ) ) . ' UTC'
					. ' window_days=' . (string) (int) ( $snap['window_days'] ?? 0 )
					. ' unacknowledged=' . (string) (int) ( $snap['unacknowledged_count'] ?? 0 )
					. ' sleepwalking=' . (string) (int) ( $snap['sleepwalking_count'] ?? 0 ),
				self::FRAMING,
			)
		);
		foreach ( (array) ( $snap['census'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$lines[] = self::csv_line(
				array(
					'census',
					(string) $row['control_id'],
					(string) $row['scope'],
					(string) $row['threshold'],
					null === $row['min'] ? '' : (string) $row['min'],
					null === $row['median'] ? '' : (string) $row['median'],
					null === $row['max'] ? '' : (string) $row['max'],
					(string) $row['verdict'],
					(string) $row['summary'],
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
					(string) $row['control_id'],
					(string) $row['scope'],
					(string) $row['threshold'],
					null === $row['min'] ? '' : (string) $row['min'],
					null === $row['median'] ? '' : (string) $row['median'],
					null === $row['max'] ? '' : (string) $row['max'],
					(string) $row['verdict'],
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
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8" /><title>SLEEPWALKER</title>';
		$html .= '<style>body{font-family:sans-serif;margin:2rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:.4rem;text-align:left}h1,h2{margin-top:1.5rem}</style>';
		$html .= '</head><body>';
		$html .= '<h1>' . esc_html__( 'Sleepwalker — threshold efficacy', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Report only — never tunes a threshold.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<p>' . esc_html( sprintf( 'Unacknowledged: %d (sleepwalking %d / alarm-fatigued %d)', (int) ( $snap['unacknowledged_count'] ?? 0 ), (int) ( $snap['sleepwalking_count'] ?? 0 ), (int) ( $snap['alarm_fatigued_count'] ?? 0 ) ) ) . '</p>';
		$html .= '<h2>' . esc_html__( 'Findings', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= self::findings_table_html( (array) ( $snap['findings'] ?? array() ), false );
		$html .= '<h2>' . esc_html__( 'Census', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= self::census_table_html( (array) ( $snap['census'] ?? array() ), false );
		$html .= '</body></html>';

		return $html;
	}

	/**
	 * @param list<array<string,mixed>> $rows Findings.
	 */
	private static function findings_table_html( array $rows, bool $links ): string {
		$html  = '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Verdict', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Finding', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Suggestion', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		$shown = 0;
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			++$shown;
			$summary = esc_html( (string) ( $row['summary'] ?? '' ) );
			if ( $links && ! empty( $row['deep_link'] ) ) {
				$summary .= ' <a href="' . esc_url( (string) $row['deep_link'] ) . '">' . esc_html__( 'Open control', 'handl-ai-connector-access-control' ) . '</a>';
			}
			$html .= '<tr><td>' . esc_html( (string) ( $row['verdict'] ?? '' ) ) . '</td><td>' . $summary . '</td><td>' . esc_html( (string) ( $row['suggestion'] ?? '' ) ) . '</td></tr>';
		}
		if ( 0 === $shown ) {
			$html .= '<tr><td colspan="3">' . esc_html__( 'No unacknowledged threshold-efficacy findings.', 'handl-ai-connector-access-control' ) . '</td></tr>';
		}
		$html .= '</tbody></table>';

		return $html;
	}

	/**
	 * @param list<array<string,mixed>> $rows Census.
	 */
	private static function census_table_html( array $rows, bool $links ): string {
		$html  = '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Control', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Scope', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Threshold', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Min / Median / Max', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Verdict', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$label = esc_html( (string) ( $row['label'] ?? '' ) );
			if ( $links && ! empty( $row['deep_link'] ) ) {
				$label = '<a href="' . esc_url( (string) $row['deep_link'] ) . '">' . $label . '</a>';
			}
			$unit = (string) ( $row['unit'] ?? '' );
			$mmm  = ( null === $row['min'] )
				? '—'
				: self::format_value( (float) $row['min'], $unit ) . ' / '
					. self::format_value( (float) $row['median'], $unit ) . ' / '
					. self::format_value( (float) $row['max'], $unit );
			$html .= '<tr>';
			$html .= '<td>' . $label . '</td>';
			$html .= '<td>' . esc_html( (string) ( $row['scope'] ?? '' ) ) . '</td>';
			$html .= '<td>' . esc_html( self::format_value( (float) ( $row['threshold'] ?? 0 ), $unit ) ) . '</td>';
			$html .= '<td>' . esc_html( $mmm ) . '</td>';
			$html .= '<td>' . esc_html( (string) ( $row['verdict'] ?? '' ) ) . '</td>';
			$html .= '</tr>';
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
		if ( ! function_exists( 'add_submenu_page' ) || ! class_exists( Admin::class, false ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Sleepwalker', 'handl-ai-connector-access-control' ),
			__( 'Sleepwalker', 'handl-ai-connector-access-control' ),
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
				'page'                         => self::PAGE_SLUG,
				'handl_aicac_sleepwalker_csv'  => '1',
				'_wpnonce'                     => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_sleepwalker_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print      = add_query_arg(
			array(
				'page'                          => self::PAGE_SLUG,
				'handl_aicac_sleepwalker_print' => '1',
				'_wpnonce'                      => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_sleepwalker_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Sleepwalker', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Compares configured thresholds on enabled controls to observed usage over a trailing window. Flags caps that cannot fire (sleepwalking) and caps that fire continuously (alarm-fatigued). Suggestion only — it never tunes a number. Checks run on admin page loads, not on cron. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable sleepwalker', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Audit threshold efficacy on admin page loads', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row">' . esc_html__( 'Trailing window (days)', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<input type="number" min="' . esc_attr( (string) self::MIN_WINDOW_DAYS ) . '" max="' . esc_attr( (string) self::MAX_WINDOW_DAYS ) . '" class="small-text" name="' . esc_attr( self::POST_WINDOW ) . '" value="' . esc_attr( (string) (int) $settings['window_days'] ) . '" /></td></tr>';
			echo '<tr><th scope="row">' . esc_html__( 'Outbound alert', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_OUTBOUND ) . '" value="1" ' . checked( ! empty( $settings['outbound_alert'] ), true, false ) . ' /> ';
			echo esc_html__( 'Also send a [SLEEPWALKER] alert by email / webhook when a new finding appears (off by default)', 'handl-ai-connector-access-control' );
			echo '</label></td></tr></tbody></table>';
			submit_button( __( 'Save sleepwalker settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled || ! is_array( $snap ) ) {
			echo '<p>' . esc_html__( 'Sleepwalker is off. Enable it to census threshold efficacy.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Report only — never tunes, edits, or suggests a specific “correct” number.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		if ( (int) $snap['unacknowledged_count'] > 0 ) {
			echo '<div class="notice notice-warning inline"><p><strong>' . esc_html__( 'Unacknowledged threshold-efficacy findings.', 'handl-ai-connector-access-control' ) . '</strong> ';
			echo esc_html__( 'Acknowledge findings you accept, or open the owning control.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		echo '<ul>';
		echo '<li>' . esc_html( sprintf( 'Window: %d days', (int) $snap['window_days'] ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( 'Unacknowledged: %d (sleepwalking %d / alarm-fatigued %d)', (int) $snap['unacknowledged_count'], (int) $snap['sleepwalking_count'], (int) $snap['alarm_fatigued_count'] ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( 'Acknowledged: %d', (int) $snap['acknowledged_count'] ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( 'Alert delivery: %s', ! empty( $snap['outbound_alert'] ) ? 'admin notice + this screen + email/webhook' : 'admin notice + this screen' ) ) . '</li>';
		echo '</ul>';

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Findings', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( $can_manage && (int) $snap['unacknowledged_count'] > 0 ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_ACK ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_ACK );
			}
			echo str_replace( '<table>', '<table class="widefat striped">', self::findings_ack_table_html( (array) $snap['findings'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			submit_button( __( 'Acknowledge selected', 'handl-ai-connector-access-control' ), 'secondary' );
			echo '</form>';
		} else {
			echo str_replace( '<table>', '<table class="widefat striped">', self::findings_table_html( (array) $snap['findings'], true ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}

		echo '<h2>' . esc_html__( 'Threshold census', 'handl-ai-connector-access-control' ) . '</h2>';
		echo str_replace( '<table>', '<table class="widefat striped">', self::census_table_html( (array) $snap['census'], true ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		echo '</div>';
	}

	/**
	 * @param list<array<string,mixed>> $rows Findings.
	 */
	private static function findings_ack_table_html( array $rows ): string {
		$html  = '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Ack', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Verdict', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Finding', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Suggestion', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$key = (string) ( $row['key'] ?? '' );
			$html .= '<tr>';
			$html .= '<td><input type="checkbox" name="ack_keys[]" value="' . esc_attr( $key ) . '" /></td>';
			$html .= '<td>' . esc_html( (string) ( $row['verdict'] ?? '' ) ) . '</td>';
			$summary = esc_html( (string) ( $row['summary'] ?? '' ) );
			if ( ! empty( $row['deep_link'] ) ) {
				$summary .= ' <a href="' . esc_url( (string) $row['deep_link'] ) . '">' . esc_html__( 'Open control', 'handl-ai-connector-access-control' ) . '</a>';
			}
			$html .= '<td>' . $summary . '</td>';
			$html .= '<td>' . esc_html( (string) ( $row['suggestion'] ?? '' ) ) . '</td>';
			$html .= '</tr>';
		}
		$html .= '</tbody></table>';

		return $html;
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_sleepwalker_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
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
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_sleepwalker_csv' ) ) {
			return;
		}
		$csv = self::csv_for_snapshot();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=handl-aicac-sleepwalker.csv' );
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		if ( empty( $_GET['handl_aicac_sleepwalker_print'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
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
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_sleepwalker_print' ) ) {
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
			wp_die( esc_html__( 'You do not have permission to save sleepwalker settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );
		}
		self::save_settings(
			array(
				'enabled'        => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'outbound_alert' => ! empty( $_POST[ self::POST_OUTBOUND ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'window_days'    => isset( $_POST[ self::POST_WINDOW ] ) ? wp_unslash( $_POST[ self::POST_WINDOW ] ) : self::DEFAULT_WINDOW_DAYS, // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			)
		);
		self::redirect_to_page();
	}

	public static function handle_ack(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to acknowledge sleepwalker findings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_ACK );
		$keys = isset( $_POST['ack_keys'] ) && is_array( $_POST['ack_keys'] ) ? wp_unslash( $_POST['ack_keys'] ) : array(); // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$clean = array();
		foreach ( $keys as $key ) {
			$clean[] = sanitize_text_field( (string) $key );
		}
		self::acknowledge( $clean );
		self::redirect_to_page();
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac sleepwalker', CLI_Sleepwalker::class );
	}
}

/**
 * WP-CLI: wp handl-aicac sleepwalker status|export
 */
final class CLI_Sleepwalker {

	/**
	 * Run a threshold-efficacy check and show unacknowledged findings.
	 * Exits non-zero while any unacknowledged sleepwalking finding is present (while enabled).
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

		if ( ! Sleepwalker::is_enabled() ) {
			\WP_CLI::log( 'enabled=no framing=' . Sleepwalker::FRAMING );
			\WP_CLI::log( 'Sleepwalker is disabled.' );

			return;
		}

		Sleepwalker::maybe_check( null, true );
		$snap = Sleepwalker::snapshot();

		\WP_CLI::log(
			sprintf(
				'enabled=yes window_days=%d unacknowledged=%d sleepwalking=%d alarm_fatigued=%d alerted=%s outbound=%s framing=%s',
				(int) $snap['window_days'],
				(int) $snap['unacknowledged_count'],
				(int) $snap['sleepwalking_count'],
				(int) $snap['alarm_fatigued_count'],
				! empty( $snap['alerted'] ) ? 'yes' : 'no',
				! empty( $snap['outbound_alert'] ) ? 'on' : 'off',
				Sleepwalker::FRAMING
			)
		);

		$display = array();
		foreach ( (array) $snap['findings'] as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$display[] = array(
				'control'  => (string) $row['control_id'],
				'scope'    => (string) $row['scope'],
				'verdict'  => (string) $row['verdict'],
				'threshold'=> (string) $row['threshold'],
				'summary'  => (string) $row['summary'],
			);
		}
		if ( ! empty( $display ) ) {
			if ( 'json' === $format ) {
				\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			} elseif ( class_exists( '\\WP_CLI\\Utils' ) ) {
				\WP_CLI\Utils\format_items( 'table', $display, array( 'control', 'scope', 'verdict', 'threshold', 'summary' ) );
			} else {
				foreach ( $display as $row ) {
					\WP_CLI::log( implode( "\t", $row ) );
				}
			}
		}

		if ( (int) $snap['sleepwalking_count'] > 0 ) {
			\WP_CLI::error( 'Unacknowledged sleepwalking finding present.' );
		}
	}

	/**
	 * Export the threshold census and findings as CSV.
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
		$csv = Sleepwalker::csv_for_snapshot();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
