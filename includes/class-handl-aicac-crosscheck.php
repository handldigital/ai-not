<?php
/**
 * AICAC-CROSSCHECK (#409): settings contradiction linter (read-only).
 *
 * Bundled static rule table of cross-control contradiction checks (threshold
 * ordering, window contradictions, enforce-without-feed, orphaned sub-toggles,
 * impossible schedules). Extensible via handl_aicac_crosscheck_rules. All reads
 * of other controls' options are read-only. Suggestion-only — never auto-fixes.
 * Exactly one re-arming [CROSSCHECK] alert on a new contradiction. Print + CSV
 * + WP-CLI. OFF by default. Own two options.
 *
 * Scope fences: recipients = Succession; policy assertions = Policy_Checks;
 * completeness = Checklist. This class reads setting COMBINATIONS only.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Cross-control settings contradiction linter.
 */
final class Crosscheck {

	public const SETTINGS_OPTION = 'handl_aicac_crosscheck';

	public const STATE_OPTION = 'handl_aicac_crosscheck_state';

	public const PAGE_SLUG = 'handl-aicac-crosscheck';

	public const ALERT_KIND = 'crosscheck';

	public const FRAMING = 'report_only_never_auto_fixes';

	public const FILTER_RULES = 'handl_aicac_crosscheck_rules';

	public const POST_PRESENT = 'handl_aicac_crosscheck_present';

	public const POST_ENABLED = 'handl_aicac_crosscheck_enabled';

	public const ACTION_SAVE = 'handl_aicac_crosscheck_save';

	public const HISTORY_CAP = 40;

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
			add_action( 'init', array( self::class, 'maybe_fire_alerts' ), 30 );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$test_mails = array();
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
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled' => ! empty( $raw['enabled'] ),
		);
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

	/**
	 * @return array{alerted:bool,history:list<array<string,mixed>>}
	 */
	public static function defaults_state(): array {
		return array(
			'alerted' => false,
			'history' => array(),
		);
	}

	/**
	 * @return array{alerted:bool,history:list<array<string,mixed>>}
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw state.
	 * @return array{alerted:bool,history:list<array<string,mixed>>}
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

		return array(
			'alerted' => ! empty( $raw['alerted'] ),
			'history' => $history,
		);
	}

	/**
	 * @param mixed $row Raw history row.
	 * @return array{ts:int,count:int,ids:list<string>}|null
	 */
	public static function sanitize_history_entry( $row ): ?array {
		if ( ! is_array( $row ) ) {
			return null;
		}
		$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		if ( $ts <= 0 ) {
			return null;
		}
		$ids = array();
		if ( isset( $row['ids'] ) && is_array( $row['ids'] ) ) {
			foreach ( $row['ids'] as $id ) {
				$id = sanitize_key( (string) $id );
				if ( '' !== $id ) {
					$ids[] = $id;
				}
			}
		}
		$ids = array_values( array_unique( $ids ) );

		return array(
			'ts'    => $ts,
			'count' => max( 0, (int) ( $row['count'] ?? count( $ids ) ) ),
			'ids'   => $ids,
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

	/**
	 * Bundled static contradiction rules.
	 *
	 * Each rule:
	 * - id (unique key)
	 * - class: threshold_ordering|window|enforce_without_feed|orphaned_subtoggle|impossible_schedule
	 * - severity: error|warning
	 * - page: admin page slug for deep link
	 * - finding: plain-language suggestion
	 * - check: built-in evaluator key OR callable returning bool (true = contradiction)
	 * - options: list of option keys read (documentation / filter consumers)
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function bundled_rules(): array {
		$policy = class_exists( Plugin::class, false ) ? Plugin::OPTION_KEY : 'handl_aicac_policy';

		return array(
			array(
				'id'       => 'spend_threshold_vs_budget',
				'class'    => 'threshold_ordering',
				'severity' => 'error',
				'page'     => 'handl-aicac',
				'finding'  => 'A soft-warn spend threshold is at or above its hard plugin budget, so the warn never precedes the cap.',
				'check'    => 'spend_threshold_vs_budget',
				'options'  => array( $policy ),
			),
			array(
				'id'       => 'rate_cap_hour_gt_day',
				'class'    => 'threshold_ordering',
				'severity' => 'error',
				'page'     => 'handl-aicac',
				'finding'  => 'An hourly rate cap is higher than the daily cap for the same plugin, so the day limit can never fire first.',
				'check'    => 'rate_cap_hour_gt_day',
				'options'  => array( $policy ),
			),
			array(
				'id'       => 'anomaly_retention_window',
				'class'    => 'window',
				'severity' => 'error',
				'page'     => 'handl-aicac',
				'finding'  => 'Spike alerts are on, but activity retention is shorter than the baseline window those alerts need.',
				'check'    => 'anomaly_retention_window',
				'options'  => array( $policy ),
			),
			array(
				'id'       => 'weekly_report_retention_window',
				'class'    => 'window',
				'severity' => 'warning',
				'page'     => 'handl-aicac',
				'finding'  => 'Weekly report is on, but activity retention is shorter than seven days, so the digest has less than a week of data.',
				'check'    => 'weekly_report_retention_window',
				'options'  => array( $policy ),
			),
			array(
				'id'       => 'shadow_block_without_logging',
				'class'    => 'enforce_without_feed',
				'severity' => 'error',
				'page'     => 'handl-aicac',
				'finding'  => 'Direct-AI block is enabled while activity logging and learn mode are both off, so blocked calls leave no audit trail.',
				'check'    => 'shadow_block_without_logging',
				'options'  => array( $policy ),
			),
			array(
				'id'       => 'budget_deny_without_amount',
				'class'    => 'enforce_without_feed',
				'severity' => 'error',
				'page'     => 'handl-aicac',
				'finding'  => 'A plugin budget mode is set to deny without a finite budget amount, so enforcement has nothing to measure.',
				'check'    => 'budget_deny_without_amount',
				'options'  => array( $policy ),
			),
			array(
				'id'       => 'anomaly_without_logging',
				'class'    => 'enforce_without_feed',
				'severity' => 'error',
				'page'     => 'handl-aicac',
				'finding'  => 'Spike alerts are enabled while activity logging is off, so the detector has no feed.',
				'check'    => 'anomaly_without_logging',
				'options'  => array( $policy ),
			),
			array(
				'id'       => 'shadow_exceptions_orphaned',
				'class'    => 'orphaned_subtoggle',
				'severity' => 'warning',
				'page'     => 'handl-aicac',
				'finding'  => 'Shadow-block exceptions are configured while direct-AI block is off, so those exceptions never apply.',
				'check'    => 'shadow_exceptions_orphaned',
				'options'  => array( $policy ),
			),
			array(
				'id'       => 'soft_deny_on_allow_plugin',
				'class'    => 'orphaned_subtoggle',
				'severity' => 'warning',
				'page'     => 'handl-aicac',
				'finding'  => 'Soft-block mode is set on a plugin that is not denied, so the soft-block path never arms.',
				'check'    => 'soft_deny_on_allow_plugin',
				'options'  => array( $policy ),
			),
			array(
				'id'       => 'spend_threshold_without_logging',
				'class'    => 'orphaned_subtoggle',
				'severity' => 'warning',
				'page'     => 'handl-aicac',
				'finding'  => 'Spend thresholds are configured while activity logging is off, so threshold alerts never evaluate.',
				'check'    => 'spend_threshold_without_logging',
				'options'  => array( $policy ),
			),
			array(
				'id'       => 'weekly_report_without_logging',
				'class'    => 'impossible_schedule',
				'severity' => 'error',
				'page'     => 'handl-aicac',
				'finding'  => 'Weekly report is scheduled while activity logging is off, so the digest has nothing to summarize.',
				'check'    => 'weekly_report_without_logging',
				'options'  => array( $policy ),
			),
			array(
				'id'       => 'monthly_report_without_logging',
				'class'    => 'impossible_schedule',
				'severity' => 'error',
				'page'     => 'handl-aicac',
				'finding'  => 'Monthly report is scheduled while activity logging is off, so the digest has nothing to summarize.',
				'check'    => 'monthly_report_without_logging',
				'options'  => array( $policy ),
			),
		);
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function rules(): array {
		$rules = self::bundled_rules();
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( self::FILTER_RULES, $rules );
			if ( is_array( $filtered ) ) {
				$rules = $filtered;
			}
		}
		$out = array();
		foreach ( $rules as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$id       = isset( $row['id'] ) ? sanitize_key( (string) $row['id'] ) : '';
			$class    = isset( $row['class'] ) ? sanitize_key( (string) $row['class'] ) : '';
			$severity = isset( $row['severity'] ) ? sanitize_key( (string) $row['severity'] ) : 'warning';
			$page     = isset( $row['page'] ) ? sanitize_key( (string) $row['page'] ) : 'handl-aicac';
			$finding  = isset( $row['finding'] ) ? sanitize_text_field( (string) $row['finding'] ) : '';
			$check    = $row['check'] ?? '';
			if ( '' === $id || '' === $class || '' === $finding ) {
				continue;
			}
			if ( 'error' !== $severity ) {
				$severity = 'warning';
			}
			$allowed_class = array(
				'threshold_ordering',
				'window',
				'enforce_without_feed',
				'orphaned_subtoggle',
				'impossible_schedule',
			);
			if ( ! in_array( $class, $allowed_class, true ) ) {
				continue;
			}
			if ( ! is_string( $check ) && ! is_callable( $check ) ) {
				continue;
			}
			$options = array();
			if ( isset( $row['options'] ) && is_array( $row['options'] ) ) {
				foreach ( $row['options'] as $opt ) {
					$opt = sanitize_key( (string) $opt );
					if ( '' !== $opt ) {
						$options[] = $opt;
					}
				}
			}
			$out[] = array(
				'id'       => $id,
				'class'    => $class,
				'severity' => $severity,
				'page'     => '' !== $page ? $page : 'handl-aicac',
				'finding'  => $finding,
				'check'    => $check,
				'options'  => $options,
			);
		}

		return $out;
	}

	/**
	 * @return array{policy:array<string,mixed>}
	 */
	public static function read_context(): array {
		$policy = array();
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' ) ) {
			$raw = Policy::get_policy();
			if ( is_array( $raw ) ) {
				$policy = $raw;
			}
		} else {
			$raw = get_option( class_exists( Plugin::class, false ) ? Plugin::OPTION_KEY : 'handl_aicac_policy', array() );
			$policy = is_array( $raw ) ? $raw : array();
		}

		return array(
			'policy' => $policy,
		);
	}

	public static function control_admin_url( string $page ): string {
		$page = sanitize_key( $page );
		if ( '' === $page ) {
			$page = 'handl-aicac';
		}
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg( 'page', $page, admin_url( 'admin.php' ) );
	}

	/**
	 * @param array<string,mixed> $rule Rule.
	 * @param array<string,mixed> $ctx  Context.
	 */
	public static function rule_is_contradiction( array $rule, array $ctx ): bool {
		$check = $rule['check'] ?? null;
		if ( is_callable( $check ) ) {
			try {
				return (bool) call_user_func( $check, $ctx, $rule );
			} catch ( \Throwable $e ) {
				return false;
			}
		}
		$key = is_string( $check ) ? $check : '';
		switch ( $key ) {
			case 'spend_threshold_vs_budget':
				return self::check_spend_threshold_vs_budget( $ctx );
			case 'rate_cap_hour_gt_day':
				return self::check_rate_cap_hour_gt_day( $ctx );
			case 'anomaly_retention_window':
				return self::check_anomaly_retention_window( $ctx );
			case 'weekly_report_retention_window':
				return self::check_weekly_report_retention_window( $ctx );
			case 'shadow_block_without_logging':
				return self::check_shadow_block_without_logging( $ctx );
			case 'budget_deny_without_amount':
				return self::check_budget_deny_without_amount( $ctx );
			case 'anomaly_without_logging':
				return self::check_anomaly_without_logging( $ctx );
			case 'shadow_exceptions_orphaned':
				return self::check_shadow_exceptions_orphaned( $ctx );
			case 'soft_deny_on_allow_plugin':
				return self::check_soft_deny_on_allow_plugin( $ctx );
			case 'spend_threshold_without_logging':
				return self::check_spend_threshold_without_logging( $ctx );
			case 'weekly_report_without_logging':
				return self::check_weekly_report_without_logging( $ctx );
			case 'monthly_report_without_logging':
				return self::check_monthly_report_without_logging( $ctx );
			default:
				return false;
		}
	}

	/**
	 * @param array<string,mixed> $ctx Context.
	 */
	public static function check_spend_threshold_vs_budget( array $ctx ): bool {
		$policy = is_array( $ctx['policy'] ?? null ) ? $ctx['policy'] : array();
		$budgets = class_exists( Budget::class, false )
			? Budget::sanitize_plugin_budgets( $policy['plugin_budgets'] ?? array() )
			: array();
		$thresholds = class_exists( Spend_Threshold::class, false )
			? Spend_Threshold::sanitize_plugin_thresholds( $policy['spend_threshold_plugins'] ?? array() )
			: array();
		foreach ( $thresholds as $plugin => $threshold ) {
			if ( ! isset( $budgets[ $plugin ] ) ) {
				continue;
			}
			if ( (float) $threshold >= (float) $budgets[ $plugin ] ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @param array<string,mixed> $ctx Context.
	 */
	public static function check_rate_cap_hour_gt_day( array $ctx ): bool {
		$policy = is_array( $ctx['policy'] ?? null ) ? $ctx['policy'] : array();
		$hour   = class_exists( Rate_Cap::class, false )
			? Rate_Cap::sanitize_plugin_caps( $policy['plugin_rate_caps_hour'] ?? array() )
			: array();
		$day = class_exists( Rate_Cap::class, false )
			? Rate_Cap::sanitize_plugin_caps( $policy['plugin_rate_caps_day'] ?? array() )
			: array();
		foreach ( $hour as $plugin => $h_limit ) {
			if ( ! isset( $day[ $plugin ] ) ) {
				continue;
			}
			if ( (int) $h_limit > (int) $day[ $plugin ] ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @param array<string,mixed> $ctx Context.
	 */
	public static function check_anomaly_retention_window( array $ctx ): bool {
		$policy = is_array( $ctx['policy'] ?? null ) ? $ctx['policy'] : array();
		if ( empty( $policy['anomaly_alert_enabled'] ) ) {
			return false;
		}
		$max_age = class_exists( Policy::class, false )
			? Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null )
			: null;
		$need = class_exists( Anomaly::class, false ) && defined( Anomaly::class . '::BASELINE_DAYS' )
			? (int) Anomaly::BASELINE_DAYS
			: 7;

		return null !== $max_age && $max_age < $need;
	}

	/**
	 * @param array<string,mixed> $ctx Context.
	 */
	public static function check_weekly_report_retention_window( array $ctx ): bool {
		$policy = is_array( $ctx['policy'] ?? null ) ? $ctx['policy'] : array();
		if ( empty( $policy['weekly_report_enabled'] ) ) {
			return false;
		}
		$max_age = class_exists( Policy::class, false )
			? Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null )
			: null;

		return null !== $max_age && $max_age < 7;
	}

	/**
	 * @param array<string,mixed> $ctx Context.
	 */
	public static function check_shadow_block_without_logging( array $ctx ): bool {
		$policy = is_array( $ctx['policy'] ?? null ) ? $ctx['policy'] : array();
		if ( empty( $policy['shadow_block_enabled'] ) ) {
			return false;
		}

		return empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] );
	}

	/**
	 * @param array<string,mixed> $ctx Context.
	 */
	public static function check_budget_deny_without_amount( array $ctx ): bool {
		$policy = is_array( $ctx['policy'] ?? null ) ? $ctx['policy'] : array();
		$modes  = class_exists( Budget::class, false )
			? Budget::sanitize_plugin_budget_modes( $policy['plugin_budget_modes'] ?? array() )
			: array();
		$budgets = class_exists( Budget::class, false )
			? Budget::sanitize_plugin_budgets( $policy['plugin_budgets'] ?? array() )
			: array();
		$deny = class_exists( Budget::class, false ) ? Budget::MODE_DENY : 'deny';
		foreach ( $modes as $plugin => $mode ) {
			if ( (string) $mode !== (string) $deny ) {
				continue;
			}
			if ( ! isset( $budgets[ $plugin ] ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @param array<string,mixed> $ctx Context.
	 */
	public static function check_anomaly_without_logging( array $ctx ): bool {
		$policy = is_array( $ctx['policy'] ?? null ) ? $ctx['policy'] : array();

		return ! empty( $policy['anomaly_alert_enabled'] ) && empty( $policy['log_enabled'] );
	}

	/**
	 * @param array<string,mixed> $ctx Context.
	 */
	public static function check_shadow_exceptions_orphaned( array $ctx ): bool {
		$policy = is_array( $ctx['policy'] ?? null ) ? $ctx['policy'] : array();
		if ( ! empty( $policy['shadow_block_enabled'] ) ) {
			return false;
		}
		$exceptions = class_exists( Shadow_AI::class, false )
			? Shadow_AI::get_block_exceptions( $policy )
			: ( is_array( $policy['shadow_block_exceptions'] ?? null ) ? $policy['shadow_block_exceptions'] : array() );

		return ! empty( $exceptions );
	}

	/**
	 * @param array<string,mixed> $ctx Context.
	 */
	public static function check_soft_deny_on_allow_plugin( array $ctx ): bool {
		$policy = is_array( $ctx['policy'] ?? null ) ? $ctx['policy'] : array();
		$soft   = class_exists( Soft_Deny::class, false )
			? Soft_Deny::sanitize_plugin_modes( $policy[ Soft_Deny::POLICY_KEY ] ?? array() )
			: array();
		if ( empty( $soft ) ) {
			return false;
		}
		$plugins = is_array( $policy['plugins'] ?? null ) ? $policy['plugins'] : array();
		$default = ( ( $policy['default'] ?? 'allow' ) === 'deny' ) ? 'deny' : 'allow';
		foreach ( array_keys( $soft ) as $plugin ) {
			$rule = isset( $plugins[ $plugin ] ) ? (string) $plugins[ $plugin ] : '';
			if ( 'deny' === $rule ) {
				continue;
			}
			if ( '' === $rule && 'deny' === $default ) {
				continue;
			}
			// Soft mode on allow / inherit-allow is orphaned.
			return true;
		}

		return false;
	}

	/**
	 * @param array<string,mixed> $ctx Context.
	 */
	public static function check_spend_threshold_without_logging( array $ctx ): bool {
		$policy = is_array( $ctx['policy'] ?? null ) ? $ctx['policy'] : array();
		if ( ! empty( $policy['log_enabled'] ) ) {
			return false;
		}
		if ( class_exists( Spend_Threshold::class, false ) ) {
			return Spend_Threshold::has_any_threshold( $policy );
		}
		$site = $policy['spend_threshold_site'] ?? null;

		return null !== $site && '' !== (string) $site && (float) $site > 0;
	}

	/**
	 * @param array<string,mixed> $ctx Context.
	 */
	public static function check_weekly_report_without_logging( array $ctx ): bool {
		$policy = is_array( $ctx['policy'] ?? null ) ? $ctx['policy'] : array();

		return ! empty( $policy['weekly_report_enabled'] ) && empty( $policy['log_enabled'] );
	}

	/**
	 * @param array<string,mixed> $ctx Context.
	 */
	public static function check_monthly_report_without_logging( array $ctx ): bool {
		$policy = is_array( $ctx['policy'] ?? null ) ? $ctx['policy'] : array();

		return ! empty( $policy['monthly_report_enabled'] ) && empty( $policy['log_enabled'] );
	}

	/**
	 * @return list<array{id:string,class:string,severity:string,finding:string,page:string,url:string}>
	 */
	public static function findings( ?array $ctx = null ): array {
		$ctx   = is_array( $ctx ) ? $ctx : self::read_context();
		$out   = array();
		foreach ( self::rules() as $rule ) {
			if ( ! self::rule_is_contradiction( $rule, $ctx ) ) {
				continue;
			}
			$page = (string) ( $rule['page'] ?? 'handl-aicac' );
			$out[] = array(
				'id'       => (string) $rule['id'],
				'class'    => (string) $rule['class'],
				'severity' => (string) $rule['severity'],
				'finding'  => (string) $rule['finding'],
				'page'     => $page,
				'url'      => self::control_admin_url( $page ),
			);
		}
		usort(
			$out,
			static function ( array $a, array $b ): int {
				$rank = static function ( string $sev ): int {
					return 'error' === $sev ? 0 : 1;
				};
				$cmp = $rank( (string) $a['severity'] ) <=> $rank( (string) $b['severity'] );
				if ( 0 !== $cmp ) {
					return $cmp;
				}

				return strcmp( (string) $a['id'], (string) $b['id'] );
			}
		);

		return $out;
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function snapshot( ?int $now = null ): array {
		$now      = null !== $now ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$findings = self::findings();
		$ids      = array_values(
			array_map(
				static function ( array $row ): string {
					return (string) $row['id'];
				},
				$findings
			)
		);
		self::record_history( $now, $ids );
		$state = self::get_state();

		return array(
			'enabled'       => self::is_enabled(),
			'count'         => count( $findings ),
			'findings'      => $findings,
			'error_count'   => count(
				array_filter(
					$findings,
					static function ( array $row ): bool {
						return 'error' === ( $row['severity'] ?? '' );
					}
				)
			),
			'warning_count' => count(
				array_filter(
					$findings,
					static function ( array $row ): bool {
						return 'warning' === ( $row['severity'] ?? '' );
					}
				)
			),
			'alerted'       => ! empty( $state['alerted'] ),
			'history'       => $state['history'],
			'framing'       => self::FRAMING,
		);
	}

	/**
	 * @param list<string> $ids Finding ids.
	 */
	public static function record_history( int $now, array $ids ): void {
		$state              = self::get_state();
		$state['history'][] = array(
			'ts'    => $now,
			'count' => count( $ids ),
			'ids'   => array_values( $ids ),
		);
		if ( count( $state['history'] ) > self::HISTORY_CAP ) {
			$state['history'] = array_slice( $state['history'], -self::HISTORY_CAP );
		}
		self::put_state( $state );
	}

	/**
	 * @return bool True when a new alert was sent.
	 */
	public static function maybe_fire_alerts( ?int $now = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now  = null !== $now ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$snap = self::snapshot( $now );
		$hot  = ! empty( $snap['findings'] );

		if ( ! $hot ) {
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
	 * @param array<string,mixed> $payload Snapshot.
	 */
	private static function fire_alert( array $payload, int $now ): bool {
		$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}
		$email = '';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		}
		if ( '' === $email ) {
			$admin = function_exists( 'sanitize_email' )
				? sanitize_email( (string) get_option( 'admin_email' ) )
				: (string) get_option( 'admin_email' );
			$email = is_string( $admin ) ? $admin : '';
		}
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

		if ( $ok && class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'    => 'handl_aicac_crosscheck',
						'count'   => (int) ( $payload['count'] ?? 0 ),
						'site'    => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'      => $now,
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
		$site  = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$count = (int) ( $payload['count'] ?? 0 );

		return sprintf(
			/* translators: 1: site name, 2: contradiction count */
			__( '[%1$s] [CROSSCHECK] %2$d settings contradiction(s) found', 'handl-ai-connector-access-control' ),
			$site,
			$count
		);
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	public static function build_body( array $payload ): string {
		$lines   = array();
		$lines[] = __( 'This site\'s AI Connector settings contain contradictions across controls. Each control saved green on its own form; together they defeat themselves.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %d: contradiction count */
			__( 'Contradictions: %d', 'handl-ai-connector-access-control' ),
			(int) ( $payload['count'] ?? 0 )
		);
		$findings = is_array( $payload['findings'] ?? null ) ? $payload['findings'] : array();
		if ( ! empty( $findings ) ) {
			$lines[] = '';
			$lines[] = __( 'Findings (suggestion only — open the linked settings; nothing is auto-fixed):', 'handl-ai-connector-access-control' );
			foreach ( $findings as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$lines[] = sprintf(
					'- [%s/%s] %s — %s',
					(string) ( $row['severity'] ?? '' ),
					(string) ( $row['class'] ?? '' ),
					(string) ( $row['finding'] ?? '' ),
					(string) ( $row['url'] ?? '' )
				);
			}
		}
		$lines[] = '';
		$lines[] = __( 'Report only — never auto-fixes settings on other controls.', 'handl-ai-connector-access-control' );
		$url     = self::admin_url();
		if ( '' !== $url ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Open crosscheck roster: %s', 'handl-ai-connector-access-control' ),
				$url
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

	public static function admin_url(): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg( 'page', self::PAGE_SLUG, admin_url( 'admin.php' ) );
	}

	/**
	 * @param array<string,mixed>|null $snap Snapshot override.
	 */
	public static function csv_for_snapshot( ?array $snap = null ): string {
		$snap = is_array( $snap ) ? $snap : self::snapshot();
		$lines = array();
		$lines[] = self::csv_line(
			array(
				'section',
				'id',
				'class',
				'severity',
				'finding',
				'url',
				'framing',
			)
		);
		$findings = is_array( $snap['findings'] ?? null ) ? $snap['findings'] : array();
		if ( empty( $findings ) ) {
			$lines[] = self::csv_line(
				array(
					'summary',
					'',
					'',
					'',
					'none',
					'',
					self::FRAMING,
				)
			);
		} else {
			foreach ( $findings as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$lines[] = self::csv_line(
					array(
						'finding',
						(string) ( $row['id'] ?? '' ),
						(string) ( $row['class'] ?? '' ),
						(string) ( $row['severity'] ?? '' ),
						(string) ( $row['finding'] ?? '' ),
						(string) ( $row['url'] ?? '' ),
						self::FRAMING,
					)
				);
			}
		}
		$history = is_array( $snap['history'] ?? null ) ? $snap['history'] : array();
		foreach ( $history as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$lines[] = self::csv_line(
				array(
					'history',
					(string) (int) ( $row['ts'] ?? 0 ),
					'',
					'',
					(string) (int) ( $row['count'] ?? 0 ),
					implode( '|', is_array( $row['ids'] ?? null ) ? $row['ids'] : array() ),
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
			if ( false !== strpos( $col, '"' ) || false !== strpos( $col, ',' ) || false !== strpos( $col, "\n" ) ) {
				$col = '"' . str_replace( '"', '""', $col ) . '"';
			}
			$out[] = $col;
		}

		return implode( ',', $out );
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_print_html( array $snap ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8" />';
		$html .= '<title>' . esc_html__( 'AI Connector crosscheck', 'handl-ai-connector-access-control' ) . '</title>';
		$html .= '<style>body{font:14px/1.4 sans-serif;margin:24px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f5f5f5}</style>';
		$html .= '</head><body>';
		$html .= '<h1>' . esc_html__( 'Settings crosscheck', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Report only — never auto-fixes settings on other controls.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<p>' . esc_html(
			sprintf(
				/* translators: %d: contradiction count */
				__( 'Contradictions: %d', 'handl-ai-connector-access-control' ),
				(int) ( $snap['count'] ?? 0 )
			)
		) . '</p>';
		$html .= '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Severity', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Class', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Finding', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Link', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		$findings = is_array( $snap['findings'] ?? null ) ? $snap['findings'] : array();
		if ( empty( $findings ) ) {
			$html .= '<tr><td colspan="4">' . esc_html__( 'No contradictions.', 'handl-ai-connector-access-control' ) . '</td></tr>';
		} else {
			foreach ( $findings as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$html .= '<tr>';
				$html .= '<td>' . esc_html( (string) ( $row['severity'] ?? '' ) ) . '</td>';
				$html .= '<td>' . esc_html( (string) ( $row['class'] ?? '' ) ) . '</td>';
				$html .= '<td>' . esc_html( (string) ( $row['finding'] ?? '' ) ) . '</td>';
				$html .= '<td>' . esc_html( (string) ( $row['url'] ?? '' ) ) . '</td>';
				$html .= '</tr>';
			}
		}
		$html .= '</tbody></table></body></html>';

		return $html;
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
			__( 'Settings crosscheck', 'handl-ai-connector-access-control' ),
			__( 'Crosscheck', 'handl-ai-connector-access-control' ),
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
				'handl_aicac_crosscheck_csv' => '1',
				'_wpnonce'                   => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_crosscheck_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print = add_query_arg(
			array(
				'page'                         => self::PAGE_SLUG,
				'handl_aicac_crosscheck_print' => '1',
				'_wpnonce'                     => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_crosscheck_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Settings crosscheck', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Find combinations of AI Connector settings that defeat themselves. Report only — never auto-fixes. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable crosscheck', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Lint settings combinations, list contradictions, and alert when a new one appears', 'handl-ai-connector-access-control' );
			echo '</label></td></tr></tbody></table>';
			submit_button( __( 'Save crosscheck settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled || ! is_array( $snap ) ) {
			echo '<p>' . esc_html__( 'Crosscheck is off. Enable it to lint settings combinations across controls.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Report only — never auto-fixes settings on other controls.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		echo '<ul>';
		echo '<li>' . esc_html(
			sprintf(
				/* translators: %d: contradiction count */
				__( 'Contradictions: %d', 'handl-ai-connector-access-control' ),
				(int) $snap['count']
			)
		) . '</li>';
		echo '<li>' . esc_html(
			sprintf(
				/* translators: 1: error count, 2: warning count */
				__( 'Errors: %1$d · Warnings: %2$d', 'handl-ai-connector-access-control' ),
				(int) $snap['error_count'],
				(int) $snap['warning_count']
			)
		) . '</li>';
		echo '</ul>';

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Findings', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $snap['findings'] ) ) {
			echo '<p>' . esc_html__( 'No contradictions detected.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Severity', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Class', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Finding', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Open', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( (array) $snap['findings'] as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				echo '<tr>';
				echo '<td>' . esc_html( (string) ( $row['severity'] ?? '' ) ) . '</td>';
				echo '<td>' . esc_html( (string) ( $row['class'] ?? '' ) ) . '</td>';
				echo '<td>' . esc_html( (string) ( $row['finding'] ?? '' ) ) . '</td>';
				$url = (string) ( $row['url'] ?? '' );
				echo '<td>';
				if ( '' !== $url ) {
					echo '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Settings', 'handl-ai-connector-access-control' ) . '</a>';
				}
				echo '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '</div>';
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_crosscheck_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		if ( ! Caps::user_can_view() ) {
			wp_die( esc_html__( 'Forbidden.', 'handl-ai-connector-access-control' ), 403 );
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['_wpnonce'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_crosscheck_csv' ) ) {
			wp_die( esc_html__( 'Invalid nonce.', 'handl-ai-connector-access-control' ), 403 );
		}
		if ( ! self::is_enabled() ) {
			wp_die( esc_html__( 'Crosscheck is disabled.', 'handl-ai-connector-access-control' ), 400 );
		}
		$csv = self::csv_for_snapshot();
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=handl-aicac-crosscheck.csv' );
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		if ( empty( $_GET['handl_aicac_crosscheck_print'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		if ( ! Caps::user_can_view() ) {
			wp_die( esc_html__( 'Forbidden.', 'handl-ai-connector-access-control' ), 403 );
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['_wpnonce'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_crosscheck_print' ) ) {
			wp_die( esc_html__( 'Invalid nonce.', 'handl-ai-connector-access-control' ), 403 );
		}
		if ( ! self::is_enabled() ) {
			wp_die( esc_html__( 'Crosscheck is disabled.', 'handl-ai-connector-access-control' ), 400 );
		}
		nocache_headers();
		echo self::build_print_html( self::snapshot() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'Forbidden.', 'handl-ai-connector-access-control' ), 403 );
		}
		$nonce = isset( $_POST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['_wpnonce'] ) ) : '';
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, self::ACTION_SAVE ) ) {
			wp_die( esc_html__( 'Invalid nonce.', 'handl-ai-connector-access-control' ), 403 );
		}
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) {
			wp_die( esc_html__( 'Missing form marker.', 'handl-ai-connector-access-control' ), 400 );
		}
		$enabled = ! empty( $_POST[ self::POST_ENABLED ] );
		self::save_settings( array( 'enabled' => $enabled ) );
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
		\WP_CLI::add_command( 'handl-aicac crosscheck', CLI_Crosscheck::class );
	}
}

/**
 * WP-CLI: wp handl-aicac crosscheck status|export
 */
final class CLI_Crosscheck {

	/**
	 * Show crosscheck status. Exits non-zero on any contradiction.
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

		if ( ! Crosscheck::is_enabled() ) {
			\WP_CLI::log(
				sprintf(
					'enabled=no framing=%s',
					Crosscheck::FRAMING
				)
			);
			\WP_CLI::log( 'Crosscheck is disabled.' );

			return;
		}

		$snap     = Crosscheck::snapshot();
		$findings = (array) $snap['findings'];

		\WP_CLI::log(
			sprintf(
				'enabled=yes count=%d errors=%d warnings=%d framing=%s',
				(int) $snap['count'],
				(int) $snap['error_count'],
				(int) $snap['warning_count'],
				Crosscheck::FRAMING
			)
		);

		$display = array();
		foreach ( $findings as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$display[] = array(
				'id'       => (string) ( $row['id'] ?? '' ),
				'class'    => (string) ( $row['class'] ?? '' ),
				'severity' => (string) ( $row['severity'] ?? '' ),
				'finding'  => (string) ( $row['finding'] ?? '' ),
			);
		}
		if ( ! empty( $display ) ) {
			if ( 'json' === $format ) {
				\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			} elseif ( class_exists( '\\WP_CLI\\Utils' ) ) {
				\WP_CLI\Utils\format_items( 'table', $display, array( 'id', 'class', 'severity', 'finding' ) );
			} else {
				foreach ( $display as $row ) {
					\WP_CLI::log( implode( "\t", $row ) );
				}
			}
		}

		if ( ! empty( $findings ) ) {
			\WP_CLI::error( 'Crosscheck contradictions present.', false );
		}
	}

	/**
	 * Export the crosscheck report as CSV.
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
		$csv = Crosscheck::csv_for_snapshot();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
