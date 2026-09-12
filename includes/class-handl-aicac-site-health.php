<?php
/**
 * Site Health status test for AI access control configuration (AICAC-HEALTH).
 *
 * Read-only snapshot of existing policy — no new options or retained data.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Site_Health {
	public const TEST_SLUG = 'handl_aicac_access_control';

	public const HARDENED_TEST_SLUG = 'handl_aicac_hardened_guard';

	private static ?Site_Health $instance = null;

	public static function instance(): Site_Health {
		if ( null === self::$instance ) {
			self::$instance = new Site_Health();
		}
		return self::$instance;
	}

	public function init(): void {
		if ( ! is_admin() ) {
			return;
		}

		add_filter( 'site_status_tests', array( $this, 'register_tests' ) );
	}

	/**
	 * @param array<string,mixed> $tests
	 * @return array<string,mixed>
	 */
	public function register_tests( array $tests ): array {
		if ( ! isset( $tests['direct'] ) || ! is_array( $tests['direct'] ) ) {
			$tests['direct'] = array();
		}

		$tests['direct'][ self::TEST_SLUG ] = array(
			'label' => __( 'HandL AI Connector Access Control', 'handl-ai-connector-access-control' ),
			'test'  => array( $this, 'run_test' ),
		);

		$tests['direct'][ Selftest::SITE_HEALTH_SLUG ] = array(
			'label' => __( 'AI blocking check', 'handl-ai-connector-access-control' ),
			'test'  => array( $this, 'run_selftest' ),
		);

		$tests['direct'][ self::HARDENED_TEST_SLUG ] = array(
			'label' => __( 'Hardened mode: Off.', 'handl-ai-connector-access-control' ),
			'test'  => array( $this, 'run_hardened_test' ),
		);

		return $tests;
	}

	/**
	 * Site Health direct-test callback: hardened mode + protection-file version.
	 *
	 * @return array<string,mixed>
	 */
	public function run_hardened_test(): array {
		$hardened = class_exists( Mu_Guard::class ) ? Mu_Guard::status() : array(
			'mode'         => '',
			'enabled'      => false,
			'stub_present' => false,
			'stub_current' => false,
			'stub_version' => null,
		);

		return self::format_hardened_site_health_result( $hardened );
	}

	/**
	 * Site Health direct-test callback: live deny + allow probe (#218).
	 *
	 * @return array<string,mixed>
	 */
	public function run_selftest(): array {
		return Selftest::format_site_health_result( Selftest::run() );
	}

	/**
	 * Site Health direct-test callback.
	 *
	 * @return array<string,mixed>
	 */
	public function run_test(): array {
		$policy = Policy::get_policy();

		$installed = function_exists( 'get_plugins' ) ? get_plugins() : array();
		if ( ! is_array( $installed ) ) {
			$installed = array();
		}

		$active_raw = get_option( 'active_plugins', array() );
		$active     = array();
		if ( is_array( $active_raw ) ) {
			$active = array_fill_keys( array_map( 'strval', $active_raw ), true );
		}

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}

		$snapshot = self::build_snapshot( $policy, $installed, $active, $log );

		return self::format_site_health_result( $snapshot );
	}

	/**
	 * Pure classification + metrics for PHPUnit and the live test.
	 *
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $installed_plugins get_plugins()-shaped map.
	 * @param array<string,bool>                $active_plugins    basename => true for active.
	 * @param list<mixed>                       $log               Activity log (optional; for gap scan).
	 * @param string|null                       $mu_dir            Override WPMU_PLUGIN_DIR for hardened stub checks.
	 * @return array{
	 *   status:string,
	 *   issue:string,
	 *   settings_tab:string,
	 *   kill_switch:bool,
	 *   kill_switch_exceptions:int,
	 *   logging_active:bool,
	 *   audit_only:bool,
	 *   deny_rule_count:int,
	 *   has_ai_client_plugins:bool,
	 *   alerts_configured:bool
	 * }
	 */
	public static function build_snapshot( array $policy, array $installed_plugins, array $active_plugins, array $log = array(), ?string $mu_dir = null ): array {
		$kill_switch   = ! empty( $policy['kill_switch'] );
		$exceptions    = Policy::get_kill_switch_exceptions( $policy );
		$logging       = self::logging_active( $policy );
		$audit_only    = ! empty( $policy['audit_only'] );
		$alerts_on     = self::alerts_configured( $policy );
		$has_ai_client = self::has_ai_client_plugins( $installed_plugins, $active_plugins );
		$deny_count    = self::count_deny_rules( $policy );

		$issue = 'ok';
		$tab   = 'dashboard';

		$failing_alerts = Alert_Health::failing_channels( $policy );
		$over_budget    = Budget::over_budget_list( $policy );
		$gaps           = class_exists( Tamper::class ) ? Tamper::recent_gap_windows( $log ) : array();
		$hardened       = class_exists( Mu_Guard::class ) ? Mu_Guard::status( $mu_dir ) : array(
			'mode'         => '',
			'enabled'      => false,
			'stub_present' => false,
			'stub_current' => false,
			'stub_version' => null,
		);

		if ( ! empty( $failing_alerts ) ) {
			$issue = 'alert_delivery_failing';
			$tab   = 'dashboard';
		} elseif ( $kill_switch && empty( $exceptions ) ) {
			$issue = 'kill_switch_zero_exceptions';
			$tab   = 'rules';
		} elseif ( $alerts_on && ! $logging ) {
			$issue = 'alerts_without_logging';
			$tab   = 'activity';
		} elseif ( ! empty( $over_budget ) ) {
			$issue = 'over_budget';
			$tab   = 'rules';
		} elseif ( ! empty( $hardened['enabled'] ) && ( empty( $hardened['stub_present'] ) || empty( $hardened['stub_current'] ) ) ) {
			$issue = 'hardened_stub_drift';
			$tab   = 'dashboard';
		} elseif ( ! empty( $gaps ) ) {
			$issue = 'enforcement_interrupted';
			$tab   = 'activity';
		} elseif ( ! $has_ai_client ) {
			$issue = 'no_ai_client_plugins';
			$tab   = 'dashboard';
		} elseif ( $audit_only ) {
			$issue = 'observing';
			$tab   = 'activity';
		}

		if ( 'alert_delivery_failing' === $issue ) {
			$status = 'critical';
		} elseif (
			'kill_switch_zero_exceptions' === $issue
			|| 'alerts_without_logging' === $issue
			|| 'over_budget' === $issue
			|| 'enforcement_interrupted' === $issue
			|| 'hardened_stub_drift' === $issue
		) {
			$status = 'recommended';
		} else {
			$status = 'good';
		}

		return array(
			'status'                  => $status,
			'issue'                   => $issue,
			'settings_tab'            => $tab,
			'kill_switch'             => $kill_switch,
			'kill_switch_exceptions'  => count( $exceptions ),
			'logging_active'          => $logging,
			'audit_only'              => $audit_only,
			'deny_rule_count'         => $deny_count,
			'has_ai_client_plugins'   => $has_ai_client,
			'alerts_configured'       => $alerts_on,
			'failing_alert_channels'  => $failing_alerts,
			'over_budget_count'       => count( $over_budget ),
			'over_budget_plugins'     => $over_budget,
			'enforcement_gap_count'   => count( $gaps ),
			'enforcement_gaps'        => $gaps,
			'hardened_mode'           => (string) ( $hardened['mode'] ?? '' ),
			'hardened_stub_present'   => ! empty( $hardened['stub_present'] ),
			'hardened_stub_current'   => ! empty( $hardened['stub_current'] ),
			'hardened_stub_version'   => $hardened['stub_version'] ?? null,
		);
	}

	/**
	 * @param array<string,mixed> $snapshot
	 * @return array<string,mixed>
	 */
	public static function format_site_health_result( array $snapshot ): array {
		$status = (string) ( $snapshot['status'] ?? 'good' );
		$issue  = (string) ( $snapshot['issue'] ?? 'ok' );
		$tab    = sanitize_key( (string) ( $snapshot['settings_tab'] ?? 'dashboard' ) );
		if ( ! in_array( $tab, array( 'dashboard', 'rules', 'activity', 'insights' ), true ) ) {
			$tab = 'dashboard';
		}

		$url = self::settings_url( $tab );

		$label = __( 'HandL AI Connector Access Control is configured', 'handl-ai-connector-access-control' );
		if ( 'alert_delivery_failing' === $issue ) {
			$label = __( 'Alert sending is failing repeatedly', 'handl-ai-connector-access-control' );
		} elseif ( 'kill_switch_zero_exceptions' === $issue ) {
			$label = __( 'Emergency stop blocks all AI Client calls', 'handl-ai-connector-access-control' );
		} elseif ( 'alerts_without_logging' === $issue ) {
			$label = __( 'Alerts cannot run because activity logging and Learn mode are off', 'handl-ai-connector-access-control' );
		} elseif ( 'over_budget' === $issue ) {
			$label = __( 'One or more plugins reached their estimated budget', 'handl-ai-connector-access-control' );
		} elseif ( 'enforcement_interrupted' === $issue ) {
			$label = __( 'AI enforcement was interrupted in the last 30 days', 'handl-ai-connector-access-control' );
		} elseif ( 'hardened_stub_drift' === $issue ) {
			$label = __( 'Hardened mode needs attention', 'handl-ai-connector-access-control' );
		} elseif ( 'no_ai_client_plugins' === $issue ) {
			$label = __( 'No AI Client plugins are installed', 'handl-ai-connector-access-control' );
		} elseif ( 'observing' === $issue ) {
			$label = __( 'Learn mode is monitoring AI Client calls', 'handl-ai-connector-access-control' );
		}

		$description = self::build_description( $snapshot );

		$actions = '';
		if ( 'critical' === $status || 'recommended' === $status || 'no_ai_client_plugins' === $issue ) {
			$actions = sprintf(
				'<a href="%s">%s</a>',
				esc_url( $url ),
				esc_html( __( 'Open HandL AI Connector Access Control settings', 'handl-ai-connector-access-control' ) )
			);
		}

		return array(
			'label'       => $label,
			'status'      => $status,
			'badge'       => array(
				'label' => __( 'Security', 'handl-ai-connector-access-control' ),
				'color' => 'blue',
			),
			'description' => $description,
			'actions'     => $actions,
			'test'        => self::TEST_SLUG,
		);
	}

	/**
	 * Dedicated Site Health row for hardened mode / protection file (#226).
	 *
	 * @param array<string,mixed> $hardened Mu_Guard::status() shape.
	 * @return array<string,mixed>
	 */
	public static function format_hardened_site_health_result( array $hardened ): array {
		$snapshot = array(
			'hardened_mode'         => (string) ( $hardened['mode'] ?? '' ),
			'hardened_stub_present' => ! empty( $hardened['stub_present'] ),
			'hardened_stub_current' => ! empty( $hardened['stub_current'] ),
			'hardened_stub_version' => $hardened['stub_version'] ?? null,
		);

		$drift = ! empty( $hardened['enabled'] ) && ( empty( $hardened['stub_present'] ) || empty( $hardened['stub_current'] ) );
		$line  = self::hardened_description_line( $snapshot );
		$label = $drift
			? __( 'Hardened mode needs attention', 'handl-ai-connector-access-control' )
			: $line;

		$description = '<p>' . esc_html( $line ) . '</p>';
		if ( $drift ) {
			$mode_key = (string) ( $snapshot['hardened_mode'] ?? Mu_Guard::MODE_FAIL_CLOSED );
			if ( Mu_Guard::MODE_WATCH !== $mode_key ) {
				$mode_key = Mu_Guard::MODE_FAIL_CLOSED;
			}
			$description .= '<p>' . esc_html(
				sprintf(
					/* translators: %s: fail_closed or watch (CLI mode key) */
					__( 'Run `wp handl-aicac hardened enable --mode=%s` to restore it.', 'handl-ai-connector-access-control' ),
					$mode_key
				)
			) . '</p>';
		}

		$actions = '';
		if ( $drift ) {
			$actions = sprintf(
				'<a href="%s">%s</a>',
				esc_url( self::settings_url( 'dashboard' ) ),
				esc_html( __( 'Open HandL AI Connector Access Control settings', 'handl-ai-connector-access-control' ) )
			);
		}

		return array(
			'label'       => $label,
			'status'      => $drift ? 'recommended' : 'good',
			'badge'       => array(
				'label' => __( 'Security', 'handl-ai-connector-access-control' ),
				'color' => 'blue',
			),
			'description' => $description,
			'actions'     => $actions,
			'test'        => self::HARDENED_TEST_SLUG,
		);
	}

	/**
	 * @param array<string,mixed> $snapshot
	 */
	private static function build_description( array $snapshot ): string {
		$kill_on   = ! empty( $snapshot['kill_switch'] );
		$exc_count = (int) ( $snapshot['kill_switch_exceptions'] ?? 0 );
		$logging   = ! empty( $snapshot['logging_active'] );
		$audit     = ! empty( $snapshot['audit_only'] );
		$deny_n    = (int) ( $snapshot['deny_rule_count'] ?? 0 );
		$has_ai    = ! empty( $snapshot['has_ai_client_plugins'] );
		$issue     = (string) ( $snapshot['issue'] ?? 'ok' );

		$lines = array();

		if ( $kill_on ) {
			$lines[] = sprintf(
				/* translators: %d: number of Emergency stop exceptions configured */
				__( 'Emergency stop: on. Exceptions configured: %d.', 'handl-ai-connector-access-control' ),
				$exc_count
			);
		} else {
			$lines[] = __( 'Emergency stop: off.', 'handl-ai-connector-access-control' );
		}

		if ( $audit ) {
			$lines[] = __( 'Learn mode: on. Calls are logged, not blocked.', 'handl-ai-connector-access-control' );
		} elseif ( $logging ) {
			$lines[] = __( 'Activity logging: on.', 'handl-ai-connector-access-control' );
		} else {
			$lines[] = __( 'Activity logging: off.', 'handl-ai-connector-access-control' );
		}

		$lines[] = self::retention_description_line();
		$lines[] = self::hardened_description_line( $snapshot );

		$lines[] = sprintf(
			/* translators: %d: count of explicit deny rules */
			_n(
				'Deny rules: %d configured.',
				'Deny rules: %d configured.',
				$deny_n,
				'handl-ai-connector-access-control'
			),
			$deny_n
		);

		$installed = function_exists( 'get_plugins' ) ? get_plugins() : array();
		if ( ! is_array( $installed ) ) {
			$installed = array();
		}
		$lines[] = Review_Due::evidence_line( Review_Due::snapshot( Policy::get_policy(), $installed ) );

		if ( $has_ai ) {
			$lines[] = __( 'AI Client plugins: detected on this site.', 'handl-ai-connector-access-control' );
		} else {
			$lines[] = __( 'AI Client plugins: none detected. Your rules will apply after an AI Client plugin is installed.', 'handl-ai-connector-access-control' );
		}

		$went_ai = Went_AI::plugins_started_since( time() - Went_AI::WINDOW_SECONDS );
		if ( ! empty( $went_ai ) ) {
			$lines[] = sprintf(
				/* translators: %s: comma-separated plugin basenames */
				__( 'Started using AI in the last 30 days: %s.', 'handl-ai-connector-access-control' ),
				implode( ', ', $went_ai )
			);
		}

		if ( 'alert_delivery_failing' === $issue ) {
			$channels = isset( $snapshot['failing_alert_channels'] ) && is_array( $snapshot['failing_alert_channels'] )
				? $snapshot['failing_alert_channels']
				: array();
			$labels   = array();
			foreach ( $channels as $ch ) {
				$labels[] = Alert_Health::channel_label( (string) $ch );
			}
			$lines[] = sprintf(
				/* translators: %s: comma-separated channel labels */
				__( 'Alert sending failed at least 3 times in a row for: %s. Check your email or webhook settings, then send a test from the Dashboard.', 'handl-ai-connector-access-control' ),
				implode( ', ', $labels )
			);
		} elseif ( 'kill_switch_zero_exceptions' === $issue ) {
			$lines[] = __( 'Emergency stop blocks every AI Client call because no exceptions are selected. Add an exception or turn off Emergency stop if you want to allow any calls.', 'handl-ai-connector-access-control' );
		} elseif ( 'alerts_without_logging' === $issue ) {
			$lines[] = __( 'Email and webhook alerts require activity logging or Learn mode.', 'handl-ai-connector-access-control' );
		} elseif ( 'over_budget' === $issue ) {
			$count = (int) ( $snapshot['over_budget_count'] ?? 0 );
			$lines[] = sprintf(
				/* translators: %d: number of plugins over estimated budget */
				_n(
					'%d plugin reached its estimated budget for this calendar month. Open the Rules tab to review the budget and whether new calls are blocked or allowed in Observe-only mode.',
					'%d plugins reached their estimated budget for this calendar month. Open the Rules tab to review budgets and whether new calls are blocked or allowed in Observe-only mode.',
					$count,
					'handl-ai-connector-access-control'
				),
				$count
			);
		} elseif ( 'enforcement_interrupted' === $issue ) {
			$count = (int) ( $snapshot['enforcement_gap_count'] ?? 0 );
			$gaps  = isset( $snapshot['enforcement_gaps'] ) && is_array( $snapshot['enforcement_gaps'] )
				? $snapshot['enforcement_gaps']
				: array();
			$lines[] = sprintf(
				/* translators: %d: number of enforcement gap windows */
				_n(
					'AI enforcement was interrupted %d time in the last 30 days. Check Activity to see when enforcement stopped and resumed.',
					'AI enforcement was interrupted %d times in the last 30 days. Check Activity to see when enforcement stopped and resumed.',
					$count,
					'handl-ai-connector-access-control'
				),
				$count
			);
			if ( ! empty( $gaps[0] ) && is_array( $gaps[0] ) && class_exists( Tamper::class ) ) {
				$lines[] = Tamper::format_gap_window(
					(int) ( $gaps[0]['from'] ?? 0 ),
					(int) ( $gaps[0]['to'] ?? 0 )
				) . '.';
			}
		} elseif ( 'hardened_stub_drift' === $issue ) {
			$mode_key = (string) ( $snapshot['hardened_mode'] ?? Mu_Guard::MODE_FAIL_CLOSED );
			if ( Mu_Guard::MODE_WATCH !== $mode_key ) {
				$mode_key = Mu_Guard::MODE_FAIL_CLOSED;
			}
			$lines[] = sprintf(
				/* translators: %s: fail_closed or watch (CLI mode key) */
				__( 'Run `wp handl-aicac hardened enable --mode=%s` to restore it.', 'handl-ai-connector-access-control' ),
				$mode_key
			);
		}

		$html = '';
		foreach ( $lines as $line ) {
			$html .= '<p>' . esc_html( $line ) . '</p>';
		}

		return $html;
	}

	/**
	 * Hardened mode + protection-file version line for Site Health (Krusty copy).
	 *
	 * @param array<string,mixed> $snapshot
	 */
	private static function hardened_description_line( array $snapshot ): string {
		$mode = (string) ( $snapshot['hardened_mode'] ?? '' );
		if ( '' === $mode ) {
			return __( 'Hardened mode: Off.', 'handl-ai-connector-access-control' );
		}

		$present = ! empty( $snapshot['hardened_stub_present'] );
		$current = ! empty( $snapshot['hardened_stub_current'] );
		$version = isset( $snapshot['hardened_stub_version'] ) && is_string( $snapshot['hardened_stub_version'] )
			? $snapshot['hardened_stub_version']
			: '-';
		$phrase  = self::hardened_mode_phrase( $mode );

		if ( $present && $current ) {
			return sprintf(
				/* translators: 1: human mode phrase, 2: protection file version */
				__( 'Hardened mode: On — %1$s. Protection file version %2$s is current.', 'handl-ai-connector-access-control' ),
				$phrase,
				$version
			);
		}

		if ( $present ) {
			return sprintf(
				/* translators: 1: human mode phrase, 2: version on disk, 3: expected version */
				__( 'Hardened mode: On — %1$s. Protection file version %2$s is out of date (expected %3$s).', 'handl-ai-connector-access-control' ),
				$phrase,
				$version,
				Mu_Guard::STUB_VERSION
			);
		}

		return sprintf(
			/* translators: %s: human mode phrase */
			__( 'Hardened mode: On — %s. The protection file is missing.', 'handl-ai-connector-access-control' ),
			$phrase
		);
	}

	/**
	 * Site Health mode phrase (not the raw CLI key).
	 */
	private static function hardened_mode_phrase( string $mode ): string {
		if ( Mu_Guard::MODE_WATCH === $mode ) {
			return __( 'Allow, log, and alert on AI Client calls while this plugin is inactive', 'handl-ai-connector-access-control' );
		}
		return __( 'Block AI Client calls while this plugin is inactive', 'handl-ai-connector-access-control' );
	}

	/**
	 * Retention period + last automatic prune for Site Health.
	 */
	private static function retention_description_line(): string {
		$policy = Policy::get_policy();
		$days   = Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null );
		$period = Log_Retention::period_label( $days );
		$meta   = Log_Retention::meta();
		if ( $meta['last_prune_ts'] > 0 ) {
			$when = function_exists( 'wp_date' )
				? wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $meta['last_prune_ts'] )
				: gmdate( 'Y-m-d H:i', (int) $meta['last_prune_ts'] );
			return sprintf(
				/* translators: 1: retention period label, 2: last prune datetime */
				__( 'Activity keep period: %1$s. Last automatic cleanup: %2$s.', 'handl-ai-connector-access-control' ),
				$period,
				$when
			);
		}

		return sprintf(
			/* translators: %s: retention period label */
			__( 'Activity keep period: %s. Automatic cleanup has not run yet.', 'handl-ai-connector-access-control' ),
			$period
		);
	}

	public static function logging_active( array $policy ): bool {
		return ! empty( $policy['log_enabled'] ) || ! empty( $policy['audit_only'] );
	}

	public static function alerts_configured( array $policy ): bool {
		if ( ! empty( $policy['alert_on_deny'] ) ) {
			return true;
		}

		if ( ! empty( $policy['alert_webhook_url'] ) ) {
			return true;
		}

		if ( ! empty( $policy['weekly_report_enabled'] ) ) {
			return true;
		}

		if ( ! empty( $policy['governance_digest_enabled'] ) ) {
			return true;
		}

		if ( ! empty( $policy['alert_on_shadow'] ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Count explicit deny rules (plugin-level + capability-family), not default-only.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function count_deny_rules( array $policy ): int {
		$count = 0;

		$plugins = is_array( $policy['plugins'] ?? null ) ? (array) $policy['plugins'] : array();
		foreach ( $plugins as $rule ) {
			if ( 'deny' === $rule ) {
				++$count;
			}
		}

		$operations = is_array( $policy['operations'] ?? null ) ? (array) $policy['operations'] : array();
		foreach ( $operations as $plugin_ops ) {
			if ( ! is_array( $plugin_ops ) ) {
				continue;
			}
			foreach ( $plugin_ops as $rule ) {
				if ( 'deny' === $rule ) {
					++$count;
				}
			}
		}

		if ( ( $policy['default'] ?? 'allow' ) === 'deny' ) {
			++$count;
		}

		return $count;
	}

	/**
	 * Whether the WordPress AI Client stack appears installed and active.
	 *
	 * @param array<string,array<string,mixed>> $installed_plugins
	 * @param array<string,bool>                $active_plugins
	 */
	public static function has_ai_client_plugins( array $installed_plugins, array $active_plugins ): bool {
		if ( isset( $active_plugins['ai/ai.php'] ) ) {
			return true;
		}

		foreach ( $installed_plugins as $basename => $data ) {
			if ( ! isset( $active_plugins[ $basename ] ) ) {
				continue;
			}

			$requires = $data['RequiresPlugins'] ?? '';
			if ( ! is_string( $requires ) || '' === $requires ) {
				continue;
			}

			foreach ( array_map( 'trim', explode( ',', $requires ) ) as $slug ) {
				if ( 'ai' === strtolower( $slug ) ) {
					return true;
				}
			}
		}

		return false;
	}

	public static function settings_url( string $tab = 'dashboard' ): string {
		$tab = sanitize_key( $tab );
		if ( ! in_array( $tab, array( 'dashboard', 'rules', 'activity', 'insights' ), true ) ) {
			$tab = 'dashboard';
		}

		return Admin::screen_url( $tab );
	}
}
