<?php
/**
 * AICAC-SELFTEST (#218): prove the live gate, not the simulator.
 *
 * Installs a temporary rule, fires wp_ai_client_prevent_prompt for a reserved
 * internal caller (deny then allow), then restores the stored policy.
 * Synthetic Activity rows are marked and excluded from totals.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Selftest {
	/** Reserved caller — never a real installed plugin. */
	public const PLUGIN_BASENAME = 'handl-aicac-selftest/selftest.php';

	public const CHANNEL = 'selftest';

	public const SITE_HEALTH_SLUG = 'handl_aicac_selftest';

	/**
	 * @param array<string,mixed> $row
	 */
	public static function is_synthetic_row( array $row ): bool {
		if ( ! empty( $row['selftest'] ) ) {
			return true;
		}
		if ( isset( $row['channel'] ) && self::CHANNEL === (string) $row['channel'] ) {
			return true;
		}
		$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
		return self::PLUGIN_BASENAME === $plugin;
	}

	public static function is_synthetic_plugin( ?string $plugin ): bool {
		return is_string( $plugin ) && self::PLUGIN_BASENAME === $plugin;
	}

	/**
	 * Run the end-to-end enforcement probe.
	 *
	 * @return array{
	 *   ok:bool,
	 *   issue:string,
	 *   message:string,
	 *   settings_tab:string,
	 *   policy_identical:bool,
	 *   links:list<array{id:string,pass:bool,label:string}>
	 * }
	 */
	public static function run(): array {
		$original = get_option( Plugin::OPTION_KEY, null );
		$log_before = get_option( Plugin::LOG_OPTION_KEY, array() );
		$log_before = is_array( $log_before ) ? $log_before : array();

		$links = array(
			'gate'            => array(
				'id'    => 'gate',
				'pass'  => false,
				'label' => __( 'AI blocking ran', 'handl-ai-connector-access-control' ),
			),
			'rule'            => array(
				'id'    => 'rule',
				'pass'  => false,
				'label' => __( 'Test rule was applied', 'handl-ai-connector-access-control' ),
			),
			'deny'            => array(
				'id'    => 'deny',
				'pass'  => false,
				'label' => __( 'Test call that should be blocked was blocked', 'handl-ai-connector-access-control' ),
			),
			'allow'           => array(
				'id'    => 'allow',
				'pass'  => false,
				'label' => __( 'Test call that should be allowed was allowed', 'handl-ai-connector-access-control' ),
			),
			'log'             => array(
				'id'    => 'log',
				'pass'  => false,
				'label' => __( 'Activity row written (test rows are not counted in totals)', 'handl-ai-connector-access-control' ),
			),
			'alerts'          => array(
				'id'    => 'alerts',
				'pass'  => false,
				'label' => __( 'Alerts are available (no email was sent)', 'handl-ai-connector-access-control' ),
			),
			'policy_restored' => array(
				'id'    => 'policy_restored',
				'pass'  => false,
				'label' => __( 'Stored rules unchanged after the check', 'handl-ai-connector-access-control' ),
			),
		);

		$issue = '';
		$tab   = 'rules';
		$msg   = '';

		try {
			$pre = self::preflight();
			if ( '' !== $pre['issue'] ) {
				$issue = $pre['issue'];
				$tab   = $pre['settings_tab'];
				$msg   = $pre['message'];
				return self::finish( $original, $links, $issue, $msg, $tab, false );
			}

			if ( ! self::gate_is_registered() ) {
				$issue = 'gate_unregistered';
				$tab   = 'dashboard';
				$msg   = __( 'AI blocking is unavailable. Check that the plugin is active, then run the test again.', 'handl-ai-connector-access-control' );
				return self::finish( $original, $links, $issue, $msg, $tab, false );
			}
			$links['gate']['pass'] = true;

			Attribution::force_plugin( self::PLUGIN_BASENAME );

			self::write_probe_policy( 'deny' );
			$denied = self::fire_loopback();
			$links['gate']['pass'] = true;
			if ( true !== $denied ) {
				$issue = 'deny_failed';
				$tab   = 'rules';
				$msg   = __( 'A test call that should have been blocked was allowed.', 'handl-ai-connector-access-control' );
				return self::finish( $original, $links, $issue, $msg, $tab, false );
			}
			$links['deny']['pass'] = true;
			$links['rule']['pass'] = true;

			self::write_probe_policy( 'allow' );
			$allowed = self::fire_loopback();
			if ( false !== $allowed ) {
				$issue = 'allow_failed';
				$tab   = 'rules';
				$msg   = __( 'A test call that should have been allowed was blocked.', 'handl-ai-connector-access-control' );
				return self::finish( $original, $links, $issue, $msg, $tab, false );
			}
			$links['allow']['pass'] = true;

			$log_after = get_option( Plugin::LOG_OPTION_KEY, array() );
			$log_after = is_array( $log_after ) ? $log_after : array();
			if ( self::synthetic_rows_written( $log_before, $log_after ) ) {
				$links['log']['pass'] = true;
			} else {
				$issue = 'log_missing';
				$tab   = 'activity';
				$msg   = __( 'The test did not write an Activity row.', 'handl-ai-connector-access-control' );
				return self::finish( $original, $links, $issue, $msg, $tab, false );
			}

			$links['alerts']['pass'] = self::alert_path_reachable();
			if ( ! $links['alerts']['pass'] ) {
				$issue = 'alerts_unreachable';
				$tab   = 'dashboard';
				$msg   = __( 'Alerts are unavailable. Check that the plugin is active, then run the test again.', 'handl-ai-connector-access-control' );
				return self::finish( $original, $links, $issue, $msg, $tab, false );
			}
		} catch ( \Throwable $e ) {
			$issue = 'error';
			$tab   = 'dashboard';
			$msg   = __( 'The enforcement check stopped unexpectedly.', 'handl-ai-connector-access-control' );
		}

		return self::finish( $original, $links, $issue, $msg, $tab, '' === $issue );
	}

	/**
	 * @param array<string,mixed> $report
	 * @return array<string,mixed>
	 */
	public static function format_site_health_result( array $report ): array {
		$ok = ! empty( $report['ok'] );
		$tab = sanitize_key( (string) ( $report['settings_tab'] ?? 'dashboard' ) );
		if ( ! in_array( $tab, array( 'dashboard', 'rules', 'activity', 'insights' ), true ) ) {
			$tab = 'dashboard';
		}

		$label = $ok
			? __( 'AI blocking is working', 'handl-ai-connector-access-control' )
			: __( 'AI blocking did not work', 'handl-ai-connector-access-control' );

		$items = array();
		$link_rows = isset( $report['links'] ) && is_array( $report['links'] ) ? $report['links'] : array();
		foreach ( $link_rows as $link ) {
			if ( ! is_array( $link ) ) {
				continue;
			}
			$mark  = ! empty( $link['pass'] ) ? '✓' : '✗';
			$items[] = $mark . ' ' . (string) ( $link['label'] ?? '' );
		}
		$body = '<p>' . esc_html( implode( ' ', $items ) ) . '</p>';
		if ( ! $ok && ! empty( $report['message'] ) ) {
			$body .= '<p>' . esc_html( (string) $report['message'] ) . '</p>';
		}

		$actions = '';
		if ( ! $ok ) {
			$actions = sprintf(
				'<a href="%s">%s</a>',
				esc_url( admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=' . $tab ) ),
				esc_html( __( 'Open HandL AI Connector Access Control settings', 'handl-ai-connector-access-control' ) )
			);
		}

		return array(
			'label'       => $label,
			'status'      => $ok ? 'good' : 'critical',
			'badge'       => array(
				'label' => __( 'Security', 'handl-ai-connector-access-control' ),
				'color' => $ok ? 'blue' : 'red',
			),
			'description' => $body,
			'actions'     => $actions,
			'test'        => self::SITE_HEALTH_SLUG,
		);
	}

	/**
	 * @return array{issue:string,settings_tab:string,message:string}
	 */
	private static function preflight(): array {
		$empty = array(
			'issue'         => '',
			'settings_tab'  => 'rules',
			'message'       => '',
		);
		$policy = Policy::get_policy();

		if ( ! empty( $policy['audit_only'] ) ) {
			return array(
				'issue'        => 'learn_mode',
				'settings_tab' => 'activity',
				'message'      => __( 'Learn mode is on. It records calls but does not block them. Turn it off on the Activity tab.', 'handl-ai-connector-access-control' ),
			);
		}
		if ( ! empty( $policy['kill_switch'] ) ) {
			return array(
				'issue'        => 'kill_switch',
				'settings_tab' => 'rules',
				'message'      => __( 'Emergency stop is on. Every AI Client call is blocked. Turn it off on the Rules tab.', 'handl-ai-connector-access-control' ),
			);
		}
		if ( class_exists( Break_Glass::class ) && Break_Glass::is_active() ) {
			return array(
				'issue'        => 'break_glass',
				'settings_tab' => 'dashboard',
				'message'      => __( 'Break-glass mode is on. Cancel it before checking AI blocking.', 'handl-ai-connector-access-control' ),
			);
		}
		$qh = Quiet_Hours::evaluate_gate( $policy );
		if ( is_array( $qh ) && ! empty( $qh['prevent'] ) ) {
			return array(
				'issue'        => 'quiet_hours',
				'settings_tab' => 'rules',
				'message'      => __( 'Quiet hours are blocking AI Client calls. Check the Rules tab.', 'handl-ai-connector-access-control' ),
			);
		}
		if ( Policy::role_gate_should_prevent( $policy ) ) {
			return array(
				'issue'        => 'role_gate',
				'settings_tab' => 'rules',
				'message'      => __( 'A user-role rule is blocking AI. Check the Rules tab.', 'handl-ai-connector-access-control' ),
			);
		}

		return $empty;
	}

	private static function gate_is_registered(): bool {
		if ( array_key_exists( 'handl_aicac_test_gate_registered', $GLOBALS ) ) {
			return (bool) $GLOBALS['handl_aicac_test_gate_registered'];
		}
		if ( function_exists( 'has_filter' ) ) {
			return false !== has_filter( 'wp_ai_client_prevent_prompt' );
		}
		return method_exists( Policy::instance(), 'maybe_prevent_prompt' );
	}

	/**
	 * @return bool True when the gate blocked the probe.
	 */
	private static function fire_loopback(): bool {
		$builder = (object) array( 'handl_aicac_selftest' => true );
		if ( function_exists( 'has_filter' ) && function_exists( 'apply_filters' ) && false !== has_filter( 'wp_ai_client_prevent_prompt' ) ) {
			return (bool) apply_filters( 'wp_ai_client_prevent_prompt', false, $builder );
		}
		return Policy::instance()->maybe_prevent_prompt( false, $builder );
	}

	/**
	 * @param 'allow'|'deny' $rule
	 */
	private static function write_probe_policy( string $rule ): void {
		$policy = Policy::get_policy();
		$plugins = is_array( $policy['plugins'] ?? null ) ? $policy['plugins'] : array();
		$plugins[ self::PLUGIN_BASENAME ] = ( 'deny' === $rule ) ? 'deny' : 'allow';
		$policy['plugins']     = $plugins;
		$policy['log_enabled'] = true;
		$policy['audit_only']  = false;
		update_option( Plugin::OPTION_KEY, $policy, false );
	}

	/**
	 * @param mixed $original Raw option value from before the probe (null = missing).
	 * @param array<string,array{id:string,pass:bool,label:string}> $links
	 * @return array{
	 *   ok:bool,
	 *   issue:string,
	 *   message:string,
	 *   settings_tab:string,
	 *   policy_identical:bool,
	 *   links:list<array{id:string,pass:bool,label:string}>
	 * }
	 */
	private static function finish( $original, array $links, string $issue, string $message, string $tab, bool $ok ): array {
		Attribution::force_plugin( null );
		self::restore_policy( $original );

		$after = get_option( Plugin::OPTION_KEY, null );
		$identical = self::policy_values_equal( $original, $after );
		$links['policy_restored']['pass'] = $identical;
		if ( $ok && ! $identical ) {
			$ok      = false;
			$issue   = 'policy_changed';
			$tab     = 'rules';
			$message = __( 'Stored rules changed during the check. They were restored.', 'handl-ai-connector-access-control' );
		}

		return array(
			'ok'                => $ok && $identical,
			'issue'             => $issue,
			'message'           => $message,
			'settings_tab'      => $tab,
			'policy_identical'  => $identical,
			'links'             => array_values( $links ),
		);
	}

	/**
	 * @param mixed $original
	 */
	private static function restore_policy( $original ): void {
		if ( null === $original || false === $original ) {
			delete_option( Plugin::OPTION_KEY );
			return;
		}
		update_option( Plugin::OPTION_KEY, $original, false );
	}

	/**
	 * @param mixed $a
	 * @param mixed $b
	 */
	private static function policy_values_equal( $a, $b ): bool {
		if ( false === $a ) {
			$a = null;
		}
		if ( false === $b ) {
			$b = null;
		}
		return $a === $b;
	}

	/**
	 * @param array<int,mixed> $before
	 * @param array<int,mixed> $after
	 */
	private static function synthetic_rows_written( array $before, array $after ): bool {
		$before_n = 0;
		foreach ( $before as $row ) {
			if ( is_array( $row ) && self::is_synthetic_row( $row ) ) {
				++$before_n;
			}
		}
		$after_n = 0;
		$saw_deny  = false;
		$saw_allow = false;
		foreach ( $after as $row ) {
			if ( ! is_array( $row ) || ! self::is_synthetic_row( $row ) ) {
				continue;
			}
			++$after_n;
			$decision = isset( $row['decision'] ) ? (string) $row['decision'] : '';
			if ( 'deny' === $decision ) {
				$saw_deny = true;
			}
			if ( 'allow' === $decision ) {
				$saw_allow = true;
			}
		}
		return $after_n > $before_n && $saw_deny && $saw_allow;
	}

	private static function alert_path_reachable(): bool {
		return class_exists( Alerts::class ) && method_exists( Alerts::class, 'maybe_notify_denial' );
	}
}
