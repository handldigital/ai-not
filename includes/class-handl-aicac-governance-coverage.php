<?php
/**
 * AICAC-SCORE (#189): advisory governance coverage score for the Dashboard.
 *
 * Pure local configuration completeness (0–100). Never claims security or
 * safety — wording is always "coverage". Weights are documented below.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Governance_Coverage {

	/**
	 * Point weights (sum = 100). Documented for maintainers and tests.
	 *
	 * - explicit_rules: share of AI-active plugins with an Allow/Deny rule (40)
	 * - alert_email: saved alert email address (15)
	 * - budgets: share of spend-recording plugins with a monthly estimated budget (20)
	 * - drift: provider/model change alerts not Off (15)
	 * - retention: Activity keep period set (finite days) (10)
	 */
	public const WEIGHT_EXPLICIT_RULES = 40;
	public const WEIGHT_ALERT_EMAIL    = 15;
	public const WEIGHT_BUDGETS        = 20;
	public const WEIGHT_DRIFT          = 15;
	public const WEIGHT_RETENTION      = 10;

	/**
	 * Compute the advisory coverage score from policy + retained Activity.
	 *
	 * @param array<string,mixed>               $policy
	 * @param array<int,mixed>                  $log
	 * @param array<string,array<string,mixed>> $plugins Unused today; reserved for labels.
	 * @return array{
	 *   score: int,
	 *   max: int,
	 *   checks: list<array{
	 *     id: string,
	 *     label: string,
	 *     done: bool,
	 *     points: float,
	 *     weight: int,
	 *     detail: string,
	 *     tab: string,
	 *     anchor: string
	 *   }>
	 * }
	 */
	public static function compute( array $policy, array $log, array $plugins = array() ): array {
		unset( $plugins );

		$ai_active = self::ai_active_plugins( $log );
		$with_spend = self::plugins_with_recorded_spend( $log, $policy );
		$rules     = is_array( $policy['plugins'] ?? null ) ? (array) $policy['plugins'] : array();
		$budgets   = Budget::sanitize_plugin_budgets( $policy['plugin_budgets'] ?? array() );

		$ruled = 0;
		foreach ( $ai_active as $basename ) {
			$rule = isset( $rules[ $basename ] ) ? (string) $rules[ $basename ] : '';
			if ( 'allow' === $rule || 'deny' === $rule ) {
				++$ruled;
			}
		}
		$active_n = count( $ai_active );
		if ( 0 === $active_n ) {
			$rules_ratio  = 1.0;
			$rules_done   = true;
			$rules_detail = __( 'No AI-active plugins in saved Activity yet. Set Allow or Deny when Activity appears.', 'handl-ai-connector-access-control' );
		} else {
			$rules_ratio  = $ruled / $active_n;
			$rules_done   = $ruled === $active_n;
			$rules_detail = sprintf(
				/* translators: 1: plugins with explicit rules, 2: AI-active plugin count */
				__( '%1$d of %2$d AI-active plugins have an Allow or Deny rule.', 'handl-ai-connector-access-control' ),
				$ruled,
				$active_n
			);
		}

		$email      = Alerts::sanitize_email( $policy['alert_email'] ?? '' );
		$email_done = '' !== $email;
		$email_detail = $email_done
			? __( 'Alert email is saved.', 'handl-ai-connector-access-control' )
			: __( 'Save an alert email on the Activity tab.', 'handl-ai-connector-access-control' );

		$budgeted = 0;
		foreach ( $with_spend as $basename ) {
			if ( isset( $budgets[ $basename ] ) && $budgets[ $basename ] > 0 ) {
				++$budgeted;
			}
		}
		$spend_n = count( $with_spend );
		if ( 0 === $spend_n ) {
			$budget_ratio  = 1.0;
			$budget_done   = true;
			$budget_detail = __( 'No estimated spend recorded yet. Set monthly budgets on the Rules tab when spend appears.', 'handl-ai-connector-access-control' );
		} else {
			$budget_ratio  = $budgeted / $spend_n;
			$budget_done   = $budgeted === $spend_n;
			$budget_detail = sprintf(
				/* translators: 1: plugins with budgets, 2: plugins with recorded spend */
				__( '%1$d of %2$d plugins with recorded estimated spend have a monthly budget.', 'handl-ai-connector-access-control' ),
				$budgeted,
				$spend_n
			);
		}

		$drift_mode = Drift::sanitize_mode( $policy['drift_alert_mode'] ?? Drift::MODE_PROVIDER );
		$drift_done = Drift::MODE_OFF !== $drift_mode;
		if ( Drift::MODE_MODEL === $drift_mode ) {
			$drift_detail = __( 'Provider or model change alerts are on.', 'handl-ai-connector-access-control' );
		} elseif ( Drift::MODE_PROVIDER === $drift_mode ) {
			$drift_detail = __( 'New-provider change alerts are on (default).', 'handl-ai-connector-access-control' );
		} else {
			$drift_detail = __( 'Turn on provider or model change alerts on the Activity tab.', 'handl-ai-connector-access-control' );
		}

		$retention_days = Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null );
		$retention_done = null !== $retention_days;
		$retention_detail = $retention_done
			? sprintf(
				/* translators: %d: keep period in days */
				__( 'Activity keep period is set to %d days.', 'handl-ai-connector-access-control' ),
				$retention_days
			)
			: __( 'Choose an Activity keep period on the Activity tab (not forever).', 'handl-ai-connector-access-control' );

		$checks = array(
			array(
				'id'     => 'explicit_rules',
				'label'  => __( 'Explicit rules for AI-active plugins', 'handl-ai-connector-access-control' ),
				'done'   => $rules_done,
				'points' => round( self::WEIGHT_EXPLICIT_RULES * $rules_ratio, 4 ),
				'weight' => self::WEIGHT_EXPLICIT_RULES,
				'detail' => $rules_detail,
				'tab'    => 'rules',
				'anchor' => '',
			),
			array(
				'id'     => 'alert_email',
				'label'  => __( 'Alert email configured', 'handl-ai-connector-access-control' ),
				'done'   => $email_done,
				'points' => $email_done ? (float) self::WEIGHT_ALERT_EMAIL : 0.0,
				'weight' => self::WEIGHT_ALERT_EMAIL,
				'detail' => $email_detail,
				'tab'    => 'activity',
				'anchor' => 'handl-aicac-alert-email',
			),
			array(
				'id'     => 'budgets',
				'label'  => __( 'Estimated budgets where spend is recorded', 'handl-ai-connector-access-control' ),
				'done'   => $budget_done,
				'points' => round( self::WEIGHT_BUDGETS * $budget_ratio, 4 ),
				'weight' => self::WEIGHT_BUDGETS,
				'detail' => $budget_detail,
				'tab'    => 'rules',
				'anchor' => '',
			),
			array(
				'id'     => 'drift',
				'label'  => __( 'Provider or model change alerts on', 'handl-ai-connector-access-control' ),
				'done'   => $drift_done,
				'points' => $drift_done ? (float) self::WEIGHT_DRIFT : 0.0,
				'weight' => self::WEIGHT_DRIFT,
				'detail' => $drift_detail,
				'tab'    => 'activity',
				'anchor' => 'handl-aicac-drift-alert-mode',
			),
			array(
				'id'     => 'retention',
				'label'  => __( 'Activity keep period configured', 'handl-ai-connector-access-control' ),
				'done'   => $retention_done,
				'points' => $retention_done ? (float) self::WEIGHT_RETENTION : 0.0,
				'weight' => self::WEIGHT_RETENTION,
				'detail' => $retention_detail,
				'tab'    => 'activity',
				'anchor' => 'handl-aicac-log-max-age-days',
			),
		);

		$earned = 0.0;
		foreach ( $checks as $check ) {
			$earned += (float) $check['points'];
		}

		return array(
			'score'  => (int) round( $earned ),
			'max'    => 100,
			'checks' => $checks,
		);
	}

	/**
	 * Plugins with at least one AI Client Activity row (not direct_http).
	 *
	 * @param array<int,mixed> $log
	 * @return list<string>
	 */
	public static function ai_active_plugins( array $log ): array {
		$seen = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'] ) {
				continue;
			}
			$plugin = isset( $row['plugin'] ) ? trim( (string) $row['plugin'] ) : '';
			$plugin = Plugin_Profile::sanitize_plugin( $plugin );
			if ( '' === $plugin ) {
				continue;
			}
			$seen[ $plugin ] = true;
		}
		$out = array_keys( $seen );
		sort( $out );

		return $out;
	}

	/**
	 * Plugins with positive estimated spend in the retained log.
	 *
	 * @param array<int,mixed>    $log
	 * @param array<string,mixed> $policy
	 * @return list<string>
	 */
	public static function plugins_with_recorded_spend( array $log, array $policy ): array {
		$totals = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'] ) {
				continue;
			}
			$plugin = isset( $row['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $row['plugin'] ) : '';
			if ( '' === $plugin ) {
				continue;
			}
			$in    = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
			$out_t = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
			$rates = Cost::rates_from_policy( $policy, isset( $row['provider'] ) ? (string) $row['provider'] : null );
			$usd   = Cost::estimate_usd( $in, $out_t, $rates );
			if ( null === $usd || $usd <= 0 ) {
				continue;
			}
			if ( ! isset( $totals[ $plugin ] ) ) {
				$totals[ $plugin ] = 0.0;
			}
			$totals[ $plugin ] += $usd;
		}

		$out = array();
		foreach ( $totals as $plugin => $usd ) {
			if ( $usd > 0 ) {
				$out[] = $plugin;
			}
		}
		sort( $out );

		return $out;
	}

	/**
	 * Admin URL for a coverage check fix target.
	 *
	 * @param array{tab?:string,anchor?:string} $check
	 */
	public static function fix_url( array $check ): string {
		$tab = isset( $check['tab'] ) ? sanitize_key( (string) $check['tab'] ) : 'dashboard';
		if ( ! in_array( $tab, array( 'dashboard', 'rules', 'activity', 'insights' ), true ) ) {
			$tab = 'dashboard';
		}
		$url = function_exists( 'admin_url' )
			? (string) admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=' . $tab )
			: '';
		$anchor = isset( $check['anchor'] ) ? (string) $check['anchor'] : '';
		if ( '' !== $url && '' !== $anchor && preg_match( '/^[a-z0-9\-]+$/', $anchor ) ) {
			$url .= '#' . $anchor;
		}

		return $url;
	}
}
