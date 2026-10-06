<?php
/**
 * AICAC-WHY (#287): per-event decision explainer on Activity rows.
 *
 * Records a compact decision_source at log time and renders a native
 * <details> expander. No assets. Backfill-free: missing keys show a
 * legacy sentence.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Activity-only decision tracing.
 */
final class Why {

	public const LEGACY_COPY = 'No explanation is available for this older entry.';

	public const SUMMARY_COPY = 'Why?';

	public const LINK_COPY = 'Open this setting';

	/**
	 * Activity filter bucket for rows with no decision_source stamp.
	 */
	public const FILTER_NONE = 'none';

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
	}

	/**
	 * Stamp decision_source onto an allow/deny event at the log funnel.
	 *
	 * Existing values are left alone so a writer can set the field itself.
	 *
	 * @param array<string,mixed>      $event
	 * @param array<string,mixed>|null $policy
	 */
	public static function stamp( array &$event, $policy = null ): void {
		if ( isset( $event['decision_source'] ) && is_string( $event['decision_source'] ) && '' !== $event['decision_source'] ) {
			return;
		}

		$decision = isset( $event['decision'] ) ? (string) $event['decision'] : '';
		if ( 'allow' !== $decision && 'deny' !== $decision ) {
			return;
		}

		$policy = is_array( $policy ) ? $policy : Policy::get_policy();
		$now    = isset( $event['ts'] ) ? (int) $event['ts'] : null;
		$freeze = class_exists( Freeze::class, false ) && Freeze::is_active( $now );
		$source = self::source_for_event( $event, $policy, $freeze );
		if ( '' !== $source ) {
			$event['decision_source'] = $source;
		}
	}

	/**
	 * Compact source matching the mechanism that actually fired.
	 *
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 */
	public static function source_for_event( array $event, array $policy, bool $freeze_active = false ): string {
		$decision = isset( $event['decision'] ) ? (string) $event['decision'] : '';
		if ( 'allow' !== $decision && 'deny' !== $decision ) {
			return '';
		}

		$reason = isset( $event['denial_reason'] ) ? (string) $event['denial_reason'] : '';
		$plugin = isset( $event['plugin'] ) ? (string) $event['plugin'] : '';
		$rule   = self::plugin_rule( $policy, $plugin );
		$now    = isset( $event['ts'] ) ? (int) $event['ts'] : null;

		if ( $freeze_active && 'deny' === $decision ) {
			return 'freeze';
		}

		if ( 'deny' === $decision ) {
			return self::source_for_deny( $event, $policy, $reason, $plugin, $rule, $now );
		}

		return self::source_for_allow( $event, $policy, $reason, $plugin, $rule, $now );
	}

	/**
	 * Plain-language sentence for a stamped (or legacy) row.
	 *
	 * @param array<string,mixed> $event
	 */
	public static function explain_line( array $event ): string {
		if ( ! array_key_exists( 'decision_source', $event ) ) {
			return __( 'No explanation is available for this older entry.', 'handl-ai-connector-access-control' );
		}

		$source = is_string( $event['decision_source'] ) ? (string) $event['decision_source'] : '';
		$limit  = isset( $event['rate_cap_limit'] ) ? (int) $event['rate_cap_limit'] : 0;
		$window = isset( $event['quiet_hours_window'] ) ? (string) $event['quiet_hours_window'] : '';

		switch ( $source ) {
			case 'freeze':
				return __( 'Denied because Panic freeze was on.', 'handl-ai-connector-access-control' );
			case 'kill_switch':
				return __( 'Denied because Emergency stop was on.', 'handl-ai-connector-access-control' );
			case 'quiet_hours':
				if ( '' !== $window ) {
					return sprintf(
						/* translators: %s: quiet hours window name */
						__( 'Denied because scheduled quiet hours (%s) were in effect.', 'handl-ai-connector-access-control' ),
						$window
					);
				}
				return __( 'Denied because scheduled quiet hours were in effect.', 'handl-ai-connector-access-control' );
			case 'role':
				return __( 'Denied because this user role is not allowed to use AI.', 'handl-ai-connector-access-control' );
			case 'rule:explicit-deny':
				return __( 'Denied because this plugin has a Deny rule.', 'handl-ai-connector-access-control' );
			case 'rule:explicit-allow':
				return __( 'Allowed because this plugin has an Allow rule.', 'handl-ai-connector-access-control' );
			case 'newcomer_hold':
				return __( 'Denied because this plugin needed approval for its first AI call.', 'handl-ai-connector-access-control' );
			case 'budget:hard':
				return __( 'Denied because the estimated budget was reached.', 'handl-ai-connector-access-control' );
			case 'budget:observe':
				return __( 'Allowed. The estimated budget was reached (logging only).', 'handl-ai-connector-access-control' );
			case 'rate_cap:hourly':
				if ( $limit > 0 ) {
					return sprintf(
						/* translators: %s: hourly call cap */
						__( 'Denied because the hourly rate cap (%s calls) was exceeded.', 'handl-ai-connector-access-control' ),
						(string) $limit
					);
				}
				return __( 'Denied because the hourly rate cap was exceeded.', 'handl-ai-connector-access-control' );
			case 'rate_cap:daily':
				if ( $limit > 0 ) {
					return sprintf(
						/* translators: %s: daily call cap */
						__( 'Denied because the daily rate cap (%s calls) was exceeded.', 'handl-ai-connector-access-control' ),
						(string) $limit
					);
				}
				return __( 'Denied because the daily rate cap was exceeded.', 'handl-ai-connector-access-control' );
			case 'residency':
				return __( 'Denied because the provider region filter blocked this call.', 'handl-ai-connector-access-control' );
			case 'pii':
				return __( 'Denied because personal information was detected.', 'handl-ai-connector-access-control' );
			case 'capability_family':
				return __( 'Denied because this AI type is blocked for this plugin.', 'handl-ai-connector-access-control' );
			case 'unknown_operation':
				return __( 'Denied because unknown operations are blocked.', 'handl-ai-connector-access-control' );
			case 'tool_armed':
				return __( 'Denied because the prompt offered a blocked tool.', 'handl-ai-connector-access-control' );
			case 'break_glass':
				return __( 'Allowed because Break-glass was on.', 'handl-ai-connector-access-control' );
			case 'temp_allow':
				return __( 'Allowed because a temporary Allow was active.', 'handl-ai-connector-access-control' );
			case 'default:allow':
				return __( 'Allowed by the site default policy.', 'handl-ai-connector-access-control' );
			case 'default:deny':
				return __( 'Denied by the site default policy.', 'handl-ai-connector-access-control' );
		}

		if ( '' === $source ) {
			return __( 'No explanation is available for this older entry.', 'handl-ai-connector-access-control' );
		}

		return sprintf(
			/* translators: %s: internal decision source code */
			__( 'Decision source: %s', 'handl-ai-connector-access-control' ),
			$source
		);
	}

	/**
	 * Settings URL for the mechanism that fired, or empty when none.
	 *
	 * @param array<string,mixed> $event
	 */
	public static function settings_url( string $source, array $event ): string {
		$plugin = isset( $event['plugin'] ) ? (string) $event['plugin'] : '';

		switch ( $source ) {
			case 'freeze':
				return self::protections_url( '#handl-aicac-freeze-start-minutes' );
			case 'kill_switch':
				return self::protections_url( '#handl-aicac-kill-switch' );
			case 'quiet_hours':
				return self::protections_url( '#handl-aicac-qh-name-0' );
			case 'role':
				return self::protections_url( '#handl-aicac-role-gate-enabled' );
			case 'newcomer_hold':
				return self::protections_url( '#handl-aicac-newcomer-hold-mode' );
			case 'default:allow':
			case 'default:deny':
				return self::protections_url( '#handl-aicac-default' );
			case 'residency':
				return self::protections_url( '#handl-aicac-residency-region' );
			case 'break_glass':
				return self::protections_url();
			case 'rule:explicit-deny':
			case 'rule:explicit-allow':
			case 'temp_allow':
			case 'budget:hard':
			case 'budget:observe':
			case 'rate_cap:hourly':
			case 'rate_cap:daily':
			case 'capability_family':
			case 'unknown_operation':
			case 'tool_armed':
			case 'pii':
				return self::rules_url( $plugin );
		}

		return '';
	}

	/**
	 * Native details expander for an Activity decision cell. Empty for non-decisions.
	 *
	 * @param array<string,mixed> $event
	 */
	public static function render_expander( array $event ): string {
		$decision = isset( $event['decision'] ) ? (string) $event['decision'] : '';
		if ( 'allow' !== $decision && 'deny' !== $decision ) {
			return '';
		}

		$source = array_key_exists( 'decision_source', $event )
			? (string) $event['decision_source']
			: '';
		$line   = self::explain_line( $event );
		$url    = '' !== $source ? self::settings_url( $source, $event ) : '';

		$html  = ' <details class="handl-aicac-why" style="display:inline;font-size:11px;">';
		$html .= '<summary>' . esc_html__( 'Why?', 'handl-ai-connector-access-control' ) . '</summary>';
		$html .= '<p class="description" style="margin:4px 0 0;">' . esc_html( $line );
		if ( '' !== $url ) {
			$html .= ' <a href="' . esc_url( $url ) . '">' . esc_html__( 'Open this setting', 'handl-ai-connector-access-control' ) . '</a>';
		}
		$html .= '</p></details>';

		return $html;
	}

	/**
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 */
	private static function source_for_deny( array $event, array $policy, string $reason, string $plugin, string $rule, ?int $now ): string {
		if ( 'kill_switch' === $reason ) {
			return 'kill_switch';
		}
		if ( 'quiet_hours' === $reason ) {
			return 'quiet_hours';
		}
		if ( 'role' === $reason ) {
			return 'role';
		}
		if ( New_Plugin::REASON === $reason ) {
			return 'newcomer_hold';
		}
		if ( 'budget' === $reason ) {
			return 'budget:hard';
		}
		if ( Rate_Cap::REASON === $reason ) {
			$window = isset( $event['rate_cap_window'] ) ? (string) $event['rate_cap_window'] : Rate_Cap::WINDOW_HOUR;
			return Rate_Cap::WINDOW_DAY === $window ? 'rate_cap:daily' : 'rate_cap:hourly';
		}
		if ( 'residency' === $reason ) {
			return 'residency';
		}
		if ( 'pii' === $reason ) {
			return 'pii';
		}
		if ( 'capability_family' === $reason ) {
			return 'capability_family';
		}
		if ( 'unknown_operation' === $reason ) {
			return 'unknown_operation';
		}
		if ( 'tool_armed' === $reason || 'ability_armed' === $reason ) {
			return 'tool_armed';
		}

		if ( 'deny' === $rule ) {
			return 'rule:explicit-deny';
		}
		if ( 'allow' === $rule && self::temp_allow_expired( $policy, $plugin, $now ) ) {
			return self::default_source( $policy );
		}

		return self::default_source( $policy );
	}

	/**
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 */
	private static function source_for_allow( array $event, array $policy, string $reason, string $plugin, string $rule, ?int $now ): string {
		if ( 'break_glass' === $reason || ! empty( $event['break_glass'] ) ) {
			return 'break_glass';
		}
		if ( 'budget' === $reason || ! empty( $event['budget_over'] ) ) {
			$mode = isset( $event['budget_mode'] ) ? (string) $event['budget_mode'] : '';
			if ( Budget::MODE_OBSERVE === $mode || ! empty( $event['budget_over'] ) ) {
				return 'budget:observe';
			}
		}
		if ( 'allow' === $rule ) {
			if ( self::temp_allow_active( $policy, $plugin, $now ) ) {
				return 'temp_allow';
			}
			return 'rule:explicit-allow';
		}

		return 'default:allow';
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private static function plugin_rule( array $policy, string $plugin ): string {
		if ( '' === $plugin ) {
			return '';
		}
		$rules = is_array( $policy['plugins'] ?? null ) ? (array) $policy['plugins'] : array();
		if ( ! isset( $rules[ $plugin ] ) ) {
			return '';
		}
		$rule = (string) $rules[ $plugin ];
		return ( 'allow' === $rule || 'deny' === $rule ) ? $rule : '';
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private static function default_source( array $policy ): string {
		return ( ( $policy['default'] ?? 'allow' ) === 'deny' ) ? 'default:deny' : 'default:allow';
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private static function temp_allow_active( array $policy, string $plugin, ?int $now ): bool {
		if ( '' === $plugin || ! class_exists( Temp_Allow::class, false ) ) {
			return false;
		}
		$ts = Temp_Allow::expires_at( $policy, $plugin );
		if ( null === $ts ) {
			return false;
		}
		return ! Temp_Allow::is_expired( $policy, $plugin, $now );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private static function temp_allow_expired( array $policy, string $plugin, ?int $now ): bool {
		if ( '' === $plugin || ! class_exists( Temp_Allow::class, false ) ) {
			return false;
		}
		return Temp_Allow::is_expired( $policy, $plugin, $now );
	}

	private static function protections_url( string $hash = '' ): string {
		if ( ! class_exists( Admin::class, false ) ) {
			return $hash;
		}
		return Admin::screen_url( 'protections' ) . $hash;
	}

	private static function rules_url( string $plugin ): string {
		if ( class_exists( Plugin_Profile::class, false ) ) {
			return Plugin_Profile::rules_url( $plugin );
		}
		if ( class_exists( Admin::class, false ) ) {
			return Admin::screen_url( 'rules' );
		}
		return '';
	}

	/**
	 * Dropdown choices for the Activity decision-source filter.
	 *
	 * @return array<string,string> bucket => label
	 */
	public static function filter_choices(): array {
		return array(
			'rule'           => __( 'Explicit rule', 'handl-ai-connector-access-control' ),
			'role'           => __( 'Role', 'handl-ai-connector-access-control' ),
			'rate_cap'       => __( 'Rate cap', 'handl-ai-connector-access-control' ),
			'budget'         => __( 'Budget', 'handl-ai-connector-access-control' ),
			'freeze'         => __( 'Freeze', 'handl-ai-connector-access-control' ),
			'kill_switch'    => __( 'Emergency stop', 'handl-ai-connector-access-control' ),
			'newcomer_hold'  => __( 'Newcomer hold', 'handl-ai-connector-access-control' ),
			'quiet_hours'    => __( 'Quiet hours', 'handl-ai-connector-access-control' ),
			'temp_allow'     => __( 'Temporary Allow', 'handl-ai-connector-access-control' ),
			'default'        => __( 'Site default', 'handl-ai-connector-access-control' ),
			self::FILTER_NONE => __( 'No explanation recorded', 'handl-ai-connector-access-control' ),
		);
	}

	public static function sanitize_filter( string $raw ): string {
		$choices = self::filter_choices();
		return isset( $choices[ $raw ] ) ? $raw : '';
	}

	/**
	 * Compact bucket for a stamped source, or FILTER_NONE for legacy rows.
	 *
	 * @param array<string,mixed> $row
	 */
	public static function bucket_for_row( array $row ): string {
		if ( ! array_key_exists( 'decision_source', $row ) ) {
			return self::FILTER_NONE;
		}
		$source = is_string( $row['decision_source'] ) ? (string) $row['decision_source'] : '';
		if ( '' === $source ) {
			return self::FILTER_NONE;
		}

		return self::bucket_for_source( $source );
	}

	public static function bucket_for_source( string $source ): string {
		if ( '' === $source ) {
			return self::FILTER_NONE;
		}
		if ( 0 === strpos( $source, 'rule:' ) ) {
			return 'rule';
		}
		if ( 0 === strpos( $source, 'rate_cap:' ) ) {
			return 'rate_cap';
		}
		if ( 0 === strpos( $source, 'budget:' ) ) {
			return 'budget';
		}
		if ( 0 === strpos( $source, 'default:' ) ) {
			return 'default';
		}

		return $source;
	}

	/**
	 * @param array<string,mixed> $row
	 */
	public static function row_matches_source( array $row, string $filter ): bool {
		if ( '' === $filter ) {
			return true;
		}

		return self::bucket_for_row( $row ) === $filter;
	}
}
