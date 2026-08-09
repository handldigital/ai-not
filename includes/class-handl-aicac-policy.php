<?php
/**
 * Enforcement + logging.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Policy {
	private static ?Policy $instance = null;

	/**
	 * Log keys awaiting token usage from wp_ai_client_after_generate_result (LIFO).
	 *
	 * @var list<string>
	 */
	private static array $pending_token_log_keys = array();

	public static function instance(): Policy {
		if ( null === self::$instance ) {
			self::$instance = new Policy();
		}
		return self::$instance;
	}

	public function init(): void {
		add_filter( 'wp_ai_client_prevent_prompt', array( $this, 'maybe_prevent_prompt' ), 1, 2 );
		add_action( 'wp_ai_client_after_generate_result', array( $this, 'maybe_log_token_usage' ), 10, 1 );
	}

	/**
	 * @param bool  $prevent
	 * @param mixed $builder WP_AI_Client_Prompt_Builder clone (read-only)
	 */
	public function maybe_prevent_prompt( bool $prevent, $builder ): bool {
		if ( $prevent ) {
			return true;
		}

		$policy = self::get_policy();

		$attrib = Attribution::resolve_from_backtrace();
		$plugin = is_string( $attrib['plugin'] ?? null ) ? (string) $attrib['plugin'] : null;

		// Snapshot first so operation/family/armed tools are known before the decision.
		// Snapshot resolves capability_family including inference for generate_result / is_supported.
		$snapshot  = Prompt_Snapshot::from_builder( $builder );
		$operation = isset( $snapshot['operation'] ) ? (string) $snapshot['operation'] : '';
		$family    = isset( $snapshot['capability_family'] ) && is_string( $snapshot['capability_family'] )
			? (string) $snapshot['capability_family']
			: Operations::family_from_operation( $operation );

		// Prefer armed_tools; accept legacy armed_abilities key from older snapshots.
		$armed_raw = $snapshot['armed_tools'] ?? $snapshot['armed_abilities'] ?? array();
		$armed     = is_array( $armed_raw )
			? array_values( array_map( 'strval', $armed_raw ) )
			: array();

		$would_eval = self::evaluate( $policy, $plugin, $operation, $armed, $family );
		$eval       = ! empty( $policy['audit_only'] )
			? array( 'prevent' => false, 'reason' => '', 'matched_tools' => array() )
			: $would_eval;

		$prevent       = (bool) $eval['prevent'];
		$would_prevent = (bool) $would_eval['prevent'];

		$event = array_merge(
			array(
				'ts'                => time(),
				'plugin'            => $plugin,
				'file'              => $attrib['file'] ?? null,
				'caller'            => $attrib['method'] ?? null,
				'decision'          => $prevent ? 'deny' : 'allow',
				'would_decision'    => $would_prevent ? 'deny' : 'allow',
				'capability_family' => $family,
				'denial_reason'     => $would_eval['reason'] ?? '',
				'matched_tools'     => $would_eval['matched_tools'] ?? array(),
				// Legacy alias for pre-rename log readers.
				'matched_abilities' => $would_eval['matched_tools'] ?? array(),
				'user_id'           => get_current_user_id(),
				'uri'               => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) ) : null,
			),
			$snapshot
		);

		if ( ! empty( $policy['audit_only'] ) ) {
			$event['audit_only'] = true;
		}

		if ( ! $prevent && self::is_generating_operation( $operation ) ) {
			$event['log_key'] = self::generate_log_key();
			self::$pending_token_log_keys[] = $event['log_key'];
		}

		// F4 experimental: per-plugin force on allowed *generating* prompts only,
		// and only outside learn mode. Support checks and generations share the
		// allow/deny *decision* (F1 family rule), but must not share the *arming*:
		// the rule answers "may it," the arm asserts "it will happen and be
		// verified," and only generations fire BeforeGenerateResultEvent to consume
		// that expectation. Arming a support check leaves a stale pending
		// expectation that can fail-close the next generation (including an
		// unpinned plugin) — fail-closed against the wrong party.
		// Learn mode (audit_only) must stay observation-only: force mutates the
		// route and fail-closes on mismatch, which would block calls — the same
		// promise-vs-mechanism gap as an unqualified "without blocking" claim.
		// Mutates the shallow-cloned builder's shared inner; final route verified later.
		// Pin follows detected caller (nearest plugin frame) — not a spend guarantee.
		//
		// Sibling of the arming gate (not inside it): empty $operation makes
		// is_generating_operation() false, so the skip whitelist below is unreachable.
		// Statement is only what the mechanism knows — force was never evaluated —
		// not "a generation missed its pin" (the call might have been a support check).
		// Observability only; stays out of the unforced count. Suppressed unless at
		// least one pin exists (resolve_route pins-exist precedent).
		// F5 cleanup #2: has_any_force_rules() already returns bool — no ! empty() wrapper.
		if ( ! $prevent && '' === $operation && Model_Force::has_any_force_rules( $policy ) ) {
			$event['model_force_skipped'] = 'operation_unresolved';
		}

		if ( ! $prevent && empty( $policy['audit_only'] ) && self::is_generating_operation( $operation ) ) {
			$force = Model_Force::maybe_apply( $builder, $policy, $plugin );
			if ( ! empty( $force['applied'] ) ) {
				$event['model_forced']    = true;
				$event['forced_provider'] = $force['provider'] ?? '';
				$event['forced_model']    = $force['model'] ?? '';
				$event['forced_source']   = $force['source'] ?? 'plugin';
			} else {
				$skip = (string) ( $force['reason'] ?? '' );
				// Log countable gaps: unattributed while pins exist, plus hard failures.
				if ( in_array( $skip, array( 'unattributed', 'clone_incompatible', 'apply_threw', 'no_preference_api', 'incomplete' ), true ) ) {
					$event['model_force_skipped'] = $skip;
					if ( 'unattributed' === $skip ) {
						$event['model_force_unforced'] = true;
					}
				}
			}
		}

		// F5 Δ3: learn mode observes that a pin *matched* — not that the call would
		// have succeeded (guardrail-2 may still fail-close). Action gates stay off.
		// Reachability: generating ops only; attributed plugin pin (source=plugin).
		// Support checks silent. Design law: action gates ≠ observation gates.
		if ( ! $prevent && ! empty( $policy['audit_only'] ) && self::is_generating_operation( $operation ) ) {
			$plugin_bn = is_string( $plugin ) ? $plugin : '';
			if ( '' !== $plugin_bn ) {
				$resolved = Model_Force::resolve_route( $policy, $plugin_bn );
				if ( ! empty( $resolved['apply'] ) && 'plugin' === (string) ( $resolved['source'] ?? '' ) ) {
					$event['pin_matched']  = true;
					$event['pin_provider'] = (string) ( $resolved['provider'] ?? '' );
					$event['pin_model']    = (string) ( $resolved['model'] ?? '' );
				}
			}
		}

		$this->log_event( $event );

		// Observability only: opt-in denial email / digest. Never changes $prevent.
		if ( $prevent && empty( $policy['audit_only'] ) ) {
			Alerts::maybe_notify_denial( $event, $policy );
		}

		return $prevent;
	}

	/**
	 * Whether to block the prompt (enforcement).
	 *
	 * @param array<string,mixed> $policy
	 * @param string|null         $operation AI Client method name when known.
	 * @param list<string>|null   $armed_tools Tool/ability names armed on the prompt.
	 * @param string|null         $capability_family Pre-resolved family from snapshot (preferred).
	 */
	public static function should_prevent( array $policy, ?string $plugin_basename, ?string $operation = null, ?array $armed_tools = null, ?string $capability_family = null ): bool {
		if ( ! empty( $policy['audit_only'] ) ) {
			return false;
		}

		return self::would_prevent( $policy, $plugin_basename, $operation, $armed_tools, $capability_family );
	}

	/**
	 * What would happen if enforcement were active (ignores audit-only).
	 *
	 * @param array<string,mixed> $policy
	 * @param string|null         $operation AI Client method name when known.
	 * @param list<string>|null   $armed_tools Tool/ability names armed on the prompt.
	 * @param string|null         $capability_family Pre-resolved family from snapshot (preferred).
	 */
	public static function would_prevent( array $policy, ?string $plugin_basename, ?string $operation = null, ?array $armed_tools = null, ?string $capability_family = null ): bool {
		$eval = self::evaluate( $policy, $plugin_basename, $operation, $armed_tools, $capability_family );
		return (bool) $eval['prevent'];
	}

	/**
	 * Full evaluation with denial reason (for loud audit trail).
	 *
	 * Decision order:
	 * 1. Kill switch — non-excepted callers blocked; exceptions fall through to normal rules
	 *    (plugin + family + tool arming), not unconditional allow.
	 * 2. Plugin-level deny (all families denied).
	 * 3. Capability-family rule when plugin is allowed (or inherits allow).
	 * 4. Unknown-operation fallback when the method has no family mapping.
	 * 5. Tool deny-at-arming — prompt arms a denied tool (F2).
	 *
	 * Matched tools are collected on every denial regardless of which rule fired.
	 *
	 * @param array<string,mixed> $policy
	 * @param string|null         $operation AI Client method name when known.
	 * @param list<string>|null   $armed_tools Tool/ability names armed on the prompt.
	 * @param string|null         $capability_family Pre-resolved family from snapshot (preferred).
	 * @return array{prevent:bool,reason:string,matched_tools:list<string>}
	 */
	public static function evaluate( array $policy, ?string $plugin_basename, ?string $operation = null, ?array $armed_tools = null, ?string $capability_family = null ): array {
		if ( ! empty( $policy['kill_switch'] ) ) {
			$exceptions = self::get_kill_switch_exceptions( $policy );
			if ( $plugin_basename && in_array( $plugin_basename, $exceptions, true ) ) {
				// Fall through to normal rules for exceptions — do not widen access.
			} else {
				return self::with_matched_tools(
					array(
						'prevent' => true,
						'reason'  => 'kill_switch',
					),
					$policy,
					$armed_tools ?? array()
				);
			}
		}

		$instance = self::instance();
		return $instance->decide_detailed( $policy, $plugin_basename, $operation, $armed_tools ?? array(), $capability_family );
	}

	/**
	 * Plugin-level allow/deny label under current policy (ignores audit-only and family rules).
	 * Used for suggested-rules UI — not a full effective matrix decision.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function effective_decision_label( array $policy, ?string $plugin_basename ): string {
		return self::would_prevent( $policy, $plugin_basename, null ) ? 'deny' : 'allow';
	}

	/**
	 * Aggregate plugins seen in the log for suggested-rule UI.
	 *
	 * @param array<int,mixed> $log
	 * @return list<array{plugin:string,label:string,calls:int,last_ts:int,effective:string,explicit:string}>
	 */
	public static function suggested_rules_from_log( array $log, array $policy, array $plugins ): array {
		$stats = array();

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			if ( '' === $plugin ) {
				continue;
			}

			if ( ! isset( $stats[ $plugin ] ) ) {
				$stats[ $plugin ] = array(
					'plugin'  => $plugin,
					'label'   => $plugin,
					'calls'   => 0,
					'last_ts' => 0,
				);
			}

			++$stats[ $plugin ]['calls'];
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts > $stats[ $plugin ]['last_ts'] ) {
				$stats[ $plugin ]['last_ts'] = $ts;
			}
		}

		if ( empty( $stats ) ) {
			return array();
		}

		$rows = array();
		foreach ( $stats as $basename => $row ) {
			if ( isset( $plugins[ $basename ]['Name'] ) ) {
				$row['label'] = (string) $plugins[ $basename ]['Name'];
			}

			$explicit = $policy['plugins'][ $basename ] ?? '';
			$row['explicit']  = ( 'allow' === $explicit || 'deny' === $explicit ) ? $explicit : '';
			$row['effective'] = self::effective_decision_label( $policy, $basename );

			$rows[] = $row;
		}

		usort(
			$rows,
			static function ( array $a, array $b ): int {
				return $b['calls'] <=> $a['calls'];
			}
		);

		return $rows;
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return list<string>
	 */
	public static function get_kill_switch_exceptions( array $policy ): array {
		$raw = $policy['kill_switch_exceptions'] ?? array();
		if ( ! is_array( $raw ) ) {
			return array();
		}

		$out = array();
		foreach ( $raw as $basename ) {
			$basename = sanitize_text_field( (string) $basename );
			if ( '' !== $basename ) {
				$out[] = $basename;
			}
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * Records prompt/completion token counts on the matching recent-call log row.
	 *
	 * @param object $event AfterGenerateResultEvent (WordPress AI Client).
	 */
	public function maybe_log_token_usage( object $event ): void {
		$policy = self::get_policy();
		if ( empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] ) ) {
			return;
		}

		$tokens = self::extract_token_usage_from_event( $event );
		if ( null === $tokens ) {
			return;
		}

		while ( ! empty( self::$pending_token_log_keys ) ) {
			$log_key = (string) array_pop( self::$pending_token_log_keys );
			if ( self::patch_log_entry( $log_key, $tokens ) ) {
				break;
			}
		}
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param string|null         $operation AI Client method name when known.
	 * @param list<string>        $armed_tools
	 * @param string|null         $capability_family Pre-resolved family (from snapshot inference).
	 * @return array{prevent:bool,reason:string,matched_tools:list<string>}
	 */
	private function decide_detailed( array $policy, ?string $plugin_basename, ?string $operation, array $armed_tools, ?string $capability_family = null ): array {
		$allow = array(
			'prevent'       => false,
			'reason'        => '',
			'matched_tools' => array(),
		);

		$plugin_decision = $this->plugin_level_decision( $policy, $plugin_basename );

		// Outer gate: plugin deny blocks every family and tool arming.
		if ( 'deny' === $plugin_decision ) {
			return self::with_matched_tools(
				array(
					'prevent' => true,
					'reason'  => 'plugin',
				),
				$policy,
				$armed_tools
			);
		}

		// Capability family (F1) — only when operation is known.
		if ( null !== $operation && '' !== $operation ) {
			$family = ( is_string( $capability_family ) && '' !== $capability_family )
				? $capability_family
				: Operations::family_from_operation( $operation );

			if ( Operations::FAMILY_UNKNOWN === $family ) {
				if ( $this->unknown_operation_prevents( $policy ) ) {
					return self::with_matched_tools(
						array(
							'prevent' => true,
							'reason'  => 'unknown_operation',
						),
						$policy,
						$armed_tools
					);
				}
			} else {
				$family_rule = $this->family_rule_for_plugin( $policy, $plugin_basename, $family );
				if ( 'deny' === $family_rule ) {
					return self::with_matched_tools(
						array(
							'prevent' => true,
							'reason'  => 'capability_family',
						),
						$policy,
						$armed_tools
					);
				}
			}
		}

		// F2: deny-at-arming — block if any armed tool is on the deny list.
		$matched = $this->matched_denied_tools( $policy, $armed_tools );
		if ( ! empty( $matched ) ) {
			return array(
				'prevent'       => true,
				'reason'        => 'tool_armed',
				'matched_tools' => $matched,
			);
		}

		// Even on allow, surface matches if any (empty when nothing matched).
		return self::with_matched_tools( $allow, $policy, $armed_tools );
	}

	/**
	 * Attach case-normalized deny-list matches to any evaluation result.
	 *
	 * @param array{prevent:bool,reason:string} $result
	 * @param array<string,mixed>               $policy
	 * @param list<string>                      $armed_tools
	 * @return array{prevent:bool,reason:string,matched_tools:list<string>}
	 */
	private static function with_matched_tools( array $result, array $policy, array $armed_tools ): array {
		$instance = self::instance();
		$result['matched_tools'] = $instance->matched_denied_tools( $policy, $armed_tools );
		return $result;
	}

	/**
	 * Case-normalized match of armed tools against the deny list.
	 * Returned values keep the armed tool's original casing for the audit trail.
	 *
	 * @param array<string,mixed> $policy
	 * @param list<string>        $armed_tools
	 * @return list<string>
	 */
	private function matched_denied_tools( array $policy, array $armed_tools ): array {
		if ( empty( $armed_tools ) ) {
			return array();
		}

		$denied = self::get_denied_tools( $policy );
		if ( empty( $denied ) ) {
			return array();
		}

		$denied_lookup = array();
		foreach ( $denied as $name ) {
			$denied_lookup[ self::normalize_tool_key( $name ) ] = true;
		}

		$matched = array();
		foreach ( $armed_tools as $tool ) {
			$tool = sanitize_text_field( (string) $tool );
			if ( '' === $tool ) {
				continue;
			}
			if ( isset( $denied_lookup[ self::normalize_tool_key( $tool ) ] ) ) {
				$matched[] = $tool;
			}
		}

		return array_values( array_unique( $matched ) );
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return list<string>
	 */
	public static function get_denied_tools( array $policy ): array {
		// Prefer denied_tools; fall back to legacy denied_abilities option key.
		$raw = $policy['denied_tools'] ?? $policy['denied_abilities'] ?? array();
		return self::sanitize_denied_tools( $raw );
	}

	/**
	 * @deprecated Use get_denied_tools().
	 * @param array<string,mixed> $policy
	 * @return list<string>
	 */
	public static function get_denied_abilities( array $policy ): array {
		return self::get_denied_tools( $policy );
	}

	/**
	 * @param mixed $raw
	 * @return list<string>
	 */
	public static function sanitize_denied_tools( $raw ): array {
		if ( is_string( $raw ) ) {
			// Textarea: one tool name per line.
			$raw = preg_split( '/\r\n|\r|\n/', $raw );
		}
		if ( ! is_array( $raw ) ) {
			return array();
		}

		$out = array();
		foreach ( $raw as $name ) {
			$name = sanitize_text_field( (string) $name );
			$name = trim( $name );
			if ( '' === $name ) {
				continue;
			}
			// Tool names look like namespace/action or custom FunctionDeclaration ids.
			if ( strlen( $name ) > 200 ) {
				continue;
			}
			$out[] = $name;
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * @deprecated Use sanitize_denied_tools().
	 * @param mixed $raw
	 * @return list<string>
	 */
	public static function sanitize_denied_abilities( $raw ): array {
		return self::sanitize_denied_tools( $raw );
	}

	/**
	 * Lowercase key for case-insensitive tool matching.
	 */
	public static function normalize_tool_key( string $name ): string {
		return strtolower( trim( $name ) );
	}

	/**
	 * Whether a deny-list entry matches any currently registered ability (case-insensitive).
	 * Used only for admin UI flags — pre-listing unregistered names is allowed.
	 *
	 * @param string       $entry           Deny-list entry as stored.
	 * @param list<string> $registered_names Currently registered ability names.
	 */
	public static function deny_entry_matches_registered( string $entry, array $registered_names ): bool {
		$key = self::normalize_tool_key( $entry );
		if ( '' === $key ) {
			return false;
		}
		foreach ( $registered_names as $name ) {
			if ( self::normalize_tool_key( (string) $name ) === $key ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Plugin-level allow/deny (no family refinement).
	 *
	 * @param array<string,mixed> $policy
	 * @return 'allow'|'deny'
	 */
	private function plugin_level_decision( array $policy, ?string $plugin_basename ): string {
		$default = ( $policy['default'] ?? 'allow' ) === 'deny' ? 'deny' : 'allow';
		$rules   = is_array( $policy['plugins'] ?? null ) ? (array) $policy['plugins'] : array();

		if ( $plugin_basename && isset( $rules[ $plugin_basename ] ) ) {
			return 'deny' === $rules[ $plugin_basename ] ? 'deny' : 'allow';
		}

		return $default;
	}

	/**
	 * Explicit per-plugin family rule, or empty string for inherit.
	 *
	 * @param array<string,mixed> $policy
	 * @return 'allow'|'deny'|''
	 */
	private function family_rule_for_plugin( array $policy, ?string $plugin_basename, string $family ): string {
		if ( ! $plugin_basename ) {
			return '';
		}

		$ops = is_array( $policy['operations'] ?? null ) ? (array) $policy['operations'] : array();
		if ( ! isset( $ops[ $plugin_basename ] ) || ! is_array( $ops[ $plugin_basename ] ) ) {
			return '';
		}

		$rule = $ops[ $plugin_basename ][ $family ] ?? '';
		if ( 'allow' === $rule || 'deny' === $rule ) {
			return $rule;
		}

		return '';
	}

	/**
	 * Unknown-operation fallback: inherit | allow | deny.
	 *
	 * Only reachable when the plugin-level decision is already allow (plugin
	 * deny returns earlier), so inherit means allow.
	 *
	 * @param array<string,mixed> $policy
	 */
	private function unknown_operation_prevents( array $policy ): bool {
		$fallback = $policy['unknown_operation'] ?? 'inherit';
		if ( 'deny' === $fallback ) {
			return true;
		}
		// allow or inherit (plugin already allowed when this is called).
		return false;
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function get_policy(): array {
		$policy = get_option( Plugin::OPTION_KEY );
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}

		$policy['default'] = ( $policy['default'] ?? 'allow' ) === 'deny' ? 'deny' : 'allow';
		$policy['plugins'] = is_array( $policy['plugins'] ?? null ) ? (array) $policy['plugins'] : array();
		// Opt-in: logging stores local request metadata (e.g. user id / URI).
		$policy['log_enabled'] = (bool) ( $policy['log_enabled'] ?? false );
		$policy['audit_only']  = (bool) ( $policy['audit_only'] ?? false );
		$policy['kill_switch'] = (bool) ( $policy['kill_switch'] ?? false );
		$policy['kill_switch_exceptions'] = self::get_kill_switch_exceptions( $policy );
		$policy['log_limit'] = (int) ( $policy['log_limit'] ?? 200 );
		if ( $policy['log_limit'] < 20 ) {
			$policy['log_limit'] = 20;
		}
		if ( $policy['log_limit'] > 1000 ) {
			$policy['log_limit'] = 1000;
		}
		// Optional time-based retention (days). null = off (entry-count cap only).
		$policy['log_max_age_days'] = self::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null );

		$policy['operations']        = self::sanitize_operations( $policy['operations'] ?? array() );
		$policy['unknown_operation'] = self::sanitize_unknown_operation( $policy['unknown_operation'] ?? 'inherit' );

		// Tools rename: read new key, migrate legacy denied_abilities.
		$tools_raw = $policy['denied_tools'] ?? null;
		if ( null === $tools_raw || ( is_array( $tools_raw ) && empty( $tools_raw ) ) ) {
			if ( ! empty( $policy['denied_abilities'] ) ) {
				$tools_raw = $policy['denied_abilities'];
			}
		}
		$policy['denied_tools'] = self::sanitize_denied_tools( $tools_raw ?? array() );

		// F3: denial alerts + estimated-$ rates (observability only).
		$policy['alert_on_deny']     = (bool) ( $policy['alert_on_deny'] ?? false );
		$policy['alert_mode']        = Alerts::sanitize_mode( $policy['alert_mode'] ?? 'immediate' );
		$policy['alert_email']       = Alerts::sanitize_email( $policy['alert_email'] ?? '' );
		$policy['alert_webhook_url'] = Alerts::sanitize_webhook_url( $policy['alert_webhook_url'] ?? '' );
		$policy['est_usd_input_per_m']  = Cost::sanitize_rate( $policy['est_usd_input_per_m'] ?? Cost::DEFAULT_INPUT_PER_M, Cost::DEFAULT_INPUT_PER_M );
		$policy['est_usd_output_per_m'] = Cost::sanitize_rate( $policy['est_usd_output_per_m'] ?? Cost::DEFAULT_OUTPUT_PER_M, Cost::DEFAULT_OUTPUT_PER_M );
		$policy['est_usd_provider_rates'] = Cost::sanitize_provider_rates( $policy['est_usd_provider_rates'] ?? array() );

		// F7: weekly report preference — staged selected-by-default until first explicit choice.
		// Delivery still requires logging/learn (Weekly_Report::is_active). Key absence ≠ off.
		$raw_option = get_option( Plugin::OPTION_KEY );
		$raw_is_arr = is_array( $raw_option );
		if ( $raw_is_arr && array_key_exists( 'weekly_report_enabled', $raw_option ) ) {
			$policy['weekly_report_enabled'] = (bool) $raw_option['weekly_report_enabled'];
		} else {
			// Checked-but-inactive: preference is selected; is_active gates send/schedule.
			$policy['weekly_report_enabled'] = Weekly_Report::default_enabled_for_policy( $policy );
		}

		// F4 experimental per-plugin model force (off by default; empty map = no force).
		$policy['model_force_plugins']               = Model_Force::sanitize_force_map( $policy['model_force_plugins'] ?? array() );
		$policy['model_force_unattributed']          = Model_Force::sanitize_unattributed_mode( $policy['model_force_unattributed'] ?? 'none' );
		$policy['model_force_unattributed_provider'] = Model_Force::sanitize_id( $policy['model_force_unattributed_provider'] ?? '' );
		$policy['model_force_unattributed_model']    = Model_Force::sanitize_id( $policy['model_force_unattributed_model'] ?? '' );
		// Incomplete unattributed "force" falls back to none (same as incomplete site-wide before).
		if ( 'force' === $policy['model_force_unattributed']
			&& ( '' === $policy['model_force_unattributed_provider'] || '' === $policy['model_force_unattributed_model'] ) ) {
			$policy['model_force_unattributed'] = 'none';
		}
		// Drop superseded site-wide keys if present in stored option (read path normalizes).
		unset( $policy['model_force_enabled'], $policy['model_force_provider'], $policy['model_force_model'] );

		return $policy;
	}

	/**
	 * @param mixed $raw
	 * @return array<string,array<string,string>>
	 */
	public static function sanitize_operations( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}

		$families = Operations::families();
		$out      = array();

		foreach ( $raw as $basename => $family_rules ) {
			$basename = sanitize_text_field( (string) $basename );
			if ( '' === $basename || ! is_array( $family_rules ) ) {
				continue;
			}

			$row = array();
			foreach ( $families as $family ) {
				$rule = isset( $family_rules[ $family ] ) ? sanitize_text_field( (string) $family_rules[ $family ] ) : '';
				if ( 'allow' === $rule || 'deny' === $rule ) {
					$row[ $family ] = $rule;
				}
			}

			if ( ! empty( $row ) ) {
				$out[ $basename ] = $row;
			}
		}

		return $out;
	}

	/**
	 * @param mixed $raw
	 * @return 'inherit'|'allow'|'deny'
	 */
	public static function sanitize_unknown_operation( $raw ): string {
		$raw = sanitize_text_field( (string) $raw );
		if ( 'allow' === $raw || 'deny' === $raw ) {
			return $raw;
		}

		return 'inherit';
	}

	/**
	 * Optional maximum log age in whole days. Empty / invalid / < 1 → off (null).
	 *
	 * @param mixed $raw Posted or stored value.
	 */
	public static function sanitize_log_max_age_days( $raw ): ?int {
		if ( null === $raw || false === $raw ) {
			return null;
		}
		if ( is_string( $raw ) && '' === trim( $raw ) ) {
			return null;
		}
		// Accept ints and digit strings; reject floats / junk.
		if ( is_string( $raw ) && ! preg_match( '/^\s*\d+\s*$/', $raw ) ) {
			return null;
		}
		$n = (int) $raw;
		if ( $n < 1 ) {
			return null;
		}
		// Soft ceiling so a typo cannot keep multi-decade windows "forever".
		if ( $n > 3650 ) {
			$n = 3650;
		}

		return $n;
	}

	/**
	 * Seconds in one day (WP constant when available).
	 */
	public static function day_in_seconds(): int {
		return defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
	}

	/**
	 * Apply time-based TTL (if configured) and entry-count cap. Stricter wins:
	 * both filters run; a row that fails either is removed.
	 *
	 * @param array<int,mixed>    $log
	 * @param array<string,mixed> $policy
	 * @param int|null            $now Unix now (injectable for tests).
	 * @return list<array<string,mixed>|mixed>
	 */
	public static function apply_log_retention( array $log, array $policy, ?int $now = null ): array {
		$now = null === $now ? time() : $now;
		if ( $now <= 0 ) {
			$now = time();
		}

		$max_age = self::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null );
		if ( null !== $max_age ) {
			$cutoff = $now - ( $max_age * self::day_in_seconds() );
			$kept   = array();
			foreach ( $log as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
				// Untimestamped rows are kept (avoid wiping pre-ts legacy data).
				if ( $ts > 0 && $ts < $cutoff ) {
					continue;
				}
				$kept[] = $row;
			}
			$log = $kept;
		}

		$limit = (int) ( $policy['log_limit'] ?? 200 );
		if ( $limit < 20 ) {
			$limit = 20;
		}
		if ( $limit > 1000 ) {
			$limit = 1000;
		}
		$count = count( $log );
		if ( $count > $limit ) {
			$log = array_slice( $log, $count - $limit );
		}

		return array_values( $log );
	}

	/**
	 * Read the ring buffer, prune by current policy retention, persist if changed.
	 *
	 * @param int|null $now Injectable clock for tests.
	 * @return list<array<string,mixed>|mixed>
	 */
	public static function get_retained_log( ?int $now = null ): array {
		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) ) {
			return array();
		}

		$policy = self::get_policy();
		$pruned = self::apply_log_retention( $log, $policy, $now );
		// Persist only when retention actually dropped rows (cheap length/content check).
		if ( count( $pruned ) !== count( $log ) || $pruned != $log ) { // phpcs:ignore WordPress.PHP.StrictComparisons.LooseComparison -- content compare
			update_option( Plugin::LOG_OPTION_KEY, $pruned, false );
		}

		return $pruned;
	}

	/**
	 * Prune the stored option in place (e.g. after saving a new TTL).
	 *
	 * @param int|null $now Injectable clock for tests.
	 * @return list<array<string,mixed>|mixed>
	 */
	public static function prune_stored_log( ?int $now = null ): array {
		return self::get_retained_log( $now );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function save_policy( array $policy ): void {
		if ( ! empty( $policy['audit_only'] ) ) {
			$policy['log_enabled'] = true;
		}

		$policy['kill_switch_exceptions'] = self::get_kill_switch_exceptions( $policy );
		$policy['operations']             = self::sanitize_operations( $policy['operations'] ?? array() );
		$policy['unknown_operation']      = self::sanitize_unknown_operation( $policy['unknown_operation'] ?? 'inherit' );
		$policy['denied_tools']           = self::sanitize_denied_tools( $policy['denied_tools'] ?? $policy['denied_abilities'] ?? array() );
		// Drop legacy key on save so the option stores the honest name.
		unset( $policy['denied_abilities'] );

		$policy['alert_on_deny']     = ! empty( $policy['alert_on_deny'] );
		$policy['alert_mode']        = Alerts::sanitize_mode( $policy['alert_mode'] ?? 'immediate' );
		$policy['alert_email']       = Alerts::sanitize_email( $policy['alert_email'] ?? '' );
		$policy['alert_webhook_url'] = Alerts::sanitize_webhook_url( $policy['alert_webhook_url'] ?? '' );
		$policy['est_usd_input_per_m']  = Cost::sanitize_rate( $policy['est_usd_input_per_m'] ?? Cost::DEFAULT_INPUT_PER_M, Cost::DEFAULT_INPUT_PER_M );
		$policy['est_usd_output_per_m'] = Cost::sanitize_rate( $policy['est_usd_output_per_m'] ?? Cost::DEFAULT_OUTPUT_PER_M, Cost::DEFAULT_OUTPUT_PER_M );
		$policy['est_usd_provider_rates'] = Cost::sanitize_provider_rates( $policy['est_usd_provider_rates'] ?? array() );

		$max_age = self::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null );
		if ( null === $max_age ) {
			unset( $policy['log_max_age_days'] );
		} else {
			$policy['log_max_age_days'] = $max_age;
		}

		$policy['log_limit'] = (int) ( $policy['log_limit'] ?? 200 );
		if ( $policy['log_limit'] < 20 ) {
			$policy['log_limit'] = 20;
		}
		if ( $policy['log_limit'] > 1000 ) {
			$policy['log_limit'] = 1000;
		}

		// F7 weekly key: store only an explicit choice. Key absence keeps the staged default.
		// Activity form sets _weekly_report_write; other save paths preserve raw presence so a
		// Rules/quick-rule save never pins a derived value and defeats default-on.
		$raw_before     = get_option( Plugin::OPTION_KEY );
		$had_weekly_key = is_array( $raw_before ) && array_key_exists( 'weekly_report_enabled', $raw_before );
		$weekly_write   = isset( $policy['_weekly_report_write'] ) ? (string) $policy['_weekly_report_write'] : '';
		unset( $policy['_weekly_report_write'], $policy['_weekly_report_value'] );

		if ( 'set' === $weekly_write ) {
			$policy['weekly_report_enabled'] = ! empty( $policy['weekly_report_enabled'] );
		} elseif ( 'omit' === $weekly_write ) {
			unset( $policy['weekly_report_enabled'] );
		} elseif ( $had_weekly_key ) {
			// Non-Activity save: keep stored explicit choice, ignore derived get_policy value.
			$policy['weekly_report_enabled'] = ! empty( $raw_before['weekly_report_enabled'] );
		} else {
			// Key was never saved — leave it absent so staged default re-derives on read.
			unset( $policy['weekly_report_enabled'] );
		}

		// In-memory preference for cron: stored value, or staged selected when key omitted.
		$weekly_for_schedule = array_key_exists( 'weekly_report_enabled', $policy )
			? ! empty( $policy['weekly_report_enabled'] )
			: true;

		$policy['model_force_plugins']               = Model_Force::sanitize_force_map( $policy['model_force_plugins'] ?? array() );
		$policy['model_force_unattributed']          = Model_Force::sanitize_unattributed_mode( $policy['model_force_unattributed'] ?? 'none' );
		$policy['model_force_unattributed_provider'] = Model_Force::sanitize_id( $policy['model_force_unattributed_provider'] ?? '' );
		$policy['model_force_unattributed_model']    = Model_Force::sanitize_id( $policy['model_force_unattributed_model'] ?? '' );
		if ( 'force' === $policy['model_force_unattributed']
			&& ( '' === $policy['model_force_unattributed_provider'] || '' === $policy['model_force_unattributed_model'] ) ) {
			$policy['model_force_unattributed'] = 'none';
		}
		// Site-wide pin removed: per-plugin replaces it. Never re-store legacy keys.
		unset( $policy['model_force_enabled'], $policy['model_force_provider'], $policy['model_force_model'] );

		update_option( Plugin::OPTION_KEY, $policy, false );
		Alerts::maybe_schedule( $policy );
		// maybe_schedule needs preference + log/learn from this save; not the stripped store shape.
		$schedule_policy                           = $policy;
		$schedule_policy['weekly_report_enabled'] = $weekly_for_schedule;
		Weekly_Report::maybe_schedule( $schedule_policy );

		// Issue 7: disabling alerts must not leave denial metadata queued.
		if ( empty( $policy['alert_on_deny'] ) ) {
			Alerts::clear_digest_queue();
		}
	}

	/**
	 * Apply allow|deny to selected installed plugins only (AICAC-BULK).
	 *
	 * Does not touch capability-family rules, model-force pins, or unselected
	 * plugin entries. Unknown / not-installed basenames are skipped (no fatal).
	 *
	 * @param array<string,mixed>               $policy             Current policy.
	 * @param list<string>|array<int|string,mixed> $selected_basenames Posted checkbox values.
	 * @param string                            $rule               'allow' or 'deny'.
	 * @param array<string,mixed>               $installed_plugins  get_plugins()-shaped map (keys = basenames).
	 * @return array{policy:array<string,mixed>,updated:int,skipped:int}|false False when $rule is invalid.
	 */
	public static function apply_bulk_plugin_rules( array $policy, array $selected_basenames, string $rule, array $installed_plugins ) {
		$rule = sanitize_text_field( $rule );
		if ( 'allow' !== $rule && 'deny' !== $rule ) {
			return false;
		}

		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();

		$updated = 0;
		$skipped = 0;

		foreach ( $selected_basenames as $raw ) {
			$basename = sanitize_text_field( (string) $raw );
			if ( '' === $basename ) {
				++$skipped;
				continue;
			}
			if ( ! array_key_exists( $basename, $installed_plugins ) ) {
				++$skipped;
				continue;
			}
			$plugins[ $basename ] = $rule;
			++$updated;
		}

		$policy['plugins'] = $plugins;

		return array(
			'policy'  => $policy,
			'updated' => $updated,
			'skipped' => $skipped,
		);
	}

	/**
	 * Set allow/deny for one plugin (quick action from Activity / Dashboard).
	 * Empty $rule clears the explicit rule (inherit Default) — used by undo.
	 */
	public static function set_plugin_rule( string $plugin_basename, string $rule ): bool {
		$rule = sanitize_text_field( $rule );
		if ( '' !== $rule && 'allow' !== $rule && 'deny' !== $rule ) {
			return false;
		}

		$plugin_basename = sanitize_text_field( $plugin_basename );
		if ( '' === $plugin_basename ) {
			return false;
		}

		$policy = self::get_policy();
		if ( ! isset( $policy['plugins'] ) || ! is_array( $policy['plugins'] ) ) {
			$policy['plugins'] = array();
		}
		if ( '' === $rule ) {
			unset( $policy['plugins'][ $plugin_basename ] );
		} else {
			$policy['plugins'][ $plugin_basename ] = $rule;
		}
		self::save_policy( $policy );

		return true;
	}

	/**
	 * Apply one capability-family rule onto a policy array (no persistence).
	 *
	 * Used by Rules save (via sanitize_operations on the full map) and by WP-CLI
	 * `aicac rule set` so both share the same validation constraints: only
	 * Operations::families() keys and allow|deny (inherit clears the field).
	 *
	 * @param array<string,mixed> $policy
	 * @return array<string,mixed>|false Updated policy, or false when args are invalid.
	 */
	public static function apply_family_rule_to_policy( array $policy, string $plugin_basename, string $family, string $rule ) {
		$plugin_basename = sanitize_text_field( $plugin_basename );
		$family          = sanitize_text_field( $family );
		$rule            = sanitize_text_field( $rule );

		if ( '' === $plugin_basename ) {
			return false;
		}
		if ( ! in_array( $family, Operations::families(), true ) ) {
			return false;
		}
		if ( 'inherit' === $rule ) {
			$rule = '';
		}
		if ( '' !== $rule && 'allow' !== $rule && 'deny' !== $rule ) {
			return false;
		}

		$operations = is_array( $policy['operations'] ?? null ) ? (array) $policy['operations'] : array();
		$row        = isset( $operations[ $plugin_basename ] ) && is_array( $operations[ $plugin_basename ] )
			? (array) $operations[ $plugin_basename ]
			: array();

		if ( '' === $rule ) {
			unset( $row[ $family ] );
		} else {
			$row[ $family ] = $rule;
		}

		if ( empty( $row ) ) {
			unset( $operations[ $plugin_basename ] );
		} else {
			$operations[ $plugin_basename ] = $row;
		}

		$policy['operations'] = self::sanitize_operations( $operations );

		return $policy;
	}

	/**
	 * Set allow/deny/inherit for one plugin × capability family.
	 * Persists through save_policy() (same path as Admin::handle_save_rules).
	 *
	 * @param string $rule allow|deny|inherit (empty string also means inherit).
	 */
	public static function set_family_rule( string $plugin_basename, string $family, string $rule ): bool {
		$policy = self::apply_family_rule_to_policy( self::get_policy(), $plugin_basename, $family, $rule );
		if ( false === $policy ) {
			return false;
		}
		self::save_policy( $policy );

		return true;
	}

	/**
	 * Build list rows for every installed plugin (Rules-tab plugin set).
	 *
	 * Inactive plugins are included — matching the Rules tab, which lists all
	 * get_plugins() entries and still shows prior family rules when deactivated.
	 *
	 * @param array<string,array<string,mixed>> $plugins Output of get_plugins().
	 * @param array<string,mixed>               $policy  Policy option (or get_policy()).
	 * @param array<string,bool|string>         $active  Map of active plugin basenames (is_plugin_active keys).
	 * @return list<array<string,string>>
	 */
	public static function family_rule_rows_for_plugins( array $plugins, array $policy, array $active = array() ): array {
		$operations = self::sanitize_operations( $policy['operations'] ?? array() );
		$families   = Operations::families();
		$rows       = array();

		foreach ( $plugins as $basename => $data ) {
			$basename = sanitize_text_field( (string) $basename );
			if ( '' === $basename ) {
				continue;
			}
			$name = isset( $data['Name'] ) ? (string) $data['Name'] : $basename;
			$ops  = isset( $operations[ $basename ] ) && is_array( $operations[ $basename ] )
				? $operations[ $basename ]
				: array();

			$row = array(
				'plugin' => $basename,
				'name'   => $name,
				'status' => isset( $active[ $basename ] ) ? 'active' : 'inactive',
			);
			foreach ( $families as $family ) {
				$rule = isset( $ops[ $family ] ) ? (string) $ops[ $family ] : '';
				$row[ $family ] = ( 'allow' === $rule || 'deny' === $rule ) ? $rule : 'inherit';
			}
			$rows[] = $row;
		}

		return $rows;
	}

	/**
	 * Idle seconds after last activity before a new direct_http row is started
	 * for the same collapse key (sliding idle timeout — not a fixed bucket).
	 * Board F6 design question 2026-07-31: deliberate YES to collapse.
	 */
	private const DIRECT_HTTP_COLLAPSE_WINDOW = 300;

	/**
	 * Append a retained log row (AI Client events and F6 direct_http observations).
	 *
	 * STORAGE CONTRACT (board 2026-07-31, binding on F6) — units in the table:
	 *
	 * | Field            | Value                                      | Unit / notes                          |
	 * |------------------|--------------------------------------------|---------------------------------------|
	 * | channel          | direct_http (AI Client omits / ai_client)  | enum                                  |
	 * | ts               | last activity in cluster (or row time)     | unix seconds                          |
	 * | first_ts         | first activity when collapsed              | unix seconds (optional)               |
	 * | plugin, file, caller | first observation retained on collapse | attribution strings / null            |
	 * | host             | request host only                          | hostname                              |
	 * | shadow_provider  | matched id or empty                        | enum string                           |
	 * | decision         | observe (F6 v1 not enforcement)            | enum                                  |
	 * | count            | HTTP *calls* (missing = 1)                 | calls — same unit as AI Client rows   |
	 * | (no body / keys) | privacy                                    | —                                     |
	 * | ring buffer      | SHARED with AI Client rows                 | log_limit slots (default 200)         |
	 *
	 * One shared FIFO is the only way F5 coverage buckets (M = N + D) sum.
	 * D = sum of count over direct_http rows. Separate per-channel budgets
	 * would re-introduce the two-denominator honesty bug in storage form.
	 *
	 * CHATTY-HOST COLLAPSE (F6 v1, deliberate):
	 * - Match key: attributed plugin|host; unattributed host|file (so unknown
	 *   callers do not all merge into one row).
	 * - Idle timeout DIRECT_HTTP_COLLAPSE_WINDOW from last `ts`.
	 * - On collapse: add incoming count (not hardcoded +1), keep first
	 *   file/caller/uri/user_id, set first_ts, refresh ts, MOVE row to tail
	 *   so active clusters are not evicted ahead of idle AI Client rows and
	 *   the array stays ordered by last activity for FIFO + span.
	 * - Shadow_AI tallies calls in-request and flushes once on shutdown so
	 *   count means calls, not page loads (Lisa gate-1 / board preference).
	 *
	 * Public so Shadow_AI can write the same ring buffer without duplicating the gate.
	 *
	 * @param array<string,mixed> $event
	 */
	public static function append_log_event( array $event ): void {
		$policy = self::get_policy();
		if ( empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] ) ) {
			return;
		}

		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) ) {
			$log = array();
		}

		// Prune first so collapse keys and FIFO count reflect the retained window.
		// Active shadow-AI clusters have a recent `ts` and are not dropped by TTL.
		$event_ts = isset( $event['ts'] ) ? (int) $event['ts'] : time();
		if ( $event_ts <= 0 ) {
			$event_ts = time();
		}
		$log = self::apply_log_retention( $log, $policy, $event_ts );

		$is_direct_http = isset( $event['channel'] ) && 'direct_http' === (string) $event['channel'];
		if ( $is_direct_http && self::collapse_direct_http_into_log( $log, $event ) ) {
			// Collapse mutates in place; re-apply entry-count (TTL already satisfied by recent ts).
			$log = self::apply_log_retention( $log, $policy, $event_ts );
			update_option( Plugin::LOG_OPTION_KEY, $log, false );
			return;
		}

		if ( $is_direct_http && ! isset( $event['count'] ) ) {
			$event['count'] = 1;
		}

		$log[] = $event;
		$log   = self::apply_log_retention( $log, $policy, $event_ts );

		update_option( Plugin::LOG_OPTION_KEY, $log, false );
	}

	/**
	 * Collapse a direct_http observation into a matching active cluster, or fail.
	 *
	 * On success the matched row is removed from its current index and appended
	 * at the tail (last-activity order restored for FIFO eviction and Δ5 span).
	 *
	 * @param array<int,mixed>    $log   Log array (modified in place on success).
	 * @param array<string,mixed> $event Incoming observation (count = calls).
	 * @return bool True if collapsed (caller must persist $log).
	 */
	private static function collapse_direct_http_into_log( array &$log, array $event ): bool {
		$host   = isset( $event['host'] ) ? (string) $event['host'] : '';
		$plugin = ( isset( $event['plugin'] ) && is_string( $event['plugin'] ) ) ? (string) $event['plugin'] : '';
		$file   = ( isset( $event['file'] ) && is_string( $event['file'] ) ) ? (string) $event['file'] : '';
		$now    = isset( $event['ts'] ) ? (int) $event['ts'] : time();
		if ( $now <= 0 ) {
			$now = time();
		}

		$incoming = isset( $event['count'] ) ? (int) $event['count'] : 1;
		if ( $incoming < 1 ) {
			$incoming = 1;
		}

		for ( $i = count( $log ) - 1; $i >= 0; $i-- ) {
			$row = $log[ $i ];
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( ! isset( $row['channel'] ) || 'direct_http' !== (string) $row['channel'] ) {
				continue;
			}
			$row_host = isset( $row['host'] ) ? (string) $row['host'] : '';
			if ( $row_host !== $host ) {
				continue;
			}
			$row_plugin = ( isset( $row['plugin'] ) && is_string( $row['plugin'] ) ) ? (string) $row['plugin'] : '';
			if ( $row_plugin !== $plugin ) {
				continue;
			}
			// Unattributed: also require matching file so distinct unknown callers stay separate.
			if ( '' === $plugin ) {
				$row_file = ( isset( $row['file'] ) && is_string( $row['file'] ) ) ? (string) $row['file'] : '';
				if ( $row_file !== $file ) {
					continue;
				}
			}

			// Newest matching row. Idle timeout from last activity (sliding, not fixed bucket).
			$row_ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $row_ts > 0 && ( $now - $row_ts ) > self::DIRECT_HTTP_COLLAPSE_WINDOW ) {
				return false;
			}

			$prior = isset( $row['count'] ) ? (int) $row['count'] : 1;
			if ( $prior < 1 ) {
				$prior = 1;
			}
			// Unit: calls. Add the incoming call tally (never discard event['count']).
			$row['count'] = $prior + $incoming;
			if ( ! isset( $row['first_ts'] ) ) {
				$row['first_ts'] = $row_ts > 0 ? $row_ts : $now;
			}
			$row['ts'] = $now;
			// Keep first observation's file/caller/uri/user_id (do not overwrite with newest).
			// Shadow_provider / host / plugin already matched; leave them alone.

			// Move to tail: restores last-activity order (Δ5 span, FIFO eviction of idle rows).
			array_splice( $log, $i, 1 );
			$log[] = $row;
			return true;
		}

		return false;
	}

	/**
	 * @param array<string,mixed> $event
	 */
	private function log_event( array $event ): void {
		self::append_log_event( $event );
	}

	/**
	 * @param array<string,int> $patch
	 */
	private static function patch_log_entry( string $log_key, array $patch ): bool {
		if ( '' === $log_key ) {
			return false;
		}

		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) ) {
			return false;
		}

		for ( $i = count( $log ) - 1; $i >= 0; $i-- ) {
			if ( ! is_array( $log[ $i ] ) ) {
				continue;
			}
			if ( ( $log[ $i ]['log_key'] ?? '' ) !== $log_key ) {
				continue;
			}
			$log[ $i ] = array_merge( $log[ $i ], $patch );
			update_option( Plugin::LOG_OPTION_KEY, $log, false );
			return true;
		}

		return false;
	}

	/**
	 * @return array{input_tokens:int,output_tokens:int,total_tokens:int,thought_tokens?:int}|null
	 */
	private static function extract_token_usage_from_event( object $event ): ?array {
		if ( ! method_exists( $event, 'getResult' ) ) {
			return null;
		}

		$result = $event->getResult();
		if ( ! is_object( $result ) || ! method_exists( $result, 'getTokenUsage' ) ) {
			return null;
		}

		$usage = $result->getTokenUsage();
		if ( ! is_object( $usage ) ) {
			return null;
		}

		$tokens = array();

		if ( method_exists( $usage, 'getPromptTokens' ) ) {
			$tokens['input_tokens'] = (int) $usage->getPromptTokens();
		}
		if ( method_exists( $usage, 'getCompletionTokens' ) ) {
			$tokens['output_tokens'] = (int) $usage->getCompletionTokens();
		}
		if ( method_exists( $usage, 'getTotalTokens' ) ) {
			$tokens['total_tokens'] = (int) $usage->getTotalTokens();
		}

		$thought = method_exists( $usage, 'getThoughtTokens' ) ? $usage->getThoughtTokens() : null;
		if ( null !== $thought ) {
			$tokens['thought_tokens'] = (int) $thought;
		}

		return ! empty( $tokens ) ? $tokens : null;
	}

	private static function is_generating_operation( string $operation ): bool {
		if ( '' === $operation ) {
			return false;
		}

		return 0 === strpos( $operation, 'generate_' ) || 0 === strpos( $operation, 'convert_text_to_speech' );
	}

	private static function generate_log_key(): string {
		if ( function_exists( 'wp_generate_uuid4' ) ) {
			return 'aicac_' . wp_generate_uuid4();
		}

		return 'aicac_' . uniqid( '', true );
	}
}
