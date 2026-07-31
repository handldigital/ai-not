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
		$policy['alert_on_deny'] = (bool) ( $policy['alert_on_deny'] ?? false );
		$policy['alert_mode']    = Alerts::sanitize_mode( $policy['alert_mode'] ?? 'immediate' );
		$policy['alert_email']   = Alerts::sanitize_email( $policy['alert_email'] ?? '' );
		$policy['est_usd_input_per_m']  = Cost::sanitize_rate( $policy['est_usd_input_per_m'] ?? Cost::DEFAULT_INPUT_PER_M, Cost::DEFAULT_INPUT_PER_M );
		$policy['est_usd_output_per_m'] = Cost::sanitize_rate( $policy['est_usd_output_per_m'] ?? Cost::DEFAULT_OUTPUT_PER_M, Cost::DEFAULT_OUTPUT_PER_M );

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

		$policy['alert_on_deny'] = ! empty( $policy['alert_on_deny'] );
		$policy['alert_mode']    = Alerts::sanitize_mode( $policy['alert_mode'] ?? 'immediate' );
		$policy['alert_email']   = Alerts::sanitize_email( $policy['alert_email'] ?? '' );
		$policy['est_usd_input_per_m']  = Cost::sanitize_rate( $policy['est_usd_input_per_m'] ?? Cost::DEFAULT_INPUT_PER_M, Cost::DEFAULT_INPUT_PER_M );
		$policy['est_usd_output_per_m'] = Cost::sanitize_rate( $policy['est_usd_output_per_m'] ?? Cost::DEFAULT_OUTPUT_PER_M, Cost::DEFAULT_OUTPUT_PER_M );

		update_option( Plugin::OPTION_KEY, $policy, false );
		Alerts::maybe_schedule( $policy );

		// Issue 7: disabling alerts must not leave denial metadata queued.
		if ( empty( $policy['alert_on_deny'] ) ) {
			Alerts::clear_digest_queue();
		}
	}

	/**
	 * Set allow/deny for one plugin (quick action from log).
	 */
	public static function set_plugin_rule( string $plugin_basename, string $rule ): bool {
		$rule = sanitize_text_field( $rule );
		if ( 'allow' !== $rule && 'deny' !== $rule ) {
			return false;
		}

		$plugin_basename = sanitize_text_field( $plugin_basename );
		if ( '' === $plugin_basename ) {
			return false;
		}

		$policy = self::get_policy();
		$policy['plugins'][ $plugin_basename ] = $rule;
		self::save_policy( $policy );

		return true;
	}

	/**
	 * @param array<string,mixed> $event
	 */
	private function log_event( array $event ): void {
		$policy = self::get_policy();
		if ( empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] ) ) {
			return;
		}

		$limit = (int) ( $policy['log_limit'] ?? 200 );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) ) {
			$log = array();
		}

		$log[] = $event;
		$count = count( $log );
		if ( $count > $limit ) {
			$log = array_slice( $log, $count - $limit );
		}

		update_option( Plugin::LOG_OPTION_KEY, $log, false );
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
