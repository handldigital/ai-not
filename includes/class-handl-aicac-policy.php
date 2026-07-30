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
	 * @param bool $prevent
	 * @param mixed $builder WP_AI_Client_Prompt_Builder clone (read-only)
	 */
	public function maybe_prevent_prompt( bool $prevent, $builder ): bool {
		if ( $prevent ) {
			return true;
		}

		$policy = self::get_policy();

		$attrib = Attribution::resolve_from_backtrace();
		$plugin = is_string( $attrib['plugin'] ?? null ) ? (string) $attrib['plugin'] : null;

		// Snapshot first so operation/family are known before the decision (F1 constraint).
		// Snapshot resolves capability_family including inference for generate_result / is_supported.
		$snapshot  = Prompt_Snapshot::from_builder( $builder );
		$operation = isset( $snapshot['operation'] ) ? (string) $snapshot['operation'] : '';
		$family    = isset( $snapshot['capability_family'] ) && is_string( $snapshot['capability_family'] )
			? (string) $snapshot['capability_family']
			: Operations::family_from_operation( $operation );

		$would_prevent = self::would_prevent( $policy, $plugin, $operation, $family );
		$prevent       = self::should_prevent( $policy, $plugin, $operation, $family );

		$event = array_merge(
			array(
				'ts'                 => time(),
				'plugin'             => $plugin,
				'file'               => $attrib['file'] ?? null,
				'caller'             => $attrib['method'] ?? null,
				'decision'           => $prevent ? 'deny' : 'allow',
				'would_decision'     => $would_prevent ? 'deny' : 'allow',
				'capability_family'  => $family,
				'user_id'            => get_current_user_id(),
				'uri'                => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) ) : null,
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

		return $prevent;
	}

	/**
	 * Whether to block the prompt (enforcement).
	 *
	 * @param array<string,mixed> $policy
	 * @param string|null         $operation AI Client method name when known.
	 * @param string|null         $capability_family Pre-resolved family from snapshot (preferred).
	 */
	public static function should_prevent( array $policy, ?string $plugin_basename, ?string $operation = null, ?string $capability_family = null ): bool {
		if ( ! empty( $policy['audit_only'] ) ) {
			return false;
		}

		return self::would_prevent( $policy, $plugin_basename, $operation, $capability_family );
	}

	/**
	 * What would happen if enforcement were active (ignores audit-only).
	 *
	 * Decision order:
	 * 1. Kill switch — non-excepted callers blocked; exceptions fall through to normal rules
	 *    (plugin + family), not unconditional allow.
	 * 2. Plugin-level deny (all families denied).
	 * 3. Capability-family rule when plugin is allowed (or inherits allow).
	 * 4. Unknown-operation fallback when the method has no family mapping.
	 *
	 * @param array<string,mixed> $policy
	 * @param string|null         $operation AI Client method name when known.
	 * @param string|null         $capability_family Pre-resolved family from snapshot (preferred).
	 */
	public static function would_prevent( array $policy, ?string $plugin_basename, ?string $operation = null, ?string $capability_family = null ): bool {
		if ( ! empty( $policy['kill_switch'] ) ) {
			$exceptions = self::get_kill_switch_exceptions( $policy );
			if ( $plugin_basename && in_array( $plugin_basename, $exceptions, true ) ) {
				// Fall through to normal rules for exceptions — do not widen access.
			} else {
				return true;
			}
		}

		$instance = self::instance();
		return $instance->decide( $policy, $plugin_basename, $operation, $capability_family );
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
	 * @param string|null         $capability_family Pre-resolved family (from snapshot inference).
	 */
	private function decide( array $policy, ?string $plugin_basename, ?string $operation = null, ?string $capability_family = null ): bool {
		$plugin_decision = $this->plugin_level_decision( $policy, $plugin_basename );

		// Outer gate: plugin deny blocks every family.
		if ( 'deny' === $plugin_decision ) {
			return true;
		}

		// No operation context (e.g. suggested-rules UI) → plugin-level only.
		if ( null === $operation || '' === $operation ) {
			return false;
		}

		$family = ( is_string( $capability_family ) && '' !== $capability_family )
			? $capability_family
			: Operations::family_from_operation( $operation );

		if ( Operations::FAMILY_UNKNOWN === $family ) {
			return $this->unknown_operation_prevents( $policy );
		}

		$family_rule = $this->family_rule_for_plugin( $policy, $plugin_basename, $family );
		if ( 'deny' === $family_rule ) {
			return true;
		}
		if ( 'allow' === $family_rule ) {
			return false;
		}

		// Inherit: plugin already allowed.
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

		update_option( Plugin::OPTION_KEY, $policy, false );
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
