<?php
/**
 * AICAC-RULE-TEST: pinned policy assertions re-checked on every save (#153).
 *
 * Checks are sample calls (plugin + optional AI type + optional tool) with an
 * expected Allow/Deny outcome. Evaluation reuses Policy_Simulator::evaluate_call
 * so results match the Rules-tab simulator and live Policy::evaluate().
 *
 * Zero checks configured → no gating and no Dashboard surface.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Policy_Checks {
	/** Stored list of checks (not part of the policy option). */
	public const OPTION_KEY = 'handl_aicac_policy_checks';

	/** Dashboard open failures after an override (until checks pass or are edited). */
	public const FAILING_OPTION_KEY = 'handl_aicac_policy_checks_failing';

	/** Transient TTL for pending save confirmation (seconds). */
	public const PREVIEW_TTL = 600;

	public const MAX_CHECKS = 20;

	/**
	 * @return list<array{id:string,label:string,plugin:string,family:string,tool:string,expected:string}>
	 */
	public static function get_all(): array {
		$raw = get_option( self::OPTION_KEY, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$check = self::sanitize_check( $row );
			if ( null !== $check ) {
				$out[] = $check;
			}
		}
		return array_slice( $out, 0, self::MAX_CHECKS );
	}

	/**
	 * @param list<array<string,mixed>> $checks
	 */
	public static function save_all( array $checks ): void {
		$clean = array();
		foreach ( $checks as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$check = self::sanitize_check( $row );
			if ( null !== $check ) {
				$clean[] = $check;
			}
			if ( count( $clean ) >= self::MAX_CHECKS ) {
				break;
			}
		}
		if ( empty( $clean ) ) {
			delete_option( self::OPTION_KEY );
		} else {
			update_option( self::OPTION_KEY, $clean, false );
		}
		// Re-evaluate open Dashboard failures against the live policy after edits.
		self::refresh_failing_dashboard( Policy::get_policy() );
	}

	/**
	 * @param array<string,mixed> $raw
	 * @return array{id:string,label:string,plugin:string,family:string,tool:string,expected:string}|null
	 */
	public static function sanitize_check( array $raw ): ?array {
		$plugin = isset( $raw['plugin'] ) ? Plugin_Profile::sanitize_plugin( (string) $raw['plugin'] ) : '';
		if ( '' === $plugin ) {
			return null;
		}

		$expected = isset( $raw['expected'] ) ? sanitize_key( (string) $raw['expected'] ) : '';
		if ( 'allow' !== $expected && 'deny' !== $expected ) {
			return null;
		}

		$family = isset( $raw['family'] ) ? sanitize_key( (string) $raw['family'] ) : '';
		$labels = Operations::family_labels();
		if ( '' !== $family && ! isset( $labels[ $family ] ) ) {
			$family = '';
		}

		$tool = isset( $raw['tool'] ) ? sanitize_text_field( (string) $raw['tool'] ) : '';
		$tool = trim( $tool );
		if ( strlen( $tool ) > 120 ) {
			$tool = substr( $tool, 0, 120 );
		}

		$label = isset( $raw['label'] ) ? sanitize_text_field( (string) $raw['label'] ) : '';
		if ( strlen( $label ) > 120 ) {
			$label = substr( $label, 0, 120 );
		}

		$id = isset( $raw['id'] ) ? sanitize_key( (string) $raw['id'] ) : '';
		if ( '' === $id || strlen( $id ) < 8 ) {
			$id = self::new_id();
		}

		return array(
			'id'       => $id,
			'label'    => $label,
			'plugin'   => $plugin,
			'family'   => $family,
			'tool'     => $tool,
			'expected' => $expected,
		);
	}

	public static function new_id(): string {
		if ( function_exists( 'wp_generate_uuid4' ) ) {
			return 'pc_' . substr( str_replace( '-', '', wp_generate_uuid4() ), 0, 12 );
		}
		return 'pc_' . substr( md5( uniqid( (string) mt_rand(), true ) ), 0, 12 );
	}

	/**
	 * Operation name used for Policy_Simulator::evaluate_call.
	 *
	 * @param array{family?:string} $check
	 */
	public static function operation_for_check( array $check ): string {
		$family = isset( $check['family'] ) ? (string) $check['family'] : '';
		if ( '' !== $family ) {
			return Operations::canonical_operation_for_family( $family );
		}
		// Plugin-level probe: text generation is the common default path.
		return 'generate_text';
	}

	/**
	 * @param array{family?:string} $check
	 */
	public static function capability_family_for_check( array $check ): ?string {
		$family = isset( $check['family'] ) ? (string) $check['family'] : '';
		return '' !== $family ? $family : null;
	}

	/**
	 * @param array{plugin?:string,family?:string,tool?:string,expected?:string,id?:string,label?:string} $check
	 * @param array<string,mixed>                                                                           $policy
	 * @return array{
	 *   pass:bool,
	 *   expected:string,
	 *   actual:string,
	 *   check:array<string,mixed>,
	 *   eval:array{prevent:bool,reason:string,matched_tools:list<string>},
	 *   verdict:array{allowed:bool,reason:string,chip:string,rule_label:string}
	 * }
	 */
	public static function evaluate_one( array $check, array $policy ): array {
		$san = self::sanitize_check( $check );
		if ( null === $san ) {
			$empty_eval = array(
				'prevent'       => false,
				'reason'        => '',
				'matched_tools' => array(),
			);
			return array(
				'pass'     => false,
				'expected' => 'deny',
				'actual'   => 'allow',
				'check'    => $check,
				'eval'     => $empty_eval,
				'verdict'  => Policy_Simulator::verdict_from_eval( $empty_eval ),
			);
		}

		$tool  = (string) $san['tool'];
		$armed = '' !== $tool ? array( $tool ) : null;
		$eval  = Policy_Simulator::evaluate_call(
			$policy,
			$san['plugin'],
			self::operation_for_check( $san ),
			$armed,
			self::capability_family_for_check( $san )
		);
		$prevent = ! empty( $eval['prevent'] );
		$actual  = $prevent ? 'deny' : 'allow';
		$pass    = $actual === $san['expected'];

		return array(
			'pass'     => $pass,
			'expected' => $san['expected'],
			'actual'   => $actual,
			'check'    => $san,
			'eval'     => $eval,
			'verdict'  => Policy_Simulator::verdict_from_eval( $eval ),
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array{
	 *   total:int,
	 *   failures:list<array{pass:bool,expected:string,actual:string,check:array<string,mixed>,eval:array<string,mixed>,verdict:array<string,mixed>}>,
	 *   results:list<array{pass:bool,expected:string,actual:string,check:array<string,mixed>,eval:array<string,mixed>,verdict:array<string,mixed>}>
	 * }
	 */
	public static function evaluate_all( array $policy ): array {
		$checks  = self::get_all();
		$results = array();
		$fails   = array();
		foreach ( $checks as $check ) {
			$row = self::evaluate_one( $check, $policy );
			$results[] = $row;
			if ( empty( $row['pass'] ) ) {
				$fails[] = $row;
			}
		}
		return array(
			'total'    => count( $checks ),
			'failures' => $fails,
			'results'  => $results,
		);
	}

	public static function preview_transient_key( int $user_id ): string {
		return 'handl_aicac_checks_save_' . $user_id;
	}

	/**
	 * Human one-line for a check (Rules list / Dashboard).
	 *
	 * @param array{label?:string,plugin?:string,family?:string,tool?:string,expected?:string} $check
	 * @param array<string,array<string,mixed>>                                                 $plugins get_plugins() map optional
	 */
	public static function check_label( array $check, array $plugins = array() ): string {
		$label = isset( $check['label'] ) ? trim( (string) $check['label'] ) : '';
		if ( '' !== $label ) {
			return $label;
		}
		$plugin = (string) ( $check['plugin'] ?? '' );
		$name   = $plugin;
		if ( isset( $plugins[ $plugin ]['Name'] ) ) {
			$name = (string) $plugins[ $plugin ]['Name'];
		}
		$family = (string) ( $check['family'] ?? '' );
		$fam_labels = Operations::family_labels();
		$fam_txt = ( '' !== $family && isset( $fam_labels[ $family ] ) )
			? (string) $fam_labels[ $family ]
			: __( 'any AI type', 'handl-ai-connector-access-control' );
		$expected = ( 'allow' === ( $check['expected'] ?? '' ) )
			? __( 'Allow', 'handl-ai-connector-access-control' )
			: __( 'Deny', 'handl-ai-connector-access-control' );
		$tool = trim( (string) ( $check['tool'] ?? '' ) );
		if ( '' !== $tool ) {
			return sprintf(
				/* translators: 1: expected Allow/Deny, 2: plugin name, 3: AI type, 4: tool name */
				__( '%1$s: %2$s · %3$s · tool %4$s', 'handl-ai-connector-access-control' ),
				$expected,
				$name,
				$fam_txt,
				$tool
			);
		}
		return sprintf(
			/* translators: 1: expected Allow/Deny, 2: plugin name, 3: AI type */
			__( '%1$s: %2$s · %3$s', 'handl-ai-connector-access-control' ),
			$expected,
			$name,
			$fam_txt
		);
	}

	/**
	 * @param list<array<string,mixed>> $failures evaluate_one rows
	 * @param string                    $source   manual|preset|restore|import
	 */
	public static function record_override_audit( array $failures, string $source ): void {
		$ids = array();
		foreach ( $failures as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$check = isset( $row['check'] ) && is_array( $row['check'] ) ? $row['check'] : array();
			$id    = isset( $check['id'] ) ? (string) $check['id'] : '';
			if ( '' !== $id ) {
				$ids[] = $id;
			}
		}
		Policy::append_log_event(
			array(
				'ts'             => time(),
				'decision'       => 'policy_checks_override',
				'channel'        => 'policy_checks',
				'plugin'         => null,
				'override_source'=> sanitize_key( $source ),
				'failed_count'   => count( $failures ),
				'failed_ids'     => array_values( array_unique( $ids ) ),
			)
		);
	}

	/**
	 * @param list<array<string,mixed>> $failures
	 */
	public static function set_failing_dashboard( array $failures ): void {
		$store = array();
		foreach ( $failures as $row ) {
			if ( ! is_array( $row ) || empty( $row['check'] ) || ! is_array( $row['check'] ) ) {
				continue;
			}
			$check = self::sanitize_check( $row['check'] );
			if ( null === $check ) {
				continue;
			}
			$store[] = array(
				'check'    => $check,
				'expected' => (string) ( $row['expected'] ?? $check['expected'] ),
				'actual'   => (string) ( $row['actual'] ?? '' ),
				'since'    => time(),
			);
		}
		if ( empty( $store ) ) {
			delete_option( self::FAILING_OPTION_KEY );
			return;
		}
		update_option( self::FAILING_OPTION_KEY, $store, false );
	}

	public static function clear_failing_dashboard(): void {
		delete_option( self::FAILING_OPTION_KEY );
	}

	/**
	 * @return list<array{check:array<string,mixed>,expected:string,actual:string,since:int}>
	 */
	public static function get_failing_dashboard(): array {
		$raw = get_option( self::FAILING_OPTION_KEY, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $row ) {
			if ( ! is_array( $row ) || empty( $row['check'] ) || ! is_array( $row['check'] ) ) {
				continue;
			}
			$check = self::sanitize_check( $row['check'] );
			if ( null === $check ) {
				continue;
			}
			$out[] = array(
				'check'    => $check,
				'expected' => (string) ( $row['expected'] ?? '' ),
				'actual'   => (string) ( $row['actual'] ?? '' ),
				'since'    => isset( $row['since'] ) ? (int) $row['since'] : 0,
			);
		}
		return $out;
	}

	/**
	 * Keep Dashboard failures in sync after a successful clean save or check edits.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function refresh_failing_dashboard( array $policy ): void {
		$report = self::evaluate_all( $policy );
		if ( empty( $report['failures'] ) ) {
			self::clear_failing_dashboard();
			return;
		}
		// Only keep Dashboard noise if we already had an open override surface,
		// or if the operator just overrode — callers that want to open the surface
		// should call set_failing_dashboard() directly.
		if ( empty( self::get_failing_dashboard() ) ) {
			return;
		}
		self::set_failing_dashboard( $report['failures'] );
	}

	/**
	 * After a successful save (no open failures): clear Dashboard.
	 * After override: pin failures. After clean save that still fails (should not): pin.
	 *
	 * @param array<string,mixed> $policy
	 * @param list<array<string,mixed>>|null $override_failures null = not an override path
	 */
	public static function after_policy_saved( array $policy, ?array $override_failures = null ): void {
		if ( null !== $override_failures ) {
			if ( empty( $override_failures ) ) {
				self::clear_failing_dashboard();
			} else {
				self::set_failing_dashboard( $override_failures );
			}
			return;
		}
		$report = self::evaluate_all( $policy );
		if ( empty( $report['failures'] ) ) {
			self::clear_failing_dashboard();
		}
	}
}
