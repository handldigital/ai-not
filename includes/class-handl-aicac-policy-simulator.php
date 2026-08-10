<?php
/**
 * Dry-run policy simulator (AICAC-SIM).
 *
 * Preview allow/deny outcomes for draft settings without saving and without
 * sending any AI Client or outbound request. Always calls Policy::evaluate()
 * — the same decision function live enforcement uses.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Policy_Simulator {
	public const DEFAULT_REPLAY_LIMIT = 100;
	public const MAX_REPLAY_LIMIT     = 1000;
	public const MAX_LIST_ROWS        = 20;

	/**
	 * Evaluate one hypothetical call under a (draft or saved) policy.
	 *
	 * Thin wrapper so callers and tests pin to a single named entry point that
	 * must remain Policy::evaluate — never a parallel decision tree.
	 *
	 * @param array<string,mixed> $policy
	 * @param list<string>|null   $armed_tools
	 * @return array{prevent:bool,reason:string,matched_tools:list<string>}
	 */
	public static function evaluate_call(
		array $policy,
		?string $plugin_basename,
		?string $operation = null,
		?array $armed_tools = null,
		?string $capability_family = null
	): array {
		return Policy::evaluate( $policy, $plugin_basename, $operation, $armed_tools, $capability_family );
	}

	/**
	 * Human verdict chip fields from an evaluate() result.
	 *
	 * @param array{prevent?:bool,reason?:string,matched_tools?:list<string>} $eval
	 * @return array{allowed:bool,reason:string,chip:string,rule_label:string}
	 */
	public static function verdict_from_eval( array $eval ): array {
		$prevent = ! empty( $eval['prevent'] );
		$reason  = isset( $eval['reason'] ) ? (string) $eval['reason'] : '';
		$label   = self::reason_label( $reason );

		if ( ! $prevent ) {
			return array(
				'allowed'    => true,
				'reason'     => '',
				'chip'       => __( 'Allowed', 'handl-ai-connector-access-control' ),
				'rule_label' => '',
			);
		}

		if ( 'kill_switch' === $reason ) {
			$chip = __( 'Blocked by Emergency stop', 'handl-ai-connector-access-control' );
		} else {
			$chip = sprintf(
				/* translators: %s: short rule name that decided the block */
				__( 'Blocked by rule: %s', 'handl-ai-connector-access-control' ),
				$label
			);
		}

		return array(
			'allowed'    => false,
			'reason'     => $reason,
			'chip'       => $chip,
			'rule_label' => $label,
		);
	}

	/**
	 * Short rule name for chips / lists (not the longer Activity-log denial string).
	 */
	public static function reason_label( string $reason ): string {
		$map = array(
			'kill_switch'       => __( 'Emergency stop', 'handl-ai-connector-access-control' ),
			'role'              => __( 'User role rule', 'handl-ai-connector-access-control' ),
			'plugin'            => __( 'Plugin rule', 'handl-ai-connector-access-control' ),
			'capability_family' => __( 'AI type rule', 'handl-ai-connector-access-control' ),
			'unknown_operation' => __( 'Unknown operation rule', 'handl-ai-connector-access-control' ),
			'tool_armed'        => __( 'Blocked tool rule', 'handl-ai-connector-access-control' ),
			'ability_armed'     => __( 'Blocked tool rule', 'handl-ai-connector-access-control' ),
		);
		if ( isset( $map[ $reason ] ) ) {
			return $map[ $reason ];
		}
		if ( '' === $reason ) {
			return __( 'Rule', 'handl-ai-connector-access-control' );
		}
		return $reason;
	}

	/**
	 * Diff draft policy vs saved policy over retained audit rows.
	 *
	 * Direct-HTTP observe rows are skipped (not governed by Policy::evaluate).
	 *
	 * @param array<string,mixed>      $saved_policy
	 * @param array<string,mixed>      $draft_policy
	 * @param array<int,mixed>         $log
	 * @return array{
	 *   scanned:int,
	 *   skipped:int,
	 *   empty:bool,
	 *   empty_reason:string,
	 *   now_blocked:list<array{plugin:string,operation:string,reason:string}>,
	 *   now_allowed:list<array{plugin:string,operation:string,reason:string}>,
	 *   now_blocked_count:int,
	 *   now_allowed_count:int,
	 *   unchanged:int
	 * }
	 */
	public static function replay_diff(
		array $saved_policy,
		array $draft_policy,
		array $log,
		int $limit = self::DEFAULT_REPLAY_LIMIT,
		?array $retention_meta = null
	): array {
		$limit = self::sanitize_replay_limit( $limit );
		$slice = self::take_recent_governable_rows( $log, $limit );

		$now_blocked = array();
		$now_allowed = array();
		$unchanged   = 0;
		$listed_b    = 0;
		$listed_a    = 0;

		foreach ( $slice['rows'] as $row ) {
			$plugin    = self::row_plugin( $row );
			$operation = self::row_operation( $row );
			$family    = self::row_family( $row, $operation );
			$armed     = self::row_armed_tools( $row );

			$saved_eval = self::evaluate_call( $saved_policy, $plugin !== '' ? $plugin : null, $operation !== '' ? $operation : null, $armed, $family );
			$draft_eval = self::evaluate_call( $draft_policy, $plugin !== '' ? $plugin : null, $operation !== '' ? $operation : null, $armed, $family );

			$saved_block = ! empty( $saved_eval['prevent'] );
			$draft_block = ! empty( $draft_eval['prevent'] );

			if ( $saved_block === $draft_block ) {
				++$unchanged;
				continue;
			}

			$entry = array(
				'plugin'    => $plugin,
				'operation' => $operation,
				'reason'    => $draft_block
					? (string) ( $draft_eval['reason'] ?? '' )
					: (string) ( $saved_eval['reason'] ?? '' ),
			);

			if ( $draft_block && ! $saved_block ) {
				++$listed_b;
				if ( count( $now_blocked ) < self::MAX_LIST_ROWS ) {
					$now_blocked[] = $entry;
				}
			} elseif ( ! $draft_block && $saved_block ) {
				++$listed_a;
				if ( count( $now_allowed ) < self::MAX_LIST_ROWS ) {
					$now_allowed[] = $entry;
				}
			}
		}

		$empty        = 0 === $slice['scanned'] && 0 === $slice['skipped_governable'];
		$empty_reason = '';
		if ( $empty ) {
			$empty_reason = self::empty_log_explanation( $retention_meta ?? array(), is_array( $log ) ? count( $log ) : 0 );
		} elseif ( 0 === $slice['scanned'] && $slice['skipped_total'] > 0 ) {
			$empty_reason = __( 'The saved activity only contains direct connections outside the AI Client. These rules do not control those calls, so there is nothing to replay.', 'handl-ai-connector-access-control' );
		}

		return array(
			'scanned'           => $slice['scanned'],
			'skipped'           => $slice['skipped_total'],
			'empty'             => $empty || ( 0 === $slice['scanned'] ),
			'empty_reason'      => $empty_reason,
			'now_blocked'       => $now_blocked,
			'now_allowed'       => $now_allowed,
			'now_blocked_count' => $listed_b,
			'now_allowed_count' => $listed_a,
			'unchanged'         => $unchanged,
		);
	}

	/**
	 * @param mixed $limit Raw limit.
	 */
	public static function sanitize_replay_limit( $limit ): int {
		$n = (int) $limit;
		if ( $n < 1 ) {
			$n = self::DEFAULT_REPLAY_LIMIT;
		}
		if ( $n > self::MAX_REPLAY_LIMIT ) {
			$n = self::MAX_REPLAY_LIMIT;
		}
		return $n;
	}

	/**
	 * @param array<string,mixed> $meta Keys: log_enabled, audit_only, log_max_age_days, log_limit.
	 */
	public static function empty_log_explanation( array $meta, int $raw_count = 0 ): string {
		$logging = ! empty( $meta['log_enabled'] ) || ! empty( $meta['audit_only'] );
		$max_age = null;
		if ( array_key_exists( 'log_max_age_days', $meta ) ) {
			$max_age = Policy::sanitize_log_max_age_days( $meta['log_max_age_days'] );
		}

		if ( ! $logging ) {
			return __( 'Activity logging is off, so there are no saved calls to replay. Turn on activity logging or Learn mode on the Activity tab, then try again.', 'handl-ai-connector-access-control' );
		}

		if ( null !== $max_age && 0 === $raw_count ) {
			return sprintf(
				/* translators: %d: maximum log age in days */
				__( 'No activity is saved for the current period. Your %d-day activity limit removed older entries.', 'handl-ai-connector-access-control' ),
				$max_age
			);
		}

		if ( 0 === $raw_count ) {
			return __( 'No activity has been saved yet. After a plugin makes an AI Client call, return here to test your rule changes against it.', 'handl-ai-connector-access-control' );
		}

		return __( 'There are no saved AI Client calls to replay.', 'handl-ai-connector-access-control' );
	}

	/**
	 * Newest-first governable rows, capped at $limit.
	 *
	 * @param array<int,mixed> $log
	 * @return array{rows:list<array<string,mixed>>,scanned:int,skipped_total:int,skipped_governable:int}
	 */
	private static function take_recent_governable_rows( array $log, int $limit ): array {
		$governable = array();
		$skipped    = 0;

		// Log is oldest→newest; walk newest first.
		for ( $i = count( $log ) - 1; $i >= 0; $i-- ) {
			$row = $log[ $i ];
			if ( ! is_array( $row ) || self::row_is_ungovernable( $row ) ) {
				++$skipped;
				continue;
			}
			if ( count( $governable ) >= $limit ) {
				++$skipped;
				continue;
			}
			$governable[] = $row;
		}

		return array(
			'rows'               => $governable,
			'scanned'            => count( $governable ),
			'skipped_total'      => $skipped,
			'skipped_governable' => 0,
		);
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function row_is_ungovernable( array $row ): bool {
		$operation = self::row_operation( $row );
		$decision  = isset( $row['decision'] ) ? (string) $row['decision'] : '';
		if ( 'direct_http' === $operation || 'observe' === $decision ) {
			return true;
		}
		return false;
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function row_plugin( array $row ): string {
		return isset( $row['plugin'] ) && is_string( $row['plugin'] ) ? (string) $row['plugin'] : '';
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function row_operation( array $row ): string {
		return isset( $row['operation'] ) ? (string) $row['operation'] : '';
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function row_family( array $row, string $operation ): ?string {
		if ( isset( $row['capability_family'] ) && is_string( $row['capability_family'] ) && '' !== $row['capability_family'] ) {
			return (string) $row['capability_family'];
		}
		if ( '' === $operation ) {
			return null;
		}
		return Operations::family_from_operation( $operation );
	}

	/**
	 * @param array<string,mixed> $row
	 * @return list<string>
	 */
	private static function row_armed_tools( array $row ): array {
		$raw = $row['armed_tools'] ?? $row['armed_abilities'] ?? array();
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $tool ) {
			$tool = sanitize_text_field( (string) $tool );
			if ( '' !== $tool ) {
				$out[] = $tool;
			}
		}
		return array_values( array_unique( $out ) );
	}
}
