<?php
/**
 * AICAC-UNDO: automatic policy snapshots + one-click restore (#130).
 *
 * Snapshots the full policy before every Policy::save_policy write (max 5,
 * newest first). Restore writes through save_policy so the restore itself is
 * snapshotted (undo-the-undo).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Policy_Snapshots {

	public const OPTION_KEY = 'handl_aicac_policy_snapshots';

	/** Maximum retained snapshots (newest first). */
	public const MAX = 5;

	/** Transient TTL for confirm-before-restore (seconds). */
	public const PREVIEW_TTL = 600;

	/**
	 * Capture the current stored policy before a save overwrites it.
	 *
	 * No-op when nothing is stored yet (first save has nothing to restore to).
	 *
	 * @param int|null $now Injectable clock for tests.
	 */
	public static function capture_before_save( ?int $now = null ): void {
		$raw = get_option( Plugin::OPTION_KEY );
		if ( ! is_array( $raw ) ) {
			return;
		}

		// Normalized full shape — restore will re-sanitize via save_policy.
		$policy = Policy::get_policy();
		self::push( $policy, $now );
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param int|null            $now
	 */
	public static function push( array $policy, ?int $now = null ): void {
		$ts = null !== $now ? (int) $now : time();
		if ( $ts <= 0 ) {
			$ts = time();
		}

		// Strip runtime-only / derived keys that should not round-trip as "dirty".
		$clean = self::strip_runtime_keys( $policy );

		$entry = array(
			'ts'      => $ts,
			'policy'  => $clean,
			'summary' => self::summary_line( $clean ),
		);

		$list = self::all();
		array_unshift( $list, $entry );
		if ( count( $list ) > self::MAX ) {
			$list = array_slice( $list, 0, self::MAX );
		}

		update_option( self::OPTION_KEY, $list, false );
	}

	/**
	 * @return list<array{ts:int,policy:array<string,mixed>,summary:string}>
	 */
	public static function all(): array {
		$raw = get_option( self::OPTION_KEY );
		if ( ! is_array( $raw ) ) {
			return array();
		}

		$out = array();
		foreach ( $raw as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			$policy = isset( $row['policy'] ) && is_array( $row['policy'] ) ? $row['policy'] : null;
			if ( $ts <= 0 || null === $policy ) {
				continue;
			}
			$summary = isset( $row['summary'] ) && is_string( $row['summary'] ) && '' !== $row['summary']
				? $row['summary']
				: self::summary_line( $policy );
			$out[] = array(
				'ts'      => $ts,
				'policy'  => $policy,
				'summary' => $summary,
			);
		}

		return $out;
	}

	/**
	 * Newest snapshot, or null when the stack is empty.
	 *
	 * @return array{ts:int,policy:array<string,mixed>,summary:string}|null
	 */
	public static function latest(): ?array {
		$list = self::all();
		return $list[0] ?? null;
	}

	/**
	 * Human one-liner: "3 rules, default Allow, Emergency stop off".
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function summary_line( array $policy ): string {
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] ) ? $policy['plugins'] : array();
		$rule_count = 0;
		foreach ( $plugins as $rule ) {
			$rule = (string) $rule;
			if ( 'allow' === $rule || 'deny' === $rule ) {
				++$rule_count;
			}
		}

		$default = ( ( $policy['default'] ?? 'allow' ) === 'deny' )
			? __( 'Deny', 'handl-ai-connector-access-control' )
			: __( 'Allow', 'handl-ai-connector-access-control' );

		$kill = ! empty( $policy['kill_switch'] )
			? __( 'Emergency stop on', 'handl-ai-connector-access-control' )
			: __( 'Emergency stop off', 'handl-ai-connector-access-control' );

		/* translators: 1: plugin rule count, 2: Allow/Deny default, 3: Emergency stop state */
		return sprintf(
			/* translators: 1: number of plugin rules, 2: default policy label, 3: emergency stop state */
			_n(
				'%1$d rule, default %2$s, %3$s',
				'%1$d rules, default %2$s, %3$s',
				$rule_count,
				'handl-ai-connector-access-control'
			),
			$rule_count,
			$default,
			$kill
		);
	}

	/**
	 * Diff current live policy vs a snapshot for the confirm table.
	 *
	 * @param array<string,mixed> $current
	 * @param array<string,mixed> $snapshot_policy
	 * @return list<array{key:string,label:string,current:string,new:string}>
	 */
	public static function diff_rows( array $current, array $snapshot_policy ): array {
		$keys = array(
			'default',
			'audit_only',
			'log_enabled',
			'kill_switch',
			'shadow_block_enabled',
			'unknown_operation',
			'role_gate_enabled',
			'alert_on_deny',
			'alert_on_shadow',
			'alert_mode',
			'plugins',
			'operations',
			'denied_tools',
			'model_force_plugins',
			'spend_threshold_site',
		);

		$rows = array();
		foreach ( $keys as $key ) {
			$cur_val = $current[ $key ] ?? null;
			$new_val = $snapshot_policy[ $key ] ?? null;
			if ( self::values_equal( $key, $cur_val, $new_val ) ) {
				continue;
			}
			$rows[] = array(
				'key'     => $key,
				'label'   => self::field_label( $key ),
				'current' => self::format_value( $key, $cur_val ),
				'new'     => self::format_value( $key, $new_val ),
			);
		}

		return $rows;
	}

	/**
	 * Restore the newest snapshot via Policy::save_policy (which re-snapshots first).
	 *
	 * @return array{ok:bool,status:string,error?:string,ts?:int}
	 */
	public static function restore_latest(): array {
		$latest = self::latest();
		if ( null === $latest ) {
			return array(
				'ok'     => false,
				'status' => 'error',
				'error'  => 'empty',
			);
		}

		$policy = $latest['policy'];
		if ( ! is_array( $policy ) ) {
			return array(
				'ok'     => false,
				'status' => 'error',
				'error'  => 'invalid',
			);
		}

		// save_policy snapshots the live policy first (undo-the-undo), then writes this.
		Policy::save_policy( $policy );

		$ts = (int) $latest['ts'];
		self::append_restore_audit( $ts );

		return array(
			'ok'     => true,
			'status' => 'restored',
			'ts'     => $ts,
		);
	}

	/**
	 * @param int $snapshot_ts Unix time of the restored snapshot (for audit).
	 */
	public static function append_restore_audit( int $snapshot_ts ): void {
		Policy::append_log_event(
			array(
				'ts'       => time(),
				'decision' => 'policy_restored',
				'channel'  => 'policy_restore',
				'plugin'   => null,
				// Keep a machine-readable pointer; no secrets leave the site.
				'snapshot_ts' => $snapshot_ts,
			)
		);
	}

	public static function preview_transient_key( int $user_id ): string {
		return 'handl_aicac_undo_preview_' . $user_id;
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array<string,mixed>
	 */
	private static function strip_runtime_keys( array $policy ): array {
		unset(
			$policy['_weekly_report_write'],
			$policy['_weekly_report_value'],
			$policy['denied_abilities'],
			$policy['model_force_enabled'],
			$policy['model_force_provider'],
			$policy['model_force_model']
		);
		return $policy;
	}

	/**
	 * @param mixed $a
	 * @param mixed $b
	 */
	private static function values_equal( string $key, $a, $b ): bool {
		return self::normalize( $key, $a ) === self::normalize( $key, $b );
	}

	/**
	 * @param mixed $raw
	 * @return mixed
	 */
	private static function normalize( string $key, $raw ) {
		switch ( $key ) {
			case 'default':
				return ( 'deny' === $raw ) ? 'deny' : 'allow';
			case 'audit_only':
			case 'log_enabled':
			case 'kill_switch':
			case 'shadow_block_enabled':
			case 'role_gate_enabled':
			case 'alert_on_deny':
			case 'alert_on_shadow':
				return (bool) $raw;
			case 'unknown_operation':
				$v = (string) $raw;
				return in_array( $v, array( 'inherit', 'allow', 'deny' ), true ) ? $v : 'inherit';
			case 'alert_mode':
				return Alerts::sanitize_mode( $raw ?? 'immediate' );
			case 'spend_threshold_site':
				return Spend_Threshold::sanitize_threshold( $raw );
			case 'plugins':
				if ( ! is_array( $raw ) ) {
					return array();
				}
				$out = array();
				foreach ( $raw as $basename => $rule ) {
					$basename = (string) $basename;
					$rule     = (string) $rule;
					if ( '' !== $basename && ( 'allow' === $rule || 'deny' === $rule ) ) {
						$out[ $basename ] = $rule;
					}
				}
				ksort( $out, SORT_STRING );
				return $out;
			case 'operations':
				return is_array( $raw ) ? Policy::sanitize_operations( $raw ) : array();
			case 'denied_tools':
				return is_array( $raw ) ? Policy::sanitize_denied_tools( $raw ) : array();
			case 'model_force_plugins':
				return is_array( $raw ) ? Model_Force::sanitize_force_map( $raw ) : array();
			default:
				return $raw;
		}
	}

	private static function field_label( string $key ): string {
		$labels = array(
			'default'              => __( 'Default policy', 'handl-ai-connector-access-control' ),
			'audit_only'           => __( 'Learn mode (observe only)', 'handl-ai-connector-access-control' ),
			'log_enabled'          => __( 'Activity logging', 'handl-ai-connector-access-control' ),
			'kill_switch'          => __( 'Emergency stop', 'handl-ai-connector-access-control' ),
			'shadow_block_enabled' => __( 'Block direct AI connections', 'handl-ai-connector-access-control' ),
			'unknown_operation'    => __( 'Unknown AI operations', 'handl-ai-connector-access-control' ),
			'role_gate_enabled'    => __( 'Limit by role', 'handl-ai-connector-access-control' ),
			'alert_on_deny'        => __( 'Blocked-call email alerts', 'handl-ai-connector-access-control' ),
			'alert_on_shadow'      => __( 'Direct-connection email alerts', 'handl-ai-connector-access-control' ),
			'alert_mode'           => __( 'Alert timing', 'handl-ai-connector-access-control' ),
			'plugins'              => __( 'Per-plugin rules', 'handl-ai-connector-access-control' ),
			'operations'           => __( 'Capability-family rules', 'handl-ai-connector-access-control' ),
			'denied_tools'         => __( 'Blocked AI tools', 'handl-ai-connector-access-control' ),
			'model_force_plugins'  => __( 'Model routes', 'handl-ai-connector-access-control' ),
			'spend_threshold_site' => __( 'Site estimated-spend alert', 'handl-ai-connector-access-control' ),
		);

		return $labels[ $key ] ?? $key;
	}

	/**
	 * @param mixed $value
	 */
	private static function format_value( string $key, $value ): string {
		$value = self::normalize( $key, $value );

		switch ( $key ) {
			case 'default':
				return ( 'deny' === $value )
					? __( 'Deny', 'handl-ai-connector-access-control' )
					: __( 'Allow', 'handl-ai-connector-access-control' );
			case 'audit_only':
			case 'log_enabled':
			case 'kill_switch':
			case 'shadow_block_enabled':
			case 'role_gate_enabled':
			case 'alert_on_deny':
			case 'alert_on_shadow':
				return $value
					? __( 'On', 'handl-ai-connector-access-control' )
					: __( 'Off', 'handl-ai-connector-access-control' );
			case 'unknown_operation':
				if ( 'allow' === $value ) {
					return __( 'Allow', 'handl-ai-connector-access-control' );
				}
				if ( 'deny' === $value ) {
					return __( 'Deny', 'handl-ai-connector-access-control' );
				}
				return __( 'Follow plugin rule', 'handl-ai-connector-access-control' );
			case 'alert_mode':
				return ( 'digest' === $value )
					? __( 'Hourly summary', 'handl-ai-connector-access-control' )
					: __( 'Immediate', 'handl-ai-connector-access-control' );
			case 'plugins':
				if ( ! is_array( $value ) || empty( $value ) ) {
					return __( '(none)', 'handl-ai-connector-access-control' );
				}
				/* translators: %d: count of per-plugin rules */
				return sprintf(
					_n( '%d plugin rule', '%d plugin rules', count( $value ), 'handl-ai-connector-access-control' ),
					count( $value )
				);
			case 'operations':
				if ( ! is_array( $value ) || empty( $value ) ) {
					return __( '(none)', 'handl-ai-connector-access-control' );
				}
				/* translators: %d: count of plugins with family rules */
				return sprintf(
					_n( '%d plugin with AI-type rules', '%d plugins with AI-type rules', count( $value ), 'handl-ai-connector-access-control' ),
					count( $value )
				);
			case 'denied_tools':
				if ( ! is_array( $value ) || empty( $value ) ) {
					return __( '(none)', 'handl-ai-connector-access-control' );
				}
				/* translators: %d: count of blocked tools */
				return sprintf(
					_n( '%d blocked tool', '%d blocked tools', count( $value ), 'handl-ai-connector-access-control' ),
					count( $value )
				);
			case 'model_force_plugins':
				if ( ! is_array( $value ) || empty( $value ) ) {
					return __( '(none)', 'handl-ai-connector-access-control' );
				}
				/* translators: %d: count of model routes */
				return sprintf(
					_n( '%d model route', '%d model routes', count( $value ), 'handl-ai-connector-access-control' ),
					count( $value )
				);
			case 'spend_threshold_site':
				if ( null === $value || '' === $value ) {
					return __( 'No alert', 'handl-ai-connector-access-control' );
				}
				// Dollar amount for the confirm table (not a raw number).
				$amount = is_numeric( $value ) ? (float) $value : 0.0;
				return '$' . rtrim( rtrim( number_format( $amount, 2, '.', '' ), '0' ), '.' );
			default:
				if ( is_bool( $value ) ) {
					return $value ? __( 'On', 'handl-ai-connector-access-control' ) : __( 'Off', 'handl-ai-connector-access-control' );
				}
				if ( is_array( $value ) ) {
					$json = wp_json_encode( $value );
					return is_string( $json ) ? $json : '';
				}
				return (string) $value;
		}
	}
}
