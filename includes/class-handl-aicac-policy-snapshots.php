<?php
/**
 * AICAC-UNDO (#130) + AICAC-HISTORY (#107): policy snapshots, restore, and
 * who/when/what change trail.
 *
 * Snapshots the full policy before every Policy::save_policy write (max 5,
 * newest first). Restore writes through save_policy so the restore itself is
 * snapshotted (undo-the-undo).
 *
 * History (#107): each save also records actor + before→after change lines on
 * the snapshot and in a longer lightweight trail (separate option; not purged
 * by activity log TTL). No parallel write path — same save_policy funnel.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Policy_Snapshots {

	public const OPTION_KEY = 'handl_aicac_policy_snapshots';

	/** Lightweight who/when/summary trail (survives full-snapshot rotation). */
	public const HISTORY_OPTION_KEY = 'handl_aicac_policy_history';

	/** Maximum retained snapshots (newest first). */
	public const MAX = 5;

	/** Maximum retained history rows (newest first). Filterable via history_max(). */
	public const HISTORY_MAX = 200;

	/** Transient TTL for confirm-before-restore (seconds). */
	public const PREVIEW_TTL = 600;

	/**
	 * Bounded history retention. Default HISTORY_MAX (200); filterable.
	 *
	 * Filter: `handl_aicac_policy_history_max` — clamped to [20, 1000].
	 */
	public static function history_max(): int {
		$max = (int) apply_filters( 'handl_aicac_policy_history_max', self::HISTORY_MAX );
		if ( $max < 20 ) {
			$max = 20;
		}
		if ( $max > 1000 ) {
			$max = 1000;
		}
		return $max;
	}

	/**
	 * Capture the current stored policy before a save overwrites it.
	 *
	 * No-op when nothing is stored yet (first save has nothing to restore to).
	 *
	 * @param array<string,mixed>|null $incoming Sanitized policy about to be written (for diff).
	 * @param int|null                 $now      Injectable clock for tests.
	 */
	public static function capture_before_save( ?array $incoming = null, ?int $now = null ): void {
		$raw = get_option( Plugin::OPTION_KEY );
		if ( ! is_array( $raw ) ) {
			return;
		}

		// Normalized full shape — restore will re-sanitize via save_policy.
		$policy = Policy::get_policy();
		self::push( $policy, $incoming, $now );
	}

	/**
	 * @param array<string,mixed>      $policy   Policy state being snapshotted (before overwrite).
	 * @param array<string,mixed>|null $incoming Sanitized policy about to be written.
	 * @param int|null                 $now
	 */
	public static function push( array $policy, ?array $incoming = null, ?int $now = null ): void {
		$ts = null !== $now ? (int) $now : time();
		if ( $ts <= 0 ) {
			$ts = time();
		}

		// Strip runtime-only / derived keys that should not round-trip as "dirty".
		$clean  = self::strip_runtime_keys( $policy );
		$actor  = self::detect_actor();
		$after  = null !== $incoming ? self::strip_runtime_keys( $incoming ) : null;
		$changes = null !== $after ? self::change_lines( $clean, $after ) : array();

		$entry = array(
			'ts'      => $ts,
			'policy'  => $clean,
			'summary' => self::summary_line( $clean ),
			'actor'   => $actor,
			'changes' => $changes,
		);

		$list = self::all();
		array_unshift( $list, $entry );
		if ( count( $list ) > self::MAX ) {
			$list = array_slice( $list, 0, self::MAX );
		}

		update_option( self::OPTION_KEY, $list, false );

		// History trail: only when something actually changed (avoid no-op spam).
		if ( ! empty( $changes ) ) {
			self::append_history(
				array(
					'ts'      => $ts,
					'actor'   => $actor,
					'changes' => $changes,
					'summary' => self::history_summary_line( $changes ),
				)
			);
		}
	}

	/**
	 * @return list<array{ts:int,policy:array<string,mixed>,summary:string,actor:array<string,mixed>,changes:list<string>}>
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
			$actor = isset( $row['actor'] ) && is_array( $row['actor'] )
				? self::sanitize_actor( $row['actor'] )
				: self::empty_actor();
			$changes = self::sanitize_change_lines( $row['changes'] ?? array() );
			$out[]   = array(
				'ts'      => $ts,
				'policy'  => $policy,
				'summary' => $summary,
				'actor'   => $actor,
				'changes' => $changes,
			);
		}

		return $out;
	}

	/**
	 * Newest snapshot, or null when the stack is empty.
	 *
	 * @return array{ts:int,policy:array<string,mixed>,summary:string,actor:array<string,mixed>,changes:list<string>}|null
	 */
	public static function latest(): ?array {
		$list = self::all();
		return $list[0] ?? null;
	}

	/**
	 * Lightweight change history (newest first). Survives full-snapshot rotation
	 * and is not touched by activity-log TTL prune.
	 *
	 * @return list<array{ts:int,actor:array<string,mixed>,changes:list<string>,summary:string}>
	 */
	public static function history(): array {
		$raw = get_option( self::HISTORY_OPTION_KEY );
		if ( ! is_array( $raw ) ) {
			return array();
		}

		$out = array();
		foreach ( $raw as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts <= 0 ) {
				continue;
			}
			$changes = self::sanitize_change_lines( $row['changes'] ?? array() );
			if ( empty( $changes ) ) {
				continue;
			}
			$actor   = isset( $row['actor'] ) && is_array( $row['actor'] )
				? self::sanitize_actor( $row['actor'] )
				: self::empty_actor();
			$summary = isset( $row['summary'] ) && is_string( $row['summary'] ) && '' !== $row['summary']
				? self::truncate_text( $row['summary'], 240 )
				: self::history_summary_line( $changes );
			$out[]   = array(
				'ts'      => $ts,
				'actor'   => $actor,
				'changes' => $changes,
				'summary' => $summary,
			);
		}

		return $out;
	}

	/**
	 * @param array{ts:int,actor:array<string,mixed>,changes:list<string>,summary:string} $entry
	 */
	public static function append_history( array $entry ): void {
		$list = self::history();
		array_unshift( $list, $entry );
		$max = self::history_max();
		if ( count( $list ) > $max ) {
			$list = array_slice( $list, 0, $max );
		}
		update_option( self::HISTORY_OPTION_KEY, $list, false );
	}

	/**
	 * Who triggered the current write (user, WP-CLI, REST, cron, or system).
	 *
	 * @return array{type:string,user_id:int,login:string}
	 */
	public static function detect_actor(): array {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return array(
				'type'    => 'wp-cli',
				'user_id' => (int) get_current_user_id(),
				'login'   => self::login_for_user_id( (int) get_current_user_id() ),
			);
		}
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			return array(
				'type'    => 'cron',
				'user_id' => 0,
				'login'   => '',
			);
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			$uid = (int) get_current_user_id();
			return array(
				'type'    => 'rest',
				'user_id' => $uid,
				'login'   => self::login_for_user_id( $uid ),
			);
		}

		$uid = (int) get_current_user_id();
		if ( $uid > 0 ) {
			return array(
				'type'    => 'user',
				'user_id' => $uid,
				'login'   => self::login_for_user_id( $uid ),
			);
		}

		return self::empty_actor();
	}

	/**
	 * Display label for an actor row. Prefer live display_name; fall back to
	 * login captured at write time.
	 *
	 * @param array<string,mixed> $actor
	 */
	public static function actor_display( array $actor ): string {
		$actor = self::sanitize_actor( $actor );
		$type  = $actor['type'];
		$uid   = $actor['user_id'];

		if ( ( 'user' === $type || 'rest' === $type || 'wp-cli' === $type ) && $uid > 0 ) {
			$name = self::display_name_for_user_id( $uid );
			if ( '' === $name && '' !== $actor['login'] ) {
				$name = $actor['login'];
			}
			if ( '' !== $name ) {
				if ( 'rest' === $type ) {
					/* translators: %s: user display name */
					return sprintf( __( '%s (REST API)', 'handl-ai-connector-access-control' ), $name );
				}
				if ( 'wp-cli' === $type ) {
					/* translators: %s: user display name */
					return sprintf( __( '%s (WP-CLI)', 'handl-ai-connector-access-control' ), $name );
				}
				return $name;
			}
		}

		switch ( $type ) {
			case 'wp-cli':
				return __( 'WP-CLI', 'handl-ai-connector-access-control' );
			case 'rest':
				return __( 'REST API', 'handl-ai-connector-access-control' );
			case 'cron':
				return __( 'Scheduled task', 'handl-ai-connector-access-control' );
			default:
				return __( 'System', 'handl-ai-connector-access-control' );
		}
	}

	/**
	 * Human before→after lines for a policy change (secret-safe allowlist).
	 *
	 * Map edits expand to per-item lines so same-count changes stay meaningful.
	 * Recipient/webhook fields never include raw values.
	 *
	 * @param array<string,mixed> $before
	 * @param array<string,mixed> $after
	 * @return list<string>
	 */
	public static function change_lines( array $before, array $after ): array {
		$lines = array();
		foreach ( self::diff_keys() as $key ) {
			$cur_val = $before[ $key ] ?? null;
			$new_val = $after[ $key ] ?? null;
			if ( self::values_equal( $key, $cur_val, $new_val ) ) {
				continue;
			}

			$label = self::field_label( $key );

			if ( self::is_secret_presence_key( $key ) ) {
				$lines[] = self::truncate_text(
					$label . ': ' . self::format_secret_presence_change( $cur_val, $new_val ),
					280
				);
				if ( count( $lines ) >= 40 ) {
					return $lines;
				}
				continue;
			}

			if ( self::is_detail_map_key( $key ) ) {
				foreach ( self::map_item_change_lines( $key, $cur_val, $new_val ) as $item_line ) {
					$lines[] = self::truncate_text( $item_line, 280 );
					if ( count( $lines ) >= 40 ) {
						return $lines;
					}
				}
				continue;
			}

			$from    = self::truncate_text( self::format_value( $key, $cur_val ), 120 );
			$to      = self::truncate_text( self::format_value( $key, $new_val ), 120 );
			$lines[] = self::truncate_text( $label . ': ' . $from . ' → ' . $to, 280 );
			if ( count( $lines ) >= 40 ) {
				return $lines;
			}
		}

		return $lines;
	}

	/**
	 * @param list<string> $changes
	 */
	public static function history_summary_line( array $changes ): string {
		$n = count( $changes );
		if ( $n <= 0 ) {
			return '';
		}
		if ( 1 === $n ) {
			return $changes[0];
		}
		/* translators: 1: first change line, 2: number of additional changes */
		return sprintf(
			__( '%1$s (+%2$d more)', 'handl-ai-connector-access-control' ),
			$changes[0],
			$n - 1
		);
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
	 * Explicit secret-safe allowlist of policy keys eligible for history/restore diffs.
	 *
	 * @return list<string>
	 */
	public static function diff_keys(): array {
		return array(
			'default',
			'audit_only',
			'log_enabled',
			'log_limit',
			'log_max_age_days',
			'kill_switch',
			'kill_switch_exceptions',
			'shadow_block_enabled',
			'shadow_block_exceptions',
			'unknown_operation',
			'role_gate_enabled',
			'allowed_roles',
			'quiet_hours',
			'alert_on_deny',
			'alert_on_shadow',
			'alert_mode',
			'alert_email',
			'alert_webhook_url',
			'new_plugin_review_enabled',
			'new_plugin_interim',
			'plugins',
			'plugin_expires',
			'review_due_days',
			'operations',
			'denied_tools',
			'model_force_plugins',
			'model_force_unattributed',
			'model_force_unattributed_provider',
			'model_force_unattributed_model',
			'est_usd_input_per_m',
			'est_usd_output_per_m',
			'est_usd_provider_rates',
			'spend_threshold_site',
			'spend_threshold_plugins',
			'plugin_budgets',
			'plugin_budget_modes',
			'anomaly_alert_enabled',
			'anomaly_multiplier',
			'anomaly_floor_calls',
			'anomaly_floor_spend',
			'drift_alert_mode',
			'monthly_report_enabled',
			'weekly_report_enabled',
			'governance_digest_enabled',
			'governance_digest_always_send',
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
		$rows = array();
		foreach ( self::diff_keys() as $key ) {
			$cur_val = $current[ $key ] ?? null;
			$new_val = $snapshot_policy[ $key ] ?? null;
			if ( self::values_equal( $key, $cur_val, $new_val ) ) {
				continue;
			}
			if ( self::is_secret_presence_key( $key ) ) {
				$rows[] = array(
					'key'     => $key,
					'label'   => self::field_label( $key ),
					'current' => self::format_secret_presence( $cur_val ),
					'new'     => self::format_secret_presence( $new_val ),
				);
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
	 * Whether a history/snapshot timestamp still has a full restore point.
	 */
	public static function has_full_snapshot_for_ts( int $ts ): bool {
		if ( $ts <= 0 ) {
			return false;
		}
		foreach ( self::all() as $row ) {
			if ( (int) ( $row['ts'] ?? 0 ) === $ts ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @return array{type:string,user_id:int,login:string}
	 */
	private static function empty_actor(): array {
		return array(
			'type'    => 'system',
			'user_id' => 0,
			'login'   => '',
		);
	}

	/**
	 * @param array<string,mixed> $actor
	 * @return array{type:string,user_id:int,login:string}
	 */
	private static function sanitize_actor( array $actor ): array {
		$type = (string) ( $actor['type'] ?? 'system' );
		if ( ! in_array( $type, array( 'user', 'wp-cli', 'rest', 'cron', 'system' ), true ) ) {
			$type = 'system';
		}
		$login = isset( $actor['login'] ) ? sanitize_text_field( (string) $actor['login'] ) : '';
		if ( strlen( $login ) > 60 ) {
			$login = substr( $login, 0, 60 );
		}
		return array(
			'type'    => $type,
			'user_id' => max( 0, (int) ( $actor['user_id'] ?? 0 ) ),
			'login'   => $login,
		);
	}

	/**
	 * @param mixed $raw
	 * @return list<string>
	 */
	private static function sanitize_change_lines( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $line ) {
			if ( ! is_string( $line ) ) {
				continue;
			}
			$line = trim( self::truncate_text( $line, 280 ) );
			if ( '' === $line ) {
				continue;
			}
			$out[] = $line;
			if ( count( $out ) >= 40 ) {
				break;
			}
		}
		return $out;
	}

	private static function truncate_text( string $text, int $max ): string {
		if ( $max < 8 ) {
			$max = 8;
		}
		if ( strlen( $text ) <= $max ) {
			return $text;
		}
		return substr( $text, 0, $max - 1 ) . '…';
	}

	private static function login_for_user_id( int $user_id ): string {
		if ( $user_id <= 0 || ! function_exists( 'get_userdata' ) ) {
			return '';
		}
		$user = get_userdata( $user_id );
		if ( ! $user || empty( $user->user_login ) ) {
			return '';
		}
		return sanitize_text_field( (string) $user->user_login );
	}

	private static function display_name_for_user_id( int $user_id ): string {
		if ( $user_id <= 0 || ! function_exists( 'get_userdata' ) ) {
			return '';
		}
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return '';
		}
		if ( ! empty( $user->display_name ) ) {
			return sanitize_text_field( (string) $user->display_name );
		}
		if ( ! empty( $user->user_login ) ) {
			return sanitize_text_field( (string) $user->user_login );
		}
		return '';
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
	 * @return list<string>
	 */
	private static function detail_map_keys(): array {
		return array(
			'plugins',
			'operations',
			'denied_tools',
			'model_force_plugins',
			'kill_switch_exceptions',
			'shadow_block_exceptions',
			'allowed_roles',
			'plugin_expires',
			'quiet_hours',
			'est_usd_provider_rates',
			'spend_threshold_plugins',
			'plugin_budgets',
			'plugin_budget_modes',
		);
	}

	private static function is_detail_map_key( string $key ): bool {
		return in_array( $key, self::detail_map_keys(), true );
	}

	private static function is_secret_presence_key( string $key ): bool {
		return 'alert_email' === $key || 'alert_webhook_url' === $key;
	}

	/**
	 * @param mixed $raw
	 */
	private static function secret_is_configured( $raw ): bool {
		if ( is_string( $raw ) ) {
			return '' !== trim( $raw );
		}
		return ! empty( $raw );
	}

	/**
	 * @param mixed $raw
	 */
	private static function format_secret_presence( $raw ): string {
		return self::secret_is_configured( $raw )
			? __( 'Configured', 'handl-ai-connector-access-control' )
			: __( 'Not configured', 'handl-ai-connector-access-control' );
	}

	/**
	 * @param mixed $before
	 * @param mixed $after
	 */
	private static function format_secret_presence_change( $before, $after ): string {
		$had  = self::secret_is_configured( $before );
		$has  = self::secret_is_configured( $after );
		$from = $had ? __( 'Configured', 'handl-ai-connector-access-control' ) : __( 'Not configured', 'handl-ai-connector-access-control' );
		if ( ! $had && $has ) {
			$to = __( 'Configured', 'handl-ai-connector-access-control' );
		} elseif ( $had && ! $has ) {
			$to = __( 'Not configured', 'handl-ai-connector-access-control' );
		} else {
			$to = __( 'Updated', 'handl-ai-connector-access-control' );
		}
		return $from . ' → ' . $to;
	}

	/**
	 * Per-item before→after lines for map/list policy fields.
	 *
	 * @param mixed $before
	 * @param mixed $after
	 * @return list<string>
	 */
	private static function map_item_change_lines( string $key, $before, $after ): array {
		$label = self::field_label( $key );
		$none  = __( '(none)', 'handl-ai-connector-access-control' );
		$lines = array();

		switch ( $key ) {
			case 'plugins':
				$a = self::normalize( 'plugins', $before );
				$b = self::normalize( 'plugins', $after );
				$ids = array_unique( array_merge( array_keys( $a ), array_keys( $b ) ) );
				sort( $ids, SORT_STRING );
				foreach ( $ids as $id ) {
					$from = isset( $a[ $id ] ) ? self::format_allow_deny( (string) $a[ $id ] ) : $none;
					$to   = isset( $b[ $id ] ) ? self::format_allow_deny( (string) $b[ $id ] ) : $none;
					if ( $from === $to ) {
						continue;
					}
					$lines[] = sprintf( '%s (%s): %s → %s', $label, $id, $from, $to );
				}
				break;

			case 'operations':
				$a = self::normalize( 'operations', $before );
				$b = self::normalize( 'operations', $after );
				$ids = array_unique( array_merge( array_keys( $a ), array_keys( $b ) ) );
				sort( $ids, SORT_STRING );
				foreach ( $ids as $id ) {
					$from_map = isset( $a[ $id ] ) && is_array( $a[ $id ] ) ? $a[ $id ] : array();
					$to_map   = isset( $b[ $id ] ) && is_array( $b[ $id ] ) ? $b[ $id ] : array();
					$families = array_unique( array_merge( array_keys( $from_map ), array_keys( $to_map ) ) );
					sort( $families, SORT_STRING );
					foreach ( $families as $family ) {
						$from = isset( $from_map[ $family ] ) ? self::format_allow_deny( (string) $from_map[ $family ] ) : $none;
						$to   = isset( $to_map[ $family ] ) ? self::format_allow_deny( (string) $to_map[ $family ] ) : $none;
						if ( $from === $to ) {
							continue;
						}
						$lines[] = sprintf( '%s (%s / %s): %s → %s', $label, $id, $family, $from, $to );
					}
					if ( empty( $from_map ) && empty( $to_map ) ) {
						continue;
					}
					if ( empty( $from_map ) !== empty( $to_map ) && empty( $families ) ) {
						$lines[] = sprintf(
							'%s (%s): %s → %s',
							$label,
							$id,
							empty( $from_map ) ? $none : self::format_operations_plugin( $from_map ),
							empty( $to_map ) ? $none : self::format_operations_plugin( $to_map )
						);
					}
				}
				break;

			case 'denied_tools':
			case 'kill_switch_exceptions':
			case 'shadow_block_exceptions':
			case 'allowed_roles':
				$a = self::normalize( $key, $before );
				$b = self::normalize( $key, $after );
				$a = is_array( $a ) ? $a : array();
				$b = is_array( $b ) ? $b : array();
				$ids = array_unique( array_merge( $a, $b ) );
				sort( $ids, SORT_STRING );
				foreach ( $ids as $id ) {
					$had = in_array( $id, $a, true );
					$has = in_array( $id, $b, true );
					if ( $had === $has ) {
						continue;
					}
					$from = $had ? __( 'Included', 'handl-ai-connector-access-control' ) : $none;
					$to   = $has ? __( 'Included', 'handl-ai-connector-access-control' ) : $none;
					$lines[] = sprintf( '%s (%s): %s → %s', $label, $id, $from, $to );
				}
				break;

			case 'plugin_expires':
				$a = self::normalize( $key, $before );
				$b = self::normalize( $key, $after );
				$ids = array_unique( array_merge( array_keys( $a ), array_keys( $b ) ) );
				sort( $ids, SORT_STRING );
				foreach ( $ids as $id ) {
					$from = isset( $a[ $id ] ) ? self::format_unix_ts( (int) $a[ $id ] ) : $none;
					$to   = isset( $b[ $id ] ) ? self::format_unix_ts( (int) $b[ $id ] ) : $none;
					if ( $from === $to ) {
						continue;
					}
					$lines[] = sprintf( '%s (%s): %s → %s', $label, $id, $from, $to );
				}
				break;

			case 'spend_threshold_plugins':
			case 'plugin_budgets':
				$a = self::normalize( $key, $before );
				$b = self::normalize( $key, $after );
				$ids = array_unique( array_merge( array_keys( $a ), array_keys( $b ) ) );
				sort( $ids, SORT_STRING );
				foreach ( $ids as $id ) {
					$from = isset( $a[ $id ] ) ? self::format_money( $a[ $id ] ) : $none;
					$to   = isset( $b[ $id ] ) ? self::format_money( $b[ $id ] ) : $none;
					if ( $from === $to ) {
						continue;
					}
					$lines[] = sprintf( '%s (%s): %s → %s', $label, $id, $from, $to );
				}
				break;

			case 'plugin_budget_modes':
				$a = self::normalize( 'plugin_budget_modes', $before );
				$b = self::normalize( 'plugin_budget_modes', $after );
				$ids = array_unique( array_merge( array_keys( $a ), array_keys( $b ) ) );
				sort( $ids, SORT_STRING );
				foreach ( $ids as $id ) {
					$from = isset( $a[ $id ] ) ? self::format_budget_mode( (string) $a[ $id ] ) : $none;
					$to   = isset( $b[ $id ] ) ? self::format_budget_mode( (string) $b[ $id ] ) : $none;
					if ( $from === $to ) {
						continue;
					}
					$lines[] = sprintf( '%s (%s): %s → %s', $label, $id, $from, $to );
				}
				break;

			case 'model_force_plugins':
				$a = self::normalize( 'model_force_plugins', $before );
				$b = self::normalize( 'model_force_plugins', $after );
				$ids = array_unique( array_merge( array_keys( $a ), array_keys( $b ) ) );
				sort( $ids, SORT_STRING );
				foreach ( $ids as $id ) {
					$from = isset( $a[ $id ] ) ? self::format_model_force_row( $a[ $id ] ) : $none;
					$to   = isset( $b[ $id ] ) ? self::format_model_force_row( $b[ $id ] ) : $none;
					if ( $from === $to ) {
						continue;
					}
					$lines[] = sprintf( '%s (%s): %s → %s', $label, $id, $from, $to );
				}
				break;

			case 'est_usd_provider_rates':
				$a = self::normalize( 'est_usd_provider_rates', $before );
				$b = self::normalize( 'est_usd_provider_rates', $after );
				$ids = array_unique( array_merge( array_keys( $a ), array_keys( $b ) ) );
				sort( $ids, SORT_STRING );
				foreach ( $ids as $id ) {
					$from = isset( $a[ $id ] ) ? self::format_provider_rate_row( $a[ $id ] ) : $none;
					$to   = isset( $b[ $id ] ) ? self::format_provider_rate_row( $b[ $id ] ) : $none;
					if ( $from === $to ) {
						continue;
					}
					$lines[] = sprintf( '%s (%s): %s → %s', $label, $id, $from, $to );
				}
				break;

			case 'quiet_hours':
				$a = self::normalize( 'quiet_hours', $before );
				$b = self::normalize( 'quiet_hours', $after );
				$a_by = self::index_quiet_hours( $a );
				$b_by = self::index_quiet_hours( $b );
				$ids  = array_unique( array_merge( array_keys( $a_by ), array_keys( $b_by ) ) );
				sort( $ids, SORT_STRING );
				foreach ( $ids as $id ) {
					$from = isset( $a_by[ $id ] ) ? self::format_quiet_window( $a_by[ $id ] ) : $none;
					$to   = isset( $b_by[ $id ] ) ? self::format_quiet_window( $b_by[ $id ] ) : $none;
					if ( $from === $to ) {
						continue;
					}
					$name = isset( $b_by[ $id ]['name'] ) ? (string) $b_by[ $id ]['name'] : ( isset( $a_by[ $id ]['name'] ) ? (string) $a_by[ $id ]['name'] : $id );
					$lines[] = sprintf( '%s (%s): %s → %s', $label, $name, $from, $to );
				}
				break;
		}

		return $lines;
	}

	private static function format_allow_deny( string $rule ): string {
		if ( 'deny' === $rule ) {
			return __( 'Deny', 'handl-ai-connector-access-control' );
		}
		if ( 'allow' === $rule ) {
			return __( 'Allow', 'handl-ai-connector-access-control' );
		}
		return $rule;
	}

	/**
	 * @param array<string,mixed> $map
	 */
	private static function format_operations_plugin( array $map ): string {
		$parts = array();
		foreach ( $map as $family => $rule ) {
			$parts[] = (string) $family . '=' . (string) $rule;
		}
		return self::truncate_text( implode( ', ', $parts ), 80 );
	}

	private static function format_unix_ts( int $ts ): string {
		if ( $ts <= 0 ) {
			return __( '(none)', 'handl-ai-connector-access-control' );
		}
		return function_exists( 'wp_date' )
			? (string) wp_date( 'Y-m-d H:i', $ts )
			: gmdate( 'Y-m-d H:i', $ts );
	}

	/**
	 * @param mixed $amount
	 */
	private static function format_money( $amount ): string {
		if ( null === $amount || '' === $amount ) {
			return __( '(none)', 'handl-ai-connector-access-control' );
		}
		$n = is_numeric( $amount ) ? (float) $amount : 0.0;
		return Cost::format_usd( $n );
	}

	/**
	 * @param string $mode Budget mode storage value.
	 */
	private static function format_budget_mode( string $mode ): string {
		if ( Budget::MODE_OBSERVE === $mode ) {
			return __( 'Observe-only when reached', 'handl-ai-connector-access-control' );
		}
		return __( 'Block when reached', 'handl-ai-connector-access-control' );
	}

	/**
	 * @param mixed $row
	 */
	private static function format_model_force_row( $row ): string {
		if ( ! is_array( $row ) ) {
			return __( '(none)', 'handl-ai-connector-access-control' );
		}
		$provider = isset( $row['provider'] ) ? (string) $row['provider'] : '';
		$model    = isset( $row['model'] ) ? (string) $row['model'] : '';
		if ( '' === $provider && '' === $model ) {
			return __( '(none)', 'handl-ai-connector-access-control' );
		}
		return self::truncate_text( $provider . '/' . $model, 80 );
	}

	/**
	 * @param mixed $row
	 */
	private static function format_provider_rate_row( $row ): string {
		if ( ! is_array( $row ) ) {
			return __( '(none)', 'handl-ai-connector-access-control' );
		}
		$in  = isset( $row['input_per_m'] ) && is_numeric( $row['input_per_m'] ) ? (float) $row['input_per_m'] : 0.0;
		$out = isset( $row['output_per_m'] ) && is_numeric( $row['output_per_m'] ) ? (float) $row['output_per_m'] : 0.0;
		return self::truncate_text(
			sprintf(
				/* translators: 1: input USD rate, 2: output USD rate */
				__( 'Input %1$s; output %2$s', 'handl-ai-connector-access-control' ),
				Cost::format_usd( $in ),
				Cost::format_usd( $out )
			),
			120
		);
	}

	/**
	 * @param mixed $windows
	 * @return array<string,array<string,mixed>>
	 */
	private static function index_quiet_hours( $windows ): array {
		if ( ! is_array( $windows ) ) {
			return array();
		}
		$out = array();
		foreach ( $windows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$id = isset( $row['id'] ) ? (string) $row['id'] : '';
			if ( '' === $id ) {
				$id = md5( (string) wp_json_encode( $row ) );
			}
			$out[ $id ] = $row;
		}
		return $out;
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private static function format_quiet_window( array $row ): string {
		$name  = isset( $row['name'] ) ? (string) $row['name'] : '';
		$start = isset( $row['start'] ) ? (string) $row['start'] : '';
		$end   = isset( $row['end'] ) ? (string) $row['end'] : '';
		$mode  = isset( $row['mode'] ) ? (string) $row['mode'] : '';
		$days  = isset( $row['days'] ) && is_array( $row['days'] ) ? implode( ',', $row['days'] ) : '';
		return self::truncate_text( trim( $name . ' ' . $days . ' ' . $start . '-' . $end . ' ' . $mode ), 100 );
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
			case 'new_plugin_review_enabled':
			case 'anomaly_alert_enabled':
			case 'monthly_report_enabled':
			case 'weekly_report_enabled':
			case 'governance_digest_enabled':
			case 'governance_digest_always_send':
				return (bool) $raw;
			case 'new_plugin_interim':
				return New_Plugin::sanitize_interim( $raw );
			case 'unknown_operation':
				$v = (string) $raw;
				return in_array( $v, array( 'inherit', 'allow', 'deny' ), true ) ? $v : 'inherit';
			case 'alert_mode':
				return Alerts::sanitize_mode( $raw ?? 'immediate' );
			case 'alert_email':
				return Alerts::sanitize_email( $raw ?? '' );
			case 'alert_webhook_url':
				return Alerts::sanitize_webhook_url( $raw ?? '' );
			case 'spend_threshold_site':
				return Spend_Threshold::sanitize_threshold( $raw );
			case 'log_limit':
				$n = (int) ( $raw ?? 200 );
				if ( $n < 20 ) {
					$n = 20;
				}
				if ( $n > 1000 ) {
					$n = 1000;
				}
				return $n;
			case 'log_max_age_days':
				return Policy::sanitize_log_max_age_days( $raw );
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
				$tools = is_array( $raw ) ? Policy::sanitize_denied_tools( $raw ) : array();
				sort( $tools, SORT_STRING );
				return $tools;
			case 'model_force_plugins':
				return is_array( $raw ) ? Model_Force::sanitize_force_map( $raw ) : array();
			case 'model_force_unattributed':
				return Model_Force::sanitize_unattributed_mode( $raw ?? 'none' );
			case 'model_force_unattributed_provider':
			case 'model_force_unattributed_model':
				return Model_Force::sanitize_id( $raw ?? '' );
			case 'kill_switch_exceptions':
				$list = Policy::get_kill_switch_exceptions( array( 'kill_switch_exceptions' => $raw ) );
				sort( $list, SORT_STRING );
				return $list;
			case 'shadow_block_exceptions':
				$list = Shadow_AI::get_block_exceptions( array( 'shadow_block_exceptions' => $raw ) );
				sort( $list, SORT_STRING );
				return $list;
			case 'allowed_roles':
				$list = Policy::sanitize_allowed_roles( $raw );
				sort( $list, SORT_STRING );
				return $list;
			case 'plugin_expires':
				$map = Temp_Allow::sanitize_plugin_expires( $raw );
				ksort( $map, SORT_STRING );
				return $map;
			case 'review_due_days':
				return Review_Due::sanitize_days( $raw );
			case 'quiet_hours':
				return Quiet_Hours::sanitize_windows( $raw );
			case 'est_usd_input_per_m':
				return Cost::sanitize_rate( $raw ?? Cost::DEFAULT_INPUT_PER_M, Cost::DEFAULT_INPUT_PER_M );
			case 'est_usd_output_per_m':
				return Cost::sanitize_rate( $raw ?? Cost::DEFAULT_OUTPUT_PER_M, Cost::DEFAULT_OUTPUT_PER_M );
			case 'est_usd_provider_rates':
				$map = Cost::sanitize_provider_rates( $raw );
				ksort( $map, SORT_STRING );
				return $map;
			case 'spend_threshold_plugins':
				$map = Spend_Threshold::sanitize_plugin_thresholds( $raw );
				ksort( $map, SORT_STRING );
				return $map;
			case 'plugin_budgets':
				$map = Budget::sanitize_plugin_budgets( $raw );
				ksort( $map, SORT_STRING );
				return $map;
			case 'plugin_budget_modes':
				$map = Budget::sanitize_plugin_budget_modes( $raw );
				ksort( $map, SORT_STRING );
				return $map;
			case 'anomaly_multiplier':
				return Anomaly::sanitize_multiplier( $raw ?? Anomaly::DEFAULT_MULTIPLIER );
			case 'anomaly_floor_calls':
				return Anomaly::sanitize_floor_calls( $raw ?? Anomaly::DEFAULT_FLOOR_CALLS );
			case 'anomaly_floor_spend':
				return Anomaly::sanitize_floor_spend( $raw ?? Anomaly::DEFAULT_FLOOR_SPEND );
			case 'drift_alert_mode':
				return Drift::sanitize_mode( $raw ?? Drift::MODE_PROVIDER );
			default:
				// Allowlist-only: never dump unknown arrays/JSON into history.
				return null;
		}
	}

	private static function field_label( string $key ): string {
		$labels = array(
			'default'                           => __( 'Default policy', 'handl-ai-connector-access-control' ),
			'audit_only'                        => __( 'Learn mode (observe only)', 'handl-ai-connector-access-control' ),
			'log_enabled'                       => __( 'Activity logging', 'handl-ai-connector-access-control' ),
			'log_limit'                         => __( 'Activity entry limit', 'handl-ai-connector-access-control' ),
			'log_max_age_days'                  => __( 'Activity keep period', 'handl-ai-connector-access-control' ),
			'kill_switch'                       => __( 'Emergency stop', 'handl-ai-connector-access-control' ),
			'kill_switch_exceptions'            => __( 'Emergency stop exceptions', 'handl-ai-connector-access-control' ),
			'shadow_block_enabled'              => __( 'Block direct AI connections', 'handl-ai-connector-access-control' ),
			'shadow_block_exceptions'           => __( 'Direct-connection exceptions', 'handl-ai-connector-access-control' ),
			'unknown_operation'                 => __( 'Unknown AI operations', 'handl-ai-connector-access-control' ),
			'role_gate_enabled'                 => __( 'Limit by role', 'handl-ai-connector-access-control' ),
			'allowed_roles'                     => __( 'Allowed roles', 'handl-ai-connector-access-control' ),
			'quiet_hours'                       => __( 'Quiet hours', 'handl-ai-connector-access-control' ),
			'alert_on_deny'                     => __( 'Blocked-call email alerts', 'handl-ai-connector-access-control' ),
			'alert_on_shadow'                   => __( 'Direct-connection email alerts', 'handl-ai-connector-access-control' ),
			'alert_mode'                        => __( 'Alert timing', 'handl-ai-connector-access-control' ),
			'alert_email'                       => __( 'Alert email', 'handl-ai-connector-access-control' ),
			'alert_webhook_url'                 => __( 'Alert webhook', 'handl-ai-connector-access-control' ),
			'new_plugin_review_enabled'         => __( 'Review new plugins', 'handl-ai-connector-access-control' ),
			'new_plugin_interim'                => __( 'New plugin interim mode', 'handl-ai-connector-access-control' ),
			'plugins'                           => __( 'Per-plugin rules', 'handl-ai-connector-access-control' ),
			'plugin_expires'                    => __( 'Temporary Allow expiry', 'handl-ai-connector-access-control' ),
			'review_due_days'                   => __( 'Rule review window', 'handl-ai-connector-access-control' ),
			'operations'                        => __( 'Capability-family rules', 'handl-ai-connector-access-control' ),
			'denied_tools'                      => __( 'Blocked AI tools', 'handl-ai-connector-access-control' ),
			'model_force_plugins'               => __( 'Model routes', 'handl-ai-connector-access-control' ),
			'model_force_unattributed'          => __( 'Calls with no detected plugin', 'handl-ai-connector-access-control' ),
			'model_force_unattributed_provider' => __( 'Unattributed model provider', 'handl-ai-connector-access-control' ),
			'model_force_unattributed_model'    => __( 'Unattributed model', 'handl-ai-connector-access-control' ),
			'est_usd_input_per_m'               => __( 'Default input rate ($ per 1M tokens)', 'handl-ai-connector-access-control' ),
			'est_usd_output_per_m'              => __( 'Default output rate ($ per 1M tokens)', 'handl-ai-connector-access-control' ),
			'est_usd_provider_rates'            => __( 'Provider rates ($ per 1M tokens)', 'handl-ai-connector-access-control' ),
			'spend_threshold_site'              => __( 'Site estimated-spend alert', 'handl-ai-connector-access-control' ),
			'spend_threshold_plugins'           => __( 'Plugin estimated-spend alerts', 'handl-ai-connector-access-control' ),
			'plugin_budgets'                    => __( 'Plugin estimated budgets', 'handl-ai-connector-access-control' ),
			'plugin_budget_modes'               => __( 'Plugin budget modes', 'handl-ai-connector-access-control' ),
			'anomaly_alert_enabled'             => __( 'Usage spike alerts', 'handl-ai-connector-access-control' ),
			'anomaly_multiplier'                => __( 'Usage spike multiplier', 'handl-ai-connector-access-control' ),
			'anomaly_floor_calls'               => __( 'Usage spike call floor', 'handl-ai-connector-access-control' ),
			'anomaly_floor_spend'               => __( 'Usage spike spend floor', 'handl-ai-connector-access-control' ),
			'drift_alert_mode'                  => __( 'Provider/model change alerts', 'handl-ai-connector-access-control' ),
			'monthly_report_enabled'            => __( 'Monthly audit email', 'handl-ai-connector-access-control' ),
			'weekly_report_enabled'             => __( 'Weekly report email', 'handl-ai-connector-access-control' ),
			'governance_digest_enabled'         => __( 'Governance digest email', 'handl-ai-connector-access-control' ),
			'governance_digest_always_send'     => __( 'Always send governance digest', 'handl-ai-connector-access-control' ),
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
			case 'new_plugin_review_enabled':
			case 'anomaly_alert_enabled':
			case 'monthly_report_enabled':
			case 'weekly_report_enabled':
			case 'governance_digest_enabled':
			case 'governance_digest_always_send':
				return $value
					? __( 'On', 'handl-ai-connector-access-control' )
					: __( 'Off', 'handl-ai-connector-access-control' );
			case 'new_plugin_interim':
				return ( New_Plugin::INTERIM_OBSERVE === $value )
					? __( 'Observe-only mode', 'handl-ai-connector-access-control' )
					: __( 'Deny', 'handl-ai-connector-access-control' );
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
			case 'log_limit':
				return (string) (int) $value;
			case 'log_max_age_days':
				if ( null === $value ) {
					return __( 'Forever', 'handl-ai-connector-access-control' );
				}
				/* translators: %d: number of days */
				return sprintf( _n( '%d day', '%d days', (int) $value, 'handl-ai-connector-access-control' ), (int) $value );
			case 'plugins':
			case 'operations':
			case 'denied_tools':
			case 'model_force_plugins':
			case 'kill_switch_exceptions':
			case 'shadow_block_exceptions':
			case 'allowed_roles':
			case 'plugin_expires':
			case 'quiet_hours':
			case 'est_usd_provider_rates':
			case 'spend_threshold_plugins':
			case 'plugin_budgets':
			case 'plugin_budget_modes':
				// Restore preview uses a compact count; history uses map_item_change_lines.
				if ( ! is_array( $value ) || empty( $value ) ) {
					return __( '(none)', 'handl-ai-connector-access-control' );
				}
				/* translators: %d: item count */
				return sprintf( _n( '%d item', '%d items', count( $value ), 'handl-ai-connector-access-control' ), count( $value ) );
			case 'spend_threshold_site':
				if ( null === $value || '' === $value ) {
					return __( 'No alert', 'handl-ai-connector-access-control' );
				}
				return self::format_money( $value );
			case 'est_usd_input_per_m':
			case 'est_usd_output_per_m':
			case 'anomaly_floor_spend':
				return self::format_money( $value );
			case 'anomaly_multiplier':
			case 'anomaly_floor_calls':
				return (string) $value;
			case 'drift_alert_mode':
				if ( Drift::MODE_OFF === $value ) {
					return __( 'Off', 'handl-ai-connector-access-control' );
				}
				if ( Drift::MODE_MODEL === $value ) {
					return __( 'Provider and model', 'handl-ai-connector-access-control' );
				}
				return __( 'Provider', 'handl-ai-connector-access-control' );
			case 'model_force_unattributed':
				return ( 'force' === $value )
					? __( 'Route to provider and model', 'handl-ai-connector-access-control' )
					: __( 'Do not route', 'handl-ai-connector-access-control' );
			case 'model_force_unattributed_provider':
			case 'model_force_unattributed_model':
				return '' !== (string) $value ? (string) $value : __( '(none)', 'handl-ai-connector-access-control' );
			case 'alert_email':
			case 'alert_webhook_url':
				return self::format_secret_presence( $value );
			default:
				if ( is_bool( $value ) ) {
					return $value ? __( 'On', 'handl-ai-connector-access-control' ) : __( 'Off', 'handl-ai-connector-access-control' );
				}
				if ( is_array( $value ) || null === $value ) {
					return __( '(none)', 'handl-ai-connector-access-control' );
				}
				return (string) $value;
		}
	}
}
