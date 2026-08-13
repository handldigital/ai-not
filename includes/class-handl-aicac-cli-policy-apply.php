<?php
/**
 * AICAC-CLI-APPLY (#195): WP-CLI policy apply with dry-run diff.
 *
 * Registers `wp handl-aicac policy apply`. Writes only through
 * Policy::save_policy() so Policy_Snapshots (undo + history actor) stay intact.
 *
 * Exit codes (documented for scripting):
 * - 0: applied successfully, or dry-run with no differences
 * - 1: dry-run found differences; validation/refusal error; apply refused without --yes
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Apply a reviewed policy JSON export from the shell.
 *
 * @when after_wp_load
 */
final class CLI_Policy_Apply {

	/**
	 * Keys accepted by import but dropped / migrated by save_policy — not applied as-is.
	 *
	 * @var list<string>
	 */
	private const LEGACY_NON_APPLIED_KEYS = array(
		'denied_abilities',
		'model_force_enabled',
		'model_force_provider',
		'model_force_model',
	);

	/**
	 * Secret-bearing keys: compare and display presence only (never raw values).
	 *
	 * @var list<string>
	 */
	private const SECRET_PRESENCE_KEYS = array(
		'alert_email',
		'alert_webhook_url',
	);

	/**
	 * Register commands when WP-CLI is available.
	 */
	public static function register(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac policy apply', array( self::class, 'cmd_apply' ) );
	}

	/**
	 * Apply a policy export JSON file (full replace via save_policy).
	 *
	 * ## OPTIONS
	 *
	 * <file>
	 * : Path to a HandL AICAC rules export JSON file.
	 *
	 * [--dry-run]
	 * : Print the diff against the live policy and exit 1 when changes exist (exit 0 when identical). Does not write.
	 *
	 * [--yes]
	 * : Confirm apply. Required for a real write (ignored with --dry-run).
	 *
	 * [--allow-mismatched-site]
	 * : Allow apply when the export's site_url does not match this site's home URL.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac policy apply ./backup.json --dry-run
	 *     wp handl-aicac policy apply ./backup.json --yes
	 *     wp handl-aicac policy apply ./other-site.json --yes --allow-mismatched-site
	 *
	 * ## EXIT CODES
	 *
	 * * 0 — Applied, or dry-run with no differences.
	 * * 1 — Dry-run found differences; malformed/foreign export; missing --yes; site mismatch without --allow-mismatched-site.
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public static function cmd_apply( $args, $assoc_args ): void {
		$file = isset( $args[0] ) ? (string) $args[0] : '';
		if ( '' === $file ) {
			\WP_CLI::error( 'Usage: wp handl-aicac policy apply <file.json> [--dry-run] [--yes] [--allow-mismatched-site]', true );
		}

		$dry_run        = ! empty( $assoc_args['dry-run'] );
		$yes            = ! empty( $assoc_args['yes'] );
		$allow_mismatch = ! empty( $assoc_args['allow-mismatched-site'] );
		$site_url       = self::current_site_url();

		$raw = self::read_file( $file );
		if ( is_array( $raw ) && isset( $raw['error'] ) ) {
			\WP_CLI::error( self::error_message( (string) $raw['error'], $file ), true );
		}

		$result = self::execute( (string) $raw, $site_url, $dry_run, $yes, $allow_mismatch );

		foreach ( $result['logs'] as $line ) {
			\WP_CLI::log( (string) $line );
		}
		if ( isset( $result['warning'] ) && '' !== (string) $result['warning'] ) {
			\WP_CLI::warning( (string) $result['warning'] );
		}
		if ( isset( $result['error'] ) && '' !== (string) $result['error'] ) {
			\WP_CLI::error( (string) $result['error'], true );
		}
		if ( isset( $result['success'] ) && '' !== (string) $result['success'] ) {
			\WP_CLI::success( (string) $result['success'] );
		}

		$exit = (int) ( $result['exit_code'] ?? 0 );
		if ( $exit > 0 ) {
			\WP_CLI::halt( $exit );
		}
	}

	/**
	 * Command-level apply/dry-run without WP-CLI (PHPUnit).
	 *
	 * @return array{
	 *   exit_code:int,
	 *   logs:list<string>,
	 *   warning?:string,
	 *   success?:string,
	 *   error?:string,
	 *   wrote:bool,
	 *   has_changes:bool,
	 *   refused_keys?:list<string>
	 * }
	 */
	public static function execute( string $json, string $site_url, bool $dry_run, bool $yes, bool $allow_mismatched_site ): array {
		$prepared = self::prepare_apply( $json, $site_url, $allow_mismatched_site );
		if ( empty( $prepared['ok'] ) ) {
			$err  = (string) ( $prepared['error'] ?? 'unknown' );
			$keys = ( 'non_comparable_applied' === $err && ! empty( $prepared['keys'] ) && is_array( $prepared['keys'] ) )
				? array_values( array_map( 'strval', $prepared['keys'] ) )
				: array();
			$out  = array(
				'exit_code'   => 1,
				'logs'        => array(),
				'error'       => self::error_message( $err, '', $keys ),
				'wrote'       => false,
				'has_changes' => false,
			);
			if ( ! empty( $keys ) ) {
				$out['refused_keys'] = $keys;
			}
			return $out;
		}

		$lines       = isset( $prepared['diff_lines'] ) && is_array( $prepared['diff_lines'] ) ? $prepared['diff_lines'] : array();
		$has_changes = ! empty( $prepared['has_changes'] );
		$logs        = array();

		if ( ! empty( $prepared['ignored'] ) && is_array( $prepared['ignored'] ) ) {
			$logs[] = 'Ignored unknown export keys: ' . implode( ', ', $prepared['ignored'] );
		}

		if ( empty( $lines ) ) {
			$logs[] = 'No differences in comparable policy settings.';
		} else {
			$logs[] = 'Policy changes:';
			foreach ( $lines as $line ) {
				$logs[] = '  - ' . (string) $line;
			}
		}

		if ( $dry_run ) {
			if ( $has_changes ) {
				return array(
					'exit_code'   => 1,
					'logs'        => $logs,
					'warning'     => 'Dry run only: the policy would change. Run this command again without --dry-run and add --yes to apply it.',
					'wrote'       => false,
					'has_changes' => true,
				);
			}
			return array(
				'exit_code'   => 0,
				'logs'        => $logs,
				'success'     => 'Dry run complete: the current policy matches this export.',
				'wrote'       => false,
				'has_changes' => false,
			);
		}

		if ( ! $yes ) {
			return array(
				'exit_code'   => 1,
				'logs'        => $logs,
				'error'       => 'Policy not applied. Use --dry-run to preview changes, or add --yes to confirm the update.',
				'wrote'       => false,
				'has_changes' => $has_changes,
			);
		}

		$policy = isset( $prepared['policy'] ) && is_array( $prepared['policy'] ) ? $prepared['policy'] : array();
		$before = Policy_Snapshots::all();
		self::commit_apply( $policy );
		$after = Policy_Snapshots::all();

		return array(
			'exit_code'   => 0,
			'logs'        => $logs,
			'success'     => $has_changes
				? 'Policy applied. A restore snapshot of the previous policy was saved.'
				: 'Policy applied. The current policy already matched this export.',
			'wrote'       => true,
			'has_changes' => $has_changes,
			// Snapshot count is informative for tests; always true after save_policy.
			'snapshot_grew' => count( $after ) > count( $before ),
		);
	}

	/**
	 * Pure prepare step for PHPUnit + CLI.
	 *
	 * Guarantees dry-run/apply parity: every accepted applied key is either
	 * shown in a secret-safe diff line or refused (named by key only).
	 *
	 * @return array{
	 *   ok:true,
	 *   policy:array<string,mixed>,
	 *   ignored:list<string>,
	 *   diff_lines:list<string>,
	 *   has_changes:bool,
	 *   export_site_url:string
	 * }|array{ok:false,error:string,keys?:list<string>}
	 */
	public static function prepare_apply( string $json, string $current_site_url, bool $allow_mismatched_site ): array {
		$parsed = Policy_Transfer::parse_import( $json );
		if ( empty( $parsed['ok'] ) ) {
			return array(
				'ok'    => false,
				'error' => (string) ( $parsed['error'] ?? 'invalid_json' ),
			);
		}

		$export_site = self::extract_export_site_url( $json );
		if ( '' !== $export_site && '' !== $current_site_url ) {
			if ( ! self::site_urls_match( $export_site, $current_site_url ) && ! $allow_mismatched_site ) {
				return array(
					'ok'    => false,
					'error' => 'site_mismatch',
				);
			}
		}

		$incoming = Policy_Transfer::policy_for_save( is_array( $parsed['policy'] ?? null ) ? $parsed['policy'] : array() );
		$current  = Policy::get_policy();
		$ignored  = isset( $parsed['ignored'] ) && is_array( $parsed['ignored'] ) ? $parsed['ignored'] : array();
		$compare  = Policy_Transfer::compare_diff( $current, $incoming, $ignored );
		$rows     = isset( $compare['rows'] ) && is_array( $compare['rows'] ) ? $compare['rows'] : array();

		$parity = self::ensure_applied_parity( $current, $incoming, $rows );
		if ( ! empty( $parity['refused_keys'] ) ) {
			return array(
				'ok'    => false,
				'error' => 'non_comparable_applied',
				'keys'  => $parity['refused_keys'],
			);
		}

		$rows  = $parity['rows'];
		$lines = self::format_compare_rows( $rows );

		return array(
			'ok'              => true,
			'policy'          => $incoming,
			'ignored'         => $ignored,
			'diff_lines'      => $lines,
			'has_changes'     => ! empty( $lines ),
			'export_site_url' => $export_site,
		);
	}

	/**
	 * Extend snapshot/import rows so every applied key difference is either
	 * secret-safe-comparable or listed for refusal.
	 *
	 * @param array<string,mixed>                                                      $current
	 * @param array<string,mixed>                                                      $incoming
	 * @param list<array{key?:string,label?:string,current?:string,new?:string}>       $rows
	 * @return array{rows:list<array{key:string,label:string,current:string,new:string}>,refused_keys:list<string>}
	 */
	public static function ensure_applied_parity( array $current, array $incoming, array $rows ): array {
		$covered = array();
		$clean   = array();
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$key = isset( $row['key'] ) ? (string) $row['key'] : '';
			if ( '' === $key ) {
				continue;
			}
			$covered[ $key ] = true;
			$clean[]         = array(
				'key'     => $key,
				'label'   => isset( $row['label'] ) ? (string) $row['label'] : $key,
				'current' => isset( $row['current'] ) ? (string) $row['current'] : '',
				'new'     => isset( $row['new'] ) ? (string) $row['new'] : '',
			);
		}

		$refused = array();
		foreach ( self::applied_policy_keys() as $key ) {
			if ( isset( $covered[ $key ] ) ) {
				continue;
			}
			$cur_val = array_key_exists( $key, $current ) ? $current[ $key ] : null;
			$new_val = array_key_exists( $key, $incoming ) ? $incoming[ $key ] : null;
			if ( self::applied_values_equal( $key, $cur_val, $new_val ) ) {
				continue;
			}

			$safe = self::safe_diff_row( $key, $cur_val, $new_val );
			if ( null === $safe ) {
				$refused[] = $key;
				continue;
			}
			$clean[]         = $safe;
			$covered[ $key ] = true;
		}

		sort( $refused, SORT_STRING );

		return array(
			'rows'         => $clean,
			'refused_keys' => $refused,
		);
	}

	/**
	 * Known import keys that apply actually writes (excludes legacy migrate-away keys).
	 *
	 * @return list<string>
	 */
	public static function applied_policy_keys(): array {
		$skip = array_fill_keys( self::LEGACY_NON_APPLIED_KEYS, true );
		$out  = array();
		foreach ( Policy_Transfer::known_policy_keys() as $key ) {
			$key = (string) $key;
			if ( isset( $skip[ $key ] ) ) {
				continue;
			}
			$out[] = $key;
		}
		return $out;
	}

	/**
	 * @param mixed $a
	 * @param mixed $b
	 */
	public static function applied_values_equal( string $key, $a, $b ): bool {
		return self::canonicalize_applied( $key, $a ) === self::canonicalize_applied( $key, $b );
	}

	/**
	 * @param mixed $raw
	 * @return mixed
	 */
	public static function canonicalize_applied( string $key, $raw ) {
		if ( in_array( $key, self::SECRET_PRESENCE_KEYS, true ) ) {
			return self::secret_is_configured( $raw ) ? '1' : '0';
		}

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
			case 'policy_backup_email_enabled':
				return (bool) $raw;
			case 'model_force_unattributed':
				return Model_Force::sanitize_unattributed_mode( $raw ?? 'none' );
			case 'new_plugin_interim':
				return New_Plugin::sanitize_interim( $raw );
			case 'unknown_operation':
				$v = (string) $raw;
				return in_array( $v, array( 'inherit', 'allow', 'deny' ), true ) ? $v : 'inherit';
			case 'alert_mode':
				return Alerts::sanitize_mode( $raw ?? 'immediate' );
			case 'log_limit':
				$n = (int) $raw;
				if ( $n < 20 ) {
					$n = 20;
				}
				if ( $n > 1000 ) {
					$n = 1000;
				}
				return $n;
			case 'log_max_age_days':
				return Policy::sanitize_log_max_age_days( $raw );
			case 'spend_threshold_site':
				return Spend_Threshold::sanitize_threshold( $raw );
			case 'anomaly_multiplier':
				return Anomaly::sanitize_multiplier( $raw ?? Anomaly::DEFAULT_MULTIPLIER );
			case 'anomaly_floor_calls':
				return Anomaly::sanitize_floor_calls( $raw ?? Anomaly::DEFAULT_FLOOR_CALLS );
			case 'anomaly_floor_spend':
				return Anomaly::sanitize_floor_spend( $raw ?? Anomaly::DEFAULT_FLOOR_SPEND );
			case 'drift_alert_mode':
				return Drift::sanitize_mode( $raw ?? Drift::MODE_PROVIDER );
			case 'est_usd_input_per_m':
				return Cost::sanitize_rate( $raw ?? Cost::DEFAULT_INPUT_PER_M, Cost::DEFAULT_INPUT_PER_M );
			case 'est_usd_output_per_m':
				return Cost::sanitize_rate( $raw ?? Cost::DEFAULT_OUTPUT_PER_M, Cost::DEFAULT_OUTPUT_PER_M );
			case 'est_usd_provider_rates':
				return Cost::sanitize_provider_rates( is_array( $raw ) ? $raw : array() );
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
			case 'plugin_expires':
				return class_exists( Temp_Allow::class )
					? Temp_Allow::sanitize_plugin_expires( is_array( $raw ) ? $raw : array() )
					: ( is_array( $raw ) ? $raw : array() );
			case 'operations':
				return is_array( $raw ) ? Policy::sanitize_operations( $raw ) : array();
			case 'denied_tools':
				return is_array( $raw ) ? Policy::sanitize_denied_tools( $raw ) : array();
			case 'model_force_plugins':
				return is_array( $raw ) ? Model_Force::sanitize_force_map( $raw ) : array();
			case 'kill_switch_exceptions':
			case 'shadow_block_exceptions':
			case 'allowed_roles':
			case 'new_plugin_known':
				return self::canonicalize_string_list( $raw );
			case 'new_plugin_pending':
				return New_Plugin::sanitize_pending( $raw );
			case 'spend_threshold_plugins':
				return Spend_Threshold::sanitize_plugin_thresholds( is_array( $raw ) ? $raw : array() );
			case 'plugin_budgets':
				return Budget::sanitize_plugin_budgets( is_array( $raw ) ? $raw : array() );
			case 'plugin_budget_modes':
				return Budget::sanitize_plugin_budget_modes( is_array( $raw ) ? $raw : array() );
			case 'model_force_unattributed_provider':
			case 'model_force_unattributed_model':
				return is_scalar( $raw ) ? trim( (string) $raw ) : '';
			case 'plugin_notes':
				if ( class_exists( Rule_Notes::class ) ) {
					return Rule_Notes::sanitize_plugin_notes( is_array( $raw ) ? $raw : array() );
				}
				return is_array( $raw ) ? $raw : array();
			case 'quiet_hours':
				if ( class_exists( Quiet_Hours::class ) ) {
					return Quiet_Hours::sanitize_windows( is_array( $raw ) ? $raw : array() );
				}
				return is_array( $raw ) ? $raw : array();
			default:
				if ( is_array( $raw ) ) {
					$encoded = wp_json_encode( self::ksort_recursive( $raw ) );
					return is_string( $encoded ) ? $encoded : '';
				}
				if ( is_bool( $raw ) || is_int( $raw ) || is_float( $raw ) || is_string( $raw ) || null === $raw ) {
					return $raw;
				}
				// Non-scalar / non-array values cannot be compared safely.
				return array( '__uncomparable__' => gettype( $raw ) );
		}
	}

	/**
	 * @param mixed $a
	 * @param mixed $b
	 * @return array{key:string,label:string,current:string,new:string}|null
	 */
	public static function safe_diff_row( string $key, $a, $b ): ?array {
		$label = self::applied_field_label( $key );

		if ( in_array( $key, self::SECRET_PRESENCE_KEYS, true ) ) {
			return array(
				'key'     => $key,
				'label'   => $label,
				'current' => self::format_secret_presence( $a ),
				'new'     => self::format_secret_presence( $b ),
			);
		}

		$from = self::format_applied_value( $key, $a );
		$to   = self::format_applied_value( $key, $b );
		if ( null === $from || null === $to ) {
			return null;
		}

		return array(
			'key'     => $key,
			'label'   => $label,
			'current' => $from,
			'new'     => $to,
		);
	}

	/**
	 * @param mixed $value
	 */
	private static function format_applied_value( string $key, $value ): ?string {
		$canon = self::canonicalize_applied( $key, $value );

		switch ( $key ) {
			case 'policy_backup_email_enabled':
			case 'weekly_report_enabled':
			case 'monthly_report_enabled':
			case 'governance_digest_enabled':
			case 'governance_digest_always_send':
			case 'anomaly_alert_enabled':
			case 'new_plugin_review_enabled':
			case 'audit_only':
			case 'log_enabled':
			case 'kill_switch':
			case 'shadow_block_enabled':
			case 'role_gate_enabled':
			case 'alert_on_deny':
			case 'alert_on_shadow':
				return $canon ? __( 'On', 'handl-ai-connector-access-control' ) : __( 'Off', 'handl-ai-connector-access-control' );
			case 'model_force_unattributed':
				return ( 'force' === $canon )
					? __( 'Force', 'handl-ai-connector-access-control' )
					: __( 'Off', 'handl-ai-connector-access-control' );
			case 'new_plugin_known':
				$count = is_array( $canon ) ? count( $canon ) : 0;
				return sprintf(
					/* translators: %d: count of grandfathered plugins */
					_n( '%d known plugin', '%d known plugins', $count, 'handl-ai-connector-access-control' ),
					$count
				);
			case 'new_plugin_pending':
				$count = is_array( $canon ) ? count( $canon ) : 0;
				return sprintf(
					/* translators: %d: count of pending plugins */
					_n( '%d pending plugin', '%d pending plugins', $count, 'handl-ai-connector-access-control' ),
					$count
				);
			case 'plugin_notes':
				$count = is_array( $canon ) ? count( $canon ) : 0;
				return sprintf(
					/* translators: %d: count of rule notes */
					_n( '%d rule note', '%d rule notes', $count, 'handl-ai-connector-access-control' ),
					$count
				);
			case 'kill_switch_exceptions':
			case 'shadow_block_exceptions':
			case 'allowed_roles':
				$count = is_array( $canon ) ? count( $canon ) : 0;
				return sprintf(
					/* translators: %d: list length */
					_n( '%d entry', '%d entries', $count, 'handl-ai-connector-access-control' ),
					$count
				);
			case 'plugin_expires':
			case 'spend_threshold_plugins':
			case 'plugin_budgets':
			case 'plugin_budget_modes':
			case 'est_usd_provider_rates':
			case 'quiet_hours':
				$count = is_array( $canon ) ? count( $canon ) : 0;
				return sprintf(
					/* translators: %d: map size */
					_n( '%d entry', '%d entries', $count, 'handl-ai-connector-access-control' ),
					$count
				);
			case 'log_limit':
			case 'anomaly_multiplier':
			case 'anomaly_floor_calls':
			case 'anomaly_floor_spend':
			case 'est_usd_input_per_m':
			case 'est_usd_output_per_m':
				return is_scalar( $canon ) ? (string) $canon : null;
			case 'log_max_age_days':
				return null === $canon ? __( 'Off', 'handl-ai-connector-access-control' ) : (string) (int) $canon;
			case 'drift_alert_mode':
			case 'alert_mode':
			case 'new_plugin_interim':
			case 'unknown_operation':
			case 'default':
			case 'model_force_unattributed_provider':
			case 'model_force_unattributed_model':
			case 'spend_threshold_site':
				if ( is_array( $canon ) ) {
					return null;
				}
				if ( null === $canon || '' === $canon ) {
					return __( '(none)', 'handl-ai-connector-access-control' );
				}
				return (string) $canon;
			default:
				if ( is_bool( $canon ) ) {
					return $canon ? __( 'On', 'handl-ai-connector-access-control' ) : __( 'Off', 'handl-ai-connector-access-control' );
				}
				if ( is_array( $canon ) ) {
					$count = count( $canon );
					return sprintf(
						/* translators: %d: map/list size */
						_n( '%d entry', '%d entries', $count, 'handl-ai-connector-access-control' ),
						$count
					);
				}
				if ( is_scalar( $canon ) || null === $canon ) {
					return null === $canon ? __( '(none)', 'handl-ai-connector-access-control' ) : (string) $canon;
				}
				return null;
		}
	}

	private static function applied_field_label( string $key ): string {
		$labels = array(
			'policy_backup_email_enabled'        => __( 'Weekly rules backup email', 'handl-ai-connector-access-control' ),
			'new_plugin_known'                   => __( 'Known plugins (new-plugin review)', 'handl-ai-connector-access-control' ),
			'new_plugin_pending'                 => __( 'Pending plugins (new-plugin review)', 'handl-ai-connector-access-control' ),
			'plugin_notes'                       => __( 'Rule notes', 'handl-ai-connector-access-control' ),
			'weekly_report_enabled'              => __( 'Weekly report email', 'handl-ai-connector-access-control' ),
			'monthly_report_enabled'             => __( 'Monthly report email', 'handl-ai-connector-access-control' ),
			'governance_digest_enabled'          => __( 'Governance digest email', 'handl-ai-connector-access-control' ),
			'governance_digest_always_send'      => __( 'Always send governance digest', 'handl-ai-connector-access-control' ),
			'anomaly_alert_enabled'              => __( 'Usage spike alerts', 'handl-ai-connector-access-control' ),
			'alert_email'                        => __( 'Alert email', 'handl-ai-connector-access-control' ),
			'alert_webhook_url'                  => __( 'Alert webhook URL', 'handl-ai-connector-access-control' ),
			'kill_switch_exceptions'             => __( 'Emergency stop exceptions', 'handl-ai-connector-access-control' ),
			'shadow_block_exceptions'            => __( 'Direct-connection block exceptions', 'handl-ai-connector-access-control' ),
			'allowed_roles'                      => __( 'Allowed roles', 'handl-ai-connector-access-control' ),
			'log_limit'                          => __( 'Activity log entry limit', 'handl-ai-connector-access-control' ),
			'log_max_age_days'                   => __( 'Activity keep period (days)', 'handl-ai-connector-access-control' ),
			'plugin_expires'                     => __( 'Temporary allow expiries', 'handl-ai-connector-access-control' ),
			'plugin_budgets'                     => __( 'Plugin budgets', 'handl-ai-connector-access-control' ),
			'plugin_budget_modes'                => __( 'Plugin budget modes', 'handl-ai-connector-access-control' ),
			'spend_threshold_plugins'            => __( 'Per-plugin spend alerts', 'handl-ai-connector-access-control' ),
			'est_usd_input_per_m'                => __( 'Estimated input rate', 'handl-ai-connector-access-control' ),
			'est_usd_output_per_m'               => __( 'Estimated output rate', 'handl-ai-connector-access-control' ),
			'est_usd_provider_rates'             => __( 'Provider rate overrides', 'handl-ai-connector-access-control' ),
			'anomaly_multiplier'                 => __( 'Spike multiplier', 'handl-ai-connector-access-control' ),
			'anomaly_floor_calls'                => __( 'Spike floor (calls)', 'handl-ai-connector-access-control' ),
			'anomaly_floor_spend'                => __( 'Spike floor (spend)', 'handl-ai-connector-access-control' ),
			'drift_alert_mode'                   => __( 'Provider/model change alerts', 'handl-ai-connector-access-control' ),
			'model_force_unattributed'           => __( 'Force model for unattributed calls', 'handl-ai-connector-access-control' ),
			'model_force_unattributed_provider'  => __( 'Unattributed force provider', 'handl-ai-connector-access-control' ),
			'model_force_unattributed_model'     => __( 'Unattributed force model', 'handl-ai-connector-access-control' ),
		);

		return $labels[ $key ] ?? $key;
	}

	/**
	 * @param mixed $raw
	 */
	private static function secret_is_configured( $raw ): bool {
		if ( ! is_scalar( $raw ) ) {
			return false;
		}
		return '' !== trim( (string) $raw );
	}

	/**
	 * @param mixed $raw
	 */
	private static function format_secret_presence( $raw ): string {
		return self::secret_is_configured( $raw )
			? __( 'Configured', 'handl-ai-connector-access-control' )
			: __( 'Not set', 'handl-ai-connector-access-control' );
	}

	/**
	 * @param mixed $raw
	 * @return list<string>
	 */
	private static function canonicalize_string_list( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $item ) {
			if ( ! is_scalar( $item ) ) {
				continue;
			}
			$s = trim( (string) $item );
			if ( '' !== $s ) {
				$out[] = $s;
			}
		}
		$out = array_values( array_unique( $out ) );
		sort( $out, SORT_STRING );
		return $out;
	}

	/**
	 * @param array<mixed> $value
	 * @return array<mixed>
	 */
	private static function ksort_recursive( array $value ): array {
		foreach ( $value as $k => $v ) {
			if ( is_array( $v ) ) {
				$value[ $k ] = self::ksort_recursive( $v );
			}
		}
		if ( array_keys( $value ) !== range( 0, count( $value ) - 1 ) ) {
			ksort( $value, SORT_STRING );
		}
		return $value;
	}

	/**
	 * Write through the shared save funnel (snapshots + history actor).
	 *
	 * @param array<string,mixed> $policy From policy_for_save().
	 */
	public static function commit_apply( array $policy ): void {
		Policy::save_policy( $policy );
	}

	/**
	 * @param list<array{key?:string,label?:string,current?:string,new?:string}> $rows
	 * @return list<string>
	 */
	public static function format_compare_rows( array $rows ): array {
		$lines = array();
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$label = isset( $row['label'] ) ? (string) $row['label'] : (string) ( $row['key'] ?? '' );
			$from  = isset( $row['current'] ) ? (string) $row['current'] : '';
			$to    = isset( $row['new'] ) ? (string) $row['new'] : '';
			if ( '' === $label ) {
				continue;
			}
			$lines[] = $label . ': ' . $from . ' → ' . $to;
		}
		return $lines;
	}

	public static function current_site_url(): string {
		if ( function_exists( 'home_url' ) ) {
			return (string) home_url( '/' );
		}
		return '';
	}

	/**
	 * Read optional site_url meta from the raw export JSON (not stored in policy).
	 */
	public static function extract_export_site_url( string $json ): string {
		$data = json_decode( $json, true );
		if ( ! is_array( $data ) || ! array_key_exists( 'site_url', $data ) ) {
			return '';
		}
		if ( ! is_scalar( $data['site_url'] ) ) {
			return '';
		}
		return self::normalize_site_url( (string) $data['site_url'] );
	}

	public static function site_urls_match( string $a, string $b ): bool {
		return self::normalize_site_url( $a ) === self::normalize_site_url( $b );
	}

	public static function normalize_site_url( string $url ): string {
		$url = trim( $url );
		if ( '' === $url ) {
			return '';
		}
		$parts = function_exists( 'wp_parse_url' ) ? wp_parse_url( $url ) : parse_url( $url );
		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			return rtrim( strtolower( $url ), '/' );
		}
		$host = strtolower( (string) $parts['host'] );
		$path = isset( $parts['path'] ) ? rtrim( (string) $parts['path'], '/' ) : '';
		if ( '' === $path || '/' === $path ) {
			return $host;
		}
		return $host . $path;
	}

	/**
	 * @return string|array{error:string}
	 */
	public static function read_file( string $path ) {
		$path = trim( $path );
		if ( '' === $path ) {
			return array( 'error' => 'missing_file' );
		}
		if ( ! is_readable( $path ) ) {
			return array( 'error' => 'unreadable_file' );
		}
		$size = filesize( $path );
		if ( false !== $size && $size > Policy_Transfer::MAX_UPLOAD_BYTES ) {
			return array( 'error' => 'too_large' );
		}
		$raw = file_get_contents( $path );
		if ( ! is_string( $raw ) ) {
			return array( 'error' => 'unreadable_file' );
		}
		return $raw;
	}

	public static function error_message( string $code, string $file = '', array $keys = array() ): string {
		switch ( $code ) {
			case 'empty':
			case 'invalid_json':
				return 'Malformed export: file is empty or not valid JSON.';
			case 'missing_required_keys':
				return 'Foreign or incomplete export: plugin_version and exported_at are required.';
			case 'site_mismatch':
				return 'This export was created for a different site. If that is intentional, run the command again with --allow-mismatched-site.';
			case 'non_comparable_applied':
				$list = array();
				foreach ( $keys as $key ) {
					$key = trim( (string) $key );
					if ( '' !== $key ) {
						$list[] = $key;
					}
				}
				if ( empty( $list ) ) {
					return 'Policy not applied. The export changes settings that cannot be previewed safely.';
				}
				return 'Policy not applied. These settings would change but cannot be previewed safely: ' . implode( ', ', $list ) . '.';
			case 'missing_file':
				return 'Missing file path.';
			case 'unreadable_file':
				return '' !== $file
					? sprintf( 'Cannot read file: %s', $file )
					: 'Cannot read export file.';
			case 'too_large':
				return 'Export file exceeds the maximum allowed size.';
			default:
				return 'Unable to apply policy export.';
		}
	}
}
