<?php
/**
 * Per-plugin AI profile (AICAC-PROFILE) — read-only aggregates for one plugin.
 *
 * Effective rules always go through Policy::evaluate() via Policy_Simulator
 * (same path as live enforcement / AICAC-SIM parity).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Plugin_Profile {

	/** Max incident rows listed on the profile page. */
	public const INCIDENT_LIST_LIMIT = 20;

	/**
	 * Sanitize a plugin basename from a query/path argument.
	 * Rejects traversal and non-plugin shapes; does not require the plugin to be installed.
	 *
	 * @param mixed $raw
	 */
	public static function sanitize_plugin( $raw ): string {
		$raw_str = (string) $raw;
		// Absolute / UNC-style paths never appear as WP plugin basenames.
		if ( preg_match( '#^[/\\\\]#', $raw_str ) || false !== strpos( $raw_str, '..' ) ) {
			return '';
		}
		$plugin = sanitize_text_field( $raw_str );
		$plugin = str_replace( '\\', '/', $plugin );
		$plugin = ltrim( $plugin, '/' );
		if ( '' === $plugin || false !== strpos( $plugin, '..' ) ) {
			return '';
		}
		// Single-file (hello.php) or dir/file.php — WordPress plugin_basename shapes.
		if ( ! preg_match( '/^[A-Za-z0-9._\-]+(?:\/[A-Za-z0-9._\-]+)*\.php$/', $plugin ) ) {
			return '';
		}

		return $plugin;
	}

	/**
	 * Admin URL for this plugin's profile page.
	 */
	public static function profile_url( string $plugin ): string {
		$plugin = self::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return '';
		}

		return add_query_arg(
			array(
				'page'               => 'handl-ai-connector-access-control',
				'handl_aicac_tab'    => 'profile',
				'handl_aicac_plugin' => $plugin,
			),
			admin_url( 'options-general.php' )
		);
	}

	/**
	 * Rules tab deep-link anchored to this plugin's matrix row.
	 */
	public static function rules_url( string $plugin ): string {
		$plugin = self::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return add_query_arg(
				array(
					'page'            => 'handl-ai-connector-access-control',
					'handl_aicac_tab' => 'rules',
				),
				admin_url( 'options-general.php' )
			);
		}

		return add_query_arg(
			array(
				'page'                      => 'handl-ai-connector-access-control',
				'handl_aicac_tab'           => 'rules',
				'handl_aicac_focus_plugin'  => $plugin,
			),
			admin_url( 'options-general.php' )
		) . '#handl-aicac-rule-' . rawurlencode( md5( $plugin ) );
	}

	/**
	 * Activity tab with this plugin filter pre-applied (CSV export uses the same filters).
	 *
	 * Built from admin_url (clean base — not the current request) so profile query args
	 * like handl_aicac_plugin cannot stick. Fragment forces a real navigation even when
	 * the Activity nav-tab is already visually active on the profile screen.
	 */
	public static function activity_url( string $plugin ): string {
		$plugin = self::sanitize_plugin( $plugin );
		$args   = array(
			'page'            => 'handl-ai-connector-access-control',
			'handl_aicac_tab' => 'activity',
		);
		if ( '' !== $plugin ) {
			$args['handl_aicac_log_plugin'] = $plugin;
		}

		return add_query_arg( $args, admin_url( 'options-general.php' ) ) . '#handl-aicac-log-wrap';
	}

	/**
	 * Build the read-only profile payload.
	 *
	 * @param array<int,mixed>                  $log     Retained audit log (already TTL-pruned).
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $plugins Installed plugins (get_plugins()).
	 * @param array<string,bool>                $active  Active plugin basenames.
	 * @return array<string,mixed>
	 */
	public static function build( string $plugin, array $log, array $policy, array $plugins, array $active = array() ): array {
		$plugin = self::sanitize_plugin( $plugin );
		$installed = '' !== $plugin && isset( $plugins[ $plugin ] );
		$label     = $plugin;
		if ( $installed && isset( $plugins[ $plugin ]['Name'] ) ) {
			$label = (string) $plugins[ $plugin ]['Name'];
		}

		$logging_on = ! empty( $policy['log_enabled'] ) || ! empty( $policy['audit_only'] );
		$retention  = Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null );

		$rows = array();
		if ( '' !== $plugin && $logging_on ) {
			foreach ( $log as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$row_plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
				if ( $row_plugin === $plugin ) {
					$rows[] = $row;
				}
			}
		}

		$first_ts = 0;
		$last_ts  = 0;
		foreach ( $rows as $row ) {
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			$first_candidate = isset( $row['first_ts'] ) ? (int) $row['first_ts'] : $ts;
			if ( $first_candidate > 0 && ( 0 === $first_ts || $first_candidate < $first_ts ) ) {
				$first_ts = $first_candidate;
			}
			if ( $ts > $last_ts ) {
				$last_ts = $ts;
			}
		}

		return array(
			'plugin'           => $plugin,
			'label'            => $label,
			'installed'        => $installed,
			'active'           => $installed && isset( $active[ $plugin ] ),
			'logging_enabled'  => $logging_on,
			'retention_days'   => $retention,
			'first_ts'         => $first_ts,
			'last_ts'          => $last_ts,
			'row_count'        => count( $rows ),
			'effective'        => self::effective_ruleset( $policy, $plugin ),
			'usage'            => self::usage_from_rows( $rows, $policy ),
			'incidents'        => self::incidents_from_rows( $rows ),
			'actions'          => array(
				'rules_url'    => self::rules_url( $plugin ),
				'activity_url' => self::activity_url( $plugin ),
				'profile_url'  => self::profile_url( $plugin ),
			),
		);
	}

	/**
	 * Effective rules for this plugin via Policy::evaluate (no parallel decision tree).
	 *
	 * @param array<string,mixed> $policy
	 * @return array<string,mixed>
	 */
	public static function effective_ruleset( array $policy, string $plugin ): array {
		$plugin = self::sanitize_plugin( $plugin );
		$exceptions = Policy::get_kill_switch_exceptions( $policy );
		$ks_on      = ! empty( $policy['kill_switch'] );
		$ks_ex      = '' !== $plugin && in_array( $plugin, $exceptions, true );

		$plugin_eval = Policy_Simulator::evaluate_call( $policy, '' !== $plugin ? $plugin : null, null );
		$plugin_verdict = Policy_Simulator::verdict_from_eval( $plugin_eval );

		$configured = self::configured_matrix_row( $policy, $plugin );

		$families = array();
		foreach ( Operations::families() as $family ) {
			$op   = Operations::canonical_operation_for_family( $family );
			$eval = Policy_Simulator::evaluate_call(
				$policy,
				'' !== $plugin ? $plugin : null,
				$op,
				null,
				$family
			);
			$families[] = array(
				'family'      => $family,
				'label'       => Operations::family_labels()[ $family ] ?? $family,
				'operation'   => $op,
				'configured'  => $configured[ $family ] ?? 'inherit',
				'eval'        => $eval,
				'verdict'     => Policy_Simulator::verdict_from_eval( $eval ),
			);
		}

		$unknown_eval = Policy_Simulator::evaluate_call(
			$policy,
			'' !== $plugin ? $plugin : null,
			'generate_result',
			null,
			Operations::FAMILY_UNKNOWN
		);

		return array(
			'kill_switch'           => $ks_on,
			'kill_switch_exception' => $ks_ex,
			'plugin_rule'           => $configured['plugin'] ?? 'default',
			'plugin_eval'           => $plugin_eval,
			'plugin_verdict'        => $plugin_verdict,
			'families'              => $families,
			'unknown_operation'     => array(
				'configured' => Policy::sanitize_unknown_operation( $policy['unknown_operation'] ?? 'inherit' ),
				'eval'       => $unknown_eval,
				'verdict'    => Policy_Simulator::verdict_from_eval( $unknown_eval ),
			),
		);
	}

	/**
	 * Configured matrix cells (not effective outcome) for display beside evaluate().
	 *
	 * @param array<string,mixed> $policy
	 * @return array<string,string>
	 */
	public static function configured_matrix_row( array $policy, string $plugin ): array {
		$plugin = self::sanitize_plugin( $plugin );
		$out    = array(
			'plugin' => 'default',
		);
		$rules = is_array( $policy['plugins'] ?? null ) ? (array) $policy['plugins'] : array();
		if ( '' !== $plugin && isset( $rules[ $plugin ] ) ) {
			$rule = (string) $rules[ $plugin ];
			$out['plugin'] = ( 'deny' === $rule ) ? 'deny' : ( ( 'allow' === $rule ) ? 'allow' : 'default' );
		}

		$ops = is_array( $policy['operations'] ?? null ) ? (array) $policy['operations'] : array();
		$plugin_ops = ( '' !== $plugin && isset( $ops[ $plugin ] ) && is_array( $ops[ $plugin ] ) )
			? $ops[ $plugin ]
			: array();
		foreach ( Operations::families() as $family ) {
			$rule = isset( $plugin_ops[ $family ] ) ? (string) $plugin_ops[ $family ] : '';
			$out[ $family ] = ( 'allow' === $rule || 'deny' === $rule ) ? $rule : 'inherit';
		}

		return $out;
	}

	/**
	 * @param list<array<string,mixed>> $rows
	 * @param array<string,mixed>       $policy
	 * @return array<string,mixed>
	 */
	public static function usage_from_rows( array $rows, array $policy ): array {
		$calls = 0;
		$usd   = 0.0;
		$by_day = array();
		$by_op  = array();
		$by_model = array();

		foreach ( $rows as $row ) {
			$channel = isset( $row['channel'] ) ? (string) $row['channel'] : '';
			// Spend / AI Client usage only — shadow + threshold alerts are incidents.
			if ( 'direct_http' === $channel || 'spend_threshold' === $channel ) {
				continue;
			}

			$n = 1;
			++$calls;
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			$day = $ts > 0
				? ( function_exists( 'wp_date' ) ? wp_date( 'Y-m-d', $ts ) : gmdate( 'Y-m-d', $ts ) )
				: 'unknown';

			$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
			$out = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
			$provider = isset( $row['provider'] ) ? (string) $row['provider'] : '';
			$est = Cost::estimate_usd( $in, $out, Cost::rates_from_policy( $policy, $provider ) );
			$est_f = null !== $est ? (float) $est : 0.0;
			$usd  += $est_f;

			if ( ! isset( $by_day[ $day ] ) ) {
				$by_day[ $day ] = array(
					'day'   => $day,
					'calls' => 0,
					'usd'   => 0.0,
				);
			}
			$by_day[ $day ]['calls'] += $n;
			$by_day[ $day ]['usd']   += $est_f;

			$op = isset( $row['operation'] ) ? (string) $row['operation'] : '';
			if ( '' === $op ) {
				$op = Analytics::UNKNOWN_KEY;
			}
			if ( ! isset( $by_op[ $op ] ) ) {
				$by_op[ $op ] = array(
					'key'   => $op,
					'calls' => 0,
					'usd'   => 0.0,
				);
			}
			$by_op[ $op ]['calls'] += $n;
			$by_op[ $op ]['usd']   += $est_f;

			$model = Audit_Export::row_model( $row );
			if ( '' === $model ) {
				$model = Analytics::UNKNOWN_KEY;
			}
			if ( ! isset( $by_model[ $model ] ) ) {
				$by_model[ $model ] = array(
					'key'   => $model,
					'calls' => 0,
					'usd'   => 0.0,
				);
			}
			$by_model[ $model ]['calls'] += $n;
			$by_model[ $model ]['usd']   += $est_f;
		}

		krsort( $by_day );
		$by_op    = self::sort_buckets_desc( $by_op );
		$by_model = self::sort_buckets_desc( $by_model );

		return array(
			'calls'          => $calls,
			'estimated_usd'  => round( $usd, 4 ),
			'by_day'         => array_values( $by_day ),
			'by_operation'   => $by_op,
			'by_model'       => $by_model,
		);
	}

	/**
	 * @param list<array<string,mixed>> $rows
	 * @return array<string,mixed>
	 */
	public static function incidents_from_rows( array $rows ): array {
		$denials = array();
		$shadow  = array();
		$alerts  = array();
		$denial_n = 0;
		$shadow_n = 0;
		$alert_n  = 0;

		// Newest first.
		$ordered = array_reverse( $rows );
		foreach ( $ordered as $row ) {
			$channel  = isset( $row['channel'] ) ? (string) $row['channel'] : '';
			$decision = isset( $row['decision'] ) ? (string) $row['decision'] : '';
			$ts       = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			$count    = isset( $row['count'] ) ? max( 1, (int) $row['count'] ) : 1;

			if ( 'spend_threshold' === $channel ) {
				++$alert_n;
				if ( count( $alerts ) < self::INCIDENT_LIST_LIMIT ) {
					$alerts[] = array(
						'ts'        => $ts,
						'threshold' => isset( $row['threshold'] ) ? (float) $row['threshold'] : 0.0,
						'est_usd'   => isset( $row['est_usd'] ) ? (float) $row['est_usd'] : 0.0,
						'scope'     => isset( $row['scope'] ) ? (string) $row['scope'] : 'plugin',
					);
				}
				continue;
			}

			if ( 'direct_http' === $channel ) {
				$shadow_n += $count;
				if ( count( $shadow ) < self::INCIDENT_LIST_LIMIT ) {
					$shadow[] = array(
						'ts'       => $ts,
						'decision' => $decision,
						'host'     => isset( $row['host'] ) ? (string) $row['host'] : '',
						'count'    => $count,
					);
				}
				continue;
			}

			if ( 'deny' === $decision ) {
				++$denial_n;
				if ( count( $denials ) < self::INCIDENT_LIST_LIMIT ) {
					$denials[] = array(
						'ts'            => $ts,
						'operation'     => isset( $row['operation'] ) ? (string) $row['operation'] : '',
						'denial_reason' => isset( $row['denial_reason'] ) ? (string) $row['denial_reason'] : '',
						'provider'      => isset( $row['provider'] ) ? (string) $row['provider'] : '',
					);
				}
			}
		}

		return array(
			'denial_count'      => $denial_n,
			'shadow_call_count' => $shadow_n,
			'spend_alert_count' => $alert_n,
			'denials'           => $denials,
			'shadow'            => $shadow,
			'spend_alerts'      => $alerts,
		);
	}

	/**
	 * @param array<string,array{key:string,calls:int,usd:float}> $map
	 * @return list<array{key:string,calls:int,usd:float}>
	 */
	private static function sort_buckets_desc( array $map ): array {
		$list = array_values( $map );
		usort(
			$list,
			static function ( array $a, array $b ): int {
				if ( $a['calls'] === $b['calls'] ) {
					return $b['usd'] <=> $a['usd'];
				}
				return $b['calls'] <=> $a['calls'];
			}
		);

		return $list;
	}
}
