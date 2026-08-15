<?php
/**
 * Read-only REST API for policy state and activity aggregates (AICAC-REST).
 *
 * Namespace: handl-aicac/v1. No write/mutation routes in v1.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Rest {
	public const NAMESPACE = 'handl-aicac/v1';

	/** Default activity window when the query arg is omitted. */
	public const DEFAULT_WINDOW = '7d';

	/** Max top plugins returned in activity summary. */
	public const TOP_PLUGINS = 10;

	/**
	 * Supported window tokens → seconds (0 = entire retained log).
	 *
	 * @var array<string,int>
	 */
	private const WINDOW_SECONDS = array(
		'1d'  => 86400,
		'7d'  => 604800,
		'30d' => 2592000,
		'all' => 0,
	);

	private static ?Rest $instance = null;

	public static function instance(): Rest {
		if ( null === self::$instance ) {
			self::$instance = new Rest();
		}
		return self::$instance;
	}

	public function init(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Route table for registration and PHPUnit (GET-only contract).
	 *
	 * @return list<array{route:string,methods:string,callback:string}>
	 */
	public static function route_definitions(): array {
		return array(
			array(
				'route'    => '/policy',
				'methods'  => 'GET',
				'callback' => 'get_policy',
			),
			array(
				'route'    => '/activity/summary',
				'methods'  => 'GET',
				'callback' => 'get_activity_summary',
			),
			array(
				'route'    => '/health',
				'methods'  => 'GET',
				'callback' => 'get_health',
			),
		);
	}

	/**
	 * Register all routes under handl-aicac/v1.
	 */
	public function register_routes(): void {
		if ( ! function_exists( 'register_rest_route' ) ) {
			return;
		}

		foreach ( self::route_definitions() as $def ) {
			register_rest_route(
				self::NAMESPACE,
				$def['route'],
				array(
					'methods'             => $def['methods'],
					'callback'            => array( $this, $def['callback'] ),
					'permission_callback' => array( $this, 'permission_check' ),
				)
			);
		}
	}

	/**
	 * Standard REST permission: manage_options (application passwords work out of the box).
	 *
	 * @param mixed $request Unused request object.
	 */
	public function permission_check( $request = null ): bool {
		unset( $request );
		return function_exists( 'current_user_can' ) && current_user_can( 'manage_options' );
	}

	/**
	 * GET /policy — active rule summary (aggregates only).
	 *
	 * @param mixed $request Unused.
	 * @return array<string,mixed>|\WP_Error
	 */
	public function get_policy( $request = null ) {
		unset( $request );
		$policy = Policy::get_policy();
		return self::build_policy_payload( $policy );
	}

	/**
	 * GET /activity/summary?window=7d — retained-log aggregates.
	 *
	 * @param mixed $request WP_REST_Request-like with get_param(), or null.
	 * @return array<string,mixed>|\WP_Error
	 */
	public function get_activity_summary( $request = null ) {
		$raw_window = self::DEFAULT_WINDOW;
		if ( is_object( $request ) && method_exists( $request, 'get_param' ) ) {
			$param = $request->get_param( 'window' );
			if ( null !== $param && '' !== (string) $param ) {
				$raw_window = (string) $param;
			}
		}

		$window = self::sanitize_window( $raw_window );
		$policy = Policy::get_policy();
		$log    = Policy::get_retained_log();

		return self::build_activity_summary( $policy, $log, $window, time() );
	}

	/**
	 * GET /health — same verdict as Site Health (#80).
	 *
	 * @param mixed $request Unused.
	 * @return array<string,mixed>|\WP_Error
	 */
	public function get_health( $request = null ) {
		unset( $request );
		$policy = Policy::get_policy();

		$installed = function_exists( 'get_plugins' ) ? get_plugins() : array();
		if ( ! is_array( $installed ) ) {
			$installed = array();
		}

		$active_raw = get_option( 'active_plugins', array() );
		$active     = array();
		if ( is_array( $active_raw ) ) {
			$active = array_fill_keys( array_map( 'strval', $active_raw ), true );
		}

		return self::build_health_payload( $policy, $installed, $active );
	}

	/**
	 * Pure policy summary for REST + tests.
	 *
	 * @param array<string,mixed> $policy
	 * @return array<string,mixed>
	 */
	public static function build_policy_payload( array $policy ): array {
		$plugin_by = array(
			'allow' => 0,
			'deny'  => 0,
		);
		$plugins = is_array( $policy['plugins'] ?? null ) ? (array) $policy['plugins'] : array();
		foreach ( $plugins as $rule ) {
			$rule = (string) $rule;
			if ( 'allow' === $rule || 'deny' === $rule ) {
				++$plugin_by[ $rule ];
			}
		}

		$ops_by = array(
			'allow' => 0,
			'deny'  => 0,
		);
		$operations = is_array( $policy['operations'] ?? null ) ? (array) $policy['operations'] : array();
		foreach ( $operations as $plugin_ops ) {
			if ( ! is_array( $plugin_ops ) ) {
				continue;
			}
			foreach ( $plugin_ops as $rule ) {
				$rule = (string) $rule;
				if ( 'allow' === $rule || 'deny' === $rule ) {
					++$ops_by[ $rule ];
				}
			}
		}

		$exceptions = Policy::get_kill_switch_exceptions( $policy );
		$allowed    = Policy::sanitize_allowed_roles( $policy['allowed_roles'] ?? array() );
		$tools      = is_array( $policy['denied_tools'] ?? null ) ? (array) $policy['denied_tools'] : array();

		return array(
			'default'                     => ( ( $policy['default'] ?? 'allow' ) === 'deny' ) ? 'deny' : 'allow',
			'plugin_rules_by_decision'    => $plugin_by,
			'operation_rules_by_decision' => $ops_by,
			'denied_tools_count'          => count( $tools ),
			'kill_switch'                 => array(
				'enabled'          => ! empty( $policy['kill_switch'] ),
				'exception_count'  => count( $exceptions ),
			),
			'role_gate'                   => array(
				'enabled'            => ! empty( $policy['role_gate_enabled'] ),
				'allowed_role_count' => count( $allowed ),
			),
			'log_enabled'                 => ! empty( $policy['log_enabled'] ),
			'audit_only'                  => ! empty( $policy['audit_only'] ),
			'log_limit'                   => (int) ( $policy['log_limit'] ?? 200 ),
			'log_max_age_days'            => Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null ),
		);
	}

	/**
	 * Pure activity summary. Never fabricates zeros when logging is disabled.
	 *
	 * @param array<string,mixed> $policy
	 * @param array<int,mixed>    $log
	 * @param string              $window Sanitized window token.
	 * @param int                 $now    Unix timestamp.
	 * @return array<string,mixed>
	 */
	public static function build_activity_summary( array $policy, array $log, string $window, int $now ): array {
		$window = self::sanitize_window( $window );
		$base   = array(
			'window'         => $window,
			'window_seconds' => self::WINDOW_SECONDS[ $window ],
		);

		$logging = ! empty( $policy['log_enabled'] ) || ! empty( $policy['audit_only'] );
		if ( ! $logging ) {
			return array_merge(
				$base,
				array(
					'status' => 'logging_disabled',
				)
			);
		}

		$filtered = self::filter_log_by_window( $log, $window, $now );
		if ( 0 === count( $filtered ) ) {
			return array_merge(
				$base,
				array(
					'status' => 'no_data',
				)
			);
		}

		$calls_by_decision = array();
		$plugin_calls      = array();
		$est_total         = 0.0;
		$est_any           = false;
		$shadow_count      = 0;
		$shadow_blocks     = 0;
		$client_calls      = 0;
		$denials_by_context = array(
			'frontend' => 0,
			'admin'    => 0,
			'cron'     => 0,
			'rest'     => 0,
			'unknown'  => 0,
		);
		$recent_denials = array();

		foreach ( $filtered as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}

			$is_direct = isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'];
			if ( $is_direct ) {
				$c = isset( $row['count'] ) ? (int) $row['count'] : 1;
				$c = $c > 0 ? $c : 1;
				$shadow_count += $c;
				$decision = isset( $row['decision'] ) ? sanitize_key( (string) $row['decision'] ) : 'observe';
				if ( 'deny' === $decision ) {
					$shadow_blocks += $c;
				}
				continue;
			}

			++$client_calls;
			$decision = isset( $row['decision'] ) ? sanitize_key( (string) $row['decision'] ) : 'unknown';
			if ( '' === $decision ) {
				$decision = 'unknown';
			}
			if ( ! isset( $calls_by_decision[ $decision ] ) ) {
				$calls_by_decision[ $decision ] = 0;
			}
			++$calls_by_decision[ $decision ];

			if ( 'deny' === $decision ) {
				$ctx = Policy::request_context_from_row( $row );
				if ( ! isset( $denials_by_context[ $ctx ] ) ) {
					$denials_by_context[ $ctx ] = 0;
				}
				++$denials_by_context[ $ctx ];
				$recent_denials[] = array(
					'ts'              => isset( $row['ts'] ) ? (int) $row['ts'] : 0,
					'plugin'          => isset( $row['plugin'] ) ? (string) $row['plugin'] : '',
					'request_context' => $ctx,
					'returned_error'  => Policy::returned_error_from_row( $row ),
				);
			}

			$plugin = isset( $row['plugin'] ) ? trim( (string) $row['plugin'] ) : '';
			if ( '' === $plugin ) {
				$plugin = Analytics::UNKNOWN_KEY;
			}
			if ( ! isset( $plugin_calls[ $plugin ] ) ) {
				$plugin_calls[ $plugin ] = array(
					'calls'          => 0,
					'estimated_usd'  => 0.0,
					'has_estimate'   => false,
				);
			}
			++$plugin_calls[ $plugin ]['calls'];

			$in    = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
			$out   = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
			$rates = Cost::rates_from_policy( $policy, isset( $row['provider'] ) ? (string) $row['provider'] : null );
			$usd   = Cost::estimate_usd( $in, $out, $rates );
			if ( null !== $usd ) {
				$est_any                            = true;
				$est_total                         += $usd;
				$plugin_calls[ $plugin ]['estimated_usd'] += $usd;
				$plugin_calls[ $plugin ]['has_estimate']   = true;
			}
		}

		// Prefer spend ranking when estimates exist; otherwise call volume.
		uasort(
			$plugin_calls,
			static function ( $a, $b ) use ( $est_any ) {
				if ( $est_any ) {
					$cmp = $b['estimated_usd'] <=> $a['estimated_usd'];
					if ( 0 !== $cmp ) {
						return $cmp;
					}
				}
				return $b['calls'] <=> $a['calls'];
			}
		);

		$top = array();
		$i   = 0;
		foreach ( $plugin_calls as $plugin => $row ) {
			if ( $i >= self::TOP_PLUGINS ) {
				break;
			}
			++$i;
			$entry = array(
				'plugin' => Analytics::UNKNOWN_KEY === $plugin ? null : $plugin,
				'calls'  => (int) $row['calls'],
			);
			if ( ! empty( $row['has_estimate'] ) ) {
				$entry['estimated_usd'] = round( (float) $row['estimated_usd'], 6 );
			}
			$top[] = $entry;
		}

		ksort( $calls_by_decision );

		// Newest denials first for QA without UI (AICAC-BLOCKED-UX Phase 1).
		usort(
			$recent_denials,
			static function ( array $a, array $b ): int {
				return (int) $b['ts'] <=> (int) $a['ts'];
			}
		);
		$recent_denials = array_slice( $recent_denials, 0, self::TOP_PLUGINS * 2 );

		$payload = array_merge(
			$base,
			array(
				'status'                       => 'ok',
				'calls_by_decision'            => $calls_by_decision,
				'ai_client_call_count'         => $client_calls,
				'top_plugins'                  => $top,
				'shadow_ai_observation_count'  => $shadow_count,
				'shadow_ai_block_count'        => $shadow_blocks,
				'denials_by_context'           => $denials_by_context,
				'recent_denials'               => $recent_denials,
			)
		);

		if ( $est_any ) {
			$payload['estimated_spend_usd'] = round( $est_total, 6 );
		}

		return $payload;
	}

	/**
	 * Health payload = Site_Health::build_snapshot (single source of truth).
	 *
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $installed_plugins
	 * @param array<string,bool>                $active_plugins
	 * @return array<string,mixed>
	 */
	public static function build_health_payload( array $policy, array $installed_plugins, array $active_plugins ): array {
		return Site_Health::build_snapshot( $policy, $installed_plugins, $active_plugins );
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_window( $raw ): string {
		$key = sanitize_key( (string) $raw );
		if ( isset( self::WINDOW_SECONDS[ $key ] ) ) {
			return $key;
		}
		return self::DEFAULT_WINDOW;
	}

	/**
	 * @param array<int,mixed> $log
	 * @return list<array<string,mixed>|mixed>
	 */
	public static function filter_log_by_window( array $log, string $window, int $now ): array {
		$window  = self::sanitize_window( $window );
		$seconds = self::WINDOW_SECONDS[ $window ];
		if ( $seconds <= 0 ) {
			return array_values( $log );
		}

		$cutoff = $now - $seconds;
		$out    = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			// Collapsed shadow clusters may carry first_ts; prefer newest activity (ts).
			if ( $ts <= 0 && isset( $row['first_ts'] ) ) {
				$ts = (int) $row['first_ts'];
			}
			if ( $ts >= $cutoff ) {
				$out[] = $row;
			}
		}
		return $out;
	}
}
