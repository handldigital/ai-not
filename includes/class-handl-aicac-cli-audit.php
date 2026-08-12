<?php
/**
 * S-105 / #31: read-only WP-CLI policy dump + activity log summary.
 *
 * Registers as `wp handl-aicac policy|log …`. Distinct from family-rule CLI
 * (`wp aicac rule`). Loaded only when WP_CLI is present.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Inspect policy and retained log from the shell (no writes).
 *
 * @when after_wp_load
 */
final class CLI_Audit {

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
		\WP_CLI::add_command( 'handl-aicac policy list', array( self::class, 'cmd_policy_list' ) );
		\WP_CLI::add_command( 'handl-aicac log summary', array( self::class, 'cmd_log_summary' ) );
	}

	/**
	 * Dump allow/deny matrix, Emergency stop, and site default.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Render format (table or json).
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac policy list
	 *     wp handl-aicac policy list --format=json
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public static function cmd_policy_list( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		if ( 'json' !== $format ) {
			$format = 'table';
		}

		$policy  = Policy::get_policy();
		$plugins = self::installed_plugins();
		$payload = self::build_policy_dump( $policy, $plugins );

		if ( 'json' === $format ) {
			\WP_CLI::print_value( $payload, array( 'format' => 'json' ) );
			return;
		}

		\WP_CLI::log(
			sprintf(
				'Default: %s | Emergency stop: %s | Exceptions: %d',
				(string) $payload['default'],
				! empty( $payload['kill_switch'] ) ? 'on' : 'off',
				(int) $payload['kill_switch_exception_count']
			)
		);
		$rows = isset( $payload['plugins'] ) && is_array( $payload['plugins'] ) ? $payload['plugins'] : array();
		if ( empty( $rows ) ) {
			\WP_CLI::log( 'No installed plugins found.' );
			return;
		}
		\WP_CLI\Utils\format_items( 'table', $rows, array( 'plugin', 'name', 'rule', 'effective' ) );
	}

	/**
	 * Aggregate retained-log counts (same Analytics call count as Dashboard Insights).
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Render format (table or json).
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac log summary
	 *     wp handl-aicac log summary --format=json
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public static function cmd_log_summary( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		if ( 'json' !== $format ) {
			$format = 'table';
		}

		$policy  = Policy::get_policy();
		$plugins = self::installed_plugins();
		$log     = Policy::get_retained_log();
		$payload = self::build_log_summary( $log, $policy, $plugins );

		if ( 'json' === $format ) {
			\WP_CLI::print_value( $payload, array( 'format' => 'json' ) );
			return;
		}

		if ( ! empty( $payload['logging_disabled'] ) ) {
			\WP_CLI::log( 'Activity logging and Learn mode are off — summary shows zero calls.' );
		}

		\WP_CLI::log(
			sprintf(
				'Calls: %d | Blocked: %d | Estimated spend: $%s',
				(int) ( $payload['calls'] ?? 0 ),
				(int) ( $payload['denials'] ?? 0 ),
				self::format_amount( (float) ( $payload['estimated_spend_usd'] ?? 0 ) )
			)
		);

		$top = isset( $payload['top_plugins'] ) && is_array( $payload['top_plugins'] ) ? $payload['top_plugins'] : array();
		if ( empty( $top ) ) {
			\WP_CLI::log( 'Top plugins by estimated spend: (none)' );
			return;
		}
		\WP_CLI::log( 'Top plugins by estimated spend:' );
		\WP_CLI\Utils\format_items( 'table', $top, array( 'plugin', 'name', 'calls', 'estimated_usd' ) );
	}

	/**
	 * Pure policy dump for PHPUnit + CLI.
	 *
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $plugins
	 * @return array{
	 *   default:string,
	 *   kill_switch:bool,
	 *   kill_switch_exception_count:int,
	 *   plugins:list<array{plugin:string,name:string,rule:string,effective:string}>
	 * }
	 */
	public static function build_policy_dump( array $policy, array $plugins ): array {
		$default = ( ( $policy['default'] ?? 'allow' ) === 'deny' ) ? 'deny' : 'allow';
		$kill    = ! empty( $policy['kill_switch'] );
		$exc     = Policy::get_kill_switch_exceptions( $policy );
		$map     = isset( $policy['plugins'] ) && is_array( $policy['plugins'] ) ? $policy['plugins'] : array();

		$rows = array();
		foreach ( $plugins as $basename => $data ) {
			$basename = sanitize_text_field( (string) $basename );
			if ( '' === $basename ) {
				continue;
			}
			$name = isset( $data['Name'] ) ? (string) $data['Name'] : $basename;
			$raw  = isset( $map[ $basename ] ) ? (string) $map[ $basename ] : '';
			$rule = ( 'allow' === $raw || 'deny' === $raw ) ? $raw : 'default';
			$eff  = ( 'allow' === $raw || 'deny' === $raw ) ? $raw : $default;
			$rows[] = array(
				'plugin'    => $basename,
				'name'      => $name,
				'rule'      => $rule,
				'effective' => $eff,
			);
		}

		return array(
			'default'                       => $default,
			'kill_switch'                   => $kill,
			'kill_switch_exception_count'   => count( $exc ),
			'plugins'                       => $rows,
		);
	}

	/**
	 * Pure log summary. Calls count reuses Analytics::aggregate_from_log;
	 * estimated spend / top plugins match Dashboard spend math.
	 *
	 * @param array<int,mixed>                  $log
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $plugins
	 * @return array<string,mixed>
	 */
	public static function build_log_summary( array $log, array $policy, array $plugins ): array {
		$logging = ! empty( $policy['log_enabled'] ) || ! empty( $policy['audit_only'] );
		if ( ! $logging ) {
			return array(
				'logging_disabled'     => true,
				'calls'                => 0,
				'denials'              => 0,
				'estimated_spend_usd'  => 0.0,
				'top_plugins'          => array(),
				'note'                 => 'Activity logging and Learn mode are off.',
			);
		}

		$agg   = Analytics::aggregate_from_log( $log, $plugins );
		$calls = (int) ( $agg['summary']['calls'] ?? 0 );

		$denials      = 0;
		$est_total    = 0.0;
		$plugin_spend = array();

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$channel = isset( $row['channel'] ) ? (string) $row['channel'] : '';
			if ( 'direct_http' === $channel
				|| 'spend_threshold' === $channel
				|| 'anomaly' === $channel
				|| 'drift' === $channel
				|| 'budget' === $channel
				|| 'alert_snooze' === $channel
				|| 'forecast_warn' === $channel ) {
				continue;
			}
			if ( 'deny' === (string) ( $row['decision'] ?? '' ) ) {
				++$denials;
			}
			$in    = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
			$out   = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
			$rates = Cost::rates_from_policy( $policy, isset( $row['provider'] ) ? (string) $row['provider'] : null );
			$usd   = Cost::estimate_usd( $in, $out, $rates );
			if ( null === $usd ) {
				continue;
			}
			$est_total += $usd;
			$p = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			if ( '' === $p ) {
				$p = Analytics::UNKNOWN_KEY;
			}
			if ( ! isset( $plugin_spend[ $p ] ) ) {
				$plugin_spend[ $p ] = array( 'usd' => 0.0, 'calls' => 0 );
			}
			$plugin_spend[ $p ]['usd']   += $usd;
			$plugin_spend[ $p ]['calls'] += 1;
		}

		uasort(
			$plugin_spend,
			static function ( $a, $b ) {
				return $b['usd'] <=> $a['usd'];
			}
		);

		$top = array();
		$i   = 0;
		foreach ( $plugin_spend as $basename => $row ) {
			if ( $i >= 3 ) {
				break;
			}
			++$i;
			$label = Analytics::UNKNOWN_KEY === $basename
				? '(unknown)'
				: ( isset( $plugins[ $basename ]['Name'] ) ? (string) $plugins[ $basename ]['Name'] : $basename );
			$top[] = array(
				'plugin'         => Analytics::UNKNOWN_KEY === $basename ? '' : $basename,
				'name'           => $label,
				'calls'          => (int) $row['calls'],
				'estimated_usd'  => round( (float) $row['usd'], 4 ),
			);
		}

		return array(
			'logging_disabled'    => false,
			'calls'               => $calls,
			'denials'             => $denials,
			'estimated_spend_usd' => round( $est_total, 4 ),
			'top_plugins'         => $top,
		);
	}

	/**
	 * @return array<string,array<string,mixed>>
	 */
	public static function installed_plugins(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			return array();
		}
		$plugins = get_plugins();
		return is_array( $plugins ) ? $plugins : array();
	}

	public static function format_amount( float $amount ): string {
		if ( $amount > 0 && $amount < 0.01 ) {
			return '0.01';
		}

		return function_exists( 'number_format_i18n' )
			? number_format_i18n( $amount, 2 )
			: number_format( $amount, 2, '.', '' );
	}
}
