<?php
/**
 * WP-CLI: `wp handl-aicac rate-cap` for AICAC-RATE-CAP (#275).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * @when after_wp_load
 */
final class CLI_Rate_Cap {

	public static function register(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac rate-cap', self::class );
	}

	/**
	 * Show call caps and current usage for one plugin.
	 *
	 * ## OPTIONS
	 *
	 * <plugin>
	 * : Plugin basename (e.g. acme-plugin/acme-plugin.php).
	 *
	 * [--format=<format>]
	 * : table or json.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac rate-cap get acme-plugin/acme-plugin.php
	 *
	 * @subcommand get
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function get( $args, $assoc_args ): void {
		$plugin = Plugin_Profile::sanitize_plugin( isset( $args[0] ) ? (string) $args[0] : '' );
		if ( '' === $plugin ) {
			\WP_CLI::error( 'Need a plugin basename like acme-plugin/acme-plugin.php.' );
		}

		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$policy = Policy::get_policy();
		$eval   = Rate_Cap::evaluate( $policy, $plugin );

		$payload = array(
			'plugin'     => $plugin,
			'hour_limit' => $eval['hour']['limit'],
			'hour_count' => $eval['hour']['count'],
			'day_limit'  => $eval['day']['limit'],
			'day_count'  => $eval['day']['count'],
			'prevent'    => ! empty( $eval['prevent'] ),
			'soft_warn'  => ! empty( $eval['soft_warn'] ),
		);

		if ( 'json' === $format ) {
			\WP_CLI::print_value( $payload, array( 'format' => 'json' ) );
			return;
		}

		$rows = array(
			array(
				'window' => 'hour',
				'limit'  => null === $payload['hour_limit'] ? 'unlimited' : (string) $payload['hour_limit'],
				'count'  => (string) $payload['hour_count'],
			),
			array(
				'window' => 'day',
				'limit'  => null === $payload['day_limit'] ? 'unlimited' : (string) $payload['day_limit'],
				'count'  => (string) $payload['day_count'],
			),
		);
		\WP_CLI::log( 'Plugin: ' . $plugin );
		\WP_CLI\Utils\format_items( 'table', $rows, array( 'window', 'limit', 'count' ) );
	}

	/**
	 * Set hour and/or day call caps for one plugin. Omit a flag to leave it unchanged; 0 clears that window.
	 *
	 * ## OPTIONS
	 *
	 * <plugin>
	 * : Plugin basename (e.g. acme-plugin/acme-plugin.php).
	 *
	 * [--hour=<n>]
	 * : Max calls this clock hour (0 = unlimited).
	 *
	 * [--day=<n>]
	 * : Max calls since local midnight (0 = unlimited).
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac rate-cap set acme-plugin/acme-plugin.php --hour=100 --day=1000
	 *
	 * @subcommand set
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function set( $args, $assoc_args ): void {
		$plugin = Plugin_Profile::sanitize_plugin( isset( $args[0] ) ? (string) $args[0] : '' );
		if ( '' === $plugin ) {
			\WP_CLI::error( 'Need a plugin basename like acme-plugin/acme-plugin.php.' );
		}
		if ( ! array_key_exists( 'hour', $assoc_args ) && ! array_key_exists( 'day', $assoc_args ) ) {
			\WP_CLI::error( 'Pass --hour and/or --day (0 clears that window).' );
		}

		$policy = Policy::get_policy();
		$hours  = Rate_Cap::sanitize_plugin_caps( $policy['plugin_rate_caps_hour'] ?? array() );
		$days   = Rate_Cap::sanitize_plugin_caps( $policy['plugin_rate_caps_day'] ?? array() );

		if ( array_key_exists( 'hour', $assoc_args ) ) {
			$cap = Rate_Cap::sanitize_cap( $assoc_args['hour'] );
			if ( null === $cap ) {
				unset( $hours[ $plugin ] );
			} else {
				$hours[ $plugin ] = $cap;
			}
		}
		if ( array_key_exists( 'day', $assoc_args ) ) {
			$cap = Rate_Cap::sanitize_cap( $assoc_args['day'] );
			if ( null === $cap ) {
				unset( $days[ $plugin ] );
			} else {
				$days[ $plugin ] = $cap;
			}
		}

		$policy['plugin_rate_caps_hour'] = $hours;
		$policy['plugin_rate_caps_day']  = $days;
		Policy::save_policy( $policy );

		\WP_CLI::success(
			sprintf(
				'Rate caps for %s: hour=%s day=%s.',
				$plugin,
				isset( $hours[ $plugin ] ) ? (string) $hours[ $plugin ] : 'unlimited',
				isset( $days[ $plugin ] ) ? (string) $days[ $plugin ] : 'unlimited'
			)
		);
	}

	/**
	 * Clear hour and day call caps for one plugin (unlimited).
	 *
	 * ## OPTIONS
	 *
	 * <plugin>
	 * : Plugin basename (e.g. acme-plugin/acme-plugin.php).
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac rate-cap clear acme-plugin/acme-plugin.php
	 *
	 * @subcommand clear
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function clear( $args, $assoc_args ): void {
		unset( $assoc_args );
		$plugin = Plugin_Profile::sanitize_plugin( isset( $args[0] ) ? (string) $args[0] : '' );
		if ( '' === $plugin ) {
			\WP_CLI::error( 'Need a plugin basename like acme-plugin/acme-plugin.php.' );
		}

		$policy = Policy::get_policy();
		$hours  = Rate_Cap::sanitize_plugin_caps( $policy['plugin_rate_caps_hour'] ?? array() );
		$days   = Rate_Cap::sanitize_plugin_caps( $policy['plugin_rate_caps_day'] ?? array() );
		unset( $hours[ $plugin ], $days[ $plugin ] );
		$policy['plugin_rate_caps_hour'] = $hours;
		$policy['plugin_rate_caps_day']  = $days;
		Policy::save_policy( $policy );

		\WP_CLI::success( sprintf( 'Cleared rate caps for %s.', $plugin ) );
	}
}
