<?php
/**
 * WP-CLI for AICAC-RETRY-STORM (#240).
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
final class CLI_Retry_Storm {

	public static function register(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac retry-storm', self::class );
	}

	/**
	 * Show retry-storm detector status.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac retry-storm status
	 *
	 * @subcommand status
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		$st = Retry_Storm::status();
		\WP_CLI::log(
			sprintf(
				'enabled=%s window=%ds threshold=%d live_storms=%d',
				! empty( $st['enabled'] ) ? 'yes' : 'no',
				(int) $st['window_seconds'],
				(int) $st['threshold'],
				count( $st['live_storms'] )
			)
		);
		foreach ( $st['live_storms'] as $row ) {
			\WP_CLI::log(
				sprintf(
					'  storm plugin=%s family=%s count=%d window_start=%d',
					(string) ( $row['plugin'] ?? '' ),
					(string) ( $row['family'] ?? '' ),
					(int) ( $row['count'] ?? 0 ),
					(int) ( $row['window_start'] ?? 0 )
				)
			);
		}
	}

	/**
	 * Update retry-storm settings (persisted on the policy option).
	 *
	 * ## OPTIONS
	 *
	 * [--enabled=<bool>]
	 * : on|off|true|false|1|0
	 *
	 * [--window=<seconds>]
	 * : Sliding window in seconds (5–600). Default 30.
	 *
	 * [--threshold=<n>]
	 * : Denies in the window before collapse (2–100). Default 5.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac retry-storm set --enabled=off
	 *     wp handl-aicac retry-storm set --window=30 --threshold=5 --enabled=on
	 *
	 * @subcommand set
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function set( $args, $assoc_args ): void {
		unset( $args );
		$changes = array();
		if ( isset( $assoc_args['enabled'] ) ) {
			$changes['enabled'] = self::parse_bool( (string) $assoc_args['enabled'] );
		}
		if ( isset( $assoc_args['window'] ) ) {
			$changes['window_seconds'] = (int) $assoc_args['window'];
		}
		if ( isset( $assoc_args['threshold'] ) ) {
			$changes['threshold'] = (int) $assoc_args['threshold'];
		}
		if ( empty( $changes ) ) {
			\WP_CLI::error( 'Pass --enabled and/or --window and/or --threshold.' );
		}
		$st = Retry_Storm::apply_settings( $changes );
		\WP_CLI::success(
			sprintf(
				'Retry-storm saved: enabled=%s window=%ds threshold=%d',
				! empty( $st['enabled'] ) ? 'yes' : 'no',
				(int) $st['window_seconds'],
				(int) $st['threshold']
			)
		);
	}

	private static function parse_bool( string $raw ): bool {
		$v = strtolower( trim( $raw ) );
		if ( in_array( $v, array( '1', 'true', 'yes', 'on' ), true ) ) {
			return true;
		}
		if ( in_array( $v, array( '0', 'false', 'no', 'off' ), true ) ) {
			return false;
		}
		\WP_CLI::error( 'Invalid --enabled value; use on|off.' );
		return false;
	}
}
