<?php
/**
 * WP-CLI for AICAC-PANIC-FREEZE (#267).
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
final class CLI_Freeze {

	public static function register(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac freeze', self::class );
	}

	/**
	 * Start a temporary deny-all freeze (Strict lockdown + auto-restore).
	 *
	 * ## OPTIONS
	 *
	 * --minutes=<minutes>
	 * : Duration. One of 15, 60, or 240.
	 *
	 * [--reason=<reason>]
	 * : Optional note stored with the freeze.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac freeze start --minutes=60
	 *
	 * @subcommand start
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function start( $args, $assoc_args ): void {
		unset( $args );
		$minutes = isset( $assoc_args['minutes'] ) ? (int) $assoc_args['minutes'] : 0;
		$reason  = isset( $assoc_args['reason'] ) ? (string) $assoc_args['reason'] : '';

		$result = Freeze::start( $minutes, $reason );
		if ( empty( $result['ok'] ) ) {
			$code = (string) ( $result['error'] ?? 'error' );
			if ( 'already_active' === $code ) {
				\WP_CLI::error( 'Panic freeze is already active. End it first, or wait for it to expire.' );
			}
			if ( 'invalid_minutes' === $code ) {
				\WP_CLI::error( 'Minutes must be 15, 60, or 240.' );
			}
			\WP_CLI::error( 'Could not start panic freeze.' );
		}

		$state = $result['state'] ?? array();
		\WP_CLI::success(
			sprintf(
				'Panic freeze is active for %d minutes (expires %s). AI Client calls are denied until it ends.',
				(int) ( $state['minutes'] ?? $minutes ),
				gmdate( 'c', (int) ( $state['expires_ts'] ?? 0 ) )
			)
		);
	}

	/**
	 * End an active freeze and restore the prior policy.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac freeze end
	 *
	 * @subcommand end
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function end( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		$result = Freeze::end();
		if ( empty( $result['ok'] ) ) {
			\WP_CLI::error( 'No active panic freeze to end.' );
		}
		\WP_CLI::success( 'Panic freeze ended. Previous policy restored.' );
	}

	/**
	 * Show whether a freeze is active and how much time remains.
	 *
	 * ## OPTIONS
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
	 *     wp handl-aicac freeze status
	 *
	 * @subcommand status
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$st     = Freeze::status();

		if ( 'json' === $format ) {
			\WP_CLI::print_value( $st, array( 'format' => 'json' ) );
			return;
		}

		if ( empty( $st['active'] ) ) {
			\WP_CLI::log( 'Panic freeze: inactive' );
			return;
		}

		$mins = (int) floor( ( (int) $st['remaining_seconds'] ) / 60 );
		$secs = ( (int) $st['remaining_seconds'] ) % 60;
		\WP_CLI::log(
			sprintf(
				'Panic freeze: active | remaining %dm %ds',
				$mins,
				$secs
			)
		);
	}
}
