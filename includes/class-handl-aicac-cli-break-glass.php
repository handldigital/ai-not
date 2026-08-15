<?php
/**
 * WP-CLI for AICAC-BREAKGLASS (#202) Phase 1.
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
final class CLI_Break_Glass {

	public static function register(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac break-glass', self::class );
	}

	/**
	 * Start a temporary global allow window.
	 *
	 * ## OPTIONS
	 *
	 * --minutes=<minutes>
	 * : Duration. One of 15, 30, or 60.
	 *
	 * --reason=<reason>
	 * : Required note explaining why the window was opened.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac break-glass start --minutes=30 --reason="Checkout outage triage"
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

		$result = Break_Glass::start( $minutes, $reason );
		if ( empty( $result['ok'] ) ) {
			$code = (string) ( $result['error'] ?? 'error' );
			if ( 'already_active' === $code ) {
				\WP_CLI::error( 'Break-glass mode is already active. Cancel it first, or wait for it to end.' );
			}
			if ( 'invalid_minutes' === $code ) {
				\WP_CLI::error( 'Minutes must be 15, 30, or 60.' );
			}
			if ( 'reason_required' === $code ) {
				\WP_CLI::error( 'A non-empty --reason is required.' );
			}
			\WP_CLI::error( 'Could not start break-glass mode.' );
		}

		$state = $result['state'] ?? array();
		\WP_CLI::success(
			sprintf(
				'Break-glass mode is active for %d minutes (expires %s). Policy rules will not block AI calls until it ends.',
				(int) ( $state['minutes'] ?? $minutes ),
				gmdate( 'c', (int) ( $state['expires_ts'] ?? 0 ) )
			)
		);
	}

	/**
	 * Cancel an active window and restore the prior policy.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac break-glass cancel
	 *
	 * @subcommand cancel
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function cancel( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		$result = Break_Glass::cancel();
		if ( empty( $result['ok'] ) ) {
			\WP_CLI::error( 'No active break-glass mode to cancel.' );
		}
		\WP_CLI::success( 'Break-glass mode cancelled. Previous policy restored.' );
	}

	/**
	 * Show whether a window is active and how much time remains.
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
	 *     wp handl-aicac break-glass status
	 *
	 * @subcommand status
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$st     = Break_Glass::status();

		if ( 'json' === $format ) {
			\WP_CLI::print_value( $st, array( 'format' => 'json' ) );
			return;
		}

		if ( empty( $st['active'] ) ) {
			\WP_CLI::log( 'Break-glass mode: inactive' );
			return;
		}

		$mins = (int) floor( ( (int) $st['remaining_seconds'] ) / 60 );
		$secs = ( (int) $st['remaining_seconds'] ) % 60;
		\WP_CLI::log(
			sprintf(
				'Break-glass mode: active | remaining %dm %ds | reason: %s',
				$mins,
				$secs,
				(string) $st['reason']
			)
		);
	}
}
