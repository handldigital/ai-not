<?php
/**
 * WP-CLI: `wp aicac latency list` for AICAC-LATENCY (#302).
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
final class CLI_Latency {

	public static function register(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'aicac latency', self::class );
	}

	/**
	 * List per-provider latency stats for the last hour (count, p50, p95).
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
	 *     wp aicac latency list
	 *     wp aicac latency list --format=json
	 *
	 * @subcommand list
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function list_( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		if ( 'json' !== $format ) {
			$format = 'table';
		}

		$rows = Latency::provider_stats( Clock::now() );

		if ( 'json' === $format ) {
			\WP_CLI::print_value( $rows, array( 'format' => 'json' ) );
			return;
		}

		if ( empty( $rows ) ) {
			\WP_CLI::log( __( 'No timed calls yet.', 'handl-ai-connector-access-control' ) );
			return;
		}

		$table = array();
		foreach ( $rows as $row ) {
			$table[] = array(
				'provider' => (string) $row['provider'],
				'count'    => (string) (int) $row['count'],
				'p50_ms'   => (string) (int) $row['p50'],
				'p95_ms'   => (string) (int) $row['p95'],
			);
		}
		\WP_CLI\Utils\format_items( 'table', $table, array( 'provider', 'count', 'p50_ms', 'p95_ms' ) );
	}
}
