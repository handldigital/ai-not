<?php
/**
 * WP-CLI for AICAC-RESCAN-SCHEDULE (#310).
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
final class CLI_Rescan {

	public static function register(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac rescan', self::class );
	}

	/**
	 * Show weekly re-scan status.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac rescan status
	 *
	 * @subcommand status
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		$st = Rescan_Schedule::status();
		if ( ! empty( $st['disabled'] ) ) {
			\WP_CLI::log( 'Weekly re-scan is turned off.' );
			return;
		}
		$when = (int) $st['last_run_at'] > 0
			? gmdate( 'c', (int) $st['last_run_at'] )
			: 'never';
		\WP_CLI::log( 'seeded: ' . ( ! empty( $st['seeded'] ) ? 'yes' : 'no' ) );
		\WP_CLI::log( 'last_run_at: ' . $when );
		\WP_CLI::log( 'new_findings: ' . (int) $st['new_findings'] );
		\WP_CLI::log( 'scheduled: ' . ( ! empty( $st['scheduled'] ) ? 'yes' : 'no' ) );
	}

	/**
	 * Run the weekly re-scan now.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac rescan now
	 *
	 * @subcommand now
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function now( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		$out = Rescan_Schedule::run();
		if ( ! empty( $out['disabled'] ) ) {
			\WP_CLI::error( 'Weekly re-scan is turned off.' );
		}
		if ( ! empty( $out['seeded'] ) && 0 === (int) $out['alerted'] && 0 === (int) $out['new_findings'] && 'disabled' !== (string) $out['error'] ) {
			\WP_CLI::success(
				sprintf(
					'Scanned %d plugins and themes. Baseline stored or unchanged. 0 new findings.',
					(int) $out['scanned']
				)
			);
			return;
		}
		\WP_CLI::success(
			sprintf(
				'Scanned %d plugins and themes. %d new findings.',
				(int) $out['scanned'],
				(int) $out['new_findings']
			)
		);
	}
}
