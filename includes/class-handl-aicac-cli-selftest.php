<?php
/**
 * AICAC-SELFTEST (#218): WP-CLI `wp handl-aicac verify`.
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
final class CLI_Selftest {

	public static function register(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac verify', array( self::class, 'cmd_verify' ) );
	}

	/**
	 * Prove the live AI Client gate with a deny and an allow probe.
	 *
	 * Installs a temporary rule for a reserved internal caller, fires the
	 * real blocking filter both ways, then restores stored rules. No
	 * provider traffic. Test Activity rows are marked and excluded from totals.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac verify
	 *
	 * ## EXIT CODES
	 *
	 * * 0 — Every link passed and stored rules are unchanged.
	 * * 1 — A link failed. The message names the setting to check.
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public static function cmd_verify( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		$result = self::execute();
		foreach ( $result['logs'] as $line ) {
			\WP_CLI::log( (string) $line );
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
	 * Command-level verify without WP-CLI (PHPUnit).
	 *
	 * @return array{
	 *   exit_code:int,
	 *   logs:list<string>,
	 *   success?:string,
	 *   error?:string,
	 *   report:array<string,mixed>
	 * }
	 */
	public static function execute(): array {
		$report = Selftest::run();
		$logs   = array();
		$links  = isset( $report['links'] ) && is_array( $report['links'] ) ? $report['links'] : array();
		foreach ( $links as $link ) {
			if ( ! is_array( $link ) ) {
				continue;
			}
			$mark   = ! empty( $link['pass'] ) ? 'pass' : 'FAIL';
			$logs[] = $mark . '  ' . (string) ( $link['label'] ?? '' );
		}

		if ( ! empty( $report['ok'] ) ) {
			return array(
				'exit_code' => 0,
				'logs'      => $logs,
				'success'   => 'Enforcement check passed.',
				'report'    => $report,
			);
		}

		$error = isset( $report['message'] ) ? (string) $report['message'] : 'Enforcement check failed.';
		if ( '' === $error ) {
			$error = 'Enforcement check failed.';
		}

		return array(
			'exit_code' => 1,
			'logs'      => $logs,
			'error'     => $error,
			'report'    => $report,
		);
	}
}
