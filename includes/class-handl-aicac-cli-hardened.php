<?php
/**
 * WP-CLI for AICAC-MU-GUARD (#226) Phase 1 hardened mode.
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
final class CLI_Hardened {

	public static function register(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac hardened', self::class );
	}

	/**
	 * Enable hardened mode and install the must-use stub.
	 *
	 * ## OPTIONS
	 *
	 * --mode=<mode>
	 * : fail_closed (default) or watch.
	 * ---
	 * default: fail_closed
	 * options:
	 *   - fail_closed
	 *   - watch
	 * ---
	 *
	 * [--yes]
	 * : Skip the confirmation prompt.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac hardened enable --mode=fail_closed --yes
	 *     wp handl-aicac hardened enable --mode=watch --yes
	 *
	 * @subcommand enable
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function enable( $args, $assoc_args ): void {
		unset( $args );
		$mode = isset( $assoc_args['mode'] ) ? (string) $assoc_args['mode'] : Mu_Guard::MODE_FAIL_CLOSED;
		$path = Mu_Guard::stub_path();

		if ( empty( $assoc_args['yes'] ) ) {
			\WP_CLI::confirm(
				sprintf(
					'Write the hardened must-use stub to %s and set mode=%s?',
					$path,
					$mode
				)
			);
		}

		$result = Mu_Guard::enable( $mode );
		if ( empty( $result['ok'] ) ) {
			self::error_from_code( (string) ( $result['error'] ?? 'error' ), $path );
		}

		$status = $result['status'] ?? Mu_Guard::status();
		\WP_CLI::success(
			sprintf(
				'Hardened mode is on (%s). Stub: %s (version %s).',
				Mu_Guard::mode_label( (string) ( $status['mode'] ?? $mode ) ),
				(string) ( $status['stub_path'] ?? $path ),
				(string) ( $status['stub_version'] ?? Mu_Guard::STUB_VERSION )
			)
		);
	}

	/**
	 * Disable hardened mode and remove the must-use stub.
	 *
	 * ## OPTIONS
	 *
	 * [--yes]
	 * : Skip the confirmation prompt.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac hardened disable --yes
	 *
	 * @subcommand disable
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function disable( $args, $assoc_args ): void {
		unset( $args );
		$path = Mu_Guard::stub_path();

		if ( empty( $assoc_args['yes'] ) ) {
			\WP_CLI::confirm(
				sprintf( 'Remove the hardened stub at %s and turn hardened mode off?', $path )
			);
		}

		$result = Mu_Guard::disable();
		if ( empty( $result['ok'] ) ) {
			self::error_from_code( (string) ( $result['error'] ?? 'error' ), $path );
		}

		\WP_CLI::success( sprintf( 'Hardened mode is off. Stub removed (path was %s).', $path ) );
	}

	/**
	 * Show hardened mode and stub status.
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
	 *     wp handl-aicac hardened status
	 *
	 * @subcommand status
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args );
		$status = Mu_Guard::status();
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';

		if ( 'json' === $format ) {
			\WP_CLI::print_value( $status, array( 'format' => 'json' ) );
			return;
		}

		$rows = array(
			array(
				'field' => 'mode',
				'value' => '' === $status['mode'] ? 'off' : (string) $status['mode'],
			),
			array(
				'field' => 'stub_path',
				'value' => (string) $status['stub_path'],
			),
			array(
				'field' => 'stub_present',
				'value' => ! empty( $status['stub_present'] ) ? 'yes' : 'no',
			),
			array(
				'field' => 'stub_version',
				'value' => null === $status['stub_version'] ? '-' : (string) $status['stub_version'],
			),
			array(
				'field' => 'stub_current',
				'value' => ! empty( $status['stub_current'] ) ? 'yes' : 'no',
			),
			array(
				'field' => 'mu_writable',
				'value' => ! empty( $status['mu_writable'] ) ? 'yes' : 'no',
			),
			array(
				'field' => 'open_tamper_gap',
				'value' => ! empty( $status['open_tamper_gap'] ) ? 'yes' : 'no',
			),
		);

		\WP_CLI\Utils\format_items( 'table', $rows, array( 'field', 'value' ) );
	}

	/**
	 * @param string $code Error code.
	 * @param string $path Stub path for context.
	 */
	private static function error_from_code( string $code, string $path ): void {
		if ( 'invalid_mode' === $code ) {
			\WP_CLI::error( 'Mode must be fail_closed or watch.' );
		}
		if ( 'mu_dir_unwritable' === $code || 'mu_dir_create_failed' === $code ) {
			\WP_CLI::error( sprintf( 'Cannot write must-use stub under %s (directory not writable).', dirname( $path ) ) );
		}
		if ( 'missing_template' === $code ) {
			\WP_CLI::error( 'Hardened stub template is missing from the plugin package.' );
		}
		if ( 'stub_write_failed' === $code || 'stub_delete_failed' === $code || 'stub_unwritable' === $code ) {
			\WP_CLI::error( sprintf( 'Could not update stub file at %s.', $path ) );
		}
		\WP_CLI::error( 'Hardened mode change failed.' );
	}
}
