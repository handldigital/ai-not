<?php
/**
 * AICAC-SIEM (#235): WP-CLI `wp handl-aicac siem`.
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
final class CLI_Siem {

	public static function register(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac siem', self::class );
	}

	/**
	 * Show whether SIEM export is on and where the file sink writes.
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
	 *     wp handl-aicac siem status
	 *
	 * @subcommand status
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$st     = Siem::status();

		if ( 'json' === $format ) {
			\WP_CLI::print_value( $st, array( 'format' => 'json' ) );
			return;
		}

		\WP_CLI::log(
			sprintf(
				'SIEM export: %s | syslog=%s | file=%s | format=%s | file_path=%s',
				! empty( $st['enabled'] ) ? 'on' : 'off',
				! empty( $st['syslog_enabled'] ) ? 'on' : 'off',
				! empty( $st['file_enabled'] ) ? 'on' : 'off',
				(string) $st['format'],
				'' !== (string) $st['file_path'] ? (string) $st['file_path'] : '(none yet)'
			)
		);
	}

	/**
	 * Enable or disable sinks / set line format (off by default).
	 *
	 * ## OPTIONS
	 *
	 * [--syslog=<on|off>]
	 * : Local syslog() sink.
	 *
	 * [--file=<on|off>]
	 * : JSON-lines / CEF file under uploads.
	 *
	 * [--format=<cef|json>]
	 * : Line format for both sinks.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac siem set --syslog=on --format=cef
	 *     wp handl-aicac siem set --file=on --format=json
	 *     wp handl-aicac siem set --syslog=off --file=off
	 *
	 * @subcommand set
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function set( $args, $assoc_args ): void {
		unset( $args );
		$changes = array();

		if ( isset( $assoc_args['syslog'] ) ) {
			$changes['syslog'] = self::parse_on_off( (string) $assoc_args['syslog'] );
			if ( null === $changes['syslog'] ) {
				\WP_CLI::error( '--syslog must be on or off.' );
			}
		}
		if ( isset( $assoc_args['file'] ) ) {
			$changes['file'] = self::parse_on_off( (string) $assoc_args['file'] );
			if ( null === $changes['file'] ) {
				\WP_CLI::error( '--file must be on or off.' );
			}
		}
		if ( isset( $assoc_args['format'] ) ) {
			$fmt = sanitize_key( (string) $assoc_args['format'] );
			if ( ! in_array( $fmt, array( Siem::FORMAT_CEF, Siem::FORMAT_JSON ), true ) ) {
				\WP_CLI::error( '--format must be cef or json.' );
			}
			$changes['format'] = $fmt;
		}

		if ( empty( $changes ) ) {
			\WP_CLI::error( 'Pass at least one of --syslog, --file, or --format.' );
		}

		$st = Siem::apply_settings( $changes );
		\WP_CLI::success(
			sprintf(
				'SIEM export updated: syslog=%s file=%s format=%s',
				! empty( $st['syslog_enabled'] ) ? 'on' : 'off',
				! empty( $st['file_enabled'] ) ? 'on' : 'off',
				(string) $st['format']
			)
		);
	}

	/**
	 * Emit one synthetic SIEM event so collectors can verify the pipeline.
	 *
	 * Requires at least one sink enabled (`siem set`). Prints the formatted line.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac siem test
	 *
	 * @subcommand test
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function test( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		$st = Siem::status();
		if ( empty( $st['enabled'] ) ) {
			\WP_CLI::error( 'SIEM export is off. Enable a sink first: wp handl-aicac siem set --syslog=on' );
		}

		$result = Siem::emit_test();
		\WP_CLI::log( $result['line'] );
		if ( empty( $result['ok'] ) ) {
			\WP_CLI::error( 'Test line was formatted but no sink accepted it.' );
		}
		\WP_CLI::success( 'SIEM test event emitted.' );
	}

	/**
	 * @return bool|null
	 */
	private static function parse_on_off( string $raw ): ?bool {
		$key = sanitize_key( $raw );
		if ( in_array( $key, array( 'on', '1', 'true', 'yes' ), true ) ) {
			return true;
		}
		if ( in_array( $key, array( 'off', '0', 'false', 'no' ), true ) ) {
			return false;
		}
		return null;
	}
}
