<?php
/**
 * AICAC-CLI-APPLY (#195): WP-CLI policy apply with dry-run diff.
 *
 * Registers `wp handl-aicac policy apply`. Writes only through
 * Policy::save_policy() so Policy_Snapshots (undo + history actor) stay intact.
 *
 * Exit codes (documented for scripting):
 * - 0: applied successfully, or dry-run with no differences
 * - 1: dry-run found differences; validation/refusal error; apply refused without --yes
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Apply a reviewed policy JSON export from the shell.
 *
 * @when after_wp_load
 */
final class CLI_Policy_Apply {

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
		\WP_CLI::add_command( 'handl-aicac policy apply', array( self::class, 'cmd_apply' ) );
	}

	/**
	 * Apply a policy export JSON file (full replace via save_policy).
	 *
	 * ## OPTIONS
	 *
	 * <file>
	 * : Path to a HandL AICAC rules export JSON file.
	 *
	 * [--dry-run]
	 * : Print the diff against the live policy and exit 1 when changes exist (exit 0 when identical). Does not write.
	 *
	 * [--yes]
	 * : Confirm apply. Required for a real write (ignored with --dry-run).
	 *
	 * [--allow-mismatched-site]
	 * : Allow apply when the export's site_url does not match this site's home URL.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac policy apply ./backup.json --dry-run
	 *     wp handl-aicac policy apply ./backup.json --yes
	 *     wp handl-aicac policy apply ./other-site.json --yes --allow-mismatched-site
	 *
	 * ## EXIT CODES
	 *
	 * * 0 — Applied, or dry-run with no differences.
	 * * 1 — Dry-run found differences; malformed/foreign export; missing --yes; site mismatch without --allow-mismatched-site.
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public static function cmd_apply( $args, $assoc_args ): void {
		$file = isset( $args[0] ) ? (string) $args[0] : '';
		if ( '' === $file ) {
			\WP_CLI::error( 'Usage: wp handl-aicac policy apply <file.json> [--dry-run] [--yes] [--allow-mismatched-site]', true );
		}

		$dry_run         = ! empty( $assoc_args['dry-run'] );
		$yes             = ! empty( $assoc_args['yes'] );
		$allow_mismatch  = ! empty( $assoc_args['allow-mismatched-site'] );
		$site_url        = self::current_site_url();

		$raw = self::read_file( $file );
		if ( is_array( $raw ) && isset( $raw['error'] ) ) {
			\WP_CLI::error( self::error_message( (string) $raw['error'], $file ), true );
		}

		$prepared = self::prepare_apply( (string) $raw, $site_url, $allow_mismatch );
		if ( empty( $prepared['ok'] ) ) {
			\WP_CLI::error( self::error_message( (string) ( $prepared['error'] ?? 'unknown' ), $file ), true );
		}

		$lines = isset( $prepared['diff_lines'] ) && is_array( $prepared['diff_lines'] )
			? $prepared['diff_lines']
			: array();
		$has_changes = ! empty( $prepared['has_changes'] );

		if ( ! empty( $prepared['ignored'] ) && is_array( $prepared['ignored'] ) ) {
			\WP_CLI::log( 'Ignored unknown export keys: ' . implode( ', ', $prepared['ignored'] ) );
		}

		if ( empty( $lines ) ) {
			\WP_CLI::log( 'No differences in comparable policy settings.' );
		} else {
			\WP_CLI::log( 'Policy changes:' );
			foreach ( $lines as $line ) {
				\WP_CLI::log( '  - ' . (string) $line );
			}
		}

		if ( $dry_run ) {
			if ( $has_changes ) {
				\WP_CLI::warning( 'Dry-run: changes would be applied. Re-run with --yes to write.' );
				\WP_CLI::halt( 1 );
			}
			\WP_CLI::success( 'Dry-run: live policy already matches the export.' );
			return;
		}

		if ( ! $yes ) {
			\WP_CLI::error( 'Refusing to apply without --yes. Use --dry-run to preview, or pass --yes to write through save_policy.', true );
		}

		$policy = isset( $prepared['policy'] ) && is_array( $prepared['policy'] ) ? $prepared['policy'] : array();
		self::commit_apply( $policy );

		if ( $has_changes ) {
			\WP_CLI::success( 'Policy applied. A restore snapshot was saved before the write.' );
		} else {
			\WP_CLI::success( 'Policy applied (no comparable differences from the live policy).' );
		}
	}

	/**
	 * Pure prepare step for PHPUnit + CLI.
	 *
	 * @return array{
	 *   ok:true,
	 *   policy:array<string,mixed>,
	 *   ignored:list<string>,
	 *   diff_lines:list<string>,
	 *   has_changes:bool,
	 *   export_site_url:string
	 * }|array{ok:false,error:string}
	 */
	public static function prepare_apply( string $json, string $current_site_url, bool $allow_mismatched_site ): array {
		$parsed = Policy_Transfer::parse_import( $json );
		if ( empty( $parsed['ok'] ) ) {
			return array(
				'ok'    => false,
				'error' => (string) ( $parsed['error'] ?? 'invalid_json' ),
			);
		}

		$export_site = self::extract_export_site_url( $json );
		if ( '' !== $export_site && '' !== $current_site_url ) {
			if ( ! self::site_urls_match( $export_site, $current_site_url ) && ! $allow_mismatched_site ) {
				return array(
					'ok'    => false,
					'error' => 'site_mismatch',
				);
			}
		}

		$incoming = Policy_Transfer::policy_for_save( is_array( $parsed['policy'] ?? null ) ? $parsed['policy'] : array() );
		$current  = Policy::get_policy();
		$ignored  = isset( $parsed['ignored'] ) && is_array( $parsed['ignored'] ) ? $parsed['ignored'] : array();
		$compare  = Policy_Transfer::compare_diff( $current, $incoming, $ignored );
		$rows     = isset( $compare['rows'] ) && is_array( $compare['rows'] ) ? $compare['rows'] : array();
		$lines    = self::format_compare_rows( $rows );

		return array(
			'ok'              => true,
			'policy'          => $incoming,
			'ignored'         => $ignored,
			'diff_lines'      => $lines,
			'has_changes'     => ! empty( $lines ),
			'export_site_url' => $export_site,
		);
	}

	/**
	 * Write through the shared save funnel (snapshots + history actor).
	 *
	 * @param array<string,mixed> $policy From policy_for_save().
	 */
	public static function commit_apply( array $policy ): void {
		Policy::save_policy( $policy );
	}

	/**
	 * @param list<array{key?:string,label?:string,current?:string,new?:string}> $rows
	 * @return list<string>
	 */
	public static function format_compare_rows( array $rows ): array {
		$lines = array();
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$label = isset( $row['label'] ) ? (string) $row['label'] : (string) ( $row['key'] ?? '' );
			$from  = isset( $row['current'] ) ? (string) $row['current'] : '';
			$to    = isset( $row['new'] ) ? (string) $row['new'] : '';
			if ( '' === $label ) {
				continue;
			}
			$lines[] = $label . ': ' . $from . ' → ' . $to;
		}
		return $lines;
	}

	public static function current_site_url(): string {
		if ( function_exists( 'home_url' ) ) {
			return (string) home_url( '/' );
		}
		return '';
	}

	/**
	 * Read optional site_url meta from the raw export JSON (not stored in policy).
	 */
	public static function extract_export_site_url( string $json ): string {
		$data = json_decode( $json, true );
		if ( ! is_array( $data ) || ! array_key_exists( 'site_url', $data ) ) {
			return '';
		}
		if ( ! is_scalar( $data['site_url'] ) ) {
			return '';
		}
		return self::normalize_site_url( (string) $data['site_url'] );
	}

	public static function site_urls_match( string $a, string $b ): bool {
		return self::normalize_site_url( $a ) === self::normalize_site_url( $b );
	}

	public static function normalize_site_url( string $url ): string {
		$url = trim( $url );
		if ( '' === $url ) {
			return '';
		}
		$parts = function_exists( 'wp_parse_url' ) ? wp_parse_url( $url ) : parse_url( $url );
		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			return rtrim( strtolower( $url ), '/' );
		}
		$host = strtolower( (string) $parts['host'] );
		$path = isset( $parts['path'] ) ? rtrim( (string) $parts['path'], '/' ) : '';
		if ( '' === $path || '/' === $path ) {
			return $host;
		}
		return $host . $path;
	}

	/**
	 * @return string|array{error:string}
	 */
	public static function read_file( string $path ) {
		$path = trim( $path );
		if ( '' === $path ) {
			return array( 'error' => 'missing_file' );
		}
		if ( ! is_readable( $path ) ) {
			return array( 'error' => 'unreadable_file' );
		}
		$size = filesize( $path );
		if ( false !== $size && $size > Policy_Transfer::MAX_UPLOAD_BYTES ) {
			return array( 'error' => 'too_large' );
		}
		$raw = file_get_contents( $path );
		if ( ! is_string( $raw ) ) {
			return array( 'error' => 'unreadable_file' );
		}
		return $raw;
	}

	public static function error_message( string $code, string $file = '' ): string {
		switch ( $code ) {
			case 'empty':
			case 'invalid_json':
				return 'Malformed export: file is empty or not valid JSON.';
			case 'missing_required_keys':
				return 'Foreign or incomplete export: plugin_version and exported_at are required.';
			case 'site_mismatch':
				return 'Export site_url does not match this site. Re-run with --allow-mismatched-site if intentional.';
			case 'missing_file':
				return 'Missing file path.';
			case 'unreadable_file':
				return '' !== $file
					? sprintf( 'Cannot read file: %s', $file )
					: 'Cannot read export file.';
			case 'too_large':
				return 'Export file exceeds the maximum allowed size.';
			default:
				return 'Unable to apply policy export.';
		}
	}
}
