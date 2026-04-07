<?php
/**
 * Caller attribution helpers (best-effort).
 *
 * @package HandL_AIGate
 */

namespace HandL\AIGate;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Attribution {
	private static function starts_with( string $haystack, string $needle ): bool {
		if ( '' === $needle ) {
			return true;
		}
		return 0 === strpos( $haystack, $needle );
	}

	private static function contains( string $haystack, string $needle ): bool {
		if ( '' === $needle ) {
			return true;
		}
		return false !== strpos( $haystack, $needle );
	}

	/**
	 * Try to resolve which plugin initiated an AI call.
	 *
	 * Returns an array like:
	 * - plugin: string|null (plugin basename, e.g. "hello-dolly/hello.php")
	 * - file: string|null (resolved source file)
	 * - method: string ("plugin"|"mu-plugin"|"unknown")
	 */
	public static function resolve_from_backtrace( int $limit = 60 ): array {
		// Using an exception trace avoids debug_backtrace() (flagged by some sniffs as "debug").
		$trace = ( new \Exception() )->getTrace();
		if ( count( $trace ) > $limit ) {
			$trace = array_slice( $trace, 0, $limit );
		}

		$plugin_dir    = wp_normalize_path( WP_PLUGIN_DIR );
		$mu_plugin_dir = defined( 'WPMU_PLUGIN_DIR' ) ? wp_normalize_path( WPMU_PLUGIN_DIR ) : null;
		$self_dir      = wp_normalize_path( dirname( HANDL_AIGATE_FILE ) );

		$plugins = function_exists( 'get_plugins' ) ? get_plugins() : array();
		$plugin_basenames_by_dir = self::index_plugins_by_directory( $plugins, $plugin_dir );

		foreach ( $trace as $frame ) {
			if ( empty( $frame['file'] ) ) {
				continue;
			}
			$file = wp_normalize_path( (string) $frame['file'] );

			// Skip frames from this plugin.
			if ( self::starts_with( $file, $self_dir . '/' ) ) {
				continue;
			}

			// Normal plugins.
			if ( self::starts_with( $file, $plugin_dir . '/' ) ) {
				$basename = self::plugin_basename_from_file( $file, $plugin_dir, $plugin_basenames_by_dir );
				return array(
					'plugin' => $basename,
					'file'   => $file,
					'method' => 'plugin',
				);
			}

			// MU plugins.
			if ( $mu_plugin_dir && self::starts_with( $file, $mu_plugin_dir . '/' ) ) {
				$basename = self::mu_plugin_basename_from_file( $file, $mu_plugin_dir );
				return array(
					'plugin' => $basename,
					'file'   => $file,
					'method' => 'mu-plugin',
				);
			}
		}

		return array(
			'plugin' => null,
			'file'   => null,
			'method' => 'unknown',
		);
	}

	/**
	 * @param array<string, array<string,mixed>> $plugins Output of get_plugins()
	 * @return array<string,string> Map plugin-dir-relative path (e.g. "akismet") => plugin basename (e.g. "akismet/akismet.php")
	 */
	private static function index_plugins_by_directory( array $plugins, string $plugin_dir ): array {
		$map = array();
		foreach ( $plugins as $basename => $data ) {
			$plugin_file = wp_normalize_path( $plugin_dir . '/' . $basename );
			$dir         = wp_normalize_path( dirname( $plugin_file ) );
			$rel_dir     = ltrim( str_replace( $plugin_dir, '', $dir ), '/' );
			if ( '' === $rel_dir ) {
				// Root-level single-file plugin: directory is plugins dir.
				$map[ '.' . '/' . $basename ] = $basename;
			} else {
				// First plugin file encountered in a directory "wins".
				$map[ $rel_dir ] ??= $basename;
			}
		}
		return $map;
	}

	/**
	 * @param array<string,string> $plugin_basenames_by_dir
	 */
	private static function plugin_basename_from_file( string $file, string $plugin_dir, array $plugin_basenames_by_dir ): ?string {
		$rel = ltrim( str_replace( $plugin_dir, '', $file ), '/' );
		if ( '' === $rel ) {
			return null;
		}

		// Common case: file is under a plugin directory (first path segment).
		$segments = explode( '/', $rel );
		$top_dir  = $segments[0] ?? '';
		if ( '' !== $top_dir && isset( $plugin_basenames_by_dir[ $top_dir ] ) ) {
			return $plugin_basenames_by_dir[ $top_dir ];
		}

		// Root-level plugin file.
		if ( self::contains( $rel, '.php' ) && file_exists( $plugin_dir . '/' . $rel ) ) {
			$maybe = plugin_basename( $plugin_dir . '/' . $rel );
			return is_string( $maybe ) && '' !== $maybe ? $maybe : null;
		}

		return null;
	}

	private static function mu_plugin_basename_from_file( string $file, string $mu_plugin_dir ): ?string {
		$rel = ltrim( str_replace( $mu_plugin_dir, '', $file ), '/' );
		if ( '' === $rel ) {
			return null;
		}
		// MU plugins are typically single-file; treat relative file as id.
		return $rel;
	}
}
