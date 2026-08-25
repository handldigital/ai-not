<?php
/**
 * AICAC-MU-GUARD (#226): hardened mode — install/remove must-use stub.
 *
 * Detection of deactivation gaps remains Tamper (#222). This class is the
 * prevention side: keep a byte-versioned mu-plugin stub on disk so AI Client
 * calls stay blocked (or watched) while the main plugin is inactive.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hardened-mode installer and status reporter.
 */
final class Mu_Guard {

	/** Option: fail_closed | watch | empty/off. */
	public const MODE_OPTION = 'handl_aicac_hardened_mode';

	public const MODE_OFF         = '';
	public const MODE_FAIL_CLOSED = 'fail_closed';
	public const MODE_WATCH       = 'watch';

	/** Must match HANDL_AICAC_GUARD_STUB_VERSION in the shipped stub template. */
	public const STUB_VERSION = '1';

	public const STUB_FILENAME = 'handl-aicac-guard.php';

	/** Fallback log written by the stub while the main plugin is inactive. */
	public const FALLBACK_LOG_OPTION = 'handl_aicac_guard_fallback_log';

	/** Option: deactivation stamp the stub already alerted for. */
	public const ALERT_FOR_OPTION = 'handl_aicac_guard_alert_for';

	private static ?Mu_Guard $instance = null;

	public static function instance(): Mu_Guard {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function init(): void {
		// Phase 1: CLI + Site Health only (no admin UI — admin.php locked).
	}

	/**
	 * Absolute path of the shipped stub template inside this plugin.
	 */
	public static function template_path(): string {
		return HANDL_AICAC_DIR . '/includes/mu-stubs/' . self::STUB_FILENAME;
	}

	/**
	 * Target path under mu-plugins (or an injectable directory for tests).
	 *
	 * @param string|null $mu_dir Override WPMU_PLUGIN_DIR.
	 */
	public static function stub_path( ?string $mu_dir = null ): string {
		$dir = self::resolve_mu_dir( $mu_dir );
		return rtrim( $dir, '/\\' ) . '/' . self::STUB_FILENAME;
	}

	/**
	 * @param string|null $mu_dir Override.
	 */
	public static function resolve_mu_dir( ?string $mu_dir = null ): string {
		if ( null !== $mu_dir && '' !== $mu_dir ) {
			return $mu_dir;
		}
		if ( defined( 'WPMU_PLUGIN_DIR' ) && is_string( WPMU_PLUGIN_DIR ) && '' !== WPMU_PLUGIN_DIR ) {
			return (string) WPMU_PLUGIN_DIR;
		}
		$content = defined( 'WP_CONTENT_DIR' ) ? (string) WP_CONTENT_DIR : dirname( HANDL_AICAC_DIR, 2 );
		return rtrim( $content, '/\\' ) . '/mu-plugins';
	}

	/**
	 * @return 'fail_closed'|'watch'|''
	 */
	public static function get_mode(): string {
		$raw = get_option( self::MODE_OPTION, self::MODE_OFF );
		if ( self::MODE_FAIL_CLOSED === $raw || self::MODE_WATCH === $raw ) {
			return $raw;
		}
		return self::MODE_OFF;
	}

	/**
	 * @param string $mode fail_closed|watch|off|'' 
	 */
	public static function sanitize_mode( string $mode ): ?string {
		$mode = sanitize_text_field( $mode );
		if ( 'off' === $mode || self::MODE_OFF === $mode ) {
			return self::MODE_OFF;
		}
		if ( self::MODE_FAIL_CLOSED === $mode || self::MODE_WATCH === $mode ) {
			return $mode;
		}
		return null;
	}

	/**
	 * Whether the mu-plugins directory can receive the stub.
	 *
	 * @param string|null $mu_dir Override.
	 */
	public static function is_mu_dir_writable( ?string $mu_dir = null ): bool {
		$dir = self::resolve_mu_dir( $mu_dir );
		if ( is_dir( $dir ) ) {
			return is_writable( $dir );
		}
		$parent = dirname( $dir );
		return is_dir( $parent ) && is_writable( $parent );
	}

	/**
	 * Read stub version from file contents without executing it.
	 *
	 * @param string $path Absolute path.
	 */
	public static function read_stub_version( string $path ): ?string {
		if ( ! is_readable( $path ) ) {
			return null;
		}
		$raw = file_get_contents( $path );
		if ( ! is_string( $raw ) || '' === $raw ) {
			return null;
		}
		if ( preg_match( "/define\\s*\\(\\s*['\"]HANDL_AICAC_GUARD_STUB_VERSION['\"]\\s*,\\s*['\"]([^'\"]+)['\"]\\s*\\)/", $raw, $m ) ) {
			return (string) $m[1];
		}
		if ( preg_match( '/Stub version:\\s*(\\S+)/', $raw, $m ) ) {
			return (string) $m[1];
		}
		return null;
	}

	/**
	 * Status snapshot for CLI and Site Health.
	 *
	 * @param string|null $mu_dir Override.
	 * @return array{
	 *   mode:string,
	 *   enabled:bool,
	 *   stub_path:string,
	 *   stub_present:bool,
	 *   stub_version:?string,
	 *   stub_current:bool,
	 *   mu_dir:string,
	 *   mu_writable:bool,
	 *   expected_version:string,
	 *   open_tamper_gap:bool
	 * }
	 */
	public static function status( ?string $mu_dir = null ): array {
		$mode     = self::get_mode();
		$path     = self::stub_path( $mu_dir );
		$present  = is_readable( $path );
		$version  = $present ? self::read_stub_version( $path ) : null;
		$current  = $present && null !== $version && self::STUB_VERSION === $version;
		$gap_open = (int) get_option( Tamper::DEACTIVATED_AT_OPTION, 0 ) > 0;

		return array(
			'mode'             => $mode,
			'enabled'          => self::MODE_OFF !== $mode,
			'stub_path'        => $path,
			'stub_present'     => $present,
			'stub_version'     => $version,
			'stub_current'     => $current,
			'mu_dir'           => self::resolve_mu_dir( $mu_dir ),
			'mu_writable'      => self::is_mu_dir_writable( $mu_dir ),
			'expected_version' => self::STUB_VERSION,
			'open_tamper_gap'  => $gap_open,
		);
	}

	/**
	 * Enable hardened mode and write the stub. Never writes without an explicit call.
	 *
	 * @param string      $mode   fail_closed|watch
	 * @param string|null $mu_dir Override.
	 * @return array{ok:bool,error?:string,status?:array<string,mixed>}
	 */
	public static function enable( string $mode, ?string $mu_dir = null ): array {
		$normalized = self::sanitize_mode( $mode );
		if ( null === $normalized || self::MODE_OFF === $normalized ) {
			return array(
				'ok'    => false,
				'error' => 'invalid_mode',
			);
		}

		$template = self::template_path();
		if ( ! is_readable( $template ) ) {
			return array(
				'ok'    => false,
				'error' => 'missing_template',
			);
		}

		$dir = self::resolve_mu_dir( $mu_dir );
		if ( ! is_dir( $dir ) ) {
			if ( ! self::is_mu_dir_writable( $mu_dir ) ) {
				return array(
					'ok'    => false,
					'error' => 'mu_dir_unwritable',
				);
			}
			if ( ! mkdir( $dir, 0755, true ) && ! is_dir( $dir ) ) {
				return array(
					'ok'    => false,
					'error' => 'mu_dir_create_failed',
				);
			}
		}

		if ( ! is_writable( $dir ) ) {
			return array(
				'ok'    => false,
				'error' => 'mu_dir_unwritable',
			);
		}

		$contents = file_get_contents( $template );
		if ( ! is_string( $contents ) || '' === $contents ) {
			return array(
				'ok'    => false,
				'error' => 'missing_template',
			);
		}

		$path = self::stub_path( $mu_dir );
		$wrote = file_put_contents( $path, $contents );
		if ( false === $wrote ) {
			return array(
				'ok'    => false,
				'error' => 'stub_write_failed',
			);
		}

		update_option( self::MODE_OPTION, $normalized, false );

		return array(
			'ok'     => true,
			'status' => self::status( $mu_dir ),
		);
	}

	/**
	 * Disable hardened mode and delete the stub file when present.
	 *
	 * @param string|null $mu_dir Override.
	 * @return array{ok:bool,error?:string,status?:array<string,mixed>}
	 */
	public static function disable( ?string $mu_dir = null ): array {
		$path = self::stub_path( $mu_dir );
		if ( is_file( $path ) ) {
			if ( ! is_writable( $path ) && ! is_writable( dirname( $path ) ) ) {
				return array(
					'ok'    => false,
					'error' => 'stub_unwritable',
				);
			}
			if ( ! unlink( $path ) && is_file( $path ) ) {
				return array(
					'ok'    => false,
					'error' => 'stub_delete_failed',
				);
			}
		}

		delete_option( self::MODE_OPTION );
		delete_option( self::ALERT_FOR_OPTION );

		return array(
			'ok'     => true,
			'status' => self::status( $mu_dir ),
		);
	}

	/**
	 * Remove the stub on plugin uninstall (always — orphaned fail-closed is unsafe).
	 *
	 * @param string|null $mu_dir Override.
	 */
	public static function remove_stub_file( ?string $mu_dir = null ): void {
		$path = self::stub_path( $mu_dir );
		if ( is_file( $path ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- uninstall path.
			@unlink( $path );
		}
	}

	/**
	 * Human label for a mode value.
	 */
	public static function mode_label( string $mode ): string {
		if ( self::MODE_FAIL_CLOSED === $mode ) {
			return 'fail closed (block AI Client while inactive)';
		}
		if ( self::MODE_WATCH === $mode ) {
			return 'watch (allow + fallback log + one alert)';
		}
		return 'off';
	}
}
