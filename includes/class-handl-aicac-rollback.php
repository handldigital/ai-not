<?php
/**
 * AICAC-ROLLBACK (#377): backup-restore detection for governance state.
 *
 * Monotonic watermark in its OWN option, mirrored to a small file under
 * uploads (and the mu-stub dir when hardened mode is on — read-only Mu_Guard
 * status). Compare on init: DB older than file → rollback detected (admin
 * notice + own Plugin::LOG_OPTION_KEY append + one alert per incident
 * fingerprint). Gap report of counters that went backwards. Quiet reseed when
 * the file is missing/older. WP-CLI. Informational only in v1 — read-only
 * against the gate. OFF by default. No admin.php/policy.php/cost.php/logger/
 * tamper/mu-guard edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Detect governance state rolling backwards after a DB restore.
 */
final class Rollback {

	public const SETTINGS_OPTION = 'handl_aicac_rollback';

	public const WATERMARK_OPTION = 'handl_aicac_rollback_wm';

	public const INCIDENT_OPTION = 'handl_aicac_rollback_incident';

	public const PAGE_SLUG = 'handl-aicac-rollback';

	public const CHANNEL = 'rollback';

	public const DECISION = 'detected';

	public const FILE_BASENAME = 'rollback-watermark.json';

	public const DIR_NAME = 'handl-aicac';

	/** Minimum seconds between watermark writes. */
	public const WRITE_INTERVAL = 60;

	public const POST_PRESENT = 'handl_aicac_rollback_present';

	public const POST_ENABLED = 'handl_aicac_rollback_enabled';

	public const ACTION_SAVE = 'handl_aicac_rollback_save';

	public const ACTION_RESEED = 'handl_aicac_rollback_reseed';

	public const ACTION_DISMISS = 'handl_aicac_rollback_dismiss';

	/** @var bool */
	private static $registered = false;

	/** @var string|null Test override for uploads-based directory. */
	private static $test_dir = null;

	/** @var bool|null Test override for whether file I/O is allowed. */
	private static $test_writes = null;

	/** @var list<array{to:string,subject:string,body:string}> */
	private static $test_mails = array();

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_RESEED, array( self::class, 'handle_reseed' ) );
		add_action( 'admin_post_' . self::ACTION_DISMISS, array( self::class, 'handle_dismiss' ) );

		if ( self::is_enabled() ) {
			add_action( 'init', array( self::class, 'maybe_detect' ), 20 );
			add_action( 'shutdown', array( self::class, 'maybe_persist' ), 20 );
			if ( function_exists( 'is_admin' ) && is_admin() ) {
				add_action( 'admin_notices', array( self::class, 'maybe_render_notice' ) );
				add_action( 'network_admin_notices', array( self::class, 'maybe_render_notice' ) );
			}
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered  = false;
		self::$test_dir    = null;
		self::$test_writes = null;
		self::$test_mails  = array();
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::WATERMARK_OPTION );
		delete_option( self::INCIDENT_OPTION );
	}

	/**
	 * @internal Tests only.
	 */
	public static function set_test_dir( ?string $dir ): void {
		self::$test_dir = ( null !== $dir && '' !== $dir ) ? $dir : null;
	}

	/**
	 * @internal Tests only.
	 */
	public static function set_test_writes( ?bool $allowed ): void {
		self::$test_writes = $allowed;
	}

	/**
	 * @return list<array{to:string,subject:string,body:string}>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	/**
	 * @return array{enabled:bool}
	 */
	public static function defaults(): array {
		return array(
			'enabled' => false,
		);
	}

	/**
	 * @return array{enabled:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled' => ! empty( $raw['enabled'] ),
		);
	}

	/**
	 * @param array<string,mixed> $settings Settings.
	 */
	public static function save_settings( array $settings ): bool {
		$clean  = self::sanitize_settings( $settings );
		$before = self::get_settings();
		if ( $clean === $before ) {
			return false;
		}
		if ( $clean === self::defaults() ) {
			delete_option( self::SETTINGS_OPTION );
			self::purge_files();

			return true;
		}
		update_option( self::SETTINGS_OPTION, $clean, false );

		return true;
	}

	public static function is_enabled(): bool {
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] );
	}

	/**
	 * Live governance counters used as the watermark payload.
	 *
	 * @return array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int}
	 */
	public static function capture_snapshot( ?int $now = null ): array {
		$now = ( null !== $now && $now > 0 ) ? $now : Clock::now();
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}

		$log_ts    = 0;
		$log_count = 0;
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			++$log_count;
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts > $log_ts ) {
				$log_ts = $ts;
			}
		}

		$policy = get_option( Plugin::OPTION_KEY, array() );
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}
		$policy_version = self::policy_version_stamp( $policy );
		$grants         = self::count_grants( $policy );
		$acks           = self::count_acks();

		return array(
			'ts'             => $now,
			'log_ts'         => $log_ts,
			'log_count'      => $log_count,
			'policy_version' => $policy_version,
			'grants'         => $grants,
			'acks'           => $acks,
		);
	}

	/**
	 * @param array<string,mixed> $policy Policy option.
	 */
	public static function policy_version_stamp( array $policy ): string {
		$payload = $policy;
		unset( $payload['plugin_versions'], $payload['version_alerted'] );
		$json = function_exists( 'wp_json_encode' )
			? wp_json_encode( $payload )
			: (string) json_encode( $payload );
		if ( ! is_string( $json ) || '' === $json ) {
			$json = serialize( $payload ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize -- fallback stamp only.
		}

		return substr( hash( 'sha256', $json ), 0, 16 );
	}

	/**
	 * @param array<string,mixed> $policy Policy option.
	 */
	public static function count_grants( array $policy ): int {
		$expires = isset( $policy['plugin_expires'] ) && is_array( $policy['plugin_expires'] )
			? $policy['plugin_expires']
			: array();
		$count   = 0;
		foreach ( $expires as $ts ) {
			if ( (int) $ts > 0 ) {
				++$count;
			}
		}

		return $count;
	}

	public static function count_acks(): int {
		// AUP index (when that feature is present) — read-only option peek.
		$index = get_option( 'handl_aicac_aup_ack_index', null );
		if ( is_array( $index ) ) {
			return count( $index );
		}

		return 0;
	}

	/**
	 * @param mixed $raw Raw watermark.
	 * @return array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int}|null
	 */
	public static function sanitize_watermark( $raw ): ?array {
		if ( ! is_array( $raw ) ) {
			return null;
		}
		$ts = isset( $raw['ts'] ) ? (int) $raw['ts'] : 0;
		if ( $ts <= 0 ) {
			return null;
		}

		return array(
			'ts'             => $ts,
			'log_ts'         => isset( $raw['log_ts'] ) ? max( 0, (int) $raw['log_ts'] ) : 0,
			'log_count'      => isset( $raw['log_count'] ) ? max( 0, (int) $raw['log_count'] ) : 0,
			'policy_version' => isset( $raw['policy_version'] ) ? substr( preg_replace( '/[^a-f0-9]/i', '', (string) $raw['policy_version'] ) ?? '', 0, 64 ) : '',
			'grants'         => isset( $raw['grants'] ) ? max( 0, (int) $raw['grants'] ) : 0,
			'acks'           => isset( $raw['acks'] ) ? max( 0, (int) $raw['acks'] ) : 0,
		);
	}

	/**
	 * @return array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int}|null
	 */
	public static function get_db_watermark(): ?array {
		return self::sanitize_watermark( get_option( self::WATERMARK_OPTION, null ) );
	}

	/**
	 * @param array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int} $wm Watermark.
	 */
	public static function put_db_watermark( array $wm ): void {
		$clean = self::sanitize_watermark( $wm );
		if ( null === $clean ) {
			return;
		}
		update_option( self::WATERMARK_OPTION, $clean, false );
	}

	public static function resolve_dir(): string {
		if ( null !== self::$test_dir ) {
			return rtrim( self::$test_dir, "/\\" );
		}
		if ( isset( $GLOBALS['handl_aicac_rollback_dir'] ) && is_string( $GLOBALS['handl_aicac_rollback_dir'] ) && '' !== $GLOBALS['handl_aicac_rollback_dir'] ) {
			return rtrim( (string) $GLOBALS['handl_aicac_rollback_dir'], "/\\" );
		}
		if ( function_exists( 'wp_upload_dir' ) ) {
			$uploads = wp_upload_dir();
			if ( is_array( $uploads ) && empty( $uploads['error'] ) && ! empty( $uploads['basedir'] ) ) {
				return rtrim( (string) $uploads['basedir'], "/\\" ) . '/' . self::DIR_NAME;
			}
		}

		return rtrim( sys_get_temp_dir(), "/\\" ) . '/' . self::DIR_NAME;
	}

	public static function file_path( ?string $dir = null ): string {
		$base = ( null !== $dir && '' !== $dir ) ? rtrim( $dir, "/\\" ) : self::resolve_dir();

		return $base . '/' . self::FILE_BASENAME;
	}

	/**
	 * Optional second mirror under the mu-plugins directory when hardened mode is on.
	 */
	public static function mu_file_path(): ?string {
		if ( ! class_exists( Mu_Guard::class, false ) ) {
			return null;
		}
		$mode = Mu_Guard::get_mode();
		if ( Mu_Guard::MODE_OFF === $mode ) {
			return null;
		}
		$dir = Mu_Guard::resolve_mu_dir();
		if ( '' === $dir ) {
			return null;
		}

		return rtrim( $dir, "/\\" ) . '/' . self::FILE_BASENAME;
	}

	/**
	 * @return array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int}|null
	 */
	public static function read_file_watermark( ?string $path = null ): ?array {
		$path = ( null !== $path && '' !== $path ) ? $path : self::file_path();
		if ( ! is_string( $path ) || '' === $path || ! is_readable( $path ) ) {
			return null;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- small JSON watermark.
		$raw = file_get_contents( $path );
		if ( ! is_string( $raw ) || '' === $raw ) {
			return null;
		}
		$data = json_decode( $raw, true );

		return self::sanitize_watermark( $data );
	}

	/**
	 * @param array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int} $wm Watermark.
	 */
	public static function write_file_watermark( array $wm, ?string $path = null ): bool {
		if ( false === self::$test_writes ) {
			return false;
		}
		$clean = self::sanitize_watermark( $wm );
		if ( null === $clean ) {
			return false;
		}
		$path = ( null !== $path && '' !== $path ) ? $path : self::file_path();
		$dir  = dirname( $path );
		if ( ! is_dir( $dir ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- small private dir.
			if ( ! mkdir( $dir, 0755, true ) && ! is_dir( $dir ) ) {
				return false;
			}
		}
		$json = function_exists( 'wp_json_encode' )
			? wp_json_encode( $clean )
			: (string) json_encode( $clean );
		if ( ! is_string( $json ) || '' === $json ) {
			return false;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		$written = file_put_contents( $path, $json, LOCK_EX );
		if ( false === $written ) {
			return false;
		}

		$mu = self::mu_file_path();
		if ( null !== $mu && $mu !== $path ) {
			$mu_dir = dirname( $mu );
			if ( ! is_dir( $mu_dir ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir
				@mkdir( $mu_dir, 0755, true );
			}
			if ( is_dir( $mu_dir ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
				@file_put_contents( $mu, $json, LOCK_EX );
			}
		}

		return true;
	}

	public static function purge_files(): void {
		$paths = array( self::file_path() );
		$mu    = self::mu_file_path();
		if ( null !== $mu ) {
			$paths[] = $mu;
		}
		// Also try the mu path even when hardened is off (stale mirror).
		if ( class_exists( Mu_Guard::class, false ) ) {
			$dir = Mu_Guard::resolve_mu_dir();
			if ( '' !== $dir ) {
				$paths[] = rtrim( $dir, "/\\" ) . '/' . self::FILE_BASENAME;
			}
		}
		foreach ( array_unique( $paths ) as $path ) {
			if ( is_string( $path ) && '' !== $path && is_file( $path ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
				@unlink( $path );
			}
		}
	}

	/**
	 * Compare DB vs file watermarks.
	 *
	 * @param array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int}|null $db DB watermark.
	 * @param array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int}|null $file File watermark.
	 * @return array{status:string,db:?array,file:?array,gaps:array<string,array{file:int|string,db:int|string}>}
	 */
	public static function compare( ?array $db, ?array $file ): array {
		$db   = null !== $db ? self::sanitize_watermark( $db ) : null;
		$file = null !== $file ? self::sanitize_watermark( $file ) : null;

		if ( null === $db && null === $file ) {
			return array(
				'status' => 'seed',
				'db'     => null,
				'file'   => null,
				'gaps'   => array(),
			);
		}
		if ( null === $file ) {
			return array(
				'status' => 'reseed',
				'db'     => $db,
				'file'   => null,
				'gaps'   => array(),
			);
		}
		if ( null === $db ) {
			return array(
				'status' => 'rollback',
				'db'     => null,
				'file'   => $file,
				'gaps'   => self::gap_report(
					array(
						'ts'             => 0,
						'log_ts'         => 0,
						'log_count'      => 0,
						'policy_version' => '',
						'grants'         => 0,
						'acks'           => 0,
					),
					$file
				),
			);
		}
		if ( (int) $db['ts'] < (int) $file['ts'] ) {
			return array(
				'status' => 'rollback',
				'db'     => $db,
				'file'   => $file,
				'gaps'   => self::gap_report( $db, $file ),
			);
		}
		if ( (int) $db['ts'] > (int) $file['ts'] ) {
			return array(
				'status' => 'reseed',
				'db'     => $db,
				'file'   => $file,
				'gaps'   => array(),
			);
		}

		return array(
			'status' => 'ok',
			'db'     => $db,
			'file'   => $file,
			'gaps'   => array(),
		);
	}

	/**
	 * @param array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int} $db DB watermark.
	 * @param array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int} $file File watermark.
	 * @return array<string,array{file:int|string,db:int|string}>
	 */
	public static function gap_report( array $db, array $file ): array {
		$gaps = array();
		foreach ( array( 'log_ts', 'log_count', 'grants', 'acks' ) as $key ) {
			$file_v = (int) $file[ $key ];
			$db_v   = (int) $db[ $key ];
			if ( $db_v < $file_v ) {
				$gaps[ $key ] = array(
					'file' => $file_v,
					'db'   => $db_v,
				);
			}
		}
		if ( (string) $db['policy_version'] !== (string) $file['policy_version'] ) {
			$gaps['policy_version'] = array(
				'file' => (string) $file['policy_version'],
				'db'   => (string) $db['policy_version'],
			);
		}
		$gaps['ts'] = array(
			'file' => (int) $file['ts'],
			'db'   => (int) $db['ts'],
		);

		return $gaps;
	}

	/**
	 * @param array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int}|null $db DB watermark.
	 * @param array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int}|null $file File watermark.
	 */
	public static function incident_fingerprint( ?array $db, ?array $file ): string {
		$db_ts   = ( null !== $db ) ? (int) $db['ts'] : 0;
		$file_ts = ( null !== $file ) ? (int) $file['ts'] : 0;
		$db_lc   = ( null !== $db ) ? (int) $db['log_count'] : 0;
		$file_lc = ( null !== $file ) ? (int) $file['log_count'] : 0;

		return hash( 'sha256', $db_ts . ':' . $file_ts . ':' . $db_lc . ':' . $file_lc );
	}

	/**
	 * @return array<string,mixed>|null
	 */
	public static function get_incident(): ?array {
		$raw = get_option( self::INCIDENT_OPTION, null );
		if ( ! is_array( $raw ) || empty( $raw['fingerprint'] ) ) {
			return null;
		}

		return $raw;
	}

	/**
	 * Run detection. Safe to call repeatedly.
	 *
	 * @return array{status:string,db:?array,file:?array,gaps:array<string,array{file:int|string,db:int|string}>,fired:bool}
	 */
	public static function maybe_detect( ?int $now = null ): array {
		$now = ( null !== $now && $now > 0 ) ? $now : Clock::now();
		if ( ! self::is_enabled() ) {
			return array(
				'status' => 'off',
				'db'     => null,
				'file'   => null,
				'gaps'   => array(),
				'fired'  => false,
			);
		}

		$db   = self::get_db_watermark();
		$file = self::read_file_watermark();
		$cmp  = self::compare( $db, $file );

		if ( 'seed' === $cmp['status'] ) {
			$snap = self::capture_snapshot( $now );
			self::put_db_watermark( $snap );
			self::write_file_watermark( $snap );

			return array(
				'status' => 'seed',
				'db'     => $snap,
				'file'   => $snap,
				'gaps'   => array(),
				'fired'  => false,
			);
		}

		if ( 'reseed' === $cmp['status'] ) {
			$source = null !== $cmp['db'] ? $cmp['db'] : self::capture_snapshot( $now );
			self::put_db_watermark( $source );
			self::write_file_watermark( $source );

			return array(
				'status' => 'reseed',
				'db'     => $source,
				'file'   => $source,
				'gaps'   => array(),
				'fired'  => false,
			);
		}

		if ( 'rollback' === $cmp['status'] ) {
			$fired = self::fire_incident( $cmp['db'], $cmp['file'], $cmp['gaps'], $now );

			return array(
				'status' => 'rollback',
				'db'     => $cmp['db'],
				'file'   => $cmp['file'],
				'gaps'   => $cmp['gaps'],
				'fired'  => $fired,
			);
		}

		return array(
			'status' => 'ok',
			'db'     => $cmp['db'],
			'file'   => $cmp['file'],
			'gaps'   => array(),
			'fired'  => false,
		);
	}

	/**
	 * @param array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int}|null $db DB watermark.
	 * @param array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int}|null $file File watermark.
	 * @param array<string,array{file:int|string,db:int|string}>                                     $gaps Gap report.
	 */
	public static function fire_incident( ?array $db, ?array $file, array $gaps, ?int $now = null ): bool {
		$now         = ( null !== $now && $now > 0 ) ? $now : Clock::now();
		$fingerprint = self::incident_fingerprint( $db, $file );
		$existing    = self::get_incident();
		if ( is_array( $existing ) && isset( $existing['fingerprint'] ) && (string) $existing['fingerprint'] === $fingerprint ) {
			return false;
		}

		$incident = array(
			'fingerprint' => $fingerprint,
			'detected_at' => $now,
			'db'          => $db,
			'file'        => $file,
			'gaps'        => $gaps,
			'notice'      => true,
		);
		update_option( self::INCIDENT_OPTION, $incident, false );

		self::append_detected_log( $db, $file, $gaps, $now );
		self::maybe_notify( $db, $file, $gaps, $now );

		return true;
	}

	/**
	 * @param array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int}|null $db DB watermark.
	 * @param array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int}|null $file File watermark.
	 * @param array<string,array{file:int|string,db:int|string}>                                     $gaps Gap report.
	 */
	public static function append_detected_log( ?array $db, ?array $file, array $gaps, ?int $now = null ): void {
		$now   = ( null !== $now && $now > 0 ) ? $now : Clock::now();
		$event = array(
			'ts'       => $now,
			'decision' => self::DECISION,
			'channel'  => self::CHANNEL,
			'reason'   => 'rollback=detected',
			'db_ts'    => ( null !== $db ) ? (int) $db['ts'] : 0,
			'file_ts'  => ( null !== $file ) ? (int) $file['ts'] : 0,
			'gaps'     => array_keys( $gaps ),
		);

		// Always-on governance append (does not depend on Activity logging).
		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) ) {
			$log = array();
		}
		$log[] = $event;
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'apply_log_retention' ) ) {
			$policy = get_option( Plugin::OPTION_KEY, array() );
			if ( ! is_array( $policy ) ) {
				$policy = array();
			}
			$log = Policy::apply_log_retention( $log, $policy, $now );
		} else {
			$count = count( $log );
			if ( $count > 200 ) {
				$log = array_values( array_slice( $log, $count - 200 ) );
			}
		}
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
	}

	/**
	 * @param array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int}|null $db DB watermark.
	 * @param array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int}|null $file File watermark.
	 * @param array<string,array{file:int|string,db:int|string}>                                     $gaps Gap report.
	 */
	public static function maybe_notify( ?array $db, ?array $file, array $gaps, ?int $now = null ): bool {
		unset( $now );
		$policy = get_option( Plugin::OPTION_KEY, array() );
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}

		$email = '';
		if ( class_exists( Alert_Routing::class, false ) && method_exists( Alert_Routing::class, 'resolve_email' ) ) {
			$email = (string) Alert_Routing::resolve_email( $policy, 'rollback' );
		} elseif ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		}
		if ( '' === $email ) {
			$admin = function_exists( 'sanitize_email' ) ? sanitize_email( (string) get_option( 'admin_email' ) ) : (string) get_option( 'admin_email' );
			$email = ( function_exists( 'is_email' ) && is_email( $admin ) ) ? $admin : $admin;
		}
		if ( '' === $email ) {
			return false;
		}

		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$db_ts   = ( null !== $db ) ? (int) $db['ts'] : 0;
		$file_ts = ( null !== $file ) ? (int) $file['ts'] : 0;
		$subject = sprintf(
			/* translators: %s: site name */
			__( '[%s] AI governance rollback detected', 'handl-ai-connector-access-control' ),
			$site
		);
		$gap_keys = array_keys( $gaps );
		$body     = sprintf(
			/* translators: 1: file watermark unix time, 2: DB watermark unix time, 3: comma-separated gap keys */
			__( "HandL AI Connector Access Control detected a governance rollback.\n\nFile watermark time: %1\$d\nDatabase watermark time: %2\$d\nCounters that moved backwards: %3\$s\n\nA database restore may have undone policy, grants, acknowledgements, or audit history. Open the Rollback screen to review the gap report, then reseed after you have investigated.", 'handl-ai-connector-access-control' ),
			$file_ts,
			$db_ts,
			array() === $gap_keys ? '(none listed)' : implode( ', ', $gap_keys )
		);

		self::$test_mails[] = array(
			'to'      => $email,
			'subject' => $subject,
			'body'    => $body,
		);

		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'safe_wp_mail' ) ) {
			return (bool) Alerts::safe_wp_mail( $email, $subject, $body );
		}
		if ( isset( $GLOBALS['handl_aicac_wp_mail'] ) && is_callable( $GLOBALS['handl_aicac_wp_mail'] ) ) {
			return (bool) call_user_func( $GLOBALS['handl_aicac_wp_mail'], $email, $subject, $body );
		}
		if ( function_exists( 'wp_mail' ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.wp_mail
			return (bool) wp_mail( $email, $subject, $body );
		}

		return false;
	}

	/**
	 * Persist a fresh watermark on shutdown when no active incident blocks it.
	 */
	public static function maybe_persist( ?int $now = null ): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		if ( null !== self::get_incident() ) {
			return;
		}
		$now = ( null !== $now && $now > 0 ) ? $now : Clock::now();
		$db  = self::get_db_watermark();
		if ( null !== $db && ( $now - (int) $db['ts'] ) < self::WRITE_INTERVAL ) {
			return;
		}
		$snap = self::capture_snapshot( $now );
		self::put_db_watermark( $snap );
		self::write_file_watermark( $snap );
	}

	/**
	 * Quiet reseed: align DB + file to a fresh live snapshot and clear the incident.
	 *
	 * @return array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int}
	 */
	public static function reseed( ?int $now = null ): array {
		$now  = ( null !== $now && $now > 0 ) ? $now : Clock::now();
		$snap = self::capture_snapshot( $now );
		self::put_db_watermark( $snap );
		self::write_file_watermark( $snap );
		delete_option( self::INCIDENT_OPTION );

		return $snap;
	}

	/**
	 * Whether a rollback incident is currently open (for CLI exit codes).
	 */
	public static function is_rollback_active(): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$incident = self::get_incident();
		if ( is_array( $incident ) ) {
			return true;
		}
		$db   = self::get_db_watermark();
		$file = self::read_file_watermark();
		$cmp  = self::compare( $db, $file );

		return 'rollback' === $cmp['status'];
	}

	/**
	 * Status payload for CLI / screen.
	 *
	 * @return array<string,mixed>
	 */
	public static function status(): array {
		$db   = self::get_db_watermark();
		$file = self::read_file_watermark();
		$cmp  = self::compare( $db, $file );

		return array(
			'enabled'   => self::is_enabled(),
			'status'    => self::is_enabled() ? $cmp['status'] : 'off',
			'db'        => $db,
			'file'      => $file,
			'gaps'      => $cmp['gaps'],
			'incident'  => self::get_incident(),
			'file_path' => self::file_path(),
			'mu_path'   => self::mu_file_path(),
		);
	}

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Rollback detection', 'handl-ai-connector-access-control' ),
			__( 'Rollback', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$settings   = self::get_settings();
		$can_manage = Caps::user_can_manage();
		$status     = self::status();
		$incident   = is_array( $status['incident'] ?? null ) ? $status['incident'] : null;

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Rollback detection', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p>' . esc_html__( 'Watch for governance state that moves backwards after a database restore. Informational only — this does not block AI calls.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tr><th scope="row">' . esc_html__( 'Enable rollback detection', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Compare the database watermark to a file mirror and alert when the database is older.', 'handl-ai-connector-access-control' );
			echo '</label></td></tr></table>';
			submit_button( __( 'Save settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! empty( $settings['enabled'] ) ) {
			echo '<h2>' . esc_html__( 'Current status', 'handl-ai-connector-access-control' ) . '</h2>';
			echo '<p><code>' . esc_html( (string) $status['status'] ) . '</code></p>';
			self::render_watermark_table(
				__( 'Database watermark', 'handl-ai-connector-access-control' ),
				is_array( $status['db'] ?? null ) ? $status['db'] : null
			);
			self::render_watermark_table(
				__( 'File watermark', 'handl-ai-connector-access-control' ),
				is_array( $status['file'] ?? null ) ? $status['file'] : null
			);
			echo '<p>' . esc_html__( 'File path:', 'handl-ai-connector-access-control' ) . ' <code>' . esc_html( (string) ( $status['file_path'] ?? '' ) ) . '</code></p>';

			$gaps = is_array( $status['gaps'] ?? null ) ? $status['gaps'] : array();
			if ( null !== $incident && is_array( $incident['gaps'] ?? null ) ) {
				$gaps = $incident['gaps'];
			}
			if ( array() !== $gaps ) {
				echo '<h2>' . esc_html__( 'Gap report', 'handl-ai-connector-access-control' ) . '</h2>';
				echo '<p>' . esc_html__( 'These counters are lower in the database than in the file mirror — they may have been undone by a restore.', 'handl-ai-connector-access-control' ) . '</p>';
				echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Counter', 'handl-ai-connector-access-control' ) . '</th><th>' . esc_html__( 'File', 'handl-ai-connector-access-control' ) . '</th><th>' . esc_html__( 'Database', 'handl-ai-connector-access-control' ) . '</th></tr></thead><tbody>';
				foreach ( $gaps as $key => $pair ) {
					if ( ! is_array( $pair ) ) {
						continue;
					}
					echo '<tr><td>' . esc_html( (string) $key ) . '</td><td>' . esc_html( (string) ( $pair['file'] ?? '' ) ) . '</td><td>' . esc_html( (string) ( $pair['db'] ?? '' ) ) . '</td></tr>';
				}
				echo '</tbody></table>';
			}

			if ( $can_manage ) {
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="margin-top:1em;">';
				echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_RESEED ) . '" />';
				if ( function_exists( 'wp_nonce_field' ) ) {
					wp_nonce_field( self::ACTION_RESEED );
				}
				submit_button( __( 'Reseed watermark', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
				echo '</form>';
			}
		}

		echo '</div>';
	}

	/**
	 * @param array{ts:int,log_ts:int,log_count:int,policy_version:string,grants:int,acks:int}|null $wm Watermark.
	 */
	private static function render_watermark_table( string $heading, ?array $wm ): void {
		echo '<h3>' . esc_html( $heading ) . '</h3>';
		if ( null === $wm ) {
			echo '<p><em>' . esc_html__( 'None', 'handl-ai-connector-access-control' ) . '</em></p>';

			return;
		}
		echo '<table class="widefat striped"><tbody>';
		foreach ( array( 'ts', 'log_ts', 'log_count', 'policy_version', 'grants', 'acks' ) as $key ) {
			echo '<tr><th scope="row">' . esc_html( $key ) . '</th><td>' . esc_html( (string) ( $wm[ $key ] ?? '' ) ) . '</td></tr>';
		}
		echo '</tbody></table>';
	}

	public static function maybe_render_notice(): void {
		if ( ! self::is_enabled() || ! Caps::user_can_view() ) {
			return;
		}
		$incident = self::get_incident();
		if ( ! is_array( $incident ) || empty( $incident['notice'] ) ) {
			return;
		}
		$db_ts   = isset( $incident['db']['ts'] ) ? (int) $incident['db']['ts'] : 0;
		$file_ts = isset( $incident['file']['ts'] ) ? (int) $incident['file']['ts'] : 0;
		$url     = admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		$dismiss = wp_nonce_url(
			admin_url( 'admin-post.php?action=' . self::ACTION_DISMISS ),
			self::ACTION_DISMISS
		);

		echo '<div class="notice notice-error"><p>';
		echo esc_html(
			sprintf(
				/* translators: 1: file watermark unix time, 2: DB watermark unix time */
				__( 'AI governance rollback detected: the file watermark (%1$d) is newer than the database watermark (%2$d). A restore may have undone policy or audit state.', 'handl-ai-connector-access-control' ),
				$file_ts,
				$db_ts
			)
		);
		echo ' <a href="' . esc_url( $url ) . '">' . esc_html__( 'View gap report', 'handl-ai-connector-access-control' ) . '</a>';
		if ( Caps::user_can_manage() ) {
			echo ' | <a href="' . esc_url( $dismiss ) . '">' . esc_html__( 'Dismiss notice', 'handl-ai-connector-access-control' ) . '</a>';
		}
		echo '</p></div>';
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'Forbidden', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) {
			wp_safe_redirect( admin_url( 'admin.php?page=' . self::PAGE_SLUG ) );
			exit;
		}
		$enabled = ! empty( $_POST[ self::POST_ENABLED ] );
		self::save_settings( array( 'enabled' => $enabled ) );
		if ( $enabled ) {
			self::reseed();
		}
		wp_safe_redirect( admin_url( 'admin.php?page=' . self::PAGE_SLUG . '&updated=1' ) );
		exit;
	}

	public static function handle_reseed(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'Forbidden', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_RESEED );
		if ( self::is_enabled() ) {
			self::reseed();
		}
		wp_safe_redirect( admin_url( 'admin.php?page=' . self::PAGE_SLUG . '&reseeded=1' ) );
		exit;
	}

	public static function handle_dismiss(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'Forbidden', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_DISMISS );
		$incident = self::get_incident();
		if ( is_array( $incident ) ) {
			$incident['notice'] = false;
			update_option( self::INCIDENT_OPTION, $incident, false );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=' . self::PAGE_SLUG ) );
		exit;
	}

	private static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac rollback', CLI_Rollback::class );
	}
}

/**
 * WP-CLI: wp handl-aicac rollback status|check|reseed
 */
class CLI_Rollback {

	/**
	 * Show rollback detection status.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac rollback status
	 *
	 * @when after_wp_load
	 */
	public function status( $args, $assoc_args ): void { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
		$st = Rollback::status();
		\WP_CLI::log( 'enabled: ' . ( ! empty( $st['enabled'] ) ? 'yes' : 'no' ) );
		\WP_CLI::log( 'status: ' . (string) ( $st['status'] ?? '' ) );
		\WP_CLI::log( 'file: ' . (string) ( $st['file_path'] ?? '' ) );
		if ( ! empty( $st['db'] ) && is_array( $st['db'] ) ) {
			\WP_CLI::log( 'db_ts: ' . (int) $st['db']['ts'] . ' log_count=' . (int) $st['db']['log_count'] );
		}
		if ( ! empty( $st['file'] ) && is_array( $st['file'] ) ) {
			\WP_CLI::log( 'file_ts: ' . (int) $st['file']['ts'] . ' log_count=' . (int) $st['file']['log_count'] );
		}
		if ( ! empty( $st['gaps'] ) && is_array( $st['gaps'] ) ) {
			\WP_CLI::log( 'gaps: ' . implode( ', ', array_keys( $st['gaps'] ) ) );
		}
	}

	/**
	 * Exit non-zero when a rollback is detected / incident is open.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac rollback check
	 *
	 * @when after_wp_load
	 */
	public function check( $args, $assoc_args ): void { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
		if ( Rollback::is_enabled() ) {
			Rollback::maybe_detect();
		}
		if ( Rollback::is_rollback_active() ) {
			\WP_CLI::error( 'Governance rollback detected.', true );
		}
		\WP_CLI::success( 'No rollback detected.' );
	}

	/**
	 * Reseed DB + file watermarks from live state and clear the incident.
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac rollback reseed
	 *
	 * @when after_wp_load
	 */
	public function reseed( $args, $assoc_args ): void { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter
		if ( ! Rollback::is_enabled() ) {
			\WP_CLI::warning( 'Rollback detection is off.' );
		}
		$snap = Rollback::reseed();
		\WP_CLI::success( 'Reseeded watermark at ts=' . (int) $snap['ts'] );
	}
}
