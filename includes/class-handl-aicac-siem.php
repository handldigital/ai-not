<?php
/**
 * AICAC-SIEM (#235): opt-in syslog / file export of security events.
 *
 * Subscribes at Policy::append_log_event. Off by default. No decision-path changes.
 * Payloads are share-safe (no alert emails, webhook URLs, notes, or prompt text).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * CEF / JSON-lines export for SIEM collectors.
 */
final class Siem {

	public const FILE_PATH_OPTION = 'handl_aicac_siem_file_path';

	public const FORMAT_CEF  = 'cef';
	public const FORMAT_JSON = 'json';

	/** Soft rotate when the tail file exceeds this many bytes. */
	public const FILE_MAX_BYTES = 5242880; // 5 MiB.

	/** Event classes exported when classified. */
	public const CLASS_DENY         = 'deny';
	public const CLASS_SHADOW_DENY  = 'shadow_deny';
	public const CLASS_TAMPER       = 'tamper';
	public const CLASS_HARDENED     = 'hardened';
	public const CLASS_POLICY       = 'policy';
	public const CLASS_BUDGET       = 'budget';
	public const CLASS_TEST         = 'test';

	/**
	 * Keys stripped from every exported payload (share-safe).
	 *
	 * @return list<string>
	 */
	public static function redact_keys(): array {
		return array(
			'alert_email',
			'alert_webhook_url',
			'email',
			'to',
			'recipient',
			'recipients',
			'prompt_preview',
			'prompt',
			'plugin_notes',
			'notes',
			'note',
			'uri',
			'user_id',
			'actor_email',
		);
	}

	/**
	 * @param mixed $raw
	 * @return 'cef'|'json'
	 */
	public static function sanitize_format( $raw ): string {
		$key = sanitize_key( (string) $raw );
		if ( self::FORMAT_JSON === $key ) {
			return self::FORMAT_JSON;
		}
		return self::FORMAT_CEF;
	}

	/**
	 * Normalize SIEM policy keys (defaults off).
	 *
	 * @param array<string,mixed> $policy
	 * @return array<string,mixed>
	 */
	public static function normalize_policy( array $policy ): array {
		$policy['siem_syslog_enabled'] = ! empty( $policy['siem_syslog_enabled'] );
		$policy['siem_file_enabled']   = ! empty( $policy['siem_file_enabled'] );
		$policy['siem_format']         = self::sanitize_format( $policy['siem_format'] ?? self::FORMAT_CEF );
		return $policy;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function is_enabled( array $policy ): bool {
		return ! empty( $policy['siem_syslog_enabled'] ) || ! empty( $policy['siem_file_enabled'] );
	}

	/**
	 * Classify a log event into an exportable security class, or null to skip.
	 *
	 * @param array<string,mixed> $event
	 */
	public static function classify( array $event ): ?string {
		$channel  = isset( $event['channel'] ) ? sanitize_key( (string) $event['channel'] ) : '';
		$decision = isset( $event['decision'] ) ? sanitize_key( (string) $event['decision'] ) : '';

		if ( ! empty( $event['siem_test'] ) || self::CLASS_TEST === $channel ) {
			return self::CLASS_TEST;
		}

		if ( 'tamper' === $channel ) {
			return self::CLASS_TAMPER;
		}

		if ( in_array( $channel, array( 'hardened', 'mu_guard' ), true )
			|| false !== strpos( $decision, 'hardened' ) ) {
			return self::CLASS_HARDENED;
		}

		if ( in_array( $channel, array( 'policy_restore', 'policy_save', 'policy_import' ), true ) ) {
			return self::CLASS_POLICY;
		}

		if ( 'budget' === $channel ) {
			return self::CLASS_BUDGET;
		}

		if ( 'direct_http' === $channel && 'deny' === $decision ) {
			return self::CLASS_SHADOW_DENY;
		}

		// AI Client deny (empty channel or explicit ai client rows).
		if ( 'deny' === $decision && ! in_array( $channel, array( 'direct_http', 'anomaly', 'spend_threshold', 'drift', 'alert_snooze', 'selftest', 'forecast_warn', 'went_ai', 'temp_allow', 'email', 'policy_checks' ), true ) ) {
			return self::CLASS_DENY;
		}

		return null;
	}

	/**
	 * Severity 0–10 for CEF.
	 */
	public static function severity_for_class( string $class ): int {
		switch ( $class ) {
			case self::CLASS_TAMPER:
				return 8;
			case self::CLASS_DENY:
			case self::CLASS_SHADOW_DENY:
				return 7;
			case self::CLASS_HARDENED:
				return 6;
			case self::CLASS_BUDGET:
				return 5;
			case self::CLASS_POLICY:
				return 3;
			case self::CLASS_TEST:
				return 1;
			default:
				return 4;
		}
	}

	/**
	 * Share-safe fields for export.
	 *
	 * @param array<string,mixed> $event
	 * @return array<string,scalar|null>
	 */
	public static function redact_payload( array $event ): array {
		$drop = array_flip( self::redact_keys() );
		$out  = array();

		$keep = array(
			'ts',
			'plugin',
			'decision',
			'channel',
			'family',
			'operation',
			'provider',
			'model',
			'model_id',
			'denial_reason',
			'count',
			'host',
			'shadow_provider',
			'actor',
			'stopped_by',
			'deactivated_at',
			'would_decision',
			'siem_class',
			'siem_test',
		);

		foreach ( $keep as $key ) {
			if ( ! array_key_exists( $key, $event ) || isset( $drop[ $key ] ) ) {
				continue;
			}
			$val = $event[ $key ];
			if ( is_bool( $val ) ) {
				$out[ $key ] = $val ? 1 : 0;
				continue;
			}
			if ( is_int( $val ) || is_float( $val ) ) {
				$out[ $key ] = $val;
				continue;
			}
			if ( null === $val ) {
				continue;
			}
			if ( ! is_scalar( $val ) ) {
				continue;
			}
			$str = sanitize_text_field( (string) $val );
			if ( self::looks_like_secret( $str ) ) {
				continue;
			}
			$out[ $key ] = $str;
		}

		return $out;
	}

	/**
	 * Reject emails / URLs that slipped into actor-like fields.
	 */
	public static function looks_like_secret( string $value ): bool {
		if ( false !== strpos( $value, '@' ) && false !== strpos( $value, '.' ) ) {
			return true;
		}
		if ( preg_match( '#^https?://#i', $value ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Plugin version for CEF header.
	 */
	public static function plugin_version(): string {
		$v = defined( 'HANDL_AICAC_VERSION' ) ? (string) HANDL_AICAC_VERSION : '0';
		$v = preg_replace( '/[^0-9A-Za-z.\-]/', '', $v ) ?? '';
		return '' !== $v ? $v : '0';
	}

	/**
	 * Build one CEF line.
	 *
	 * @param array<string,scalar|null> $payload
	 */
	public static function format_cef( string $class, array $payload ): string {
		$severity = self::severity_for_class( $class );
		$name     = str_replace( '_', ' ', $class );
		$version  = self::plugin_version();
		$sig      = 'AICAC:' . $class;

		$ext = array();
		$ts  = isset( $payload['ts'] ) ? (int) $payload['ts'] : time();
		if ( $ts > 0 ) {
			$ext[] = 'rt=' . ( $ts * 1000 );
		}
		if ( isset( $payload['plugin'] ) && '' !== (string) $payload['plugin'] ) {
			$ext[] = 'cs1Label=plugin';
			$ext[] = 'cs1=' . self::cef_escape( (string) $payload['plugin'] );
		}
		$family = '';
		if ( isset( $payload['family'] ) && '' !== (string) $payload['family'] ) {
			$family = (string) $payload['family'];
		} elseif ( isset( $payload['operation'] ) && '' !== (string) $payload['operation'] ) {
			$family = (string) $payload['operation'];
		}
		if ( '' !== $family ) {
			$ext[] = 'cs2Label=operation';
			$ext[] = 'cs2=' . self::cef_escape( $family );
		}
		$decision = isset( $payload['decision'] ) ? (string) $payload['decision'] : $class;
		$ext[]    = 'cs3Label=decision';
		$ext[]    = 'cs3=' . self::cef_escape( $decision );
		$ext[]    = 'act=' . self::cef_escape( $class );
		if ( isset( $payload['denial_reason'] ) && '' !== (string) $payload['denial_reason'] ) {
			$ext[] = 'reason=' . self::cef_escape( (string) $payload['denial_reason'] );
		}
		if ( isset( $payload['host'] ) && '' !== (string) $payload['host'] ) {
			$ext[] = 'dhost=' . self::cef_escape( (string) $payload['host'] );
		}

		return sprintf(
			'CEF:0|HandL|AICAC|%s|%s|%s|%d|%s',
			self::cef_escape( $version ),
			self::cef_escape( $sig ),
			self::cef_escape( $name ),
			$severity,
			implode( ' ', $ext )
		);
	}

	/**
	 * Escape CEF extension values (backslash, equals, pipe, newline).
	 */
	public static function cef_escape( string $value ): string {
		$value = str_replace( '\\', '\\\\', $value );
		$value = str_replace( "\n", '\\n', $value );
		$value = str_replace( "\r", '\\r', $value );
		$value = str_replace( '=', '\\=', $value );
		$value = str_replace( '|', '\\|', $value );
		return $value;
	}

	/**
	 * @param array<string,scalar|null> $payload
	 */
	public static function format_json( string $class, array $payload ): string {
		$row = array_merge(
			array(
				'vendor'  => 'HandL',
				'product' => 'AICAC',
				'version' => self::plugin_version(),
				'class'   => $class,
			),
			$payload
		);
		if ( function_exists( 'wp_json_encode' ) ) {
			$json = wp_json_encode( $row );
		} else {
			$json = json_encode( $row );
		}
		return is_string( $json ) ? $json : '{}';
	}

	/**
	 * Format + emit one classified event. Returns false when skipped or both sinks fail.
	 *
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 */
	public static function observe( array $event, array $policy ): bool {
		$policy = self::normalize_policy( $policy );
		if ( ! self::is_enabled( $policy ) ) {
			return false;
		}

		$class = self::classify( $event );
		if ( null === $class ) {
			return false;
		}

		$payload               = self::redact_payload( $event );
		$payload['siem_class'] = $class;
		if ( ! isset( $payload['ts'] ) || (int) $payload['ts'] <= 0 ) {
			$payload['ts'] = time();
		}

		$format = $policy['siem_format'];
		$line   = ( self::FORMAT_JSON === $format )
			? self::format_json( $class, $payload )
			: self::format_cef( $class, $payload );

		return self::emit_line( $line, $policy );
	}

	/**
	 * Write one line to enabled sinks.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function emit_line( string $line, array $policy ): bool {
		$policy  = self::normalize_policy( $policy );
		$ok      = false;
		$line    = rtrim( $line, "\r\n" );
		if ( '' === $line ) {
			return false;
		}

		if ( ! empty( $policy['siem_syslog_enabled'] ) ) {
			if ( self::write_syslog( $line ) ) {
				$ok = true;
			}
		}
		if ( ! empty( $policy['siem_file_enabled'] ) ) {
			if ( self::write_file( $line ) ) {
				$ok = true;
			}
		}

		return $ok;
	}

	/**
	 * @return bool
	 */
	public static function write_syslog( string $line ): bool {
		if ( isset( $GLOBALS['handl_aicac_syslog'] ) && is_callable( $GLOBALS['handl_aicac_syslog'] ) ) {
			call_user_func( $GLOBALS['handl_aicac_syslog'], $line );
			return true;
		}
		if ( ! function_exists( 'syslog' ) ) {
			return false;
		}
		$priority = defined( 'LOG_WARNING' ) ? LOG_WARNING : 4;
		if ( function_exists( 'openlog' ) ) {
			$facility = defined( 'LOG_USER' ) ? LOG_USER : 8;
			$opts     = 0;
			if ( defined( 'LOG_ODELAY' ) ) {
				$opts |= LOG_ODELAY;
			}
			if ( defined( 'LOG_PID' ) ) {
				$opts |= LOG_PID;
			}
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- host syslog may be unavailable.
			@openlog( 'handl-aicac', $opts, $facility );
		}
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$result = @syslog( $priority, $line );
		return (bool) $result;
	}

	/**
	 * Append one line to the rotating uploads file.
	 */
	public static function write_file( string $line ): bool {
		$path = self::ensure_file_path();
		if ( '' === $path ) {
			return false;
		}

		if ( is_file( $path ) && filesize( $path ) >= self::FILE_MAX_BYTES ) {
			$rotated = $path . '.1';
			if ( is_file( $rotated ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
				@unlink( $rotated );
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename
			@rename( $path, $rotated );
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		$bytes = @file_put_contents( $path, $line . "\n", FILE_APPEND | LOCK_EX );
		return false !== $bytes;
	}

	/**
	 * Stable path under uploads with a random suffix (created once).
	 */
	public static function ensure_file_path(): string {
		$stored = get_option( self::FILE_PATH_OPTION, '' );
		if ( is_string( $stored ) && '' !== $stored && self::path_is_allowed( $stored ) ) {
			return $stored;
		}

		$dir = self::resolve_dir();
		if ( '' === $dir ) {
			return '';
		}
		if ( ! is_dir( $dir ) ) {
			if ( function_exists( 'wp_mkdir_p' ) ) {
				wp_mkdir_p( $dir );
			} else {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir
				@mkdir( $dir, 0755, true );
			}
		}
		if ( ! is_dir( $dir ) || ! is_writable( $dir ) ) {
			return '';
		}

		$token = function_exists( 'wp_generate_password' )
			? wp_generate_password( 12, false, false )
			: bin2hex( random_bytes( 6 ) );
		$token = preg_replace( '/[^a-zA-Z0-9]/', '', (string) $token ) ?? '';
		if ( strlen( $token ) < 8 ) {
			$token = bin2hex( random_bytes( 6 ) );
		}

		$path = self::slashit( $dir ) . 'handl-aicac-siem-' . $token . '.log';
		update_option( self::FILE_PATH_OPTION, $path, false );
		return $path;
	}

	/**
	 * @return string Absolute directory for SIEM files.
	 */
	public static function resolve_dir(): string {
		if ( isset( $GLOBALS['handl_aicac_siem_dir'] ) && is_string( $GLOBALS['handl_aicac_siem_dir'] ) && '' !== $GLOBALS['handl_aicac_siem_dir'] ) {
			return (string) $GLOBALS['handl_aicac_siem_dir'];
		}
		if ( function_exists( 'wp_upload_dir' ) ) {
			$uploads = wp_upload_dir();
			if ( is_array( $uploads ) && empty( $uploads['error'] ) && ! empty( $uploads['basedir'] ) ) {
				return self::slashit( (string) $uploads['basedir'] ) . 'handl-aicac-siem';
			}
		}
		return self::slashit( sys_get_temp_dir() ) . 'handl-aicac-siem';
	}

	/**
	 * Reject path traversal outside uploads / temp SIEM dirs.
	 */
	public static function path_is_allowed( string $path ): bool {
		$path = self::normalize_path( $path );
		if ( '' === $path || false !== strpos( $path, "\0" ) ) {
			return false;
		}
		$base = self::normalize_path( self::resolve_dir() );
		return 0 === strpos( $path, self::slashit( $base ) );
	}

	private static function slashit( string $path ): string {
		return rtrim( $path, "/\\" ) . '/';
	}

	private static function normalize_path( string $path ): string {
		$path = str_replace( '\\', '/', $path );
		$path = preg_replace( '#/+#', '/', $path ) ?? $path;
		return $path;
	}

	/**
	 * Status snapshot for CLI / diagnostics.
	 *
	 * @param array<string,mixed>|null $policy
	 * @return array{
	 *   syslog_enabled:bool,
	 *   file_enabled:bool,
	 *   format:string,
	 *   enabled:bool,
	 *   file_path:string
	 * }
	 */
	public static function status( ?array $policy = null ): array {
		$policy = self::normalize_policy( null !== $policy ? $policy : Policy::get_policy() );
		$path   = get_option( self::FILE_PATH_OPTION, '' );
		$path   = is_string( $path ) ? $path : '';

		return array(
			'syslog_enabled' => ! empty( $policy['siem_syslog_enabled'] ),
			'file_enabled'   => ! empty( $policy['siem_file_enabled'] ),
			'format'         => $policy['siem_format'],
			'enabled'        => self::is_enabled( $policy ),
			'file_path'      => $path,
		);
	}

	/**
	 * Persist enable/disable / format. Returns updated status.
	 *
	 * Mutates only SIEM keys on the raw stored option (does not pin get_policy defaults).
	 *
	 * @param array{syslog?:bool|null,file?:bool|null,format?:string|null} $changes
	 * @return array<string,mixed>
	 */
	public static function apply_settings( array $changes ): array {
		$raw = get_option( Plugin::OPTION_KEY );
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}

		if ( array_key_exists( 'syslog', $changes ) && null !== $changes['syslog'] ) {
			$raw['siem_syslog_enabled'] = (bool) $changes['syslog'];
		}
		if ( array_key_exists( 'file', $changes ) && null !== $changes['file'] ) {
			$raw['siem_file_enabled'] = (bool) $changes['file'];
		}
		if ( array_key_exists( 'format', $changes ) && null !== $changes['format'] && '' !== (string) $changes['format'] ) {
			$raw['siem_format'] = self::sanitize_format( $changes['format'] );
		}

		Policy::save_policy( $raw );

		$normalized = self::normalize_policy( Policy::get_policy() );
		if ( ! empty( $normalized['siem_file_enabled'] ) ) {
			self::ensure_file_path();
		}

		return self::status( $normalized );
	}

	/**
	 * Emit one synthetic test event through the live sinks.
	 *
	 * @param array<string,mixed>|null $policy
	 * @return array{ok:bool,line:string,class:string,status:array<string,mixed>}
	 */
	public static function emit_test( ?array $policy = null ): array {
		$policy = self::normalize_policy( null !== $policy ? $policy : Policy::get_policy() );
		$event  = array(
			'ts'         => time(),
			'channel'    => self::CLASS_TEST,
			'decision'   => 'test',
			'plugin'     => 'handl-aicac/siem-test',
			'family'     => 'text',
			'siem_test'  => true,
			'alert_email'=> 'should-not-leak@example.test',
		);

		$class   = self::CLASS_TEST;
		$payload = self::redact_payload( $event );
		$payload['siem_class'] = $class;
		$line    = ( self::FORMAT_JSON === $policy['siem_format'] )
			? self::format_json( $class, $payload )
			: self::format_cef( $class, $payload );

		$ok = false;
		if ( self::is_enabled( $policy ) ) {
			$ok = self::emit_line( $line, $policy );
		}

		return array(
			'ok'     => $ok,
			'line'   => $line,
			'class'  => $class,
			'status' => self::status( $policy ),
		);
	}
}
