<?php
/**
 * AICAC-SCHED-EXPORT (#179): weekly policy JSON backup email (off by default).
 *
 * Distinct from Log_Retention prune cron. Uses Policy_Transfer export bytes and
 * Alerts::safe_wp_mail (shared Email_Template). Stores only the latest backup
 * JSON in an option for download / compare baseline.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Policy_Backup {

	public const CRON_HOOK = 'handl_aicac_send_policy_backup';

	/** Latest backup payload (JSON string + metadata). */
	public const LATEST_OPTION = 'handl_aicac_policy_backup_latest';

	/** Last successfully emailed ISO week id (o-WW). */
	public const SENT_OPTION = 'handl_aicac_policy_backup_sent';

	private static ?Policy_Backup $instance = null;

	public static function instance(): Policy_Backup {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function init(): void {
		add_action( self::CRON_HOOK, array( $this, 'cron_send' ) );
		add_action( 'init', array( $this, 'maybe_self_heal_schedule' ), 25 );
	}

	public function maybe_self_heal_schedule(): void {
		self::maybe_schedule( Policy::get_policy() );
	}

	public function cron_send(): void {
		self::send_if_due( Policy::get_policy(), time() );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function is_enabled( array $policy ): bool {
		return ! empty( $policy['policy_backup_email_enabled'] );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function maybe_schedule( array $policy ): void {
		$want = self::is_enabled( $policy );

		if ( $want ) {
			if ( function_exists( 'wp_next_scheduled' ) && function_exists( 'wp_schedule_event' ) ) {
				if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
					$delay = defined( 'WEEK_IN_SECONDS' ) ? (int) WEEK_IN_SECONDS : 604800;
					wp_schedule_event( time() + $delay, 'weekly', self::CRON_HOOK );
				}
			}
			return;
		}

		if ( function_exists( 'wp_next_scheduled' ) && function_exists( 'wp_unschedule_event' ) ) {
			$ts = wp_next_scheduled( self::CRON_HOOK );
			if ( $ts ) {
				wp_unschedule_event( $ts, self::CRON_HOOK );
			}
		}
	}

	/**
	 * Build export JSON identical to Rules → Download rules for the same inputs.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function build_export_json( array $policy, string $plugin_version, string $exported_at ): string {
		$export = Policy_Transfer::build_export( $policy, $plugin_version, $exported_at );
		return Policy_Transfer::encode_export( $export );
	}

	/**
	 * @return array{ts:int,json:string,filename:string,exported_at:string}|null
	 */
	public static function get_latest(): ?array {
		$raw = get_option( self::LATEST_OPTION );
		if ( ! is_array( $raw ) ) {
			return null;
		}
		$json = isset( $raw['json'] ) ? (string) $raw['json'] : '';
		$ts   = isset( $raw['ts'] ) ? (int) $raw['ts'] : 0;
		if ( '' === $json || $ts <= 0 ) {
			return null;
		}
		$filename = isset( $raw['filename'] ) ? (string) $raw['filename'] : ( 'handl-aicac-rules-' . gmdate( 'Ymd-His', $ts ) . '.json' );
		$exported_at = isset( $raw['exported_at'] ) ? (string) $raw['exported_at'] : gmdate( 'c', $ts );

		return array(
			'ts'          => $ts,
			'json'        => $json,
			'filename'    => $filename,
			'exported_at' => $exported_at,
		);
	}

	/**
	 * Persist only the most recent backup (replaces prior).
	 */
	public static function store_latest( string $json, int $ts, string $exported_at, string $filename ): void {
		update_option(
			self::LATEST_OPTION,
			array(
				'ts'          => $ts,
				'json'        => $json,
				'filename'    => $filename,
				'exported_at' => $exported_at,
			),
			false
		);
	}

	/**
	 * Generate, store, and email the weekly backup (at most once per ISO week).
	 *
	 * @param array<string,mixed> $policy
	 * @return array{ok:bool,status:string,json?:string,subject?:string}
	 */
	public static function send_if_due( array $policy, ?int $now = null ): array {
		$now = null !== $now ? $now : time();
		if ( ! self::is_enabled( $policy ) ) {
			return array(
				'ok'     => true,
				'status' => 'disabled',
			);
		}

		$week_id = self::iso_week_id( $now );
		$sent    = get_option( self::SENT_OPTION );
		if ( is_string( $sent ) && $sent === $week_id ) {
			return array(
				'ok'     => true,
				'status' => 'already_sent',
			);
		}

		$version = defined( 'HANDL_AICAC_VERSION' ) ? (string) HANDL_AICAC_VERSION : '';
		$exported_at = gmdate( 'c', $now );
		$json = self::build_export_json( $policy, $version, $exported_at );
		$filename = 'handl-aicac-rules-' . gmdate( 'Ymd-His', $now ) . '.json';

		self::store_latest( $json, $now, $exported_at, $filename );

		$to = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return array(
				'ok'     => false,
				'status' => 'no_email',
				'json'   => $json,
			);
		}

		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES )
			: '';
		if ( '' === $site ) {
			$site = __( 'WordPress', 'handl-ai-connector-access-control' );
		}

		$subject = sprintf(
			/* translators: %s: site name */
			__( '[%s] HandL AI rules backup', 'handl-ai-connector-access-control' ),
			$site
		);
		$body = __( 'Attached is this week’s HandL AI Connector Access Control rules backup (JSON). Keep the file somewhere safe. You can compare or import it later from the Rules tab.', 'handl-ai-connector-access-control' );

		$attachment = self::write_temp_json_attachment( $json, $filename );
		$attachments = '' !== $attachment ? array( $attachment ) : array();
		$ok = Alerts::safe_wp_mail( $to, $subject, $body, $attachments );
		if ( '' !== $attachment ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- best-effort temp cleanup.
			@unlink( $attachment );
		}

		if ( $ok ) {
			update_option( self::SENT_OPTION, $week_id, false );
		}

		return array(
			'ok'      => $ok,
			'status'  => $ok ? 'sent' : 'failed',
			'json'    => $json,
			'subject' => $subject,
		);
	}

	/**
	 * Force a backup now (settings “Send test” / manual), still stores latest.
	 *
	 * @param array<string,mixed> $policy
	 * @return array{ok:bool,status:string,json?:string}
	 */
	public static function send_now( array $policy, ?int $now = null ): array {
		$now = null !== $now ? $now : time();
		// Bypass week gate by clearing sent marker for this call path only after success overwrite.
		$version = defined( 'HANDL_AICAC_VERSION' ) ? (string) HANDL_AICAC_VERSION : '';
		$exported_at = gmdate( 'c', $now );
		$json = self::build_export_json( $policy, $version, $exported_at );
		$filename = 'handl-aicac-rules-' . gmdate( 'Ymd-His', $now ) . '.json';
		self::store_latest( $json, $now, $exported_at, $filename );

		$to = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return array(
				'ok'     => false,
				'status' => 'no_email',
				'json'   => $json,
			);
		}

		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES )
			: '';
		if ( '' === $site ) {
			$site = __( 'WordPress', 'handl-ai-connector-access-control' );
		}
		$subject = sprintf(
			/* translators: %s: site name */
			__( '[%s] HandL AI rules backup', 'handl-ai-connector-access-control' ),
			$site
		);
		$body = __( 'Attached is your HandL AI Connector Access Control rules backup (JSON).', 'handl-ai-connector-access-control' );
		$attachment = self::write_temp_json_attachment( $json, $filename );
		$attachments = '' !== $attachment ? array( $attachment ) : array();
		$ok = Alerts::safe_wp_mail( $to, $subject, $body, $attachments );
		if ( '' !== $attachment ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			@unlink( $attachment );
		}

		return array(
			'ok'     => $ok,
			'status' => $ok ? 'sent' : 'failed',
			'json'   => $json,
		);
	}

	private static function iso_week_id( int $now ): string {
		try {
			$tz = function_exists( 'wp_timezone' ) ? wp_timezone() : new \DateTimeZone( 'UTC' );
			$dt = new \DateTimeImmutable( '@' . $now );
			$dt = $dt->setTimezone( $tz instanceof \DateTimeZone ? $tz : new \DateTimeZone( 'UTC' ) );
			return $dt->format( 'o-\WW' );
		} catch ( \Exception $e ) {
			return gmdate( 'o-\WW', $now );
		}
	}

	private static function write_temp_json_attachment( string $json, string $filename ): string {
		if ( '' === $json ) {
			return '';
		}
		$base = function_exists( 'wp_tempnam' )
			? wp_tempnam( 'handl-aicac-rules-' )
			: tempnam( sys_get_temp_dir(), 'handl-aicac-rules-' );
		if ( ! is_string( $base ) || '' === $base ) {
			return '';
		}
		$path = $base . '.json';
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		@unlink( $base );
		$written = file_put_contents( $path, $json );
		if ( false === $written ) {
			return '';
		}
		unset( $filename );

		return $path;
	}
}
