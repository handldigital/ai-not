<?php
/**
 * AICAC-WEBHOOK-TEST (#175): capped webhook delivery history for admins.
 *
 * Stores the last N outbound webhook attempts (timestamp, event type,
 * HTTP status, retry count) so delivery failures are visible without
 * relying only on consecutive-failure health counters.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Ring-buffer of recent webhook delivery rows.
 */
final class Webhook_Delivery_Log {

	public const OPTION_KEY = 'handl_aicac_webhook_delivery_log';

	public const MAX_ROWS = 20;

	/**
	 * @param array{
	 *   ts?:int,
	 *   event?:string,
	 *   http_status?:int|null,
	 *   retries?:int,
	 *   ok?:bool,
	 *   error?:string
	 * } $row
	 */
	public static function push( array $row ): void {
		$normalized = self::normalize_row( $row );
		$list       = self::get_rows();
		array_unshift( $list, $normalized );
		$list = array_slice( $list, 0, self::MAX_ROWS );
		update_option( self::OPTION_KEY, $list, false );
	}

	/**
	 * @return list<array{
	 *   ts:int,
	 *   event:string,
	 *   http_status:?int,
	 *   retries:int,
	 *   ok:bool,
	 *   error:string
	 * }>
	 */
	public static function get_rows(): array {
		$raw = get_option( self::OPTION_KEY, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}

		$out = array();
		foreach ( $raw as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$out[] = self::normalize_row( $row );
			if ( count( $out ) >= self::MAX_ROWS ) {
				break;
			}
		}

		return $out;
	}

	/**
	 * Plain-language event label for the Activity table.
	 */
	public static function event_label( string $event ): string {
		switch ( sanitize_key( $event ) ) {
			case 'denial':
				return __( 'Blocked call', 'handl-ai-connector-access-control' );
			case 'denial_digest':
				return __( 'Blocked-call summary', 'handl-ai-connector-access-control' );
			case 'test':
				return __( 'Test', 'handl-ai-connector-access-control' );
			case 'drift':
				return __( 'Usage change', 'handl-ai-connector-access-control' );
			case 'anomaly':
				return __( 'Usage spike', 'handl-ai-connector-access-control' );
			default:
				$event = sanitize_key( $event );
				return '' !== $event ? $event : __( 'Webhook', 'handl-ai-connector-access-control' );
		}
	}

	/**
	 * @param array<string,mixed> $row
	 * @return array{
	 *   ts:int,
	 *   event:string,
	 *   http_status:?int,
	 *   retries:int,
	 *   ok:bool,
	 *   error:string
	 * }
	 */
	public static function normalize_row( array $row ): array {
		$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		if ( $ts < 0 ) {
			$ts = 0;
		}

		$event = isset( $row['event'] ) ? sanitize_key( (string) $row['event'] ) : '';
		if ( strlen( $event ) > 64 ) {
			$event = substr( $event, 0, 64 );
		}

		$http = null;
		if ( array_key_exists( 'http_status', $row ) && null !== $row['http_status'] && '' !== $row['http_status'] ) {
			$http = (int) $row['http_status'];
			if ( $http < 0 ) {
				$http = 0;
			}
		}

		$retries = isset( $row['retries'] ) ? (int) $row['retries'] : 0;
		if ( $retries < 0 ) {
			$retries = 0;
		}
		if ( $retries > 5 ) {
			$retries = 5;
		}

		$error = isset( $row['error'] ) ? sanitize_text_field( (string) $row['error'] ) : '';
		if ( strlen( $error ) > 200 ) {
			$error = substr( $error, 0, 200 );
		}

		return array(
			'ts'          => $ts,
			'event'       => $event,
			'http_status' => $http,
			'retries'     => $retries,
			'ok'          => ! empty( $row['ok'] ),
			'error'       => $error,
		);
	}
}
