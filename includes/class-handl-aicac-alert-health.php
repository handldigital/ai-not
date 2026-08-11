<?php
/**
 * AICAC-ALERT-HEALTH: Track alert email/webhook delivery success and failures.
 *
 * Records last success/failure per channel so a broken mail or webhook path
 * is visible on the Dashboard and in Site Health. No new outbound collection.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Delivery-health telemetry for configured alert channels.
 */
final class Alert_Health {

	public const OPTION_KEY = 'handl_aicac_alert_health';

	/** Consecutive failures before Site Health goes critical. */
	public const FAILURE_THRESHOLD = 3;

	public const CHANNEL_EMAIL   = 'email';
	public const CHANNEL_WEBHOOK = 'webhook';

	/**
	 * @return list<string>
	 */
	public static function channels(): array {
		return array( self::CHANNEL_EMAIL, self::CHANNEL_WEBHOOK );
	}

	/**
	 * @return array<string,array{
	 *   last_success_at:?int,
	 *   last_failure_at:?int,
	 *   last_failure_reason:string,
	 *   consecutive_failures:int
	 * }>
	 */
	public static function get_state(): array {
		$raw = get_option( self::OPTION_KEY, array() );
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}

		$out = array();
		foreach ( self::channels() as $channel ) {
			$row = isset( $raw[ $channel ] ) && is_array( $raw[ $channel ] ) ? $raw[ $channel ] : array();
			$out[ $channel ] = self::normalize_row( $row );
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $row
	 * @return array{
	 *   last_success_at:?int,
	 *   last_failure_at:?int,
	 *   last_failure_reason:string,
	 *   consecutive_failures:int
	 * }
	 */
	public static function normalize_row( array $row ): array {
		$success = isset( $row['last_success_at'] ) ? (int) $row['last_success_at'] : 0;
		$failure = isset( $row['last_failure_at'] ) ? (int) $row['last_failure_at'] : 0;
		$reason  = isset( $row['last_failure_reason'] ) ? sanitize_text_field( (string) $row['last_failure_reason'] ) : '';
		$consec  = isset( $row['consecutive_failures'] ) ? (int) $row['consecutive_failures'] : 0;

		return array(
			'last_success_at'       => $success > 0 ? $success : null,
			'last_failure_at'       => $failure > 0 ? $failure : null,
			'last_failure_reason'   => $reason,
			'consecutive_failures'  => max( 0, $consec ),
		);
	}

	public static function sanitize_channel( string $channel ): string {
		$channel = sanitize_key( $channel );
		return in_array( $channel, self::channels(), true ) ? $channel : '';
	}

	public static function record_success( string $channel, ?int $now = null ): void {
		$channel = self::sanitize_channel( $channel );
		if ( '' === $channel ) {
			return;
		}
		$now   = null !== $now ? $now : time();
		$state = self::get_state();
		$row   = $state[ $channel ];
		$row['last_success_at']      = $now;
		$row['consecutive_failures'] = 0;
		$state[ $channel ]           = $row;
		update_option( self::OPTION_KEY, $state, false );
	}

	public static function record_failure( string $channel, string $reason, ?int $now = null ): void {
		$channel = self::sanitize_channel( $channel );
		if ( '' === $channel ) {
			return;
		}
		$now    = null !== $now ? $now : time();
		$reason = sanitize_text_field( $reason );
		if ( strlen( $reason ) > 200 ) {
			$reason = substr( $reason, 0, 200 );
		}
		$state = self::get_state();
		$row   = $state[ $channel ];
		$row['last_failure_at']      = $now;
		$row['last_failure_reason']  = $reason;
		$row['consecutive_failures'] = (int) $row['consecutive_failures'] + 1;
		$state[ $channel ]           = $row;
		update_option( self::OPTION_KEY, $state, false );
	}

	/**
	 * Record the result of an email or webhook attempt.
	 */
	public static function record_result( string $channel, bool $ok, string $failure_reason = '', ?int $now = null ): void {
		if ( $ok ) {
			self::record_success( $channel, $now );
			return;
		}
		if ( '' === $failure_reason ) {
			$failure_reason = self::CHANNEL_WEBHOOK === $channel
				? 'Webhook request failed'
				: 'Email send failed';
		}
		self::record_failure( $channel, $failure_reason, $now );
	}

	/**
	 * Whether a channel is considered "configured" for health surfaces.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function channel_configured( string $channel, array $policy ): bool {
		$channel = self::sanitize_channel( $channel );
		if ( self::CHANNEL_EMAIL === $channel ) {
			// Any email-backed alert path that can fire.
			return '' !== Alerts::resolve_email( $policy )
				&& (
					! empty( $policy['alert_on_deny'] )
					|| ! empty( $policy['alert_on_shadow'] )
					|| ! empty( $policy['weekly_report_enabled'] )
					|| Spend_Threshold::has_any_threshold( $policy )
					|| ! empty( $policy['anomaly_alert_enabled'] )
				);
		}
		if ( self::CHANNEL_WEBHOOK === $channel ) {
			return '' !== Alerts::resolve_webhook( $policy );
		}

		return false;
	}

	/**
	 * Configured channels that currently meet the consecutive-failure threshold.
	 *
	 * @param array<string,mixed> $policy
	 * @return list<string>
	 */
	public static function failing_channels( array $policy ): array {
		$state = self::get_state();
		$out   = array();
		foreach ( self::channels() as $channel ) {
			if ( ! self::channel_configured( $channel, $policy ) ) {
				continue;
			}
			$row = $state[ $channel ];
			if ( (int) $row['consecutive_failures'] >= self::FAILURE_THRESHOLD ) {
				$out[] = $channel;
			}
		}

		return $out;
	}

	/**
	 * Plain-language channel label for UI.
	 */
	public static function channel_label( string $channel ): string {
		if ( self::CHANNEL_WEBHOOK === $channel ) {
			return __( 'Webhook', 'handl-ai-connector-access-control' );
		}

		return __( 'Alert email', 'handl-ai-connector-access-control' );
	}

	/**
	 * One Dashboard line for a channel row.
	 *
	 * @param array{
	 *   last_success_at:?int,
	 *   last_failure_at:?int,
	 *   last_failure_reason:string,
	 *   consecutive_failures:int
	 * } $row
	 */
	public static function format_status_line( string $channel, array $row ): string {
		$label   = self::channel_label( $channel );
		$parts   = array( $label );
		$success = $row['last_success_at'];
		$failure = $row['last_failure_at'];

		if ( null === $success && null === $failure ) {
			$parts[] = __( 'No delivery attempts recorded yet.', 'handl-ai-connector-access-control' );
			return implode( ' — ', $parts );
		}

		if ( null !== $success ) {
			$parts[] = sprintf(
				/* translators: %s: localized date/time */
				__( 'Last delivered: %s', 'handl-ai-connector-access-control' ),
				self::format_time( $success )
			);
		} else {
			$parts[] = __( 'Last delivered: never', 'handl-ai-connector-access-control' );
		}

		if ( null !== $failure ) {
			$reason = (string) $row['last_failure_reason'];
			if ( '' !== $reason ) {
				$parts[] = sprintf(
					/* translators: 1: localized date/time, 2: failure reason */
					__( 'Last failure: %1$s (%2$s)', 'handl-ai-connector-access-control' ),
					self::format_time( $failure ),
					$reason
				);
			} else {
				$parts[] = sprintf(
					/* translators: %s: localized date/time */
					__( 'Last failure: %s', 'handl-ai-connector-access-control' ),
					self::format_time( $failure )
				);
			}
		}

		$consec = (int) $row['consecutive_failures'];
		if ( $consec >= self::FAILURE_THRESHOLD ) {
			$parts[] = sprintf(
				/* translators: %d: consecutive failure count */
				__( '%d failed attempts in a row.', 'handl-ai-connector-access-control' ),
				$consec
			);
		}

		return implode( ' — ', $parts );
	}

	private static function format_time( int $ts ): string {
		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( 'Y-m-d H:i', $ts );
		}

		return gmdate( 'Y-m-d H:i', $ts ) . ' UTC';
	}
}
