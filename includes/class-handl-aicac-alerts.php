<?php
/**
 * Denial email alerts and digests (opt-in).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Loud attributed denial notifications via wp_mail.
 *
 * Observability only — never influences allow/deny.
 */
final class Alerts {
	public const DIGEST_OPTION_KEY = 'handl_aicac_denial_digest_queue';
	public const RATE_OPTION_KEY   = 'handl_aicac_denial_email_rate';
	public const CRON_HOOK         = 'handl_aicac_send_denial_digest';

	/** Max immediate emails per rolling hour (flood guard). */
	private const IMMEDIATE_MAX_PER_HOUR = 20;

	/** Max rows retained in the digest queue. */
	private const DIGEST_QUEUE_MAX = 200;

	private static ?Alerts $instance = null;

	public static function instance(): Alerts {
		if ( null === self::$instance ) {
			self::$instance = new Alerts();
		}
		return self::$instance;
	}

	public function init(): void {
		add_action( self::CRON_HOOK, array( $this, 'send_digest' ) );
	}

	/**
	 * Schedule hourly digest when policy uses digest mode.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function maybe_schedule( array $policy ): void {
		$enabled = ! empty( $policy['alert_on_deny'] );
		$mode    = self::sanitize_mode( $policy['alert_mode'] ?? 'immediate' );

		if ( $enabled && 'digest' === $mode ) {
			if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
				wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::CRON_HOOK );
			}
			return;
		}

		$ts = wp_next_scheduled( self::CRON_HOOK );
		if ( $ts ) {
			wp_unschedule_event( $ts, self::CRON_HOOK );
		}
	}

	/**
	 * Called after a real enforcement denial is logged.
	 *
	 * @param array<string,mixed> $event  Log row shape.
	 * @param array<string,mixed> $policy Current policy.
	 */
	public static function maybe_notify_denial( array $event, array $policy ): void {
		if ( empty( $policy['alert_on_deny'] ) ) {
			return;
		}
		// Learn mode never blocks — no denial emails for would-deny rows.
		if ( ! empty( $policy['audit_only'] ) ) {
			return;
		}
		if ( ( $event['decision'] ?? '' ) !== 'deny' ) {
			return;
		}

		$mode = self::sanitize_mode( $policy['alert_mode'] ?? 'immediate' );
		if ( 'digest' === $mode ) {
			self::queue_digest_row( $event );
			return;
		}

		self::send_immediate( $event, $policy );
	}

	/**
	 * @param mixed $raw
	 * @return 'immediate'|'digest'
	 */
	public static function sanitize_mode( $raw ): string {
		$raw = sanitize_key( (string) $raw );
		return 'digest' === $raw ? 'digest' : 'immediate';
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_email( $raw ): string {
		$email = sanitize_email( (string) $raw );
		return is_email( $email ) ? $email : '';
	}

	/**
	 * Recipient: configured address or site admin_email.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function resolve_email( array $policy ): string {
		$configured = self::sanitize_email( $policy['alert_email'] ?? '' );
		if ( '' !== $configured ) {
			return $configured;
		}
		$admin = sanitize_email( (string) get_option( 'admin_email' ) );
		return is_email( $admin ) ? $admin : '';
	}

	/**
	 * @param array<string,mixed> $event
	 */
	private static function queue_digest_row( array $event ): void {
		$queue = get_option( self::DIGEST_OPTION_KEY, array() );
		if ( ! is_array( $queue ) ) {
			$queue = array();
		}

		$queue[] = self::summarize_event( $event );
		$count   = count( $queue );
		if ( $count > self::DIGEST_QUEUE_MAX ) {
			$queue = array_slice( $queue, $count - self::DIGEST_QUEUE_MAX );
		}

		update_option( self::DIGEST_OPTION_KEY, $queue, false );
	}

	/**
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 */
	private static function send_immediate( array $event, array $policy ): void {
		if ( ! self::under_rate_limit() ) {
			// Still queue so the denial is not silently lost.
			self::queue_digest_row( $event );
			return;
		}

		$to = self::resolve_email( $policy );
		if ( '' === $to ) {
			return;
		}

		$summary = self::summarize_event( $event );
		$subject = sprintf(
			/* translators: %s: site name */
			__( '[%s] HandL AICAC denied an AI Client call', 'handl-ai-connector-access-control' ),
			wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
		);

		$body  = __( 'HandL AI Connector Access Control blocked an AI Client prompt.', 'handl-ai-connector-access-control' ) . "\n\n";
		$body .= self::format_summary_lines( $summary );
		$body .= "\n" . __( 'This message was sent by HandL AICAC (not by the calling plugin). Review rules under Settings → HandL AI Connector Access Control.', 'handl-ai-connector-access-control' ) . "\n";
		$body .= admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=log' ) . "\n";

		// phpcs:ignore WordPress.WP.AlternativeFunctions.wp_mail -- intentional notification path.
		wp_mail( $to, $subject, $body );
		self::record_send();
	}

	/**
	 * Cron / manual digest flush.
	 */
	public function send_digest(): void {
		$policy = Policy::get_policy();
		if ( empty( $policy['alert_on_deny'] ) ) {
			return;
		}

		$queue = get_option( self::DIGEST_OPTION_KEY, array() );
		if ( ! is_array( $queue ) || empty( $queue ) ) {
			return;
		}

		$to = self::resolve_email( $policy );
		if ( '' === $to ) {
			return;
		}

		$count   = count( $queue );
		$subject = sprintf(
			/* translators: 1: site name, 2: denial count */
			__( '[%1$s] HandL AICAC denial digest (%2$d)', 'handl-ai-connector-access-control' ),
			wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
			$count
		);

		$body  = sprintf(
			/* translators: %d: number of denials in this digest */
			__( 'HandL AI Connector Access Control blocked %d AI Client prompt(s) since the last digest.', 'handl-ai-connector-access-control' ),
			$count
		) . "\n\n";

		$shown = 0;
		foreach ( $queue as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			++$shown;
			if ( $shown > 50 ) {
				$body .= sprintf(
					/* translators: %d: remaining rows not listed */
					__( "…and %d more (see the audit log).\n", 'handl-ai-connector-access-control' ),
					$count - 50
				);
				break;
			}
			$body .= '--- #' . $shown . " ---\n";
			$body .= self::format_summary_lines( $row ) . "\n";
		}

		$body .= __( 'This digest was sent by HandL AICAC. Review rules under Settings → HandL AI Connector Access Control.', 'handl-ai-connector-access-control' ) . "\n";
		$body .= admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=log' ) . "\n";

		// phpcs:ignore WordPress.WP.AlternativeFunctions.wp_mail -- intentional notification path.
		$ok = wp_mail( $to, $subject, $body );
		if ( $ok ) {
			update_option( self::DIGEST_OPTION_KEY, array(), false );
		}
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function pending_digest_rows(): array {
		$queue = get_option( self::DIGEST_OPTION_KEY, array() );
		return is_array( $queue ) ? array_values( $queue ) : array();
	}

	/**
	 * @param array<string,mixed> $event
	 * @return array<string,mixed>
	 */
	private static function summarize_event( array $event ): array {
		$matched = array();
		if ( isset( $event['matched_tools'] ) && is_array( $event['matched_tools'] ) ) {
			$matched = array_values( array_map( 'strval', $event['matched_tools'] ) );
		}

		return array(
			'ts'                => isset( $event['ts'] ) ? (int) $event['ts'] : time(),
			'plugin'            => isset( $event['plugin'] ) ? (string) $event['plugin'] : '',
			'operation'         => isset( $event['operation'] ) ? (string) $event['operation'] : '',
			'capability_family' => isset( $event['capability_family'] ) ? (string) $event['capability_family'] : '',
			'denial_reason'     => isset( $event['denial_reason'] ) ? (string) $event['denial_reason'] : '',
			'matched_tools'     => $matched,
			'provider'          => isset( $event['provider'] ) ? (string) $event['provider'] : '',
			'model'             => isset( $event['model'] ) ? (string) $event['model'] : '',
			'model_inferred'    => ! empty( $event['model_inferred'] ),
			'uri'               => isset( $event['uri'] ) ? (string) $event['uri'] : '',
		);
	}

	/**
	 * @param array<string,mixed> $summary
	 */
	private static function format_summary_lines( array $summary ): string {
		$ts = ! empty( $summary['ts'] ) ? wp_date( 'Y-m-d H:i:s', (int) $summary['ts'] ) : '—';
		$lines = array(
			sprintf( 'Time: %s', $ts ),
			sprintf( 'Plugin: %s', $summary['plugin'] !== '' ? $summary['plugin'] : '(unknown)' ),
			sprintf( 'Operation: %s', $summary['operation'] !== '' ? $summary['operation'] : '—' ),
			sprintf( 'Family: %s', $summary['capability_family'] !== '' ? $summary['capability_family'] : '—' ),
			sprintf( 'Reason: %s', $summary['denial_reason'] !== '' ? $summary['denial_reason'] : '—' ),
		);
		if ( ! empty( $summary['matched_tools'] ) && is_array( $summary['matched_tools'] ) ) {
			$lines[] = 'Matched tools: ' . implode( ', ', $summary['matched_tools'] );
		}
		$prov = (string) ( $summary['provider'] ?? '' );
		$mod  = (string) ( $summary['model'] ?? '' );
		if ( '' !== $prov || '' !== $mod ) {
			$inf = ! empty( $summary['model_inferred'] ) ? ' (inferred)' : '';
			$lines[] = sprintf( 'Provider/model: %s / %s%s', $prov ?: '—', $mod ?: '—', $inf );
		}
		if ( ! empty( $summary['uri'] ) ) {
			$lines[] = 'URI: ' . $summary['uri'];
		}

		return implode( "\n", $lines ) . "\n";
	}

	private static function under_rate_limit(): bool {
		$bucket = get_option( self::RATE_OPTION_KEY, array() );
		if ( ! is_array( $bucket ) ) {
			$bucket = array();
		}
		$now   = time();
		$since = $now - HOUR_IN_SECONDS;
		$times = array();
		foreach ( $bucket as $t ) {
			$t = (int) $t;
			if ( $t >= $since ) {
				$times[] = $t;
			}
		}
		return count( $times ) < self::IMMEDIATE_MAX_PER_HOUR;
	}

	private static function record_send(): void {
		$bucket = get_option( self::RATE_OPTION_KEY, array() );
		if ( ! is_array( $bucket ) ) {
			$bucket = array();
		}
		$now   = time();
		$since = $now - HOUR_IN_SECONDS;
		$times = array();
		foreach ( $bucket as $t ) {
			$t = (int) $t;
			if ( $t >= $since ) {
				$times[] = $t;
			}
		}
		$times[] = $now;
		update_option( self::RATE_OPTION_KEY, $times, false );
	}
}
