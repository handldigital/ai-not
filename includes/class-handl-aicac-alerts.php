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
 *
 * Mail work is deferred to shutdown so the AI Client denial *filter* path
 * does not block on SMTP. That is not the same as releasing the HTTP
 * connection early — typical FastCGI holds the client open until shutdown
 * finishes unless something calls fastcgi_finish_request() (WordPress does
 * not by default). Outbound copies use path-only URIs; full request URIs
 * remain in the local audit log only.
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

	/** @var list<array{event:array<string,mixed>,policy:array<string,mixed>}> */
	private static array $deferred_immediate = array();

	/** @var list<array<string,mixed>> */
	private static array $deferred_digest_events = array();

	private static bool $flush_hooked = false;

	public static function instance(): Alerts {
		if ( null === self::$instance ) {
			self::$instance = new Alerts();
		}
		return self::$instance;
	}

	public function init(): void {
		add_action( self::CRON_HOOK, array( $this, 'send_digest' ) );
		// Self-heal lost cron events (hosting resets / "optimize" plugins).
		add_action( 'init', array( $this, 'maybe_self_heal_schedule' ), 20 );
	}

	/**
	 * Re-schedule digest cron when policy wants it and the event is missing.
	 */
	public function maybe_self_heal_schedule(): void {
		self::maybe_schedule( Policy::get_policy() );
	}

	/**
	 * Schedule the hourly digest/drain cron whenever denial alerts are on.
	 *
	 * Digest mode: primary delivery. Immediate mode: safety net that drains
	 * failed sends and rate-limit overflow within the hour (does nothing when
	 * the queue is empty). Unschedules only when alerts are fully off.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function maybe_schedule( array $policy ): void {
		$enabled = ! empty( $policy['alert_on_deny'] );

		if ( $enabled ) {
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
	 * Drop queued denial rows (disable / uninstall).
	 */
	public static function clear_digest_queue(): void {
		delete_option( self::DIGEST_OPTION_KEY );
	}

	/**
	 * Called after a real enforcement denial is logged.
	 *
	 * Work is deferred to shutdown so the AI Client filter path does not block
	 * on SMTP or option thrash (not a claim that the HTTP response is already
	 * released to the client). Never changes allow/deny.
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
			self::$deferred_digest_events[] = $event;
			self::hook_flush();
			return;
		}

		self::$deferred_immediate[] = array(
			'event'  => $event,
			'policy' => $policy,
		);
		self::hook_flush();
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
	 * Register a single shutdown flush for this request.
	 */
	private static function hook_flush(): void {
		if ( self::$flush_hooked ) {
			return;
		}
		self::$flush_hooked = true;
		add_action( 'shutdown', array( self::class, 'flush_deferred' ), 5 );
	}

	/**
	 * Process deferred digest queue writes and immediate mails.
	 *
	 * Public so the shutdown hook can call it; not part of the external API.
	 */
	public static function flush_deferred(): void {
		if ( ! empty( self::$deferred_digest_events ) ) {
			self::append_digest_rows( self::$deferred_digest_events );
			self::$deferred_digest_events = array();
		}

		if ( empty( self::$deferred_immediate ) ) {
			return;
		}

		$pending                      = self::$deferred_immediate;
		self::$deferred_immediate     = array();

		foreach ( $pending as $item ) {
			if ( ! is_array( $item ) || ! isset( $item['event'], $item['policy'] ) || ! is_array( $item['event'] ) || ! is_array( $item['policy'] ) ) {
				continue;
			}
			self::send_immediate_now( $item['event'], $item['policy'] );
		}
	}

	/**
	 * @param list<array<string,mixed>> $events
	 */
	private static function append_digest_rows( array $events ): void {
		$queue = get_option( self::DIGEST_OPTION_KEY, array() );
		if ( ! is_array( $queue ) ) {
			$queue = array();
		}

		foreach ( $events as $event ) {
			if ( ! is_array( $event ) ) {
				continue;
			}
			$queue[] = self::summarize_event( $event );
		}

		$count = count( $queue );
		if ( $count > self::DIGEST_QUEUE_MAX ) {
			$queue = array_slice( $queue, $count - self::DIGEST_QUEUE_MAX );
		}

		update_option( self::DIGEST_OPTION_KEY, $queue, false );
	}

	/**
	 * @param array<string,mixed> $event
	 */
	private static function queue_digest_row( array $event ): void {
		self::append_digest_rows( array( $event ) );
	}

	/**
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 */
	private static function send_immediate_now( array $event, array $policy ): void {
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

		// record_send only on true; false/Throwable → queue so the denial is not silently lost
		// and does not burn a rate slot (Frink live: pre_wp_mail → false still rate_count++ on 488b0df).
		if ( self::safe_wp_mail( $to, $subject, $body ) ) {
			self::record_send();
		} else {
			self::queue_digest_row( $event );
		}
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

		if ( self::safe_wp_mail( $to, $subject, $body ) ) {
			update_option( self::DIGEST_OPTION_KEY, array(), false );
		}
	}

	/**
	 * wp_mail is pluggable; SMTP replacements may throw. A failed notification
	 * must never turn a denied AI call into a fatal on the filter path (or on
	 * shutdown after a denial).
	 */
	private static function safe_wp_mail( string $to, string $subject, string $body ): bool {
		try {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.wp_mail -- intentional notification path.
			return (bool) wp_mail( $to, $subject, $body );
		} catch ( \Throwable $e ) {
			return false;
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
	 * Strip query string (and fragment) for outbound mail / digest storage.
	 * Full URI stays in the local audit ring buffer only.
	 */
	private static function uri_path_only( string $uri ): string {
		if ( '' === $uri ) {
			return '';
		}
		// REQUEST_URI is typically path?query — avoid parse_url so relative paths work.
		$cut = strpos( $uri, '?' );
		if ( false !== $cut ) {
			$uri = substr( $uri, 0, $cut );
		}
		$cut = strpos( $uri, '#' );
		if ( false !== $cut ) {
			$uri = substr( $uri, 0, $cut );
		}
		return $uri;
	}

	/**
	 * Mail/digest summary — deliberately omits prompt_preview and user identity.
	 * URI is path-only (query string never leaves the box via this path).
	 *
	 * @param array<string,mixed> $event
	 * @return array<string,mixed>
	 */
	private static function summarize_event( array $event ): array {
		$matched = array();
		if ( isset( $event['matched_tools'] ) && is_array( $event['matched_tools'] ) ) {
			$matched = array_values( array_map( 'strval', $event['matched_tools'] ) );
		}

		$uri = isset( $event['uri'] ) ? (string) $event['uri'] : '';

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
			'uri'               => self::uri_path_only( $uri ),
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
			// Path only — query strings are stripped in summarize_event.
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
