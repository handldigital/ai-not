<?php
/**
 * Denial / shadow-observe email (and denial webhook) alerts and digests (opt-in).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Loud attributed denial notifications via wp_mail and optional webhook POST,
 * plus optional shadow-AI (direct_http observe) email alerts.
 *
 * Observability only — never influences allow/deny / never blocks HTTP.
 *
 * Mail and webhook work is deferred to shutdown so the AI Client denial
 * *filter* path (and shadow observe path) does not block on SMTP or HTTP.
 * That is not the same as releasing the HTTP connection early — typical
 * FastCGI holds the client open until shutdown finishes unless something
 * calls fastcgi_finish_request() (WordPress does not by default). Outbound
 * copies use path-only URIs; full request URIs remain in the local audit
 * log only.
 *
 * Webhook URL is an intentional admin-supplied outbound integration (same
 * trust model as the configurable wp_mail recipient). Scheme is restricted
 * to http/https; delivery uses wp_remote_post (WP HTTP API) with redirects
 * disabled. Shadow-AI alerts are email-only (no webhook) in this release.
 */
final class Alerts {
	public const DIGEST_OPTION_KEY = 'handl_aicac_denial_digest_queue';
	public const RATE_OPTION_KEY   = 'handl_aicac_denial_email_rate';
	public const TEST_EMAIL_RATE_OPTION_KEY = 'handl_aicac_test_email_rate';
	public const CRON_HOOK         = 'handl_aicac_send_denial_digest';

	/** Max immediate emails per rolling hour (flood guard). */
	private const IMMEDIATE_MAX_PER_HOUR = 20;

	/** Cooldown between admin "Send test email" clicks (abuse / relay guard). */
	private const TEST_EMAIL_COOLDOWN_SECONDS = 60;

	/** Max rows retained in the digest queue. */
	private const DIGEST_QUEUE_MAX = 200;

	/** Allowed admin test-email channels (denial alerts vs weekly report). */
	public const TEST_EMAIL_CHANNELS = array( 'denial_alert', 'weekly_report', 'monthly_report' );

	private static ?Alerts $instance = null;

	/** @var list<array{event:array<string,mixed>,policy:array<string,mixed>,kind?:string}> */
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
	 * Schedule the hourly digest/drain cron whenever denial or shadow alerts are on.
	 *
	 * Digest mode: primary delivery. Immediate mode: safety net that drains
	 * failed sends and rate-limit overflow within the hour (does nothing when
	 * the queue is empty). Unschedules only when both alert types are off.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function maybe_schedule( array $policy ): void {
		$enabled = ! empty( $policy['alert_on_deny'] ) || ! empty( $policy['alert_on_shadow'] );

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
	 * Drop queued alert rows (disable / uninstall).
	 */
	public static function clear_digest_queue(): void {
		delete_option( self::DIGEST_OPTION_KEY );
	}

	/**
	 * Keep only queue rows whose alert type is still enabled.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function prune_digest_queue( array $policy ): void {
		$deny_on   = ! empty( $policy['alert_on_deny'] );
		$shadow_on = ! empty( $policy['alert_on_shadow'] );
		if ( ! $deny_on && ! $shadow_on ) {
			self::clear_digest_queue();
			return;
		}

		$queue = get_option( self::DIGEST_OPTION_KEY, array() );
		if ( ! is_array( $queue ) || empty( $queue ) ) {
			return;
		}

		$keep = array();
		foreach ( $queue as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$kind = isset( $row['alert_kind'] ) ? (string) $row['alert_kind'] : 'denial';
			if ( 'shadow' === $kind ) {
				if ( $shadow_on ) {
					$keep[] = $row;
				}
				continue;
			}
			if ( $deny_on ) {
				$keep[] = $row;
			}
		}

		update_option( self::DIGEST_OPTION_KEY, $keep, false );
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
		// AICAC-SNOOZE: mute delivery for this plugin; enforcement/logging unchanged.
		$plugin = isset( $event['plugin'] ) ? (string) $event['plugin'] : '';
		if ( Alert_Snooze::should_suppress( $plugin, 'denial' ) ) {
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
			'kind'   => 'denial',
		);
		self::hook_flush();
	}

	/**
	 * Called after a new direct_http observe row is retained (not collapsed).
	 *
	 * Opt-in shadow-AI email only. Observability — never blocks HTTP.
	 * Deferred to shutdown like denial alerts so observe path does not block
	 * on SMTP. Skips when AI is disabled site-wide via wp_supports_ai.
	 *
	 * @param array<string,mixed> $event  Log row shape (channel=direct_http).
	 * @param array<string,mixed> $policy Current policy.
	 */
	public static function maybe_notify_shadow( array $event, array $policy ): void {
		if ( empty( $policy['alert_on_shadow'] ) ) {
			return;
		}
		// Same observability gate as the detector / ring buffer.
		if ( empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] ) ) {
			return;
		}
		if ( function_exists( 'wp_supports_ai' ) && ! wp_supports_ai() ) {
			return;
		}
		if ( ( $event['channel'] ?? '' ) !== 'direct_http' ) {
			return;
		}
		// AICAC-SNOOZE: mute delivery for this plugin; observe logging continues.
		$plugin = isset( $event['plugin'] ) ? (string) $event['plugin'] : '';
		if ( Alert_Snooze::should_suppress( $plugin, 'shadow' ) ) {
			return;
		}

		$mode = self::sanitize_mode( $policy['alert_mode'] ?? 'immediate' );
		if ( 'digest' === $mode ) {
			// Tag before queue so digest formatting/pruning can distinguish.
			$event['alert_kind'] = 'shadow';
			self::$deferred_digest_events[] = $event;
			self::hook_flush();
			return;
		}

		self::$deferred_immediate[] = array(
			'event'  => $event,
			'policy' => $policy,
			'kind'   => 'shadow',
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
	 * Encode an email for add_query_arg() redirects.
	 *
	 * WordPress build_query() leaves "+" unencoded; PHP query parsing turns
	 * unencoded "+" into a space, which sanitize_email() then strips — so
	 * plus-addressed recipients (user+tag@domain) corrupt in admin notices.
	 */
	public static function encode_email_query_arg( string $email ): string {
		return rawurlencode( $email );
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
	 * Sanitize webhook URL: http/https only. Empty input → empty string.
	 * Invalid non-empty input also yields '' (use validate_webhook_url_input
	 * when rejecting with an inline error is required).
	 *
	 * @param mixed $raw
	 */
	public static function sanitize_webhook_url( $raw ): string {
		$raw = trim( (string) $raw );
		if ( '' === $raw ) {
			return '';
		}

		// esc_url_raw with scheme allowlist drops javascript:, data:, ftp:, etc.
		$url = esc_url_raw( $raw, array( 'http', 'https' ) );
		if ( '' === $url ) {
			return '';
		}

		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return '';
		}

		$scheme = strtolower( (string) $parts['scheme'] );
		if ( 'http' !== $scheme && 'https' !== $scheme ) {
			return '';
		}

		return $url;
	}

	/**
	 * Validate admin webhook URL input for save (AC6).
	 *
	 * Empty is valid (clears the channel). Non-empty must sanitize to http(s).
	 *
	 * @param mixed $raw
	 * @return array{ok:bool,url:string,error:string}
	 */
	public static function validate_webhook_url_input( $raw ): array {
		$trimmed = trim( (string) $raw );
		if ( '' === $trimmed ) {
			return array(
				'ok'    => true,
				'url'   => '',
				'error' => '',
			);
		}

		$url = self::sanitize_webhook_url( $trimmed );
		if ( '' === $url ) {
			return array(
				'ok'    => false,
				'url'   => '',
				'error' => 'invalid',
			);
		}

		return array(
			'ok'    => true,
			'url'   => $url,
			'error' => '',
		);
	}

	/**
	 * Configured webhook URL, or empty when unset/invalid.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function resolve_webhook( array $policy ): string {
		return self::sanitize_webhook_url( $policy['alert_webhook_url'] ?? '' );
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
			$kind = isset( $item['kind'] ) ? (string) $item['kind'] : 'denial';
			if ( 'shadow' === $kind ) {
				self::send_immediate_shadow_now( $item['event'], $item['policy'] );
			} else {
				self::send_immediate_now( $item['event'], $item['policy'] );
			}
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

		$to  = self::resolve_email( $policy );
		$url = self::resolve_webhook( $policy );
		if ( '' === $to && '' === $url ) {
			return;
		}

		$summary = self::summarize_event( $event );
		$mail_ok = null;
		$hook_ok = null;

		if ( '' !== $to ) {
			$subject = sprintf(
				/* translators: %s: site name */
				__( '[%s] HandL blocked an AI Client call', 'handl-ai-connector-access-control' ),
				wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			);

			$body  = __( 'HandL AI Access blocked an AI Client prompt.', 'handl-ai-connector-access-control' ) . "\n\n";
			$body .= self::format_summary_lines( $summary );
			$body .= "\n" . __( 'This alert came from HandL AI Access, not the plugin that made the call. Review your rules under Settings → HandL AI Access.', 'handl-ai-connector-access-control' ) . "\n";
			$body .= admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=log' ) . "\n";

			// record_send only on true; false/Throwable → queue so the denial is not silently lost
			// and does not burn a rate slot (Frink live: pre_wp_mail → false still rate_count++ on 488b0df).
			$mail_ok = self::safe_wp_mail( $to, $subject, $body );
		}

		if ( '' !== $url ) {
			$hook_ok = self::safe_wp_remote_post( $url, self::build_immediate_webhook_payload( $summary ) );
		}

		$delivered = ( true === $mail_ok ) || ( null === $mail_ok && true === $hook_ok );
		if ( $delivered ) {
			self::record_send();
		}

		// Preserve email-path semantics: failed mail still queues for digest drain.
		// Webhook-only failure also queues so the denial is not silently lost.
		if ( false === $mail_ok || ( null === $mail_ok && false === $hook_ok ) ) {
			self::queue_digest_row( $event );
		}
	}

	/**
	 * Immediate shadow-AI observe email (no webhook — email-only channel).
	 *
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 */
	private static function send_immediate_shadow_now( array $event, array $policy ): void {
		$event['alert_kind'] = 'shadow';

		if ( ! self::under_rate_limit() ) {
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
			__( '[%s] HandL detected a direct AI connection (not blocked)', 'handl-ai-connector-access-control' ),
			wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
		);

		$body  = __( 'HandL AI Connector Access Control detected a direct connection to a known AI provider outside the AI Client. This request was observed, not blocked.', 'handl-ai-connector-access-control' ) . "\n\n";
		$body .= self::format_summary_lines( $summary );
		$body .= "\n" . __( 'This alert was sent by HandL AI Connector Access Control, not by the plugin that made the request. The request was not blocked. Review it under Settings → HandL AI Connector Access Control → Activity.', 'handl-ai-connector-access-control' ) . "\n";
		$body .= admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=log' ) . "\n";

		$mail_ok = self::safe_wp_mail( $to, $subject, $body );
		if ( true === $mail_ok ) {
			self::record_send();
			return;
		}

		// Failed / throwing mail → queue; do not burn a rate slot.
		self::queue_digest_row( $event );
	}

	/**
	 * Cron / manual digest flush.
	 */
	public function send_digest(): void {
		$policy = Policy::get_policy();
		$deny_on   = ! empty( $policy['alert_on_deny'] );
		$shadow_on = ! empty( $policy['alert_on_shadow'] );
		if ( ! $deny_on && ! $shadow_on ) {
			return;
		}

		$queue = get_option( self::DIGEST_OPTION_KEY, array() );
		if ( ! is_array( $queue ) || empty( $queue ) ) {
			return;
		}

		$denials = array();
		$shadows = array();
		foreach ( $queue as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			// Drop snoozed plugins from digest delivery; count as would-have-alerted.
			$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			$kind   = isset( $row['alert_kind'] ) ? (string) $row['alert_kind'] : 'denial';
			if ( '' !== $plugin && Alert_Snooze::should_suppress( $plugin, $kind ) ) {
				continue;
			}
			if ( 'shadow' === $kind ) {
				if ( $shadow_on ) {
					$shadows[] = $row;
				}
				continue;
			}
			if ( $deny_on ) {
				$denials[] = $row;
			}
		}

		if ( empty( $denials ) && empty( $shadows ) ) {
			// All rows were snoozed or disabled — drop them so the queue does not stick.
			update_option( self::DIGEST_OPTION_KEY, array(), false );
			return;
		}

		$to  = self::resolve_email( $policy );
		$url = self::resolve_webhook( $policy );
		// Shadow is email-only; webhook still useful when denials are present.
		if ( '' === $to && ( '' === $url || empty( $denials ) ) ) {
			return;
		}

		$mail_ok = null;
		$hook_ok = null;

		if ( '' !== $to ) {
			$subject = self::digest_subject( $denials, $shadows );
			$body    = self::format_digest_body( $denials, $shadows );
			$mail_ok = self::safe_wp_mail( $to, $subject, $body );
		}

		if ( '' !== $url && ! empty( $denials ) ) {
			// Webhook stays denial-scoped (shadow alerts are email-only).
			$hook_ok = self::safe_wp_remote_post( $url, self::build_digest_webhook_payload( $denials ) );
		}

		// Email path: clear only on mail success.
		// Webhook-only installs (denials, no email): clear when the POST succeeds.
		$cleared = ( true === $mail_ok ) || ( null === $mail_ok && true === $hook_ok );
		if ( $cleared ) {
			update_option( self::DIGEST_OPTION_KEY, array(), false );
		}
	}

	/**
	 * @param list<array<string,mixed>> $denials
	 * @param list<array<string,mixed>> $shadows
	 */
	private static function digest_subject( array $denials, array $shadows ): string {
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$d    = count( $denials );
		$s    = count( $shadows );

		if ( $d > 0 && $s > 0 ) {
			return sprintf(
				/* translators: 1: site name, 2: denial count, 3: shadow observe count */
				__( '[%1$s] HandL alert summary (%2$d blocked, %3$d direct connections observed)', 'handl-ai-connector-access-control' ),
				$site,
				$d,
				$s
			);
		}
		if ( $s > 0 ) {
			return sprintf(
				/* translators: 1: site name, 2: shadow observe count */
				__( '[%1$s] HandL direct AI connection summary (%2$d)', 'handl-ai-connector-access-control' ),
				$site,
				$s
			);
		}

		// Denial-only — match Krusty-signed #89/#51 blocked-call summary language.
		return sprintf(
			/* translators: 1: site name, 2: denial count */
			__( '[%1$s] HandL blocked-call summary (%2$d)', 'handl-ai-connector-access-control' ),
			$site,
			$d
		);
	}

	/**
	 * @param list<array<string,mixed>> $denials
	 * @param list<array<string,mixed>> $shadows
	 */
	private static function format_digest_body( array $denials, array $shadows ): string {
		$body = '';

		if ( ! empty( $denials ) ) {
			$body .= sprintf(
				/* translators: %d: number of denials in this digest */
				__( 'Blocked AI Client prompts since the last summary: %d', 'handl-ai-connector-access-control' ),
				count( $denials )
			) . "\n\n";

			$shown = 0;
			foreach ( $denials as $row ) {
				++$shown;
				if ( $shown > 50 ) {
					$body .= sprintf(
						/* translators: %d: remaining rows not listed */
						__( "Plus %d more. See the Activity log.\n", 'handl-ai-connector-access-control' ),
						count( $denials ) - 50
					);
					break;
				}
				$body .= '--- #' . $shown . " ---\n";
				$body .= self::format_summary_lines( $row ) . "\n";
			}
		}

		// Omit the shadow section entirely when empty (error_empty_states).
		if ( ! empty( $shadows ) ) {
			if ( '' !== $body ) {
				$body .= "\n";
			}
			$body .= sprintf(
				/* translators: %d: number of shadow observations in this digest */
				__( 'Direct AI connections observed outside the AI Client (not blocked): %d', 'handl-ai-connector-access-control' ),
				count( $shadows )
			) . "\n\n";

			$shown = 0;
			foreach ( $shadows as $row ) {
				++$shown;
				if ( $shown > 50 ) {
					$body .= sprintf(
						/* translators: %d: remaining rows not listed */
						__( "Plus %d more. See the Activity log.\n", 'handl-ai-connector-access-control' ),
						count( $shadows ) - 50
					);
					break;
				}
				$body .= '--- shadow #' . $shown . " ---\n";
				$body .= self::format_summary_lines( $row ) . "\n";
			}
		}

		$body .= __( 'This summary was sent by HandL AI Connector Access Control. Review activity and alert settings under Settings → HandL AI Connector Access Control.', 'handl-ai-connector-access-control' ) . "\n";
		$body .= admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=activity' ) . "\n";

		return $body;
	}

	/**
	 * Admin "Send test webhook" — immediate POST, bypasses rate limiting.
	 * Payload is clearly labeled as a test (not a real denial).
	 *
	 * @param array<string,mixed> $policy
	 * @return bool True when the endpoint returned 2xx.
	 */
	public static function send_test_webhook( array $policy ): bool {
		$url = self::resolve_webhook( $policy );
		if ( '' === $url ) {
			return false;
		}

		return self::safe_wp_remote_post( $url, self::build_test_webhook_payload() );
	}

	/**
	 * Admin "Send test email" — immediate wp_mail to the saved recipient
	 * (or admin_email). Never accepts a free-text To address.
	 *
	 * @param array<string,mixed> $policy
	 * @param string              $channel One of TEST_EMAIL_CHANNELS.
	 * @return array{ok:bool,status:string,to:string} status is sent|failed|rate_limited|no_recipient|invalid_channel.
	 */
	public static function send_test_email( array $policy, string $channel = 'denial_alert' ): array {
		$channel = self::sanitize_test_email_channel( $channel );
		if ( '' === $channel ) {
			return array(
				'ok'     => false,
				'status' => 'invalid_channel',
				'to'     => '',
			);
		}

		$to = self::resolve_email( $policy );
		if ( '' === $to ) {
			return array(
				'ok'     => false,
				'status' => 'no_recipient',
				'to'     => '',
			);
		}

		if ( ! self::under_test_email_rate_limit() ) {
			return array(
				'ok'     => false,
				'status' => 'rate_limited',
				'to'     => $to,
			);
		}

		// Count the attempt before wp_mail so rapid clicks cannot hammer SMTP.
		self::record_test_email_send();

		$subject = self::build_test_email_subject( $channel );
		$body    = self::build_test_email_body( $channel );
		$ok      = self::safe_wp_mail( $to, $subject, $body );

		return array(
			'ok'     => $ok,
			'status' => $ok ? 'sent' : 'failed',
			'to'     => $to,
		);
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_test_email_channel( $raw ): string {
		$channel = sanitize_key( (string) $raw );
		return in_array( $channel, self::TEST_EMAIL_CHANNELS, true ) ? $channel : '';
	}

	/**
	 * Subject for admin test email — clearly labeled; no per-call data.
	 */
	public static function build_test_email_subject( string $channel ): string {
		$channel = self::sanitize_test_email_channel( $channel );
		$site    = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );

		if ( 'weekly_report' === $channel ) {
			return sprintf(
				/* translators: %s: site name */
				__( '[%s] Test: HandL AICAC weekly report', 'handl-ai-connector-access-control' ),
				$site
			);
		}

		if ( 'monthly_report' === $channel ) {
			return sprintf(
				/* translators: %s: site name */
				__( '[%s] Test: HandL AI Access monthly audit report', 'handl-ai-connector-access-control' ),
				$site
			);
		}

		return sprintf(
			/* translators: %s: site name */
			__( '[%s] Test: HandL AICAC denial alert', 'handl-ai-connector-access-control' ),
			$site
		);
	}

	/**
	 * Body for admin test email — labeled as a test; no prompts, users, or call data.
	 */
	public static function build_test_email_body( string $channel ): string {
		$channel = self::sanitize_test_email_channel( $channel );

		$lines   = array();
		$lines[] = __( 'TEST MESSAGE: HandL AI Connector Access Control', 'handl-ai-connector-access-control' );

		if ( 'weekly_report' === $channel ) {
			$lines[] = __( 'This is a test. This is not a real weekly report.', 'handl-ai-connector-access-control' );
			$lines[] = '';
			$lines[] = __( 'You requested a test of weekly report email delivery from Settings → HandL AI Connector Access Control.', 'handl-ai-connector-access-control' );
		} elseif ( 'monthly_report' === $channel ) {
			$lines[] = __( 'This is a test. This is not a monthly audit report.', 'handl-ai-connector-access-control' );
			$lines[] = '';
			$lines[] = __( 'You requested a test of monthly audit report delivery from HandL AI Access.', 'handl-ai-connector-access-control' );
		} else {
			$lines[] = __( 'This is a test. No denial occurred.', 'handl-ai-connector-access-control' );
			$lines[] = '';
			$lines[] = __( 'You requested a test of denial alert email delivery from Settings → HandL AI Connector Access Control.', 'handl-ai-connector-access-control' );
		}

		$lines[] = '';
		$lines[] = __( 'This message contains no prompt text, user identity, or call details. It only confirms that WordPress accepted the test for sending to the saved recipient, or the site admin email. Inbox delivery is not guaranteed.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = __( 'Manage email settings:', 'handl-ai-connector-access-control' );
		$lines[] = admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=activity' );

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Privacy-scoped summary fields used by email and webhook (AC1).
	 *
	 * @param array<string,mixed> $event
	 * @return array<string,mixed>
	 */
	public static function summarize_event_public( array $event ): array {
		return self::summarize_event( $event );
	}

	/**
	 * Contained wp_mail wrapper. Records Alert_Health email channel result.
	 * wp_mail is pluggable; SMTP replacements may throw — never fatal on the
	 * denial filter path or shutdown after a denial.
	 */
	public static function safe_wp_mail( string $to, string $subject, string $body, array $attachments = array() ): bool {
		try {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.wp_mail -- intentional notification path.
			$ok = (bool) wp_mail( $to, $subject, $body, '', $attachments );
			Alert_Health::record_result(
				Alert_Health::CHANNEL_EMAIL,
				$ok,
				$ok ? '' : 'wp_mail returned false'
			);
			return $ok;
		} catch ( \Throwable $e ) {
			Alert_Health::record_result(
				Alert_Health::CHANNEL_EMAIL,
				false,
				'wp_mail error'
			);
			return false;
		}
	}

	/**
	 * Contained webhook POST (AC3): never throws; non-2xx / WP_Error / timeout → false.
	 * Does not follow redirects (SSRF-adjacent admin URL — intentional outbound).
	 * Records Alert_Health webhook channel result.
	 *
	 * @param array<string,mixed> $payload
	 */
	public static function safe_wp_remote_post( string $url, array $payload ): bool {
		$url = self::sanitize_webhook_url( $url );
		if ( '' === $url ) {
			Alert_Health::record_result( Alert_Health::CHANNEL_WEBHOOK, false, 'Webhook URL missing or invalid' );
			return false;
		}

		$body = wp_json_encode( $payload );
		if ( ! is_string( $body ) || '' === $body ) {
			Alert_Health::record_result( Alert_Health::CHANNEL_WEBHOOK, false, 'Webhook payload encode failed' );
			return false;
		}

		try {
			$response = wp_remote_post(
				$url,
				array(
					'timeout'     => 5,
					'redirection' => 0,
					'blocking'    => true,
					'headers'     => array(
						'Content-Type' => 'application/json; charset=utf-8',
					),
					'body'        => $body,
				)
			);
		} catch ( \Throwable $e ) {
			Alert_Health::record_result( Alert_Health::CHANNEL_WEBHOOK, false, 'Webhook request error' );
			return false;
		}

		if ( is_wp_error( $response ) ) {
			$msg = $response->get_error_message();
			Alert_Health::record_result(
				Alert_Health::CHANNEL_WEBHOOK,
				false,
				'' !== $msg ? $msg : 'Webhook request failed'
			);
			return false;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		$ok   = $code >= 200 && $code < 300;
		Alert_Health::record_result(
			Alert_Health::CHANNEL_WEBHOOK,
			$ok,
			$ok ? '' : sprintf( 'HTTP %d', $code )
		);
		return $ok;
	}

	/**
	 * @param array<string,mixed> $summary From summarize_event().
	 * @return array<string,mixed>
	 */
	public static function build_immediate_webhook_payload( array $summary ): array {
		return array_merge(
			array(
				'source'  => 'handl-aicac',
				'event'   => 'denial',
				'site'     => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
				'site_url' => home_url( '/' ),
			),
			self::summary_fields_for_json( $summary )
		);
	}

	/**
	 * @param list<mixed> $queue Digest rows (already summarized).
	 * @return array<string,mixed>
	 */
	public static function build_digest_webhook_payload( array $queue ): array {
		$denials = array();
		foreach ( $queue as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$denials[] = self::summary_fields_for_json( $row );
			if ( count( $denials ) >= 50 ) {
				break;
			}
		}

		return array(
			'source'   => 'handl-aicac',
			'event'    => 'denial_digest',
			'site'     => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
			'site_url' => home_url( '/' ),
			'count'    => count( $queue ),
			'denials'  => $denials,
		);
	}

	/**
	 * Sample payload for the admin test button (AC5) — clearly labeled as a test.
	 *
	 * @return array<string,mixed>
	 */
	public static function build_test_webhook_payload(): array {
		return array(
			'source'   => 'handl-aicac',
			'event'    => 'test',
			'test'     => true,
			'message'  => 'HandL AICAC test webhook — this is not a real denial.',
			'site'     => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
			'site_url' => home_url( '/' ),
			'ts'       => time(),
		);
	}

	/**
	 * Same field set the email alert includes (no prompt preview, no user identity).
	 *
	 * @param array<string,mixed> $summary
	 * @return array<string,mixed>
	 */
	public static function summary_fields_for_json( array $summary ): array {
		$matched = array();
		if ( isset( $summary['matched_tools'] ) && is_array( $summary['matched_tools'] ) ) {
			$matched = array_values( array_map( 'strval', $summary['matched_tools'] ) );
		}

		return array(
			'ts'                => isset( $summary['ts'] ) ? (int) $summary['ts'] : 0,
			'plugin'            => isset( $summary['plugin'] ) ? (string) $summary['plugin'] : '',
			'operation'         => isset( $summary['operation'] ) ? (string) $summary['operation'] : '',
			'capability_family' => isset( $summary['capability_family'] ) ? (string) $summary['capability_family'] : '',
			'denial_reason'     => isset( $summary['denial_reason'] ) ? (string) $summary['denial_reason'] : '',
			'matched_tools'     => $matched,
			'provider'          => isset( $summary['provider'] ) ? (string) $summary['provider'] : '',
			'model'             => isset( $summary['model'] ) ? (string) $summary['model'] : '',
			'model_inferred'    => ! empty( $summary['model_inferred'] ),
			'uri'               => isset( $summary['uri'] ) ? (string) $summary['uri'] : '',
		);
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
	 * URI/path is path-only (query string never leaves the box via this path).
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
		$is_shadow = ( 'shadow' === ( $event['alert_kind'] ?? '' ) )
			|| ( isset( $event['channel'] ) && 'direct_http' === (string) $event['channel'] );

		$out = array(
			'ts'                => isset( $event['ts'] ) ? (int) $event['ts'] : time(),
			'plugin'            => isset( $event['plugin'] ) && is_string( $event['plugin'] ) ? (string) $event['plugin'] : '',
			'operation'         => isset( $event['operation'] ) ? (string) $event['operation'] : '',
			'capability_family' => isset( $event['capability_family'] ) ? (string) $event['capability_family'] : '',
			'denial_reason'     => isset( $event['denial_reason'] ) ? (string) $event['denial_reason'] : '',
			'matched_tools'     => $matched,
			'provider'          => isset( $event['provider'] ) ? (string) $event['provider'] : '',
			'model'             => isset( $event['model'] ) ? (string) $event['model'] : '',
			'model_inferred'    => ! empty( $event['model_inferred'] ),
			'uri'               => self::uri_path_only( $uri ),
			'alert_kind'        => $is_shadow ? 'shadow' : 'denial',
		);

		if ( $is_shadow ) {
			$out['host']         = isset( $event['host'] ) ? (string) $event['host'] : '';
			$out['caller']       = isset( $event['caller'] ) && is_string( $event['caller'] ) ? (string) $event['caller'] : '';
			$out['file']         = isset( $event['file'] ) && is_string( $event['file'] ) ? (string) $event['file'] : '';
			$out['decision']     = 'observe';
			$out['status_label'] = 'Observed, not blocked';
			if ( '' === $out['provider'] && isset( $event['shadow_provider'] ) ) {
				$out['provider'] = (string) $event['shadow_provider'];
			}
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $summary
	 */
	private static function format_summary_lines( array $summary ): string {
		$ts = ! empty( $summary['ts'] ) ? wp_date( 'Y-m-d H:i:s', (int) $summary['ts'] ) : '—';

		if ( 'shadow' === ( $summary['alert_kind'] ?? '' ) ) {
			$caller = self::best_effort_caller_label( $summary );
			$lines  = array(
				'Status: Observed, not blocked',
				sprintf( 'Time: %s', $ts ),
				sprintf( 'Caller: %s', $caller ),
				sprintf( 'Host: %s', ( $summary['host'] ?? '' ) !== '' ? (string) $summary['host'] : '—' ),
				sprintf( 'Path: %s', ( $summary['uri'] ?? '' ) !== '' ? (string) $summary['uri'] : '—' ),
			);
			$prov = (string) ( $summary['provider'] ?? '' );
			if ( '' !== $prov ) {
				$lines[] = sprintf( 'Provider: %s', $prov );
			}
			return implode( "\n", $lines ) . "\n";
		}

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

	/**
	 * Best-effort caller for shadow alerts: plugin, else file, else method.
	 *
	 * @param array<string,mixed> $summary
	 */
	private static function best_effort_caller_label( array $summary ): string {
		$plugin = isset( $summary['plugin'] ) ? (string) $summary['plugin'] : '';
		if ( '' !== $plugin ) {
			return $plugin;
		}
		$file = isset( $summary['file'] ) ? (string) $summary['file'] : '';
		if ( '' !== $file ) {
			return $file;
		}
		$caller = isset( $summary['caller'] ) ? (string) $summary['caller'] : '';
		if ( '' !== $caller ) {
			return $caller;
		}
		return '(unknown)';
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

	private static function under_test_email_rate_limit(): bool {
		$last = (int) get_option( self::TEST_EMAIL_RATE_OPTION_KEY, 0 );
		if ( $last <= 0 ) {
			return true;
		}
		return ( time() - $last ) >= self::TEST_EMAIL_COOLDOWN_SECONDS;
	}

	private static function record_test_email_send(): void {
		update_option( self::TEST_EMAIL_RATE_OPTION_KEY, time(), false );
	}
}
