<?php
/**
 * Unit tests for AICAC-SHADOW-ALERT opt-in shadow-AI observe emails.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alerts;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-cost.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-weekly-report.php';

final class ShadowAlertsTest extends TestCase {

	/** @var list<array{to:mixed,subject:string,body:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		self::$mails                         = array();
		$GLOBALS['handl_aicac_test_options'] = array();
		unset( $GLOBALS['handl_aicac_wp_supports_ai'] );
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) {
			ShadowAlertsTest::record_mail( $to, (string) $subject, (string) $message );
			return true;
		};
		$this->reset_alerts_deferred_state();
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'], $GLOBALS['handl_aicac_wp_supports_ai'] );
		$this->reset_alerts_deferred_state();
	}

	private function reset_alerts_deferred_state(): void {
		$ref = new \ReflectionClass( Alerts::class );
		foreach ( array( 'deferred_immediate', 'deferred_digest_events' ) as $prop ) {
			$p = $ref->getProperty( $prop );
			$p->setAccessible( true );
			$p->setValue( null, array() );
		}
		$hooked = $ref->getProperty( 'flush_hooked' );
		$hooked->setAccessible( true );
		$hooked->setValue( null, false );
	}

	/**
	 * @param mixed $to
	 */
	public static function record_mail( $to, string $subject, string $body ): void {
		self::$mails[] = array(
			'to'      => $to,
			'subject' => $subject,
			'body'    => $body,
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	private function shadow_event( array $overrides = array() ): array {
		return array_merge(
			array(
				'channel'         => 'direct_http',
				'ts'              => 1700000000,
				'plugin'          => 'shadow-caller/plugin.php',
				'file'            => '/wp-content/plugins/shadow-caller/plugin.php',
				'caller'          => 'Shadow_Caller\\Client::request',
				'host'            => 'api.openai.com',
				'shadow_provider' => 'openai',
				'provider'        => 'openai',
				'decision'        => 'observe',
				'operation'       => 'direct_http',
				'uri'             => '/v1/chat/completions?api_key=secret',
				'count'           => 1,
			),
			$overrides
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	private function shadow_policy( array $overrides = array() ): array {
		return array_merge(
			array(
				'alert_on_shadow' => true,
				'alert_on_deny'   => false,
				'alert_mode'      => 'immediate',
				'alert_email'     => 'admin@example.com',
				'log_enabled'     => true,
				'audit_only'      => false,
			),
			$overrides
		);
	}

	public function test_toggle_off_default_never_sends_shadow_alert(): void {
		$policy = $this->shadow_policy( array( 'alert_on_shadow' => false ) );
		Alerts::maybe_notify_shadow( $this->shadow_event(), $policy );
		Alerts::flush_deferred();

		$this->assertCount( 0, self::$mails );
		$this->assertSame( array(), Alerts::pending_digest_rows() );
	}

	public function test_toggle_on_sends_one_immediate_alert_with_observe_body(): void {
		Alerts::maybe_notify_shadow( $this->shadow_event(), $this->shadow_policy() );
		$this->assertCount( 0, self::$mails, 'must defer until flush (shutdown)' );

		Alerts::flush_deferred();
		$this->assertCount( 1, self::$mails );

		$mail = self::$mails[0];
		$this->assertSame( 'admin@example.com', $mail['to'] );
		$this->assertStringContainsString( 'not blocked', strtolower( $mail['subject'] ) );
		$this->assertStringContainsString( 'observe / not blocked', $mail['body'] );
		$this->assertStringContainsString( 'Time:', $mail['body'] );
		$this->assertStringContainsString( 'Caller: shadow-caller/plugin.php', $mail['body'] );
		$this->assertStringContainsString( 'Host: api.openai.com', $mail['body'] );
		$this->assertStringContainsString( 'Path: /v1/chat/completions', $mail['body'] );
		$this->assertStringNotContainsString( 'api_key=secret', $mail['body'] );
		$this->assertStringNotContainsString( 'blocked an AI Client', $mail['body'] );
	}

	public function test_digest_mode_queues_shadow_row_without_immediate_mail(): void {
		$policy = $this->shadow_policy( array( 'alert_mode' => 'digest' ) );
		Alerts::maybe_notify_shadow( $this->shadow_event(), $policy );
		Alerts::flush_deferred();

		$this->assertCount( 0, self::$mails );
		$rows = Alerts::pending_digest_rows();
		$this->assertCount( 1, $rows );
		$this->assertSame( 'shadow', $rows[0]['alert_kind'] ?? '' );
		$this->assertSame( 'api.openai.com', $rows[0]['host'] ?? '' );
		$this->assertSame( '/v1/chat/completions', $rows[0]['uri'] ?? '' );
		$this->assertSame( 'observe / not blocked', $rows[0]['status_label'] ?? '' );
	}

	public function test_wp_mail_throw_is_contained_and_queues(): void {
		$GLOBALS['handl_aicac_wp_mail'] = static function () {
			throw new \RuntimeException( 'SMTP exploded' );
		};

		Alerts::maybe_notify_shadow( $this->shadow_event(), $this->shadow_policy() );
		Alerts::flush_deferred();

		$this->assertCount( 0, self::$mails );
		$this->assertCount( 1, Alerts::pending_digest_rows() );
	}

	public function test_wp_supports_ai_false_suppresses_alert(): void {
		$GLOBALS['handl_aicac_wp_supports_ai'] = false;
		Alerts::maybe_notify_shadow( $this->shadow_event(), $this->shadow_policy() );
		Alerts::flush_deferred();
		$this->assertCount( 0, self::$mails );
	}

	public function test_append_first_pair_alerts_collapse_and_retained_pair_do_not(): void {
		$GLOBALS['handl_aicac_test_options'][ Plugin::OPTION_KEY ] = array(
			'log_enabled'     => true,
			'alert_on_shadow' => true,
			'alert_mode'      => 'immediate',
			'alert_email'     => 'admin@example.com',
		);

		$event = $this->shadow_event( array( 'ts' => 1000 ) );
		Policy::append_log_event( $event );
		Alerts::flush_deferred();
		$this->assertCount( 1, self::$mails, 'first pair in window should alert' );

		// Same pair inside collapse window — tallied into existing row, no alert.
		self::$mails = array();
		$this->reset_alerts_deferred_state();
		Policy::append_log_event(
			$this->shadow_event(
				array(
					'ts'  => 1100,
					'uri' => '/v1/other?token=x',
				)
			)
		);
		Alerts::flush_deferred();
		$this->assertCount( 0, self::$mails, 'chatty collapse must not re-alert' );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertCount( 1, $log );
		$this->assertSame( 2, (int) ( $log[0]['count'] ?? 0 ) );

		// Outside collapse window (idle from last activity ts=1100) but pair still
		// retained → new row, still no alert.
		self::$mails = array();
		$this->reset_alerts_deferred_state();
		Policy::append_log_event(
			$this->shadow_event(
				array(
					'ts' => 1100 + 301,
				)
			)
		);
		Alerts::flush_deferred();
		$this->assertCount( 0, self::$mails, 'retained-window pair must not re-alert (mid-cluster / idle reopen)' );
		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertCount( 2, $log, 'idle timeout starts a new row but alert stays suppressed' );
	}

	public function test_append_does_not_alert_when_toggle_off(): void {
		$GLOBALS['handl_aicac_test_options'][ Plugin::OPTION_KEY ] = array(
			'log_enabled'     => true,
			'alert_on_shadow' => false,
			'alert_mode'      => 'immediate',
			'alert_email'     => 'admin@example.com',
		);

		Policy::append_log_event( $this->shadow_event() );
		Alerts::flush_deferred();
		$this->assertCount( 0, self::$mails );
	}

	public function test_summarize_strips_query_and_labels_observe(): void {
		$summary = Alerts::summarize_event_public( $this->shadow_event() );
		$this->assertSame( 'shadow', $summary['alert_kind'] );
		$this->assertSame( '/v1/chat/completions', $summary['uri'] );
		$this->assertSame( 'observe / not blocked', $summary['status_label'] );
		$this->assertSame( 'api.openai.com', $summary['host'] );
	}

	public function test_log_has_direct_http_pair_matches_plugin_host(): void {
		$log = array(
			$this->shadow_event(),
		);
		$this->assertTrue( Policy::log_has_direct_http_pair( $log, $this->shadow_event() ) );
		$this->assertFalse(
			Policy::log_has_direct_http_pair(
				$log,
				$this->shadow_event( array( 'host' => 'api.anthropic.com' ) )
			)
		);
	}
}
