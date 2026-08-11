<?php
/**
 * AICAC-ALERT-HEALTH: delivery success/failure recording.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Health;
use HandL\AICAC\Alerts;
use HandL\AICAC\Plugin;
use HandL\AICAC\Site_Health;
use PHPUnit\Framework\TestCase;

final class AlertHealthTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		delete_option( Alert_Health::OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Alerts::TEST_EMAIL_RATE_OPTION_KEY );
		update_option( 'admin_email', 'admin@example.com' );

		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);
			return ! empty( $GLOBALS['handl_aicac_wp_mail_ok'] );
		};
		$GLOBALS['handl_aicac_wp_mail_ok'] = true;
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'], $GLOBALS['handl_aicac_wp_mail_ok'], $GLOBALS['handl_aicac_wp_remote_post'] );
		delete_option( Alert_Health::OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Alerts::TEST_EMAIL_RATE_OPTION_KEY );
		parent::tearDown();
	}

	public function test_records_email_failure_and_increments_consecutive(): void {
		$GLOBALS['handl_aicac_wp_mail_ok'] = false;
		Alerts::safe_wp_mail( 'ops@example.com', 'subj', 'body' );
		Alerts::safe_wp_mail( 'ops@example.com', 'subj', 'body' );

		$state = Alert_Health::get_state();
		$this->assertSame( 2, $state['email']['consecutive_failures'] );
		$this->assertNotNull( $state['email']['last_failure_at'] );
		$this->assertStringContainsString( 'wp_mail', $state['email']['last_failure_reason'] );
		$this->assertNull( $state['email']['last_success_at'] );
	}

	public function test_success_clears_consecutive_failures(): void {
		Alert_Health::record_failure( 'email', 'wp_mail returned false' );
		Alert_Health::record_failure( 'email', 'wp_mail returned false' );
		Alert_Health::record_failure( 'email', 'wp_mail returned false' );

		$GLOBALS['handl_aicac_wp_mail_ok'] = true;
		Alerts::safe_wp_mail( 'ops@example.com', 'subj', 'body' );

		$state = Alert_Health::get_state();
		$this->assertSame( 0, $state['email']['consecutive_failures'] );
		$this->assertNotNull( $state['email']['last_success_at'] );
	}

	public function test_webhook_records_http_failure_reason(): void {
		$GLOBALS['handl_aicac_wp_remote_post'] = static function () {
			return array(
				'response' => array( 'code' => 500 ),
				'body'     => 'nope',
			);
		};

		$ok = Alerts::safe_wp_remote_post( 'https://example.com/hook', array( 'ping' => 1 ) );
		$this->assertFalse( $ok );

		$state = Alert_Health::get_state();
		$this->assertSame( 1, $state['webhook']['consecutive_failures'] );
		$this->assertSame( 'HTTP 500', $state['webhook']['last_failure_reason'] );
	}

	public function test_site_health_critical_after_three_failures(): void {
		$policy = array(
			'kill_switch'     => false,
			'log_enabled'     => true,
			'audit_only'      => false,
			'alert_on_deny'   => true,
			'alert_email'     => 'ops@example.com',
			'alert_webhook_url' => '',
		);
		update_option( Plugin::OPTION_KEY, $policy, false );

		Alert_Health::record_failure( 'email', 'wp_mail returned false' );
		Alert_Health::record_failure( 'email', 'wp_mail returned false' );
		$this->assertSame( array(), Alert_Health::failing_channels( $policy ) );

		Alert_Health::record_failure( 'email', 'wp_mail returned false' );
		$this->assertSame( array( 'email' ), Alert_Health::failing_channels( $policy ) );

		$snapshot = Site_Health::build_snapshot(
			$policy,
			array(
				'ai/ai.php' => array( 'Name' => 'AI' ),
			),
			array( 'ai/ai.php' => true )
		);
		$this->assertSame( 'critical', $snapshot['status'] );
		$this->assertSame( 'alert_delivery_failing', $snapshot['issue'] );
		$this->assertSame( array( 'email' ), $snapshot['failing_alert_channels'] );
	}

	public function test_unconfigured_channel_not_flagged(): void {
		$policy = array(
			'kill_switch'   => false,
			'log_enabled'   => true,
			'alert_on_deny' => false,
			'alert_email'   => '',
		);
		Alert_Health::record_failure( 'email', 'wp_mail returned false' );
		Alert_Health::record_failure( 'email', 'wp_mail returned false' );
		Alert_Health::record_failure( 'email', 'wp_mail returned false' );

		$this->assertSame( array(), Alert_Health::failing_channels( $policy ) );
	}

	public function test_test_email_records_health(): void {
		$GLOBALS['handl_aicac_wp_mail_ok'] = true;
		$result = Alerts::send_test_email( array( 'alert_email' => 'ops@example.com' ), 'denial_alert' );
		$this->assertTrue( $result['ok'] );

		$state = Alert_Health::get_state();
		$this->assertSame( 0, $state['email']['consecutive_failures'] );
		$this->assertNotNull( $state['email']['last_success_at'] );
	}

	public function test_status_line_includes_last_delivered_and_failure(): void {
		$row = array(
			'last_success_at'      => strtotime( '2026-08-11 12:00:00 UTC' ),
			'last_failure_at'      => strtotime( '2026-08-11 11:00:00 UTC' ),
			'last_failure_reason'  => 'HTTP 500',
			'consecutive_failures' => 0,
		);
		$line = Alert_Health::format_status_line( 'webhook', $row );
		$this->assertStringContainsString( 'Webhook', $line );
		$this->assertStringContainsString( 'Last successful send:', $line );
		$this->assertStringContainsString( 'Last failed send:', $line );
		$this->assertStringContainsString( 'HTTP 500', $line );
		$this->assertStringNotContainsString( ' — ', $line );
	}
}
