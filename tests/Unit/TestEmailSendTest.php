<?php
/**
 * Unit tests for AICAC-25 admin test-send email (denial alert + weekly report).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alerts;
use PHPUnit\Framework\TestCase;

final class TestEmailSendTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	/** @var bool */
	private static $mail_ok = true;

	protected function setUp(): void {
		self::$mails   = array();
		self::$mail_ok = true;
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_wp_mail']      = static function ( $to, $subject, $message ) {
			TestEmailSendTest::record_mail( (string) $to, (string) $subject, (string) $message );
			return TestEmailSendTest::mail_ok();
		};
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'] );
	}

	public static function record_mail( string $to, string $subject, string $message ): void {
		self::$mails[] = array(
			'to'      => $to,
			'subject' => $subject,
			'message' => $message,
		);
	}

	public static function mail_ok(): bool {
		return self::$mail_ok;
	}

	public function test_send_test_email_uses_configured_recipient_not_free_text(): void {
		$result = Alerts::send_test_email(
			array( 'alert_email' => 'alerts@example.com' ),
			'denial_alert'
		);

		$this->assertTrue( $result['ok'] );
		$this->assertSame( 'sent', $result['status'] );
		$this->assertSame( 'alerts@example.com', $result['to'] );
		$this->assertCount( 1, self::$mails );
		$this->assertSame( 'alerts@example.com', self::$mails[0]['to'] );
	}

	public function test_send_test_email_falls_back_to_admin_email(): void {
		$result = Alerts::send_test_email( array( 'alert_email' => '' ), 'denial_alert' );

		$this->assertTrue( $result['ok'] );
		$this->assertSame( 'admin@example.com', $result['to'] );
		$this->assertSame( 'admin@example.com', self::$mails[0]['to'] );
	}

	public function test_send_test_email_failure_does_not_claim_delivery(): void {
		self::$mail_ok = false;
		$result        = Alerts::send_test_email(
			array( 'alert_email' => 'alerts@example.com' ),
			'denial_alert'
		);

		$this->assertFalse( $result['ok'] );
		$this->assertSame( 'failed', $result['status'] );
		$this->assertSame( 'alerts@example.com', $result['to'] );
		$this->assertCount( 1, self::$mails );
	}

	public function test_test_message_is_labeled_and_has_no_sensitive_fields(): void {
		Alerts::send_test_email( array( 'alert_email' => 'a@example.com' ), 'denial_alert' );
		$subject = self::$mails[0]['subject'];
		$body    = self::$mails[0]['message'];

		$this->assertStringContainsString( 'Test: HandL AICAC denial alert', $subject );
		$this->assertStringContainsString( 'denial alert', strtolower( $subject ) );
		$this->assertStringContainsString( 'TEST MESSAGE: HandL AI Connector Access Control', $body );
		$this->assertStringContainsString( 'This is a test. No denial occurred.', $body );
		$this->assertStringContainsString( 'inbox delivery is not guaranteed', strtolower( $body ) );

		// Must not embed per-call / identity fields (disclaimer may mention "prompt text").
		foreach ( array( 'prompt_preview', 'user_id=', 'user_login', 'display_name', 'capability_family' ) as $needle ) {
			$this->assertStringNotContainsString( $needle, strtolower( $body ) );
		}
	}

	public function test_weekly_report_test_email_is_distinctly_labeled(): void {
		$result = Alerts::send_test_email( array( 'alert_email' => 'a@example.com' ), 'weekly_report' );

		$this->assertTrue( $result['ok'] );
		$this->assertStringContainsString( 'Test: HandL AICAC weekly report', self::$mails[0]['subject'] );
		$this->assertStringContainsString( 'weekly report', strtolower( self::$mails[0]['subject'] ) );
		$this->assertStringContainsString( 'This is a test. This is not a real weekly report.', self::$mails[0]['message'] );
		$this->assertStringContainsString( 'weekly report email delivery', strtolower( self::$mails[0]['message'] ) );
	}

	public function test_rate_limit_blocks_rapid_repeat_clicks(): void {
		$first = Alerts::send_test_email( array( 'alert_email' => 'a@example.com' ), 'denial_alert' );
		$this->assertTrue( $first['ok'] );
		$this->assertCount( 1, self::$mails );

		$second = Alerts::send_test_email( array( 'alert_email' => 'a@example.com' ), 'weekly_report' );
		$this->assertFalse( $second['ok'] );
		$this->assertSame( 'rate_limited', $second['status'] );
		$this->assertCount( 1, self::$mails, 'Rate-limited click must not call wp_mail' );
	}

	public function test_invalid_channel_rejected(): void {
		$result = Alerts::send_test_email( array( 'alert_email' => 'a@example.com' ), 'not_a_channel' );
		$this->assertFalse( $result['ok'] );
		$this->assertSame( 'invalid_channel', $result['status'] );
		$this->assertCount( 0, self::$mails );
	}

	public function test_build_helpers_contain_no_per_call_data(): void {
		$subject = Alerts::build_test_email_subject( 'denial_alert' );
		$body    = Alerts::build_test_email_body( 'weekly_report' );

		$this->assertStringContainsString( 'Test: HandL AICAC denial alert', $subject );
		$this->assertStringNotContainsString( 'URI:', $body );
		$this->assertStringNotContainsString( 'Plugin:', $body );
		$this->assertStringNotContainsString( 'prompt_preview', strtolower( $body ) );
		$this->assertStringNotContainsString( 'user_login', strtolower( $body ) );
		$this->assertStringNotContainsString( 'wp_mail can deliver', strtolower( $body ) );
	}

	public function test_admin_ui_has_test_email_buttons_and_detached_forms(): void {
		$source = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringContainsString( 'id="handl-aicac-test-email-denial"', $source );
		$this->assertStringContainsString( 'id="handl-aicac-test-email-weekly"', $source );
		$this->assertStringContainsString( "value=\"send_test_email\"", $source );
		$this->assertStringContainsString( 'handl-aicac-send-test-denial-email', $source );
		$this->assertStringContainsString( 'handl-aicac-send-test-weekly-email', $source );
		$this->assertStringContainsString( "handl_aicac_send_test_email", $source );
		// Detached test forms must not include a free-text recipient input (relay abuse).
		foreach ( array( 'handl-aicac-test-email-denial', 'handl-aicac-test-email-weekly' ) as $form_id ) {
			if ( ! preg_match(
				'/id="' . preg_quote( $form_id, '/' ) . '"[^>]*>(.*?)<\/form>/s',
				$source,
				$form_match
			) ) {
				$this->fail( "Form {$form_id} not found" );
			}
			$this->assertStringNotContainsString( 'type="email"', $form_match[1] );
			$this->assertStringNotContainsString( 'name="handl_aicac_alert_email"', $form_match[1] );
			$this->assertStringNotContainsString( 'name="to"', $form_match[1] );
		}
	}
}
