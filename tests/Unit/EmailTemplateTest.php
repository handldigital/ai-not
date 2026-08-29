<?php
/**
 * AICAC-EMAIL-BRAND (#154): shared email chrome.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alerts;
use HandL\AICAC\Email_Template;
use HandL\AICAC\Plugin;
use HandL\AICAC\Spend_Threshold;
use PHPUnit\Framework\TestCase;

final class EmailTemplateTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string,headers:mixed}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		delete_option( Plugin::OPTION_KEY );
		update_option( 'admin_email', 'admin@example.com' );
		update_option( 'blogname', 'Sandbox Site' );
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message, $headers = '', $attachments = array() ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
				'headers' => $headers,
			);
			unset( $attachments );
			return true;
		};
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		delete_option( Plugin::OPTION_KEY );
		parent::tearDown();
	}

	public function test_compose_preserves_content_block_bytes(): void {
		$content = Spend_Threshold::build_body( 'site', null, 10.0, 12.5, '1 Jan – 2 Jan' );
		$parts   = Email_Template::compose( $content );
		$this->assertSame( $content, Email_Template::extract_content( $parts['text'] ) );
		$this->assertStringContainsString( Email_Template::product_name(), $parts['text'] );
		$this->assertStringContainsString( 'Site:', $parts['text'] );
		$this->assertStringContainsString( Email_Template::site_name(), $parts['text'] );
		$this->assertStringContainsString( Email_Template::default_intro(), $parts['text'] );
		$this->assertStringContainsString( 'admin.php?page=handl-aicac', $parts['text'] );
		$this->assertStringNotContainsString( 'admin@example.com', $parts['text'] );
		$this->assertStringNotContainsString( 'admin@example.com', $parts['html'] );
		$this->assertStringContainsString( '<html', $parts['html'] );
		$this->assertStringContainsString( 'Alert threshold:', $parts['html'] );
	}

	public function test_safe_wp_mail_sends_multipart_and_keeps_content(): void {
		$content = "Line one\nLine two\n";
		Alerts::safe_wp_mail( 'admin@example.com', 'Subject', $content );
		$this->assertCount( 1, self::$mails );
		$msg = self::$mails[0]['message'];
		$this->assertStringContainsString( 'Content-Type: text/plain', $msg );
		$this->assertStringContainsString( 'Content-Type: text/html', $msg );
		$this->assertStringContainsString( $content, $msg );
		$this->assertSame( $content, Email_Template::extract_content( $msg ) );
		$headers = self::$mails[0]['headers'];
		$header_blob = is_array( $headers ) ? implode( "\n", $headers ) : (string) $headers;
		$this->assertStringContainsString( 'multipart/alternative', $header_blob );
		$this->assertStringNotContainsString( 'admin@example.com', Email_Template::extract_content( $msg ) );
	}

	public function test_double_wrap_is_skipped(): void {
		$parts = Email_Template::compose( "Hello\n" );
		Alerts::safe_wp_mail( 'admin@example.com', 'S', $parts['text'] );
		$this->assertCount( 1, self::$mails );
		// Already wrapped text is sent as-is (no second CONTENT_START pair nesting).
		$this->assertSame( 1, substr_count( self::$mails[0]['message'], Email_Template::CONTENT_START ) );
	}
}
