<?php
/**
 * AICAC-REQUEST-CHAT (#321).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Access_Request;
use HandL\AICAC\Alert_Health;
use HandL\AICAC\Chat_Notify;
use HandL\AICAC\Plugin;
use HandL\AICAC\Request_Chat;
use HandL\AICAC\Webhook_Delivery_Log;
use PHPUnit\Framework\TestCase;

final class RequestChatTest extends TestCase {

	/** @var list<array{url:string,args:array<string,mixed>}> */
	public static array $posts = array();

	/** @var mixed */
	public static $next_response = null;

	/** @var int */
	public static int $mail_calls = 0;

	protected function setUp(): void {
		parent::setUp();
		self::$posts         = array();
		self::$mail_calls    = 0;
		self::$next_response = array(
			'response' => array( 'code' => 200 ),
			'body'     => 'ok',
		);
		Request_Chat::reset_for_tests();
		Chat_Notify::reset_for_tests();
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_filters'] = array(
			'handl_aicac_webhook_retry_backoff_ms'       => static function () {
				return 0;
			},
			'handl_aicac_webhook_failure_email_cooldown' => static function () {
				return 0;
			},
		);
		$GLOBALS['handl_aicac_test_user_id']    = 12;
		$GLOBALS['handl_aicac_test_user_login'] = 'editor';
		$GLOBALS['handl_aicac_test_users']      = array(
			12 => array(
				'ID'         => 12,
				'user_login' => 'editor',
			),
		);
		$GLOBALS['handl_aicac_wp_remote_post'] = static function ( string $url, array $args ) {
			RequestChatTest::$posts[] = array(
				'url'  => $url,
				'args' => $args,
			);
			return RequestChatTest::$next_response;
		};
		$GLOBALS['handl_aicac_wp_mail'] = static function () {
			++RequestChatTest::$mail_calls;
			return true;
		};
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php';
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'deny',
				'log_enabled' => true,
				'plugins'     => array(
					'blocked/plugin.php' => 'deny',
				),
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
		delete_option( Access_Request::OPTION_KEY );
		delete_option( Chat_Notify::OPTION_KEY );
		delete_option( Request_Chat::OPTION_KEY );
		delete_option( Request_Chat::SENT_OPTION_KEY );
		delete_option( Webhook_Delivery_Log::OPTION_KEY );
		delete_option( Alert_Health::OPTION_KEY );
	}

	protected function tearDown(): void {
		Request_Chat::reset_for_tests();
		Chat_Notify::reset_for_tests();
		unset(
			$GLOBALS['handl_aicac_wp_remote_post'],
			$GLOBALS['handl_aicac_wp_mail'],
			$GLOBALS['handl_aicac_test_filters'],
			$GLOBALS['handl_aicac_test_user_login'],
			$GLOBALS['handl_aicac_test_users']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_user_id'] = 0;
		parent::tearDown();
	}

	private function enable_chat_webhooks(): void {
		Chat_Notify::save_config(
			array(
				'slack_url' => 'https://hooks.slack.com/services/T00/B00/XXX',
				'teams_url' => 'https://outlook.office.com/webhook/aaa/IncomingWebhook/bbb/ccc',
			)
		);
		Request_Chat::save_config( array( 'enabled' => true ) );
	}

	public function test_off_by_default_no_posts_on_new_request(): void {
		Chat_Notify::save_config(
			array(
				'slack_url' => 'https://hooks.slack.com/services/T00/B00/XXX',
				'teams_url' => 'https://outlook.office.com/webhook/aaa/IncomingWebhook/bbb/ccc',
			)
		);
		$result = Access_Request::submit_request( 'blocked/plugin.php', 12, 'Need GPT', 1000 );
		$this->assertTrue( $result['ok'] );
		$this->assertSame( 0, count( self::$posts ) );
		$this->assertGreaterThanOrEqual( 1, self::$mail_calls );
	}

	public function test_new_request_posts_one_slack_and_one_teams_with_review_link(): void {
		$this->enable_chat_webhooks();
		$result = Access_Request::submit_request( 'blocked/plugin.php', 12, 'Need GPT', 2000 );
		$this->assertTrue( $result['ok'] );
		$this->assertSame( 2, count( self::$posts ) );

		$bodies = array();
		foreach ( self::$posts as $post ) {
			$bodies[] = (string) ( $post['args']['body'] ?? '' );
		}
		$joined = implode( "\n", $bodies );
		$plain  = stripslashes( $joined );
		$this->assertStringContainsString( 'AI access request', $plain );
		$this->assertStringContainsString( 'blocked/plugin.php', $plain );
		$this->assertStringContainsString( 'Need GPT', $plain );
		$this->assertStringContainsString( 'handl-aicac-protections', $plain );
		$this->assertStringContainsString( 'Review request', $plain );
		$this->assertStringContainsString( 'Not recorded', $plain ); // provider
		$this->assertGreaterThanOrEqual( 1, self::$mail_calls );
	}

	public function test_duplicate_same_request_id_no_second_card(): void {
		$this->enable_chat_webhooks();
		$first = Access_Request::submit_request( 'blocked/plugin.php', 12, 'One', 3000 );
		$this->assertTrue( $first['ok'] );
		$this->assertSame( 2, count( self::$posts ) );

		// Collapse within 24h — same id, no new cards.
		$second = Access_Request::submit_request( 'blocked/plugin.php', 12, 'Two', 3100 );
		$this->assertTrue( $second['ok'] );
		$this->assertSame( $first['id'], $second['id'] );
		$this->assertSame( 2, count( self::$posts ) );

		// Direct re-deliver of created also dedupes.
		$row = get_option( Access_Request::OPTION_KEY, array() )[ $first['id'] ];
		$out = Request_Chat::deliver_for_row( $row, 'created', 3200 );
		$this->assertSame( 'deduped', $out['skipped'] );
		$this->assertSame( 2, count( self::$posts ) );
	}

	public function test_chat_404_increments_health_request_still_created(): void {
		$this->enable_chat_webhooks();
		self::$next_response = array(
			'response' => array( 'code' => 404 ),
			'body'     => 'missing',
		);
		$result = Access_Request::submit_request( 'blocked/plugin.php', 12, 'Still queue', 4000 );
		$this->assertTrue( $result['ok'] );
		$this->assertNotSame( '', $result['id'] );

		$map = get_option( Access_Request::OPTION_KEY, array() );
		$this->assertArrayHasKey( $result['id'], $map );
		$this->assertSame( Access_Request::STATUS_PENDING, $map[ $result['id'] ]['status'] );

		$health = Alert_Health::get_state();
		$this->assertFalse( empty( $health ) );
		$this->assertGreaterThanOrEqual( 1, self::$mail_calls );
	}

	public function test_disabled_save_byte_identical_delete(): void {
		Request_Chat::save_config( array( 'enabled' => true ) );
		$this->assertNotFalse( get_option( Request_Chat::OPTION_KEY, false ) );
		Request_Chat::save_config( array( 'enabled' => false ) );
		$this->assertFalse( get_option( Request_Chat::OPTION_KEY, false ) );
	}

	public function test_reminder_after_window_once(): void {
		$this->enable_chat_webhooks();
		$result = Access_Request::submit_request( 'blocked/plugin.php', 12, 'Remind me', 5000 );
		$this->assertSame( 2, count( self::$posts ) );

		$row = get_option( Access_Request::OPTION_KEY, array() )[ $result['id'] ];
		// Too early.
		$this->assertSame( 0, Request_Chat::remind_pending( 5000 + 100 ) );
		$this->assertSame( 2, count( self::$posts ) );

		// After 24h window from emailed_ts.
		$n = Request_Chat::remind_pending( 5000 + DAY_IN_SECONDS + 1 );
		$this->assertSame( 1, $n );
		$this->assertSame( 4, count( self::$posts ) );
		$last = (string) ( self::$posts[3]['args']['body'] ?? '' );
		$this->assertStringContainsString( 'still pending', $last );

		// Second remind deduped.
		$this->assertSame( 0, Request_Chat::remind_pending( 5000 + DAY_IN_SECONDS + 100 ) );
		$this->assertSame( 4, count( self::$posts ) );
	}

	public function test_status_lists_toggle(): void {
		$st = Request_Chat::status();
		$this->assertFalse( $st['enabled'] );
		Request_Chat::save_config( array( 'enabled' => true ) );
		Chat_Notify::save_config(
			array(
				'slack_url' => 'https://hooks.slack.com/services/T00/B00/XXX',
			)
		);
		$st = Request_Chat::status();
		$this->assertTrue( $st['enabled'] );
		$this->assertTrue( $st['slack_configured'] );
		$this->assertFalse( $st['teams_configured'] );
		$this->assertStringContainsString( '…', $st['slack_url_masked'] );
	}

	public function test_slack_payload_shape(): void {
		$payload = Request_Chat::build_slack_blocks(
			Request_Chat::row_to_event(
				array(
					'id'         => str_repeat( 'a', 32 ),
					'plugin'     => 'acme/acme.php',
					'reason'     => 'scope text',
					'user_login' => 'editor',
					'status'     => 'pending',
				),
				'created'
			),
			'created'
		);
		$this->assertSame( 'handl_aicac_chat_slack', $payload['type'] );
		$this->assertStringContainsString( 'handl-aicac-protections', $payload['blocks'][2]['elements'][0]['url'] );
		$this->assertSame( 'Review request', $payload['blocks'][2]['elements'][0]['text']['text'] );
	}
}
