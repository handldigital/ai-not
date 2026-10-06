<?php
/**
 * AICAC-CHAT-REPORTS (#306).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Health;
use HandL\AICAC\Chat_Notify;
use HandL\AICAC\Monthly_Report;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Webhook_Delivery_Log;
use HandL\AICAC\Weekly_Report;
use PHPUnit\Framework\TestCase;

final class ChatReportsTest extends TestCase {

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
		$GLOBALS['handl_aicac_wp_remote_post'] = static function ( string $url, array $args ) {
			ChatReportsTest::$posts[] = array(
				'url'  => $url,
				'args' => $args,
			);
			return ChatReportsTest::$next_response;
		};
		$GLOBALS['handl_aicac_wp_mail'] = static function () {
			++ChatReportsTest::$mail_calls;
			return true;
		};
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Chat_Notify::OPTION_KEY );
		delete_option( Webhook_Delivery_Log::OPTION_KEY );
		delete_option( Alert_Health::OPTION_KEY );
		delete_option( Monthly_Report::SENT_OPTION_KEY );
		update_option( 'admin_email', 'admin@example.com' );
	}

	protected function tearDown(): void {
		Chat_Notify::reset_for_tests();
		unset( $GLOBALS['handl_aicac_wp_remote_post'], $GLOBALS['handl_aicac_wp_mail'], $GLOBALS['handl_aicac_test_filters'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Chat_Notify::OPTION_KEY );
		delete_option( Webhook_Delivery_Log::OPTION_KEY );
		delete_option( Alert_Health::OPTION_KEY );
		delete_option( Monthly_Report::SENT_OPTION_KEY );
		parent::tearDown();
	}

	public function test_weekly_report_posts_slack_block_kit_and_teams_message_card(): void {
		Chat_Notify::save_config(
			array(
				'slack_url'     => 'https://hooks.slack.com/services/T00/B00/xxx',
				'teams_url'     => 'https://outlook.office.com/webhook/aaa',
				'report_weekly' => true,
			)
		);
		$this->seed_weekly_policy_and_log();
		Weekly_Report::instance()->send_report();

		$this->assertSame( 1, self::$mail_calls );
		$this->assertCount( 2, self::$posts );
		$slack = json_decode( (string) self::$posts[0]['args']['body'], true );
		$teams = json_decode( (string) self::$posts[1]['args']['body'], true );
		$this->assertIsArray( $slack );
		$this->assertIsArray( $teams );
		$this->assertArrayHasKey( 'blocks', $slack );
		$this->assertSame( 'handl_aicac_chat_slack', $slack['type'] );
		$this->assertStringContainsString( 'page=handl-aicac', (string) wp_json_encode( $slack ) );
		$this->assertSame( 'MessageCard', $teams['@type'] );
		$this->assertStringContainsString( 'page=handl-aicac', (string) wp_json_encode( $teams ) );
		$this->assertStringNotContainsString( '<table', (string) wp_json_encode( $slack ) );
		$this->assertStringNotContainsString( '<table', (string) wp_json_encode( $teams ) );
	}

	public function test_chat_404_increments_webhook_health_and_email_still_delivers(): void {
		Chat_Notify::save_config(
			array(
				'slack_url'      => 'https://hooks.slack.com/services/T00/B00/bad',
				'report_monthly' => true,
			)
		);
		self::$next_response = array(
			'response' => array( 'code' => 404 ),
			'body'     => 'nope',
		);
		$now = strtotime( '2026-08-01 12:00:00 UTC' );
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'            => strtotime( '2026-07-15 10:00:00 UTC' ),
					'plugin'        => 'a/a.php',
					'decision'      => 'allow',
					'provider'      => 'openai',
					'input_tokens'  => 0,
					'output_tokens' => 200000,
				),
			),
			false
		);
		$policy = $this->persist_policy(
			array(
				'monthly_report_enabled' => true,
				'log_enabled'            => true,
				'alert_email'            => 'ops@example.com',
			)
		);
		$out = Monthly_Report::send_if_due( $policy, array( 'a/a.php' => array( 'Name' => 'A' ) ), $now );
		$this->assertTrue( $out['sent'] );
		$this->assertSame( 1, self::$mail_calls );
		$this->assertCount( 1, self::$posts );
		$health = Alert_Health::get_state();
		$this->assertGreaterThan( 0, $health[ Alert_Health::CHANNEL_WEBHOOK ]['consecutive_failures'] );
		$this->assertSame( 0, $health[ Alert_Health::CHANNEL_EMAIL ]['consecutive_failures'] );
	}

	public function test_chat_disabled_zero_posts_and_untouched_policy_save_is_byte_identical(): void {
		$stored = array(
			'slack_url'    => 'https://hooks.slack.com/services/T00/B00/xxx',
			'teams_url'    => '',
			'min_severity' => 0,
		);
		update_option( Chat_Notify::OPTION_KEY, $stored, false );
		$this->seed_weekly_policy_and_log();
		Weekly_Report::instance()->send_report();
		$this->assertSame( 1, self::$mail_calls );
		$this->assertCount( 0, self::$posts );

		Policy::save_policy(
			array(
				'default'     => 'observe',
				'log_enabled' => true,
			)
		);
		$this->assertSame( $stored, get_option( Chat_Notify::OPTION_KEY ) );
	}

	public function test_cli_status_masks_webhook_secrets_and_shows_report_toggles(): void {
		$secret = 'https://hooks.slack.com/services/T000/B000/abcdefghijklmnopqrstuv';
		Chat_Notify::save_config(
			array(
				'slack_url'     => $secret,
				'report_weekly' => true,
			)
		);
		$st = Chat_Notify::status();
		$this->assertTrue( $st['report_weekly'] );
		$this->assertFalse( $st['report_monthly'] );
		$this->assertFalse( $st['report_digest'] );
		$this->assertStringContainsString( 'hooks.slack.com', $st['slack_url_masked'] );
		$this->assertStringContainsString( '****', $st['slack_url_masked'] );
		$this->assertStringNotContainsString( 'abcdefghijklmnopqrstuv', $st['slack_url_masked'] );
	}

	private function seed_weekly_policy_and_log(): void {
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'            => 1_700_000_000,
					'plugin'        => 'a/a.php',
					'decision'      => 'deny',
					'provider'      => 'openai',
					'input_tokens'  => 100,
					'output_tokens' => 50,
				),
			),
			false
		);
		$this->persist_policy(
			array(
				'weekly_report_enabled' => true,
				'log_enabled'           => true,
				'alert_email'           => 'ops@example.com',
			)
		);
	}

	/**
	 * @param array<string,mixed> $extra
	 * @return array<string,mixed>
	 */
	private function persist_policy( array $extra ): array {
		$policy = array_merge(
			array(
				'log_enabled'            => true,
				'audit_only'             => false,
				'alert_email'            => 'ops@example.com',
				'est_usd_input_per_m'    => 2.50,
				'est_usd_output_per_m'   => 10.00,
				'est_usd_provider_rates' => array(),
				'log_limit'              => 200,
			),
			$extra
		);
		update_option( Plugin::OPTION_KEY, $policy, false );

		return Policy::get_policy();
	}
}
