<?php
/**
 * AICAC-CHAT-NOTIFY (#298).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Health;
use HandL\AICAC\Alerts;
use HandL\AICAC\Chat_Notify;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Webhook_Delivery_Log;
use PHPUnit\Framework\TestCase;

final class ChatNotifyTest extends TestCase {

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
			ChatNotifyTest::$posts[] = array(
				'url'  => $url,
				'args' => $args,
			);
			return ChatNotifyTest::$next_response;
		};
		$GLOBALS['handl_aicac_wp_mail'] = static function () {
			++ChatNotifyTest::$mail_calls;
			return true;
		};
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Chat_Notify::OPTION_KEY );
		delete_option( Webhook_Delivery_Log::OPTION_KEY );
		delete_option( Alert_Health::OPTION_KEY );
	}

	protected function tearDown(): void {
		Chat_Notify::reset_for_tests();
		unset( $GLOBALS['handl_aicac_wp_remote_post'], $GLOBALS['handl_aicac_wp_mail'], $GLOBALS['handl_aicac_test_filters'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Chat_Notify::OPTION_KEY );
		delete_option( Webhook_Delivery_Log::OPTION_KEY );
		delete_option( Alert_Health::OPTION_KEY );
		parent::tearDown();
	}

	public function test_classify_deny_storm_from_retry_flag(): void {
		$this->assertSame(
			Chat_Notify::CLASS_DENY_STORM,
			Chat_Notify::classify(
				array(
					'retry_storm' => true,
					'plugin'      => 'acme/acme.php',
					'decision'    => 'deny',
				)
			)
		);
	}

	public function test_slack_block_kit_includes_fields_and_activity_link(): void {
		$payload = Chat_Notify::build_slack_blocks(
			array(
				'plugin'   => 'acme/acme.php',
				'provider' => 'openai',
				'count'    => 12,
			),
			Chat_Notify::CLASS_DENY_STORM
		);
		$this->assertSame( 'handl_aicac_chat_slack', $payload['type'] );
		$this->assertIsArray( $payload['blocks'] );
		$json = (string) wp_json_encode( $payload );
		$this->assertStringContainsString( '"blocks"', $json );
		$this->assertStringContainsString( 'Repeated blocked requests', $json );
		$this->assertStringContainsString( "*Plugin*\nacme/acme.php", $payload['blocks'][1]['fields'][1]['text'] );
		$this->assertStringContainsString( "*Provider*\nopenai", $payload['blocks'][1]['fields'][2]['text'] );
		$this->assertStringContainsString( "*Count*\n12", $payload['blocks'][1]['fields'][3]['text'] );
		$this->assertStringContainsString( 'handl-aicac-activity', $payload['blocks'][2]['elements'][0]['url'] );
		$this->assertStringContainsString( 'Open Activity', $payload['blocks'][2]['elements'][0]['text']['text'] );
	}

	public function test_krusty_copy_titles_and_not_recorded(): void {
		$this->assertSame( 'Repeated blocked requests', Chat_Notify::class_title( Chat_Notify::CLASS_DENY_STORM ) );
		$this->assertSame( 'AI spending alert', Chat_Notify::class_title( Chat_Notify::CLASS_BUDGET ) );
		$this->assertSame( 'Access control status changed', Chat_Notify::class_title( Chat_Notify::CLASS_TAMPER ) );
		$this->assertSame( 'Trap AI API key used', Chat_Notify::class_title( Chat_Notify::CLASS_CANARY ) );
		$fields = Chat_Notify::card_fields( array(), Chat_Notify::CLASS_DENY_STORM );
		$this->assertSame( 'Not recorded', $fields[1]['value'] );
		$this->assertSame( 'Not recorded', $fields[2]['value'] );
	}

	public function test_teams_adaptive_card_includes_facts_and_open_uri(): void {
		$payload = Chat_Notify::build_teams_card(
			array(
				'plugin'   => 'acme/acme.php',
				'provider' => 'openai',
				'count'    => 12,
			),
			Chat_Notify::CLASS_DENY_STORM
		);
		$this->assertSame( 'MessageCard', $payload['@type'] );
		$this->assertSame( 'acme/acme.php', $payload['sections'][0]['facts'][1]['value'] );
		$this->assertStringContainsString( 'handl-aicac-activity', $payload['potentialAction'][0]['targets'][0]['uri'] );
		$this->assertSame( 'OpenUri', $payload['potentialAction'][0]['@type'] );
	}

	public function test_mask_url_never_echoes_full_secret(): void {
		$secret = 'https://hooks.slack.com/services/T000/B000/abcdefghijklmnopqrstuv';
		$masked = Chat_Notify::mask_url( $secret );
		$this->assertStringContainsString( 'hooks.slack.com', $masked );
		$this->assertStringNotContainsString( 'abcdefghijklmnopqrstuv', $masked );
		$this->assertStringContainsString( '****', $masked );
	}

	public function test_deny_storm_posts_slack_and_teams(): void {
		Chat_Notify::save_config(
			array(
				'slack_url' => 'https://hooks.slack.com/services/T00/B00/xxx',
				'teams_url' => 'https://outlook.office.com/webhook/aaa',
			)
		);
		$out = Chat_Notify::notify(
			array(
				'retry_storm' => true,
				'plugin'      => 'acme/acme.php',
				'provider'    => 'openai',
				'count'       => 9,
			),
			array(),
			Chat_Notify::CLASS_DENY_STORM
		);
		$this->assertTrue( $out['slack']['ok'] );
		$this->assertTrue( $out['teams']['ok'] );
		$this->assertCount( 2, self::$posts );
		$slack = json_decode( (string) self::$posts[0]['args']['body'], true );
		$teams = json_decode( (string) self::$posts[1]['args']['body'], true );
		$this->assertIsArray( $slack );
		$this->assertIsArray( $teams );
		$this->assertArrayHasKey( 'blocks', $slack );
		$this->assertSame( 'MessageCard', $teams['@type'] );
	}

	public function test_http_4xx_logs_health_without_calling_email(): void {
		Chat_Notify::save_config(
			array(
				'slack_url' => 'https://hooks.slack.com/services/T00/B00/bad',
			)
		);
		self::$next_response = array(
			'response' => array( 'code' => 404 ),
			'body'     => 'nope',
		);
		$result = Chat_Notify::notify(
			array(
				'retry_storm' => true,
				'plugin'      => 'acme/acme.php',
			),
			array(),
			Chat_Notify::CLASS_DENY_STORM
		);
		$this->assertFalse( $result['slack']['ok'] );
		$this->assertSame( 404, $result['slack']['http_status'] );
		$this->assertSame( 0, self::$mail_calls );

		$rows = Webhook_Delivery_Log::get_rows();
		$this->assertNotEmpty( $rows );
		$this->assertFalse( $rows[0]['ok'] );
		$this->assertSame( 404, $rows[0]['http_status'] );
		$this->assertSame( 'chat_slack', $rows[0]['event'] );

		$health = Alert_Health::get_state();
		$this->assertGreaterThan( 0, $health[ Alert_Health::CHANNEL_WEBHOOK ]['consecutive_failures'] );
		$this->assertSame( 0, $health[ Alert_Health::CHANNEL_EMAIL ]['consecutive_failures'] );
	}

	public function test_alert_routing_table_gates_mapped_classes_only(): void {
		Chat_Notify::save_config(
			array(
				'slack_url' => 'https://hooks.slack.com/services/T00/B00/xxx',
			)
		);
		$policy = array(
			'alert_routing' => array(
				'drift' => 'ops@example.com',
			),
		);
		$budget = Chat_Notify::notify(
			array(
				'channel' => 'budget',
				'plugin'  => 'acme/acme.php',
			),
			$policy,
			Chat_Notify::CLASS_BUDGET
		);
		$this->assertFalse( $budget['slack']['ok'] );
		$this->assertCount( 0, self::$posts );

		$storm = Chat_Notify::notify(
			array(
				'retry_storm' => true,
				'plugin'      => 'acme/acme.php',
			),
			$policy,
			Chat_Notify::CLASS_DENY_STORM
		);
		$this->assertTrue( $storm['slack']['ok'] );
		$this->assertCount( 1, self::$posts );
	}

	public function test_observe_from_policy_funnel_posts_tamper(): void {
		Chat_Notify::save_config(
			array(
				'slack_url' => 'https://hooks.slack.com/services/T00/B00/xxx',
			)
		);
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
				'log_limit'   => 50,
			),
			false
		);
		Policy::append_log_event(
			array(
				'ts'       => 1_700_000_000,
				'channel'  => 'tamper',
				'plugin'   => 'acme/acme.php',
				'decision' => 'tamper',
				'count'    => 1,
			)
		);
		$this->assertCount( 1, self::$posts );
		$body = json_decode( (string) self::$posts[0]['args']['body'], true );
		$this->assertIsArray( $body );
		$this->assertStringContainsString( 'Access control status changed', (string) wp_json_encode( $body ) );
	}

	public function test_filter_can_block_delivery(): void {
		Chat_Notify::save_config(
			array(
				'slack_url' => 'https://hooks.slack.com/services/T00/B00/xxx',
			)
		);
		$GLOBALS['handl_aicac_test_filters'][ Chat_Notify::FILTER_SHOULD_SEND ] = static function () {
			return false;
		};
		$out = Chat_Notify::notify(
			array( 'retry_storm' => true, 'plugin' => 'acme/acme.php' ),
			array(),
			Chat_Notify::CLASS_DENY_STORM
		);
		$this->assertFalse( $out['slack']['ok'] );
		$this->assertCount( 0, self::$posts );
	}

	public function test_send_test_logs_test_event(): void {
		Chat_Notify::save_config(
			array(
				'slack_url' => 'https://hooks.slack.com/services/T00/B00/xxx',
			)
		);
		$result = Chat_Notify::send_test( Chat_Notify::TARGET_SLACK );
		$this->assertTrue( $result['ok'] );
		$rows = Webhook_Delivery_Log::get_rows();
		$this->assertSame( 'test', $rows[0]['event'] );
		$body = json_decode( (string) self::$posts[0]['args']['body'], true );
		$this->assertIsArray( $body );
		$this->assertStringContainsString( 'handl-aicac-alerts', (string) wp_json_encode( $body ) );
	}

	public function test_rejects_non_http_webhook(): void {
		$saved = Chat_Notify::save_config(
			array(
				'slack_url' => 'javascript:alert(1)',
			)
		);
		$this->assertSame( '', $saved['slack_url'] );
	}

	public function test_min_severity_skips_test_when_raised(): void {
		Chat_Notify::save_config(
			array(
				'slack_url'    => 'https://hooks.slack.com/services/T00/B00/xxx',
				'min_severity' => 7,
			)
		);
		$test = Chat_Notify::notify(
			array( 'chat_test' => true ),
			array(),
			Chat_Notify::CLASS_TEST
		);
		$this->assertCount( 0, self::$posts );
		$this->assertFalse( $test['slack']['ok'] );

		$storm = Chat_Notify::notify(
			array( 'retry_storm' => true, 'plugin' => 'acme/acme.php' ),
			array(),
			Chat_Notify::CLASS_DENY_STORM
		);
		$this->assertTrue( $storm['slack']['ok'] );
	}
}
