<?php
/**
 * Unit tests for AICAC-104 denial-alert webhook channel.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alerts;
use HandL\AICAC\Webhook_Delivery_Log;
use PHPUnit\Framework\TestCase;
use WP_Error;

final class AlertsWebhookTest extends TestCase {

	/** @var list<array{url:string,args:array}> */
	private static array $posts = array();

	/** @var mixed */
	private static $next_response = null;

	/** @var list<mixed> */
	private static array $response_queue = array();

	protected function setUp(): void {
		self::$posts          = array();
		self::$response_queue = array();
		self::$next_response  = array(
			'response' => array( 'code' => 200 ),
			'body'     => 'ok',
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_filters'] = array(
			'handl_aicac_webhook_retry_backoff_ms'     => static function () {
				return 0;
			},
			'handl_aicac_webhook_failure_email_cooldown' => static function () {
				return 0;
			},
		);
		$GLOBALS['handl_aicac_wp_remote_post'] = static function ( string $url, array $args ) {
			AlertsWebhookTest::record_post( $url, $args );
			return AlertsWebhookTest::next_response();
		};
		unset( $GLOBALS['handl_aicac_wp_mail'] );
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
	 * @param array<string,mixed> $args
	 */
	public static function record_post( string $url, array $args ): void {
		self::$posts[] = array(
			'url'  => $url,
			'args' => $args,
		);
	}

	/**
	 * @return mixed
	 */
	public static function next_response() {
		if ( array() !== self::$response_queue ) {
			return array_shift( self::$response_queue );
		}

		return self::$next_response;
	}

	public function test_sanitize_webhook_url_accepts_http_https_only(): void {
		$this->assertSame(
			'https://hooks.example.com/services/abc',
			Alerts::sanitize_webhook_url( 'https://hooks.example.com/services/abc' )
		);
		$this->assertSame(
			'http://example.com/hook',
			Alerts::sanitize_webhook_url( 'http://example.com/hook' )
		);
		$this->assertSame( '', Alerts::sanitize_webhook_url( '' ) );
		$this->assertSame( '', Alerts::sanitize_webhook_url( '   ' ) );
		$this->assertSame( '', Alerts::sanitize_webhook_url( 'ftp://example.com/x' ) );
		$this->assertSame( '', Alerts::sanitize_webhook_url( 'javascript:alert(1)' ) );
		$this->assertSame( '', Alerts::sanitize_webhook_url( 'not a url' ) );
		$this->assertSame( '', Alerts::sanitize_webhook_url( '/relative/path' ) );
	}

	public function test_validate_webhook_url_input_rejects_invalid_inline(): void {
		$ok = Alerts::validate_webhook_url_input( 'https://hooks.slack.com/services/T/B/X' );
		$this->assertTrue( $ok['ok'] );
		$this->assertSame( 'https://hooks.slack.com/services/T/B/X', $ok['url'] );

		$clear = Alerts::validate_webhook_url_input( '' );
		$this->assertTrue( $clear['ok'] );
		$this->assertSame( '', $clear['url'] );

		$bad = Alerts::validate_webhook_url_input( 'ftp://evil.example/hook' );
		$this->assertFalse( $bad['ok'] );
		$this->assertSame( 'invalid', $bad['error'] );
		$this->assertSame( '', $bad['url'] );
	}

	public function test_summary_fields_match_email_privacy_scope(): void {
		$summary = Alerts::summarize_event_public(
			array(
				'ts'                => 1700000000,
				'plugin'            => 'demo/demo.php',
				'operation'         => 'generate_text',
				'capability_family' => 'text',
				'denial_reason'     => 'plugin',
				'matched_tools'     => array( 'tool_a' ),
				'provider'          => 'openai',
				'model'             => 'gpt-4o',
				'model_inferred'    => true,
				'uri'               => '/wp-admin/admin-ajax.php?action=secret&token=abc',
				'prompt_preview'    => 'SHOULD NOT APPEAR',
				'user_id'           => 42,
				'user_login'        => 'admin',
			)
		);

		$fields = Alerts::summary_fields_for_json( $summary );
		$this->assertSame( '/wp-admin/admin-ajax.php', $fields['uri'] );
		$this->assertArrayNotHasKey( 'prompt_preview', $fields );
		$this->assertArrayNotHasKey( 'user_id', $fields );
		$this->assertArrayNotHasKey( 'user_login', $fields );
		foreach (
			array(
				'ts',
				'plugin',
				'operation',
				'capability_family',
				'denial_reason',
				'matched_tools',
				'provider',
				'model',
				'model_inferred',
				'uri',
			) as $key
		) {
			$this->assertArrayHasKey( $key, $fields );
		}

		$payload = Alerts::build_immediate_webhook_payload( $summary );
		$this->assertSame( 'denial', $payload['event'] );
		$this->assertSame( 'handl-aicac', $payload['source'] );
		$this->assertSame( '/wp-admin/admin-ajax.php', $payload['uri'] );
		$this->assertArrayNotHasKey( 'prompt_preview', $payload );
	}

	public function test_test_payload_is_labeled_as_test(): void {
		$payload = Alerts::build_test_webhook_payload();
		$this->assertSame( 'test', $payload['event'] );
		$this->assertTrue( $payload['test'] );
		$this->assertStringContainsString( 'test webhook', strtolower( (string) $payload['message'] ) );
		$this->assertStringContainsString( 'not a real denial', strtolower( (string) $payload['message'] ) );
	}

	public function test_digest_payload_includes_summaries(): void {
		$rows = array(
			Alerts::summarize_event_public(
				array(
					'ts'     => 1,
					'plugin' => 'a/a.php',
					'uri'    => '/a?x=1',
				)
			),
			Alerts::summarize_event_public(
				array(
					'ts'     => 2,
					'plugin' => 'b/b.php',
					'uri'    => '/b',
				)
			),
		);
		$payload = Alerts::build_digest_webhook_payload( $rows );
		$this->assertSame( 'denial_digest', $payload['event'] );
		$this->assertSame( 2, $payload['count'] );
		$this->assertCount( 2, $payload['denials'] );
		$this->assertSame( '/a', $payload['denials'][0]['uri'] );
	}

	public function test_safe_wp_remote_post_success_and_failure_contained(): void {
		$this->assertTrue(
			Alerts::safe_wp_remote_post(
				'https://hooks.example.com/x',
				Alerts::build_test_webhook_payload()
			)
		);
		$this->assertCount( 1, self::$posts );
		$this->assertSame( 0, self::$posts[0]['args']['redirection'] );
		$this->assertSame( 'application/json; charset=utf-8', self::$posts[0]['args']['headers']['Content-Type'] );

		self::$posts         = array();
		self::$next_response = new WP_Error( 'http_request_failed', 'timeout' );
		$this->assertFalse(
			Alerts::safe_wp_remote_post(
				'https://hooks.example.com/x',
				Alerts::build_test_webhook_payload()
			)
		);
		$this->assertCount( 2, self::$posts, 'timeout is retryable: one automatic retry' );

		self::$posts         = array();
		self::$next_response = array(
			'response' => array( 'code' => 500 ),
			'body'     => 'nope',
		);
		$this->assertFalse(
			Alerts::safe_wp_remote_post(
				'https://hooks.example.com/x',
				Alerts::build_test_webhook_payload()
			)
		);
		$this->assertCount( 2, self::$posts, '5xx is retryable: one automatic retry' );

		// 4xx is not retryable.
		self::$posts         = array();
		self::$next_response = array(
			'response' => array( 'code' => 404 ),
			'body'     => 'missing',
		);
		$this->assertFalse(
			Alerts::safe_wp_remote_post(
				'https://hooks.example.com/x',
				Alerts::build_test_webhook_payload()
			)
		);
		$this->assertCount( 1, self::$posts );

		// Empty / invalid URL → no POST attempted (AC2-adjacent).
		self::$posts = array();
		$this->assertFalse( Alerts::safe_wp_remote_post( '', array( 'event' => 'test' ) ) );
		$this->assertFalse( Alerts::safe_wp_remote_post( 'ftp://x', array( 'event' => 'test' ) ) );
		$this->assertCount( 0, self::$posts );
	}

	public function test_deliver_webhook_retries_then_succeeds_and_logs(): void {
		self::$response_queue = array(
			array(
				'response' => array( 'code' => 503 ),
				'body'     => 'busy',
			),
			array(
				'response' => array( 'code' => 200 ),
				'body'     => 'ok',
			),
		);

		$result = Alerts::deliver_webhook(
			'https://hooks.example.com/x',
			Alerts::build_test_webhook_payload(),
			'test'
		);

		$this->assertTrue( $result['ok'] );
		$this->assertSame( 200, $result['http_status'] );
		$this->assertSame( 1, $result['retries'] );
		$this->assertCount( 2, self::$posts );

		$rows = Webhook_Delivery_Log::get_rows();
		$this->assertCount( 1, $rows );
		$this->assertTrue( $rows[0]['ok'] );
		$this->assertSame( 'test', $rows[0]['event'] );
		$this->assertSame( 200, $rows[0]['http_status'] );
		$this->assertSame( 1, $rows[0]['retries'] );
	}

	public function test_deliver_webhook_failure_after_retry_sends_email_once(): void {
		$mail_calls = 0;
		$GLOBALS['handl_aicac_wp_mail'] = static function () use ( &$mail_calls ) {
			++$mail_calls;
			return true;
		};

		self::$response_queue = array(
			new WP_Error( 'http_request_failed', 'timeout' ),
			new WP_Error( 'http_request_failed', 'timeout' ),
		);

		$result = Alerts::deliver_webhook(
			'https://hooks.example.com/x',
			array( 'event' => 'denial', 'source' => 'handl-aicac' ),
			'denial'
		);
		$this->assertFalse( $result['ok'] );
		$this->assertSame( 1, $result['retries'] );
		$this->assertSame( 1, $mail_calls );

		self::$posts          = array();
		self::$response_queue = array(
			array(
				'response' => array( 'code' => 500 ),
				'body'     => 'err',
			),
			array(
				'response' => array( 'code' => 500 ),
				'body'     => 'err',
			),
		);
		Alerts::deliver_webhook(
			'https://hooks.example.com/x',
			array( 'event' => 'denial', 'source' => 'handl-aicac' ),
			'denial'
		);
		// Cooldown filter returns 0 in setUp, so a second failure email is allowed.
		$this->assertSame( 2, $mail_calls );

		$rows = Webhook_Delivery_Log::get_rows();
		$this->assertGreaterThanOrEqual( 2, count( $rows ) );
		$this->assertLessThanOrEqual( Webhook_Delivery_Log::MAX_ROWS, count( $rows ) );
		$this->assertFalse( $rows[0]['ok'] );
		$this->assertSame( 1, $rows[0]['retries'] );
	}

	public function test_webhook_delivery_log_caps_at_twenty(): void {
		for ( $i = 0; $i < 25; $i++ ) {
			Webhook_Delivery_Log::push(
				array(
					'ts'          => 1700000000 + $i,
					'event'       => 'test',
					'http_status' => 200,
					'retries'     => 0,
					'ok'          => true,
				)
			);
		}
		$rows = Webhook_Delivery_Log::get_rows();
		$this->assertCount( 20, $rows );
		$this->assertSame( 1700000024, $rows[0]['ts'] );
		$this->assertSame( 1700000005, $rows[19]['ts'] );
	}

	public function test_send_test_webhook_posts_immediately_when_configured(): void {
		$ok = Alerts::send_test_webhook(
			array( 'alert_webhook_url' => 'https://hooks.example.com/test' )
		);
		$this->assertTrue( $ok );
		$this->assertCount( 1, self::$posts );
		$body = json_decode( (string) self::$posts[0]['args']['body'], true );
		$this->assertIsArray( $body );
		$this->assertSame( 'test', $body['event'] );
		$this->assertTrue( $body['test'] );
	}

	public function test_send_test_webhook_noop_without_url(): void {
		$this->assertFalse( Alerts::send_test_webhook( array() ) );
		$this->assertCount( 0, self::$posts );
	}

	public function test_maybe_notify_defers_webhook_until_shutdown_flush(): void {
		$policy = array(
			'alert_on_deny'     => true,
			'alert_mode'        => 'immediate',
			'alert_email'       => 'admin@example.com',
			'alert_webhook_url' => 'https://hooks.example.com/denial',
			'audit_only'        => false,
		);
		$event  = array(
			'decision'          => 'deny',
			'ts'                => 1700000000,
			'plugin'            => 'demo/demo.php',
			'operation'         => 'generate_text',
			'capability_family' => 'text',
			'denial_reason'     => 'plugin',
			'matched_tools'     => array(),
			'provider'          => '',
			'model'             => '',
			'uri'               => '/wp-admin/post.php?post=1',
		);

		Alerts::maybe_notify_denial( $event, $policy );
		$this->assertCount( 0, self::$posts, 'AC4: must not POST during the filter path' );

		Alerts::flush_deferred();
		$this->assertCount( 1, self::$posts, 'AC1: flush should POST when webhook configured' );
		$body = json_decode( (string) self::$posts[0]['args']['body'], true );
		$this->assertIsArray( $body );
		$this->assertSame( 'denial', $body['event'] );
		$this->assertSame( '/wp-admin/post.php', $body['uri'] );
		$this->assertArrayNotHasKey( 'prompt_preview', $body );
	}

	public function test_no_webhook_post_when_url_empty_email_path_still_runs(): void {
		$mail_calls = 0;
		$GLOBALS['handl_aicac_wp_mail'] = static function () use ( &$mail_calls ) {
			++$mail_calls;
			return true;
		};

		$policy = array(
			'alert_on_deny'     => true,
			'alert_mode'        => 'immediate',
			'alert_email'       => 'admin@example.com',
			'alert_webhook_url' => '',
			'audit_only'        => false,
		);
		$event  = array(
			'decision' => 'deny',
			'ts'       => time(),
			'plugin'   => 'x/x.php',
			'uri'      => '/x',
		);

		Alerts::maybe_notify_denial( $event, $policy );
		Alerts::flush_deferred();

		$this->assertCount( 0, self::$posts );
		$this->assertSame( 1, $mail_calls );
		unset( $GLOBALS['handl_aicac_wp_mail'] );
	}
}
