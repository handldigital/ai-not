<?php
/**
 * Unit tests for AICAC-CANARY honeytoken (#233).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Routing;
use HandL\AICAC\Attribution;
use HandL\AICAC\Canary;
use HandL\AICAC\Plugin;
use HandL\AICAC\Shadow_AI;
use PHPUnit\Framework\TestCase;

final class CanaryTest extends TestCase {

	/** @var list<array{to:mixed,subject:string,body:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails                         = array();
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_transients'] = array();
		Attribution::force_plugin( null );
		Shadow_AI::reset_pending_for_tests();
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) {
			CanaryTest::record_mail( $to, (string) $subject, (string) $message );
			return true;
		};
	}

	protected function tearDown(): void {
		Attribution::force_plugin( null );
		Shadow_AI::reset_pending_for_tests();
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		$GLOBALS['handl_aicac_test_options']    = array();
		$GLOBALS['handl_aicac_test_transients'] = array();
		parent::tearDown();
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

	private function enable_log_and_alerts(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
				'alert_email' => 'ops@example.com',
			),
			false
		);
	}

	public function test_fresh_seed_plants_exactly_one_decoy(): void {
		$first = Canary::ensure_seeded();
		$this->assertNotSame( '', $first['token'] );
		$this->assertStringStartsWith( 'sk-htlcan', $first['token'] );
		$this->assertSame( 'openai_api_key', $first['option'] );
		$this->assertSame( $first['token'], get_option( 'openai_api_key' ) );

		$again = Canary::ensure_seeded();
		$this->assertSame( $first['token'], $again['token'] );
		$this->assertSame( $first['option'], $again['option'] );
		$this->assertSame( $first['token'], get_option( 'openai_api_key' ) );
	}

	public function test_seed_skips_occupied_provider_option(): void {
		update_option( 'openai_api_key', 'sk-real-customer-key-not-ours', false );
		$state = Canary::ensure_seeded();
		$this->assertSame( 'openai_key', $state['option'] );
		$this->assertSame( 'sk-real-customer-key-not-ours', get_option( 'openai_api_key' ) );
		$this->assertSame( $state['token'], get_option( 'openai_key' ) );
	}

	public function test_payload_detects_header_body_and_url(): void {
		$state = Canary::ensure_seeded();
		$token = $state['token'];

		$this->assertTrue(
			Canary::payload_contains_token(
				array( 'headers' => array( 'Authorization' => 'Bearer ' . $token ) ),
				'https://api.openai.com/v1/chat/completions',
				$token
			)
		);
		$this->assertTrue(
			Canary::payload_contains_token(
				array( 'body' => wp_json_encode( array( 'api_key' => $token ) ) ),
				'https://api.openai.com/v1/chat/completions',
				$token
			)
		);
		$this->assertTrue(
			Canary::payload_contains_token(
				array(),
				'https://api.openai.com/v1/models?api_key=' . $token,
				$token
			)
		);
		$this->assertFalse(
			Canary::payload_contains_token(
				array( 'headers' => array( 'Authorization' => 'Bearer sk-other' ) ),
				'https://api.openai.com/v1/chat/completions',
				$token
			)
		);
	}

	public function test_preflight_block_and_attribution(): void {
		$this->enable_log_and_alerts();
		$state = Canary::ensure_seeded();
		Attribution::force_plugin( 'thief/thief.php' );

		$result = Shadow_AI::handle_http_request(
			false,
			array(
				'headers' => array( 'Authorization' => 'Bearer ' . $state['token'] ),
				'body'    => '{"model":"gpt-4"}',
			),
			'https://api.openai.com/v1/chat/completions'
		);

		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( Canary::BLOCK_ERROR_CODE, $result->code );
		$this->assertStringContainsString( 'trap AI API key', $result->message );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertCount( 1, $log );
		$this->assertSame( 'canary', $log[0]['channel'] );
		$this->assertSame( 'thief/thief.php', $log[0]['plugin'] );
		$this->assertSame( 'deny', $log[0]['decision'] );
		$encoded = wp_json_encode( $log[0] );
		$this->assertIsString( $encoded );
		$this->assertStringNotContainsString( $state['token'], $encoded );
		$this->assertSame( Canary::masked_token( $state['token'] ), $log[0]['canary_masked'] );
	}

	public function test_unknown_host_still_blocked_when_token_present(): void {
		$state = Canary::ensure_seeded();
		Attribution::force_plugin( 'thief/thief.php' );

		$result = Shadow_AI::handle_http_request(
			false,
			array( 'headers' => array( 'Authorization' => 'Bearer ' . $state['token'] ) ),
			'https://exfil.example/collect'
		);

		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( Canary::BLOCK_ERROR_CODE, $result->code );
	}

	public function test_request_without_token_is_not_a_canary_block(): void {
		Canary::ensure_seeded();
		$result = Shadow_AI::handle_http_request(
			false,
			array( 'headers' => array( 'Authorization' => 'Bearer sk-unrelated' ) ),
			'https://example.com/api'
		);
		$this->assertFalse( $result );
	}

	public function test_alert_dedupes_within_hour(): void {
		$this->enable_log_and_alerts();
		$state = Canary::ensure_seeded();
		Attribution::force_plugin( 'thief/thief.php' );
		$args = array( 'headers' => array( 'Authorization' => 'Bearer ' . $state['token'] ) );
		$url  = 'https://api.openai.com/v1/chat/completions';

		$first = Canary::intercept( $args, $url );
		$this->assertInstanceOf( \WP_Error::class, $first );
		$this->assertCount( 1, self::$mails );
		$this->assertSame( 'ops@example.com', self::$mails[0]['to'] );
		$this->assertStringContainsString( 'trap AI key', self::$mails[0]['subject'] );
		$this->assertStringContainsString( 'thief/thief.php', self::$mails[0]['body'] );
		$this->assertStringContainsString( Canary::masked_token( $state['token'] ), self::$mails[0]['body'] );
		$this->assertStringNotContainsString( $state['token'], self::$mails[0]['body'] );
		$this->assertStringNotContainsString( $state['token'], self::$mails[0]['subject'] );

		$second = Canary::intercept( $args, $url );
		$this->assertInstanceOf( \WP_Error::class, $second );
		$this->assertCount( 1, self::$mails, 'repeat within the hour must not send a second alert' );
	}

	public function test_mask_text_replaces_decoy(): void {
		$state = Canary::ensure_seeded();
		$raw   = 'Authorization: Bearer ' . $state['token'];
		$masked = Canary::mask_text( $raw );
		$this->assertStringNotContainsString( $state['token'], $masked );
		$this->assertStringContainsString( Canary::masked_token( $state['token'] ), $masked );
	}

	public function test_self_plugin_does_not_trip(): void {
		$state = Canary::ensure_seeded();
		Attribution::force_plugin( 'handl-ai-connector-access-control/handl-ai-connector-access-control.php' );
		$result = Canary::intercept(
			array( 'headers' => array( 'Authorization' => 'Bearer ' . $state['token'] ) ),
			'https://api.openai.com/v1/chat/completions'
		);
		$this->assertNull( $result );
		$this->assertCount( 0, self::$mails );
	}

	public function test_site_health_critical_after_trip(): void {
		$this->enable_log_and_alerts();
		$state = Canary::ensure_seeded();
		Attribution::force_plugin( 'thief/thief.php' );
		Canary::intercept(
			array( 'headers' => array( 'Authorization' => 'Bearer ' . $state['token'] ) ),
			'https://api.openai.com/v1/chat/completions'
		);

		$health = Canary::instance()->run_site_health_test();
		$this->assertSame( 'critical', $health['status'] );
		$this->assertStringContainsString( 'thief/thief.php', wp_specialchars_decode( strip_tags( (string) $health['description'] ), ENT_QUOTES ) );
		$this->assertStringNotContainsString( $state['token'], (string) $health['description'] );
	}

	public function test_site_health_good_when_never_tripped(): void {
		Canary::ensure_seeded();
		$health = Canary::instance()->run_site_health_test();
		$this->assertSame( 'good', $health['status'] );
	}

	public function test_alert_routing_accepts_canary_type(): void {
		$this->assertContains( 'canary', Alert_Routing::TYPES );
		$clean = Alert_Routing::sanitize_routing(
			array(
				'canary' => 'sec@example.com',
			)
		);
		$this->assertSame( array( 'canary' => 'sec@example.com' ), $clean );
		$this->assertSame(
			'sec@example.com',
			Alert_Routing::resolve_email(
				array(
					'alert_email'   => 'ops@example.com',
					'alert_routing' => $clean,
				),
				'canary'
			)
		);
	}

	public function test_uninstall_keep_leaves_planted_option(): void {
		if ( ! defined( 'HANDL_AICAC_UNINSTALL_HELPERS' ) ) {
			define( 'HANDL_AICAC_UNINSTALL_HELPERS', true );
		}
		require_once HANDL_AICAC_DIR . '/uninstall.php';

		$state = Canary::ensure_seeded();
		update_option( 'handl_aicac_uninstall_policy', 'keep', false );
		\handl_aicac_run_uninstall();

		$this->assertSame( $state['token'], get_option( $state['option'] ) );
		$this->assertSame( $state['token'], Canary::token() );
	}

	public function test_uninstall_purge_removes_planted_option_and_registry(): void {
		if ( ! defined( 'HANDL_AICAC_UNINSTALL_HELPERS' ) ) {
			define( 'HANDL_AICAC_UNINSTALL_HELPERS', true );
		}
		require_once HANDL_AICAC_DIR . '/uninstall.php';

		$state = Canary::ensure_seeded();
		$option = $state['option'];
		$this->assertNotSame( '', get_option( $option ) );
		update_option( 'handl_aicac_uninstall_policy', 'purge', false );
		\handl_aicac_run_uninstall();

		$this->assertFalse( get_option( $option, false ) );
		$this->assertFalse( get_option( Canary::REGISTRY_OPTION, false ) );
		$this->assertFalse( get_option( Canary::LAST_TRIP_OPTION, false ) );
	}
}
