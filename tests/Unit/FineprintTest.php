<?php
/**
 * AICAC-FINEPRINT (#455).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Fineprint;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class FineprintTest extends TestCase {

	private const NOW = 1792518000;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_cron']             = array();
		unset( $GLOBALS['handl_aicac_fineprint_http'] );
		Fineprint::reset_for_tests();
		Fineprint::set_test_now( self::NOW );
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_fineprint_http'] );
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_cron']    = array();
		Fineprint::reset_for_tests();
		parent::tearDown();
	}

	public function test_detect_pure_verdicts(): void {
		$body_a = '<html><body>Terms version one</body></html>';
		$body_b = '<html><body>Terms version two</body></html>';
		$hash_a = Fineprint::hash_body( $body_a );

		$this->assertSame(
			Fineprint::VERDICT_UNREACHABLE,
			Fineprint::detect( $hash_a, false, $body_b )
		);
		$this->assertSame(
			Fineprint::VERDICT_UNCHANGED,
			Fineprint::detect( null, true, $body_a )
		);
		$this->assertSame(
			Fineprint::VERDICT_UNCHANGED,
			Fineprint::detect( $hash_a, true, $body_a )
		);
		$this->assertSame(
			Fineprint::VERDICT_CHANGED,
			Fineprint::detect( $hash_a, true, $body_b )
		);
		// Markup-only volatility does not change the hash.
		$body_noisy = '<html><script>track()</script><body>Terms version one<!--x--></body></html>';
		$this->assertSame(
			Fineprint::VERDICT_UNCHANGED,
			Fineprint::detect( $hash_a, true, $body_noisy )
		);
	}

	public function test_defaults_off_and_disabled_poll_is_noop(): void {
		$this->assertFalse( Fineprint::is_enabled() );
		$before = $GLOBALS['handl_aicac_test_options'];
		$called = 0;
		$GLOBALS['handl_aicac_fineprint_http'] = static function () use ( &$called ) {
			++$called;

			return array(
				'response' => array( 'code' => 200 ),
				'body'     => 'changed forever',
			);
		};
		$result = Fineprint::poll( self::NOW );
		$this->assertSame( 0, $result['polled'] );
		$this->assertSame( 0, $called );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] );
		$this->assertFalse( (bool) get_option( Fineprint::SETTINGS_OPTION, false ) );
		$this->assertFalse( (bool) get_option( Fineprint::STATE_OPTION, false ) );
	}

	public function test_enable_schedules_one_cron_disable_clears(): void {
		$this->assertFalse( (bool) wp_next_scheduled( Fineprint::CRON_HOOK ) );
		Fineprint::save_settings( array( 'enabled' => true ) );
		$this->assertNotFalse( wp_next_scheduled( Fineprint::CRON_HOOK ) );
		$this->assertArrayHasKey( Fineprint::CRON_HOOK, $GLOBALS['handl_aicac_test_cron'] );

		Fineprint::save_settings( array( 'enabled' => false ) );
		$this->assertFalse( (bool) wp_next_scheduled( Fineprint::CRON_HOOK ) );
		$this->assertArrayNotHasKey( Fineprint::CRON_HOOK, $GLOBALS['handl_aicac_test_cron'] );
	}

	public function test_first_fetch_seeds_without_notice_second_change_opens_per_change_notice(): void {
		Fineprint::save_settings( array( 'enabled' => true ) );
		$this->stub_body( 'Terms A', 'Terms A' );

		$first = Fineprint::poll( self::NOW );
		$this->assertSame( 2, $first['polled'] );
		$this->assertSame( 2, $first['unchanged'] );
		$this->assertSame( 0, $first['changed'] );
		$this->assertSame( array(), Fineprint::active_notices() );
		$this->assertSame( array(), Fineprint::get_state()['ledger'] );

		$this->stub_body( 'Terms B', 'Terms A' );
		$trip = Fineprint::poll( self::NOW + 3600 );
		$this->assertSame( 1, $trip['changed'] );
		$this->assertSame( 1, $trip['unchanged'] );
		$notices = Fineprint::active_notices();
		$this->assertCount( 1, $notices );
		$this->assertSame( 'openai', $notices[0]['provider'] );
		$this->assertSame( 'OpenAI', $notices[0]['label'] );
		$this->assertCount( 1, Fineprint::get_state()['ledger'] );

		ob_start();
		Fineprint::maybe_render_notice();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'OpenAI terms page changed on', $html );
		$this->assertStringContainsString( 'review', $html );

		$change_id = $notices[0]['change_id'];
		$this->assertTrue( Fineprint::dismiss( $change_id ) );
		$this->assertSame( array(), Fineprint::active_notices() );

		// Same changed body again: no new notice (hash already current).
		$repeat = Fineprint::poll( self::NOW + 7200 );
		$this->assertSame( 0, $repeat['changed'] );
		$this->assertSame( array(), Fineprint::active_notices() );
	}

	public function test_fetch_failure_is_unreachable_never_a_change(): void {
		Fineprint::save_settings( array( 'enabled' => true ) );
		$this->stub_body( 'Terms A', 'Terms A' );
		Fineprint::poll( self::NOW );
		$before_ledger = Fineprint::get_state()['ledger'];
		$before_hash   = Fineprint::get_state()['providers']['openai']['hash'];

		$GLOBALS['handl_aicac_fineprint_http'] = static function () {
			return new \WP_Error( 'http_request_failed', 'timeout' );
		};
		$result = Fineprint::poll( self::NOW + 60 );
		$this->assertSame( 2, $result['unreachable'] );
		$this->assertSame( 0, $result['changed'] );
		$this->assertSame( $before_ledger, Fineprint::get_state()['ledger'] );
		$this->assertSame( $before_hash, Fineprint::get_state()['providers']['openai']['hash'] );
		$this->assertSame( 'unreachable', Fineprint::get_state()['providers']['openai']['status'] );
		$this->assertSame( array(), Fineprint::active_notices() );
	}

	public function test_http_404_is_unreachable(): void {
		Fineprint::save_settings( array( 'enabled' => true ) );
		$GLOBALS['handl_aicac_fineprint_http'] = static function () {
			return array(
				'response' => array( 'code' => 404 ),
				'body'     => 'missing',
			);
		};
		$result = Fineprint::poll( self::NOW );
		$this->assertSame( 2, $result['unreachable'] );
		$this->assertSame( 0, $result['changed'] );
		$this->assertSame( array(), Fineprint::get_state()['ledger'] );
	}

	public function test_url_override_and_zero_writes_outside_own_options(): void {
		Fineprint::save_settings(
			array(
				'enabled' => true,
				'urls'    => array(
					'openai' => 'https://example.com/openai-terms',
				),
			)
		);
		$this->assertSame( 'https://example.com/openai-terms', Fineprint::url_for( 'openai' ) );

		$before_policy = get_option( 'handl_aicac_policy', null );
		$before_weather = get_option( 'handl_aicac_weather', null );
		$this->stub_body( 'x', 'y' );
		Fineprint::poll( self::NOW );
		$this->assertSame( $before_policy, get_option( 'handl_aicac_policy', null ) );
		$this->assertSame( $before_weather, get_option( 'handl_aicac_weather', null ) );
		$this->assertNotFalse( get_option( Fineprint::SETTINGS_OPTION, false ) );
		$this->assertNotFalse( get_option( Fineprint::STATE_OPTION, false ) );
	}

	public function test_screen_empty_ledger_and_escaped_output(): void {
		Fineprint::save_settings( array( 'enabled' => true ) );
		ob_start();
		Fineprint::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Fine print', $html );
		$this->assertStringContainsString( 'No terms-page changes recorded yet', $html );
		$this->assertStringContainsString( 'hashes only', $html );
		$this->assertStringContainsString( 'OpenAI', $html );

		$this->stub_body( 'A', 'A' );
		Fineprint::poll( self::NOW );
		$this->stub_body( 'evil<script>x</script>', 'A' );
		Fineprint::poll( self::NOW + 1 );
		ob_start();
		Fineprint::render_page();
		$html2 = (string) ob_get_clean();
		$this->assertStringContainsString( 'Change ledger', $html2 );
		$this->assertStringNotContainsString( '<script>', $html2 );
	}

	public function test_registry_separate_from_weather_urls(): void {
		$reg = Fineprint::registry();
		$this->assertArrayHasKey( 'openai', $reg );
		$this->assertStringContainsString( 'terms', strtolower( $reg['openai']['url'] ) );
		$this->assertStringNotContainsString( 'status.', $reg['openai']['url'] );
		$this->assertStringNotContainsString( '/api/v2/status', $reg['openai']['url'] );
	}

	/**
	 * @param string $openai Body for openai URL.
	 * @param string $anthropic Body for anthropic URL.
	 */
	private function stub_body( string $openai, string $anthropic ): void {
		$GLOBALS['handl_aicac_fineprint_http'] = static function ( string $url ) use ( $openai, $anthropic ) {
			$body = false !== strpos( $url, 'anthropic' ) ? $anthropic : $openai;

			return array(
				'response' => array( 'code' => 200 ),
				'body'     => '<html><body>' . $body . '</body></html>',
			);
		};
	}
}
