<?php
/**
 * AICAC-WEATHER (#447).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Weather;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class WeatherTest extends TestCase {

	private const NOW = 1792517659;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_cron']             = array();
		unset( $GLOBALS['handl_aicac_weather_http'] );
		Weather::reset_for_tests();
		Weather::set_test_now( self::NOW );
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_weather_http'] );
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_cron']    = array();
		Weather::reset_for_tests();
		parent::tearDown();
	}

	public function test_defaults_off_and_noop_save_leaves_options_byte_identical(): void {
		$this->assertFalse( Weather::is_enabled() );
		$before = $GLOBALS['handl_aicac_test_options'];
		$this->assertFalse( Weather::save_settings( Weather::defaults() ) );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] );
		$this->assertFalse( (bool) get_option( Weather::OPTION_KEY, false ) );
		$this->assertSame( 0, strpos( Weather::OPTION_KEY, 'handl_aicac_' ) );
	}

	public function test_save_defaults_after_enable_deletes_option(): void {
		$this->assertTrue( Weather::save_settings( array( 'enabled' => true ) ) );
		$this->assertTrue( Weather::is_enabled() );
		$this->assertNotFalse( get_option( Weather::OPTION_KEY, false ) );
		Weather::save_settings( array( 'enabled' => false ) );
		$this->assertFalse( Weather::is_enabled() );
		$this->assertFalse( (bool) get_option( Weather::OPTION_KEY, false ) );
	}

	public function test_ok_to_major_opens_one_notice_and_repeat_cron_does_not_duplicate(): void {
		Weather::save_settings( array( 'enabled' => true ) );
		$this->stub_status( 'none', 'none' );

		$first = Weather::poll( self::NOW );
		$this->assertSame( 2, $first['polled'] );
		$this->assertSame( 2, $first['updated'] );
		$this->assertSame( 0, $first['notices'] );
		$this->assertSame( array(), Weather::active_notices() );

		$this->stub_status( 'major', 'none' );
		$trip = Weather::poll( self::NOW + 60 );
		$this->assertSame( 1, $trip['notices'] );
		$notices = Weather::active_notices();
		$this->assertCount( 1, $notices );
		$this->assertSame( 'openai', $notices[0]['id'] );
		$this->assertSame( 'OpenAI', $notices[0]['label'] );
		$this->assertSame( Weather::INDICATOR_MAJOR, $notices[0]['indicator'] );

		ob_start();
		Weather::maybe_render_notice();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'OpenAI is at major', $html );
		$this->assertStringContainsString( 'This is the provider, not this site.', $html );

		$repeat = Weather::poll( self::NOW + 120 );
		$this->assertSame( 0, $repeat['notices'] );
		$this->assertCount( 1, Weather::active_notices() );
	}

	public function test_recovery_clears_notice(): void {
		Weather::save_settings( array( 'enabled' => true ) );
		$this->stub_status( 'major', 'none' );
		Weather::poll( self::NOW );
		$this->assertCount( 1, Weather::active_notices() );

		$this->stub_status( 'none', 'none' );
		Weather::poll( self::NOW + 60 );
		$this->assertSame( array(), Weather::active_notices() );
		$openai = Weather::get_state()['providers']['openai'];
		$this->assertSame( Weather::INDICATOR_OK, $openai['indicator'] );
		$this->assertFalse( $openai['notice'] );
		$this->assertFalse( $openai['dismissed'] );
	}

	public function test_fetch_failure_does_not_change_stored_state_or_open_notice(): void {
		Weather::save_settings( array( 'enabled' => true ) );
		$this->stub_status( 'none', 'none' );
		Weather::poll( self::NOW );
		$before = get_option( Weather::OPTION_KEY, null );

		$GLOBALS['handl_aicac_weather_http'] = static function () {
			return new \WP_Error( 'http_request_failed', 'timeout' );
		};
		$result = Weather::poll( self::NOW + 60 );
		$this->assertSame( 2, $result['failed'] );
		$this->assertSame( 0, $result['updated'] );
		$this->assertSame( 0, $result['notices'] );
		$this->assertSame( $before, get_option( Weather::OPTION_KEY, null ) );
		$this->assertSame( array(), Weather::active_notices() );
	}

	public function test_http_500_is_fetch_failure(): void {
		Weather::save_settings( array( 'enabled' => true ) );
		$before = get_option( Weather::OPTION_KEY, null );
		$GLOBALS['handl_aicac_weather_http'] = static function () {
			return array(
				'response' => array( 'code' => 500 ),
				'body'     => 'nope',
			);
		};
		$result = Weather::poll( self::NOW );
		$this->assertSame( 2, $result['failed'] );
		$this->assertSame( 0, $result['notices'] );
		$this->assertSame( $before, get_option( Weather::OPTION_KEY, null ) );
	}

	public function test_disabled_poll_is_noop(): void {
		$before = $GLOBALS['handl_aicac_test_options'];
		$called = 0;
		$GLOBALS['handl_aicac_weather_http'] = static function () use ( &$called ) {
			++$called;
			return array(
				'response' => array( 'code' => 200 ),
				'body'     => '{"status":{"indicator":"major","description":"down"}}',
			);
		};
		$result = Weather::poll( self::NOW );
		$this->assertSame( 0, $result['polled'] );
		$this->assertSame( 0, $called );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] );
	}

	public function test_screen_lists_indicator_and_last_change(): void {
		Weather::save_settings( array( 'enabled' => true ) );
		$this->stub_status( 'minor', 'none' );
		Weather::poll( self::NOW );

		$rows = Weather::screen_rows();
		$this->assertSame( 'OpenAI', $rows[0]['label'] );
		$this->assertSame( Weather::INDICATOR_DEGRADED, $rows[0]['indicator'] );
		$this->assertSame( self::NOW, $rows[0]['changed_at'] );
		$this->assertSame( 'Anthropic', $rows[1]['label'] );
		$this->assertSame( Weather::INDICATOR_OK, $rows[1]['indicator'] );

		ob_start();
		Weather::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Provider weather', $html );
		$this->assertStringContainsString( 'OpenAI', $html );
		$this->assertStringContainsString( 'degraded', $html );
		$this->assertStringContainsString( gmdate( 'Y-m-d H:i', self::NOW ), $html );
		$this->assertStringContainsString( 'Anthropic', $html );
	}

	public function test_dismiss_hides_notice_until_new_incident(): void {
		Weather::save_settings( array( 'enabled' => true ) );
		$this->stub_status( 'major', 'none' );
		Weather::poll( self::NOW );
		$this->assertTrue( Weather::dismiss( 'openai' ) );
		$this->assertSame( array(), Weather::active_notices() );

		$this->stub_status( 'major', 'none' );
		Weather::poll( self::NOW + 60 );
		$this->assertSame( array(), Weather::active_notices() );

		$this->stub_status( 'none', 'none' );
		Weather::poll( self::NOW + 120 );
		$this->stub_status( 'major', 'none' );
		Weather::poll( self::NOW + 180 );
		$notices = Weather::active_notices();
		$this->assertCount( 1, $notices );
		$this->assertSame( 'openai', $notices[0]['id'] );
	}

	public function test_normalize_statuspage_indicators(): void {
		$this->assertSame( Weather::INDICATOR_OK, Weather::normalize_indicator( 'none' ) );
		$this->assertSame( Weather::INDICATOR_OK, Weather::normalize_indicator( 'operational' ) );
		$this->assertSame( Weather::INDICATOR_DEGRADED, Weather::normalize_indicator( 'minor' ) );
		$this->assertSame( Weather::INDICATOR_MAJOR, Weather::normalize_indicator( 'major' ) );
		$this->assertSame( Weather::INDICATOR_MAJOR, Weather::normalize_indicator( 'critical' ) );
	}

	/**
	 * Stub both roster URLs. $openai / $anthropic are statuspage indicators.
	 */
	private function stub_status( string $openai, string $anthropic ): void {
		$GLOBALS['handl_aicac_weather_http'] = static function ( string $url ) use ( $openai, $anthropic ) {
			$ind = false !== strpos( $url, 'openai' ) ? $openai : $anthropic;
			return array(
				'response' => array( 'code' => 200 ),
				'body'     => wp_json_encode(
					array(
						'status' => array(
							'indicator'   => $ind,
							'description' => $ind,
						),
					)
				),
			);
		};
	}
}
