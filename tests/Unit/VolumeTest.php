<?php
/**
 * AICAC-VOLUME (#385).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Attribution;
use HandL\AICAC\Plugin;
use HandL\AICAC\Volume;
use PHPUnit\Framework\TestCase;

final class VolumeTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Volume::reset_for_tests();
		Attribution::force_plugin( 'alpha/alpha.php' );
		Volume::set_test_provider( null );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'haktan+aicac-volume@handldigital.com',
			)
		);
	}

	protected function tearDown(): void {
		Attribution::force_plugin( null );
		Volume::reset_for_tests();
		unset( $GLOBALS['handl_aicac_test_current_user_can'], $GLOBALS['handl_aicac_wp_mail'] );
		$GLOBALS['handl_aicac_test_options'] = array();
		parent::tearDown();
	}

	public function test_defaults_off_and_noop_save_deletes_option(): void {
		$this->assertFalse( Volume::is_enabled() );
		$this->assertSame( Volume::defaults(), Volume::get_settings() );
		$this->assertFalse( Volume::save_settings( Volume::defaults() ) );
		$this->assertFalse( (bool) get_option( Volume::SETTINGS_OPTION, false ) );

		Volume::save_settings(
			array(
				'enabled'             => true,
				'spike_multiple'      => 10,
				'daily_ceiling_bytes' => 0,
			)
		);
		$this->assertTrue( Volume::is_enabled() );
		$serialized = serialize( get_option( Volume::SETTINGS_OPTION ) );
		$this->assertFalse(
			Volume::save_settings(
				array(
					'enabled'             => true,
					'spike_multiple'      => 10,
					'daily_ceiling_bytes' => 0,
				)
			)
		);
		$this->assertSame( $serialized, serialize( get_option( Volume::SETTINGS_OPTION ) ) );

		Volume::save_settings( Volume::defaults() );
		$this->assertFalse( (bool) get_option( Volume::SETTINGS_OPTION, false ) );
	}

	public function test_off_records_nothing(): void {
		$this->assertNull(
			Volume::record_bytes( 'alpha/alpha.php', 'openai', 1000, 50, 1_720_000_000 )
		);
		$this->assertFalse( (bool) get_option( Volume::COUNTERS_OPTION, false ) );
		$this->assertSame( array(), Volume::test_mails() );
	}

	public function test_body_bytes_counts_only_never_returns_content(): void {
		$secret = 'super-secret-prompt-content';
		$this->assertSame( strlen( $secret ), Volume::body_bytes( $secret ) );
		$this->assertSame( 6, Volume::body_bytes( array( 'a' => 'hello', 'b' => '!' ) ) );
		$this->assertSame( 0, Volume::body_bytes( null ) );
	}

	public function test_non_ai_host_ignored(): void {
		Volume::save_settings( array( 'enabled' => true ) );
		$out = Volume::record_from_http(
			array( 'body' => 'resp' ),
			array( 'body' => str_repeat( 'x', 500 ) ),
			'https://example.com/api',
			1_720_000_000
		);
		$this->assertNull( $out );
		$this->assertFalse( (bool) get_option( Volume::COUNTERS_OPTION, false ) );
	}

	public function test_ai_host_accumulates_per_plugin_provider_day(): void {
		Volume::save_settings( array( 'enabled' => true ) );
		$now = 1_720_000_000;
		$cell = Volume::record_from_http(
			array( 'body' => str_repeat( 'r', 20 ) ),
			array( 'body' => str_repeat( 'q', 100 ) ),
			'https://api.openai.com/v1/chat/completions',
			$now
		);
		$this->assertNotNull( $cell );
		$this->assertSame( 100, (int) $cell['bytes_out'] );
		$this->assertSame( 20, (int) $cell['bytes_in'] );
		$this->assertSame( 1, (int) $cell['calls'] );
		$this->assertSame( 100, (int) $cell['max_request'] );

		Volume::record_bytes( 'alpha/alpha.php', 'openai', 50, 0, $now );
		$totals = Volume::plugin_daily_totals( 'alpha/alpha.php' );
		$day    = Volume::day_key( $now );
		$this->assertSame( 150, (int) $totals[ $day ] );

		$store = get_option( Volume::COUNTERS_OPTION );
		$this->assertIsArray( $store );
		$blob = serialize( $store );
		$this->assertStringNotContainsString( 'qqqq', $blob );
		$this->assertStringNotContainsString( 'rrrr', $blob );
	}

	public function test_ten_x_spike_alerts_once_per_plugin_day(): void {
		Volume::save_settings(
			array(
				'enabled'             => true,
				'spike_multiple'      => 10,
				'daily_ceiling_bytes' => 0,
			)
		);
		$base = strtotime( '2026-10-01 12:00:00 UTC' );
		for ( $i = 0; $i < 5; $i++ ) {
			$ts = $base + ( $i * DAY_IN_SECONDS );
			Volume::record_bytes( 'alpha/alpha.php', 'openai', 100, 0, $ts );
		}
		$spike_day_ts = $base + ( 5 * DAY_IN_SECONDS );
		$this->assertCount( 0, Volume::test_mails() );
		Volume::record_bytes( 'alpha/alpha.php', 'openai', 1000, 0, $spike_day_ts );
		$this->assertCount( 1, Volume::test_mails() );
		Volume::record_bytes( 'alpha/alpha.php', 'openai', 500, 0, $spike_day_ts );
		$this->assertCount( 1, Volume::test_mails() );
		$this->assertStringContainsString( 'volume spike', strtolower( Volume::test_mails()[0]['subject'] ) );
		$this->assertStringNotContainsString( 'secret', Volume::test_mails()[0]['body'] );
	}

	public function test_absolute_ceiling_alerts(): void {
		Volume::save_settings(
			array(
				'enabled'             => true,
				'spike_multiple'      => 1000,
				'daily_ceiling_bytes' => 500,
			)
		);
		$now = 1_720_100_000;
		Volume::record_bytes( 'beta/beta.php', 'anthropic', 500, 0, $now );
		$this->assertCount( 1, Volume::test_mails() );
		Volume::record_bytes( 'beta/beta.php', 'anthropic', 10, 0, $now );
		$this->assertCount( 1, Volume::test_mails() );
	}

	public function test_roster_and_csv_match(): void {
		Volume::save_settings( array( 'enabled' => true ) );
		$now = strtotime( '2026-10-12 15:00:00 UTC' );
		Volume::record_bytes( 'alpha/alpha.php', 'openai', 2000, 0, $now );
		Volume::record_bytes( 'beta/beta.php', 'anthropic', 500, 0, $now );
		Volume::record_bytes( 'alpha/alpha.php', 'openai', 100, 0, $now - DAY_IN_SECONDS );

		$rows = Volume::roster( '2026-10-12' );
		$this->assertNotEmpty( $rows );
		$this->assertSame( 'alpha/alpha.php', $rows[0]['plugin'] );
		$this->assertSame( 2000, (int) $rows[0]['today'] );
		$this->assertSame( 'openai', $rows[0]['top_provider'] );

		$csv = Volume::csv_for_roster( $rows );
		$this->assertStringContainsString( 'alpha/alpha.php', $csv );
		$this->assertStringContainsString( '2000', $csv );
		$this->assertStringContainsString( 'beta/beta.php', $csv );
	}

	public function test_window_evicts_beyond_30_days(): void {
		Volume::save_settings( array( 'enabled' => true ) );
		$base = strtotime( '2026-01-01 12:00:00 UTC' );
		for ( $i = 0; $i < 35; $i++ ) {
			Volume::record_bytes( 'alpha/alpha.php', 'openai', 10, 0, $base + ( $i * DAY_IN_SECONDS ) );
		}
		$counters = Volume::get_counters();
		$this->assertLessThanOrEqual( Volume::WINDOW_DAYS, count( $counters['days'] ) );
		$this->assertArrayNotHasKey( '2026-01-01', $counters['days'] );
	}

	public function test_http_debug_wrapper_uses_provider_map(): void {
		Volume::save_settings( array( 'enabled' => true ) );
		Volume::on_http_api_debug(
			array( 'body' => 'ok' ),
			'response',
			'WP_Http',
			array( 'body' => str_repeat( 'z', 42 ) ),
			'https://api.anthropic.com/v1/messages'
		);
		$day  = Volume::day_key();
		$key  = Volume::cell_key( 'alpha/alpha.php', 'anthropic' );
		$cell = Volume::get_counters()['days'][ $day ][ $key ] ?? null;
		$this->assertNotNull( $cell );
		$this->assertSame( 42, (int) $cell['bytes_out'] );
	}
}
