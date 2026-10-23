<?php
/**
 * AICAC-CONCENTRATION (#393).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Concentration;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class ConcentrationTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Concentration::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'haktan+aicac-concentration@handldigital.com',
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_filters'][ Concentration::FILTER_THRESHOLD ],
			$GLOBALS['handl_aicac_test_current_user_can']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		Concentration::reset_for_tests();
		parent::tearDown();
	}

	public function test_defaults_off_and_save_defaults_deletes_option(): void {
		$this->assertFalse( Concentration::is_enabled() );
		$this->assertSame( Concentration::defaults(), Concentration::get_settings() );
		Concentration::save_settings(
			array(
				'enabled'   => true,
				'threshold' => 0.8,
			)
		);
		$this->assertTrue( Concentration::is_enabled() );
		Concentration::save_settings( Concentration::defaults() );
		$this->assertFalse( (bool) get_option( Concentration::SETTINGS_OPTION, false ) );
	}

	public function test_threshold_accepts_percent_and_filter(): void {
		$this->assertSame( 0.8, Concentration::sanitize_threshold( 80 ) );
		$this->assertSame( 0.8, Concentration::sanitize_threshold( 0.8 ) );
		Concentration::save_settings(
			array(
				'enabled'   => true,
				'threshold' => 0.75,
			)
		);
		$this->assertEqualsWithDelta( 0.75, Concentration::threshold(), 0.0001 );
		$GLOBALS['handl_aicac_test_filters'][ Concentration::FILTER_THRESHOLD ] = static function (): float {
			return 0.9;
		};
		$this->assertEqualsWithDelta( 0.9, Concentration::threshold(), 0.0001 );
	}

	public function test_shares_hhi_and_divorce_from_log(): void {
		Concentration::save_settings(
			array(
				'enabled'   => true,
				'threshold' => 0.8,
			)
		);
		$now = strtotime( '2026-10-12 15:00:00 UTC' );
		$log = array(
			// 9 openai + 1 anthropic = 90% openai.
			array(
				'ts'            => $now,
				'plugin'        => 'alpha/alpha.php',
				'provider'      => 'openai',
				'decision'      => 'allow',
				'operation'     => 'generate_text',
				'input_tokens'  => 1000,
				'output_tokens' => 0,
				'count'         => 9,
			),
			array(
				'ts'            => $now,
				'plugin'        => 'beta/beta.php',
				'provider'      => 'anthropic',
				'decision'      => 'allow',
				'operation'     => 'generate_text',
				'input_tokens'  => 1000,
				'output_tokens' => 0,
				'count'         => 1,
			),
			// Divorce: gamma only talks to openai.
			array(
				'ts'            => $now,
				'plugin'        => 'gamma/gamma.php',
				'provider'      => 'openai',
				'decision'      => 'allow',
				'operation'     => 'generate_text',
				'input_tokens'  => 500,
				'output_tokens' => 0,
			),
		);

		$analysis = Concentration::analyze_window( 30, $log, $now );
		$this->assertSame( 'openai', $analysis['top_provider'] );
		// alpha 9 openai + gamma 1 openai = 10 openai, beta 1 anthropic → 10/11.
		$this->assertEqualsWithDelta( 10 / 11, $analysis['top_calls_share'], 0.0001 );
		$this->assertTrue( $analysis['above_threshold'] );
		$this->assertGreaterThan( 0.5, $analysis['hhi_calls'] );

		$divorce = Concentration::divorce_roster( 30, $log, $now );
		$by_plugin = array();
		foreach ( $divorce as $row ) {
			$by_plugin[ $row['plugin'] ] = $row;
		}
		$this->assertArrayHasKey( 'alpha/alpha.php', $by_plugin );
		$this->assertArrayHasKey( 'beta/beta.php', $by_plugin );
		$this->assertArrayHasKey( 'gamma/gamma.php', $by_plugin );
		$this->assertSame( 'openai', $by_plugin['gamma/gamma.php']['provider'] );

		$csv = Concentration::csv_for_roster( Concentration::provider_roster( $log, $now ) );
		$this->assertStringContainsString( 'estimate_from_logged_traffic_not_a_bill', $csv );
		$this->assertStringContainsString( 'openai', $csv );
	}

	public function test_alert_fires_once_per_provider_window(): void {
		Concentration::save_settings(
			array(
				'enabled'   => true,
				'threshold' => 0.8,
			)
		);
		$now = strtotime( '2026-10-12 12:00:00 UTC' );
		$log = array();
		for ( $i = 0; $i < 9; $i++ ) {
			$log[] = array(
				'ts'            => $now,
				'plugin'        => 'alpha/alpha.php',
				'provider'      => 'openai',
				'decision'      => 'allow',
				'operation'     => 'generate_text',
				'input_tokens'  => 100,
				'output_tokens' => 0,
			);
		}
		$log[] = array(
			'ts'            => $now,
			'plugin'        => 'beta/beta.php',
			'provider'      => 'anthropic',
			'decision'      => 'allow',
			'operation'     => 'generate_text',
			'input_tokens'  => 100,
			'output_tokens' => 0,
		);

		$first = Concentration::maybe_fire_alerts( $log, null, $now );
		$this->assertNotEmpty( $first );
		$mails = count( Concentration::test_mails() );
		$this->assertGreaterThan( 0, $mails );

		$second = Concentration::maybe_fire_alerts( $log, null, $now );
		$this->assertSame( array(), $second );
		$this->assertSame( $mails, count( Concentration::test_mails() ) );
	}

	public function test_off_page_shows_enable_prompt(): void {
		$_GET['page'] = Concentration::PAGE_SLUG;
		ob_start();
		Concentration::render_page();
		$html = ob_get_clean();
		$this->assertStringContainsString( 'Concentration watch is off', $html );
		$this->assertStringNotContainsString( 'Provider shares', $html );
		unset( $_GET['page'] );
	}

	public function test_enabled_page_shows_estimate_framing(): void {
		Concentration::save_settings(
			array(
				'enabled'   => true,
				'threshold' => 0.8,
			)
		);
		$now = strtotime( '2026-10-12 12:00:00 UTC' );
		$log = array(
			array(
				'ts'            => $now,
				'plugin'        => 'alpha/alpha.php',
				'provider'      => 'openai',
				'decision'      => 'allow',
				'operation'     => 'generate_text',
				'input_tokens'  => 1000,
				'output_tokens' => 0,
			),
		);
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
		$_GET['page'] = Concentration::PAGE_SLUG;
		ob_start();
		Concentration::render_page();
		$html = ob_get_clean();
		$this->assertStringContainsString( 'Estimate from logged traffic, not a bill', $html );
		$this->assertStringContainsString( 'openai', $html );
		$this->assertStringContainsString( 'Divorce roster', $html );
		unset( $_GET['page'] );
	}
}
