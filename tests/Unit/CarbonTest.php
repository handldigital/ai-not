<?php
/**
 * AICAC-CARBON (#387).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Carbon;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class CarbonTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Carbon::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'haktan+aicac-carbon@handldigital.com',
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_filters'][ Carbon::FILTER_FACTORS ],
			$GLOBALS['handl_aicac_test_current_user_can']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		Carbon::reset_for_tests();
		parent::tearDown();
	}

	public function test_defaults_off_and_save_defaults_deletes_option(): void {
		$this->assertFalse( Carbon::is_enabled() );
		$this->assertSame( Carbon::defaults(), Carbon::get_settings() );
		Carbon::save_settings( array( 'enabled' => true ) );
		$this->assertTrue( Carbon::is_enabled() );
		Carbon::save_settings( array( 'enabled' => false ) );
		$this->assertFalse( (bool) get_option( Carbon::SETTINGS_OPTION, false ) );
	}

	public function test_off_rebuild_is_noop_unless_forced(): void {
		$log = array(
			array(
				'ts'            => strtotime( '2026-10-12 12:00:00 UTC' ),
				'plugin'        => 'alpha/alpha.php',
				'provider'      => 'openai',
				'model'         => 'gpt-4o-mini',
				'decision'      => 'allow',
				'operation'     => 'generate_text',
				'input_tokens'  => 1_000_000,
				'output_tokens' => 0,
			),
		);
		$out = Carbon::rebuild_rollups( $log, strtotime( '2026-10-12 12:00:00 UTC' ), false );
		$this->assertSame( Carbon::empty_rollups(), $out );
		$this->assertFalse( (bool) get_option( Carbon::ROLLUPS_OPTION, false ) );
	}

	public function test_energy_for_tokens_uses_model_factor_and_grid(): void {
		$factors = Carbon::bundled_factors();
		$energy  = Carbon::energy_for_tokens( 1_000_000, 'gpt-4o-mini', $factors );
		$this->assertEqualsWithDelta( 0.15, $energy['kwh'], 0.00001 );
		$this->assertEqualsWithDelta( 0.15 * (float) $factors['grid_kg_per_kwh'], $energy['kg_co2e'], 0.00001 );

		$default = Carbon::energy_for_tokens( 1_000_000, '', $factors );
		$this->assertEqualsWithDelta( (float) $factors['default_kwh_per_1m'], $default['kwh'], 0.00001 );
	}

	public function test_filter_override_changes_factors_and_staleness_age(): void {
		$GLOBALS['handl_aicac_test_filters'][ Carbon::FILTER_FACTORS ] = static function (): array {
			return array(
				'shipped'            => '2026-11-01',
				'grid_kg_per_kwh'    => 0.2,
				'default_kwh_per_1m' => 1.0,
				'models'             => array(
					'gpt-custom' => 2.0,
				),
			);
		};
		$factors = Carbon::factors();
		$this->assertSame( '2026-11-01', $factors['shipped'] );
		$this->assertEqualsWithDelta( 2.0, Carbon::kwh_per_1m_for_model( 'gpt-custom' ), 0.00001 );
		$age = strtotime( '2026-11-01 UTC' );
		$this->assertSame( $age, Carbon::factors_age_ts() );
		$this->assertFalse( Carbon::is_factors_stale( $age + ( 30 * DAY_IN_SECONDS ) ) );
		$this->assertTrue( Carbon::is_factors_stale( $age + ( 121 * DAY_IN_SECONDS ) ) );
	}

	public function test_rebuild_rollups_and_roster_from_log(): void {
		Carbon::save_settings( array( 'enabled' => true ) );
		$now = strtotime( '2026-10-12 15:00:00 UTC' );
		$log = array(
			array(
				'ts'            => $now,
				'plugin'        => 'alpha/alpha.php',
				'provider'      => 'openai',
				'model'         => 'gpt-4o-mini',
				'decision'      => 'allow',
				'operation'     => 'generate_text',
				'input_tokens'  => 500_000,
				'output_tokens' => 500_000,
				'count'         => 1,
			),
			array(
				'ts'            => $now,
				'plugin'        => 'beta/beta.php',
				'provider'      => 'anthropic',
				'model'         => 'claude-3-haiku',
				'decision'      => 'allow',
				'operation'     => 'generate_text',
				'input_tokens'  => 1_000_000,
				'output_tokens' => 0,
			),
			array(
				'ts'            => $now - DAY_IN_SECONDS,
				'plugin'        => 'alpha/alpha.php',
				'provider'      => 'openai',
				'model'         => 'gpt-4o-mini',
				'decision'      => 'allow',
				'operation'     => 'generate_text',
				'input_tokens'  => 1_000_000,
				'output_tokens' => 0,
			),
			// No tokens → ignored.
			array(
				'ts'        => $now,
				'plugin'    => 'gamma/gamma.php',
				'provider'  => 'openai',
				'decision'  => 'allow',
				'operation' => 'generate_text',
			),
		);

		$rollups = Carbon::rebuild_rollups( $log, $now, true );
		$this->assertArrayHasKey( '2026-10-12', $rollups['days'] );
		$this->assertArrayHasKey( '2026-10', $rollups['months'] );

		$rows = Carbon::roster( '2026-10-12', $rollups, false );
		$this->assertNotEmpty( $rows );
		$this->assertTrue( ! empty( $rows[0]['estimate'] ) );

		$by_plugin = array();
		foreach ( $rows as $row ) {
			$by_plugin[ $row['plugin'] ] = $row;
		}
		$this->assertArrayHasKey( 'alpha/alpha.php', $by_plugin );
		$this->assertArrayHasKey( 'beta/beta.php', $by_plugin );
		$this->assertEqualsWithDelta( 0.15, (float) $by_plugin['alpha/alpha.php']['today_kwh'], 0.0001 );
		$this->assertEqualsWithDelta( 0.30, (float) $by_plugin['alpha/alpha.php']['month_kwh'], 0.0001 );
		$this->assertSame( 'openai', $by_plugin['alpha/alpha.php']['top_provider'] );

		$csv = Carbon::csv_for_roster( $rows );
		$this->assertStringContainsString( 'directional_estimate_not_compliance_grade', $csv );
		$this->assertStringContainsString( 'alpha/alpha.php', $csv );
		$this->assertStringContainsString( 'beta/beta.php', $csv );

		$providers = Carbon::provider_roster( '2026-10-12', $rollups, false );
		$this->assertNotEmpty( $providers );
	}

	public function test_window_evicts_old_days(): void {
		Carbon::save_settings( array( 'enabled' => true ) );
		$base = strtotime( '2026-01-01 12:00:00 UTC' );
		$log  = array();
		for ( $i = 0; $i < 100; $i++ ) {
			$log[] = array(
				'ts'            => $base + ( $i * DAY_IN_SECONDS ),
				'plugin'        => 'alpha/alpha.php',
				'provider'      => 'openai',
				'model'         => 'gpt-4o-mini',
				'decision'      => 'allow',
				'operation'     => 'generate_text',
				'input_tokens'  => 1000,
				'output_tokens' => 0,
			);
		}
		$now     = $base + ( 99 * DAY_IN_SECONDS );
		$rollups = Carbon::rebuild_rollups( $log, $now, true );
		$this->assertLessThanOrEqual( Carbon::WINDOW_DAYS, count( $rollups['days'] ) );
		$this->assertArrayNotHasKey( '2026-01-01', $rollups['days'] );
	}

	public function test_off_page_shows_enable_prompt_not_roster(): void {
		$_GET['page'] = Carbon::PAGE_SLUG;
		ob_start();
		Carbon::render_page();
		$html = ob_get_clean();
		$this->assertStringContainsString( 'Sustainability ledger is off', $html );
		$this->assertStringNotContainsString( 'By plugin (estimates)', $html );
		unset( $_GET['page'] );
	}

	public function test_enabled_page_shows_estimate_framing(): void {
		Carbon::save_settings( array( 'enabled' => true ) );
		$now = strtotime( '2026-10-12 12:00:00 UTC' );
		$log = array(
			array(
				'ts'            => $now,
				'plugin'        => 'alpha/alpha.php',
				'provider'      => 'openai',
				'model'         => 'gpt-4o-mini',
				'decision'      => 'allow',
				'operation'     => 'generate_text',
				'input_tokens'  => 1_000_000,
				'output_tokens' => 0,
			),
		);
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
		Carbon::rebuild_rollups( $log, $now, true );
		$_GET['page'] = Carbon::PAGE_SLUG;
		ob_start();
		Carbon::render_page();
		$html = ob_get_clean();
		$this->assertStringContainsString( 'Estimate, directional', $html );
		$this->assertStringContainsString( 'not compliance-grade', $html );
		$this->assertStringContainsString( 'alpha/alpha.php', $html );
		unset( $_GET['page'] );
	}
}
