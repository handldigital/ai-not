<?php
/**
 * AICAC-FOOTPRINT (#401).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Footprint;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class FootprintTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Footprint::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'haktan+aicac-footprint@handldigital.com',
			)
		);
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_filters'][ Footprint::FILTER_BUDGET ],
			$GLOBALS['handl_aicac_test_current_user_can'],
			$GLOBALS['handl_aicac_footprint_test_rows'],
			$GLOBALS['handl_aicac_footprint_test_site_autoload_bytes'],
			$GLOBALS['handl_aicac_footprint_test_cron']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		Footprint::reset_for_tests();
		parent::tearDown();
	}

	private function enable( int $budget = 1024 ): void {
		Footprint::save_settings(
			array(
				'enabled'      => true,
				'budget_bytes' => $budget,
			)
		);
	}

	/**
	 * @return list<array{option_name:string,option_value:string,autoload:string}>
	 */
	private function seed_rows(): array {
		$rows = array(
			array(
				'option_name'  => 'handl_aicac_big',
				'option_value' => str_repeat( 'A', 5000 ),
				'autoload'     => 'yes',
			),
			array(
				'option_name'  => 'handl_aicac_mid',
				'option_value' => str_repeat( 'B', 3000 ),
				'autoload'     => 'yes',
			),
			array(
				'option_name'  => 'handl_aicac_small',
				'option_value' => str_repeat( 'C', 100 ),
				'autoload'     => 'no',
			),
		);
		// Pad to >10 for top-10 ordering.
		for ( $i = 0; $i < 10; $i++ ) {
			$rows[] = array(
				'option_name'  => 'handl_aicac_pad_' . $i,
				'option_value' => str_repeat( 'x', 50 + $i ),
				'autoload'     => 'no',
			);
		}
		$GLOBALS['handl_aicac_footprint_test_rows']                = $rows;
		$GLOBALS['handl_aicac_footprint_test_site_autoload_bytes'] = 16000;

		return $rows;
	}

	public function test_defaults_off_save_defaults_deletes_and_noop_byte_identical(): void {
		$this->assertFalse( Footprint::is_enabled() );
		$this->assertSame( Footprint::defaults(), Footprint::get_settings() );
		$this->assertSame( 524288, Footprint::defaults()['budget_bytes'] );

		$this->assertTrue(
			Footprint::save_settings(
				array(
					'enabled'      => true,
					'budget_bytes' => 524288,
				)
			)
		);
		$this->assertTrue( Footprint::is_enabled() );
		$before  = get_option( Footprint::SETTINGS_OPTION );
		$changed = Footprint::save_settings(
			array(
				'enabled'      => true,
				'budget_bytes' => 524288,
			)
		);
		$this->assertFalse( $changed );
		$this->assertSame( $before, get_option( Footprint::SETTINGS_OPTION ) );

		Footprint::save_settings( Footprint::defaults() );
		$this->assertFalse( (bool) get_option( Footprint::SETTINGS_OPTION, false ) );
	}

	public function test_budget_sanitize_and_filter(): void {
		$this->assertSame( 1024, Footprint::sanitize_budget_bytes( 10 ) );
		$this->assertSame( 104857600, Footprint::sanitize_budget_bytes( 999999999 ) );
		$this->assertSame( 524288, Footprint::sanitize_budget_bytes( 'nope' ) );

		$this->enable( 4096 );
		$this->assertSame( 4096, Footprint::budget_bytes() );
		$GLOBALS['handl_aicac_test_filters'][ Footprint::FILTER_BUDGET ] = static function (): int {
			return 8192;
		};
		$this->assertSame( 8192, Footprint::budget_bytes() );
	}

	public function test_inventory_from_injected_rows(): void {
		$this->seed_rows();
		$inv = Footprint::option_inventory();

		$this->assertSame( 13, $inv['option_count'] );
		$this->assertSame( 5000 + 3000, $inv['our_autoload_bytes'] );
		$this->assertSame( 5000 + 3000 + 100 + array_sum( range( 50, 59 ) ), $inv['our_total_bytes'] );
		$this->assertSame( 16000, $inv['site_autoload_bytes'] );
		$this->assertEqualsWithDelta( 8000 / 16000, $inv['autoload_share'], 0.0001 );

		$this->assertCount( 10, $inv['top10'] );
		$this->assertSame( 'handl_aicac_big', $inv['top10'][0]['option_name'] );
		$this->assertSame( 'handl_aicac_mid', $inv['top10'][1]['option_name'] );
		$this->assertSame( 5000, $inv['top10'][0]['bytes'] );
		$this->assertSame( 'yes', $inv['top10'][0]['autoload'] );
	}

	public function test_cron_inventory_from_injected_cron(): void {
		$GLOBALS['handl_aicac_footprint_test_cron'] = array(
			array(
				'hook'       => 'handl_aicac_weekly_report',
				'recurrence' => 'weekly',
				'next_run'   => 1791800000,
			),
			array(
				'hook'       => 'unrelated_cron',
				'recurrence' => 'daily',
				'next_run'   => 1791800100,
			),
			array(
				'hook'       => 'handl_aicac_rescan',
				'recurrence' => 'daily',
				'next_run'   => 1791800200,
			),
		);
		$crons = Footprint::cron_inventory();
		$this->assertCount( 2, $crons );
		$hooks = array_column( $crons, 'hook' );
		$this->assertContains( 'handl_aicac_weekly_report', $hooks );
		$this->assertContains( 'handl_aicac_rescan', $hooks );
		$this->assertNotContains( 'unrelated_cron', $hooks );
	}

	public function test_hot_path_table_includes_pre_http_request(): void {
		$table = Footprint::hot_path_table();
		$this->assertNotEmpty( $table );
		$hooks = array_column( $table, 'hook' );
		$this->assertContains( 'pre_http_request', $hooks );
		$classes = array_column( $table, 'class' );
		$this->assertContains( 'Shadow_AI', $classes );
		$this->assertContains( 'Mcp_Gate', $classes );
		$this->assertContains( 'Soft_Deny', $classes );
	}

	public function test_alert_fires_once_rearms_when_under_budget(): void {
		$this->enable( 1000 );
		$GLOBALS['handl_aicac_footprint_test_rows'] = array(
			array(
				'option_name'  => 'handl_aicac_heavy',
				'option_value' => str_repeat( 'Z', 2000 ),
				'autoload'     => 'yes',
			),
		);
		$GLOBALS['handl_aicac_footprint_test_site_autoload_bytes'] = 10000;

		$this->assertTrue( Footprint::is_over_budget() );
		$this->assertTrue( Footprint::maybe_fire_alerts() );
		$mails = Footprint::test_mails();
		$this->assertCount( 1, $mails );
		$this->assertStringContainsString( '[FOOTPRINT]', $mails[0]['subject'] );
		$this->assertStringContainsString( 'haktan+aicac-footprint@handldigital.com', $mails[0]['to'] );
		$this->assertStringContainsString( 'Report only — never changes options.', $mails[0]['body'] );
		$this->assertTrue( Footprint::is_alerted() );

		$this->assertFalse( Footprint::maybe_fire_alerts() );
		$this->assertCount( 1, Footprint::test_mails() );

		// Drop under budget → re-arm.
		$GLOBALS['handl_aicac_footprint_test_rows'] = array(
			array(
				'option_name'  => 'handl_aicac_light',
				'option_value' => str_repeat( 'z', 10 ),
				'autoload'     => 'yes',
			),
		);
		$this->assertFalse( Footprint::is_over_budget() );
		$this->assertFalse( Footprint::maybe_fire_alerts() );
		$this->assertFalse( Footprint::is_alerted() );

		// Over again → second alert.
		$GLOBALS['handl_aicac_footprint_test_rows'] = array(
			array(
				'option_name'  => 'handl_aicac_heavy',
				'option_value' => str_repeat( 'Z', 2000 ),
				'autoload'     => 'yes',
			),
		);
		$this->assertTrue( Footprint::maybe_fire_alerts() );
		$this->assertCount( 2, Footprint::test_mails() );
	}

	public function test_history_capped_and_recorded_on_snapshot(): void {
		$this->enable( 999999 );
		$GLOBALS['handl_aicac_footprint_test_rows'] = array(
			array(
				'option_name'  => 'handl_aicac_a',
				'option_value' => 'abc',
				'autoload'     => 'yes',
			),
		);
		$GLOBALS['handl_aicac_footprint_test_site_autoload_bytes'] = 100;

		$base = 1_700_000_000;
		for ( $i = 0; $i < 45; $i++ ) {
			// Vary totals so same-minute dedupe does not collapse entries.
			$GLOBALS['handl_aicac_footprint_test_rows'][0]['option_value'] = str_repeat( 'a', 10 + $i );
			Footprint::snapshot( $base + ( $i * 120 ) );
		}
		$history = Footprint::get_state()['history'];
		$this->assertCount( Footprint::HISTORY_CAP, $history );
		$this->assertSame( Footprint::HISTORY_CAP, count( $history ) );
	}

	public function test_csv_contains_option_names(): void {
		$this->seed_rows();
		$csv = Footprint::csv_for_inventory();
		$this->assertStringContainsString( 'option_name,bytes,autoload,framing', $csv );
		$this->assertStringContainsString( 'handl_aicac_big', $csv );
		$this->assertStringContainsString( 'handl_aicac_mid', $csv );
		$this->assertStringContainsString( Footprint::FRAMING, $csv );
	}

	public function test_cli_status_error_path_via_is_over_budget(): void {
		$this->enable( 1024 );
		$GLOBALS['handl_aicac_footprint_test_rows'] = array(
			array(
				'option_name'  => 'handl_aicac_over',
				'option_value' => str_repeat( 'O', 2000 ),
				'autoload'     => 'yes',
			),
		);
		$GLOBALS['handl_aicac_footprint_test_site_autoload_bytes'] = 10000;
		$this->assertTrue( Footprint::is_over_budget() );

		$GLOBALS['handl_aicac_footprint_test_rows'] = array(
			array(
				'option_name'  => 'handl_aicac_ok',
				'option_value' => 'x',
				'autoload'     => 'yes',
			),
		);
		$this->assertFalse( Footprint::is_over_budget() );
	}
}
