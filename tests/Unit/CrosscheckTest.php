<?php
/**
 * AICAC-CROSSCHECK (#409).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Budget;
use HandL\AICAC\Crosscheck;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class CrosscheckTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12.

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Crosscheck::reset_for_tests();
		update_option( 'admin_email', 'haktan+aicac-crosscheck@handldigital.com' );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'haktan+aicac-crosscheck@handldigital.com',
			)
		);
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_test_filters'][ Crosscheck::FILTER_RULES ] );
		$GLOBALS['handl_aicac_test_options'] = array();
		Crosscheck::reset_for_tests();
		parent::tearDown();
	}

	private function enable(): void {
		Crosscheck::save_settings( array( 'enabled' => true ) );
	}

	public function test_defaults_off_save_defaults_deletes_and_noop_byte_identical(): void {
		$this->assertFalse( Crosscheck::is_enabled() );
		$this->assertSame( Crosscheck::defaults(), Crosscheck::get_settings() );

		$this->assertTrue( Crosscheck::save_settings( array( 'enabled' => true ) ) );
		$this->assertTrue( Crosscheck::is_enabled() );
		$before  = get_option( Crosscheck::SETTINGS_OPTION );
		$changed = Crosscheck::save_settings( array( 'enabled' => true ) );
		$this->assertFalse( $changed );
		$this->assertSame( $before, get_option( Crosscheck::SETTINGS_OPTION ) );

		Crosscheck::save_settings( Crosscheck::defaults() );
		$this->assertFalse( (bool) get_option( Crosscheck::SETTINGS_OPTION, false ) );
	}

	public function test_clean_policy_has_no_findings(): void {
		$this->enable();
		$findings = Crosscheck::findings();
		$this->assertSame( array(), $findings );
	}

	public function test_spend_threshold_vs_budget_threshold_ordering(): void {
		$this->enable();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'                 => 'allow',
				'log_enabled'             => true,
				'plugin_budgets'          => array( 'demo/demo.php' => 10.0 ),
				'spend_threshold_plugins' => array( 'demo/demo.php' => 12.0 ),
				'alert_email'             => 'haktan+aicac-crosscheck@handldigital.com',
			)
		);
		$ids = array_column( Crosscheck::findings(), 'id' );
		$this->assertContains( 'spend_threshold_vs_budget', $ids );
	}

	public function test_anomaly_retention_window_contradiction(): void {
		$this->enable();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'                => 'allow',
				'log_enabled'            => true,
				'anomaly_alert_enabled'  => true,
				'log_max_age_days'       => 3,
				'alert_email'            => 'haktan+aicac-crosscheck@handldigital.com',
			)
		);
		$ids = array_column( Crosscheck::findings(), 'id' );
		$this->assertContains( 'anomaly_retention_window', $ids );
	}

	public function test_shadow_block_without_logging_enforce_without_feed(): void {
		$this->enable();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'              => 'allow',
				'log_enabled'          => false,
				'audit_only'           => false,
				'shadow_block_enabled' => true,
				'alert_email'          => 'haktan+aicac-crosscheck@handldigital.com',
			)
		);
		$ids = array_column( Crosscheck::findings(), 'id' );
		$this->assertContains( 'shadow_block_without_logging', $ids );
	}

	public function test_shadow_exceptions_orphaned_subtoggle(): void {
		$this->enable();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'                  => 'allow',
				'log_enabled'              => true,
				'shadow_block_enabled'     => false,
				'shadow_block_exceptions'  => array( 'other/plugin.php' ),
				'alert_email'              => 'haktan+aicac-crosscheck@handldigital.com',
			)
		);
		$ids = array_column( Crosscheck::findings(), 'id' );
		$this->assertContains( 'shadow_exceptions_orphaned', $ids );
	}

	public function test_weekly_report_without_logging_impossible_schedule(): void {
		$this->enable();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'                => 'allow',
				'log_enabled'            => false,
				'weekly_report_enabled'  => true,
				'alert_email'            => 'haktan+aicac-crosscheck@handldigital.com',
			)
		);
		$ids = array_column( Crosscheck::findings(), 'id' );
		$this->assertContains( 'weekly_report_without_logging', $ids );
	}

	public function test_rate_cap_hour_gt_day(): void {
		$this->enable();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'                 => 'allow',
				'log_enabled'             => true,
				'plugin_rate_caps_hour'   => array( 'demo/demo.php' => 100 ),
				'plugin_rate_caps_day'    => array( 'demo/demo.php' => 50 ),
				'alert_email'             => 'haktan+aicac-crosscheck@handldigital.com',
			)
		);
		$ids = array_column( Crosscheck::findings(), 'id' );
		$this->assertContains( 'rate_cap_hour_gt_day', $ids );
	}

	public function test_budget_deny_without_amount(): void {
		$this->enable();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'              => 'allow',
				'log_enabled'          => true,
				'plugin_budget_modes'  => array( 'demo/demo.php' => Budget::MODE_DENY ),
				'alert_email'          => 'haktan+aicac-crosscheck@handldigital.com',
			)
		);
		$ids = array_column( Crosscheck::findings(), 'id' );
		$this->assertContains( 'budget_deny_without_amount', $ids );
	}

	public function test_alert_fires_once_and_rearms(): void {
		$this->enable();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'              => 'allow',
				'log_enabled'          => false,
				'audit_only'           => false,
				'shadow_block_enabled' => true,
				'alert_email'          => 'haktan+aicac-crosscheck@handldigital.com',
			)
		);

		$this->assertTrue( Crosscheck::maybe_fire_alerts( self::NOW ) );
		$mails = Crosscheck::test_mails();
		$this->assertNotEmpty( $mails );
		$this->assertStringContainsString( '[CROSSCHECK]', $mails[0]['subject'] );
		$this->assertStringContainsString( 'never auto-fixes', $mails[0]['body'] );
		$this->assertTrue( Crosscheck::is_alerted() );

		$before = count( Crosscheck::test_mails() );
		$this->assertFalse( Crosscheck::maybe_fire_alerts( self::NOW ) );
		$this->assertCount( $before, Crosscheck::test_mails() );

		// Clear contradictions → re-arm.
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'alert_email' => 'haktan+aicac-crosscheck@handldigital.com',
			)
		);
		Crosscheck::put_state(
			array(
				'alerted' => true,
				'history' => array(),
			)
		);
		$this->assertSame( array(), Crosscheck::findings() );
		$this->assertFalse( Crosscheck::maybe_fire_alerts( self::NOW + 10 ) );
		$this->assertFalse( Crosscheck::is_alerted() );
	}

	public function test_csv_contains_roster_and_framing(): void {
		$this->enable();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'              => 'allow',
				'log_enabled'          => false,
				'shadow_block_enabled' => true,
				'alert_email'          => 'haktan+aicac-crosscheck@handldigital.com',
			)
		);
		$csv = Crosscheck::csv_for_snapshot( Crosscheck::snapshot( self::NOW ) );
		$this->assertStringContainsString( 'section,id,class,severity,finding,url,framing', $csv );
		$this->assertStringContainsString( 'shadow_block_without_logging', $csv );
		$this->assertStringContainsString( Crosscheck::FRAMING, $csv );
	}

	public function test_rules_filter(): void {
		$GLOBALS['handl_aicac_test_filters'][ Crosscheck::FILTER_RULES ] = static function ( array $rules ): array {
			return array(
				array(
					'id'       => 'custom_always',
					'class'    => 'threshold_ordering',
					'severity' => 'error',
					'page'     => 'handl-aicac',
					'finding'  => 'Custom contradiction',
					'check'    => static function (): bool {
						return true;
					},
					'options'  => array( Plugin::OPTION_KEY ),
				),
			);
		};
		$this->enable();
		$ids = array_column( Crosscheck::findings(), 'id' );
		$this->assertSame( array( 'custom_always' ), $ids );
	}

	public function test_writes_confined_to_own_options(): void {
		$this->enable();
		$before = get_option( Plugin::OPTION_KEY );
		Crosscheck::snapshot( self::NOW );
		Crosscheck::maybe_fire_alerts( self::NOW );
		$this->assertSame( $before, get_option( Plugin::OPTION_KEY ) );
		$this->assertNotFalse( get_option( Crosscheck::SETTINGS_OPTION, false ) );
		$this->assertNotFalse( get_option( Crosscheck::STATE_OPTION, false ) );
	}
}
