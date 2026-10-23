<?php
/**
 * AICAC-AI-ACT (#391).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Ai_Act;
use HandL\AICAC\Disclosure;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class AiActTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Ai_Act::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => false,
				'audit_only'  => false,
				'alert_email' => '',
				'plugins'     => array(),
			)
		);
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_filters'][ Ai_Act::FILTER_OBLIGATIONS ],
			$GLOBALS['handl_aicac_test_current_user_can']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		Ai_Act::reset_for_tests();
		parent::tearDown();
	}

	public function test_defaults_off_and_save_defaults_deletes_option(): void {
		$this->assertFalse( Ai_Act::is_enabled() );
		$this->assertSame( Ai_Act::defaults(), Ai_Act::get_settings() );
		Ai_Act::save_settings( array( 'enabled' => true ) );
		$this->assertTrue( Ai_Act::is_enabled() );
		Ai_Act::save_settings( array( 'enabled' => false ) );
		$this->assertFalse( (bool) get_option( Ai_Act::SETTINGS_OPTION, false ) );
	}

	public function test_filter_override_and_staleness(): void {
		$GLOBALS['handl_aicac_test_filters'][ Ai_Act::FILTER_OBLIGATIONS ] = static function (): array {
			return array(
				'shipped' => '2026-11-01',
				'items'   => array(
					array(
						'id'      => 'custom_one',
						'article' => '26',
						'label'   => 'Custom',
						'summary' => 'Custom row',
						'control' => 'alerts',
					),
				),
			);
		};
		$table = Ai_Act::obligations();
		$this->assertSame( '2026-11-01', $table['shipped'] );
		$this->assertCount( 1, $table['items'] );
		$age = strtotime( '2026-11-01 UTC' );
		$this->assertSame( $age, Ai_Act::table_age_ts() );
		$this->assertFalse( Ai_Act::is_table_stale( $age + ( 30 * DAY_IN_SECONDS ) ) );
		$this->assertTrue( Ai_Act::is_table_stale( $age + ( 121 * DAY_IN_SECONDS ) ) );
	}

	public function test_readiness_reacts_to_live_config(): void {
		Ai_Act::save_settings( array( 'enabled' => true ) );
		$empty = Ai_Act::readiness_roster();
		$by_id = array();
		foreach ( $empty as $row ) {
			$by_id[ $row['id'] ] = $row;
		}
		$this->assertSame( Ai_Act::STATUS_MISSING, $by_id['art26_record_keeping']['status'] );
		$this->assertSame( Ai_Act::STATUS_MISSING, $by_id['art26_monitoring_alerts']['status'] );
		$this->assertSame( Ai_Act::STATUS_MISSING, $by_id['art26_instructions_use']['status'] );
		$this->assertSame( Ai_Act::STATUS_MISSING, $by_id['art50_transparency']['status'] );

		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'          => 'deny',
				'log_enabled'      => true,
				'audit_only'       => false,
				'log_max_age_days' => 30,
				'alert_email'      => 'haktan+aicac-ai-act@handldigital.com',
				Disclosure::POLICY_PRIVACY_KEY => true,
				'plugins'          => array(),
			)
		);
		$full = Ai_Act::readiness_roster();
		$by   = array();
		foreach ( $full as $row ) {
			$by[ $row['id'] ] = $row;
		}
		$this->assertSame( Ai_Act::STATUS_MET, $by['art26_record_keeping']['status'] );
		$this->assertSame( Ai_Act::STATUS_MET, $by['art26_log_retention']['status'] );
		$this->assertSame( Ai_Act::STATUS_MET, $by['art26_instructions_use']['status'] );
		$this->assertSame( Ai_Act::STATUS_MET, $by['art26_monitoring_alerts']['status'] );
		$this->assertSame( Ai_Act::STATUS_MET, $by['art50_transparency']['status'] );
		$this->assertNotSame( '', $by['art26_record_keeping']['link'] );

		$gaps = Ai_Act::gap_list( $full );
		foreach ( $gaps as $gap ) {
			$this->assertContains( $gap['control'], array( 'spot_check', 'register' ) );
		}
	}

	public function test_partial_retention_and_gate(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => '',
				'plugins'     => array(
					'alpha/alpha.php' => 'allow',
				),
			)
		);
		$roster = Ai_Act::readiness_roster();
		$by     = array();
		foreach ( $roster as $row ) {
			$by[ $row['id'] ] = $row;
		}
		$this->assertSame( Ai_Act::STATUS_PARTIAL, $by['art26_log_retention']['status'] );
		$this->assertSame( Ai_Act::STATUS_PARTIAL, $by['art26_instructions_use']['status'] );
	}

	public function test_csv_includes_framing_and_matches_roster(): void {
		Ai_Act::save_settings( array( 'enabled' => true ) );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'deny',
				'log_enabled' => true,
				'alert_email' => 'haktan+aicac-ai-act@handldigital.com',
			)
		);
		$roster = Ai_Act::readiness_roster();
		$csv    = Ai_Act::csv_for_roster( $roster );
		$this->assertStringContainsString( 'inventory_not_legal_advice', $csv );
		$this->assertStringContainsString( 'art26_record_keeping', $csv );
		$this->assertStringContainsString( "\n", $csv );
		$this->assertGreaterThan( count( $roster ), substr_count( $csv, "\n" ) );
	}

	public function test_render_off_shows_enable_copy(): void {
		Ai_Act::save_settings( array( 'enabled' => false ) );
		$_GET['page'] = Ai_Act::PAGE_SLUG;
		ob_start();
		Ai_Act::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'AI Act readiness inventory is off', $html );
		$this->assertStringNotContainsString( 'Obligation readiness', $html );
	}

	public function test_render_on_shows_inventory_framing(): void {
		Ai_Act::save_settings( array( 'enabled' => true ) );
		$_GET['page'] = Ai_Act::PAGE_SLUG;
		ob_start();
		Ai_Act::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Inventory, not legal advice', $html );
		$this->assertStringContainsString( 'Obligation readiness', $html );
		$this->assertStringContainsString( 'Gaps (not configured)', $html );
	}

	public function test_status_counts(): void {
		$roster = array(
			array( 'status' => Ai_Act::STATUS_MET ),
			array( 'status' => Ai_Act::STATUS_PARTIAL ),
			array( 'status' => Ai_Act::STATUS_MISSING ),
			array( 'status' => Ai_Act::STATUS_MISSING ),
		);
		$counts = Ai_Act::status_counts( $roster );
		$this->assertSame( 1, $counts['met'] );
		$this->assertSame( 1, $counts['partial'] );
		$this->assertSame( 2, $counts['not_configured'] );
		$this->assertSame( 4, $counts['total'] );
	}
}
