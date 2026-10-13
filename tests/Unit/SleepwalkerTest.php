<?php
/**
 * AICAC-SLEEPWALKER (#429).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Sleepwalker;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class SleepwalkerTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12 UTC.

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$GLOBALS['handl_aicac_test_cron']             = array();
		Sleepwalker::reset_for_tests();
		update_option( 'admin_email', 'owner@prod.example.com' );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'alert_email' => 'alerts@example.com',
			)
		);
		Sleepwalker::set_test_now( self::NOW );
		Sleepwalker::set_test_policy(
			array(
				'default'     => 'allow',
				'alert_email' => 'alerts@example.com',
			)
		);
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_cron']          = array();
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		Sleepwalker::reset_for_tests();
		parent::tearDown();
	}

	private function enable( bool $outbound = false ): void {
		Sleepwalker::save_settings(
			array(
				'enabled'        => true,
				'outbound_alert' => $outbound,
				'window_days'    => 60,
			)
		);
	}

	public function test_defaults_off_and_constants(): void {
		$this->assertFalse( Sleepwalker::is_enabled() );
		$this->assertFalse( Sleepwalker::is_outbound_enabled() );
		$this->assertSame( 'report_only_never_tunes_thresholds', Sleepwalker::FRAMING );
		$this->assertSame( 'handl-aicac-sleepwalker', Sleepwalker::PAGE_SLUG );
		$this->assertSame( 'handl_aicac_sleepwalker', Sleepwalker::SETTINGS_OPTION );
		$this->assertSame( 'handl_aicac_sleepwalker_state', Sleepwalker::STATE_OPTION );
		$this->assertSame( Sleepwalker::defaults(), Sleepwalker::sanitize_settings( 'junk' ) );

		$this->assertTrue( Sleepwalker::save_settings( array( 'enabled' => true ) ) );
		$this->assertTrue( Sleepwalker::is_enabled() );
		$this->assertSame( 60, Sleepwalker::window_days() );
		$this->assertTrue( Sleepwalker::save_settings( Sleepwalker::defaults() ) );
		$this->assertFalse( (bool) get_option( Sleepwalker::SETTINGS_OPTION, false ) );
	}

	public function test_disabled_does_nothing(): void {
		$this->assertFalse( Sleepwalker::maybe_check( self::NOW, true ) );
		$this->assertFalse( Sleepwalker::maybe_fire_alerts( self::NOW ) );
		$this->assertFalse( get_option( Sleepwalker::STATE_OPTION, false ) );
	}

	public function test_registry_filterable(): void {
		$reg = Sleepwalker::bundled_registry();
		$this->assertNotEmpty( $reg );
		$ids = array_column( $reg, 'id' );
		$this->assertContains( 'plugin_budget', $ids );
		$this->assertContains( 'rate_cap_hour', $ids );
		$this->assertContains( 'anomaly_multiplier', $ids );

		$GLOBALS['handl_aicac_test_filters']['handl_aicac_sleepwalker_registry'] = static function ( $rows ) {
			$rows[] = array(
				'id'       => 'custom_cap',
				'label'    => 'Custom',
				'unit'     => 'calls',
				'observer' => 'custom_cap',
			);
			return $rows;
		};
		$ids2 = array_column( Sleepwalker::bundled_registry(), 'id' );
		$this->assertContains( 'custom_cap', $ids2 );
		unset( $GLOBALS['handl_aicac_test_filters']['handl_aicac_sleepwalker_registry'] );
	}

	public function test_verdicts_sleepwalk_and_fatigue(): void {
		$this->assertSame( Sleepwalker::VERDICT_SLEEPWALK, Sleepwalker::evaluate_verdict( 5000.0, 10.0, 38.0 ) );
		$this->assertSame( Sleepwalker::VERDICT_FATIGUE, Sleepwalker::evaluate_verdict( 50.0, 210.0, 400.0 ) );
		$this->assertSame( Sleepwalker::VERDICT_OK, Sleepwalker::evaluate_verdict( 100.0, 40.0, 80.0 ) );
	}

	public function test_distribution_and_summaries_include_numbers(): void {
		$dist = Sleepwalker::distribution( array( 10, 20, 30, 40 ) );
		$this->assertNotNull( $dist );
		$this->assertSame( 10.0, $dist['min'] );
		$this->assertSame( 25.0, $dist['median'] );
		$this->assertSame( 40.0, $dist['max'] );

		$summary = Sleepwalker::build_summary(
			'Monthly plugin budget',
			'acme/plugin.php',
			5000.0,
			'usd',
			Sleepwalker::VERDICT_SLEEPWALK,
			10.0,
			20.0,
			38.0,
			0,
			60,
			''
		);
		$this->assertStringContainsString( '$5,000', $summary );
		$this->assertStringContainsString( '$38', $summary );
		$this->assertStringContainsString( 'cannot fire', $summary );

		$fat = Sleepwalker::build_summary(
			'Visitor hour cap',
			'hour',
			50.0,
			'visitors',
			Sleepwalker::VERDICT_FATIGUE,
			100.0,
			210.0,
			400.0,
			1400,
			60,
			''
		);
		$this->assertStringContainsString( '50', $fat );
		$this->assertStringContainsString( '210', $fat );
		$this->assertStringContainsString( '1400', $fat );
	}

	public function test_findings_from_injected_census_and_ack_regime(): void {
		$this->enable();
		Sleepwalker::set_test_census(
			array(
				Sleepwalker::compose_row(
					array(
						'id'    => 'plugin_budget',
						'label' => 'Monthly plugin budget',
						'unit'  => 'usd',
					),
					'acme/x.php',
					5000.0,
					array( 10.0, 20.0, 38.0 ),
					0,
					'',
					60
				),
				Sleepwalker::compose_row(
					array(
						'id'    => 'rate_cap_hour',
						'label' => 'Plugin rate cap (hour)',
						'unit'  => 'calls',
					),
					'acme/x.php',
					100.0,
					array( 40.0, 50.0, 60.0 ),
					0,
					'',
					60
				),
			)
		);

		$findings = Sleepwalker::findings( self::NOW );
		$this->assertCount( 1, $findings );
		$this->assertSame( Sleepwalker::VERDICT_SLEEPWALK, $findings[0]['verdict'] );
		$this->assertStringContainsString( 'cannot fire', $findings[0]['summary'] );

		$key = (string) $findings[0]['key'];
		$this->assertGreaterThan( 0, Sleepwalker::acknowledge( array( $key ) ) );
		$this->assertSame( 0, count( Sleepwalker::findings( self::NOW ) ) );

		// Material regime change (max jumps toward threshold) re-arms.
		Sleepwalker::set_test_census(
			array(
				Sleepwalker::compose_row(
					array(
						'id'    => 'plugin_budget',
						'label' => 'Monthly plugin budget',
						'unit'  => 'usd',
					),
					'acme/x.php',
					5000.0,
					array( 10.0, 20.0, 2500.0 ),
					0,
					'',
					60
				),
			)
		);
		// 2500/5000 = 0.5 → still sleepwalk? SLEEPWALK_FRACTION is 0.1, so 2500 is OK not sleepwalk.
		$this->assertSame( 0, count( Sleepwalker::findings( self::NOW ) ) );

		Sleepwalker::set_test_census(
			array(
				Sleepwalker::compose_row(
					array(
						'id'    => 'plugin_budget',
						'label' => 'Monthly plugin budget',
						'unit'  => 'usd',
					),
					'acme/x.php',
					5000.0,
					array( 10.0, 20.0, 40.0 ),
					0,
					'',
					60
				),
			)
		);
		// Same regime bucket as first ack → stays quiet.
		$this->assertSame( 0, count( Sleepwalker::findings( self::NOW ) ) );

		// Threshold change produces new key.
		Sleepwalker::set_test_census(
			array(
				Sleepwalker::compose_row(
					array(
						'id'    => 'plugin_budget',
						'label' => 'Monthly plugin budget',
						'unit'  => 'usd',
					),
					'acme/x.php',
					100.0,
					array( 10.0, 20.0, 40.0 ),
					0,
					'',
					60
				),
			)
		);
		// max 40 vs threshold 100 → OK (40% > 10%), no finding
		$this->assertSame( 0, count( Sleepwalker::findings( self::NOW ) ) );

		Sleepwalker::set_test_census(
			array(
				Sleepwalker::compose_row(
					array(
						'id'    => 'plugin_budget',
						'label' => 'Monthly plugin budget',
						'unit'  => 'usd',
					),
					'acme/x.php',
					10000.0,
					array( 10.0, 20.0, 40.0 ),
					0,
					'',
					60
				),
			)
		);
		$again = Sleepwalker::findings( self::NOW );
		$this->assertNotEmpty( $again );
		$this->assertSame( Sleepwalker::VERDICT_SLEEPWALK, $again[0]['verdict'] );
	}

	public function test_one_rearming_alert(): void {
		$this->enable( true );
		$GLOBALS['handl_aicac_wp_mail'] = true;
		Sleepwalker::set_test_census(
			array(
				Sleepwalker::compose_row(
					array(
						'id'    => 'plugin_budget',
						'label' => 'Monthly plugin budget',
						'unit'  => 'usd',
					),
					'acme/x.php',
					5000.0,
					array( 10.0, 20.0, 38.0 ),
					0,
					'',
					60
				),
			)
		);

		$this->assertTrue( Sleepwalker::maybe_fire_alerts( self::NOW ) );
		$this->assertTrue( Sleepwalker::is_alerted() );
		$this->assertFalse( Sleepwalker::maybe_fire_alerts( self::NOW + 10 ), 'latched until re-arm' );

		$mails = Sleepwalker::test_mails();
		$this->assertNotEmpty( $mails );
		$this->assertStringContainsString( '[SLEEPWALKER]', (string) $mails[0]['subject'] );
		$this->assertStringContainsString( 'cannot fire', (string) $mails[0]['body'] );

		Sleepwalker::acknowledge( array_column( Sleepwalker::findings( self::NOW ), 'key' ) );
		$this->assertFalse( Sleepwalker::is_alerted() );
	}

	public function test_throttle_skips_within_window(): void {
		$this->enable();
		Sleepwalker::set_test_census( array() );
		$this->assertTrue( Sleepwalker::maybe_check( self::NOW, false ) );
		$this->assertFalse( Sleepwalker::maybe_check( self::NOW + 60, false ) );
		$this->assertTrue( Sleepwalker::maybe_check( self::NOW + 400, false ) );
	}

	public function test_csv_snapshot_and_cli_exit_shape(): void {
		$this->enable();
		Sleepwalker::set_test_census(
			array(
				Sleepwalker::compose_row(
					array(
						'id'    => 'plugin_budget',
						'label' => 'Monthly plugin budget',
						'unit'  => 'usd',
					),
					'acme/x.php',
					5000.0,
					array( 10.0, 20.0, 38.0 ),
					0,
					'',
					60
				),
			)
		);
		$snap = Sleepwalker::snapshot( self::NOW );
		$this->assertSame( 1, $snap['sleepwalking_count'] );
		$this->assertSame( 1, $snap['unacknowledged_count'] );
		$csv = Sleepwalker::csv_for_snapshot( $snap );
		$this->assertStringContainsString( 'census', $csv );
		$this->assertStringContainsString( 'finding', $csv );
		$this->assertStringContainsString( Sleepwalker::FRAMING, $csv );
		$this->assertCount( 1, Sleepwalker::sleepwalking_findings( self::NOW ) );
	}

	public function test_insufficient_history_is_not_a_finding(): void {
		$this->enable();
		$row = Sleepwalker::compose_row(
			array(
				'id'    => 'plugin_budget',
				'label' => 'Monthly plugin budget',
				'unit'  => 'usd',
			),
			'acme/x.php',
			5000.0,
			array(),
			0,
			'',
			60
		);
		$this->assertSame( Sleepwalker::VERDICT_INSUFFICIENT, $row['verdict'] );
		$this->assertStringContainsString( 'Not enough history', $row['summary'] );
		Sleepwalker::set_test_census( array( $row ) );
		$this->assertSame( 0, count( Sleepwalker::findings( self::NOW ) ) );
	}
}
