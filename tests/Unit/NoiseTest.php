<?php
/**
 * AICAC-NOISE (#405).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Noise;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class NoiseTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12.

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Noise::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'haktan+aicac-noise@handldigital.com',
			)
		);
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_filters'][ Noise::FILTER_BUDGET ],
			$GLOBALS['handl_aicac_test_filters'][ Noise::FILTER_WALLPAPER_WEEKS ],
			$GLOBALS['handl_aicac_test_current_user_can']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		Noise::reset_for_tests();
		parent::tearDown();
	}

	private function enable( int $budget = 10, int $wallpaper_weeks = 4 ): void {
		Noise::save_settings(
			array(
				'enabled'         => true,
				'budget_per_week' => $budget,
				'wallpaper_weeks' => $wallpaper_weeks,
			)
		);
	}

	public function test_defaults_off_save_defaults_deletes_and_noop_byte_identical(): void {
		$this->assertFalse( Noise::is_enabled() );
		$this->assertSame( Noise::defaults(), Noise::get_settings() );
		$this->assertSame( 10, Noise::defaults()['budget_per_week'] );

		$this->assertTrue(
			Noise::save_settings(
				array(
					'enabled'         => true,
					'budget_per_week' => 10,
					'wallpaper_weeks' => 4,
				)
			)
		);
		$this->assertTrue( Noise::is_enabled() );
		$before  = get_option( Noise::SETTINGS_OPTION );
		$changed = Noise::save_settings(
			array(
				'enabled'         => true,
				'budget_per_week' => 10,
				'wallpaper_weeks' => 4,
			)
		);
		$this->assertFalse( $changed );
		$this->assertSame( $before, get_option( Noise::SETTINGS_OPTION ) );

		Noise::save_settings( Noise::defaults() );
		$this->assertFalse( (bool) get_option( Noise::SETTINGS_OPTION, false ) );
	}

	public function test_budget_sanitize_and_filter(): void {
		$this->assertSame( 1, Noise::sanitize_budget( 0 ) );
		$this->assertSame( 1000, Noise::sanitize_budget( 999999 ) );
		$this->assertSame( 10, Noise::sanitize_budget( 'nope' ) );

		$this->enable( 7 );
		$this->assertSame( 7, Noise::budget_per_week() );
		$GLOBALS['handl_aicac_test_filters'][ Noise::FILTER_BUDGET ] = static function (): int {
			return 12;
		};
		$this->assertSame( 12, Noise::budget_per_week() );
	}

	public function test_disabled_listener_is_noop(): void {
		$this->assertFalse( Noise::is_enabled() );
		Noise::on_alert_sent( 'footprint', array( 'ts' => self::NOW ) );
		$this->assertSame( array(), Noise::get_state()['ledger'] );
	}

	public function test_control_from_label_subject_and_slug(): void {
		$this->assertSame( 'footprint', Noise::control_from_label( '[Example] [FOOTPRINT] over budget' ) );
		$this->assertSame( 'noise', Noise::control_from_label( '[Example] [NOISE] volume' ) );
		$this->assertSame( 'alert', Noise::control_from_label( '[Example] HandL blocked an AI Client call' ) );
		$this->assertSame( 'drill', Noise::control_from_label( 'drill' ) );
	}

	public function test_wallpaper_four_consecutive_weeks_fixture_driven(): void {
		$this->enable( 100, 4 );
		// Four Mondays of consecutive ISO weeks ending at NOW's week.
		$weeks = Noise::week_keys_ending_at( self::NOW, 4 );
		$this->assertCount( 4, $weeks );

		$ledger = array();
		foreach ( $weeks as $i => $week ) {
			// Mid-week timestamp inside each ISO week (approx).
			$ts       = self::NOW - ( ( 3 - $i ) * 7 * 86400 );
			$ledger[] = array(
				'control' => 'dormant',
				'ts'      => $ts,
			);
		}
		// One-off control missing a week → not wallpaper.
		$ledger[] = array(
			'control' => 'went_ai',
			'ts'      => self::NOW,
		);

		$findings = Noise::wallpaper_findings( self::NOW, $ledger );
		$controls = array_column( $findings, 'control' );
		$this->assertContains( 'dormant', $controls );
		$this->assertNotContains( 'went_ai', $controls );
		$this->assertSame( 4, $findings[0]['weeks'] );
		$this->assertStringContainsString( 'page=', $findings[0]['url'] );
	}

	public function test_alert_fires_once_rearms_when_under_budget_and_self_accounts(): void {
		$this->enable( 2, 12 ); // high wallpaper threshold so only budget matters.
		Noise::append_ledger( 'footprint', self::NOW );
		Noise::append_ledger( 'drill', self::NOW );
		Noise::append_ledger( 'key_age', self::NOW ); // 3 > 2.

		$this->assertTrue( Noise::is_over_budget( self::NOW ) );
		$this->assertTrue( Noise::maybe_fire_alerts( self::NOW ) );
		$mails = Noise::test_mails();
		$this->assertCount( 1, $mails );
		$this->assertStringContainsString( '[NOISE]', $mails[0]['subject'] );
		$this->assertStringContainsString( 'haktan+aicac-noise@handldigital.com', $mails[0]['to'] );
		$this->assertStringContainsString( 'Report only — never auto-tunes', $mails[0]['body'] );
		$this->assertTrue( Noise::is_alerted() );

		// Self-account: production Alerts::safe_wp_mail fires handl_aicac_alert_sent; bootstrap has no do_action.
		$this->assertSame( 'noise', Noise::control_from_label( $mails[0]['subject'] ) );
		Noise::on_alert_sent( $mails[0]['subject'], array( 'ts' => self::NOW ) );
		$this->assertContains( 'noise', array_column( Noise::get_state()['ledger'], 'control' ) );

		$this->assertFalse( Noise::maybe_fire_alerts( self::NOW ) );
		$this->assertCount( 1, Noise::test_mails() );

		// Clear ledger under budget → re-arm.
		Noise::put_state(
			array(
				'alerted' => true,
				'ledger'  => array(
					array(
						'control' => 'drill',
						'ts'      => self::NOW,
					),
				),
				'history' => array(),
			)
		);
		$this->assertFalse( Noise::is_over_budget( self::NOW ) );
		$this->assertFalse( Noise::maybe_fire_alerts( self::NOW ) );
		$this->assertFalse( Noise::is_alerted() );

		// Over again → second alert.
		Noise::append_ledger( 'footprint', self::NOW );
		Noise::append_ledger( 'unattended', self::NOW );
		$this->assertTrue( Noise::maybe_fire_alerts( self::NOW ) );
		$this->assertCount( 2, Noise::test_mails() );
	}

	public function test_csv_contains_roster_and_framing(): void {
		$this->enable( 10, 4 );
		Noise::append_ledger( 'footprint', self::NOW );
		Noise::append_ledger( 'footprint', self::NOW + 10 );
		Noise::append_ledger( 'drill', self::NOW + 20 );
		$csv = Noise::csv_for_snapshot( Noise::snapshot( self::NOW ) );
		$this->assertStringContainsString( 'section,control,count,weeks,url,framing', $csv );
		$this->assertStringContainsString( 'footprint', $csv );
		$this->assertStringContainsString( 'drill', $csv );
		$this->assertStringContainsString( Noise::FRAMING, $csv );
	}

	public function test_cli_status_error_path_over_budget_or_wallpaper(): void {
		$this->enable( 1, 4 );
		Noise::append_ledger( 'alert', self::NOW );
		Noise::append_ledger( 'alert', self::NOW + 1 );
		$this->assertTrue( Noise::is_over_budget( self::NOW ) );

		$weeks  = Noise::week_keys_ending_at( self::NOW, 4 );
		$ledger = array();
		foreach ( $weeks as $i => $_week ) {
			$ledger[] = array(
				'control' => 'dormant',
				'ts'      => self::NOW - ( ( 3 - $i ) * 7 * 86400 ),
			);
		}
		$this->assertNotEmpty( Noise::wallpaper_findings( self::NOW, $ledger ) );
	}
}
