<?php
/**
 * AICAC-SUCCESSION (#407).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Succession;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class SuccessionTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12.

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_users']            = array(
			1 => array(
				'ID'         => 1,
				'user_email' => 'haktan+aicac-succession@handldigital.com',
				'user_login' => 'haktan',
				'allcaps'    => array( 'manage_options' => true ),
			),
			2 => array(
				'ID'         => 2,
				'user_email' => 'editor@example.com',
				'user_login' => 'editor',
				'allcaps'    => array( 'manage_options' => false, 'edit_posts' => true ),
			),
		);
		Succession::reset_for_tests();
		update_option( 'admin_email', 'haktan+aicac-succession@handldigital.com' );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'haktan+aicac-succession@handldigital.com',
			)
		);
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_filters'][ Succession::FILTER_SOURCES ],
			$GLOBALS['handl_aicac_test_current_user_can'],
			$GLOBALS['handl_aicac_test_users'],
			$GLOBALS['handl_aicac_test_unattended_state']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		Succession::reset_for_tests();
		parent::tearDown();
	}

	private function enable(): void {
		Succession::save_settings( array( 'enabled' => true ) );
	}

	public function test_defaults_off_save_defaults_deletes_and_noop_byte_identical(): void {
		$this->assertFalse( Succession::is_enabled() );
		$this->assertSame( Succession::defaults(), Succession::get_settings() );

		$this->assertTrue( Succession::save_settings( array( 'enabled' => true ) ) );
		$this->assertTrue( Succession::is_enabled() );
		$before  = get_option( Succession::SETTINGS_OPTION );
		$changed = Succession::save_settings( array( 'enabled' => true ) );
		$this->assertFalse( $changed );
		$this->assertSame( $before, get_option( Succession::SETTINGS_OPTION ) );

		Succession::save_settings( Succession::defaults() );
		$this->assertFalse( (bool) get_option( Succession::SETTINGS_OPTION, false ) );
	}

	public function test_spof_when_entire_suite_routes_to_one_human(): void {
		$this->enable();
		$humans = Succession::distinct_humans();
		$this->assertCount( 1, $humans );
		$this->assertTrue( Succession::is_spof( $humans ) );
		$this->assertSame( 'haktan+aicac-succession@handldigital.com', $humans[0]['email'] );
		$this->assertSame( 'user', $humans[0]['match'] );
		$this->assertContains( 'denial', $humans[0]['controls'] );
	}

	public function test_second_destination_clears_spof(): void {
		$this->enable();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'        => 'allow',
				'log_enabled'    => true,
				'alert_email'    => 'haktan+aicac-succession@handldigital.com',
				'alert_routing'  => array(
					'budget' => 'backup-owner@example.com',
				),
			)
		);
		$humans = Succession::distinct_humans();
		$emails = array_column( $humans, 'email' );
		$this->assertContains( 'haktan+aicac-succession@handldigital.com', $emails );
		$this->assertContains( 'backup-owner@example.com', $emails );
		$this->assertFalse( Succession::is_spof( $humans ) );
	}

	public function test_lost_manage_options_is_dead_finding(): void {
		$this->enable();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'alert_email' => 'editor@example.com',
			)
		);
		update_option( 'admin_email', 'editor@example.com' );
		$dead = Succession::dead_findings();
		$reasons = array_column( $dead, 'reason' );
		$this->assertContains( 'lost_manage_options', $reasons );
		$this->assertSame( 'editor@example.com', $dead[0]['email'] );
	}

	public function test_deleted_user_via_known_users_state(): void {
		$this->enable();
		Succession::put_state(
			array(
				'alerted'     => false,
				'known_users' => array(
					'ghost@example.com' => 99,
				),
				'history'     => array(),
			)
		);
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'alert_email' => 'ghost@example.com',
			)
		);
		update_option( 'admin_email', 'ghost@example.com' );
		$dead = Succession::dead_findings();
		$this->assertNotEmpty( $dead );
		$this->assertSame( 'deleted_user', $dead[0]['reason'] );
		$this->assertSame( 'ghost@example.com', $dead[0]['email'] );
	}

	public function test_alert_fires_once_to_every_destination_and_rearms(): void {
		$this->enable();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'       => 'allow',
				'alert_email'   => 'haktan+aicac-succession@handldigital.com',
				'alert_routing' => array(
					'drift' => 'second@example.com',
				),
			)
		);
		// Two humans, but editor lost manage_options on second destination? Keep second unmatched external — SPOF false, no dead → no alert.
		// Force dead via lost manage on second matched user:
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'       => 'allow',
				'alert_email'   => 'haktan+aicac-succession@handldigital.com',
				'alert_routing' => array(
					'drift' => 'editor@example.com',
				),
			)
		);

		$this->assertTrue( Succession::maybe_fire_alerts( self::NOW ) );
		$mails = Succession::test_mails();
		$this->assertGreaterThanOrEqual( 2, count( $mails ) );
		$tos = array_column( $mails, 'to' );
		$this->assertContains( 'haktan+aicac-succession@handldigital.com', $tos );
		$this->assertContains( 'editor@example.com', $tos );
		$this->assertStringContainsString( '[SUCCESSION]', $mails[0]['subject'] );
		$this->assertStringContainsString( 'Report only — never rewrites recipients', $mails[0]['body'] );
		$this->assertTrue( Succession::is_alerted() );

		$before = count( Succession::test_mails() );
		$this->assertFalse( Succession::maybe_fire_alerts( self::NOW ) );
		$this->assertCount( $before, Succession::test_mails() );

		// Clear dead + SPOF by routing to two healthy manage users.
		$GLOBALS['handl_aicac_test_users'][3] = array(
			'ID'         => 3,
			'user_email' => 'second-admin@example.com',
			'user_login' => 'second',
			'allcaps'    => array( 'manage_options' => true ),
		);
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'       => 'allow',
				'alert_email'   => 'haktan+aicac-succession@handldigital.com',
				'alert_routing' => array(
					'drift' => 'second-admin@example.com',
				),
			)
		);
		Succession::put_state(
			array(
				'alerted'     => true,
				'known_users' => array(),
				'history'     => array(),
			)
		);
		$this->assertFalse( Succession::is_spof() );
		$this->assertSame( array(), Succession::dead_findings() );
		$this->assertFalse( Succession::maybe_fire_alerts( self::NOW + 10 ) );
		$this->assertFalse( Succession::is_alerted() );
	}

	public function test_csv_contains_roster_and_framing(): void {
		$this->enable();
		$csv = Succession::csv_for_snapshot( Succession::snapshot( self::NOW ) );
		$this->assertStringContainsString( 'section,email,user_id,match,controls_or_reason,url,framing', $csv );
		$this->assertStringContainsString( 'haktan+aicac-succession@handldigital.com', $csv );
		$this->assertStringContainsString( Succession::FRAMING, $csv );
		$this->assertStringContainsString( 'spof', $csv );
	}

	public function test_recipient_sources_filter(): void {
		$GLOBALS['handl_aicac_test_filters'][ Succession::FILTER_SOURCES ] = static function ( array $sources ): array {
			return array(
				array(
					'control'        => 'custom',
					'option'         => Plugin::OPTION_KEY,
					'field'          => 'alert_email',
					'kind'           => 'policy_field',
					'page'           => 'handl-aicac',
					'fallback_admin' => true,
					'label'          => 'Custom',
				),
			);
		};
		$sources = Succession::recipient_sources();
		$this->assertCount( 1, $sources );
		$this->assertSame( 'custom', $sources[0]['control'] );
	}
}
