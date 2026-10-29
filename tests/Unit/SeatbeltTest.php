<?php
/**
 * AICAC-SEATBELT (#487) unit tests.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Freeze;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Policy_Snapshots;
use HandL\AICAC\Seatbelt;
use PHPUnit\Framework\TestCase;

final class SeatbeltTest extends TestCase {

	private const NOW = 1_700_100_000;

	/** @var list<array{0:mixed,1:string,2:string}> */
	private array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_cron'] = array();
		$this->mails                      = array();
		$GLOBALS['handl_aicac_wp_mail']   = function ( $to, $subject, $message ) {
			$this->mails[] = array( $to, $subject, $message );
			return true;
		};
		update_option( 'admin_email', 'admin@example.test' );

		Seatbelt::reset_for_tests();
		Seatbelt::set_test_now( self::NOW );
		Seatbelt::set_test_maintenance( false );
		delete_option( Freeze::OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Policy_Snapshots::OPTION_KEY );
		delete_option( Policy_Snapshots::HISTORY_OPTION_KEY );

		Policy::save_policy(
			array(
				'default'              => 'allow',
				'plugins'              => array( 'acme/acme.php' => 'allow' ),
				'kill_switch'          => false,
				'shadow_block_enabled' => false,
				'audit_only'           => false,
				'log_enabled'          => true,
				'alert_email'          => 'ops@example.test',
				'alert_on_deny'        => true,
			)
		);
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		Seatbelt::reset_for_tests();
		delete_option( Freeze::OPTION_KEY );
		parent::tearDown();
	}

	public function test_off_by_default_toggle_changes_nothing_outside_window(): void {
		$this->assertFalse( Seatbelt::is_enabled() );
		$this->assertFalse( Seatbelt::should_deny( self::NOW ) );

		$eval = Policy::evaluate( Policy::get_policy(), 'acme/acme.php', 'generate_text', array(), null, self::NOW );
		$this->assertFalse( $eval['prevent'] );

		Seatbelt::save_settings( array( 'enabled' => true ) );
		$this->assertTrue( Seatbelt::is_enabled() );
		$this->assertFalse( Seatbelt::should_deny( self::NOW ), 'enabled alone does not deny' );

		$eval2 = Policy::evaluate( Policy::get_policy(), 'acme/acme.php', 'generate_text', array(), null, self::NOW );
		$this->assertFalse( $eval2['prevent'] );
		$this->assertFalse( Freeze::is_active( self::NOW ) );
	}

	public function test_upgrader_window_denies_with_update_reason_and_summary(): void {
		Seatbelt::save_settings( array( 'enabled' => true, 'failsafe_seconds' => 600 ) );
		$before = Policy::get_policy();

		Seatbelt::on_upgrader_pre_install( true, array() );
		$this->assertTrue( Freeze::is_active( self::NOW ) );
		$this->assertTrue( Seatbelt::should_deny( self::NOW ) );

		$eval = Policy::evaluate( Policy::get_policy(), 'acme/acme.php', 'generate_text', array(), null, self::NOW );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( Seatbelt::REASON, $eval['reason'] );

		$eval2 = Policy::evaluate( Policy::get_policy(), 'acme/acme.php', 'generate_text', array(), null, self::NOW );
		$this->assertTrue( $eval2['prevent'] );

		$win = Seatbelt::get_window();
		$this->assertSame( 2, (int) $win['held_count'] );

		Seatbelt::set_test_now( self::NOW + 30 );
		Seatbelt::on_upgrader_process_complete( null, array() );

		$this->assertFalse( Freeze::is_active( self::NOW + 30 ) );
		$this->assertFalse( Seatbelt::should_deny( self::NOW + 30 ) );
		$this->assertSame( $before, Policy::get_policy(), 'AC3: prior policy restored byte-identical' );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $log );
		$summary = null;
		foreach ( array_reverse( $log ) as $row ) {
			if ( is_array( $row ) && 'seatbelt_window' === ( $row['decision'] ?? '' ) ) {
				$summary = $row;
				break;
			}
		}
		$this->assertNotNull( $summary );
		$this->assertSame( 2, (int) ( $summary['held'] ?? -1 ) );
		$this->assertSame( 'seatbelt', (string) ( $summary['channel'] ?? '' ) );
	}

	public function test_failsafe_expiry_restores_policy(): void {
		Seatbelt::save_settings( array( 'enabled' => true, 'failsafe_seconds' => 600 ) );
		$before = Policy::get_policy();

		Seatbelt::begin_window( 'upgrader', self::NOW );
		$this->assertTrue( Freeze::is_active( self::NOW ) );

		Seatbelt::set_test_now( self::NOW + 601 );
		$this->assertFalse( Seatbelt::should_deny( self::NOW + 601 ), 'failsafe closes window' );
		$this->assertFalse( Freeze::is_active( self::NOW + 601 ) );
		$this->assertSame( $before, Policy::get_policy() );
	}

	public function test_manual_panic_freeze_wins_seatbelt_release_does_not_unfreeze(): void {
		$now = self::NOW;
		$this->assertTrue( Freeze::start( 60, 'Spend spike', $now )['ok'] );
		$manual_before = Policy::get_policy();

		Seatbelt::save_settings( array( 'enabled' => true ) );
		Seatbelt::begin_window( 'upgrader', $now + 1 );

		$win = Seatbelt::get_window();
		$this->assertTrue( ! empty( $win['active'] ) );
		$this->assertTrue( ! empty( $win['deferred_manual'] ) );
		$this->assertFalse( ! empty( $win['owns_freeze'] ) );
		$this->assertFalse( Seatbelt::should_deny( $now + 1 ), 'deferred: seatbelt does not own reason' );

		// Kill switch from manual freeze still blocks.
		$eval = Policy::evaluate( Policy::get_policy(), 'acme/acme.php', 'generate_text', array(), null, $now + 1 );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( 'kill_switch', $eval['reason'] );

		Seatbelt::end_window( 'complete', $now + 2 );
		$this->assertTrue( Freeze::is_active( $now + 2 ), 'AC4: seatbelt release leaves manual freeze' );
		$this->assertSame( $manual_before, Policy::get_policy() );
	}

	public function test_maintenance_file_arms_and_clears_window(): void {
		Seatbelt::save_settings( array( 'enabled' => true ) );
		$before = Policy::get_policy();

		Seatbelt::set_test_maintenance( true );
		Seatbelt::sync_maintenance();
		$this->assertTrue( Seatbelt::should_deny( self::NOW ) );
		$this->assertTrue( Freeze::is_active( self::NOW ) );

		Seatbelt::set_test_maintenance( false );
		Seatbelt::set_test_now( self::NOW + 5 );
		Seatbelt::sync_maintenance();
		$this->assertFalse( Seatbelt::should_deny( self::NOW + 5 ) );
		$this->assertFalse( Freeze::is_active( self::NOW + 5 ) );
		$this->assertSame( $before, Policy::get_policy() );
	}
}
