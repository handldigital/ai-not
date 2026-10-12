<?php
/**
 * AICAC-LIMBO (#411).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Limbo;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class LimboTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12.

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Limbo::reset_for_tests();
		update_option( 'admin_email', 'haktan+aicac-limbo@handldigital.com' );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'haktan+aicac-limbo@handldigital.com',
			)
		);
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_test_filters'][ Limbo::FILTER_SLA_DAYS ] );
		$GLOBALS['handl_aicac_test_options'] = array();
		Limbo::reset_for_tests();
		parent::tearDown();
	}

	private function enable( int $sla = 7 ): void {
		Limbo::save_settings(
			array(
				'enabled'  => true,
				'sla_days' => $sla,
			)
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	private function pending_row( string $id, int $created, string $plugin = 'demo/demo.php' ): array {
		return array(
			'id'          => $id,
			'plugin'      => $plugin,
			'user_id'     => 3,
			'user_login'  => 'editor',
			'reason'      => 'need access',
			'status'      => 'pending',
			'ts'          => $created,
			'resolved_ts' => 0,
			'resolved_by' => 0,
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	private function decided_row( string $id, int $created, int $resolved, string $status = 'approved' ): array {
		return array(
			'id'          => $id,
			'plugin'      => 'demo/demo.php',
			'user_id'     => 3,
			'user_login'  => 'editor',
			'reason'      => 'need access',
			'status'      => $status,
			'ts'          => $created,
			'resolved_ts' => $resolved,
			'resolved_by' => 1,
		);
	}

	public function test_defaults_off_save_defaults_deletes_and_noop_byte_identical(): void {
		$this->assertFalse( Limbo::is_enabled() );
		$this->assertSame( Limbo::defaults(), Limbo::get_settings() );
		$this->assertSame( 7, Limbo::defaults()['sla_days'] );

		$this->assertTrue( Limbo::save_settings( array( 'enabled' => true, 'sla_days' => 7 ) ) );
		$this->assertTrue( Limbo::is_enabled() );
		$before  = get_option( Limbo::SETTINGS_OPTION );
		$changed = Limbo::save_settings( array( 'enabled' => true, 'sla_days' => 7 ) );
		$this->assertFalse( $changed );
		$this->assertSame( $before, get_option( Limbo::SETTINGS_OPTION ) );

		Limbo::save_settings( Limbo::defaults() );
		$this->assertFalse( (bool) get_option( Limbo::SETTINGS_OPTION, false ) );
	}

	public function test_sla_sanitize_and_filter(): void {
		$this->assertSame( 1, Limbo::sanitize_sla_days( 0 ) );
		$this->assertSame( 365, Limbo::sanitize_sla_days( 9999 ) );
		$this->assertSame( 7, Limbo::sanitize_sla_days( 'nope' ) );

		$this->enable( 14 );
		$this->assertSame( 14, Limbo::sla_days() );
		$GLOBALS['handl_aicac_test_filters'][ Limbo::FILTER_SLA_DAYS ] = static function (): int {
			return 3;
		};
		$this->assertSame( 3, Limbo::sla_days() );
	}

	public function test_aging_roster_oldest_first_and_stale(): void {
		$day = DAY_IN_SECONDS;
		$this->enable( 7 );
		Limbo::set_test_requests(
			array(
				$this->pending_row( str_repeat( 'a', 32 ), self::NOW - ( 3 * $day ), 'new/new.php' ),
				$this->pending_row( str_repeat( 'b', 32 ), self::NOW - ( 10 * $day ), 'old/old.php' ),
				$this->pending_row( str_repeat( 'c', 32 ), self::NOW - ( 7 * $day ), 'edge/edge.php' ),
			)
		);

		$roster = Limbo::aging_roster( null, self::NOW );
		$this->assertCount( 3, $roster );
		$this->assertSame( str_repeat( 'b', 32 ), $roster[0]['id'] );
		$this->assertSame( 10, $roster[0]['days_in_limbo'] );
		$this->assertTrue( $roster[0]['stale'] );
		$this->assertSame( str_repeat( 'c', 32 ), $roster[1]['id'] );
		$this->assertTrue( $roster[1]['stale'] );
		$this->assertSame( str_repeat( 'a', 32 ), $roster[2]['id'] );
		$this->assertFalse( $roster[2]['stale'] );

		$stale = Limbo::stale_findings( null, self::NOW );
		$this->assertCount( 2, $stale );
		$this->assertSame( 'old/old.php', $stale[0]['plugin'] );
	}

	public function test_decision_stats_median_and_worst(): void {
		$day = DAY_IN_SECONDS;
		$this->enable( 7 );
		Limbo::set_test_requests(
			array(
				$this->decided_row( str_repeat( '1', 32 ), self::NOW - ( 20 * $day ), self::NOW - ( 18 * $day ) ), // 2d
				$this->decided_row( str_repeat( '2', 32 ), self::NOW - ( 15 * $day ), self::NOW - ( 5 * $day ) ), // 10d
				$this->decided_row( str_repeat( '3', 32 ), self::NOW - ( 12 * $day ), self::NOW - ( 8 * $day ) ), // 4d
				$this->pending_row( str_repeat( '4', 32 ), self::NOW - ( 1 * $day ) ),
			)
		);

		$stats = Limbo::decision_stats();
		$this->assertSame( 3, $stats['sample_count'] );
		$this->assertSame( 4 * $day, $stats['median_sec'] );
		$this->assertSame( 10 * $day, $stats['worst_sec'] );
		$this->assertSame( 4.0, $stats['median_days'] );
		$this->assertSame( 10.0, $stats['worst_days'] );
	}

	public function test_alert_fires_once_and_rearms_when_cleared(): void {
		$day = DAY_IN_SECONDS;
		$this->enable( 7 );
		Limbo::set_test_requests(
			array(
				$this->pending_row( str_repeat( 'd', 32 ), self::NOW - ( 12 * $day ), 'stuck/stuck.php' ),
			)
		);

		$this->assertTrue( Limbo::maybe_fire_alerts( self::NOW ) );
		$mails = Limbo::test_mails();
		$this->assertNotEmpty( $mails );
		$this->assertStringContainsString( '[LIMBO]', $mails[0]['subject'] );
		$this->assertStringContainsString( 'stuck/stuck.php', $mails[0]['body'] );
		$this->assertStringContainsString( 'never decides', $mails[0]['body'] );
		$this->assertTrue( Limbo::is_alerted() );

		$before = count( Limbo::test_mails() );
		$this->assertFalse( Limbo::maybe_fire_alerts( self::NOW ) );
		$this->assertCount( $before, Limbo::test_mails() );

		// Clear stale → re-arm.
		Limbo::set_test_requests(
			array(
				$this->pending_row( str_repeat( 'e', 32 ), self::NOW - ( 1 * $day ), 'fresh/fresh.php' ),
			)
		);
		$this->assertSame( array(), Limbo::stale_findings( null, self::NOW ) );
		$this->assertFalse( Limbo::maybe_fire_alerts( self::NOW + 10 ) );
		$this->assertFalse( Limbo::is_alerted() );

		// New stale can alert again.
		Limbo::set_test_requests(
			array(
				$this->pending_row( str_repeat( 'f', 32 ), self::NOW - ( 9 * $day ), 'again/again.php' ),
			)
		);
		$this->assertTrue( Limbo::maybe_fire_alerts( self::NOW + 20 ) );
		$this->assertCount( $before + 1, Limbo::test_mails() );
	}

	public function test_no_alert_when_pending_under_sla(): void {
		$day = DAY_IN_SECONDS;
		$this->enable( 7 );
		Limbo::set_test_requests(
			array(
				$this->pending_row( str_repeat( 'g', 32 ), self::NOW - ( 2 * $day ) ),
			)
		);
		$this->assertFalse( Limbo::maybe_fire_alerts( self::NOW ) );
		$this->assertCount( 0, Limbo::test_mails() );
	}

	public function test_csv_contains_roster_stats_and_framing(): void {
		$day = DAY_IN_SECONDS;
		$this->enable( 7 );
		Limbo::set_test_requests(
			array(
				$this->pending_row( str_repeat( 'h', 32 ), self::NOW - ( 9 * $day ), 'slow/slow.php' ),
				$this->decided_row( str_repeat( 'i', 32 ), self::NOW - ( 20 * $day ), self::NOW - ( 15 * $day ) ),
			)
		);
		$csv = Limbo::csv_for_snapshot( Limbo::snapshot( null, self::NOW ) );
		$this->assertStringContainsString( 'section,id,plugin,status,days_in_limbo', $csv );
		$this->assertStringContainsString( 'pending', $csv );
		$this->assertStringContainsString( 'slow/slow.php', $csv );
		$this->assertStringContainsString( 'decided', $csv );
		$this->assertStringContainsString( 'stats', $csv );
		$this->assertStringContainsString( Limbo::FRAMING, $csv );
	}

	public function test_writes_confined_to_own_options(): void {
		$day = DAY_IN_SECONDS;
		$this->enable( 7 );
		$req_key = Limbo::requests_option_key();
		update_option(
			$req_key,
			array(
				str_repeat( 'j', 32 ) => $this->pending_row( str_repeat( 'j', 32 ), self::NOW - ( 10 * $day ) ),
			),
			false
		);
		$before_req    = get_option( $req_key );
		$before_policy = get_option( Plugin::OPTION_KEY );

		Limbo::set_test_requests( null );
		Limbo::snapshot( null, self::NOW );
		Limbo::maybe_fire_alerts( self::NOW );

		$this->assertSame( $before_req, get_option( $req_key ) );
		$this->assertSame( $before_policy, get_option( Plugin::OPTION_KEY ) );
		$this->assertNotFalse( get_option( Limbo::SETTINGS_OPTION, false ) );
		$this->assertNotFalse( get_option( Limbo::STATE_OPTION, false ) );
	}

	public function test_median_helper(): void {
		$this->assertNull( Limbo::median_int( array() ) );
		$this->assertSame( 5, Limbo::median_int( array( 5 ) ) );
		$this->assertSame( 3, Limbo::median_int( array( 1, 5 ) ) );
		$this->assertSame( 4, Limbo::median_int( array( 1, 4, 9 ) ) );
	}
}
