<?php
/**
 * AICAC-WELCOME-BACK (#438).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Welcome_Back;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class WelcomeBackTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12 UTC.
	private const USER = 3;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_user_id']          = self::USER;
		$GLOBALS['handl_aicac_test_user_meta']        = array();
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		Welcome_Back::reset_for_tests();
		Welcome_Back::set_test_now( self::NOW );
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_user_meta']     = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		unset( $GLOBALS['handl_aicac_test_user_id'] );
		Welcome_Back::reset_for_tests();
		parent::tearDown();
	}

	private function enable( int $gap_days = 7 ): void {
		Welcome_Back::save_settings(
			array(
				'enabled'  => true,
				'gap_days' => $gap_days,
			)
		);
	}

	private function day(): int {
		return defined( 'DAY_IN_SECONDS' ) ? DAY_IN_SECONDS : 86400;
	}

	public function test_defaults_off(): void {
		$this->assertFalse( Welcome_Back::is_enabled() );
		$this->assertSame( 7, Welcome_Back::gap_days() );
		$this->assertSame( 'on_return_personal_brief_read_only', Welcome_Back::FRAMING );
		$this->assertSame( Welcome_Back::defaults(), Welcome_Back::sanitize_settings( null ) );
		$this->assertTrue( Welcome_Back::save_settings( array( 'enabled' => true, 'gap_days' => 10 ) ) );
		$this->assertTrue( Welcome_Back::is_enabled() );
		$this->assertSame( 10, Welcome_Back::gap_days() );
		$this->assertTrue( Welcome_Back::save_settings( Welcome_Back::defaults() ) );
		$this->assertFalse( (bool) get_option( Welcome_Back::SETTINGS_OPTION, false ) );
	}

	public function test_gap_detection_and_threshold(): void {
		$this->enable( 7 );
		$day = $this->day();

		Welcome_Back::set_last_seen( self::USER, self::NOW - ( 6 * $day ) );
		$this->assertFalse( Welcome_Back::qualifies_for_notice( self::USER, self::NOW ) );

		Welcome_Back::set_last_seen( self::USER, self::NOW - ( 7 * $day ) );
		$this->assertTrue( Welcome_Back::qualifies_for_notice( self::USER, self::NOW ) );

		Welcome_Back::set_last_seen( self::USER, self::NOW - ( 10 * $day ) );
		$this->assertTrue( Welcome_Back::qualifies_for_notice( self::USER, self::NOW ) );
	}

	public function test_no_notice_for_gaps_under_threshold(): void {
		$this->enable( 7 );
		$day = $this->day();
		Welcome_Back::set_last_seen( self::USER, self::NOW - ( 3 * $day ) );
		$this->assertSame( 3 * $day, Welcome_Back::absence_gap_seconds( self::USER, self::NOW ) );
		$this->assertFalse( Welcome_Back::qualifies_for_notice( self::USER, self::NOW ) );
	}

	public function test_dismiss_and_rearm(): void {
		$this->enable( 7 );
		$day = $this->day();
		$away = self::NOW - ( 10 * $day );
		Welcome_Back::set_last_seen( self::USER, $away );
		$this->assertTrue( Welcome_Back::qualifies_for_notice( self::USER, self::NOW ) );

		Welcome_Back::dismiss_for_user( self::USER, self::NOW );
		$this->assertFalse( Welcome_Back::qualifies_for_notice( self::USER, self::NOW ) );

		// Next qualifying gap after dismiss.
		Welcome_Back::set_test_now( self::NOW + ( 8 * $day ) );
		// last_seen was advanced to NOW on dismiss; 8 days later qualifies again.
		$this->assertTrue( Welcome_Back::qualifies_for_notice( self::USER, self::NOW + ( 8 * $day ) ) );
	}

	public function test_window_scoped_counts_at_edges(): void {
		$this->enable( 7 );
		$day       = $this->day();
		$gap_start = self::NOW - ( 10 * $day );
		$prior_start = $gap_start - ( 10 * $day );

		$log = array(
			// Inside absence window [gap_start, now).
			array( 'ts' => $gap_start, 'decision' => 'deny' ),
			array( 'ts' => self::NOW - 1, 'decision' => 'allow' ),
			array( 'ts' => self::NOW - 2, 'decision' => 'deny' ),
			// Edge: exactly at now — excluded (end exclusive).
			array( 'ts' => self::NOW, 'decision' => 'deny' ),
			// Prior equal window [prior_start, gap_start).
			array( 'ts' => $prior_start, 'decision' => 'allow' ),
			array( 'ts' => $gap_start - 1, 'decision' => 'deny' ),
			// Edge: exactly at gap_start belongs to absence, not prior.
			array( 'ts' => $gap_start - ( 11 * $day ), 'decision' => 'deny' ), // outside both
		);
		Welcome_Back::set_test_log( $log );
		Welcome_Back::set_test_history( array() );
		Welcome_Back::set_test_pending( array() );
		Welcome_Back::set_test_findings( array() );
		Welcome_Back::set_last_seen( self::USER, $gap_start );

		$brief = Welcome_Back::build_brief( self::USER, self::NOW );
		$traffic = $brief['sections']['traffic'];
		$this->assertTrue( $traffic['available'] );
		$this->assertSame( 2, $traffic['absence']['deny'] );
		$this->assertSame( 1, $traffic['absence']['allow'] );
		$this->assertSame( 1, $traffic['prior']['deny'] );
		$this->assertSame( 1, $traffic['prior']['allow'] );

		// Settings changes at edges.
		Welcome_Back::set_test_history(
			array(
				array( 'ts' => $gap_start, 'changes' => array( 'default' ) ),
				array( 'ts' => self::NOW - 1, 'changes' => array( 'budget' ) ),
				array( 'ts' => self::NOW, 'changes' => array( 'too-late' ) ),
				array( 'ts' => $gap_start - 1, 'changes' => array( 'before' ) ),
			)
		);
		$brief2 = Welcome_Back::build_brief( self::USER, self::NOW );
		$this->assertSame( 2, $brief2['sections']['settings_changes']['count'] );
	}

	public function test_source_unavailable_sections(): void {
		$this->enable( 7 );
		Welcome_Back::set_last_seen( self::USER, self::NOW - ( 10 * $this->day() ) );
		// Force unavailable by leaving injections null and ensuring empty option reads.
		// Activity log: option absent → unavailable.
		$brief = Welcome_Back::build_brief( self::USER, self::NOW );
		$this->assertFalse( $brief['sections']['traffic']['available'] );
		$this->assertStringContainsString( 'source unavailable', strtolower( $brief['sections']['traffic']['sentence'] ) );
	}

	public function test_disabled_never_qualifies(): void {
		Welcome_Back::set_last_seen( self::USER, self::NOW - ( 30 * $this->day() ) );
		$this->assertFalse( Welcome_Back::qualifies_for_notice( self::USER, self::NOW ) );
	}
}
