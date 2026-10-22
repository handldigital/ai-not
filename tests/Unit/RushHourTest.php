<?php
/**
 * AICAC-RUSH-HOUR (#458).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Rush_Hour;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class RushHourTest extends TestCase {

	private const TZ = 'America/Chicago';

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_filters']          = array();
		Rush_Hour::reset_for_tests();
		Rush_Hour::set_test_timezone( self::TZ );
		Rush_Hour::set_skip_cache( true );
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_filters'] = array();
		Rush_Hour::reset_for_tests();
		parent::tearDown();
	}

	private function ts( string $local ): int {
		return ( new \DateTimeImmutable( $local, new \DateTimeZone( self::TZ ) ) )->getTimestamp();
	}

	/**
	 * @return array<string,mixed>
	 */
	private function call_row( string $local, string $decision = 'allow', int $user_id = 7, string $role = 'editor', string $provider = 'openai' ): array {
		return array(
			'ts'        => $this->ts( $local ),
			'decision'  => $decision,
			'user_id'   => $user_id,
			'user_role' => $role,
			'plugin'    => 'connector/plugin.php',
			'provider'  => $provider,
		);
	}

	public function test_classifier_four_grades_and_insufficient(): void {
		$this->assertSame( Rush_Hour::GRADE_INSUFFICIENT, Rush_Hour::classify( 4, 4, 0, 0 ) );
		$this->assertSame( Rush_Hour::GRADE_BUSINESS, Rush_Hour::classify( 10, 8, 0, 0 ) );
		$this->assertSame( Rush_Hour::GRADE_BUSINESS, Rush_Hour::classify( 10, 9, 0, 0 ) );
		$this->assertSame( Rush_Hour::GRADE_AFTER, Rush_Hour::classify( 10, 7, 0, 0 ) );
		$this->assertSame( Rush_Hour::GRADE_AFTER, Rush_Hour::classify( 10, 5, 0, 2 ) );
		$this->assertSame( Rush_Hour::GRADE_NIGHT, Rush_Hour::classify( 10, 0, 5, 0 ) );
		$this->assertSame( Rush_Hour::GRADE_WEEKEND, Rush_Hour::classify( 10, 0, 0, 5 ) );
	}

	public function test_night_outranks_weekend_on_overlap(): void {
		$this->assertSame( Rush_Hour::GRADE_NIGHT, Rush_Hour::classify( 10, 0, 6, 6 ) );
	}

	public function test_chicago_timezone_not_utc(): void {
		// Wednesday 14:00 Chicago = 19:00 UTC in October (CDT).
		$business = $this->ts( '2026-10-21 14:00:00' );
		$flags    = Rush_Hour::local_flags( $business );
		$this->assertNotNull( $flags );
		$this->assertSame( 14, $flags['hour'] );
		$this->assertTrue( $flags['business'] );
		$this->assertFalse( $flags['night'] );
		$this->assertFalse( $flags['weekend'] );

		$utc_would_be_night = $this->ts( '2026-10-21 02:00:00' );
		$night              = Rush_Hour::local_flags( $utc_would_be_night );
		$this->assertNotNull( $night );
		$this->assertSame( 2, $night['hour'] );
		$this->assertTrue( $night['night'] );
		$this->assertFalse( $night['business'] );

		Rush_Hour::set_test_timezone( 'UTC' );
		$as_utc = Rush_Hour::local_flags( $business );
		$this->assertNotNull( $as_utc );
		$this->assertSame( 19, $as_utc['hour'] );
		$this->assertFalse( $as_utc['business'] );
	}

	public function test_census_grades_from_fixture_log_and_24_hour_table(): void {
		$log = array();
		// User 11: 10x Wed 14:00 → BUSINESS-HOURS.
		for ( $i = 0; $i < 10; $i++ ) {
			$log[] = $this->call_row( '2026-10-21 14:00:00', 'allow', 11, 'editor', 'openai' );
		}
		// User 12: 10x Wed 02:00 → NIGHT-SHIFT (deny rows still count).
		for ( $i = 0; $i < 10; $i++ ) {
			$log[] = $this->call_row( '2026-10-21 02:00:00', 'deny', 12, 'author', 'anthropic' );
		}
		// User 13: 10x Saturday 14:00 → WEEKENDER.
		for ( $i = 0; $i < 10; $i++ ) {
			$log[] = $this->call_row( '2026-10-24 14:00:00', 'allow', 13, 'subscriber', 'openai' );
		}
		// User 14: 6x Wed 14:00 + 4x Wed 20:00 → AFTER-HOURS (40% outside).
		for ( $i = 0; $i < 6; $i++ ) {
			$log[] = $this->call_row( '2026-10-21 14:00:00', 'allow', 14, 'shop_manager', 'openai' );
		}
		for ( $i = 0; $i < 4; $i++ ) {
			$log[] = $this->call_row( '2026-10-21 20:00:00', 'allow', 14, 'shop_manager', 'openai' );
		}
		// User 15: 3 calls → INSUFFICIENT-DATA, excluded from grades.
		$log[] = $this->call_row( '2026-10-21 14:00:00', 'allow', 15, 'editor', 'openai' );
		$log[] = $this->call_row( '2026-10-21 14:00:00', 'allow', 15, 'editor', 'openai' );
		$log[] = $this->call_row( '2026-10-21 14:00:00', 'allow', 15, 'editor', 'openai' );

		Rush_Hour::set_test_log( $log );
		$data = Rush_Hour::census();

		$this->assertCount( 24, $data['hours'] );
		$by_hour = array();
		foreach ( $data['hours'] as $row ) {
			$by_hour[ (int) $row['hour'] ] = (int) $row['count'];
		}
		$this->assertSame( 10, $by_hour[2] );
		$this->assertSame( 4, $by_hour[20] );
		$this->assertGreaterThan( 0, $by_hour[14] );

		$users = array();
		foreach ( $data['actors'] as $actor ) {
			if ( Rush_Hour::KIND_USER === $actor['kind'] ) {
				$users[ $actor['id'] ] = $actor['grade'];
			}
		}
		$this->assertSame( Rush_Hour::GRADE_BUSINESS, $users['11'] );
		$this->assertSame( Rush_Hour::GRADE_NIGHT, $users['12'] );
		$this->assertSame( Rush_Hour::GRADE_WEEKEND, $users['13'] );
		$this->assertSame( Rush_Hour::GRADE_AFTER, $users['14'] );
		$this->assertArrayNotHasKey( '15', $users );
	}

	public function test_empty_log_empty_state_and_log_byte_identical_after_render(): void {
		$log = array(
			$this->call_row( '2026-10-21 14:00:00', 'allow', 21, 'editor', 'openai' ),
		);
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
		$before = get_option( Plugin::LOG_OPTION_KEY, null );

		Rush_Hour::set_test_log( array() );
		ob_start();
		Rush_Hour::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'No AI calls in the activity log yet', $html );
		$this->assertStringContainsString( 'Rush hour', $html );

		Rush_Hour::set_test_log( null );
		ob_start();
		Rush_Hour::render_page();
		$html2 = (string) ob_get_clean();
		$this->assertStringContainsString( '14:00', $html2 );
		$this->assertSame( $before, get_option( Plugin::LOG_OPTION_KEY, null ) );
	}

	public function test_render_table_escapes_and_skips_non_call_rows(): void {
		$log = array();
		for ( $i = 0; $i < 5; $i++ ) {
			$log[] = $this->call_row( '2026-10-21 02:00:00', 'allow', 9, 'evil<script>', 'openai' );
		}
		$log[] = array(
			'ts'       => $this->ts( '2026-10-21 02:00:00' ),
			'decision' => 'anomaly_alert',
			'user_id'  => 9,
			'provider' => 'openai',
		);
		Rush_Hour::set_test_log( $log );
		ob_start();
		Rush_Hour::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringNotContainsString( '<script>', $html );
		$this->assertStringContainsString( 'NIGHT-SHIFT', $html );
		$this->assertStringContainsString( '02:00', $html );
	}

	public function test_cache_writes_only_own_options(): void {
		Rush_Hour::set_skip_cache( false );
		$log = array();
		for ( $i = 0; $i < 5; $i++ ) {
			$log[] = $this->call_row( '2026-10-21 14:00:00', 'allow', 3, 'editor', 'openai' );
		}
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
		update_option( 'handl_aicac_policy', array( 'keep' => true ), false );
		$policy_before = get_option( 'handl_aicac_policy', null );
		$log_before    = get_option( Plugin::LOG_OPTION_KEY, null );

		Rush_Hour::set_test_log( null );
		Rush_Hour::set_test_now( 1792694152 );
		$snap = Rush_Hour::snapshot( 1792694152 );
		$this->assertFalse( $snap['cached'] );
		$this->assertNotFalse( get_option( Rush_Hour::CENSUS_OPTION, false ) );
		$this->assertSame( 1792694152, (int) get_option( Rush_Hour::GENERATED_OPTION, 0 ) );
		$this->assertSame( $policy_before, get_option( 'handl_aicac_policy', null ) );
		$this->assertSame( $log_before, get_option( Plugin::LOG_OPTION_KEY, null ) );

		$again = Rush_Hour::snapshot( 1792694152 );
		$this->assertTrue( $again['cached'] );
	}

	public function test_thresholds_filter_changes_min_calls(): void {
		$GLOBALS['handl_aicac_test_filters']['handl_aicac_rush_hour_thresholds'] = static function ( array $th ): array {
			$th['min_calls'] = 2;
			return $th;
		};
		$this->assertSame( Rush_Hour::GRADE_BUSINESS, Rush_Hour::classify( 2, 2, 0, 0 ) );
	}
}
