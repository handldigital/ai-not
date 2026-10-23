<?php
/**
 * AICAC-MANNERS (#451).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Manners;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class MannersTest extends TestCase {

	private const NOW = 1791800000;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_transients']       = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Manners::reset_for_tests();
		Manners::set_test_now( self::NOW );
		Manners::set_skip_cache( true );
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options']    = array();
		$GLOBALS['handl_aicac_test_transients'] = array();
		Manners::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private function denies( string $plugin, array $timestamps ): array {
		$rows = array();
		foreach ( $timestamps as $ts ) {
			$rows[] = array(
				'ts'       => (int) $ts,
				'decision' => 'deny',
				'plugin'   => $plugin,
				'user_id'  => 1,
			);
		}

		return $rows;
	}

	public function test_classifier_four_grades_deterministic(): void {
		$now = self::NOW;

		// HAMMER: median gap 5s, still active.
		$this->assertSame(
			Manners::GRADE_HAMMER,
			Manners::classify( array( $now - 20, $now - 15, $now - 10, $now - 5 ), $now )
		);

		// PERSISTENT: steady 60s gaps, still active.
		$this->assertSame(
			Manners::GRADE_PERSISTENT,
			Manners::classify( array( $now - 180, $now - 120, $now - 60, $now ), $now )
		);

		// BACKOFF: gaps 30s → 60s → 120s (>=2x first to last).
		$this->assertSame(
			Manners::GRADE_BACKOFF,
			Manners::classify( array( $now - 210, $now - 180, $now - 120, $now ), $now )
		);

		// WENT-QUIET: two denies, then silence >= 1h.
		$this->assertSame(
			Manners::GRADE_WENT_QUIET,
			Manners::classify( array( $now - 7200, $now - 7000 ), $now )
		);
	}

	public function test_grade_connectors_produces_all_four(): void {
		$now = self::NOW;
		$log = array_merge(
			$this->denies( 'hammer/plugin.php', array( $now - 20, $now - 15, $now - 10, $now - 5 ) ),
			$this->denies( 'persist/plugin.php', array( $now - 180, $now - 120, $now - 60, $now ) ),
			$this->denies( 'backoff/plugin.php', array( $now - 210, $now - 180, $now - 120, $now ) ),
			$this->denies( 'quiet/plugin.php', array( $now - 7200, $now - 7000 ) ),
			// Single deny ignored (COLDCASE territory).
			$this->denies( 'once/plugin.php', array( $now - 100 ) )
		);
		Manners::set_test_log( $log );

		$rows = Manners::grade_connectors( $now );
		$by   = array();
		foreach ( $rows as $row ) {
			$by[ $row['connector'] ] = $row['grade'];
		}

		$this->assertSame( Manners::GRADE_HAMMER, $by['hammer/plugin.php'] );
		$this->assertSame( Manners::GRADE_PERSISTENT, $by['persist/plugin.php'] );
		$this->assertSame( Manners::GRADE_BACKOFF, $by['backoff/plugin.php'] );
		$this->assertSame( Manners::GRADE_WENT_QUIET, $by['quiet/plugin.php'] );
		$this->assertArrayNotHasKey( 'once/plugin.php', $by );
	}

	public function test_missing_history_empty_census_no_writes_to_log(): void {
		Manners::set_test_log( null );
		$pack = Manners::read_activity_log();
		$this->assertFalse( $pack['available'] );

		$rows = Manners::grade_connectors( self::NOW );
		$this->assertSame( array(), $rows );

		$log_key = 'handl_aicac_recent_calls';
		$this->assertFalse( (bool) get_option( $log_key, false ) );

		$snap = Manners::snapshot( self::NOW );
		$this->assertSame( array(), $snap['rows'] );
		$this->assertFalse( $snap['log_available'] );
	}

	public function test_no_policy_writes_and_cache_roundtrip(): void {
		$now = self::NOW;
		Manners::set_test_log(
			$this->denies( 'hammer/plugin.php', array( $now - 20, $now - 15, $now - 10, $now - 5 ) )
		);
		Manners::set_skip_cache( false );

		$before_policy = get_option( 'handl_aicac_policy', null );
		$snap1         = Manners::snapshot( $now );
		$this->assertFalse( $snap1['cached'] );
		$this->assertCount( 1, $snap1['rows'] );
		$this->assertSame( $before_policy, get_option( 'handl_aicac_policy', null ) );

		$snap2 = Manners::snapshot( $now + 10 );
		$this->assertTrue( $snap2['cached'] );
		$this->assertSame( $snap1['rows'], $snap2['rows'] );
	}

	public function test_render_empty_and_table_escaped(): void {
		Manners::set_test_log( array() );
		ob_start();
		Manners::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'No connectors with two or more denies', $html );
		$this->assertStringContainsString( 'HAMMER', $html );

		$now = self::NOW;
		Manners::set_test_log(
			$this->denies( 'evil<script>/x.php', array( $now - 20, $now - 10, $now - 5 ) )
		);
		ob_start();
		Manners::render_page();
		$html2 = (string) ob_get_clean();
		$this->assertStringNotContainsString( '<script>', $html2 );
		$this->assertStringContainsString( 'evil&lt;script&gt;/x.php', $html2 );
		$this->assertStringContainsString( 'HAMMER', $html2 );
	}
}
