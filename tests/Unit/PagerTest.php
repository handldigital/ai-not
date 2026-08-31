<?php
/**
 * Shared Pager helper unit tests (AICAC-RULES-PAGINATION / AICAC-ACTIVITY-PAGINATION).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Pager;
use PHPUnit\Framework\TestCase;

final class PagerTest extends TestCase {

	public function test_sanitize_per_page_allows_only_25_50_100(): void {
		$this->assertSame( 25, Pager::sanitize_per_page( null ) );
		$this->assertSame( 25, Pager::sanitize_per_page( 0 ) );
		$this->assertSame( 25, Pager::sanitize_per_page( 13 ) );
		$this->assertSame( 25, Pager::sanitize_per_page( '25' ) );
		$this->assertSame( 50, Pager::sanitize_per_page( 50 ) );
		$this->assertSame( 100, Pager::sanitize_per_page( '100' ) );
	}

	public function test_sizes_within_input_budget_hides_oversize_options(): void {
		// Default PHP (1000): 100 rows × 13 fields exceeds the budget → 25/50 only.
		$this->assertSame(
			array( 25, 50 ),
			Pager::sizes_within_input_budget( 1000, 16, 13 )
		);
		// Raised limit: all three nominal sizes fit.
		$this->assertSame(
			array( 25, 50, 100 ),
			Pager::sizes_within_input_budget( 4000, 16, 13 )
		);
	}

	public function test_sanitize_per_page_clamps_to_allowed_subset(): void {
		$allowed = array( 25, 50 );
		$this->assertSame( 50, Pager::sanitize_per_page( 100, $allowed ) );
		$this->assertSame( 50, Pager::sanitize_per_page( 50, $allowed ) );
		$this->assertSame( 25, Pager::sanitize_per_page( 25, $allowed ) );
		$this->assertSame( 25, Pager::sanitize_per_page( null, $allowed ) );
	}

	public function test_total_pages_and_offset(): void {
		$this->assertSame( 1, Pager::total_pages( 0, 25 ) );
		$this->assertSame( 1, Pager::total_pages( 25, 25 ) );
		$this->assertSame( 2, Pager::total_pages( 26, 25 ) );
		$this->assertSame( 8, Pager::total_pages( 177, 25 ) );
		$this->assertSame( 0, Pager::offset( 1, 25 ) );
		$this->assertSame( 25, Pager::offset( 2, 25 ) );
		$this->assertSame( 50, Pager::offset( 2, 50 ) );
	}

	public function test_sanitize_page_clamps_to_range(): void {
		$this->assertSame( 1, Pager::sanitize_page( 0, 5 ) );
		$this->assertSame( 1, Pager::sanitize_page( -3, 5 ) );
		$this->assertSame( 5, Pager::sanitize_page( 99, 5 ) );
		$this->assertSame( 3, Pager::sanitize_page( '3', 5 ) );
	}

	public function test_slice_preserves_keys_for_assoc_maps(): void {
		$items = array(
			'a/a.php' => array( 'Name' => 'A' ),
			'b/b.php' => array( 'Name' => 'B' ),
			'c/c.php' => array( 'Name' => 'C' ),
			'd/d.php' => array( 'Name' => 'D' ),
		);
		$page1 = Pager::slice( $items, 1, 25 );
		$this->assertSame( array( 'a/a.php', 'b/b.php', 'c/c.php', 'd/d.php' ), array_keys( $page1 ) );

		// Force a tiny page via offset math with a non-allowed size sanitized up —
		// use array_slice path with page 2 of 25 after manually checking offset.
		$all = array();
		for ( $i = 0; $i < 30; $i++ ) {
			$all[ 'p' . $i . '/x.php' ] = $i;
		}
		$page2 = Pager::slice( $all, 2, 25 );
		$this->assertCount( 5, $page2 );
		$this->assertArrayHasKey( 'p25/x.php', $page2 );
		$this->assertArrayNotHasKey( 'p0/x.php', $page2 );
	}

	public function test_plugin_require_registers_pager_before_admin(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$pager = strpos( $src, "require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-pager.php'" );
		$admin = strpos( $src, "require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php'" );
		$this->assertNotFalse( $pager );
		$this->assertNotFalse( $admin );
		$this->assertLessThan( $admin, $pager );
	}
}
