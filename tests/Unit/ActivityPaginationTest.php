<?php
/**
 * AICAC-ACTIVITY-PAGINATION (#247): paginate the Activity log table.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Admin;
use HandL\AICAC\Pager;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class ActivityPaginationTest extends TestCase {

	public function test_activity_default_per_page_is_50(): void {
		$this->assertSame( 50, Admin::ACTIVITY_DEFAULT_PER_PAGE );
		$this->assertSame(
			array( 25, 50, 100 ),
			Admin::activity_allowed_per_page()
		);
	}

	public function test_collect_filtered_then_slice_pages_activity_rows(): void {
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php';

		$log = array();
		for ( $i = 0; $i < 120; $i++ ) {
			$log[] = array(
				'ts'       => 1_700_000_000 + $i,
				'decision' => 'allow',
				'plugin'   => 'demo/demo.php',
			);
		}

		$ref   = new ReflectionClass( Admin::class );
		$admin = $ref->newInstanceWithoutConstructor();
		$collect = $ref->getMethod( 'collect_filtered_log_rows' );
		$collect->setAccessible( true );

		$filters = array(
			'decision'  => '',
			'operation' => '',
			'provider'  => '',
			'model'     => '',
			'plugin'    => '',
		);
		$rows = $collect->invoke( $admin, $log, $filters );
		$this->assertCount( 120, $rows );

		$page1 = Pager::slice( $rows, 1, 50 );
		$page2 = Pager::slice( $rows, 2, 50 );
		$page3 = Pager::slice( $rows, 3, 50 );
		$this->assertCount( 50, $page1 );
		$this->assertCount( 50, $page2 );
		$this->assertCount( 20, $page3 );
	}

	public function test_filtering_keeps_whole_set_for_counts(): void {
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php';

		$log = array(
			array( 'ts' => 1, 'decision' => 'allow', 'plugin' => 'a/a.php' ),
			array( 'ts' => 2, 'decision' => 'deny', 'plugin' => 'a/a.php' ),
			array( 'ts' => 3, 'decision' => 'allow', 'plugin' => 'b/b.php' ),
		);

		$ref   = new ReflectionClass( Admin::class );
		$admin = $ref->newInstanceWithoutConstructor();
		$collect = $ref->getMethod( 'collect_filtered_log_rows' );
		$collect->setAccessible( true );

		$deny_only = $collect->invoke(
			$admin,
			$log,
			array(
				'decision'  => 'deny',
				'operation' => '',
				'provider'  => '',
				'model'     => '',
				'plugin'    => '',
			)
		);
		$this->assertCount( 1, $deny_only );
		$this->assertSame( 'deny', $deny_only[0]['decision'] );
	}

	public function test_admin_source_wires_activity_pager(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringContainsString( 'collect_filtered_log_rows', $src );
		$this->assertStringContainsString( 'activity_list_query_args', $src );
		$this->assertStringContainsString( 'handl-aicac-activity-per-page', $src );
		$this->assertStringContainsString( 'ACTIVITY_DEFAULT_PER_PAGE', $src );
		$this->assertStringContainsString( 'handl-aicac-activity-nav', $src );
		$this->assertStringContainsString( 'Pager::render_tablenav_pages', $src );
		$this->assertStringContainsString( 'Pager::render_per_page_select', $src );
		$this->assertStringContainsString(
			'Downloads all saved activity matching your current filters, not just the rows shown here.',
			$src
		);
		$this->assertStringContainsString( 'Audit_Export::build_csv', $src );
	}
}
