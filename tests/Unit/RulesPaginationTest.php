<?php
/**
 * AICAC-RULES-PAGINATION (#246): search + page-scoped expected count contracts.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Admin;
use HandL\AICAC\Pager;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class RulesPaginationTest extends TestCase {

	public function test_search_matches_name_or_basename_case_insensitive(): void {
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php';

		$this->assertTrue( Admin::plugin_matches_rules_search( 'Acme AI', 'acme/acme.php', 'acme' ) );
		$this->assertTrue( Admin::plugin_matches_rules_search( 'Acme AI', 'vendor/tool.php', 'AI' ) );
		$this->assertFalse( Admin::plugin_matches_rules_search( 'Acme AI', 'acme/acme.php', 'zzz' ) );
		$this->assertTrue( Admin::plugin_matches_rules_search( 'Acme AI', 'acme/acme.php', '' ) );
	}

	public function test_collect_visible_then_slice_bounds_expected_count(): void {
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php';

		$plugins = array();
		$active  = array();
		for ( $i = 0; $i < 60; $i++ ) {
			$bn             = sprintf( 'plug-%02d/plug.php', $i );
			$plugins[ $bn ] = array( 'Name' => 'Plugin ' . $i );
			if ( 0 === $i % 2 ) {
				$active[ $bn ] = 1;
			}
		}
		$policy = array(
			'default' => 'allow',
			'plugins' => array(
				'plug-00/plug.php' => 'deny',
			),
		);

		$ref   = new ReflectionClass( Admin::class );
		$admin = $ref->newInstanceWithoutConstructor();
		$collect = $ref->getMethod( 'collect_visible_rule_plugins' );
		$collect->setAccessible( true );

		$visible = $collect->invoke(
			$admin,
			$plugins,
			$active,
			$policy,
			'all',
			'all',
			'',
			'allow'
		);
		$this->assertCount( 60, $visible );

		$page1 = Pager::slice( $visible, 1, 25 );
		$page2 = Pager::slice( $visible, 2, 25 );
		$page3 = Pager::slice( $visible, 3, 25 );
		$this->assertCount( 25, $page1 );
		$this->assertCount( 25, $page2 );
		$this->assertCount( 10, $page3 );
		$this->assertTrue( Policy::posted_rules_match_expected( array_fill_keys( array_keys( $page1 ), 'allow' ), 25 ) );
		$this->assertFalse( Policy::posted_rules_match_expected( array_fill_keys( array_keys( $page1 ), 'allow' ), 60 ) );
	}

	public function test_page_scoped_merge_keeps_other_page_rules(): void {
		$stored = array(
			'plugins' => array(
				'page1/a.php' => 'allow',
				'page2/b.php' => 'deny',
			),
		);
		// Saving page 1 with untouched Allow must not wipe page 2 Deny.
		$merged = Policy::merge_posted_plugin_rules(
			$stored['plugins'],
			array( 'page1/a.php' => 'allow' )
		);
		$this->assertSame( 'allow', $merged['page1/a.php'] );
		$this->assertSame( 'deny', $merged['page2/b.php'] );
	}

	public function test_admin_source_wires_pager_and_search(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringContainsString( 'Pager::render_tablenav_pages', $src );
		$this->assertStringContainsString( 'Pager::slice', $src );
		$this->assertStringContainsString( 'handl-aicac-rules-search', $src );
		$this->assertStringContainsString( 'collect_visible_rule_plugins', $src );
		$this->assertStringContainsString( "name=\"handl_aicac_s\"", $src );
		$this->assertStringContainsString( 'rules_allowed_per_page', $src );
		$this->assertSame( 13, Admin::RULES_MATRIX_FIELDS_PER_ROW );
		$this->assertSame( array( 25, 50 ), Admin::rules_allowed_per_page( 1000 ) );
		$this->assertSame( array( 25, 50, 100 ), Admin::rules_allowed_per_page( 4000 ) );
		// Must not touch Activity log renderers in this lane.
		$this->assertDoesNotMatchRegularExpression(
			'/function\s+render_log_tab\s*\([^)]*\)\s*:\s*void\s*\{[^}]{0,200}Pager::/',
			$src
		);
	}
}
