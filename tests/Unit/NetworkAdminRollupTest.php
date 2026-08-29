<?php
/**
 * Unit tests for Network_Admin rollup helpers (AICAC-105).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Network_Admin;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

final class NetworkAdminRollupTest extends TestCase {

	public function test_sites_per_page_cap_is_fifty(): void {
		$this->assertSame( 50, Network_Admin::SITES_PER_PAGE );
	}

	public function test_pagination_offset_and_total_pages(): void {
		$this->assertSame( 0, Network_Admin::offset_for_page( 1, 50 ) );
		$this->assertSame( 50, Network_Admin::offset_for_page( 2, 50 ) );
		$this->assertSame( 1, Network_Admin::sanitize_page( '0' ) );
		$this->assertSame( 3, Network_Admin::sanitize_page( '3' ) );
		$this->assertSame( 1, Network_Admin::total_pages( 0, 50 ) );
		$this->assertSame( 1, Network_Admin::total_pages( 50, 50 ) );
		$this->assertSame( 3, Network_Admin::total_pages( 101, 50 ) );
	}

	public function test_count_denials_matches_dashboard_semantics(): void {
		$log = array(
			array( 'decision' => 'deny', 'ts' => 10 ),
			array( 'decision' => 'allow', 'ts' => 20 ),
			array( 'decision' => 'deny', 'channel' => 'direct_http', 'ts' => 30 ),
			array( 'decision' => 'deny', 'ts' => 40 ),
			array( 'decision' => 'observe', 'channel' => 'direct_http', 'ts' => 50 ),
			'not-an-array',
		);

		$this->assertSame( 2, Network_Admin::count_denials( $log ) );
		$this->assertSame( 50, Network_Admin::newest_log_timestamp( $log ) );
		$this->assertSame( 0, Network_Admin::newest_log_timestamp( array() ) );
	}

	public function test_summarize_site_data_flags_and_ai_disabled(): void {
		$policy = array(
			'kill_switch'  => true,
			'audit_only'   => true,
			'log_enabled'  => false,
		);
		$log = array(
			array( 'decision' => 'deny', 'ts' => 100 ),
			array( 'decision' => 'allow', 'ts' => 200 ),
		);

		$row = Network_Admin::summarize_site_data(
			7,
			'https://example.test/site-a',
			'https://example.test/site-a/wp-admin/admin.php?page=handl-aicac-activity',
			$policy,
			$log,
			true
		);

		$this->assertSame( 7, $row['blog_id'] );
		$this->assertSame( 'https://example.test/site-a', $row['site_url'] );
		$this->assertTrue( $row['kill_switch'] );
		$this->assertTrue( $row['learn_mode'] );
		$this->assertFalse( $row['log_enabled'] );
		$this->assertTrue( $row['logging_or_learn'] );
		$this->assertSame( 1, $row['denial_count'] );
		$this->assertSame( 200, $row['last_activity_ts'] );
		$this->assertTrue( $row['ai_disabled'] );
		$this->assertStringContainsString( 'page=handl-aicac-activity', $row['activity_url'] );
	}

	public function test_summarize_logging_only_without_learn(): void {
		$row = Network_Admin::summarize_site_data(
			1,
			'https://example.test/',
			Network_Admin::activity_admin_url( 1 ),
			array( 'log_enabled' => true ),
			array(),
			false
		);

		$this->assertFalse( $row['kill_switch'] );
		$this->assertFalse( $row['learn_mode'] );
		$this->assertTrue( $row['logging_or_learn'] );
		$this->assertFalse( $row['ai_disabled'] );
		$this->assertSame( 0, $row['denial_count'] );
	}

	public function test_plugin_basename_fallback(): void {
		$basename = Network_Admin::plugin_basename();
		$this->assertStringContainsString( 'handl-ai-connector-access-control.php', $basename );
	}

	public function test_blog_id_from_site_object_and_array(): void {
		$obj = (object) array( 'blog_id' => '12' );
		$this->assertSame( 12, Network_Admin::blog_id_from_site( $obj ) );
		$this->assertSame( 9, Network_Admin::blog_id_from_site( array( 'blog_id' => 9 ) ) );
		$this->assertSame( 0, Network_Admin::blog_id_from_site( array() ) );
	}

	public function test_option_keys_reuse_plugin_constants(): void {
		$this->assertSame( 'handl_aicac_policy', Plugin::OPTION_KEY );
		$this->assertSame( 'handl_aicac_recent_calls', Plugin::LOG_OPTION_KEY );
	}

	/**
	 * AC1: init must not register network_admin_menu when not multisite.
	 */
	public function test_init_is_noop_when_not_multisite(): void {
		$GLOBALS['handl_aicac_test_is_multisite']   = false;
		$GLOBALS['handl_aicac_test_added_actions'] = array();

		$ref = new \ReflectionClass( Network_Admin::class );
		$obj = $ref->newInstanceWithoutConstructor();
		$obj->init();

		$this->assertNotContains(
			'network_admin_menu',
			$GLOBALS['handl_aicac_test_added_actions'],
			'AC1: non-multisite must not register network_admin_menu'
		);
	}

	/**
	 * Multisite path registers network_admin_menu (still no render without WP).
	 */
	public function test_init_registers_menu_when_multisite(): void {
		$GLOBALS['handl_aicac_test_is_multisite']   = true;
		$GLOBALS['handl_aicac_test_added_actions'] = array();

		$ref = new \ReflectionClass( Network_Admin::class );
		$obj = $ref->newInstanceWithoutConstructor();
		$obj->init();

		$this->assertContains( 'network_admin_menu', $GLOBALS['handl_aicac_test_added_actions'] );

		$GLOBALS['handl_aicac_test_is_multisite'] = false;
	}

	/**
	 * Static source locks for AC1/AC5/AC6 and capability.
	 */
	public function test_network_admin_source_guards(): void {
		$path = HANDL_AICAC_DIR . '/includes/class-handl-aicac-network-admin.php';
		$this->assertFileExists( $path );
		$src = file_get_contents( $path );
		$this->assertNotFalse( $src );

		$this->assertMatchesRegularExpression( '/is_multisite\s*\(/', $src );
		$this->assertMatchesRegularExpression( '/network_admin_menu/', $src );
		$this->assertMatchesRegularExpression( '/manage_network_options/', $src );
		$this->assertMatchesRegularExpression( '/SITES_PER_PAGE\s*=\s*50/', $src );
		$this->assertMatchesRegularExpression( '/switch_to_blog\s*\(/', $src );
		$this->assertMatchesRegularExpression( '/restore_current_blog\s*\(/', $src );
		$this->assertMatchesRegularExpression( '/SCREEN_SLUGS\[.activity.\]/', $src );
		$this->assertMatchesRegularExpression( '/AI disabled/', $src );

		// AC5: read-only — no policy mutation entry points on this screen.
		$this->assertDoesNotMatchRegularExpression( '/\$_POST/', $src );
		$this->assertDoesNotMatchRegularExpression( '/handl_aicac_action/', $src );
		$this->assertDoesNotMatchRegularExpression( '/\bupdate_option\s*\(/', $src );
		$this->assertDoesNotMatchRegularExpression( '/\bdelete_option\s*\(/', $src );
	}

	public function test_plugin_bootstrap_loads_network_admin(): void {
		$path = HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php';
		$src  = file_get_contents( $path );
		$this->assertNotFalse( $src );
		$this->assertStringContainsString( 'class-handl-aicac-network-admin.php', $src );
		$this->assertStringContainsString( 'Network_Admin::instance()->init()', $src );
	}
}
