<?php
/**
 * AICAC-FOYER (#508): Simple mode More tools hall.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Admin;
use HandL\AICAC\Foyer;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class FoyerTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$_GET  = array();
		$_POST = array();
		$GLOBALS['submenu'] = array();
		Foyer::reset_for_tests();
		delete_option( Foyer::MODE_OPTION );
		delete_option( Foyer::STATE_OPTION );
	}

	protected function tearDown(): void {
		$_GET  = array();
		$_POST = array();
		$GLOBALS['submenu'] = array();
		Foyer::reset_for_tests();
		delete_option( Foyer::MODE_OPTION );
		delete_option( Foyer::STATE_OPTION );
		unset(
			$GLOBALS['handl_aicac_test_added_actions'],
			$GLOBALS['handl_aicac_test_caps']
		);
		parent::tearDown();
	}

	/**
	 * @return list<array{0:string,1:string,2:string}>
	 */
	private function sample_submenu(): array {
		return array(
			array( 'Dashboard', 'manage_options', 'handl-aicac' ),
			array( 'Rules', 'manage_options', 'handl-aicac-rules' ),
			array( 'Protections', 'manage_options', 'handl-aicac-protections' ),
			array( 'Activity', 'manage_options', 'handl-aicac-activity' ),
			array( 'Insights', 'manage_options', 'handl-aicac-insights' ),
			array( 'Policy tools', 'manage_options', 'handl-aicac-policy-tools' ),
			array( 'Settings', 'manage_options', 'handl-aicac-alerts' ),
			array( 'More tools', 'handl_aicac_view', Foyer::PAGE_SLUG ),
			array( 'Injection screen', 'handl_aicac_view', 'handl-aicac-taint' ),
			array( 'Exposure lookback', 'handl_aicac_view', 'handl-aicac-lookback' ),
			array( 'Outbound media', 'handl_aicac_view', 'handl-aicac-luggage' ),
			array( 'Chargeback', 'handl_aicac_view', 'handl-aicac-chargeback' ),
		);
	}

	/**
	 * @param list<array{0:string,1:string,2:string}> $rows
	 * @return list<string>
	 */
	private function slugs_of( array $rows ): array {
		$out = array();
		foreach ( $rows as $row ) {
			$out[] = (string) ( $row[2] ?? '' );
		}

		return $out;
	}

	public function test_plugin_bootstrap_wires_foyer_after_litmus(): void {
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-foyer.php', $plugin );
		$this->assertStringContainsString( 'Foyer::init()', $plugin );
		$this->assertGreaterThan(
			(int) strrpos( $plugin, 'class-handl-aicac-litmus.php' ),
			(int) strrpos( $plugin, 'class-handl-aicac-foyer.php' )
		);
		$this->assertGreaterThan(
			(int) strrpos( $plugin, 'Litmus::init()' ),
			(int) strrpos( $plugin, 'Foyer::init()' )
		);
		$boot = (string) file_get_contents( HANDL_AICAC_DIR . '/tests/bootstrap.php' );
		$this->assertStringContainsString( 'class-handl-aicac-foyer.php', $boot );
		$this->assertGreaterThan(
			(int) strrpos( $boot, 'class-handl-aicac-litmus.php' ),
			(int) strrpos( $boot, 'class-handl-aicac-foyer.php' )
		);
		$readme = (string) file_get_contents( HANDL_AICAC_DIR . '/readme.txt' );
		$this->assertStringNotContainsString( 'foyer', strtolower( $readme ) );
		$admin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringNotContainsString( 'Foyer', $admin );
		foreach ( array( 'taint', 'lookback', 'litmus', 'luggage', 'neighbors' ) as $feature ) {
			$body = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-' . $feature . '.php' );
			$this->assertStringNotContainsString( 'Foyer', $body );
		}
		$this->assertSame( Foyer::FRAMING, 'presentation_only_never_edits_features' );
	}

	public function test_init_is_idempotent_and_registers_late_menu_hide(): void {
		Foyer::init();
		Foyer::init();
		$this->assertSame(
			array(
				'admin_menu',
				'admin_menu',
				'admin_menu',
				'admin_menu',
				'admin_init',
				'admin_init',
				'admin_notices',
			),
			$GLOBALS['handl_aicac_test_added_actions']
		);
		$this->assertSame( 'handl-aicac-foyer', Foyer::PAGE_SLUG );
		$this->assertSame( 'handl_aicac_ui_mode', Foyer::MODE_OPTION );
	}

	public function test_fresh_install_seeds_simple_mode(): void {
		delete_option( Plugin::OPTION_KEY );
		Foyer::maybe_seed_mode();
		$this->assertSame( Foyer::MODE_SIMPLE, Foyer::mode() );
		$this->assertTrue( Foyer::is_simple() );
	}

	public function test_existing_install_seeds_full_mode(): void {
		update_option( Plugin::OPTION_KEY, array( 'mode' => 'enforce' ), false );
		Foyer::maybe_seed_mode();
		$this->assertSame( Foyer::MODE_FULL, Foyer::mode() );
		$this->assertFalse( Foyer::is_simple() );
		Foyer::maybe_seed_mode();
		$this->assertSame( Foyer::MODE_FULL, Foyer::mode() );
	}

	public function test_simple_mode_keeps_seven_core_and_more_tools(): void {
		Foyer::set_mode( Foyer::MODE_SIMPLE );
		$full = $this->sample_submenu();
		Foyer::set_test_submenu( $full );
		Foyer::apply_simple_menu();
		$kept = $this->slugs_of( $GLOBALS['submenu'][ Admin::MENU_SLUG ] );
		$this->assertSame(
			array(
				'handl-aicac',
				'handl-aicac-rules',
				'handl-aicac-protections',
				'handl-aicac-activity',
				'handl-aicac-insights',
				'handl-aicac-policy-tools',
				'handl-aicac-alerts',
				Foyer::PAGE_SLUG,
			),
			$kept
		);
		$this->assertCount( 7, Foyer::core_slugs() );
		$this->assertSame(
			$kept,
			Foyer::visible_menu_slugs( $this->slugs_of( $full ) )
		);
	}

	public function test_hidden_tools_remain_on_cards_after_menu_hide(): void {
		Foyer::set_mode( Foyer::MODE_SIMPLE );
		$full = $this->sample_submenu();
		$GLOBALS['submenu'][ Admin::MENU_SLUG ] = $full;
		Foyer::snapshot_menu();
		Foyer::apply_simple_menu();
		$this->assertNotContains( 'handl-aicac-taint', $this->slugs_of( $GLOBALS['submenu'][ Admin::MENU_SLUG ] ) );

		$cards = Foyer::cards( $full );
		$by_slug = array();
		foreach ( $cards as $card ) {
			$by_slug[ $card['slug'] ] = $card;
		}
		$this->assertArrayHasKey( 'handl-aicac-taint', $by_slug );
		$this->assertArrayHasKey( 'handl-aicac-lookback', $by_slug );
		$this->assertArrayHasKey( 'handl-aicac-luggage', $by_slug );
		$this->assertArrayHasKey( 'handl-aicac-chargeback', $by_slug );
		$this->assertArrayNotHasKey( 'handl-aicac', $by_slug );
		$this->assertArrayNotHasKey( Foyer::PAGE_SLUG, $by_slug );
		$this->assertStringContainsString( 'page=handl-aicac-taint', $by_slug['handl-aicac-taint']['url'] );
		$this->assertSame( 'privacy', $by_slug['handl-aicac-taint']['group'] );
		$this->assertSame( 'cost', $by_slug['handl-aicac-chargeback']['group'] );
		$this->assertStringContainsString( 'injection', strtolower( $by_slug['handl-aicac-taint']['description'] ) );
	}

	public function test_pin_adds_tool_to_simple_menu_and_survives_reload(): void {
		Foyer::set_mode( Foyer::MODE_SIMPLE );
		$full = $this->sample_submenu();
		Foyer::set_test_submenu( $full );
		$_POST = array(
			'action'                 => Foyer::ACTION_PIN,
			'_wpnonce'               => 'testnonce',
			'handl_aicac_foyer_slug' => 'handl-aicac-taint',
		);
		Foyer::maybe_handle_post();
		Foyer::apply_simple_menu();
		$this->assertTrue( Foyer::is_pinned( 'handl-aicac-taint' ) );
		$this->assertContains( 'handl-aicac-taint', $this->slugs_of( $GLOBALS['submenu'][ Admin::MENU_SLUG ] ) );

		Foyer::reset_for_tests();
		$this->assertTrue( Foyer::is_pinned( 'handl-aicac-taint' ) );
		$this->assertContains( 'handl-aicac-taint', Foyer::pins() );

		Foyer::set_test_submenu( $full );
		$_POST = array(
			'action'                 => Foyer::ACTION_UNPIN,
			'_wpnonce'               => 'testnonce',
			'handl_aicac_foyer_slug' => 'handl-aicac-taint',
		);
		Foyer::maybe_handle_post();
		Foyer::apply_simple_menu();
		$this->assertFalse( Foyer::is_pinned( 'handl-aicac-taint' ) );
		$this->assertNotContains( 'handl-aicac-taint', $this->slugs_of( $GLOBALS['submenu'][ Admin::MENU_SLUG ] ) );
	}

	public function test_search_filters_title_and_description(): void {
		Foyer::set_mode( Foyer::MODE_SIMPLE );
		$full  = $this->sample_submenu();
		$title = Foyer::cards( $full, 'Chargeback' );
		$this->assertCount( 1, $title );
		$this->assertSame( 'handl-aicac-chargeback', $title[0]['slug'] );

		$desc = Foyer::cards( $full, 'injection' );
		$this->assertCount( 1, $desc );
		$this->assertSame( 'handl-aicac-taint', $desc[0]['slug'] );

		$empty = Foyer::cards( $full, 'zzzz-no-such-tool' );
		$this->assertSame( array(), $empty );
	}

	public function test_full_mode_restores_complete_menu(): void {
		$full = $this->sample_submenu();
		Foyer::set_mode( Foyer::MODE_SIMPLE );
		Foyer::set_test_submenu( $full );
		Foyer::apply_simple_menu();
		$this->assertCount( 8, $GLOBALS['submenu'][ Admin::MENU_SLUG ] );

		Foyer::reset_for_tests();
		Foyer::set_mode( Foyer::MODE_FULL );
		Foyer::set_test_submenu( $full );
		Foyer::apply_simple_menu();
		$this->assertSame( $this->slugs_of( $full ), $this->slugs_of( $GLOBALS['submenu'][ Admin::MENU_SLUG ] ) );
		$this->assertSame(
			$this->slugs_of( $full ),
			Foyer::visible_menu_slugs( $this->slugs_of( $full ) )
		);

		$_POST = array(
			'action'             => Foyer::ACTION_MODE,
			'_wpnonce'           => 'testnonce',
			'handl_aicac_ui_mode'=> Foyer::MODE_FULL,
		);
		Foyer::maybe_handle_post();
		$this->assertSame( Foyer::MODE_FULL, Foyer::mode() );
	}

	public function test_mode_toggle_renders_on_settings_screen(): void {
		Foyer::set_mode( Foyer::MODE_SIMPLE );
		$_GET['page'] = 'handl-aicac-alerts';
		ob_start();
		Foyer::maybe_render_mode_toggle();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Simple mode keeps the seven main screens in the menu and moves extra tools to More tools.', $html );
		$this->assertStringContainsString( 'Menu mode', $html );
		$this->assertStringContainsString( 'Full menu', $html );
		$this->assertStringContainsString( 'Save menu mode', $html );
		$this->assertStringContainsString( 'selected="selected"', $html );

		$_GET['page'] = 'handl-aicac';
		ob_start();
		Foyer::maybe_render_mode_toggle();
		$this->assertSame( '', (string) ob_get_clean() );
	}

	public function test_more_tools_page_copy_and_pin_controls(): void {
		Foyer::set_mode( Foyer::MODE_SIMPLE );
		Foyer::set_test_submenu( $this->sample_submenu() );
		$_GET['page'] = Foyer::PAGE_SLUG;
		ob_start();
		Foyer::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'More tools', $html );
		$this->assertStringContainsString( 'Extra screens stay available here. Pin a tool to put it back in the menu.', $html );
		$this->assertStringContainsString( 'Search tools', $html );
		$this->assertStringContainsString( 'Pin to menu', $html );
		$this->assertStringContainsString( 'Injection screen', $html );
		$this->assertStringContainsString( 'Exposure lookback', $html );
		$this->assertStringContainsString( 'Cost', $html );
		$this->assertStringContainsString( 'Privacy &amp; exposure', $html );
		$this->assertStringNotContainsString( '>Dashboard<', $html );
	}
}
