<?php
/**
 * AICAC-SWITCH-IMPORT (#330): robots.txt + Block AI Crawlers → draft policy.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Disclosure;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Switch_Import;
use PHPUnit\Framework\TestCase;

final class SwitchImportTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		Switch_Import::reset_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Switch_Import::COMPETITOR_OPTION_DISABLED );
		delete_option( Switch_Import::COMPETITOR_OPTION_CUSTOM );
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
	}

	protected function tearDown(): void {
		Switch_Import::reset_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Switch_Import::COMPETITOR_OPTION_DISABLED );
		delete_option( Switch_Import::COMPETITOR_OPTION_CUSTOM );
		unset( $GLOBALS['handl_aicac_test_current_user_can'] );
		parent::tearDown();
	}

	public function test_known_agents_at_least_ten(): void {
		$agents = Switch_Import::known_agents();
		$this->assertGreaterThanOrEqual( 10, count( $agents ) );
		$this->assertArrayHasKey( 'GPTBot', $agents );
		$this->assertArrayHasKey( 'CCBot', $agents );
		$this->assertArrayHasKey( 'ClaudeBot', $agents );
		$this->assertArrayHasKey( 'Google-Extended', $agents );
	}

	public function test_parse_robots_maps_known_and_lists_unmapped(): void {
		$text = <<<'ROBOTS'
User-agent: GPTBot
Disallow: /

User-agent: ClaudeBot
Disallow: /

User-agent: WeirdBot9000
Disallow: /

User-agent: Googlebot
Allow: /
ROBOTS;

		$parsed = Switch_Import::parse_robots( $text );
		$this->assertSame( 2, $parsed['blocked_count'] );

		$mapped_agents = array_column( $parsed['mapped'], 'agent' );
		$this->assertContains( 'GPTBot', $mapped_agents );
		$this->assertContains( 'ClaudeBot', $mapped_agents );

		$unmapped_agents = array_column( $parsed['unmapped'], 'agent' );
		$this->assertContains( 'WeirdBot9000', $unmapped_agents );
		$this->assertContains( 'Googlebot', $unmapped_agents );

		foreach ( $parsed['unmapped'] as $row ) {
			if ( 'WeirdBot9000' === $row['agent'] ) {
				$this->assertTrue( $row['disallow'] );
			}
			if ( 'Googlebot' === $row['agent'] ) {
				$this->assertFalse( $row['disallow'] );
			}
		}
	}

	public function test_parse_robots_multi_ua_block_group(): void {
		$text = <<<'ROBOTS'
User-agent: GPTBot
User-agent: CCBot
User-agent: Bytespider
Disallow: /
ROBOTS;

		$parsed = Switch_Import::parse_robots( $text );
		$this->assertSame( 3, $parsed['blocked_count'] );
		$agents = array_column( $parsed['mapped'], 'agent' );
		$this->assertContains( 'GPTBot', $agents );
		$this->assertContains( 'CCBot', $agents );
		$this->assertContains( 'Bytespider', $agents );
	}

	public function test_competitor_inactive_is_graceful_empty(): void {
		$comp = Switch_Import::detect_block_ai_crawlers( array( 'akismet/akismet.php' ) );
		$this->assertFalse( $comp['active'] );
		$this->assertFalse( $comp['found'] );
		$this->assertSame( 'not_installed', $comp['note'] );
		$this->assertSame( array(), $comp['blocked_agents'] );
	}

	public function test_competitor_active_maps_blocked_agents(): void {
		update_option( Switch_Import::COMPETITOR_OPTION_DISABLED, array( 'GPTBot' ), false );
		$comp = Switch_Import::detect_block_ai_crawlers(
			array( Switch_Import::COMPETITOR_BLOCK_AI_CRAWLERS )
		);
		$this->assertTrue( $comp['active'] );
		$this->assertTrue( $comp['found'] );
		$this->assertNotContains( 'GPTBot', $comp['blocked_agents'] );
		$this->assertContains( 'ClaudeBot', $comp['blocked_agents'] );
	}

	public function test_competitor_active_all_disabled_is_nothing_to_import(): void {
		update_option(
			Switch_Import::COMPETITOR_OPTION_DISABLED,
			array_keys( Switch_Import::known_agents() ),
			false
		);
		$comp = Switch_Import::detect_block_ai_crawlers(
			array( Switch_Import::COMPETITOR_BLOCK_AI_CRAWLERS )
		);
		$this->assertTrue( $comp['active'] );
		$this->assertFalse( $comp['found'] );
		$this->assertSame( 'nothing_to_import', $comp['note'] );
	}

	public function test_scan_empty_produces_no_patch(): void {
		$result = Switch_Import::scan(
			"User-agent: *\nDisallow:\n",
			array( 'akismet/akismet.php' )
		);
		$this->assertTrue( $result['ok'] );
		$this->assertSame( 'empty', $result['status'] );
		$this->assertFalse( $result['draft']['has_import'] );
		$this->assertSame( array(), $result['draft']['patch'] );
	}

	public function test_scan_builds_draft_without_saving(): void {
		$before = get_option( Plugin::OPTION_KEY, null );
		$result = Switch_Import::scan(
			"User-agent: GPTBot\nDisallow: /\n\nUser-agent: Google-Extended\nDisallow: /\n",
			array()
		);
		$this->assertSame( 'draft', $result['status'] );
		$this->assertTrue( $result['draft']['has_import'] );
		$this->assertTrue( $result['draft']['patch']['shadow_block_enabled'] );
		$this->assertTrue( $result['draft']['patch']['disclosure_privacy'] );
		$this->assertContains( 'robots.txt', $result['draft']['sources'] );
		$this->assertSame( $before, get_option( Plugin::OPTION_KEY, null ) );
	}

	public function test_cancel_path_leaves_policy_unchanged(): void {
		Policy::save_policy(
			array(
				'default'              => 'allow',
				'shadow_block_enabled' => false,
				'disclosure_privacy'   => false,
			)
		);
		$before = Policy::get_policy();
		$scan   = Switch_Import::scan(
			"User-agent: GPTBot\nDisallow: /\n",
			array()
		);
		$this->assertTrue( $scan['draft']['has_import'] );
		// Cancel = do not call apply.
		$after = Policy::get_policy();
		$this->assertSame(
			! empty( $before['shadow_block_enabled'] ),
			! empty( $after['shadow_block_enabled'] )
		);
		$this->assertFalse( ! empty( $after['shadow_block_enabled'] ) );
	}

	public function test_apply_persists_draft_via_save_policy(): void {
		Policy::save_policy(
			array(
				'default'              => 'allow',
				'shadow_block_enabled' => false,
				'disclosure_privacy'   => false,
				'unknown_operation'    => 'inherit',
			)
		);
		$scan = Switch_Import::scan(
			"User-agent: GPTBot\nDisallow: /\n",
			array()
		);
		$result = Switch_Import::apply( Policy::get_policy(), $scan['draft'] );
		$this->assertTrue( $result['ok'] );
		$this->assertSame( 'applied', $result['status'] );

		$policy = Policy::get_policy();
		$this->assertTrue( ! empty( $policy['shadow_block_enabled'] ) );
		$this->assertSame( 'deny', $policy['unknown_operation'] );
		$this->assertTrue( Disclosure::is_privacy_enabled( $policy ) );
	}

	public function test_plugin_wires_switch_import(): void {
		$plugin = file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertNotFalse( $plugin );
		$this->assertStringContainsString( 'class-handl-aicac-switch-import.php', $plugin );
		$this->assertStringContainsString( 'Switch_Import::instance()->init()', $plugin );

		$admin = file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertNotFalse( $admin );
		$this->assertStringContainsString( 'Switch_Import::render_policy_tools_section', $admin );

		$boot = file_get_contents( HANDL_AICAC_DIR . '/tests/bootstrap.php' );
		$this->assertNotFalse( $boot );
		$this->assertStringContainsString( 'class-handl-aicac-switch-import.php', $boot );
	}

	public function test_readme_untouched_for_readme_free_lane(): void {
		// Ralph routing: README-FREE for #330 — no Unreleased bullet in this PR.
		$readme = file_get_contents( HANDL_AICAC_DIR . '/readme.txt' );
		$this->assertNotFalse( $readme );
		$this->assertStringNotContainsString( 'Create a policy from existing AI blocks', $readme );
		$this->assertStringNotContainsString( 'SWITCH-IMPORT', $readme );
	}

	public function test_krusty_copy_strings_present(): void {
		$src = file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-switch-import.php' );
		$this->assertNotFalse( $src );
		$this->assertStringContainsString( 'Create a policy from existing AI blocks', $src );
		$this->assertStringContainsString( 'Scan robots.txt and Block AI Crawlers settings, then review suggested AI Not settings.', $src );
		$this->assertStringContainsString( 'Scan robots.txt and Block AI Crawlers', $src );
		$this->assertStringContainsString( 'Crawler rules are shown for reference.', $src );
		$this->assertStringContainsString( 'Unrecognized crawlers', $src );
		$this->assertStringContainsString( 'These crawlers are not in our AI list.', $src );
		$this->assertStringContainsString( 'No supported AI block rules found. Your policy is unchanged.', $src );
		$this->assertStringContainsString( 'Cancel (keep current policy)', $src );
		$this->assertStringContainsString( 'Disallow rule found', $src );
		$this->assertStringContainsString( 'No site-wide Disallow rule found', $src );
		$this->assertStringContainsString( 'Queued alerts', $src );
		$this->assertStringContainsString( 'Not set', $src );
		$this->assertStringNotContainsString( "'blocked'", $src );
		$this->assertStringNotContainsString( "'allowed'", $src );
	}
}
