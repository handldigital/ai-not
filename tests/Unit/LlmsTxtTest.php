<?php
/**
 * Unit tests for opt-in /llms.txt (AICAC-LLMS-TXT / #337).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Llms_Txt;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

final class LlmsTxtTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_added_filters'] = array();
		$GLOBALS['handl_aicac_test_query_vars']    = array();
		$GLOBALS['handl_aicac_test_rewrite_rules'] = array();
		$GLOBALS['handl_aicac_test_transients']    = array();
		unset(
			$GLOBALS['handl_aicac_test_flush_rewrite'],
			$GLOBALS['handl_aicac_test_llms_txt_emitted'],
			$GLOBALS['handl_aicac_test_status_header'],
			$GLOBALS['handl_aicac_test_filters']
		);
		Llms_Txt::reset_for_tests();
	}

	protected function tearDown(): void {
		Llms_Txt::reset_for_tests();
		unset(
			$GLOBALS['handl_aicac_test_options'],
			$GLOBALS['handl_aicac_test_added_actions'],
			$GLOBALS['handl_aicac_test_added_filters'],
			$GLOBALS['handl_aicac_test_query_vars'],
			$GLOBALS['handl_aicac_test_rewrite_rules'],
			$GLOBALS['handl_aicac_test_transients'],
			$GLOBALS['handl_aicac_test_flush_rewrite'],
			$GLOBALS['handl_aicac_test_llms_txt_emitted'],
			$GLOBALS['handl_aicac_test_status_header'],
			$GLOBALS['handl_aicac_test_filters']
		);
	}

	public function test_init_registers_hooks_without_option_io(): void {
		$before = $GLOBALS['handl_aicac_test_options'] ?? array();
		Llms_Txt::instance()->init();
		$actions = $GLOBALS['handl_aicac_test_added_actions'] ?? array();
		$filters = $GLOBALS['handl_aicac_test_added_filters'] ?? array();
		$this->assertContains( 'init', $actions );
		$this->assertContains( 'template_redirect', $actions );
		$this->assertContains( 'update_option_' . Plugin::OPTION_KEY, $actions );
		$this->assertContains( 'handl_aicac_protections_settings', $actions );
		$this->assertContains( 'query_vars', $filters );
		$this->assertContains( 'pre_update_option_' . Plugin::OPTION_KEY, $filters );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] ?? array() );
	}

	public function test_register_rewrite_and_query_var(): void {
		Llms_Txt::instance()->register_rewrite();
		$rules = $GLOBALS['handl_aicac_test_rewrite_rules'] ?? array();
		$this->assertNotEmpty( $rules );
		$this->assertSame( 'top', $rules[0]['after'] );
		$this->assertStringContainsString( 'llms', $rules[0]['regex'] );
		$vars = Llms_Txt::instance()->query_vars( array( 'p' ) );
		$this->assertContains( Llms_Txt::QUERY_VAR, $vars );
	}

	public function test_toggle_off_is_404_and_writes_nothing(): void {
		$before = $GLOBALS['handl_aicac_test_options'] ?? array();
		$out    = Llms_Txt::respond( array(), "User-agent: GPTBot\nDisallow: /\n" );
		$this->assertSame( 404, $out['status'] );
		$this->assertSame( '', $out['body'] );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] ?? array() );
	}

	public function test_toggle_on_serves_text_plain_reflecting_policy_and_crawlers(): void {
		$policy = array(
			Llms_Txt::POLICY_KEY => true,
			'default'            => 'deny',
			'audit_only'         => true,
			'plugins'            => array(
				'akismet/akismet.php' => 'allow',
				'hello.php'          => 'deny',
			),
		);
		$robots = "User-agent: GPTBot\nDisallow: /\n\nUser-agent: ClaudeBot\nAllow: /\n";
		$before = $GLOBALS['handl_aicac_test_options'] ?? array();
		$out    = Llms_Txt::respond( $policy, $robots );
		$this->assertSame( 200, $out['status'] );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] ?? array() );
		$this->assertSame( 'public, max-age=3600', $out['headers']['Cache-Control'] );
		$this->assertStringContainsString( 'text/plain', $out['headers']['Content-Type'] );
		$this->assertStringContainsString( '# Test Site', $out['body'] );
		$this->assertStringContainsString( 'Default for unknown plugins: Deny', $out['body'] );
		$this->assertStringContainsString( 'Mode: Learn (observe only)', $out['body'] );
		$this->assertStringContainsString( 'Explicit allow rules: 1', $out['body'] );
		$this->assertStringContainsString( 'Explicit deny rules: 1', $out['body'] );
		$this->assertStringContainsString( 'GPTBot', $out['body'] );
		$this->assertStringContainsString( 'Disallow', $out['body'] );
		$this->assertStringContainsString( 'ClaudeBot', $out['body'] );
	}

	public function test_preview_matches_served_bytes(): void {
		$policy = array(
			Llms_Txt::POLICY_KEY => true,
			'default'            => 'allow',
			'plugins'            => array(),
		);
		$robots  = "User-agent: *\nDisallow:\n";
		$preview = Llms_Txt::build_body( $policy, $robots );
		$served  = Llms_Txt::respond( $policy, $robots );
		$this->assertSame( 200, $served['status'] );
		$this->assertSame( $preview, $served['body'] );
	}

	public function test_policy_change_invalidates_cache_without_manual_regen(): void {
		$robots = "User-agent: GPTBot\nDisallow: /\n";
		$first  = Llms_Txt::respond(
			array(
				Llms_Txt::POLICY_KEY => true,
				'default'            => 'allow',
			),
			$robots
		);
		$this->assertStringContainsString( 'Default for unknown plugins: Allow', $first['body'] );

		Llms_Txt::invalidate_cache();
		$second = Llms_Txt::respond(
			array(
				Llms_Txt::POLICY_KEY => true,
				'default'            => 'deny',
			),
			$robots
		);
		$this->assertStringContainsString( 'Default for unknown plugins: Deny', $second['body'] );
		$this->assertNotSame( $first['body'], $second['body'] );
	}

	public function test_sections_filter_extends_body(): void {
		$GLOBALS['handl_aicac_test_filters'][ Llms_Txt::FILTER_SECTIONS ] = static function ( $sections ) {
			$sections = is_array( $sections ) ? $sections : array();
			$sections['Extensions'] = array( '- Custom extension line' );

			return $sections;
		};
		$body = Llms_Txt::build_body(
			array( Llms_Txt::POLICY_KEY => true ),
			"User-agent: *\nDisallow:\n"
		);
		$this->assertStringContainsString( '## Extensions', $body );
		$this->assertStringContainsString( 'Custom extension line', $body );
	}

	public function test_flush_only_when_toggle_changes(): void {
		Llms_Txt::instance()->on_policy_updated( array(), array( Llms_Txt::POLICY_KEY => true ) );
		$this->assertArrayHasKey( 'handl_aicac_test_flush_rewrite', $GLOBALS );
		unset( $GLOBALS['handl_aicac_test_flush_rewrite'] );
		Llms_Txt::instance()->on_policy_updated(
			array( Llms_Txt::POLICY_KEY => true ),
			array( Llms_Txt::POLICY_KEY => true )
		);
		$this->assertArrayNotHasKey( 'handl_aicac_test_flush_rewrite', $GLOBALS );
	}

	public function test_deactivate_flushes_rewrites_and_cache(): void {
		set_transient(
			Llms_Txt::CACHE_TRANSIENT,
			array(
				'fingerprint' => 'x',
				'body'        => ' stale ',
			),
			60
		);
		Llms_Txt::on_deactivate();
		$this->assertFalse( get_transient( Llms_Txt::CACHE_TRANSIENT ) );
		$this->assertArrayHasKey( 'handl_aicac_test_flush_rewrite', $GLOBALS );
	}

	public function test_emit_skips_exit_under_phpunit(): void {
		$out = array(
			'status'  => 200,
			'body'    => "# Site\n",
			'headers' => array( 'Cache-Control' => 'public, max-age=3600' ),
		);
		Llms_Txt::emit( $out );
		$this->assertSame( 200, $GLOBALS['handl_aicac_test_status_header'] );
		$this->assertSame( $out, $GLOBALS['handl_aicac_test_llms_txt_emitted'] );
	}

	public function test_plugin_wires_require_and_init(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertNotFalse( strpos( $src, "class-handl-aicac-llms-txt.php" ) );
		$this->assertNotFalse( strpos( $src, 'Llms_Txt::instance()->init()' ) );
	}

	public function test_readme_untouched(): void {
		$diff = shell_exec( 'git -C ' . escapeshellarg( HANDL_AICAC_DIR ) . ' diff --name-only origin/main -- readme.txt 2>/dev/null' );
		$this->assertSame( '', trim( (string) $diff ) );
	}

	public function test_merge_on_policy_save_reads_posted_toggle(): void {
		$_POST[ Llms_Txt::POST_PRESENT ] = '1';
		$_POST[ Llms_Txt::POST_ENABLED ] = '1';
		$merged = Llms_Txt::merge_on_policy_save( array( 'default' => 'allow' ), array() );
		$this->assertTrue( ! empty( $merged[ Llms_Txt::POLICY_KEY ] ) );
		unset( $_POST[ Llms_Txt::POST_PRESENT ], $_POST[ Llms_Txt::POST_ENABLED ] );

		$_POST[ Llms_Txt::POST_PRESENT ] = '1';
		$off = Llms_Txt::merge_on_policy_save( array( 'default' => 'allow' ), array() );
		$this->assertTrue( empty( $off[ Llms_Txt::POLICY_KEY ] ) );
		unset( $_POST[ Llms_Txt::POST_PRESENT ] );
	}

	public function test_render_settings_includes_toggle_and_preview(): void {
		ob_start();
		Llms_Txt::instance()->render_settings(
			array(
				Llms_Txt::POLICY_KEY => true,
				'default'            => 'deny',
			)
		);
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( Llms_Txt::SETTINGS_TITLE, $html );
		$this->assertStringContainsString( Llms_Txt::SETTINGS_TOGGLE, $html );
		$this->assertStringContainsString( 'handl-aicac-llms-txt-preview', $html );
		$this->assertStringContainsString( 'Default for unknown plugins: Deny', $html );
	}
}
