<?php
/**
 * Unit tests for opt-in /.well-known/ai.json (AICAC-AI-TXT / #309).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Ai_Json;
use HandL\AICAC\Disclosure;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

final class AiJsonTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_added_filters'] = array();
		$GLOBALS['handl_aicac_test_query_vars']    = array();
		$GLOBALS['handl_aicac_test_rewrite_rules'] = array();
		unset( $GLOBALS['handl_aicac_test_flush_rewrite'], $GLOBALS['handl_aicac_test_ai_json_emitted'], $GLOBALS['handl_aicac_test_status_header'] );
		Ai_Json::reset_for_tests();
	}

	protected function tearDown(): void {
		Ai_Json::reset_for_tests();
		unset(
			$GLOBALS['handl_aicac_test_options'],
			$GLOBALS['handl_aicac_test_added_actions'],
			$GLOBALS['handl_aicac_test_added_filters'],
			$GLOBALS['handl_aicac_test_query_vars'],
			$GLOBALS['handl_aicac_test_rewrite_rules'],
			$GLOBALS['handl_aicac_test_flush_rewrite'],
			$GLOBALS['handl_aicac_test_ai_json_emitted'],
			$GLOBALS['handl_aicac_test_status_header']
		);
	}

	public function test_init_registers_rewrite_hooks_without_option_io(): void {
		$before = $GLOBALS['handl_aicac_test_options'] ?? array();
		Ai_Json::instance()->init();
		$actions = $GLOBALS['handl_aicac_test_added_actions'] ?? array();
		$filters = $GLOBALS['handl_aicac_test_added_filters'] ?? array();
		$this->assertContains( 'init', $actions );
		$this->assertContains( 'template_redirect', $actions );
		$this->assertContains( 'update_option_' . Plugin::OPTION_KEY, $actions );
		$this->assertContains( 'query_vars', $filters );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] ?? array() );
	}

	public function test_register_rewrite_and_query_var(): void {
		Ai_Json::instance()->register_rewrite();
		$rules = $GLOBALS['handl_aicac_test_rewrite_rules'] ?? array();
		$this->assertNotEmpty( $rules );
		$this->assertSame( 'top', $rules[0]['after'] );
		$this->assertStringContainsString( 'well-known/ai', $rules[0]['regex'] );
		$vars = Ai_Json::instance()->query_vars( array( 'p' ) );
		$this->assertContains( Ai_Json::QUERY_VAR, $vars );
	}

	public function test_toggle_off_is_404_and_writes_nothing(): void {
		$before = $GLOBALS['handl_aicac_test_options'] ?? array();
		$out    = Ai_Json::respond( array(), array(), false );
		$this->assertSame( 404, $out['status'] );
		$this->assertSame( '', $out['body'] );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] ?? array() );
	}

	public function test_toggle_on_is_cached_json_and_byte_stable(): void {
		$policy = array( Disclosure::POLICY_JSON_KEY => true );
		$log    = array(
			array(
				'ts'                => 1_700_000_000,
				'provider'          => 'openai',
				'capability_family' => 'text',
			),
			array(
				'ts'                => 1_700_000_100,
				'provider'          => 'anthropic',
				'capability_family' => 'image',
			),
		);
		$before = $GLOBALS['handl_aicac_test_options'] ?? array();
		$first  = Ai_Json::respond( $policy, $log, false );
		$second = Ai_Json::respond( $policy, $log, false );
		$this->assertSame( 200, $first['status'] );
		$this->assertSame( $first['body'], $second['body'] );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] ?? array() );
		$this->assertSame( 'public, max-age=3600', $first['headers']['Cache-Control'] );
		$this->assertStringContainsString( 'application/json', $first['headers']['Content-Type'] );
		$decoded = json_decode( $first['body'], true );
		$this->assertIsArray( $decoded );
		$this->assertSame( 'OpenAI', $decoded['providers'][0]['label'] );
		$this->assertSame( 'Anthropic', $decoded['providers'][1]['label'] );
		$this->assertSame( array( 'Text', 'Image' ), $decoded['used_for'] );
	}

	public function test_flush_only_when_json_toggle_changes(): void {
		Ai_Json::instance()->maybe_flush_rewrites( array(), array( Disclosure::POLICY_JSON_KEY => true ) );
		$this->assertArrayHasKey( 'handl_aicac_test_flush_rewrite', $GLOBALS );
		unset( $GLOBALS['handl_aicac_test_flush_rewrite'] );
		Ai_Json::instance()->maybe_flush_rewrites( array( Disclosure::POLICY_JSON_KEY => true ), array( Disclosure::POLICY_JSON_KEY => true ) );
		$this->assertArrayNotHasKey( 'handl_aicac_test_flush_rewrite', $GLOBALS );
	}

	public function test_rest_mirror_url_does_not_need_permalinks(): void {
		$this->assertStringContainsString( 'wp-json/handl-aicac/v1/disclosure', Ai_Json::rest_mirror_url() );
		$this->assertStringContainsString( '/.well-known/ai.json', Ai_Json::public_url() );
	}

	public function test_emit_skips_exit_under_phpunit(): void {
		$out = array(
			'status'  => 200,
			'body'    => '{"ok":true}',
			'headers' => array( 'Cache-Control' => 'public, max-age=3600' ),
		);
		Ai_Json::emit( $out );
		$this->assertSame( 200, $GLOBALS['handl_aicac_test_status_header'] );
		$this->assertSame( $out, $GLOBALS['handl_aicac_test_ai_json_emitted'] );
	}
}
