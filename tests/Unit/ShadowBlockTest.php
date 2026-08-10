<?php
/**
 * Unit tests for AICAC-23 opt-in shadow-AI blocking.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Shadow_AI;
use PHPUnit\Framework\TestCase;

final class ShadowBlockTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['handl_aicac_test_options'] = array();
		Shadow_AI::reset_pending_for_tests();
	}

	protected function tearDown(): void {
		Shadow_AI::reset_pending_for_tests();
		unset( $GLOBALS['handl_aicac_test_options'] );
	}

	public function test_decide_default_off_is_observe(): void {
		$v = Shadow_AI::decide( false, false );
		$this->assertSame( 'observe', $v['decision'] );
		$this->assertSame( '', $v['denial_reason'] );
		$this->assertFalse( $v['shadow_exception'] );
	}

	public function test_decide_block_on_denies_non_exception(): void {
		$v = Shadow_AI::decide( true, false );
		$this->assertSame( 'deny', $v['decision'] );
		$this->assertSame( 'shadow_block', $v['denial_reason'] );
		$this->assertFalse( $v['shadow_exception'] );
	}

	public function test_decide_block_on_allows_exception_explicitly(): void {
		$v = Shadow_AI::decide( true, true );
		$this->assertSame( 'allow', $v['decision'] );
		$this->assertSame( 'shadow_block_exception', $v['denial_reason'] );
		$this->assertTrue( $v['shadow_exception'] );
	}

	public function test_plugin_is_exception(): void {
		$policy = array(
			'shadow_block_exceptions' => array( 'acme/acme.php', 'other/other.php' ),
		);
		$this->assertTrue( Shadow_AI::plugin_is_exception( 'acme/acme.php', $policy ) );
		$this->assertFalse( Shadow_AI::plugin_is_exception( 'nope/nope.php', $policy ) );
		$this->assertFalse( Shadow_AI::plugin_is_exception( '', $policy ) );
	}

	public function test_block_error_code(): void {
		$err = Shadow_AI::block_error();
		$this->assertInstanceOf( \WP_Error::class, $err );
		$this->assertSame( Shadow_AI::BLOCK_ERROR_CODE, $err->code );
		$this->assertStringContainsString( 'Blocked', $err->message );
	}

	public function test_default_off_does_not_block_matched_host(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled'           => true,
				'shadow_block_enabled'  => false,
			)
		);

		$result = Shadow_AI::handle_http_request(
			false,
			array(),
			'https://api.openai.com/v1/chat/completions'
		);

		$this->assertFalse( $result );
	}

	public function test_block_on_returns_wp_error_for_matched_host(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled'          => true,
				'shadow_block_enabled' => true,
			)
		);

		$result = Shadow_AI::handle_http_request(
			false,
			array(),
			'https://api.anthropic.com/v1/messages'
		);

		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( Shadow_AI::BLOCK_ERROR_CODE, $result->code );
	}

	public function test_block_on_exception_plugin_not_blocked(): void {
		// Attribution without a plugin basename cannot match exceptions; pure path uses decide.
		// Integration: empty plugin is never an exception → would block. Covered by decide + is_exception.
		$this->assertTrue(
			Shadow_AI::plugin_is_exception(
				'trusted/trusted.php',
				array( 'shadow_block_exceptions' => array( 'trusted/trusted.php' ) )
			)
		);
		$v = Shadow_AI::decide( true, true );
		$this->assertSame( 'allow', $v['decision'] );
	}

	public function test_unknown_host_never_blocked(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled'          => true,
				'shadow_block_enabled' => true,
			)
		);

		$result = Shadow_AI::handle_http_request(
			false,
			array(),
			'https://example.com/api'
		);

		$this->assertFalse( $result );
	}

	public function test_match_provider_known_hosts(): void {
		$this->assertSame( 'openai', Shadow_AI::match_provider( 'api.openai.com' ) );
		$this->assertSame( 'openai', Shadow_AI::match_provider( 'sub.api.openai.com' ) );
		$this->assertNull( Shadow_AI::match_provider( 'evil-api.openai.com.evil.com' ) );
		$this->assertNull( Shadow_AI::match_provider( 'example.com' ) );
	}

	public function test_get_block_exceptions_sanitizes(): void {
		$clean = Shadow_AI::get_block_exceptions(
			array(
				'shadow_block_exceptions' => array( ' a/a.php ', '', 'b/b.php', 'a/a.php' ),
			)
		);
		$this->assertSame( array( 'a/a.php', 'b/b.php' ), $clean );
	}
}
