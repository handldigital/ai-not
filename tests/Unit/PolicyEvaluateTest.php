<?php
/**
 * Unit tests for Policy::evaluate() allow/deny branches.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Operations;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class PolicyEvaluateTest extends TestCase {

	/**
	 * Default policy is allow: unknown plugins are permitted.
	 */
	public function test_default_allow_permits_unknown_plugin(): void {
		$policy = array(
			'default' => 'allow',
			'plugins' => array(),
		);

		$result = Policy::evaluate( $policy, 'some-plugin/plugin.php', 'generate_text' );

		$this->assertFalse( $result['prevent'] );
		$this->assertSame( '', $result['reason'] );
	}

	/**
	 * Explicit per-plugin deny blocks regardless of default allow.
	 */
	public function test_explicit_plugin_deny(): void {
		$policy = array(
			'default' => 'allow',
			'plugins' => array(
				'blocked/plugin.php' => 'deny',
			),
		);

		$result = Policy::evaluate( $policy, 'blocked/plugin.php', 'generate_text' );

		$this->assertTrue( $result['prevent'] );
		$this->assertSame( 'plugin', $result['reason'] );
	}

	/**
	 * Explicit allow still works when default is deny.
	 */
	public function test_explicit_plugin_allow_overrides_default_deny(): void {
		$policy = array(
			'default' => 'deny',
			'plugins' => array(
				'trusted/plugin.php' => 'allow',
			),
		);

		$result = Policy::evaluate( $policy, 'trusted/plugin.php', 'generate_text' );

		$this->assertFalse( $result['prevent'] );
	}

	/**
	 * Default deny blocks plugins with no explicit rule.
	 */
	public function test_default_deny_blocks_unknown_plugin(): void {
		$policy = array(
			'default' => 'deny',
			'plugins' => array(),
		);

		$result = Policy::evaluate( $policy, 'unknown/plugin.php', 'generate_text' );

		$this->assertTrue( $result['prevent'] );
		$this->assertSame( 'plugin', $result['reason'] );
	}

	/**
	 * Per-capability-family deny blocks that family while other families remain allowed.
	 */
	public function test_capability_family_deny_overrides_plugin_allow(): void {
		$plugin = 'matrix/plugin.php';
		$policy = array(
			'default'    => 'allow',
			'plugins'    => array(
				$plugin => 'allow',
			),
			'operations' => array(
				$plugin => array(
					Operations::FAMILY_IMAGE => 'deny',
				),
			),
		);

		$image = Policy::evaluate( $policy, $plugin, 'generate_image' );
		$this->assertTrue( $image['prevent'] );
		$this->assertSame( 'capability_family', $image['reason'] );

		$text = Policy::evaluate( $policy, $plugin, 'generate_text' );
		$this->assertFalse( $text['prevent'] );
	}

	/**
	 * Family deny applies to support-check operations in the same family.
	 */
	public function test_capability_family_deny_covers_support_check(): void {
		$plugin = 'matrix/plugin.php';
		$policy = array(
			'default'    => 'allow',
			'plugins'    => array( $plugin => 'allow' ),
			'operations' => array(
				$plugin => array( Operations::FAMILY_TEXT => 'deny' ),
			),
		);

		$result = Policy::evaluate( $policy, $plugin, 'is_supported_for_text_generation' );

		$this->assertTrue( $result['prevent'] );
		$this->assertSame( 'capability_family', $result['reason'] );
	}

	/**
	 * Unknown-operation fallback inherit: plugin already allowed ⇒ allow.
	 */
	public function test_unknown_operation_fallback_inherit_allows(): void {
		$policy = array(
			'default'            => 'allow',
			'plugins'            => array(),
			'unknown_operation'  => 'inherit',
		);

		$result = Policy::evaluate( $policy, 'any/plugin.php', 'is_supported_for_music_generation' );

		$this->assertFalse( $result['prevent'] );
	}

	/**
	 * Unknown-operation fallback allow: explicitly permits unmapped ops.
	 */
	public function test_unknown_operation_fallback_allow(): void {
		$policy = array(
			'default'           => 'allow',
			'plugins'           => array(),
			'unknown_operation' => 'allow',
		);

		$result = Policy::evaluate( $policy, 'any/plugin.php', 'is_supported_for_embedding_generation' );

		$this->assertFalse( $result['prevent'] );
	}

	/**
	 * Unknown-operation fallback deny: blocks unmapped ops even when plugin is allowed.
	 */
	public function test_unknown_operation_fallback_deny(): void {
		$policy = array(
			'default'           => 'allow',
			'plugins'           => array( 'any/plugin.php' => 'allow' ),
			'unknown_operation' => 'deny',
		);

		$result = Policy::evaluate( $policy, 'any/plugin.php', 'is_supported_for_music_generation' );

		$this->assertTrue( $result['prevent'] );
		$this->assertSame( 'unknown_operation', $result['reason'] );
	}

	/**
	 * Kill switch blocks all callers when exceptions list is empty.
	 */
	public function test_kill_switch_blocks_all_with_empty_exceptions(): void {
		$policy = array(
			'default'                 => 'allow',
			'kill_switch'             => true,
			'kill_switch_exceptions'  => array(),
		);

		$result = Policy::evaluate( $policy, 'any/plugin.php', 'generate_text' );

		$this->assertTrue( $result['prevent'] );
		$this->assertSame( 'kill_switch', $result['reason'] );
	}

	/**
	 * Kill-switch exception falls through to normal rules (not unconditional allow).
	 */
	public function test_kill_switch_exception_falls_through_to_normal_rules(): void {
		$excepted = 'excepted/plugin.php';
		$policy   = array(
			'default'                => 'allow',
			'kill_switch'            => true,
			'kill_switch_exceptions' => array( $excepted ),
			'plugins'                => array(
				$excepted => 'deny',
			),
		);

		// Excepted from kill switch, but still denied by plugin rule.
		$denied = Policy::evaluate( $policy, $excepted, 'generate_text' );
		$this->assertTrue( $denied['prevent'] );
		$this->assertSame( 'plugin', $denied['reason'] );

		// Non-excepted caller still hit by kill switch.
		$blocked = Policy::evaluate( $policy, 'other/plugin.php', 'generate_text' );
		$this->assertTrue( $blocked['prevent'] );
		$this->assertSame( 'kill_switch', $blocked['reason'] );
	}

	/**
	 * Kill-switch exception with plugin allow proceeds past kill switch.
	 */
	public function test_kill_switch_exception_with_allow_permits(): void {
		$excepted = 'excepted/plugin.php';
		$policy   = array(
			'default'                => 'allow',
			'kill_switch'            => true,
			'kill_switch_exceptions' => array( $excepted ),
			'plugins'                => array(
				$excepted => 'allow',
			),
		);

		$result = Policy::evaluate( $policy, $excepted, 'generate_text' );

		$this->assertFalse( $result['prevent'] );
	}

	/**
	 * Unattributed caller (null plugin) uses default — allow when default-allow.
	 */
	public function test_unattributed_caller_uses_default_allow(): void {
		$policy = array(
			'default' => 'allow',
			'plugins' => array(),
		);

		$result = Policy::evaluate( $policy, null, 'generate_text' );

		$this->assertFalse( $result['prevent'] );
	}

	/**
	 * Unattributed caller under kill switch is blocked (cannot match exceptions).
	 */
	public function test_unattributed_caller_blocked_by_kill_switch(): void {
		$policy = array(
			'default'                => 'allow',
			'kill_switch'            => true,
			'kill_switch_exceptions' => array( 'excepted/plugin.php' ),
		);

		$result = Policy::evaluate( $policy, null, 'generate_text' );

		$this->assertTrue( $result['prevent'] );
		$this->assertSame( 'kill_switch', $result['reason'] );
	}

	/**
	 * Empty / corrupted-style policy array still evaluates without fatal (documented default allow).
	 */
	public function test_empty_policy_array_defaults_to_allow(): void {
		$result = Policy::evaluate( array(), 'any/plugin.php', 'generate_text' );

		$this->assertFalse( $result['prevent'] );
	}
}
