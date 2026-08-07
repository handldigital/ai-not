<?php
/**
 * Unit tests for Model_Force::resolve_route().
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Model_Force;
use PHPUnit\Framework\TestCase;

final class ModelForceResolveRouteTest extends TestCase {

	/**
	 * Plugin with a force row resolves to that provider/model.
	 */
	public function test_resolve_route_for_pinned_plugin(): void {
		$policy = array(
			'model_force_plugins' => array(
				'pinned/plugin.php' => array(
					'provider' => 'openai',
					'model'    => 'gpt-4o-mini',
				),
			),
		);

		$result = Model_Force::resolve_route( $policy, 'pinned/plugin.php' );

		$this->assertTrue( $result['apply'] );
		$this->assertSame( 'ok', $result['reason'] );
		$this->assertSame( 'openai', $result['provider'] );
		$this->assertSame( 'gpt-4o-mini', $result['model'] );
		$this->assertSame( 'plugin', $result['source'] );
	}

	/**
	 * Unattributed caller with default "don't force" and existing pins ⇒ unattributed gap.
	 */
	public function test_unattributed_with_pins_reports_unattributed(): void {
		$policy = array(
			'model_force_plugins'      => array(
				'pinned/plugin.php' => array(
					'provider' => 'openai',
					'model'    => 'gpt-4o-mini',
				),
			),
			'model_force_unattributed' => 'none',
		);

		$result = Model_Force::resolve_route( $policy, null );

		$this->assertFalse( $result['apply'] );
		$this->assertSame( 'unattributed', $result['reason'] );
	}

	/**
	 * Unattributed caller with explicit force target applies unattributed route.
	 */
	public function test_unattributed_force_opt_in_applies_route(): void {
		$policy = array(
			'model_force_unattributed'          => 'force',
			'model_force_unattributed_provider' => 'anthropic',
			'model_force_unattributed_model'    => 'claude-3-haiku',
		);

		$result = Model_Force::resolve_route( $policy, null );

		$this->assertTrue( $result['apply'] );
		$this->assertSame( 'ok', $result['reason'] );
		$this->assertSame( 'anthropic', $result['provider'] );
		$this->assertSame( 'claude-3-haiku', $result['model'] );
		$this->assertSame( 'unattributed', $result['source'] );
	}

	/**
	 * Plugin without a force row ⇒ no_rule.
	 */
	public function test_plugin_without_pin_is_no_rule(): void {
		$policy = array(
			'model_force_plugins' => array(
				'other/plugin.php' => array(
					'provider' => 'openai',
					'model'    => 'gpt-4o-mini',
				),
			),
		);

		$result = Model_Force::resolve_route( $policy, 'unpinned/plugin.php' );

		$this->assertFalse( $result['apply'] );
		$this->assertSame( 'no_rule', $result['reason'] );
	}
}
