<?php
/**
 * Unit tests for curated policy presets (AICAC-PRESET / #106).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Cost;
use HandL\AICAC\Plugin;
use HandL\AICAC\Presets;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class PresetsTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['handl_aicac_test_options'] = array();
		unset( $GLOBALS['handl_aicac_test_filters'] );
	}

	public function test_catalog_has_four_builtin_presets_and_is_filterable(): void {
		$defs = Presets::definitions();
		$this->assertArrayHasKey( 'observe', $defs );
		$this->assertArrayHasKey( 'cost_guard', $defs );
		$this->assertArrayHasKey( 'lockdown', $defs );
		$this->assertArrayHasKey( 'privacy', $defs );

		$GLOBALS['handl_aicac_test_filters']['handl_aicac_presets'] = static function ( $defs ) {
			$defs['custom'] = array(
				'id'          => 'custom',
				'label'       => 'Custom',
				'description' => 'Test',
				'patch'       => array( 'default' => 'deny' ),
			);
			return $defs;
		};

		$filtered = Presets::definitions();
		$this->assertArrayHasKey( 'custom', $filtered );
		$this->assertSame( 'deny', $filtered['custom']['patch']['default'] );
	}

	public function test_diff_lists_current_to_new_and_flags_plugin_overwrites(): void {
		$current = array(
			'default'              => 'allow',
			'audit_only'           => false,
			'log_enabled'          => false,
			'kill_switch'          => false,
			'shadow_block_enabled' => false,
			'unknown_operation'    => 'inherit',
			'alert_on_deny'        => false,
			'alert_on_shadow'      => false,
			'alert_mode'           => 'immediate',
			'plugins'              => array( 'acme/plugin.php' => 'allow' ),
			'operations'           => array(),
		);

		// Built-in lockdown does not touch plugins — no overwrite flag.
		$diff = Presets::diff( 'lockdown', $current );
		$this->assertTrue( $diff['ok'] );
		$this->assertFalse( $diff['active'] );
		$this->assertFalse( $diff['overwrites'] );
		$this->assertNotEmpty( $diff['rows'] );
		$keys = array_column( $diff['rows'], 'key' );
		$this->assertContains( 'default', $keys );
		$this->assertContains( 'kill_switch', $keys );

		// Filter-injected preset that clears plugins must flag overwrite.
		$GLOBALS['handl_aicac_test_filters']['handl_aicac_presets'] = static function ( $defs ) {
			$defs['wipe'] = array(
				'id'          => 'wipe',
				'label'       => 'Wipe',
				'description' => 'Clears plugins',
				'patch'       => array( 'plugins' => array() ),
			);
			return $defs;
		};
		$wipe = Presets::diff( 'wipe', $current );
		$this->assertTrue( $wipe['ok'] );
		$this->assertTrue( $wipe['overwrites'] );
	}

	public function test_apply_is_idempotent_noop_when_active(): void {
		$base = array(
			'default'              => 'allow',
			'audit_only'           => false,
			'log_enabled'          => true,
			'kill_switch'          => false,
			'shadow_block_enabled' => false,
			'unknown_operation'    => 'inherit',
			'alert_on_deny'        => false,
			'alert_mode'           => 'immediate',
			'plugins'              => array(),
			'operations'           => array(),
		);
		update_option( Plugin::OPTION_KEY, $base );

		$first = Presets::apply( 'observe', Policy::get_policy() );
		$this->assertTrue( $first['ok'] );
		$this->assertSame( 'applied', $first['status'] );

		$policy = Policy::get_policy();
		$this->assertTrue( Presets::is_active( 'observe', $policy ) );
		$this->assertTrue( ! empty( $policy['audit_only'] ) );
		$this->assertTrue( ! empty( $policy['alert_on_deny'] ) );

		$second = Presets::apply( 'observe', $policy );
		$this->assertTrue( $second['ok'] );
		$this->assertSame( 'noop', $second['status'] );

		$diff = Presets::diff( 'observe', Policy::get_policy() );
		$this->assertTrue( $diff['active'] );
		$this->assertSame( array(), $diff['rows'] );
	}

	public function test_cost_guard_sets_spend_threshold_and_default_rates(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
			)
		);
		$result = Presets::apply( 'cost_guard', Policy::get_policy() );
		$this->assertSame( 'applied', $result['status'] );
		$policy = Policy::get_policy();
		$this->assertSame( 25.0, $policy['spend_threshold_site'] );
		$this->assertSame( Cost::DEFAULT_INPUT_PER_M, $policy['est_usd_input_per_m'] );
		$this->assertSame( Cost::DEFAULT_OUTPUT_PER_M, $policy['est_usd_output_per_m'] );
		$this->assertFalse( ! empty( $policy['kill_switch'] ) );
		$this->assertFalse( ! empty( $policy['shadow_block_enabled'] ) );
	}

	public function test_privacy_denies_unknown_operations_and_enables_immediate_alerts(): void {
		update_option( Plugin::OPTION_KEY, array( 'default' => 'allow' ) );
		Presets::apply( 'privacy', Policy::get_policy() );
		$policy = Policy::get_policy();
		$this->assertSame( 'deny', $policy['unknown_operation'] );
		$this->assertTrue( ! empty( $policy['shadow_block_enabled'] ) );
		$this->assertTrue( ! empty( $policy['alert_on_deny'] ) );
		$this->assertSame( 'immediate', $policy['alert_mode'] );
	}

	public function test_lockdown_deny_default_kill_switch_and_shadow_block(): void {
		update_option( Plugin::OPTION_KEY, array( 'default' => 'allow' ) );
		Presets::apply( 'lockdown', Policy::get_policy() );
		$policy = Policy::get_policy();
		$this->assertSame( 'deny', $policy['default'] );
		$this->assertTrue( ! empty( $policy['kill_switch'] ) );
		$this->assertTrue( ! empty( $policy['shadow_block_enabled'] ) );
	}
}
