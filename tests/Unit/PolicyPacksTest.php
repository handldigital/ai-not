<?php
/**
 * Unit tests for starter policy packs (AICAC-TEMPLATES / #173).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Policy_Packs;
use HandL\AICAC\Policy_Snapshots;
use PHPUnit\Framework\TestCase;

final class PolicyPacksTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['handl_aicac_test_options'] = array();
		unset( $GLOBALS['handl_aicac_test_filters'] );
	}

	public function test_catalog_has_three_builtin_packs_and_is_filterable(): void {
		$defs = Policy_Packs::definitions();
		$this->assertArrayHasKey( 'strict', $defs );
		$this->assertArrayHasKey( 'balanced', $defs );
		$this->assertArrayHasKey( 'observe_first', $defs );
		$this->assertStringContainsString( 'Observe-only mode', $defs['balanced']['description'] );
		$this->assertStringContainsString( 'Observe-only mode', $defs['observe_first']['description'] );

		$GLOBALS['handl_aicac_test_filters']['handl_aicac_policy_packs'] = static function ( $defs ) {
			$defs['custom'] = array(
				'id'          => 'custom',
				'label'       => 'Custom',
				'description' => 'Test',
				'patch'       => array( 'default' => 'deny' ),
			);
			return $defs;
		};

		$filtered = Policy_Packs::definitions();
		$this->assertArrayHasKey( 'custom', $filtered );
		$this->assertSame( 'deny', $filtered['custom']['patch']['default'] );
	}

	public function test_observe_first_enables_observe_only_mode(): void {
		$current = array(
			'default'     => 'allow',
			'audit_only'  => false,
			'log_enabled' => false,
			'plugins'     => array(),
		);
		$target = Policy_Packs::build_target( 'observe_first', $current );
		$this->assertNotNull( $target );
		$this->assertTrue( ! empty( $target['audit_only'] ) );
		$this->assertTrue( ! empty( $target['log_enabled'] ) );
	}

	public function test_strict_seeds_active_plugins_allow_and_keeps_conflicting_user_rules(): void {
		$current = array(
			'default'     => 'allow',
			'audit_only'  => false,
			'log_enabled' => true,
			'plugins'     => array(
				'keep/me.php' => 'deny',
			),
			'operations'  => array(),
		);

		$merge = Policy_Packs::build_merge(
			'strict',
			$current,
			array( 'keep/me.php', 'fresh/ok.php' )
		);
		$this->assertNotNull( $merge );
		$this->assertSame( 'deny', $merge['target']['default'] );
		$this->assertSame( 'deny', $merge['target']['plugins']['keep/me.php'] );
		$this->assertSame( 'allow', $merge['target']['plugins']['fresh/ok.php'] );
		$this->assertNotEmpty( $merge['conflicts'] );
		$this->assertSame( 'keep/me.php', $merge['conflicts'][0]['key'] );
		$this->assertSame( 'deny', $merge['conflicts'][0]['current'] );
		$this->assertSame( 'allow', $merge['conflicts'][0]['pack'] );
	}

	public function test_preview_reuses_policy_snapshots_diff_rows(): void {
		$current = array(
			'default'                   => 'allow',
			'audit_only'                => false,
			'log_enabled'               => true,
			'kill_switch'               => false,
			'shadow_block_enabled'      => false,
			'unknown_operation'         => 'inherit',
			'alert_on_deny'             => false,
			'alert_on_shadow'           => false,
			'alert_mode'                => 'immediate',
			'new_plugin_review_enabled' => false,
			'new_plugin_interim'        => 'deny',
			'plugins'                   => array(),
			'operations'                => array(),
		);
		$preview = Policy_Packs::preview( 'balanced', $current, array() );
		$this->assertTrue( $preview['ok'] );
		$this->assertFalse( $preview['active'] );
		$this->assertNotEmpty( $preview['rows'] );

		$target = Policy_Packs::build_target( 'balanced', $current, array() );
		$this->assertNotNull( $target );
		$this->assertSame( Policy_Snapshots::diff_rows( $current, $target ), $preview['rows'] );
	}

	public function test_apply_is_idempotent_noop_when_active(): void {
		$base = array(
			'default'                   => 'allow',
			'audit_only'                => false,
			'log_enabled'               => true,
			'kill_switch'               => false,
			'shadow_block_enabled'      => false,
			'unknown_operation'         => 'inherit',
			'alert_on_deny'             => false,
			'alert_on_shadow'           => false,
			'alert_mode'                => 'immediate',
			'new_plugin_review_enabled' => false,
			'new_plugin_interim'        => 'deny',
			'plugins'                   => array(),
			'operations'                => array(),
		);
		update_option( Plugin::OPTION_KEY, $base );

		$first = Policy_Packs::apply( 'observe_first', Policy::get_policy(), array() );
		$this->assertTrue( $first['ok'] );
		$this->assertSame( 'applied', $first['status'] );

		$policy = Policy::get_policy();
		$this->assertTrue( Policy_Packs::is_active( 'observe_first', $policy, array() ) );
		$this->assertTrue( ! empty( $policy['audit_only'] ) );

		$second = Policy_Packs::apply( 'observe_first', $policy, array() );
		$this->assertTrue( $second['ok'] );
		$this->assertSame( 'noop', $second['status'] );
	}

	public function test_balanced_enables_new_plugin_observe_and_shadow_block(): void {
		$current = array(
			'default'                   => 'allow',
			'audit_only'                => false,
			'log_enabled'               => true,
			'kill_switch'               => false,
			'shadow_block_enabled'      => false,
			'unknown_operation'         => 'inherit',
			'alert_on_deny'             => false,
			'alert_on_shadow'           => false,
			'alert_mode'                => 'immediate',
			'new_plugin_review_enabled' => false,
			'new_plugin_interim'        => 'deny',
			'plugins'                   => array(),
			'operations'                => array(),
		);
		$target = Policy_Packs::build_target( 'balanced', $current, array() );
		$this->assertNotNull( $target );
		$this->assertTrue( ! empty( $target['new_plugin_review_enabled'] ) );
		$this->assertSame( 'observe', $target['new_plugin_interim'] );
		$this->assertTrue( ! empty( $target['shadow_block_enabled'] ) );
	}
}
