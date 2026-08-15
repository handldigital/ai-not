<?php
/**
 * AICAC-P0-TRUNCATE (#214): a truncated Rules POST must not erase stored rules.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class RulesSaveTruncationTest extends TestCase {

	/**
	 * The pre-#214 rebuild (empty base + posted rows only) drops any plugin
	 * whose field PHP never received. That is the data-loss bug.
	 */
	public function test_rebuild_from_truncated_post_erases_late_deny(): void {
		$stored = array(
			'early/plugin.php' => 'allow',
			'late/plugin.php'  => 'deny',
		);
		$posted = array(
			'early/plugin.php' => 'deny',
		);

		$rebuilt = Policy::merge_posted_plugin_rules( array(), $posted );

		$this->assertSame( 'deny', $rebuilt['early/plugin.php'] );
		$this->assertArrayNotHasKey( 'late/plugin.php', $rebuilt );
	}

	/**
	 * Manual save must merge onto the stored map so an absent row keeps its value.
	 */
	public function test_merge_keeps_unposted_deny_and_applies_posted_change(): void {
		$stored = array(
			'early/plugin.php' => 'allow',
			'late/plugin.php'  => 'deny',
		);
		$posted = array(
			'early/plugin.php' => 'deny',
		);

		$merged = Policy::merge_posted_plugin_rules( $stored, $posted );

		$this->assertSame( 'deny', $merged['early/plugin.php'] );
		$this->assertSame( 'deny', $merged['late/plugin.php'] );
	}

	public function test_merge_empty_posted_value_clears_explicit_rule(): void {
		$stored = array(
			'alpha/alpha.php' => 'deny',
		);
		$merged = Policy::merge_posted_plugin_rules(
			$stored,
			array( 'alpha/alpha.php' => '' )
		);
		$this->assertArrayNotHasKey( 'alpha/alpha.php', $merged );
	}

	public function test_expected_count_rejects_truncated_payload(): void {
		$posted = array(
			'a/a.php' => 'allow',
			'b/b.php' => 'deny',
		);
		$this->assertTrue( Policy::posted_rules_match_expected( $posted, 2 ) );
		$this->assertTrue( Policy::posted_rules_match_expected( $posted, '2' ) );
		$this->assertFalse( Policy::posted_rules_match_expected( $posted, 177 ) );
		$this->assertFalse( Policy::posted_rules_match_expected( $posted, false ) );
		$this->assertFalse( Policy::posted_rules_match_expected( $posted, null ) );
		$this->assertFalse( Policy::posted_rules_match_expected( null, 13 ) );
		$this->assertTrue( Policy::posted_rules_match_expected( null, 0 ) );
		$this->assertTrue( Policy::posted_rules_match_expected( array(), 0 ) );
	}

	public function test_merge_model_force_keeps_unposted_route(): void {
		$stored = array(
			'early/plugin.php' => array( 'provider' => 'openai', 'model' => 'gpt-4o' ),
			'late/plugin.php'  => array( 'provider' => 'anthropic', 'model' => 'claude-3' ),
		);
		$posted = array(
			'early/plugin.php' => array( 'provider' => 'openai', 'model' => 'gpt-4o-mini' ),
		);

		$merged = Policy::merge_posted_model_force( $stored, $posted );

		$this->assertSame( 'gpt-4o-mini', $merged['early/plugin.php']['model'] );
		$this->assertSame( 'claude-3', $merged['late/plugin.php']['model'] );
	}

	/**
	 * handle_save_rules must refuse a mismatched count before Policy::save_policy.
	 */
	public function test_handle_save_rules_aborts_before_write_on_mismatch(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );

		$this->assertTrue(
			(bool) preg_match(
				'/function handle_save_rules\(\): bool \{(?P<body>[\s\S]*?)\n\t\}/',
				$src,
				$m
			)
		);
		$body = $m['body'];
		$match_pos = strpos( $body, 'posted_rules_match_expected' );
		$save_pos  = strpos( $body, 'Policy::save_policy' );
		$this->assertNotFalse( $match_pos, 'handle_save_rules must call posted_rules_match_expected' );
		$this->assertNotFalse( $save_pos, 'handle_save_rules must still save on a complete POST' );
		$this->assertLessThan( $save_pos, $match_pos );
		$this->assertStringContainsString( 'return false', $body );
		$this->assertStringContainsString( 'get_option( Plugin::OPTION_KEY )', $body );
		$this->assertStringContainsString( 'build_rules_policy_from_post( $stored, true )', $body );
		$this->assertStringNotContainsString(
			'build_rules_policy_from_post( Policy::get_policy()',
			$body,
			'Save must start from the raw option so get_policy() defaults are not persisted'
		);
	}

	public function test_rules_form_posts_expected_count_inside_rules_form_before_matrix(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );

		$open     = strpos( $src, 'echo \'<form method="post" id="\' . esc_attr( $rules_form_id ) . \'">\';' );
		$expected = strpos( $src, 'name="handl_aicac_rules_expected"' );
		$matrix   = strpos( $src, 'handl-aicac-rules-matrix' );
		$this->assertNotFalse( $open, 'Rules form open must exist' );
		$this->assertNotFalse( $expected, 'Expected-row sentinel must exist' );
		$this->assertNotFalse( $matrix, 'Rules matrix must exist' );
		$this->assertGreaterThan( $open, $expected, 'Expected-row sentinel must be inside the Rules form' );
		$this->assertLessThan( $matrix, $expected, 'Expected-row sentinel must arrive before the matrix' );
		$this->assertStringContainsString( 'id="handl-aicac-rules-expected"', $src );
	}

	/**
	 * Filtered / truncated POST: only posted plugin rows change. Role, kill,
	 * shadow, new-plugin, budgets, and hidden model routes stay put.
	 */
	public function test_filtered_subset_changes_only_posted_plugin_and_route_rows(): void {
		$stored = array(
			'plugins'                  => array(
				'visible/a.php' => 'allow',
				'hidden/b.php'  => 'deny',
			),
			'role_gate_enabled'        => true,
			'allowed_roles'            => array( 'administrator' ),
			'kill_switch'              => true,
			'kill_switch_exceptions'   => array( 'hidden/b.php' ),
			'shadow_block_enabled'     => true,
			'shadow_block_exceptions'  => array( 'hidden/b.php' ),
			'model_force_plugins'      => array(
				'visible/a.php' => array( 'provider' => 'openai', 'model' => 'gpt-4o' ),
				'hidden/b.php'  => array( 'provider' => 'anthropic', 'model' => 'claude-3' ),
			),
			'plugin_budgets'           => array( 'hidden/b.php' => 10.0 ),
			'new_plugin_review_enabled'=> true,
		);

		$after                          = $stored;
		$after['plugins']               = Policy::merge_posted_plugin_rules(
			$stored['plugins'],
			array( 'visible/a.php' => 'deny' )
		);
		$after['model_force_plugins']   = Policy::merge_posted_model_force(
			$stored['model_force_plugins'],
			array( 'visible/a.php' => array( 'provider' => 'openai', 'model' => 'gpt-4o-mini' ) )
		);

		$this->assertSame( 'deny', $after['plugins']['visible/a.php'] );
		$untouched = $stored;
		unset( $untouched['plugins'], $untouched['model_force_plugins'] );
		$after_rest = $after;
		unset( $after_rest['plugins'], $after_rest['model_force_plugins'] );
		$this->assertSame( $untouched, $after_rest );
		$this->assertSame( 'deny', $after['plugins']['hidden/b.php'] );
		$this->assertSame( 'claude-3', $after['model_force_plugins']['hidden/b.php']['model'] );
	}

	/**
	 * Settings checkbox writers must not fire on a merge save unless the
	 * panel sentinel was posted. Unchecked boxes cannot be told from absent
	 * without that field.
	 */
	public function test_settings_writers_require_panel_sentinel_when_merging(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );

		$this->assertStringContainsString(
			'name="handl_aicac_settings_present"',
			$src
		);
		$this->assertStringContainsString(
			'apply_kill_switch_settings_from_post( $policy, $merge_missing )',
			$src
		);
		$this->assertStringContainsString(
			'apply_shadow_block_settings_from_post( $policy, $merge_missing )',
			$src
		);
		$this->assertStringContainsString(
			'apply_role_gate_settings_from_post( $policy, $merge_missing )',
			$src
		);
		$this->assertStringContainsString(
			'apply_new_plugin_settings_from_post( $policy, $merge_missing )',
			$src
		);
		$this->assertStringContainsString(
			'apply_model_force_settings_from_post( $policy, $merge_missing )',
			$src
		);
		$this->assertStringContainsString(
			'apply_plugin_budget_settings_from_post( $policy, $base )',
			$src
		);

		foreach ( array(
			'apply_kill_switch_settings_from_post',
			'apply_shadow_block_settings_from_post',
			'apply_role_gate_settings_from_post',
			'apply_new_plugin_settings_from_post',
		) as $fn ) {
			$this->assertTrue(
				(bool) preg_match(
					'/function ' . preg_quote( $fn, '/' ) . '\( array &\$policy, bool \$merge_missing = false \): void \{(?P<body>[\s\S]*?)\n\t\}/',
					$src,
					$m
				),
				$fn . ' must take $merge_missing'
			);
			$this->assertStringContainsString(
				'if ( $merge_missing && ! $this->rules_settings_panel_posted() )',
				$m['body'],
				$fn . ' must keep stored keys when Settings was not submitted'
			);
			$this->assertStringContainsString( 'return;', $m['body'] );
		}
	}
}
