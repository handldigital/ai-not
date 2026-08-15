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
		$this->assertStringContainsString( 'build_rules_policy_from_post( Policy::get_policy(), true )', $body );
	}

	public function test_rules_form_posts_expected_count_before_nested_sections(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );

		$this->assertTrue(
			(bool) preg_match(
				'/echo \'<form method="post" id="\' \. esc_attr\( \$rules_form_id \) \. \'">\';(?P<body>[\s\S]*?)\$this->render_policy_packs_section\(/',
				$src,
				$m
			)
		);
		$this->assertStringContainsString(
			'name="handl_aicac_rules_expected"',
			$m['body']
		);
		$this->assertStringContainsString(
			'id="handl-aicac-rules-expected"',
			$m['body']
		);
	}
}
