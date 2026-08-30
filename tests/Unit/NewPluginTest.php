<?php
/**
 * Unit tests for review-first new plugins (AICAC-NEWPLUGIN / #141).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\New_Plugin;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class NewPluginTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options'] = array();
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options'] = array();
		parent::tearDown();
	}

	public function test_setting_off_zero_behavior_on_first_seen(): void {
		$policy = array(
			'default'                    => 'allow',
			'plugins'                    => array(),
			'new_plugin_review_enabled'  => false,
			'new_plugin_interim'         => 'deny',
			'new_plugin_known'           => array(),
			'new_plugin_pending'         => array(),
		);

		$result = New_Plugin::mark_first_seen( $policy, 'brand-new/plugin.php', 1_700_000_000 );
		$this->assertFalse( $result['changed'] );
		$this->assertFalse( $result['pending'] );
		$this->assertSame( array(), $result['policy']['new_plugin_pending'] );

		$eval = Policy::evaluate( $result['policy'], 'brand-new/plugin.php', 'generate_text' );
		$this->assertFalse( $eval['prevent'], 'Off: new plugin follows site default allow' );
	}

	public function test_grandfather_on_enable_does_not_restrict_existing(): void {
		$previous = array(
			'new_plugin_review_enabled' => false,
			'new_plugin_known'          => array(),
			'new_plugin_pending'        => array(),
		);
		$policy = array(
			'new_plugin_review_enabled' => true,
			'new_plugin_interim'        => 'deny',
			'new_plugin_known'          => array(),
			'new_plugin_pending'        => array(),
		);

		$out = New_Plugin::apply_settings_transition(
			$policy,
			$previous,
			array( 'akismet/akismet.php', 'hello.php' )
		);

		$this->assertTrue( New_Plugin::is_enabled( $out ) );
		$this->assertContains( 'akismet/akismet.php', $out['new_plugin_known'] );
		$this->assertContains( 'hello.php', $out['new_plugin_known'] );
		$this->assertSame( array(), $out['new_plugin_pending'] );

		// First-seen of grandfathered plugin is a no-op.
		$seen = New_Plugin::mark_first_seen( $out, 'akismet/akismet.php', 1_700_000_000 );
		$this->assertFalse( $seen['changed'] );
		$this->assertFalse( $seen['pending'] );
	}

	public function test_fresh_activation_deny_interim_enforces_and_pends(): void {
		$policy = array(
			'default'                   => 'allow',
			'plugins'                   => array(),
			'new_plugin_review_enabled' => true,
			'new_plugin_interim'        => 'deny',
			'new_plugin_known'          => array( 'already/on.php' ),
			'new_plugin_pending'        => array(),
		);

		$result = New_Plugin::mark_first_seen( $policy, 'fresh/plugin.php', 1_700_000_100 );
		$this->assertTrue( $result['changed'] );
		$this->assertTrue( $result['pending'] );
		$this->assertArrayHasKey( 'fresh/plugin.php', $result['policy']['new_plugin_pending'] );
		$this->assertSame( 'deny', $result['policy']['plugins']['fresh/plugin.php'] );

		$eval = Policy::evaluate( $result['policy'], 'fresh/plugin.php', 'generate_text' );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( 'plugin', $eval['reason'] );

		// Second activation is idempotent.
		$again = New_Plugin::mark_first_seen( $result['policy'], 'fresh/plugin.php', 1_700_000_200 );
		$this->assertFalse( $again['changed'] );
		$this->assertTrue( $again['pending'] );
	}

	public function test_observe_interim_allows_calls_but_stays_pending(): void {
		$policy = array(
			'default'                   => 'allow',
			'plugins'                   => array(),
			'new_plugin_review_enabled' => true,
			'new_plugin_interim'        => 'observe',
			'new_plugin_known'          => array(),
			'new_plugin_pending'        => array(),
		);

		$result = New_Plugin::mark_first_seen( $policy, 'watch/me.php', 1_700_000_000 );
		$this->assertTrue( $result['changed'] );
		$this->assertTrue( New_Plugin::is_pending( $result['policy'], 'watch/me.php' ) );
		$this->assertArrayNotHasKey( 'watch/me.php', $result['policy']['plugins'] ?? array() );

		$eval = Policy::evaluate( $result['policy'], 'watch/me.php', 'generate_text' );
		$this->assertFalse( $eval['prevent'], 'Observe interim must not block' );
	}

	public function test_allow_or_deny_clears_pending_no_duplicate_state(): void {
		$policy = array(
			'default'                   => 'allow',
			'plugins'                   => array( 'fresh/plugin.php' => 'deny' ),
			'new_plugin_review_enabled' => true,
			'new_plugin_interim'        => 'deny',
			'new_plugin_known'          => array(),
			'new_plugin_pending'        => array( 'fresh/plugin.php' => 1_700_000_000 ),
		);

		$cleared = New_Plugin::clear_review( $policy, 'fresh/plugin.php' );
		$this->assertArrayNotHasKey( 'fresh/plugin.php', $cleared['new_plugin_pending'] );
		$this->assertContains( 'fresh/plugin.php', $cleared['new_plugin_known'] );
		$this->assertFalse( New_Plugin::is_pending( $cleared, 'fresh/plugin.php' ) );

		// clear_reviewed_from_plugins_map after admin sets Allow.
		$policy['plugins']['fresh/plugin.php'] = 'allow';
		$from_map = New_Plugin::clear_reviewed_from_plugins_map( $policy );
		$this->assertArrayNotHasKey( 'fresh/plugin.php', $from_map['new_plugin_pending'] );
		$this->assertContains( 'fresh/plugin.php', $from_map['new_plugin_known'] );

		// set_plugin_rule path (persists).
		$GLOBALS['handl_aicac_test_options'][ Plugin::OPTION_KEY ] = $policy;
		$this->assertTrue( Policy::set_plugin_rule( 'fresh/plugin.php', 'allow' ) );
		$stored = Policy::get_policy();
		$this->assertArrayNotHasKey( 'fresh/plugin.php', $stored['new_plugin_pending'] );
		$this->assertContains( 'fresh/plugin.php', $stored['new_plugin_known'] );
	}

	public function test_pending_list_empty_when_feature_off(): void {
		$policy = array(
			'new_plugin_review_enabled' => false,
			'new_plugin_pending'        => array( 'x/y.php' => 1 ),
		);
		$this->assertSame( array(), New_Plugin::pending_plugins( $policy ) );
	}

	public function test_review_rules_url_reuses_graduate_focus(): void {
		$url = New_Plugin::review_rules_url( 'akismet/akismet.php' );
		$this->assertStringContainsString( 'page=handl-aicac-rules', $url );
		$this->assertStringContainsString( 'handl_aicac_focus_plugin=', $url );
		$this->assertStringContainsString( 'handl_aicac_graduate=1', $url );
		$this->assertStringContainsString( '#handl-aicac-rule-', $url );
	}

	public function test_sanitize_interim_defaults_to_deny(): void {
		$this->assertSame( 'deny', New_Plugin::sanitize_interim( 'nope' ) );
		$this->assertSame( 'observe', New_Plugin::sanitize_interim( 'observe' ) );
	}
}
