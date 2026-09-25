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

	public function test_review_all_url_filters_pending_review(): void {
		$url = New_Plugin::review_all_url();
		$this->assertStringContainsString( 'page=handl-aicac-rules', $url );
		$this->assertStringContainsString( 'handl_aicac_access=pending-review', $url );
	}

	public function test_sanitize_interim_defaults_to_deny(): void {
		$this->assertSame( 'deny', New_Plugin::sanitize_interim( 'nope' ) );
		$this->assertSame( 'observe', New_Plugin::sanitize_interim( 'observe' ) );
	}

	public function test_newcomer_hold_off_matches_today(): void {
		$policy = array(
			'default'                => 'allow',
			'plugins'                => array(),
			'newcomer_hold_enabled'  => false,
			'newcomer_hold_mode'     => 'watch',
		);
		$eval = Policy::evaluate( $policy, 'gallery/gallery.php', 'generate_text' );
		$this->assertFalse( $eval['prevent'] );
		$event = array( 'plugin' => 'gallery/gallery.php', 'ts' => 1_700_000_000 );
		$hit   = New_Plugin::apply_to_event( $event, $policy, 1_700_000_000, false );
		$this->assertFalse( $hit['active'] );
		$this->assertArrayNotHasKey( 'first_seen_hold', $event );
	}

	public function test_newcomer_hold_watch_flags_first_call_and_allows(): void {
		$policy = array(
			'default'               => 'allow',
			'plugins'               => array(),
			'newcomer_hold_enabled' => true,
			'newcomer_hold_mode'    => 'watch',
			'alert_email'           => 'owner@example.com',
		);
		$eval = Policy::evaluate( $policy, 'gallery/gallery.php', 'generate_text' );
		$this->assertFalse( $eval['prevent'], 'Watch hold must not block' );

		$mails = array();
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) use ( &$mails ) {
			$mails[] = array( $to, $subject, $message );
			return true;
		};

		$event = array( 'plugin' => 'gallery/gallery.php', 'ts' => 1_700_000_000 );
		$hit   = New_Plugin::apply_to_event( $event, $policy, 1_700_000_000, false );
		$this->assertTrue( $hit['active'] );
		$this->assertFalse( $hit['prevent'] );
		$this->assertTrue( $hit['first'] );
		$this->assertTrue( ! empty( $event['first_seen_hold'] ) );
		$this->assertTrue( $hit['emailed'] );
		$this->assertCount( 1, $mails );
		$this->assertStringContainsString( 'made its first AI call', (string) $mails[0][1] );

		$second = New_Plugin::apply_to_event( $event, $hit['policy'], 1_700_000_100, false );
		$this->assertTrue( $second['active'] );
		$this->assertFalse( $second['first'] );
		$this->assertFalse( $second['emailed'], 'Second call inside 24h must not email again' );
		$this->assertCount( 1, $mails );
		unset( $GLOBALS['handl_aicac_wp_mail'] );
	}

	public function test_newcomer_hold_deny_mode_blocks_with_reason(): void {
		$policy = array(
			'default'               => 'allow',
			'plugins'               => array(),
			'newcomer_hold_enabled' => true,
			'newcomer_hold_mode'    => 'deny',
		);
		$eval = Policy::evaluate( $policy, 'gallery/gallery.php', 'generate_text' );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( New_Plugin::REASON, $eval['reason'] );
	}

	public function test_newcomer_hold_allow_deny_clears_and_keep_watching_is_ack_only(): void {
		$policy = array(
			'default'                 => 'allow',
			'plugins'                 => array(),
			'newcomer_hold_enabled'   => true,
			'newcomer_hold_mode'      => 'watch',
			'newcomer_hold_pending'   => array( 'gallery/gallery.php' => 1_700_000_000 ),
			'newcomer_hold_email_at'  => array( 'gallery/gallery.php' => 1_700_000_000 ),
		);

		$watch = New_Plugin::resolve_hold( 'watch', 'gallery/gallery.php', $policy, 1_700_000_500, false );
		$this->assertArrayHasKey( 'gallery/gallery.php', $watch['newcomer_hold_pending'] );
		$this->assertArrayHasKey( 'gallery/gallery.php', $watch['newcomer_hold_watch_ack'] );
		$this->assertArrayNotHasKey( 'gallery/gallery.php', $watch['plugins'] );
		$this->assertSame( array(), New_Plugin::hold_notice_plugins( $watch ) );
		$this->assertTrue( New_Plugin::hold_should_apply( $watch, 'gallery/gallery.php' ) );

		$allow = New_Plugin::resolve_hold( 'allow', 'gallery/gallery.php', $policy, 1_700_000_500, false );
		$this->assertSame( 'allow', $allow['plugins']['gallery/gallery.php'] );
		$this->assertArrayNotHasKey( 'gallery/gallery.php', $allow['newcomer_hold_pending'] );
		$this->assertContains( 'gallery/gallery.php', $allow['newcomer_hold_known'] );
		$this->assertFalse( New_Plugin::hold_should_apply( $allow, 'gallery/gallery.php' ) );

		$deny = New_Plugin::resolve_hold( 'deny', 'gallery/gallery.php', $policy, 1_700_000_500, false );
		$this->assertSame( 'deny', $deny['plugins']['gallery/gallery.php'] );
		$eval = Policy::evaluate( $deny, 'gallery/gallery.php', 'generate_text' );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( 'plugin', $eval['reason'] );
	}

	public function test_newcomer_hold_skips_explicit_allow(): void {
		$policy = array(
			'default'               => 'allow',
			'plugins'               => array( 'gallery/gallery.php' => 'allow' ),
			'newcomer_hold_enabled' => true,
			'newcomer_hold_mode'    => 'deny',
		);
		$eval = Policy::evaluate( $policy, 'gallery/gallery.php', 'generate_text' );
		$this->assertFalse( $eval['prevent'] );
		$this->assertFalse( New_Plugin::hold_should_apply( $policy, 'gallery/gallery.php' ) );
	}

	public function test_newcomer_hold_settings_merge_from_protections_post(): void {
		$_POST[ New_Plugin::POST_HOLD_PRESENT ] = '1';
		$_POST[ New_Plugin::POST_HOLD_ENABLED ] = '1';
		$_POST[ New_Plugin::POST_HOLD_MODE ]    = 'deny';
		$on = New_Plugin::merge_hold_on_policy_save(
			array( 'default' => 'allow' ),
			array( 'newcomer_hold_pending' => array( 'x/y.php' => 9 ) )
		);
		$this->assertTrue( $on['newcomer_hold_enabled'] );
		$this->assertSame( 'deny', $on['newcomer_hold_mode'] );
		$this->assertArrayHasKey( 'x/y.php', $on['newcomer_hold_pending'] );
		unset( $_POST[ New_Plugin::POST_HOLD_PRESENT ], $_POST[ New_Plugin::POST_HOLD_ENABLED ], $_POST[ New_Plugin::POST_HOLD_MODE ] );

		$kept = New_Plugin::merge_hold_on_policy_save(
			array( 'default' => 'deny' ),
			array(
				'newcomer_hold_enabled' => true,
				'newcomer_hold_mode'    => 'watch',
				'newcomer_hold_pending' => array( 'x/y.php' => 1 ),
			)
		);
		$this->assertTrue( $kept['newcomer_hold_enabled'] );
		$this->assertSame( 'watch', $kept['newcomer_hold_mode'] );
		$this->assertArrayHasKey( 'x/y.php', $kept['newcomer_hold_pending'] );
	}

	public function test_newcomer_hold_settings_copy_is_plain(): void {
		ob_start();
		New_Plugin::instance()->render_hold_settings( array() );
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'First AI call hold', $html );
		$this->assertStringContainsString( 'Hold a plugin', $html );
		$this->assertStringContainsString( 'Watch (allow this call and ask)', $html );
		$this->assertStringContainsString( 'Block (deny this call and ask)', $html );
		$this->assertStringContainsString( 'Off by default', $html );
		$this->assertStringContainsString( 'name="' . New_Plugin::POST_HOLD_PRESENT . '"', $html );
	}

	public function test_newcomer_hold_notice_lists_unacked_only(): void {
		$policy = array(
			'newcomer_hold_enabled'   => true,
			'newcomer_hold_pending'   => array(
				'a/a.php' => 1,
				'b/b.php' => 2,
			),
			'newcomer_hold_watch_ack' => array( 'b/b.php' => 3 ),
		);
		$this->assertSame( array( 'a/a.php' ), New_Plugin::hold_notice_plugins( $policy ) );
	}
}
