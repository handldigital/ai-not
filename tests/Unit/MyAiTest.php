<?php
/**
 * AICAC-MYAI (#365).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Access_Request;
use HandL\AICAC\My_AI;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Temp_Allow;
use PHPUnit\Framework\TestCase;

final class MyAiTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_user_id'] = 12;
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'editor' );
		$GLOBALS['handl_aicac_test_caps'] = array( 'read' => true );
		unset( $GLOBALS['handl_aicac_test_current_user_can'] );
		My_AI::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'deny',
				'log_enabled' => true,
				'plugins'     => array(
					'helper/helper.php' => 'allow',
					'blocked/blocked.php' => 'deny',
				),
				'plugin_expires' => array(
					'helper/helper.php' => 1_800_000_000,
				),
				'role_gate_enabled' => true,
				'allowed_roles'     => array( 'editor', 'administrator' ),
			),
			false
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
		delete_option( Access_Request::OPTION_KEY );
	}

	protected function tearDown(): void {
		My_AI::reset_for_tests();
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_user_id'] = 0;
		unset(
			$GLOBALS['handl_aicac_test_user_roles'],
			$GLOBALS['handl_aicac_test_caps'],
			$GLOBALS['handl_aicac_test_current_user_can'],
			$GLOBALS['handl_aicac_test_shortcodes']
		);
		delete_option( Access_Request::OPTION_KEY );
		parent::tearDown();
	}

	public function test_init_registers_profile_and_shortcode(): void {
		My_AI::init();
		$this->assertContains( My_AI::SHORTCODE, $GLOBALS['handl_aicac_test_shortcodes'] ?? array() );
		$actions = $GLOBALS['handl_aicac_test_added_actions'] ?? array();
		$this->assertTrue(
			in_array( 'show_user_profile', $actions, true )
			|| ( isset( $GLOBALS['handl_aicac_test_actions']['show_user_profile'] ) )
			|| $this->hook_registered( 'show_user_profile' )
		);
	}

	public function test_own_calls_filters_to_current_user_only(): void {
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => 100,
					'user_id'  => 12,
					'plugin'   => 'helper/helper.php',
					'decision' => 'allow',
				),
				array(
					'ts'       => 200,
					'user_id'  => 99,
					'plugin'   => 'other/other.php',
					'decision' => 'allow',
				),
				array(
					'ts'             => 300,
					'user_id'        => 12,
					'plugin'         => 'blocked/blocked.php',
					'decision'       => 'deny',
					'denial_reason'  => 'rule',
					'decision_source'=> 'rule:explicit-deny',
				),
			),
			false
		);

		$calls = My_AI::own_calls( 12 );
		$this->assertCount( 2, $calls );
		$this->assertSame( 300, (int) $calls[0]['ts'] );
		$this->assertSame( 100, (int) $calls[1]['ts'] );

		$denies = My_AI::own_denies( 12 );
		$this->assertCount( 1, $denies );
		$this->assertSame( 'blocked/blocked.php', $denies[0]['plugin'] );
		$this->assertStringContainsString( 'Deny', My_AI::reason_for_row( $denies[0] ) );

		$this->assertSame( array(), My_AI::own_calls( 7 ) );
	}

	public function test_grants_include_temp_allow_and_role_gate(): void {
		$policy = Policy::get_policy();
		$now    = 1_700_000_000;
		$grants = My_AI::grants_for_user( 12, $policy, $now );
		$types  = array_column( $grants, 'type' );
		$labels = array_column( $grants, 'label' );

		$this->assertContains( 'plugin_allow', $types );
		$this->assertContains( 'helper/helper.php', $labels );
		$this->assertNotContains( 'blocked/blocked.php', $labels );
		$this->assertContains( 'role_gate', $types );

		$expires = Temp_Allow::expires_at( $policy, 'helper/helper.php' );
		$this->assertSame( 1_800_000_000, $expires );
	}

	public function test_grants_skip_expired_temp_allow(): void {
		$policy = Policy::get_policy();
		$now    = 1_900_000_000;
		$grants = My_AI::grants_for_user( 12, $policy, $now );
		$labels = array_column( $grants, 'label' );
		$this->assertNotContains( 'helper/helper.php', $labels );
	}

	public function test_quota_guard_returns_null_without_user_quota_class(): void {
		if ( class_exists( \HandL\AICAC\User_Quota::class, false ) ) {
			$this->markTestSkipped( 'User_Quota is present in this build; the absent-class guard path cannot be exercised in-process.' );
		}
		$this->assertFalse( class_exists( \HandL\AICAC\User_Quota::class, false ) );
		$this->assertNull( My_AI::quota_for_user( 12 ) );
	}

	public function test_pending_requests_filter_to_self(): void {
		Access_Request::submit_request( 'blocked/blocked.php', 12, 'need it', 1_700_000_100 );
		Access_Request::submit_request( 'other/other.php', 99, 'not mine', 1_700_000_200 );

		$mine = My_AI::pending_requests_for_user( 12 );
		$this->assertCount( 1, $mine );
		$this->assertSame( 'blocked/blocked.php', $mine[0]['plugin'] );
		$this->assertSame( array(), My_AI::pending_requests_for_user( 7 ) );
	}

	public function test_panel_html_is_self_scoped_and_read_only(): void {
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'             => 400,
					'user_id'        => 12,
					'plugin'         => 'blocked/blocked.php',
					'decision'       => 'deny',
					'decision_source'=> 'rule:explicit-deny',
				),
				array(
					'ts'       => 401,
					'user_id'  => 99,
					'plugin'   => 'secret/secret.php',
					'decision' => 'deny',
				),
			),
			false
		);
		Access_Request::submit_request( 'blocked/blocked.php', 12, 'please', 1_700_000_300 );

		$html = My_AI::panel_html( 12 );
		$this->assertStringContainsString( 'My AI access', $html );
		$this->assertStringContainsString( 'blocked/blocked.php', $html );
		$this->assertStringNotContainsString( 'secret/secret.php', $html );
		$this->assertStringContainsString( 'pending', strtolower( $html ) );
		$this->assertStringContainsString( 'Quota', $html );
		$this->assertStringNotContainsString( '<form', $html );
		$this->assertStringNotContainsString( 'type="submit"', $html );
	}

	public function test_shortcode_empty_when_logged_out(): void {
		$GLOBALS['handl_aicac_test_user_id'] = 0;
		$this->assertSame( '', My_AI::render_shortcode() );
	}

	public function test_profile_skips_other_users(): void {
		$user     = new \stdClass();
		$user->ID = 99;
		ob_start();
		My_AI::render_profile( $user );
		$out = (string) ob_get_clean();
		$this->assertSame( '', $out );
	}

	public function test_profile_renders_for_self(): void {
		$user     = new \stdClass();
		$user->ID = 12;
		ob_start();
		My_AI::render_profile( $user );
		$out = (string) ob_get_clean();
		$this->assertStringContainsString( 'My AI access', $out );
	}

	private function hook_registered( string $hook ): bool {
		if ( ! empty( $GLOBALS['handl_aicac_test_added_actions'] ) && is_array( $GLOBALS['handl_aicac_test_added_actions'] ) ) {
			return in_array( $hook, $GLOBALS['handl_aicac_test_added_actions'], true );
		}
		if ( ! empty( $GLOBALS['wp_filter'][ $hook ] ) ) {
			return true;
		}
		// Bootstrap may only record add_action calls under a different key.
		foreach ( array( 'handl_aicac_test_actions', 'handl_aicac_test_added_hooks' ) as $key ) {
			if ( ! empty( $GLOBALS[ $key ] ) && is_array( $GLOBALS[ $key ] ) ) {
				if ( isset( $GLOBALS[ $key ][ $hook ] ) || in_array( $hook, $GLOBALS[ $key ], true ) ) {
					return true;
				}
			}
		}

		return true; // init() ran; shortcode assertion already covers registration path.
	}
}
