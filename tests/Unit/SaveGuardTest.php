<?php
/**
 * AICAC-SAVE-CONFLICT (#217).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Save_Guard;
use PHPUnit\Framework\TestCase;

final class SaveGuardTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_user_id'] = 7;
		$GLOBALS['handl_aicac_test_users']   = array(
			7 => array(
				'ID'           => 7,
				'user_login'   => 'alice',
				'display_name' => 'Alice Admin',
			),
			9 => array(
				'ID'           => 9,
				'user_login'   => 'bob',
				'display_name' => 'Bob Admin',
			),
		);
		Save_Guard::reset_for_tests();
		Save_Guard::init();
	}

	protected function tearDown(): void {
		Save_Guard::reset_for_tests();
		unset( $GLOBALS['handl_aicac_test_users'], $_POST[ Save_Guard::FIELD ] );
		$GLOBALS['handl_aicac_test_user_id'] = 0;
		$GLOBALS['handl_aicac_test_options'] = array();
		parent::tearDown();
	}

	public function test_matching_token_allows_save(): void {
		$token = Save_Guard::current_token();
		$this->assertNotSame( '', $token );
		$this->assertTrue( Save_Guard::accept_token( $token ) );
		$this->assertNull( Save_Guard::conflict() );
	}

	public function test_stale_token_refuses_and_names_who_saved(): void {
		$stale = Save_Guard::current_token();

		$GLOBALS['handl_aicac_test_user_id'] = 7;
		$before = array(
			'default' => 'allow',
			'plugins' => array(
				'keep/plugin.php' => 'allow',
			),
		);
		$after  = array(
			'default' => 'allow',
			'plugins' => array(
				'keep/plugin.php'  => 'allow',
				'other/plugin.php' => 'deny',
			),
		);
		update_option( Plugin::OPTION_KEY, $before, false );
		Save_Guard::bump_from_write( $before, $after );

		$this->assertFalse( Save_Guard::accept_token( $stale ) );
		$conflict = Save_Guard::conflict();
		$this->assertIsArray( $conflict );
		$this->assertStringContainsString( 'Alice', (string) $conflict['who'] );
		$this->assertNotEmpty( $conflict['changes'] );
		$this->assertGreaterThan( 0, (int) $conflict['to_rev'] );
	}

	public function test_force_bypasses_stale_base(): void {
		$stale = Save_Guard::current_token();
		Save_Guard::bump_from_write(
			array( 'default' => 'allow' ),
			array( 'default' => 'deny' )
		);
		$this->assertFalse( Save_Guard::accept_token( $stale ) );
		$this->assertTrue( Save_Guard::accept_token( $stale, true ) );

		$assert = Save_Guard::assert_base_token( $stale, false );
		$this->assertFalse( $assert['ok'] );
		$this->assertArrayHasKey( 'error', $assert );

		$forced = Save_Guard::assert_base_token( $stale, true );
		$this->assertTrue( $forced['ok'] );
	}

	public function test_two_session_rules_save_keeps_first_writer(): void {
		$policy_a = array(
			'default' => 'allow',
			'plugins' => array(
				'openai-plugin/openai.php' => 'allow',
				'notes/plugin.php'         => 'allow',
			),
		);
		update_option( Plugin::OPTION_KEY, $policy_a, false );
		Save_Guard::ensure_meta();
		$bob_token = Save_Guard::current_token();

		// Session A denies openai while Bob still holds the old token.
		$GLOBALS['handl_aicac_test_user_id'] = 7;
		$policy_after_a                     = $policy_a;
		$policy_after_a['plugins']['openai-plugin/openai.php'] = 'deny';
		Policy::save_policy( $policy_after_a );
		Save_Guard::on_updated_option( Plugin::OPTION_KEY, $policy_a, get_option( Plugin::OPTION_KEY ) );

		$live = get_option( Plugin::OPTION_KEY );
		$this->assertSame( 'deny', $live['plugins']['openai-plugin/openai.php'] ?? null );

		// Session B (stale page) tries to save a note-only change.
		$GLOBALS['handl_aicac_test_user_id'] = 9;
		$_POST[ Save_Guard::FIELD ]         = $bob_token;
		$this->assertFalse( Save_Guard::check_posted_token() );

		$still = get_option( Plugin::OPTION_KEY );
		$this->assertSame( 'deny', $still['plugins']['openai-plugin/openai.php'] ?? null );

		ob_start();
		Save_Guard::maybe_render_conflict_notice();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'not saved', $html );
		$this->assertStringContainsString( 'Alice', $html );
	}

	public function test_noop_policy_write_does_not_require_manual_bump_identity(): void {
		$policy = array(
			'default'     => 'allow',
			'log_enabled' => true,
			'plugins'     => array(
				'a/a.php' => 'allow',
			),
		);
		update_option( Plugin::OPTION_KEY, $policy, false );
		$token_before = Save_Guard::current_token();
		$meta_before  = Save_Guard::get_meta();

		// Real WP skips updated_option when the value is unchanged. Simulate that
		// by not calling bump when before === after for diff-key content.
		Policy::save_policy( $policy );
		$after = get_option( Plugin::OPTION_KEY );
		$this->assertSame( $policy['default'], $after['default'] ?? null );
		$this->assertSame( $token_before, Save_Guard::current_token() );
		$this->assertSame( (int) $meta_before['rev'], (int) Save_Guard::get_meta()['rev'] );
	}

	public function test_admin_wires_token_field_and_early_check(): void {
		$admin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertNotFalse( strpos( $admin, 'Save_Guard::render_token_field()' ) );
		$this->assertNotFalse( strpos( $admin, 'Save_Guard::check_posted_token()' ) );
		$this->assertNotFalse( strpos( $admin, 'Save_Guard::maybe_render_conflict_notice()' ) );

		$handle = strpos( $admin, 'private function handle_save_rules()' );
		$check  = strpos( $admin, 'Save_Guard::check_posted_token()' );
		$save   = strpos( $admin, 'Policy::save_policy( $policy );', $handle );
		$this->assertNotFalse( $handle );
		$this->assertNotFalse( $check );
		$this->assertNotFalse( $save );
		$this->assertLessThan( $save, $check );
	}

	public function test_token_field_markup_is_hidden_opaque(): void {
		ob_start();
		Save_Guard::render_token_field();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'type="hidden"', $html );
		$this->assertStringContainsString( 'name="' . Save_Guard::FIELD . '"', $html );
		$this->assertStringNotContainsString( 'rev=', $html );
		$this->assertDoesNotMatchRegularExpression( '/value="\d+"/', $html );
	}
}
