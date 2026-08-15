<?php
/**
 * Unit tests for optional role gate (AICAC-ROLE / #79).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class RoleGateTest extends TestCase {

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_user_id'],
			$GLOBALS['handl_aicac_test_user_roles'],
			$GLOBALS['handl_aicac_test_available_roles']
		);
		parent::tearDown();
	}

	public function test_role_gate_off_allows_any_role(): void {
		$GLOBALS['handl_aicac_test_user_id']    = 7;
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'subscriber' );

		$policy = array(
			'default'           => 'allow',
			'plugins'           => array(),
			'role_gate_enabled' => false,
			'allowed_roles'     => array( 'administrator' ),
		);

		$result = Policy::evaluate( $policy, 'any/plugin.php', 'generate_text' );
		$this->assertFalse( $result['prevent'] );
	}

	public function test_role_gate_denies_disallowed_role(): void {
		$GLOBALS['handl_aicac_test_user_id']    = 7;
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'author' );

		$policy = array(
			'default'           => 'allow',
			'plugins'           => array(),
			'role_gate_enabled' => true,
			'allowed_roles'     => array( 'administrator', 'editor' ),
		);

		$result = Policy::evaluate( $policy, 'any/plugin.php', 'generate_text' );
		$this->assertTrue( $result['prevent'] );
		$this->assertSame( 'role', $result['reason'] );
	}

	public function test_role_gate_allows_listed_role(): void {
		$GLOBALS['handl_aicac_test_user_id']    = 3;
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'editor' );

		$policy = array(
			'default'           => 'allow',
			'plugins'           => array(),
			'role_gate_enabled' => true,
			'allowed_roles'     => array( 'administrator', 'editor' ),
		);

		$result = Policy::evaluate( $policy, 'any/plugin.php', 'generate_text' );
		$this->assertFalse( $result['prevent'] );
	}

	public function test_role_gate_bypasses_no_user_context(): void {
		$GLOBALS['handl_aicac_test_user_id']    = 0;
		$GLOBALS['handl_aicac_test_user_roles'] = array();

		$policy = array(
			'default'           => 'allow',
			'plugins'           => array(),
			'role_gate_enabled' => true,
			'allowed_roles'     => array( 'administrator' ),
		);

		$result = Policy::evaluate( $policy, 'any/plugin.php', 'generate_text' );
		$this->assertFalse( $result['prevent'], 'cron/CLI must bypass role gate in v1' );
	}

	public function test_role_gate_empty_allowed_denies_signed_in_user(): void {
		$GLOBALS['handl_aicac_test_user_id']    = 9;
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'administrator' );

		$policy = array(
			'default'           => 'allow',
			'plugins'           => array(),
			'role_gate_enabled' => true,
			'allowed_roles'     => array(),
		);

		$result = Policy::evaluate( $policy, 'any/plugin.php', 'generate_text' );
		$this->assertTrue( $result['prevent'] );
		$this->assertSame( 'role', $result['reason'] );
	}

	public function test_role_gate_multi_role_user_passes_if_any_allowed(): void {
		$GLOBALS['handl_aicac_test_user_id']    = 4;
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'author', 'editor' );

		$policy = array(
			'default'           => 'allow',
			'plugins'           => array(),
			'role_gate_enabled' => true,
			'allowed_roles'     => array( 'editor' ),
		);

		$result = Policy::evaluate( $policy, 'any/plugin.php', 'generate_text' );
		$this->assertFalse( $result['prevent'] );
	}

	public function test_sanitize_allowed_roles_filters_junk(): void {
		$out = Policy::sanitize_allowed_roles( array( 'Editor', '  ', 'author', 'author', 12 ) );
		$this->assertSame( array( 'editor', 'author', '12' ), $out );
	}

	public function test_current_user_role_for_log_empty_without_user(): void {
		$GLOBALS['handl_aicac_test_user_id']    = 0;
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'editor' );
		$this->assertSame( '', Policy::current_user_role_for_log() );
	}

	public function test_current_user_role_for_log_joins_roles(): void {
		$GLOBALS['handl_aicac_test_user_id']    = 2;
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'editor', 'author' );
		$this->assertSame( 'editor,author', Policy::current_user_role_for_log() );
	}

	public function test_kill_switch_still_outranks_role_allow(): void {
		$GLOBALS['handl_aicac_test_user_id']    = 1;
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'administrator' );

		$policy = array(
			'default'           => 'allow',
			'plugins'           => array(),
			'kill_switch'       => true,
			'role_gate_enabled' => true,
			'allowed_roles'     => array( 'administrator' ),
		);

		$result = Policy::evaluate( $policy, 'any/plugin.php', 'generate_text' );
		$this->assertTrue( $result['prevent'] );
		$this->assertSame( 'kill_switch', $result['reason'] );
	}


	public function test_checked_roles_gate_on_empty_shows_none(): void {
		$available = array( 'administrator' => 'Administrator', 'editor' => 'Editor' );
		$this->assertSame( array(), Policy::role_gate_checked_roles( true, array(), $available ) );
	}

	public function test_checked_roles_gate_on_mirrors_stored(): void {
		$available = array( 'administrator' => 'Administrator', 'editor' => 'Editor', 'author' => 'Author' );
		$this->assertSame( array( 'administrator' ), Policy::role_gate_checked_roles( true, array( 'administrator' ), $available ) );
	}

	public function test_checked_roles_gate_off_empty_defaults_all(): void {
		$available = array( 'administrator' => 'Administrator', 'editor' => 'Editor' );
		$this->assertSame( array( 'administrator', 'editor' ), Policy::role_gate_checked_roles( false, array(), $available ) );
	}

	public function test_all_checked_canonicalizes_to_empty_when_gate_off(): void {
		$available = array( 'administrator' => 'Administrator', 'editor' => 'Editor', 'author' => 'Author' );
		$posted    = array( 'author', 'administrator', 'editor' );
		$this->assertSame(
			array(),
			Policy::canonicalize_unrestricted_roles( $posted, $available, false )
		);
	}

	public function test_all_checked_stays_listed_when_gate_on(): void {
		$available = array( 'administrator' => 'Administrator', 'editor' => 'Editor' );
		$posted    = array( 'administrator', 'editor' );
		$this->assertSame(
			array( 'administrator', 'editor' ),
			Policy::canonicalize_unrestricted_roles( $posted, $available, true )
		);
	}

	public function test_subset_is_not_canonicalized(): void {
		$available = array( 'administrator' => 'Administrator', 'editor' => 'Editor', 'author' => 'Author' );
		$this->assertSame(
			array( 'administrator', 'editor' ),
			Policy::canonicalize_unrestricted_roles( array( 'administrator', 'editor' ), $available, false )
		);
	}

	public function test_posted_roles_match_rendered_ignores_order(): void {
		$this->assertTrue(
			Policy::posted_roles_match_rendered(
				array( 'editor', 'administrator' ),
				array( 'administrator', 'editor' )
			)
		);
		$this->assertFalse(
			Policy::posted_roles_match_rendered(
				array( 'administrator' ),
				array( 'administrator', 'editor' )
			)
		);
	}

}
