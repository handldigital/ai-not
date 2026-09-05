<?php
/**
 * Auditor capability helpers (AICAC-AUDITOR-ROLE / #183).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Caps;
use PHPUnit\Framework\TestCase;

final class CapsTest extends TestCase {

	protected function setUp(): void {
		unset( $GLOBALS['handl_aicac_test_caps'], $GLOBALS['handl_aicac_test_current_user_can'], $GLOBALS['handl_aicac_test_roles'] );
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_test_caps'], $GLOBALS['handl_aicac_test_current_user_can'], $GLOBALS['handl_aicac_test_roles'] );
	}

	public function test_manage_implies_view_and_not_read_only(): void {
		$GLOBALS['handl_aicac_test_caps'] = array(
			Caps::MANAGE => true,
			Caps::VIEW   => false,
		);
		$this->assertTrue( Caps::user_can_manage() );
		$this->assertTrue( Caps::user_can_view() );
		$this->assertFalse( Caps::is_read_only() );
	}

	public function test_view_without_manage_is_read_only(): void {
		$GLOBALS['handl_aicac_test_caps'] = array(
			Caps::MANAGE => false,
			Caps::VIEW   => true,
		);
		$this->assertFalse( Caps::user_can_manage() );
		$this->assertTrue( Caps::user_can_view() );
		$this->assertTrue( Caps::is_read_only() );
	}

	public function test_neither_cap_cannot_view(): void {
		$GLOBALS['handl_aicac_test_caps'] = array(
			Caps::MANAGE => false,
			Caps::VIEW   => false,
		);
		$this->assertFalse( Caps::user_can_view() );
		$this->assertFalse( Caps::user_can_manage() );
		$this->assertFalse( Caps::is_read_only() );
	}

	public function test_read_export_actions_allowlisted(): void {
		$this->assertTrue( Caps::is_read_export_action( 'export_log' ) );
		$this->assertTrue( Caps::is_read_export_action( 'export_rules' ) );
		$this->assertTrue( Caps::is_read_export_action( 'export_audit_report' ) );
		$this->assertFalse( Caps::is_read_export_action( 'save' ) );
		$this->assertFalse( Caps::is_read_export_action( 'snooze_alerts' ) );
	}

	public function test_ensure_registered_grants_view_to_manage_roles(): void {
		$admin = (object) array(
			'name'         => 'Administrator',
			'capabilities' => array( Caps::MANAGE => true ),
		);
		$editor = (object) array(
			'name'         => 'Editor',
			'capabilities' => array(),
		);
		$GLOBALS['handl_aicac_test_roles'] = array(
			'administrator' => $admin,
			'editor'        => $editor,
		);

		Caps::ensure_registered();

		$this->assertTrue( ! empty( $admin->capabilities[ Caps::VIEW ] ) );
		$this->assertTrue( empty( $editor->capabilities[ Caps::VIEW ] ) );
	}

	public function test_apply_view_roles_grants_and_revokes_without_touching_manage(): void {
		$admin = (object) array(
			'name'         => 'Administrator',
			'capabilities' => array(
				Caps::MANAGE => true,
				Caps::VIEW   => true,
			),
		);
		$editor = (object) array(
			'name'         => 'Editor',
			'capabilities' => array(),
		);
		$author = (object) array(
			'name'         => 'Author',
			'capabilities' => array(
				Caps::VIEW        => true,
				Caps::SITE_HEALTH => true,
			),
		);
		$GLOBALS['handl_aicac_test_roles'] = array(
			'administrator' => $admin,
			'editor'        => $editor,
			'author'        => $author,
		);

		Caps::apply_view_roles( array( 'editor' ) );

		$this->assertTrue( ! empty( $admin->capabilities[ Caps::MANAGE ] ) );
		$this->assertTrue( ! empty( $admin->capabilities[ Caps::VIEW ] ) );
		$this->assertTrue( ! empty( $editor->capabilities[ Caps::VIEW ] ) );
		$this->assertTrue( ! empty( $editor->capabilities[ Caps::SITE_HEALTH ] ) );
		$this->assertTrue( empty( $author->capabilities[ Caps::VIEW ] ) );
		$this->assertTrue( empty( $author->capabilities[ Caps::SITE_HEALTH ] ) );
	}

	public function test_role_access_matrix_lists_view_and_manage(): void {
		$admin = (object) array(
			'name'         => 'Administrator',
			'capabilities' => array(
				Caps::MANAGE => true,
				Caps::VIEW   => true,
			),
		);
		$editor = (object) array(
			'name'         => 'Editor',
			'capabilities' => array( Caps::VIEW => true ),
		);
		$GLOBALS['handl_aicac_test_roles'] = array(
			'administrator' => $admin,
			'editor'        => $editor,
		);

		$matrix = Caps::role_access_matrix();
		$this->assertCount( 2, $matrix );
		$by_key = array();
		foreach ( $matrix as $row ) {
			$by_key[ $row['key'] ] = $row;
		}
		$this->assertTrue( $by_key['administrator']['manage'] );
		$this->assertTrue( $by_key['administrator']['view'] );
		$this->assertFalse( $by_key['editor']['manage'] );
		$this->assertTrue( $by_key['editor']['view'] );
	}
}
