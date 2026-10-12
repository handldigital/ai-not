<?php
/**
 * AICAC-OFFBOARD (#351).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Access_Request;
use HandL\AICAC\Alert_Snooze;
use HandL\AICAC\Offboard;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Temp_Allow;
use PHPUnit\Framework\TestCase;

final class OffboardTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		$GLOBALS['handl_aicac_test_options']     = array();
		$GLOBALS['handl_aicac_test_user_id']     = 12;
		$GLOBALS['handl_aicac_test_user_login']  = 'alice';
		$GLOBALS['handl_aicac_test_users']       = array(
			12 => array(
				'ID'         => 12,
				'user_login' => 'alice',
				'roles'      => array( 'editor' ),
			),
			1  => array(
				'ID'         => 1,
				'user_login' => 'admin',
				'roles'      => array( 'administrator' ),
			),
		);
		$GLOBALS['handl_aicac_test_user_meta']         = array();
		$GLOBALS['handl_aicac_test_current_user_can']   = true;
		$GLOBALS['handl_aicac_wp_mail']                = static function ( $to, $subject, $message ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);
			return true;
		};

		Offboard::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'            => 'deny',
				'log_enabled'        => true,
				'audit_only'         => false,
				'alert_on_deny'      => true,
				'alert_mode'         => 'immediate',
				'alert_email'        => 'ops@example.test',
				'role_gate_enabled'  => true,
				'allowed_roles'      => array( 'administrator', 'editor' ),
				'plugins'            => array(
					'blocked/plugin.php' => 'deny',
					'other/other.php'    => 'deny',
				),
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
		delete_option( Access_Request::OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		delete_option( Offboard::NOTICE_OPTION );
		delete_option( Temp_Allow::WARNED_OPTION_KEY );
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_wp_mail'],
			$GLOBALS['handl_aicac_test_current_user_can'],
			$GLOBALS['handl_aicac_test_user_login'],
			$GLOBALS['handl_aicac_test_users'],
			$GLOBALS['handl_aicac_test_user_meta'],
			$GLOBALS['handl_aicac_test_missing_users']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_user_id'] = 0;
		Offboard::reset_for_tests();
		self::$mails = array();
		parent::tearDown();
	}

	public function test_quiet_when_user_has_nothing(): void {
		$result = Offboard::revoke_user( 12, 'deleted', 'alice', 1_700_000_000 );
		$this->assertFalse( $result['revoked'] );
		$this->assertSame( '', $result['summary'] );
		$this->assertFalse( (bool) get_option( Offboard::NOTICE_OPTION, false ) );
		$this->assertSame( array(), get_option( Plugin::LOG_OPTION_KEY, array() ) );
	}

	public function test_closes_pending_requests_and_writes_one_audit(): void {
		$now    = 1_700_000_000;
		$first  = Access_Request::submit_request( 'blocked/plugin.php', 12, 'Need copy', $now );
		$second = Access_Request::submit_request( 'other/other.php', 12, '', $now + 1 );
		$this->assertTrue( $first['ok'] );
		$this->assertTrue( $second['ok'] );
		$this->assertCount( 2, Access_Request::pending_rows() );

		update_user_meta(
			12,
			Access_Request::NOTICE_META,
			array(
				'plugin' => 'blocked/plugin.php',
				'ts'     => $now,
			)
		);

		$result = Offboard::revoke_user( 12, 'deleted', 'alice', $now + 60 );
		$this->assertTrue( $result['revoked'] );
		$this->assertSame( array(), Access_Request::pending_rows() );
		$this->assertSame( '', get_user_meta( 12, Access_Request::NOTICE_META, true ) );
		$this->assertStringContainsString( 'alice left with:', $result['summary'] );
		$this->assertStringContainsString( '2 pending request', $result['summary'] );
		$this->assertTrue( $result['notice_cleared'] );

		$notice = get_option( Offboard::NOTICE_OPTION, null );
		$this->assertIsArray( $notice );
		$this->assertSame( $result['summary'], $notice['summary'] );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$off = array_values(
			array_filter(
				$log,
				static function ( $row ) {
					return is_array( $row ) && ( $row['decision'] ?? '' ) === 'offboard';
				}
			)
		);
		$this->assertCount( 1, $off );
		$this->assertSame( 'deleted', $off[0]['offboard_reason'] );
		$this->assertSame( 12, (int) $off[0]['user_id'] );
	}

	public function test_revokes_temp_allow_from_approved_request(): void {
		$now    = 1_700_000_000;
		$submit = Access_Request::submit_request( 'blocked/plugin.php', 12, '', $now );
		$ok     = Access_Request::approve( $submit['id'], 1, $now + 10 );
		$this->assertTrue( $ok['ok'] );

		$policy = Policy::get_policy();
		$this->assertSame( 'allow', $policy['plugins']['blocked/plugin.php'] ?? '' );
		$this->assertNotNull( Temp_Allow::expires_at( $policy, 'blocked/plugin.php' ) );

		$result = Offboard::revoke_user( 12, 'deleted', 'alice', $now + 20 );
		$this->assertTrue( $result['revoked'] );
		$this->assertContains( 'blocked/plugin.php', $result['temp_allows'] );
		$this->assertStringContainsString( 'temp-allow', $result['summary'] );

		$policy = Policy::get_policy();
		$this->assertArrayNotHasKey( 'blocked/plugin.php', $policy['plugins'] ?? array() );
		$this->assertNull( Temp_Allow::expires_at( $policy, 'blocked/plugin.php' ) );
	}

	public function test_demotion_only_when_role_gate_loses_access(): void {
		// After demotion, userdata already reflects the new (non-allowed) role.
		$GLOBALS['handl_aicac_test_users'][12]['roles'] = array( 'subscriber' );
		$this->assertTrue(
			Offboard::is_demotion_losing_ai( 12, 'subscriber', array( 'editor' ) )
		);

		// Still has an allowed role after change.
		$GLOBALS['handl_aicac_test_users'][12]['roles'] = array( 'editor', 'subscriber' );
		$this->assertFalse(
			Offboard::is_demotion_losing_ai( 12, 'subscriber', array( 'editor' ) )
		);

		// Gate off → never demotion-offboard.
		$policy                      = Policy::get_policy();
		$policy['role_gate_enabled'] = false;
		Policy::save_policy( $policy );
		$GLOBALS['handl_aicac_test_users'][12]['roles'] = array( 'subscriber' );
		$this->assertFalse(
			Offboard::is_demotion_losing_ai( 12, 'subscriber', array( 'editor' ) )
		);
	}

	public function test_orphan_sweep_closes_requests_for_missing_users(): void {
		$now = 1_700_000_000;
		Access_Request::submit_request( 'blocked/plugin.php', 12, '', $now );
		$this->assertCount( 1, Access_Request::pending_rows() );

		// Simulate user deleted while plugin was inactive — row remains, user gone.
		unset( $GLOBALS['handl_aicac_test_users'][12] );

		$sweep = Offboard::sweep_orphans( $now + 100 );
		$this->assertSame( 1, $sweep['closed'] );
		$this->assertSame( array(), Access_Request::pending_rows() );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$off = array_values(
			array_filter(
				$log,
				static function ( $row ) {
					return is_array( $row ) && ( $row['decision'] ?? '' ) === 'offboard';
				}
			)
		);
		$this->assertNotEmpty( $off );
		$this->assertSame( 'orphan', $off[0]['offboard_reason'] );
	}

	public function test_alert_snooze_not_cancelled_on_offboard(): void {
		$now = 1_700_000_000;
		Alert_Snooze::set( 'noisy/plugin.php', '7d', $now );
		$this->assertTrue( Alert_Snooze::is_snoozed( 'noisy/plugin.php', $now + 10 ) );

		Access_Request::submit_request( 'blocked/plugin.php', 12, '', $now );
		Offboard::revoke_user( 12, 'deleted', 'alice', $now + 20 );

		$this->assertTrue( Alert_Snooze::is_snoozed( 'noisy/plugin.php', $now + 30 ) );
	}

	public function test_build_summary_format(): void {
		$summary = Offboard::build_summary(
			'alice',
			array( 'a/a.php', 'b/b.php' ),
			array( 'c/c.php until Fri' ),
			true
		);
		$this->assertSame(
			'alice left with: 2 pending requests (a/a.php, b/b.php); 1 temp-allow (c/c.php until Fri); request notice',
			$summary
		);
	}
}
