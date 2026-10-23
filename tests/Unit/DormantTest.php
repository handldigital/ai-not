<?php
/**
 * AICAC-DORMANT (#353).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Access_Request;
use HandL\AICAC\Dormant;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class DormantTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']    = array();
		$GLOBALS['handl_aicac_test_user_id']    = 12;
		$GLOBALS['handl_aicac_test_user_meta']  = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_users']      = array(
			12 => array(
				'ID'              => 12,
				'user_login'      => 'alice',
				'roles'           => array( 'editor' ),
				'user_registered' => '2025-01-01 00:00:00',
			),
			13 => array(
				'ID'              => 13,
				'user_login'      => 'bob',
				'roles'           => array( 'editor' ),
				'user_registered' => '2025-01-01 00:00:00',
			),
			1  => array(
				'ID'         => 1,
				'user_login' => 'admin',
				'roles'      => array( 'administrator' ),
			),
		);

		Dormant::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'           => 'allow',
				'log_enabled'       => true,
				'audit_only'        => false,
				'role_gate_enabled' => true,
				'allowed_roles'     => array( 'administrator', 'editor' ),
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
		delete_option( Access_Request::OPTION_KEY );
		Dormant::save_days( 90 );
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_current_user_can'],
			$GLOBALS['handl_aicac_test_users'],
			$GLOBALS['handl_aicac_test_user_meta'],
			$GLOBALS['handl_aicac_test_filters']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_user_id'] = 0;
		Dormant::reset_for_tests();
		parent::tearDown();
	}

	public function test_window_zero_disables_sweep(): void {
		Dormant::save_days( 0 );
		$now = 1_700_000_000;
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => $now - ( 200 * DAY_IN_SECONDS ),
					'user_id'  => 12,
					'decision' => 'allow',
					'plugin'   => 'a/a.php',
				),
			),
			false
		);

		$result = Dormant::sweep( $now );
		$this->assertSame( array(), $result['suspended'] );
		$this->assertFalse( Dormant::is_suspended( 12 ) );
	}

	public function test_sweep_suspends_idle_user_with_one_audit(): void {
		$now = 1_700_000_000;
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => $now - ( 100 * DAY_IN_SECONDS ),
					'user_id'  => 12,
					'decision' => 'allow',
					'plugin'   => 'a/a.php',
				),
				array(
					'ts'       => $now - DAY_IN_SECONDS,
					'user_id'  => 13,
					'decision' => 'allow',
					'plugin'   => 'a/a.php',
				),
			),
			false
		);

		$result = Dormant::sweep( $now );
		$this->assertContains( 12, $result['suspended'] );
		$this->assertNotContains( 13, $result['suspended'] );
		$this->assertTrue( Dormant::is_suspended( 12 ) );
		$this->assertFalse( Dormant::is_suspended( 13 ) );

		$notice = get_option( Dormant::NOTICE_OPTION, null );
		$this->assertIsArray( $notice );
		$this->assertStringContainsString( 'alice', (string) $notice['summary'] );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$dormant = array_values(
			array_filter(
				$log,
				static function ( $row ) {
					return is_array( $row ) && ( $row['decision'] ?? '' ) === 'dormant';
				}
			)
		);
		$this->assertCount( 1, $dormant );
		$this->assertSame( 'suspend', $dormant[0]['dormant_action'] );
		$this->assertSame( 12, (int) $dormant[0]['user_id'] );
		$this->assertGreaterThanOrEqual( 90, (int) $dormant[0]['dormant_days'] );
	}

	public function test_sweep_idempotent_no_duplicate_audit(): void {
		$now = 1_700_000_000;
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => $now - ( 120 * DAY_IN_SECONDS ),
					'user_id'  => 12,
					'decision' => 'allow',
					'plugin'   => 'a/a.php',
				),
			),
			false
		);

		Dormant::sweep( $now );
		Dormant::sweep( $now + 60 );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$dormant = array_values(
			array_filter(
				$log,
				static function ( $row ) {
					return is_array( $row )
						&& ( $row['decision'] ?? '' ) === 'dormant'
						&& ( $row['dormant_action'] ?? '' ) === 'suspend';
				}
			)
		);
		$this->assertCount( 1, $dormant );
	}

	public function test_active_user_never_touched(): void {
		$now = 1_700_000_000;
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => $now - ( 10 * DAY_IN_SECONDS ),
					'user_id'  => 12,
					'decision' => 'allow',
					'plugin'   => 'a/a.php',
				),
			),
			false
		);

		$result = Dormant::sweep( $now );
		$this->assertSame( array(), $result['suspended'] );
		$this->assertFalse( Dormant::is_suspended( 12 ) );
	}

	public function test_admin_lift_is_audited(): void {
		$now = 1_700_000_000;
		Dormant::suspend_user( 12, 95, $now );
		$this->assertTrue( Dormant::is_suspended( 12 ) );

		$lift = Dormant::lift_user( 12, 'admin', 1, $now + 10 );
		$this->assertTrue( $lift['lifted'] );
		$this->assertFalse( Dormant::is_suspended( 12 ) );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$lifts = array_values(
			array_filter(
				$log,
				static function ( $row ) {
					return is_array( $row )
						&& ( $row['decision'] ?? '' ) === 'dormant'
						&& ( $row['dormant_action'] ?? '' ) === 'lift';
				}
			)
		);
		$this->assertCount( 1, $lifts );
		$this->assertSame( 'admin', $lifts[0]['dormant_via'] );
		$this->assertSame( 1, (int) $lifts[0]['actor_id'] );
	}

	public function test_access_request_approve_lifts_suspended_user(): void {
		$now = 1_700_000_000;
		Dormant::suspend_user( 12, 100, $now );

		$policy            = Policy::get_policy();
		$policy['plugins'] = array( 'blocked/plugin.php' => 'deny' );
		Policy::save_policy( $policy );

		$submit = Access_Request::submit_request( 'blocked/plugin.php', 12, 'Need AI again', $now + 1 );
		$this->assertTrue( $submit['ok'] );
		$old = get_option( Access_Request::OPTION_KEY, array() );

		$ok = Access_Request::approve( $submit['id'], 1, $now + 2 );
		$this->assertTrue( $ok['ok'] );
		$new = get_option( Access_Request::OPTION_KEY, array() );

		// Unit harness update_option does not fire updated_option_*; invoke the hook body.
		Dormant::on_access_requests_updated( $old, $new );
		$this->assertFalse( Dormant::is_suspended( 12 ) );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$lifts = array_values(
			array_filter(
				$log,
				static function ( $row ) {
					return is_array( $row )
						&& ( $row['decision'] ?? '' ) === 'dormant'
						&& ( $row['dormant_action'] ?? '' ) === 'lift';
				}
			)
		);
		$this->assertNotEmpty( $lifts );
		$this->assertSame( 'access_request', $lifts[0]['dormant_via'] );
	}

	public function test_gate_denies_suspended_user(): void {
		$now = 1_700_000_000;
		Dormant::suspend_user( 12, 90, $now );

		$GLOBALS['handl_aicac_test_user_id'] = 12;
		Policy::save_policy(
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
			)
		);

		$allow = array(
			'ts'       => $now,
			'user_id'  => 12,
			'decision' => 'allow',
			'plugin'   => 'acme/acme.php',
		);
		Policy::append_log_event( $allow );

		putenv( 'HANDL_AICAC_TEST_NOW=' . (string) $now );
		$prevent = Dormant::maybe_prevent_prompt( false, new \stdClass() );
		putenv( 'HANDL_AICAC_TEST_NOW' );

		$this->assertTrue( $prevent );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$last = $log[ count( $log ) - 1 ];
		$this->assertSame( 'deny', $last['decision'] ?? '' );
		$this->assertSame( Dormant::REASON, $last['denial_reason'] ?? '' );
	}

	public function test_days_filter_overrides_stored(): void {
		Dormant::save_days( 90 );
		$GLOBALS['handl_aicac_test_filters']['handl_aicac_dormant_days'] = static function () {
			return 0;
		};
		$this->assertSame( 0, Dormant::days_window() );
	}
}
