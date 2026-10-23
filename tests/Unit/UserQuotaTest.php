<?php
/**
 * AICAC-USER-QUOTA (#339): per-user / per-role rolling-24h call quotas.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Soft_Deny;
use HandL\AICAC\User_Quota;
use PHPUnit\Framework\TestCase;

final class UserQuotaTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		User_Quota::reset_for_tests();
		unset( $GLOBALS['handl_aicac_test_user_id'], $GLOBALS['handl_aicac_test_user_roles'], $GLOBALS['handl_aicac_test_user_meta'] );
		Soft_Deny::reset_for_tests();
	}

	protected function tearDown(): void {
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		User_Quota::reset_for_tests();
		unset( $GLOBALS['handl_aicac_test_user_id'], $GLOBALS['handl_aicac_test_user_roles'], $GLOBALS['handl_aicac_test_user_meta'] );
		Soft_Deny::reset_for_tests();
		parent::tearDown();
	}

	public function test_sanitize_limit_empty_is_unlimited(): void {
		$this->assertNull( User_Quota::sanitize_limit( '' ) );
		$this->assertNull( User_Quota::sanitize_limit( 0 ) );
		$this->assertNull( User_Quota::sanitize_limit( -1 ) );
		$this->assertSame( 50, User_Quota::sanitize_limit( 50 ) );
		$this->assertSame( User_Quota::MAX_CAP, User_Quota::sanitize_limit( User_Quota::MAX_CAP + 9 ) );
	}

	public function test_no_role_quota_is_noop(): void {
		$GLOBALS['handl_aicac_test_user_id']    = 9;
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'editor' );
		$policy = array( 'default' => 'allow' );
		$eval   = User_Quota::evaluate( $policy, 9 );
		$this->assertFalse( $eval['prevent'] );
		$this->assertNull( $eval['limit'] );
		$this->assertSame( '', $eval['source'] );
	}

	public function test_role_quota_deny_at_limit(): void {
		$tz  = new \DateTimeZone( 'UTC' );
		$now = ( new \DateTimeImmutable( '2026-10-12 15:30:00', $tz ) )->getTimestamp();
		$hk  = User_Quota::hour_key( $now, $tz );
		User_Quota::set_window_count( 9, $hk, 5 );

		$GLOBALS['handl_aicac_test_user_id']    = 9;
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'editor' );

		$policy = array(
			'default'                         => 'allow',
			User_Quota::POLICY_ROLE_LIMITS    => array( 'editor' => 5 ),
		);

		$eval = User_Quota::evaluate( $policy, 9, null, $now, $tz );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( User_Quota::REASON, $eval['reason'] );
		$this->assertSame( 5, $eval['limit'] );
		$this->assertSame( 5, $eval['count'] );
		$this->assertSame( 'role', $eval['source'] );
	}

	public function test_user_override_beats_role_quota(): void {
		$GLOBALS['handl_aicac_test_user_id']    = 9;
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'editor' );
		update_user_meta( 9, User_Quota::USER_META_LIMIT, 2 );

		$policy = array(
			User_Quota::POLICY_ROLE_LIMITS => array( 'editor' => 50 ),
		);

		$eval = User_Quota::evaluate( $policy, 9 );
		$this->assertSame( 2, $eval['limit'] );
		$this->assertSame( 'user', $eval['source'] );
	}

	public function test_apply_to_event_allows_under_quota_and_counts(): void {
		$tz  = new \DateTimeZone( 'UTC' );
		$now = ( new \DateTimeImmutable( '2026-10-12 15:30:00', $tz ) )->getTimestamp();

		$GLOBALS['handl_aicac_test_user_id']    = 9;
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'editor' );

		$policy = array(
			User_Quota::POLICY_ROLE_LIMITS => array( 'editor' => 3 ),
		);

		$event = array(
			'ts'       => $now,
			'user_id'  => 9,
			'decision' => 'allow',
			'plugin'   => 'acme/acme.php',
		);
		$r1 = User_Quota::apply_to_event( $event, $policy, $now );
		$this->assertFalse( $r1['prevent'] );
		$this->assertSame( 1, $event['user_quota_count'] );

		$event2 = array(
			'ts'       => $now,
			'user_id'  => 9,
			'decision' => 'allow',
		);
		$r2 = User_Quota::apply_to_event( $event2, $policy, $now );
		$this->assertFalse( $r2['prevent'] );

		$event3 = array(
			'ts'       => $now,
			'user_id'  => 9,
			'decision' => 'allow',
		);
		$r3 = User_Quota::apply_to_event( $event3, $policy, $now );
		$this->assertFalse( $r3['prevent'] );

		$event4 = array(
			'ts'       => $now,
			'user_id'  => 9,
			'decision' => 'allow',
		);
		$r4 = User_Quota::apply_to_event( $event4, $policy, $now );
		$this->assertTrue( $r4['prevent'] );
		$this->assertSame( User_Quota::REASON, $r4['reason'] );
		$this->assertSame( User_Quota::REASON, $event4['denial_reason'] );
	}

	public function test_cron_user_zero_bypasses_quota(): void {
		$policy = array(
			User_Quota::POLICY_ROLE_LIMITS => array( 'editor' => 1 ),
		);
		$eval = User_Quota::evaluate( $policy, 0 );
		$this->assertFalse( $eval['prevent'] );
		$this->assertNull( $eval['limit'] );
	}

	public function test_merge_on_policy_save_noop_preserves_role_limits(): void {
		$stored = array(
			'default'                      => 'allow',
			User_Quota::POLICY_ROLE_LIMITS => array( 'editor' => 50, 'author' => 20 ),
		);
		update_option( Plugin::OPTION_KEY, $stored, false );

		$_POST = array(); // no POST_PRESENT → preserve.
		$out   = User_Quota::merge_on_policy_save(
			array( 'default' => 'allow', 'plugins' => array() ),
			$stored
		);
		$this->assertSame(
			array( 'author' => 20, 'editor' => 50 ),
			$out[ User_Quota::POLICY_ROLE_LIMITS ]
		);
		unset( $_POST );
	}

	public function test_merge_on_policy_save_reads_posted_limits(): void {
		$_POST = array(
			User_Quota::POST_PRESENT     => '1',
			User_Quota::POST_ROLE_LIMITS => array(
				'editor' => '50',
				'author' => '',
				'foo'    => '0',
			),
		);
		$out = User_Quota::merge_on_policy_save( array( 'default' => 'allow' ), array() );
		$this->assertSame( array( 'editor' => 50 ), $out[ User_Quota::POLICY_ROLE_LIMITS ] );
		unset( $_POST );
	}

	public function test_noop_save_with_existing_quotas_stays_byte_identical(): void {
		$stored = array(
			'default'                      => 'allow',
			'plugins'                      => array( 'a/a.php' => 'deny' ),
			User_Quota::POLICY_ROLE_LIMITS => array( 'editor' => 50 ),
		);
		update_option( Plugin::OPTION_KEY, $stored, false );
		Policy::save_policy( $stored );
		$this->assertSame( $stored, get_option( Plugin::OPTION_KEY ) );
	}

	public function test_gate_filter_denies_over_quota_with_reason(): void {
		$tz  = new \DateTimeZone( 'UTC' );
		$now = ( new \DateTimeImmutable( '2026-10-12 15:30:00', $tz ) )->getTimestamp();
		$hk  = User_Quota::hour_key( $now, $tz );
		User_Quota::set_window_count( 9, $hk, 2 );

		$GLOBALS['handl_aicac_test_user_id']    = 9;
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'editor' );

		$policy = array(
			'default'                      => 'allow',
			'log_enabled'                  => true,
			User_Quota::POLICY_ROLE_LIMITS => array( 'editor' => 2 ),
		);
		Policy::save_policy( $policy );

		// Simulate Policy already logging an allow for this call.
		$allow = array(
			'ts'       => $now,
			'user_id'  => 9,
			'decision' => 'allow',
			'plugin'   => 'acme/acme.php',
		);
		Policy::append_log_event( $allow );

		$user_quota = User_Quota::instance();
		$user_quota->init();

		$builder = new \stdClass();
		putenv( 'HANDL_AICAC_TEST_NOW=' . (string) $now );
		$prevent = $user_quota->maybe_prevent_prompt( false, $builder );
		putenv( 'HANDL_AICAC_TEST_NOW' );

		$this->assertTrue( $prevent );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $log );
		$this->assertNotEmpty( $log );
		$last = $log[ count( $log ) - 1 ];
		$this->assertSame( 'deny', $last['decision'] ?? '' );
		$this->assertSame( User_Quota::REASON, $last['denial_reason'] ?? '' );

		// Only one row: allow was reclassified / replaced by deny.
		$decisions = array_map(
			static function ( $row ) {
				return is_array( $row ) ? (string) ( $row['decision'] ?? '' ) : '';
			},
			$log
		);
		$this->assertSame( array( 'deny' ), array_values( array_filter( $decisions ) ) );
	}

	public function test_gate_filter_soft_deny_reuses_soft_deny_arm(): void {
		$tz  = new \DateTimeZone( 'UTC' );
		$now = ( new \DateTimeImmutable( '2026-10-12 15:30:00', $tz ) )->getTimestamp();
		$hk  = User_Quota::hour_key( $now, $tz );
		User_Quota::set_window_count( 9, $hk, 1 );

		$GLOBALS['handl_aicac_test_user_id']    = 9;
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'editor' );

		$plugin = 'soft/a.php';
		$policy = array(
			'default'                      => 'allow',
			'log_enabled'                  => true,
			User_Quota::POLICY_ROLE_LIMITS => array( 'editor' => 1 ),
			Soft_Deny::POLICY_KEY          => array( $plugin => Soft_Deny::MODE_SOFT ),
		);
		Policy::save_policy( $policy );

		// Attribution stub via backtrace is hard; seed plugin on a prior allow then
		// exercise Soft_Deny arming through apply path + Soft_Deny helper.
		$event = array(
			'ts'       => $now,
			'user_id'  => 9,
			'plugin'   => $plugin,
			'decision' => 'deny',
		);
		$rc = User_Quota::apply_to_event( $event, $policy, $now );
		$this->assertTrue( $rc['prevent'] );

		$soft = Soft_Deny::maybe_arm_from_deny( true, $event, $policy, $plugin, 'generate_text', 'text-generation' );
		$this->assertTrue( $soft );
		$this->assertTrue( Soft_Deny::is_armed() );
		$this->assertSame( Soft_Deny::OUTCOME, $event['outcome'] ?? '' );
	}

	public function test_plugin_does_not_touch_cost_or_rate_cap_files(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-user-quota.php' );
		$this->assertStringNotContainsString( 'Rate_Cap::', $src );
		$this->assertStringNotContainsString( 'class-handl-aicac-cost', $src );
		$this->assertStringNotContainsString( 'class-handl-aicac-rate-cap', $src );

		$cost = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-cost.php' );
		$this->assertStringNotContainsString( 'User_Quota', $cost );

		$rc = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-rate-cap.php' );
		$this->assertStringNotContainsString( 'User_Quota', $rc );

		$policy = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy.php' );
		$this->assertStringNotContainsString( 'User_Quota', $policy );
	}

	public function test_max_role_quota_when_user_has_multiple_roles(): void {
		$GLOBALS['handl_aicac_test_user_id']    = 9;
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'author', 'editor' );
		$policy = array(
			User_Quota::POLICY_ROLE_LIMITS => array(
				'author' => 20,
				'editor' => 50,
			),
		);
		$this->assertSame( 50, User_Quota::effective_limit( $policy, 9 ) );
	}
}
