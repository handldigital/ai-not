<?php
/**
 * AICAC-AUP-ACK (#369).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Aup;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class AupTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']         = array();
		$GLOBALS['handl_aicac_test_user_id']         = 12;
		$GLOBALS['handl_aicac_test_user_meta']       = array();
		$GLOBALS['handl_aicac_test_aup_users']       = array( 12, 34 );
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Aup::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_current_user_can'],
			$GLOBALS['handl_aicac_test_aup_users']
		);
		$GLOBALS['handl_aicac_test_options']   = array();
		$GLOBALS['handl_aicac_test_user_id']   = 0;
		$GLOBALS['handl_aicac_test_user_meta'] = array();
		Aup::reset_for_tests();
		parent::tearDown();
	}

	public function test_disabled_never_prevents(): void {
		Aup::save_settings(
			array(
				'enabled'     => false,
				'policy_text' => 'Be kind to robots.',
				'grace_days'  => 7,
			),
			1_700_000_000
		);
		$this->assertFalse( Aup::is_enabled() );
		$this->assertFalse( Aup::maybe_prevent_prompt( false, new \stdClass() ) );
	}

	public function test_empty_policy_never_enables(): void {
		Aup::save_settings(
			array(
				'enabled'     => true,
				'policy_text' => '',
				'grace_days'  => 7,
			),
			1_700_000_000
		);
		$this->assertFalse( Aup::is_enabled() );
		$this->assertFalse( Aup::maybe_prevent_prompt( false, new \stdClass() ) );
	}

	public function test_unaccepted_user_is_denied(): void {
		Aup::save_settings(
			array(
				'enabled'     => true,
				'policy_text' => 'Use AI responsibly.',
				'grace_days'  => 7,
			),
			1_700_000_000
		);
		$this->assertTrue( Aup::is_enabled() );
		$this->assertSame( Aup::STATUS_LOCKED, Aup::status_for_user( 12 ) );

		Policy::append_log_event(
			array(
				'ts'       => 1_700_000_001,
				'decision' => 'allow',
				'user_id'  => 12,
			)
		);

		$prevent = Aup::maybe_prevent_prompt( false, new \stdClass() );
		$this->assertTrue( $prevent );

		$log  = get_option( Plugin::LOG_OPTION_KEY, array() );
		$last = $log[ count( $log ) - 1 ];
		$this->assertSame( 'deny', $last['decision'] ?? '' );
		$this->assertSame( Aup::REASON, $last['denial_reason'] ?? '' );
		$this->assertSame( Aup::REASON, $last['decision_source'] ?? '' );
	}

	public function test_accept_current_allows(): void {
		Aup::save_settings(
			array(
				'enabled'     => true,
				'policy_text' => 'Use AI responsibly.',
				'grace_days'  => 7,
			),
			1_700_000_000
		);
		$result = Aup::accept_current( 12, 1_700_000_010, '127.0.0.1' );
		$this->assertTrue( $result['accepted'] );
		$this->assertSame( Aup::STATUS_CURRENT, Aup::status_for_user( 12 ) );
		$this->assertFalse( Aup::maybe_prevent_prompt( false, new \stdClass() ) );

		$ack = Aup::get_acceptance( 12 );
		$this->assertNotNull( $ack );
		$this->assertSame( $result['version'], $ack['version'] );
		$this->assertSame( '127.0.0.1', $ack['ip'] );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$accepts = array_values(
			array_filter(
				$log,
				static function ( $row ) {
					return is_array( $row ) && ( $row['decision'] ?? '' ) === 'aup_accept';
				}
			)
		);
		$this->assertCount( 1, $accepts );
	}

	public function test_policy_edit_bumps_version_and_grace_allows(): void {
		Aup::save_settings(
			array(
				'enabled'     => true,
				'policy_text' => 'Version one.',
				'grace_days'  => 7,
			),
			1_700_000_000
		);
		$v1 = Aup::get_settings()['version'];
		Aup::accept_current( 12, 1_700_000_001 );

		Aup::save_settings(
			array(
				'enabled'     => true,
				'policy_text' => 'Version two — revised.',
				'grace_days'  => 7,
			),
			1_700_000_100
		);
		$v2 = Aup::get_settings()['version'];
		$this->assertNotSame( $v1, $v2 );

		// Within grace (same day as bump).
		$this->assertSame( Aup::STATUS_GRACE, Aup::status_for_user( 12, null, 1_700_000_100 ) );
		$this->assertFalse( Aup::should_deny( 12, null, 1_700_000_100 ) );
		putenv( 'HANDL_AICAC_TEST_NOW=1700000100' );
		$this->assertFalse( Aup::maybe_prevent_prompt( false, new \stdClass() ) );
		putenv( 'HANDL_AICAC_TEST_NOW' );
	}

	public function test_grace_expiry_locks_until_reack(): void {
		Aup::save_settings(
			array(
				'enabled'     => true,
				'policy_text' => 'Old text.',
				'grace_days'  => 1,
			),
			1_700_000_000
		);
		Aup::accept_current( 12, 1_700_000_001 );

		Aup::save_settings(
			array(
				'enabled'     => true,
				'policy_text' => 'New text after edit.',
				'grace_days'  => 1,
			),
			1_700_000_000
		);

		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
		$past_grace = 1_700_000_000 + $day + 10;
		$this->assertSame( Aup::STATUS_LOCKED, Aup::status_for_user( 12, null, $past_grace ) );
		$this->assertTrue( Aup::should_deny( 12, null, $past_grace ) );

		Aup::accept_current( 12, $past_grace );
		$this->assertSame( Aup::STATUS_CURRENT, Aup::status_for_user( 12, null, $past_grace ) );
	}

	public function test_zero_grace_locks_immediately_on_edit(): void {
		Aup::save_settings(
			array(
				'enabled'     => true,
				'policy_text' => 'First.',
				'grace_days'  => 0,
			),
			1_700_000_000
		);
		Aup::accept_current( 12, 1_700_000_001 );
		Aup::save_settings(
			array(
				'enabled'     => true,
				'policy_text' => 'Second.',
				'grace_days'  => 0,
			),
			1_700_000_050
		);
		$this->assertSame( Aup::STATUS_LOCKED, Aup::status_for_user( 12, null, 1_700_000_050 ) );
	}

	public function test_prior_prevent_unchanged(): void {
		Aup::save_settings(
			array(
				'enabled'     => true,
				'policy_text' => 'Policy.',
				'grace_days'  => 7,
			),
			1_700_000_000
		);
		$this->assertTrue( Aup::maybe_prevent_prompt( true, new \stdClass() ) );
	}

	public function test_audit_only_skips_gate(): void {
		Aup::save_settings(
			array(
				'enabled'     => true,
				'policy_text' => 'Policy.',
				'grace_days'  => 7,
			),
			1_700_000_000
		);
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => true,
			)
		);
		$this->assertFalse( Aup::maybe_prevent_prompt( false, new \stdClass() ) );
	}

	public function test_roster_and_csv_and_reset(): void {
		Aup::save_settings(
			array(
				'enabled'     => true,
				'policy_text' => 'Site AI rules.',
				'grace_days'  => 7,
			),
			1_700_000_000
		);
		Aup::accept_current( 12, 1_700_000_010 );
		$roster = Aup::roster( array( 12, 34 ) );
		$this->assertNotEmpty( $roster );
		$by_id = array();
		foreach ( $roster as $row ) {
			$by_id[ (int) $row['user_id'] ] = $row;
		}
		$this->assertSame( Aup::STATUS_CURRENT, $by_id[12]['status'] );
		$this->assertSame( Aup::STATUS_LOCKED, $by_id[34]['status'] );

		$csv = Aup::csv_for_roster( array( 12, 34 ) );
		$this->assertStringContainsString( 'user_id,login,display,status,version', $csv );
		$this->assertStringContainsString( 'current', $csv );

		Aup::clear_acceptance( 12 );
		$this->assertSame( Aup::STATUS_LOCKED, Aup::status_for_user( 12 ) );
		$this->assertNull( Aup::get_acceptance( 12 ) );
	}

	public function test_hash_stable_for_same_text(): void {
		$a = Aup::hash_policy( 'Same policy text.' );
		$b = Aup::hash_policy( 'Same policy text.' );
		$this->assertSame( $a, $b );
		$this->assertSame( 16, strlen( $a ) );
		$this->assertNotSame( $a, Aup::hash_policy( 'Different text.' ) );
	}
}
