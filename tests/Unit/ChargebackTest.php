<?php
/**
 * AICAC-CHARGEBACK (#349).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Chargeback;
use HandL\AICAC\Cost;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class ChargebackTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_user_id'] = 1;
		$GLOBALS['handl_aicac_test_users']   = array(
			12 => array(
				'ID'         => 12,
				'user_login' => 'alice',
				'roles'      => array( 'editor' ),
			),
			13 => array(
				'ID'         => 13,
				'user_login' => 'bob',
				'roles'      => array( 'author' ),
			),
			1  => array(
				'ID'         => 1,
				'user_login' => 'admin',
				'roles'      => array( 'administrator' ),
			),
		);
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) {
			$GLOBALS['handl_aicac_test_mails'][] = array(
				'to'      => $to,
				'subject' => $subject,
				'message' => $message,
			);
			return true;
		};
		$GLOBALS['handl_aicac_test_mails'] = array();

		Chargeback::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'alert_email' => 'owner@example.com',
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_users'],
			$GLOBALS['handl_aicac_wp_mail'],
			$GLOBALS['handl_aicac_test_mails']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		Chargeback::reset_for_tests();
		parent::tearDown();
	}

	public function test_month_window_boundaries_exclusive_end(): void {
		$window = Chargeback::month_window( '2026-03' );
		$this->assertNotNull( $window );
		$this->assertSame( '2026-03', $window['ym'] );

		$tz    = Chargeback::timezone();
		$start = ( new \DateTimeImmutable( '@' . $window['start_ts'] ) )->setTimezone( $tz );
		$end   = ( new \DateTimeImmutable( '@' . $window['end_ts'] ) )->setTimezone( $tz );
		$this->assertSame( '2026-03-01 00:00:00', $start->format( 'Y-m-d H:i:s' ) );
		$this->assertSame( '2026-04-01 00:00:00', $end->format( 'Y-m-d H:i:s' ) );
	}

	public function test_aggregation_math_and_zero_spend_omitted(): void {
		$policy = array(
			'est_usd_input_per_m'  => 1.0,
			'est_usd_output_per_m' => 2.0,
		);
		$tz     = Chargeback::timezone();
		$mid    = \DateTimeImmutable::createFromFormat( '!Y-m-d H:i:s', '2026-03-15 12:00:00', $tz );
		$edge   = \DateTimeImmutable::createFromFormat( '!Y-m-d H:i:s', '2026-04-01 00:00:00', $tz );
		$this->assertNotFalse( $mid );
		$this->assertNotFalse( $edge );

		$log = array(
			array(
				'ts'            => $mid->getTimestamp(),
				'user_id'       => 12,
				'provider'      => 'openai',
				'input_tokens'  => 1_000_000,
				'output_tokens' => 500_000,
				'decision'      => 'allow',
				'plugin'        => 'a/a.php',
			),
			array(
				'ts'            => $mid->getTimestamp() + 10,
				'user_id'       => 13,
				'provider'      => 'openai',
				'input_tokens'  => 0,
				'output_tokens' => 0,
				'decision'      => 'allow',
				'plugin'        => 'b/b.php',
			),
			// Outside month — must not count.
			array(
				'ts'            => $edge->getTimestamp(),
				'user_id'       => 12,
				'provider'      => 'openai',
				'input_tokens'  => 1_000_000,
				'output_tokens' => 0,
				'decision'      => 'allow',
				'plugin'        => 'a/a.php',
			),
		);

		$statement = Chargeback::build_statement( $log, $policy, '2026-03' );
		$this->assertSame( '2026-03', $statement['ym'] );
		// bob = $0 → omitted from statement; only alice's call remains.
		$this->assertSame( 1, $statement['total_calls'] );
		// 1.0 * 1M/1M + 2.0 * 0.5M/1M = 2.0 from alice.
		$this->assertEqualsWithDelta( 2.0, $statement['total_cost'], 0.00001 );
		$this->assertCount( 1, $statement['users'] );
		$this->assertSame( 'alice', $statement['users'][0]['label'] );
		$this->assertSame( 'editor', $statement['users'][0]['role'] );
		$this->assertEqualsWithDelta( 2.0, $statement['users'][0]['cost'], 0.00001 );

		$roles = array();
		foreach ( $statement['roles'] as $r ) {
			$roles[ $r['role'] ] = $r;
		}
		$this->assertArrayHasKey( 'editor', $roles );
		$this->assertArrayNotHasKey( 'author', $roles );
		$this->assertEqualsWithDelta( 2.0, $roles['editor']['cost'], 0.00001 );
	}

	public function test_role_change_mid_month_splits_role_rollup(): void {
		$policy = array(
			'est_usd_input_per_m'  => 1.0,
			'est_usd_output_per_m' => 0.0,
		);
		$tz  = Chargeback::timezone();
		$t1  = \DateTimeImmutable::createFromFormat( '!Y-m-d H:i:s', '2026-03-05 10:00:00', $tz );
		$t2  = \DateTimeImmutable::createFromFormat( '!Y-m-d H:i:s', '2026-03-20 10:00:00', $tz );
		$this->assertNotFalse( $t1 );
		$this->assertNotFalse( $t2 );

		$log = array(
			array(
				'ts'           => $t1->getTimestamp(),
				'user_id'      => 12,
				'role'         => 'author',
				'input_tokens' => 1_000_000,
				'output_tokens'=> 0,
				'decision'     => 'allow',
				'plugin'       => 'a/a.php',
			),
			array(
				'ts'           => $t2->getTimestamp(),
				'user_id'      => 12,
				'role'         => 'editor',
				'input_tokens' => 2_000_000,
				'output_tokens'=> 0,
				'decision'     => 'allow',
				'plugin'       => 'a/a.php',
			),
		);

		$statement = Chargeback::build_statement( $log, $policy, '2026-03' );
		$roles     = array();
		foreach ( $statement['roles'] as $r ) {
			$roles[ $r['role'] ] = $r;
		}
		$this->assertEqualsWithDelta( 1.0, $roles['author']['cost'], 0.00001 );
		$this->assertEqualsWithDelta( 2.0, $roles['editor']['cost'], 0.00001 );
		$this->assertSame( 1, $roles['author']['calls'] );
		$this->assertSame( 1, $roles['editor']['calls'] );
		$this->assertCount( 1, $statement['users'] );
		$this->assertEqualsWithDelta( 3.0, $statement['users'][0]['cost'], 0.00001 );
	}

	public function test_deleted_users_folded_into_removed_bucket(): void {
		$policy = array(
			'est_usd_input_per_m'  => 1.0,
			'est_usd_output_per_m' => 0.0,
		);
		$tz  = Chargeback::timezone();
		$mid = \DateTimeImmutable::createFromFormat( '!Y-m-d H:i:s', '2026-03-10 08:00:00', $tz );
		$this->assertNotFalse( $mid );

		$log = array(
			array(
				'ts'           => $mid->getTimestamp(),
				'user_id'      => 99,
				'role'         => 'editor',
				'input_tokens' => 1_000_000,
				'output_tokens'=> 0,
				'decision'     => 'allow',
				'plugin'       => 'gone/gone.php',
			),
			array(
				'ts'           => $mid->getTimestamp() + 5,
				'user_id'      => 98,
				'role'         => 'author',
				'input_tokens' => 500_000,
				'output_tokens'=> 0,
				'decision'     => 'allow',
				'plugin'       => 'gone/gone.php',
			),
		);

		$statement = Chargeback::build_statement( $log, $policy, '2026-03' );
		$this->assertCount( 1, $statement['users'] );
		$this->assertSame( Chargeback::REMOVED_LABEL, $statement['users'][0]['label'] );
		$this->assertSame( 0, $statement['users'][0]['user_id'] );
		$this->assertSame( 2, $statement['users'][0]['calls'] );
		$this->assertEqualsWithDelta( 1.5, $statement['users'][0]['cost'], 0.00001 );
	}

	public function test_csv_and_email_off_by_default(): void {
		$this->assertFalse( Chargeback::get_settings()['email_enabled'] );

		$policy = array(
			'est_usd_input_per_m'  => Cost::DEFAULT_INPUT_PER_M,
			'est_usd_output_per_m' => Cost::DEFAULT_OUTPUT_PER_M,
			'alert_email'         => 'owner@example.com',
		);
		$result = Chargeback::send_if_due( $policy, strtotime( '2026-04-02 12:00:00 UTC' ) );
		$this->assertFalse( $result['sent'] );
		$this->assertSame( 'inactive', $result['status'] );
		$this->assertSame( array(), $GLOBALS['handl_aicac_test_mails'] );

		$tz  = Chargeback::timezone();
		$mid = \DateTimeImmutable::createFromFormat( '!Y-m-d H:i:s', '2026-03-12 09:00:00', $tz );
		$this->assertNotFalse( $mid );
		$statement = Chargeback::build_statement(
			array(
				array(
					'ts'           => $mid->getTimestamp(),
					'user_id'      => 12,
					'input_tokens' => 1000,
					'output_tokens'=> 0,
					'decision'     => 'allow',
					'plugin'       => 'a/a.php',
				),
			),
			$policy,
			'2026-03'
		);
		$csv = Chargeback::csv_for( $statement, 'users' );
		$this->assertStringContainsString( 'user,user_id,role,calls', $csv );
		$this->assertStringContainsString( 'alice', $csv );

		Chargeback::save_settings( array( 'email_enabled' => true ) );
		$sent = Chargeback::send_if_due( Policy::get_policy(), strtotime( '2026-04-02 12:00:00 UTC' ) );
		$this->assertTrue( $sent['sent'] );
		$this->assertSame( '2026-03', $sent['period_ym'] );
		$this->assertNotEmpty( $GLOBALS['handl_aicac_test_mails'] );
		$this->assertStringContainsString( '2026-03', $GLOBALS['handl_aicac_test_mails'][0]['subject'] );
	}

	public function test_sort_rows_by_calls_asc(): void {
		$rows = array(
			array( 'label' => 'a', 'calls' => 5, 'cost' => 1.0 ),
			array( 'label' => 'b', 'calls' => 2, 'cost' => 9.0 ),
		);
		$sorted = Chargeback::sort_rows( $rows, 'calls', 'asc' );
		$this->assertSame( 'b', $sorted[0]['label'] );
		$this->assertSame( 'a', $sorted[1]['label'] );
	}
}
