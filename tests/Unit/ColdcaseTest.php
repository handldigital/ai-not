<?php
/**
 * AICAC-COLDCASE (#448).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Coldcase;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class ColdcaseTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12 UTC.

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$GLOBALS['handl_aicac_test_cron']             = array();
		$GLOBALS['handl_aicac_test_users']            = array(
			7 => array(
				'ID'         => 7,
				'user_login' => 'left_once',
				'user_email' => 'left@example.com',
			),
			8 => array(
				'ID'         => 8,
				'user_login' => 'retried',
				'user_email' => 'retry@example.com',
			),
			9 => array(
				'ID'         => 9,
				'user_login' => 'recent_deny',
				'user_email' => 'recent@example.com',
			),
		);
		Coldcase::reset_for_tests();
		Coldcase::set_test_now( self::NOW );
		Coldcase::set_test_access_requests( array() );
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_cron']          = array();
		$GLOBALS['handl_aicac_test_users']         = array();
		Coldcase::reset_for_tests();
		parent::tearDown();
	}

	private function day(): int {
		return defined( 'DAY_IN_SECONDS' ) ? DAY_IN_SECONDS : 86400;
	}

	/**
	 * @return array<string,mixed>
	 */
	private function deny_row( int $user_id, int $ts, string $rule = 'plugin' ): array {
		return array(
			'ts'            => $ts,
			'decision'      => 'deny',
			'user_id'       => $user_id,
			'denial_reason' => $rule,
			'plugin'        => 'acme/acme.php',
		);
	}

	public function test_single_old_deny_is_cold_case(): void {
		$ts = self::NOW - ( 20 * $this->day() );
		Coldcase::set_test_log( array( $this->deny_row( 7, $ts, 'budget' ) ) );

		$cases = Coldcase::detect_cases( self::NOW, 14 );
		$this->assertCount( 1, $cases );
		$this->assertSame( 7, (int) $cases[0]['user_id'] );
		$this->assertSame( 'budget', (string) $cases[0]['rule'] );
		$this->assertSame( 20, (int) $cases[0]['days_silent'] );
		$this->assertSame( 1, (int) $cases[0]['count'] );
		$this->assertSame( 'left_once', (string) $cases[0]['user_login'] );

		$this->assertTrue( Coldcase::scan( self::NOW ) );
		$state = Coldcase::get_state();
		$this->assertCount( 1, $state['cases'] );
		$this->assertSame( self::NOW, (int) $state['updated_at'] );

		$snap = Coldcase::snapshot( self::NOW );
		$this->assertSame( 1, (int) $snap['count'] );
		$this->assertStringContainsString( '1 user', $snap['headline'] );
	}

	public function test_retry_or_access_request_excludes_user(): void {
		$first = self::NOW - ( 20 * $this->day() );
		$later = self::NOW - ( 10 * $this->day() );

		// Later AI event (allow) = retry.
		Coldcase::set_test_log(
			array(
				$this->deny_row( 8, $first, 'plugin' ),
				array(
					'ts'       => $later,
					'decision' => 'allow',
					'user_id'  => 8,
					'plugin'   => 'acme/acme.php',
				),
			)
		);
		$this->assertSame( array(), Coldcase::detect_cases( self::NOW, 14 ) );

		// Two denies = also a retry path.
		Coldcase::set_test_log(
			array(
				$this->deny_row( 8, $first, 'plugin' ),
				$this->deny_row( 8, $later, 'plugin' ),
			)
		);
		$this->assertSame( array(), Coldcase::detect_cases( self::NOW, 14 ) );

		// Single deny + access request after = not cold.
		Coldcase::set_test_log( array( $this->deny_row( 8, $first, 'plugin' ) ) );
		Coldcase::set_test_access_requests(
			array(
				'abcdabcdabcdabcdabcdabcdabcdabcd' => array(
					'user_id' => 8,
					'ts'      => $later,
					'status'  => 'pending',
					'plugin'  => 'acme/acme.php',
				),
			)
		);
		$this->assertSame( array(), Coldcase::detect_cases( self::NOW, 14 ) );
	}

	public function test_recent_deny_not_yet_cold(): void {
		$ts = self::NOW - ( 5 * $this->day() );
		Coldcase::set_test_log( array( $this->deny_row( 9, $ts, 'role' ) ) );
		$this->assertSame( array(), Coldcase::detect_cases( self::NOW, 14 ) );
	}

	public function test_missing_history_empty_census_no_errors(): void {
		Coldcase::set_test_log( null );
		// Force live soft-read of missing option.
		$pack = Coldcase::read_activity_log();
		$this->assertFalse( $pack['available'] );
		$this->assertSame( array(), $pack['rows'] );

		$cases = Coldcase::detect_cases( self::NOW, 14 );
		$this->assertSame( array(), $cases );
		$this->assertFalse( Coldcase::scan( self::NOW ) ); // empty never-written → no option write
		$this->assertFalse( (bool) get_option( Coldcase::OPTION_KEY, false ) );
		$snap = Coldcase::snapshot( self::NOW );
		$this->assertSame( 0, (int) $snap['count'] );
	}

	public function test_noop_save_invariant(): void {
		Coldcase::set_test_log(
			array( $this->deny_row( 7, self::NOW - ( 20 * $this->day() ), 'plugin' ) )
		);
		$this->assertTrue( Coldcase::scan( self::NOW ) );
		$serialized = get_option( Coldcase::OPTION_KEY, null );
		$this->assertFalse( Coldcase::scan( self::NOW ) );
		$this->assertSame( $serialized, get_option( Coldcase::OPTION_KEY, null ) );

		$this->assertFalse( Coldcase::save_silent_days( 14 ) );
		$this->assertTrue( Coldcase::save_silent_days( 21 ) );
		$this->assertSame( 21, Coldcase::silent_days() );
		$this->assertSame( Coldcase::defaults(), Coldcase::sanitize_state( 'junk' ) );
	}
}
