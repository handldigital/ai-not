<?php
/**
 * AICAC-BUDGET-A (#166): period spend accounting.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Budget;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class BudgetAccountingTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Budget::SPEND_OPTION_KEY );
	}

	protected function tearDown(): void {
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Budget::SPEND_OPTION_KEY );
		parent::tearDown();
	}

	public function test_period_id_uses_timezone(): void {
		// 2026-08-01 00:30 UTC → still July in America/Chicago (UTC-5).
		$ts = ( new \DateTimeImmutable( '2026-08-01 00:30:00', new \DateTimeZone( 'UTC' ) ) )->getTimestamp();
		$utc = Budget::period_id( $ts, new \DateTimeZone( 'UTC' ) );
		$chi = Budget::period_id( $ts, new \DateTimeZone( 'America/Chicago' ) );
		$this->assertSame( '2026-08', $utc );
		$this->assertSame( '2026-07', $chi );
	}

	public function test_accumulator_tracks_estimated_spend_per_plugin_per_period(): void {
		$tz = new \DateTimeZone( 'UTC' );
		$ts = ( new \DateTimeImmutable( '2026-08-15 12:00:00', $tz ) )->getTimestamp();

		Budget::add_estimated_spend( 'acme/acme.php', 1.25, $ts, $tz );
		Budget::add_estimated_spend( 'acme/acme.php', 0.75, $ts, $tz );
		Budget::add_estimated_spend( 'other/other.php', 2.0, $ts, $tz );

		$this->assertSame( 2.0, Budget::period_spend( 'acme/acme.php', '2026-08' ) );
		$this->assertSame( 2.0, Budget::period_spend( 'other/other.php', '2026-08' ) );
		$this->assertSame( 0.0, Budget::period_spend( 'acme/acme.php', '2026-07' ) );
	}

	public function test_period_boundary_rollover_does_not_carry_spend(): void {
		$tz = new \DateTimeZone( 'UTC' );
		$aug = ( new \DateTimeImmutable( '2026-08-31 23:00:00', $tz ) )->getTimestamp();
		$sep = ( new \DateTimeImmutable( '2026-09-01 01:00:00', $tz ) )->getTimestamp();

		Budget::add_estimated_spend( 'acme/acme.php', 5.0, $aug, $tz );
		Budget::add_estimated_spend( 'acme/acme.php', 1.0, $sep, $tz );

		$this->assertSame( 5.0, Budget::period_spend( 'acme/acme.php', '2026-08' ) );
		$this->assertSame( 1.0, Budget::current_period_spend( 'acme/acme.php', $sep, $tz ) );
	}

	public function test_timezone_change_does_not_double_count(): void {
		$utc = new \DateTimeZone( 'UTC' );
		$chi = new \DateTimeZone( 'America/Chicago' );
		// Same unix instant recorded under the period key from the TZ in effect at write time.
		$ts = ( new \DateTimeImmutable( '2026-08-01 00:30:00', $utc ) )->getTimestamp();

		Budget::add_estimated_spend( 'acme/acme.php', 3.0, $ts, $utc );
		$this->assertSame( 3.0, Budget::period_spend( 'acme/acme.php', '2026-08' ) );
		$this->assertSame( 0.0, Budget::period_spend( 'acme/acme.php', '2026-07' ) );

		// Site TZ flips to Chicago: current period for that instant is July, but
		// already-recorded August spend stays under 2026-08 (period key authoritative).
		$this->assertSame( '2026-07', Budget::period_id( $ts, $chi ) );
		$this->assertSame( 0.0, Budget::current_period_spend( 'acme/acme.php', $ts, $chi ) );
		$this->assertSame( 3.0, Budget::period_spend( 'acme/acme.php', '2026-08' ) );

		// New spend after the TZ change lands in the Chicago period for that ts.
		Budget::add_estimated_spend( 'acme/acme.php', 1.0, $ts, $chi );
		$this->assertSame( 1.0, Budget::period_spend( 'acme/acme.php', '2026-07' ) );
		$this->assertSame( 3.0, Budget::period_spend( 'acme/acme.php', '2026-08' ) );
	}

	public function test_status_read_api_budget_and_percent(): void {
		$policy = array(
			'plugin_budgets' => array(
				'acme/acme.php' => 10.0,
			),
		);
		$tz = new \DateTimeZone( 'UTC' );
		$ts = ( new \DateTimeImmutable( '2026-08-10 12:00:00', $tz ) )->getTimestamp();
		Budget::add_estimated_spend( 'acme/acme.php', 2.5, $ts, $tz );

		$status = Budget::status( $policy, 'acme/acme.php', $ts, $tz );
		$this->assertSame( '2026-08', $status['period'] );
		$this->assertSame( 2.5, $status['spend'] );
		$this->assertSame( 10.0, $status['budget'] );
		$this->assertFalse( $status['unlimited'] );
		$this->assertSame( 25.0, $status['percent_used'] );

		$open = Budget::status( $policy, 'other/other.php', $ts, $tz );
		$this->assertTrue( $open['unlimited'] );
		$this->assertNull( $open['budget'] );
		$this->assertNull( $open['percent_used'] );
		$this->assertSame( 0.0, $open['spend'] );
	}

	public function test_sanitize_plugin_budgets_drops_unlimited(): void {
		$map = Budget::sanitize_plugin_budgets(
			array(
				'acme/acme.php'  => 5,
				'zero/zero.php'  => 0,
				'blank/blank.php'=> '',
				'neg/neg.php'    => -1,
			)
		);
		$this->assertSame( array( 'acme/acme.php' => 5.0 ), $map );
	}

	public function test_token_patch_records_estimated_delta(): void {
		$policy = array(
			'log_enabled'         => true,
			'est_usd_input_per_m' => 1.0,
			'est_usd_output_per_m'=> 1.0,
		);
		Policy::save_policy( $policy );

		$tz = new \DateTimeZone( 'UTC' );
		$ts = ( new \DateTimeImmutable( '2026-08-20 12:00:00', $tz ) )->getTimestamp();
		$log_key = 'budget-test-key';
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => $ts,
					'plugin'   => 'acme/acme.php',
					'provider' => 'openai',
					'decision' => 'allow',
					'log_key'  => $log_key,
				),
			),
			false
		);

		// 1M input tokens @ $1/1M = $1.00 estimated.
		$ref = new \ReflectionClass( Policy::class );
		$method = $ref->getMethod( 'patch_log_entry' );
		$method->setAccessible( true );
		$ok = $method->invoke( null, $log_key, array( 'input_tokens' => 1_000_000, 'output_tokens' => 0 ) );
		$this->assertTrue( $ok );
		$this->assertEqualsWithDelta( 1.0, Budget::period_spend( 'acme/acme.php', '2026-08' ), 0.0001 );

		// Second patch adding another 1M input → +$1 more (delta only).
		$ok2 = $method->invoke( null, $log_key, array( 'input_tokens' => 2_000_000, 'output_tokens' => 0 ) );
		$this->assertTrue( $ok2 );
		$this->assertEqualsWithDelta( 2.0, Budget::period_spend( 'acme/acme.php', '2026-08' ), 0.0001 );
	}
}
