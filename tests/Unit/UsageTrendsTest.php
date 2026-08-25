<?php
/**
 * AICAC-TRENDS: weekly usage / spend aggregation (#134).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Usage_Trends;
use PHPUnit\Framework\TestCase;

final class UsageTrendsTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
	}

	protected function tearDown(): void {
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		parent::tearDown();
	}

	public function test_hides_when_fewer_than_two_weeks_of_history(): void {
		$now = strtotime( '2026-08-12 12:00:00 UTC' ); // Wednesday
		$log = array(
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-11 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-12 09:00:00 UTC' ) ),
		);
		$policy = $this->policy();
		$this->assertNull( Usage_Trends::compute( $log, $policy, array(), $now ) );
	}

	public function test_weekly_bucketing_and_delta_math(): void {
		// Fixed clock: Wed 2026-08-12. Weeks Mon-Sun.
		// Current week Mon Aug 10 – Sun Aug 16; prior Mon Aug 3 – Sun Aug 9.
		$now = strtotime( '2026-08-12 15:00:00 UTC' );
		$log = array(
			// Prior week: 5 calls @ $1 each = $5
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-03 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-04 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-05 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-06 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-07 10:00:00 UTC' ) ),
			// Current week: 7 calls @ $1 = $7 → +40% calls, +40% spend
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-10 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-10 11:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-11 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-11 12:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-12 08:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-12 09:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-12 10:00:00 UTC' ) ),
		);
		$policy = $this->policy();
		$out    = Usage_Trends::compute( $log, $policy, array( 'a/a.php' => array( 'Name' => 'Plugin A' ) ), $now );
		$this->assertNotNull( $out );
		$this->assertCount( 8, $out['weeks'] );
		$this->assertSame( 2, $out['weeks_with_data'] );

		$site = $out['site']['weeks'];
		$this->assertSame( 'data', $site[6]['status'] );
		$this->assertSame( 5, $site[6]['calls'] );
		$this->assertEqualsWithDelta( 5.0, (float) $site[6]['spend'], 0.0001 );
		$this->assertSame( 'data', $site[7]['status'] );
		$this->assertSame( 7, $site[7]['calls'] );
		$this->assertEqualsWithDelta( 7.0, (float) $site[7]['spend'], 0.0001 );

		$this->assertEqualsWithDelta( 40.0, (float) $out['site']['calls_delta_pct'], 0.0001 );
		$this->assertEqualsWithDelta( 40.0, (float) $out['site']['spend_delta_pct'], 0.0001 );

		$this->assertNotEmpty( $out['plugins'] );
		$this->assertSame( 'a/a.php', $out['plugins'][0]['plugin'] );
		$this->assertSame( 'Plugin A', $out['plugins'][0]['label'] );
		$this->assertEqualsWithDelta( 40.0, (float) $out['plugins'][0]['calls_delta_pct'], 0.0001 );
	}

	public function test_parity_with_activity_window_totals(): void {
		$now = strtotime( '2026-08-12 15:00:00 UTC' );
		$log = array(
			$this->spend_row( 'a/a.php', 2.0, strtotime( '2026-08-04 10:00:00 UTC' ) ),
			$this->spend_row( 'b/b.php', 3.0, strtotime( '2026-08-05 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-11 10:00:00 UTC' ) ),
			// Shadow / alert rows must not inflate Activity parity counts.
			array(
				'ts'       => strtotime( '2026-08-11 11:00:00 UTC' ),
				'plugin'   => 'a/a.php',
				'channel'  => 'direct_http',
				'decision' => 'observe',
				'count'    => 9,
			),
			array(
				'ts'       => strtotime( '2026-08-11 12:00:00 UTC' ),
				'plugin'   => 'a/a.php',
				'channel'  => 'anomaly',
				'decision' => 'anomaly',
			),
			$this->spend_row( 'a/a.php', 4.0, strtotime( '2026-08-12 09:00:00 UTC' ) ),
		);
		$policy = $this->policy();
		$out    = Usage_Trends::compute( $log, $policy, array(), $now );
		$this->assertNotNull( $out );

		foreach ( $out['weeks'] as $i => $def ) {
			$week = $out['site']['weeks'][ $i ];
			if ( 'data' !== $week['status'] ) {
				continue;
			}
			$expected_calls = Usage_Trends::count_activity_calls_in_window( $log, $def['start_ts'], $def['end_ts'] );
			$expected_spend = Usage_Trends::sum_activity_spend_in_window( $log, $policy, $def['start_ts'], $def['end_ts'] );
			$this->assertSame( $expected_calls, $week['calls'], 'calls parity for ' . $def['key'] );
			$this->assertEqualsWithDelta( $expected_spend, (float) $week['spend'], 0.0001, 'spend parity for ' . $def['key'] );
		}
	}

	public function test_ttl_purged_weeks_are_gaps_not_zeros(): void {
		$now = strtotime( '2026-08-12 15:00:00 UTC' );
		// 14-day TTL: anything before Jul 29 is purged from knowledge.
		$policy = $this->policy( array( 'log_max_age_days' => 14 ) );
		$log    = array(
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-04 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-11 10:00:00 UTC' ) ),
		);
		$out = Usage_Trends::compute( $log, $policy, array(), $now );
		$this->assertNotNull( $out );

		$knowledge = $out['knowledge_start_ts'];
		$this->assertSame( $now - ( 14 * 86400 ), $knowledge );

		foreach ( $out['weeks'] as $i => $def ) {
			$week = $out['site']['weeks'][ $i ];
			if ( $def['end_ts'] <= $knowledge ) {
				$this->assertSame( 'gap', $week['status'], 'TTL week must be gap: ' . $def['key'] );
				$this->assertNull( $week['calls'] );
				$this->assertNull( $week['spend'] );
			}
		}

		// Empty week inside retention with no rows is also a gap (never zero).
		$empty_inside = false;
		foreach ( $out['site']['weeks'] as $week ) {
			if ( 'gap' === $week['status'] && null === $week['calls'] ) {
				$empty_inside = true;
				break;
			}
		}
		$this->assertTrue( $empty_inside );
	}

	public function test_sparkline_exposes_aria_label_and_hides_nothing(): void {
		$weeks = array(
			array( 'status' => 'gap', 'calls' => null, 'spend' => null ),
			array( 'status' => 'data', 'calls' => 5, 'spend' => 1.5 ),
			array( 'status' => 'data', 'calls' => 7, 'spend' => 0.004 ),
		);
		$svg = Usage_Trends::sparkline_svg( $weeks, 'calls' );
		$this->assertStringContainsString( '<svg', $svg );
		$this->assertStringContainsString( 'role="img"', $svg );
		$this->assertStringContainsString( 'aria-label=', $svg );
		$this->assertStringNotContainsString( 'aria-hidden', $svg );
		$this->assertSame( '', Usage_Trends::sparkline_svg( array( array( 'status' => 'data', 'calls' => 1, 'spend' => 1.0 ) ), 'calls' ) );

		$aria = Usage_Trends::sparkline_aria_label( $weeks, 'spend', 'Estimated spend' );
		$this->assertStringContainsString( 'Estimated spend over 2 saved weeks', $aria );
		$this->assertStringContainsString( 'First: $', $aria );
		$this->assertStringContainsString( '<$0.01', $aria );
		$this->assertSame( '<$0.01', Usage_Trends::format_metric_value( 'spend', 0.004 ) );
	}

	public function test_delta_pct_helpers(): void {
		$this->assertEqualsWithDelta( 40.0, (float) Usage_Trends::delta_pct( 7, 5 ), 0.0001 );
		$this->assertNull( Usage_Trends::delta_pct( 5, 0 ) );
		$this->assertNull( Usage_Trends::delta_pct( null, 5 ) );
		$this->assertSame( '+40%', Usage_Trends::format_delta_label( 40.0 ) );
		$this->assertSame( 'About the same', Usage_Trends::format_delta_label( 0.2 ) );
		$this->assertSame( 'Not enough data', Usage_Trends::format_delta_label( null ) );
	}

	/**
	 * @param array<string,mixed> $extra
	 * @return array<string,mixed>
	 */
	private function policy( array $extra = array() ): array {
		return array_merge(
			array(
				'log_enabled'            => true,
				'log_limit'              => 200,
				'est_usd_input_per_m'    => 2.50,
				'est_usd_output_per_m'   => 10.00,
				'est_usd_provider_rates' => array(),
			),
			$extra
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	private function spend_row( string $plugin, float $usd, int $ts ): array {
		$out_tokens = (int) round( $usd * 100000 );

		return array(
			'ts'            => $ts,
			'plugin'        => $plugin,
			'decision'      => 'allow',
			'operation'     => 'generate_text',
			'provider'      => 'openai',
			'input_tokens'  => 0,
			'output_tokens' => $out_tokens,
		);
	}
}
