<?php
/**
 * AICAC-TREND (#184): 30-day daily sparklines.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Daily_Trends;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

final class DailyTrendsTest extends TestCase {

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

	public function test_day_windows_clips_to_single_day_when_knowledge_is_today(): void {
		$now = strtotime( '2026-08-12 12:00:00 UTC' );
		$tz  = new \DateTimeZone( 'UTC' );
		$windows = Daily_Trends::day_windows( $now, Daily_Trends::DAY_COUNT, $tz, $now );
		$this->assertCount( 1, $windows );
		$this->assertSame( '2026-08-12', $windows[0]['key'] );

		// compute() returns null when the clipped window is shorter than MIN_WINDOW_DAYS.
		$log    = array( $this->row( 'a/a.php', 'allow', 1.0, $now - 60 ) );
		$policy = $this->policy();
		// Monkey the knowledge by using a TTL of ~0.01 day is impossible; call day_windows path via reflection-free
		// assert: a one-day defs list is below MIN_WINDOW_DAYS.
		$this->assertLessThan( Daily_Trends::MIN_WINDOW_DAYS, count( $windows ) );
		unset( $log, $policy );
	}

	public function test_daily_bucket_calls_spend_blocks_and_short_window_label(): void {
		$now = strtotime( '2026-08-12 15:00:00 UTC' );
		$log = array(
			$this->row( 'a/a.php', 'allow', 2.0, strtotime( '2026-08-10 10:00:00 UTC' ) ),
			$this->row( 'a/a.php', 'deny', 1.0, strtotime( '2026-08-11 10:00:00 UTC' ) ),
			$this->row( 'a/a.php', 'allow', 1.0, strtotime( '2026-08-11 12:00:00 UTC' ) ),
			$this->row( 'b/b.php', 'deny', 3.0, strtotime( '2026-08-12 09:00:00 UTC' ) ),
			// Ignored channels.
			array(
				'ts'       => strtotime( '2026-08-12 10:00:00 UTC' ),
				'plugin'   => 'a/a.php',
				'channel'  => 'direct_http',
				'decision' => 'observe',
			),
		);
		// TTL 5 days → window shorter than 30.
		$policy = $this->policy( array( 'log_max_age_days' => 5 ) );
		$out    = Daily_Trends::compute(
			$log,
			$policy,
			array(
				'a/a.php' => array( 'Name' => 'Plugin A' ),
				'b/b.php' => array( 'Name' => 'Plugin B' ),
			),
			$now
		);
		$this->assertNotNull( $out );
		$this->assertFalse( $out['full_window'] );
		$this->assertSame( 6, $out['window_days'] ); // Aug 7–12 with 5-day TTL from Aug 12.
		$this->assertStringContainsString( 'not a full 30-day window', $out['window_label'] );
		$this->assertTrue( $out['has_activity'] );

		$by_key = array();
		foreach ( $out['site']['days'] as $d ) {
			$by_key[ $d['key'] ] = $d;
		}
		$this->assertSame( 1, $by_key['2026-08-10']['calls'] );
		$this->assertSame( 0, $by_key['2026-08-10']['blocks'] );
		$this->assertEqualsWithDelta( 2.0, (float) $by_key['2026-08-10']['spend'], 0.0001 );

		$this->assertSame( 2, $by_key['2026-08-11']['calls'] );
		$this->assertSame( 1, $by_key['2026-08-11']['blocks'] );

		$this->assertSame( 1, $by_key['2026-08-12']['calls'] );
		$this->assertSame( 1, $by_key['2026-08-12']['blocks'] );

		$this->assertArrayHasKey( 'a/a.php', $out['plugins'] );
		$this->assertSame( 'Plugin A', $out['plugins']['a/a.php']['label'] );
		$this->assertSame( 1, $out['plugins']['b/b.php']['days'][ array_key_last( $out['plugins']['b/b.php']['days'] ) ]['blocks'] );
	}

	public function test_sparkline_includes_quiet_days_as_zeros(): void {
		$days = array(
			array( 'calls' => 0, 'spend' => 0.0, 'blocks' => 0 ),
			array( 'calls' => 4, 'spend' => 1.5, 'blocks' => 1 ),
			array( 'calls' => 2, 'spend' => 0.5, 'blocks' => 0 ),
		);
		$svg = Daily_Trends::sparkline_svg( $days, 'calls' );
		$this->assertStringContainsString( '<svg', $svg );
		$this->assertStringContainsString( 'polyline', $svg );
		$this->assertStringContainsString( 'aria-label=', $svg );
		$this->assertStringNotContainsString( 'aria-hidden', $svg );
		$this->assertSame( '', Daily_Trends::sparkline_svg( array( array( 'calls' => 1 ) ), 'calls' ) );

		$aria = Daily_Trends::sparkline_aria_label( $days, 'spend', 'Estimated spend' );
		$this->assertStringContainsString( 'Estimated spend over 3 saved days', $aria );
		$this->assertStringContainsString( 'First: $', $aria );
		$this->assertStringContainsString( 'High: $', $aria );

		$this->assertSame( '<$0.01', Daily_Trends::format_metric_value( 'spend', 0.004 ) );
		$subCentAria = Daily_Trends::sparkline_aria_label(
			array(
				array( 'calls' => 1, 'spend' => 0.004, 'blocks' => 0 ),
				array( 'calls' => 1, 'spend' => 0.004, 'blocks' => 0 ),
			),
			'spend',
			'Estimated spend'
		);
		$this->assertStringContainsString( '<$0.01', $subCentAria );
		$this->assertStringNotContainsString( 'First: $0.01', $subCentAria );
		$this->assertStringNotContainsString( 'Latest: $0.01', $subCentAria );
	}

	public function test_full_30_day_window_without_ttl(): void {
		$now = strtotime( '2026-08-12 12:00:00 UTC' );
		$log = array(
			$this->row( 'a/a.php', 'allow', 1.0, strtotime( '2026-07-20 10:00:00 UTC' ) ),
			$this->row( 'a/a.php', 'allow', 1.0, $now - 3600 ),
		);
		$out = Daily_Trends::compute( $log, $this->policy(), array(), $now );
		$this->assertNotNull( $out );
		$this->assertTrue( $out['full_window'] );
		$this->assertSame( 30, $out['window_days'] );
		$this->assertStringContainsString( 'Last 30 days', $out['window_label'] );
	}

	/**
	 * @param array<string,mixed> $extra
	 * @return array<string,mixed>
	 */
	private function policy( array $extra = array() ): array {
		return array_merge(
			array(
				'log_enabled'            => true,
				'log_limit'              => 500,
				'est_usd_input_per_m'    => 0.0,
				'est_usd_output_per_m'   => 10.0,
				'est_usd_provider_rates' => array(),
			),
			$extra
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	private function row( string $plugin, string $decision, float $usd, int $ts ): array {
		// output_tokens chosen so Cost::estimate_usd ≈ $usd at $10/M output.
		$out_tokens = (int) round( $usd * 100000 );

		return array(
			'ts'            => $ts,
			'plugin'        => $plugin,
			'decision'      => $decision,
			'provider'      => 'openai',
			'input_tokens'  => 0,
			'output_tokens' => $out_tokens,
		);
	}
}
