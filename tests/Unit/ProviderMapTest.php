<?php
/**
 * AICAC-PROVIDER-MAP: who-talks-to-whom Insights aggregation (#158).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Provider_Map;
use HandL\AICAC\Usage_Trends;
use PHPUnit\Framework\TestCase;

final class ProviderMapTest extends TestCase {

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

	public function test_hides_when_fewer_than_seven_days_of_data(): void {
		$now = strtotime( '2026-08-12 12:00:00 UTC' );
		$log = array();
		// 6 distinct days only.
		for ( $d = 0; $d < 6; $d++ ) {
			$log[] = $this->row(
				'a/a.php',
				'openai',
				'gpt-4o',
				1_000_000,
				0,
				strtotime( '2026-08-' . sprintf( '%02d', 7 + $d ) . ' 10:00:00 UTC' )
			);
		}
		$this->assertNull( Provider_Map::compute( $log, $this->policy_with_openai_rate(), array(), $now ) );
	}

	public function test_groups_plugin_provider_model_and_share_math(): void {
		$now  = strtotime( '2026-08-14 15:00:00 UTC' );
		$log  = array();
		$base = strtotime( '2026-08-08 10:00:00 UTC' );
		// 7 days of openai (rate known): $1/day = $7 total known.
		for ( $d = 0; $d < 7; $d++ ) {
			$log[] = $this->row(
				'a/a.php',
				'openai',
				'gpt-4o',
				1_000_000,
				0,
				$base + ( $d * 86400 )
			);
		}
		// Same window: anthropic has tokens but no rate-table entry → spend unknown.
		$log[] = $this->row(
			'b/b.php',
			'anthropic',
			'claude',
			1_000_000,
			0,
			$base + ( 3 * 86400 )
		);

		$out = Provider_Map::compute(
			$log,
			$this->policy_with_openai_rate(),
			array(
				'a/a.php' => array( 'Name' => 'Plugin A' ),
				'b/b.php' => array( 'Name' => 'Plugin B' ),
			),
			$now
		);
		$this->assertNotNull( $out );
		$this->assertSame( 8, $out['totals']['calls'] );
		$this->assertEqualsWithDelta( 7.0, $out['totals']['known_spend'], 0.0001 );
		$this->assertSame( 1, $out['totals']['unknown_spend_calls'] );
		$this->assertSame( 1, $out['totals']['unknown_spend_providers'] );

		$this->assertSame( 'a/a.php', $out['plugins'][0]['plugin'] );
		$this->assertSame( 'Plugin A', $out['plugins'][0]['label'] );
		$this->assertEqualsWithDelta( 100.0, (float) $out['plugins'][0]['spend_share_pct'], 0.01 );

		$openai = $out['plugins'][0]['providers'][0];
		$this->assertSame( 'openai', $openai['provider'] );
		$this->assertSame( 'known', $openai['spend_status'] );
		$this->assertEqualsWithDelta( 100.0, (float) $openai['spend_share_pct'], 0.01 );
		$this->assertSame( 'gpt-4o', $openai['models'][0]['model'] );

		$b = $out['plugins'][1];
		$this->assertSame( 'b/b.php', $b['plugin'] );
		$this->assertSame( 'unknown', $b['providers'][0]['spend_status'] );
		$this->assertNull( $b['providers'][0]['spend_share_pct'] );
		$this->assertSame( 'Spend unknown', Provider_Map::format_spend_cell( 'unknown', null, null ) );
	}

	public function test_call_parity_with_activity_window(): void {
		$now  = strtotime( '2026-08-14 15:00:00 UTC' );
		$base = strtotime( '2026-08-08 10:00:00 UTC' );
		$log  = array();
		for ( $d = 0; $d < 7; $d++ ) {
			$log[] = $this->row( 'a/a.php', 'openai', 'gpt-4o', 500_000, 0, $base + ( $d * 86400 ) );
		}
		$log[] = array(
			'ts'       => $base + 86400,
			'plugin'   => 'a/a.php',
			'channel'  => 'direct_http',
			'decision' => 'observe',
			'count'    => 9,
		);
		$policy = $this->policy_with_openai_rate();
		$out    = Provider_Map::compute( $log, $policy, array(), $now );
		$this->assertNotNull( $out );

		$expected = Usage_Trends::count_activity_calls_in_window(
			$log,
			(int) $out['window']['start_ts'],
			(int) $out['window']['end_ts']
		);
		$this->assertSame( $expected, $out['totals']['calls'] );
	}

	public function test_known_spend_parity_when_all_providers_have_rates(): void {
		$now  = strtotime( '2026-08-14 15:00:00 UTC' );
		$base = strtotime( '2026-08-08 10:00:00 UTC' );
		$log  = array();
		for ( $d = 0; $d < 7; $d++ ) {
			$log[] = $this->row( 'a/a.php', 'openai', 'gpt-4o', 1_000_000, 0, $base + ( $d * 86400 ) );
		}
		$policy = $this->policy_with_openai_rate();
		$out    = Provider_Map::compute( $log, $policy, array(), $now );
		$this->assertNotNull( $out );

		$expected = Usage_Trends::sum_activity_spend_in_window(
			$log,
			$policy,
			(int) $out['window']['start_ts'],
			(int) $out['window']['end_ts']
		);
		$this->assertEqualsWithDelta( $expected, $out['totals']['known_spend'], 0.0001 );
	}

	public function test_ttl_gap_label_when_knowledge_truncates(): void {
		$now    = strtotime( '2026-08-20 15:00:00 UTC' );
		$policy = $this->policy_with_openai_rate( array( 'log_max_age_days' => 14 ) );
		$log    = array();
		// 7 days inside the 14-day TTL window.
		$base = strtotime( '2026-08-14 10:00:00 UTC' );
		for ( $d = 0; $d < 7; $d++ ) {
			$log[] = $this->row( 'a/a.php', 'openai', 'm', 1000, 0, $base + ( $d * 86400 ) );
		}
		$out = Provider_Map::compute( $log, $policy, array(), $now );
		$this->assertNotNull( $out );
		$this->assertSame( $now - ( 14 * 86400 ), $out['window']['knowledge_start_ts'] );
		$this->assertNotNull( $out['window']['gap_label'] );
		$this->assertStringContainsString( 'Older activity is not available', (string) $out['window']['gap_label'] );
	}

	public function test_share_pct_helpers(): void {
		$this->assertEqualsWithDelta( 25.0, (float) Provider_Map::share_pct( 1.0, 4.0 ), 0.001 );
		$this->assertNull( Provider_Map::share_pct( null, 4.0 ) );
		$this->assertNull( Provider_Map::share_pct( 1.0, 0.0 ) );
		$this->assertTrue( Provider_Map::provider_has_rate_table_entry( 'openai', array( 'openai' => array( 'input_per_m' => 1.0, 'output_per_m' => 2.0 ) ) ) );
		$this->assertFalse( Provider_Map::provider_has_rate_table_entry( 'anthropic', array( 'openai' => array( 'input_per_m' => 1.0, 'output_per_m' => 2.0 ) ) ) );
	}

	/**
	 * @param array<string,mixed> $extra
	 * @return array<string,mixed>
	 */
	private function policy_with_openai_rate( array $extra = array() ): array {
		return array_merge(
			array(
				'log_enabled'            => true,
				'log_limit'              => 200,
				'est_usd_input_per_m'    => 2.50,
				'est_usd_output_per_m'   => 10.00,
				'est_usd_provider_rates' => array(
					'openai' => array(
						'input_per_m'  => 1.0,
						'output_per_m' => 2.0,
					),
				),
			),
			$extra
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	private function row( string $plugin, string $provider, string $model, int $in, int $out, int $ts ): array {
		return array(
			'ts'            => $ts,
			'plugin'        => $plugin,
			'provider'      => $provider,
			'model'         => $model,
			'input_tokens'  => $in,
			'output_tokens' => $out,
			'decision'      => 'allow',
			'channel'       => 'ai_client',
		);
	}
}
