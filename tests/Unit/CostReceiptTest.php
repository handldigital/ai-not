<?php
/**
 * AICAC-COST-RECEIPT: calendar-month estimated spend (#263).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Cost_Receipt;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

final class CostReceiptTest extends TestCase {

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

	public function test_bundled_model_rates_current_and_previous_month(): void {
		$now = strtotime( '2026-09-15 12:00:00 UTC' );
		$log = array(
			$this->row( 'a/a.php', 'openai', 'gpt-4o-mini', 1_000_000, 0, strtotime( '2026-09-10 10:00:00 UTC' ) ),
			$this->row( 'a/a.php', 'openai', 'gpt-4o-mini', 1_000_000, 0, strtotime( '2026-08-20 10:00:00 UTC' ) ),
			$this->row( 'b/b.php', 'openai', 'gpt-4o-mini', 2_000_000, 0, strtotime( '2026-09-05 10:00:00 UTC' ) ),
		);

		$out = Cost_Receipt::compute(
			$log,
			array(),
			array(
				'a/a.php' => array( 'Name' => 'Plugin A' ),
				'b/b.php' => array( 'Name' => 'Plugin B' ),
			),
			$now
		);

		$this->assertSame( '2026-09', $out['current_ym'] );
		$this->assertSame( '2026-08', $out['previous_ym'] );
		// gpt-4o-mini bundled input 0.15 / 1M → Sep: A=$0.15 + B=$0.30 = $0.45; Aug A=$0.15.
		$this->assertEqualsWithDelta( 0.45, $out['totals']['current'], 0.0001 );
		$this->assertEqualsWithDelta( 0.15, $out['totals']['previous'], 0.0001 );
		$this->assertSame( 2, $out['totals']['current_plugins'] );
		$this->assertSame( 'b/b.php', $out['top_current']['plugin'] );
		$this->assertSame( 'Plugin B', $out['top_current']['label'] );
		$this->assertEqualsWithDelta( 0.30, $out['top_current']['usd'], 0.0001 );
		$this->assertSame( 'Plugin B', $out['plugins'][0]['label'] );
	}

	public function test_unknown_model_is_na_never_zero_and_excluded_from_totals(): void {
		$now = strtotime( '2026-09-15 12:00:00 UTC' );
		$log = array(
			$this->row( 'a/a.php', 'openai', 'gpt-4o-mini', 1_000_000, 0, strtotime( '2026-09-10 10:00:00 UTC' ) ),
			$this->row( 'a/a.php', 'mystery-co', 'totally-unknown-model', 1_000_000, 0, strtotime( '2026-09-11 10:00:00 UTC' ) ),
			$this->row( 'c/c.php', 'mystery-co', 'totally-unknown-model', 5_000_000, 0, strtotime( '2026-09-12 10:00:00 UTC' ) ),
		);

		$out = Cost_Receipt::compute( $log, array(), array(), $now );

		$this->assertEqualsWithDelta( 0.15, $out['totals']['current'], 0.0001 );
		$this->assertSame( 2, $out['totals']['current_na_calls'] );

		$by_plugin = array();
		foreach ( $out['plugins'] as $row ) {
			$by_plugin[ $row['plugin'] ] = $row;
		}
		$this->assertEqualsWithDelta( 0.15, (float) $by_plugin['a/a.php']['current'], 0.0001 );
		$this->assertSame( 1, $by_plugin['a/a.php']['current_na_calls'] );
		$this->assertNull( $by_plugin['c/c.php']['current'] );
		$this->assertSame( 1, $by_plugin['c/c.php']['current_na_calls'] );
	}

	public function test_model_override_changes_totals_immediately(): void {
		$now = strtotime( '2026-09-15 12:00:00 UTC' );
		$log = array(
			$this->row( 'a/a.php', 'openai', 'gpt-4o-mini', 1_000_000, 0, strtotime( '2026-09-10 10:00:00 UTC' ) ),
		);

		$base = Cost_Receipt::compute( $log, array(), array(), $now );
		$this->assertEqualsWithDelta( 0.15, $base['totals']['current'], 0.0001 );

		$overridden = Cost_Receipt::compute(
			$log,
			array(
				'est_usd_model_rates' => array(
					'gpt-4o-mini' => array(
						'input_per_m'  => 10.0,
						'output_per_m' => 0.0,
					),
				),
			),
			array(),
			$now
		);
		$this->assertEqualsWithDelta( 10.0, $overridden['totals']['current'], 0.0001 );
	}

	public function test_provider_bundled_fallback_when_model_unknown(): void {
		$now = strtotime( '2026-09-15 12:00:00 UTC' );
		$log = array(
			$this->row( 'a/a.php', 'openai', 'custom-finetune-xyz', 1_000_000, 0, strtotime( '2026-09-10 10:00:00 UTC' ) ),
		);

		$out = Cost_Receipt::compute( $log, array(), array(), $now );
		// Bundled openai input 2.50 / 1M.
		$this->assertEqualsWithDelta( 2.50, $out['totals']['current'], 0.0001 );
		$this->assertSame( 0, $out['totals']['current_na_calls'] );
	}

	public function test_skips_direct_http_and_non_token_rows(): void {
		$now = strtotime( '2026-09-15 12:00:00 UTC' );
		$log = array(
			array(
				'ts'       => strtotime( '2026-09-10 10:00:00 UTC' ),
				'plugin'   => 'a/a.php',
				'channel'  => 'direct_http',
				'decision' => 'observe',
				'provider' => 'openai',
				'model'    => 'gpt-4o-mini',
				'input_tokens'  => 1_000_000,
				'output_tokens' => 0,
			),
			array(
				'ts'       => strtotime( '2026-09-10 11:00:00 UTC' ),
				'plugin'   => 'a/a.php',
				'decision' => 'allow',
				'provider' => 'openai',
				'model'    => 'gpt-4o-mini',
				// no tokens
			),
			$this->row( 'a/a.php', 'openai', 'gpt-4o-mini', 1_000_000, 0, strtotime( '2026-09-10 12:00:00 UTC' ) ),
		);

		$out = Cost_Receipt::compute( $log, array(), array(), $now );
		$this->assertEqualsWithDelta( 0.15, $out['totals']['current'], 0.0001 );
		$this->assertSame( 1, $out['plugins'][0]['current_calls'] );
	}

	public function test_sanitize_model_rates_drops_blank_pairs(): void {
		$out = Cost_Receipt::sanitize_model_rates(
			array(
				'gpt-4o-mini' => array( 'input' => '', 'output' => '' ),
				'gpt-4o'      => array( 'input' => '1.25', 'output' => '5' ),
				''            => array( 'input' => 1, 'output' => 2 ),
			)
		);
		$this->assertArrayNotHasKey( 'gpt-4o-mini', $out );
		$this->assertEqualsWithDelta( 1.25, $out['gpt-4o']['input_per_m'], 0.0001 );
		$this->assertEqualsWithDelta( 5.0, $out['gpt-4o']['output_per_m'], 0.0001 );
	}

	public function test_normalize_model_id_strips_vendor_prefix(): void {
		$this->assertSame( 'claude-3-5-sonnet', Cost_Receipt::normalize_model_id( 'Anthropic/claude-3-5-sonnet' ) );
		$this->assertSame( 'gpt-4o', Cost_Receipt::normalize_model_id( 'openai/gpt-4o' ) );
	}

	/**
	 * @return array<string,mixed>
	 */
	private function row( string $plugin, string $provider, string $model, int $in, int $out, int $ts ): array {
		return array(
			'ts'            => $ts,
			'plugin'        => $plugin,
			'decision'      => 'allow',
			'provider'      => $provider,
			'model'         => $model,
			'input_tokens'  => $in,
			'output_tokens' => $out,
			'count'         => 1,
		);
	}
}
