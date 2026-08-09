<?php
/**
 * Unit tests for Cost rate resolution (AICAC-24).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Cost;
use PHPUnit\Framework\TestCase;

final class CostProviderRatesTest extends TestCase {

	public function test_no_provider_config_uses_global_fallback(): void {
		$policy = array(
			'est_usd_input_per_m'  => 1.25,
			'est_usd_output_per_m' => 5.00,
		);

		$rates = Cost::rates_from_policy( $policy, 'openai' );
		$this->assertSame( 1.25, $rates['input_per_m'] );
		$this->assertSame( 5.00, $rates['output_per_m'] );
		$this->assertFalse( Cost::using_default_rates( $policy ) );
	}

	public function test_empty_policy_uses_built_in_defaults(): void {
		$rates = Cost::rates_from_policy( array(), null );
		$this->assertSame( Cost::DEFAULT_INPUT_PER_M, $rates['input_per_m'] );
		$this->assertSame( Cost::DEFAULT_OUTPUT_PER_M, $rates['output_per_m'] );
		$this->assertTrue( Cost::using_default_rates( array() ) );
	}

	public function test_one_provider_override_does_not_affect_others(): void {
		$policy = array(
			'est_usd_input_per_m'     => 2.50,
			'est_usd_output_per_m'    => 10.00,
			'est_usd_provider_rates'  => array(
				'anthropic' => array(
					'input_per_m'  => 3.00,
					'output_per_m' => 15.00,
				),
			),
		);

		$anth = Cost::rates_from_policy( $policy, 'anthropic' );
		$this->assertSame( 3.00, $anth['input_per_m'] );
		$this->assertSame( 15.00, $anth['output_per_m'] );

		$openai = Cost::rates_from_policy( $policy, 'openai' );
		$this->assertSame( 2.50, $openai['input_per_m'] );
		$this->assertSame( 10.00, $openai['output_per_m'] );

		$this->assertFalse( Cost::using_default_rates( $policy ) );
	}

	public function test_unknown_or_missing_provider_uses_fallback(): void {
		$policy = array(
			'est_usd_input_per_m'    => 4.00,
			'est_usd_output_per_m'   => 8.00,
			'est_usd_provider_rates' => array(
				'openai' => array(
					'input_per_m'  => 1.00,
					'output_per_m' => 2.00,
				),
			),
		);

		$unknown = Cost::rates_from_policy( $policy, 'not-a-real-provider' );
		$this->assertSame( 4.00, $unknown['input_per_m'] );
		$this->assertSame( 8.00, $unknown['output_per_m'] );

		$missing = Cost::rates_from_policy( $policy, '' );
		$this->assertSame( 4.00, $missing['input_per_m'] );
		$this->assertSame( 8.00, $missing['output_per_m'] );

		$null = Cost::rates_from_policy( $policy, null );
		$this->assertSame( 4.00, $null['input_per_m'] );
		$this->assertSame( 8.00, $null['output_per_m'] );
	}

	public function test_sanitize_provider_rates_clamps_and_drops_unknown(): void {
		$raw = array(
			'openai'   => array(
				'input'  => -5,
				'output' => 20000,
			),
			'bogus'    => array(
				'input'  => 1,
				'output' => 2,
			),
			'anthropic'=> array(
				'input'  => '',
				'output' => '',
			),
		);

		$clean = Cost::sanitize_provider_rates( $raw );
		$this->assertArrayHasKey( 'openai', $clean );
		$this->assertSame( 0.0, $clean['openai']['input_per_m'] );
		$this->assertSame( 10000.0, $clean['openai']['output_per_m'] );
		$this->assertArrayNotHasKey( 'bogus', $clean );
		$this->assertArrayNotHasKey( 'anthropic', $clean );
	}

	public function test_estimate_usd_uses_resolved_rates(): void {
		$rates = array(
			'input_per_m'  => 1.00,
			'output_per_m' => 2.00,
		);
		// 1M in + 1M out = $3.
		$this->assertSame( 3.0, Cost::estimate_usd( 1_000_000, 1_000_000, $rates ) );
	}

	public function test_post_style_keys_accepted_by_sanitizer(): void {
		$clean = Cost::sanitize_provider_rates(
			array(
				'groq' => array(
					'input'  => '7.5',
					'output' => '9.25',
				),
			)
		);
		$this->assertSame( 7.5, $clean['groq']['input_per_m'] );
		$this->assertSame( 9.25, $clean['groq']['output_per_m'] );
	}
}
