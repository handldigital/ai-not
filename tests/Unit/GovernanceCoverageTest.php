<?php
/**
 * AICAC-SCORE (#189): governance coverage scoring.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Drift;
use HandL\AICAC\Governance_Coverage;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

final class GovernanceCoverageTest extends TestCase {

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

	public function test_weights_sum_to_one_hundred(): void {
		$sum = Governance_Coverage::WEIGHT_EXPLICIT_RULES
			+ Governance_Coverage::WEIGHT_ALERT_EMAIL
			+ Governance_Coverage::WEIGHT_BUDGETS
			+ Governance_Coverage::WEIGHT_DRIFT
			+ Governance_Coverage::WEIGHT_RETENTION;
		$this->assertSame( 100, $sum );
	}

	public function test_empty_site_scores_partial_without_email_retention_when_drift_default_on(): void {
		// No AI activity / spend → rules + budgets N/A full points.
		// Drift defaults to provider (on). Alert email + retention off.
		$out = Governance_Coverage::compute(
			array(
				'plugins'         => array(),
				'plugin_budgets'  => array(),
				'alert_email'     => '',
				'drift_alert_mode'=> Drift::MODE_PROVIDER,
				'log_max_age_days'=> null,
			),
			array()
		);
		$this->assertSame( 75, $out['score'] ); // 40 + 0 + 20 + 15 + 0
		$by_id = $this->by_id( $out['checks'] );
		$this->assertTrue( $by_id['explicit_rules']['done'] );
		$this->assertFalse( $by_id['alert_email']['done'] );
		$this->assertTrue( $by_id['budgets']['done'] );
		$this->assertTrue( $by_id['drift']['done'] );
		$this->assertFalse( $by_id['retention']['done'] );
		$this->assertSame( 'activity', $by_id['alert_email']['tab'] );
		$this->assertSame( 'handl-aicac-alert-email', $by_id['alert_email']['anchor'] );
	}

	public function test_full_configuration_scores_one_hundred(): void {
		$policy = array(
			'plugins'              => array( 'a/a.php' => 'allow', 'b/b.php' => 'deny' ),
			'plugin_budgets'       => array( 'a/a.php' => 10.0 ),
			'alert_email'          => 'ops@example.com',
			'drift_alert_mode'     => Drift::MODE_MODEL,
			'log_max_age_days'     => 90,
			'est_usd_input_per_m'  => 0.0,
			'est_usd_output_per_m' => 10.0,
		);
		$log = array(
			$this->row( 'a/a.php', 'allow', 1.0, time() - 60 ),
			$this->row( 'b/b.php', 'deny', 0.0, time() - 30 ),
		);
		$out = Governance_Coverage::compute( $policy, $log );
		$this->assertSame( 100, $out['score'] );
		foreach ( $out['checks'] as $check ) {
			$this->assertTrue( $check['done'], $check['id'] );
		}
	}

	public function test_partial_rules_and_budgets_are_fractional(): void {
		$policy = array(
			'plugins'              => array( 'a/a.php' => 'allow' ), // b missing
			'plugin_budgets'       => array(), // a has spend, no budget
			'alert_email'          => 'ops@example.com',
			'drift_alert_mode'     => Drift::MODE_OFF,
			'log_max_age_days'     => 30,
			'est_usd_input_per_m'  => 0.0,
			'est_usd_output_per_m' => 10.0,
		);
		$log = array(
			$this->row( 'a/a.php', 'allow', 2.0, time() - 60 ),
			$this->row( 'b/b.php', 'allow', 0.0, time() - 30 ),
		);
		$out = Governance_Coverage::compute( $policy, $log );
		// rules: 1/2 * 40 = 20; email 15; budgets 0/1 * 20 = 0; drift 0; retention 10 → 45
		$this->assertSame( 45, $out['score'] );
		$by_id = $this->by_id( $out['checks'] );
		$this->assertFalse( $by_id['explicit_rules']['done'] );
		$this->assertEqualsWithDelta( 20.0, $by_id['explicit_rules']['points'], 0.0001 );
		$this->assertFalse( $by_id['budgets']['done'] );
		$this->assertFalse( $by_id['drift']['done'] );
		$this->assertSame( 'rules', $by_id['explicit_rules']['tab'] );
	}

	public function test_ignores_direct_http_for_ai_active_and_spend(): void {
		$log = array(
			array(
				'ts'       => time(),
				'plugin'   => 'shadow/s.php',
				'channel'  => 'direct_http',
				'decision' => 'observe',
				'host'     => 'api.openai.com',
			),
		);
		$this->assertSame( array(), Governance_Coverage::ai_active_plugins( $log ) );
		$this->assertSame(
			array(),
			Governance_Coverage::plugins_with_recorded_spend(
				$log,
				array(
					'est_usd_input_per_m'  => 0.0,
					'est_usd_output_per_m' => 10.0,
				)
			)
		);
	}

	public function test_sub_cent_spend_counts_as_recorded_spend(): void {
		$policy = array(
			'est_usd_input_per_m'  => 0.0,
			'est_usd_output_per_m' => 10.0,
		);
		// 1 output token @ $10/M = $0.00001
		$log = array(
			array(
				'ts'            => time(),
				'plugin'        => 'a/a.php',
				'decision'      => 'allow',
				'provider'      => 'openai',
				'input_tokens'  => 0,
				'output_tokens' => 1,
			),
		);
		$this->assertSame( array( 'a/a.php' ), Governance_Coverage::plugins_with_recorded_spend( $log, $policy ) );
	}

	/**
	 * @param list<array<string,mixed>> $checks
	 * @return array<string,array<string,mixed>>
	 */
	private function by_id( array $checks ): array {
		$out = array();
		foreach ( $checks as $c ) {
			$out[ (string) $c['id'] ] = $c;
		}
		return $out;
	}

	/**
	 * @return array<string,mixed>
	 */
	private function row( string $plugin, string $decision, float $usd, int $ts ): array {
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
