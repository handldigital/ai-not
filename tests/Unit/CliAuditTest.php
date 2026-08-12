<?php
/**
 * S-105 / #31: WP-CLI policy dump + log summary builders.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Analytics;
use HandL\AICAC\CLI_Audit;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class CliAuditTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-cli-audit.php';
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
	}

	protected function tearDown(): void {
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		parent::tearDown();
	}

	public function test_fresh_install_policy_dump_defaults(): void {
		$policy  = Policy::get_policy();
		$plugins = array(
			'acme/acme.php' => array( 'Name' => 'Acme' ),
		);
		$dump = CLI_Audit::build_policy_dump( $policy, $plugins );

		$this->assertSame( 'allow', $dump['default'] );
		$this->assertFalse( $dump['kill_switch'] );
		$this->assertSame( 0, $dump['kill_switch_exception_count'] );
		$this->assertCount( 1, $dump['plugins'] );
		$this->assertSame( 'default', $dump['plugins'][0]['rule'] );
		$this->assertSame( 'allow', $dump['plugins'][0]['effective'] );
	}

	public function test_policy_dump_reflects_rules_and_kill_switch(): void {
		$policy = array(
			'default'                => 'deny',
			'kill_switch'            => true,
			'kill_switch_exceptions' => array( 'safe/safe.php' ),
			'plugins'                => array(
				'acme/acme.php' => 'allow',
				'bad/bad.php'   => 'deny',
			),
		);
		$plugins = array(
			'acme/acme.php'  => array( 'Name' => 'Acme' ),
			'bad/bad.php'    => array( 'Name' => 'Bad' ),
			'other/other.php'=> array( 'Name' => 'Other' ),
		);
		$dump = CLI_Audit::build_policy_dump( $policy, $plugins );

		$this->assertSame( 'deny', $dump['default'] );
		$this->assertTrue( $dump['kill_switch'] );
		$this->assertSame( 1, $dump['kill_switch_exception_count'] );
		$by = array();
		foreach ( $dump['plugins'] as $row ) {
			$by[ $row['plugin'] ] = $row;
		}
		$this->assertSame( 'allow', $by['acme/acme.php']['rule'] );
		$this->assertSame( 'allow', $by['acme/acme.php']['effective'] );
		$this->assertSame( 'deny', $by['bad/bad.php']['rule'] );
		$this->assertSame( 'default', $by['other/other.php']['rule'] );
		$this->assertSame( 'deny', $by['other/other.php']['effective'] );
	}

	public function test_log_summary_uses_analytics_call_count_and_estimated_spend(): void {
		$policy = array(
			'log_enabled'          => true,
			'est_usd_input_per_m'  => 0.0,
			'est_usd_output_per_m' => 10.0,
		);
		$plugins = array(
			'a/a.php' => array( 'Name' => 'Plugin A' ),
			'b/b.php' => array( 'Name' => 'Plugin B' ),
		);
		// $1 and $2 at $10 / 1M output tokens.
		$log = array(
			array(
				'ts'            => 100,
				'plugin'        => 'a/a.php',
				'decision'      => 'allow',
				'provider'      => 'openai',
				'input_tokens'  => 0,
				'output_tokens' => 100000,
			),
			array(
				'ts'            => 101,
				'plugin'        => 'b/b.php',
				'decision'      => 'deny',
				'provider'      => 'openai',
				'input_tokens'  => 0,
				'output_tokens' => 200000,
			),
			array(
				'ts'       => 102,
				'channel'  => 'direct_http',
				'decision' => 'observe',
				'count'    => 5,
				'host'     => 'api.openai.com',
			),
		);

		$agg     = Analytics::aggregate_from_log( $log, $plugins );
		$summary = CLI_Audit::build_log_summary( $log, $policy, $plugins );

		$this->assertFalse( $summary['logging_disabled'] );
		$this->assertSame( (int) $agg['summary']['calls'], $summary['calls'] );
		$this->assertSame( 2, $summary['calls'] );
		$this->assertSame( 1, $summary['denials'] );
		$this->assertEqualsWithDelta( 3.0, (float) $summary['estimated_spend_usd'], 0.0001 );
		$this->assertCount( 2, $summary['top_plugins'] );
		$this->assertSame( 'b/b.php', $summary['top_plugins'][0]['plugin'] );
		$this->assertSame( 'Plugin B', $summary['top_plugins'][0]['name'] );
	}

	public function test_logging_disabled_reports_zeros_with_note(): void {
		$summary = CLI_Audit::build_log_summary(
			array(
				array(
					'ts'       => 1,
					'plugin'   => 'a/a.php',
					'decision' => 'allow',
				),
			),
			array(
				'log_enabled' => false,
				'audit_only'  => false,
			),
			array()
		);

		$this->assertTrue( $summary['logging_disabled'] );
		$this->assertSame( 0, $summary['calls'] );
		$this->assertSame( 0, $summary['denials'] );
		$this->assertSame( 0.0, $summary['estimated_spend_usd'] );
		$this->assertSame( array(), $summary['top_plugins'] );
		$this->assertNotEmpty( $summary['note'] );
	}
}
