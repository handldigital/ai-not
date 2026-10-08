<?php
/**
 * AICAC-WHY-INSIGHTS (#322).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Admin;
use HandL\AICAC\Plugin;
use HandL\AICAC\Weekly_Report;
use HandL\AICAC\Why;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class WhyInsightsTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options'] = array();
		delete_option( Plugin::OPTION_KEY );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
				'log_limit'   => 200,
			),
			false
		);
	}

	/**
	 * Fixture: budget 3, rate-cap 2, freeze 1, legacy 1 denies + allow rows.
	 *
	 * @return list<array<string,mixed>>
	 */
	private function fixture_log(): array {
		return array(
			array(
				'ts'              => 10,
				'decision'        => 'deny',
				'plugin'          => 'a/a.php',
				'decision_source' => 'budget:hard',
			),
			array(
				'ts'              => 11,
				'decision'        => 'deny',
				'plugin'          => 'a/a.php',
				'decision_source' => 'budget:hard',
			),
			array(
				'ts'              => 12,
				'decision'        => 'deny',
				'plugin'          => 'a/a.php',
				'decision_source' => 'budget:observe',
			),
			array(
				'ts'              => 20,
				'decision'        => 'deny',
				'plugin'          => 'b/b.php',
				'decision_source' => 'rate_cap:hourly',
			),
			array(
				'ts'              => 21,
				'decision'        => 'deny',
				'plugin'          => 'b/b.php',
				'decision_source' => 'rate_cap:daily',
			),
			array(
				'ts'              => 30,
				'decision'        => 'deny',
				'plugin'          => 'c/c.php',
				'decision_source' => 'freeze',
			),
			array(
				'ts'       => 40,
				'decision' => 'deny',
				'plugin'   => 'd/d.php',
			),
			array(
				'ts'              => 50,
				'decision'        => 'allow',
				'plugin'          => 'e/e.php',
				'decision_source' => 'budget:observe',
			),
			array(
				'ts'              => 51,
				'decision'        => 'allow',
				'plugin'          => 'e/e.php',
				'decision_source' => 'default:allow',
			),
		);
	}

	public function test_aggregate_orders_fixture_and_excludes_allows(): void {
		$rows = Why::aggregate_deny_reasons( $this->fixture_log() );
		$this->assertSame(
			array( 'budget', 'rate_cap', 'freeze', Why::FILTER_NONE ),
			array_column( $rows, 'bucket' )
		);
		$this->assertSame( array( 3, 2, 1, 1 ), array_column( $rows, 'count' ) );
		$this->assertSame(
			array( 'Budget', 'Rate cap', 'Freeze', 'No explanation recorded' ),
			array_column( $rows, 'label' )
		);
	}

	public function test_empty_log_has_no_rows_and_no_top(): void {
		$this->assertSame( array(), Why::aggregate_deny_reasons( array() ) );
		$this->assertNull( Why::top_deny_reason( array() ) );
		$this->assertSame( '', Why::top_deny_reason_report_line( array() ) );
	}

	public function test_activity_url_includes_source_and_deny(): void {
		$url = Why::activity_url_for_source( 'budget' );
		$this->assertStringContainsString( 'handl_aicac_log_source=budget', $url );
		$this->assertStringContainsString( 'handl_aicac_log_decision=deny', $url );
		$this->assertStringContainsString( 'handl-aicac-log-wrap', $url );
	}

	public function test_insights_card_renders_ordered_links_and_empty_state(): void {
		$admin = Admin::instance();
		$ref   = new ReflectionClass( $admin );
		$method = $ref->getMethod( 'render_insights_top_block_reasons' );
		$method->setAccessible( true );

		ob_start();
		$method->invoke( $admin, $this->fixture_log() );
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'Top block reasons', $html );
		$this->assertStringContainsString( 'Budget', $html );
		$this->assertStringContainsString( 'Rate cap', $html );
		$this->assertStringContainsString( 'Freeze', $html );
		$this->assertStringContainsString( 'No explanation recorded', $html );
		$this->assertStringContainsString( 'handl_aicac_log_source=budget', $html );
		$this->assertStringNotContainsString( 'Site default', $html );

		$budget_pos = strpos( $html, 'Budget' );
		$rate_pos   = strpos( $html, 'Rate cap' );
		$freeze_pos = strpos( $html, 'Freeze' );
		$legacy_pos = strpos( $html, 'No explanation recorded' );
		$this->assertNotFalse( $budget_pos );
		$this->assertNotFalse( $rate_pos );
		$this->assertNotFalse( $freeze_pos );
		$this->assertNotFalse( $legacy_pos );
		$this->assertLessThan( $rate_pos, $budget_pos );
		$this->assertLessThan( $freeze_pos, $rate_pos );
		$this->assertLessThan( $legacy_pos, $freeze_pos );

		ob_start();
		$method->invoke( $admin, array() );
		$empty = (string) ob_get_clean();
		$this->assertStringContainsString( 'No blocked calls in the saved log yet.', $empty );
		$this->assertStringNotContainsString( 'NaN', $empty );
		$this->assertStringNotContainsString( 'INF', $empty );
	}

	public function test_weekly_report_includes_top_reason_only_when_denies_exist(): void {
		$line = Why::top_deny_reason_report_line( $this->fixture_log() );
		$this->assertStringContainsString( 'Budget', $line );
		$this->assertStringContainsString( 'Top block reason:', $line );
		$this->assertSame( '', Why::top_deny_reason_report_line( array() ) );

		$base = array(
			'coverage'             => array(
				'D'          => 0,
				'M'          => 0,
				'N'          => 0,
				'A'          => 0,
				'U'          => 0,
				'log_limit'  => 200,
				'span_label' => '—',
				'saturated'  => false,
			),
			'deny_n'               => 7,
			'est_any'              => false,
			'est_total'            => 0.0,
			'top_plugins'          => array(),
			'has_pins'             => false,
			'pin'                  => array(),
			'unforced'             => 0,
			'using_default_rates'  => true,
			'top_deny_reason_line' => $line,
			'window_label'         => 'test window',
		);

		$body = Weekly_Report::build_body( $base, array() );
		$this->assertStringContainsString( 'Top block reason: Budget', $body );

		$base['top_deny_reason_line'] = '';
		$base['deny_n']               = 0;
		$body_empty                   = Weekly_Report::build_body( $base, array() );
		$this->assertStringNotContainsString( 'Top block reason:', $body_empty );
	}
}
