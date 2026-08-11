<?php
/**
 * Unit tests for printable audit evidence report (AICAC-EVIDENCE / #118).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Audit_Evidence;
use HandL\AICAC\Operations;
use HandL\AICAC\Rest;
use PHPUnit\Framework\TestCase;

final class AuditEvidenceTest extends TestCase {

	public function test_build_report_data_uses_rest_activity_summary(): void {
		$now    = 1_700_000_000;
		$policy = array(
			'default'       => 'deny',
			'log_enabled'   => true,
			'plugins'       => array( 'trusted/plugin.php' => 'allow' ),
			'operations'    => array(
				'trusted/plugin.php' => array( Operations::FAMILY_TEXT => 'deny' ),
			),
			'denied_tools'  => array( 'my-tool' ),
			'kill_switch'   => false,
			'audit_only'    => false,
		);
		$log = array(
			array(
				'ts'                 => $now - 3600,
				'decision'           => 'allow',
				'plugin'             => 'trusted/plugin.php',
				'operation'          => 'generate_text',
				'capability_family'  => Operations::FAMILY_TEXT,
				'input_tokens'       => 100,
				'output_tokens'      => 50,
			),
			array(
				'ts'       => $now - 1800,
				'decision' => 'deny',
				'plugin'   => 'other/plugin.php',
				'operation'=> 'generate_text',
				'capability_family' => Operations::FAMILY_TEXT,
			),
		);
		$plugins = array(
			'trusted/plugin.php' => array( 'Name' => 'Trusted Plugin' ),
		);

		$data = Audit_Evidence::build_report_data( $policy, $log, '7d', $now, $plugins );

		$this->assertSame( '7d', $data['meta']['window'] );
		$this->assertSame( 'ok', $data['activity']['status'] );
		$this->assertSame( 2, $data['activity']['ai_client_call_count'] );
		$this->assertArrayHasKey( 'deny', $data['activity']['calls_by_decision'] );
		$this->assertNotEmpty( $data['family_counts'] );
		$this->assertCount( 1, $data['plugin_rules'] );
		$this->assertSame( 'Trusted Plugin', $data['plugin_rules'][0]['label'] );
		$this->assertFalse( $data['change_history']['available'] );
	}

	public function test_family_counts_skip_direct_http_rows(): void {
		$now = 1_700_000_000;
		$log = array(
			array(
				'ts'       => $now,
				'channel'  => 'direct_http',
				'decision' => 'observe',
				'count'    => 5,
			),
			array(
				'ts'                => $now,
				'decision'          => 'allow',
				'operation'         => 'generate_image',
				'capability_family' => Operations::FAMILY_IMAGE,
			),
		);

		$counts = Audit_Evidence::family_counts_from_rows( $log );
		$this->assertCount( 1, $counts );
		$this->assertSame( Operations::FAMILY_IMAGE, $counts[0]['family'] );
		$this->assertSame( 1, $counts[0]['calls'] );
	}

	public function test_build_html_is_self_contained_with_print_styles(): void {
		$policy = array(
			'default'     => 'allow',
			'log_enabled' => true,
			'plugins'     => array(),
		);
		$data = Audit_Evidence::build_report_data( $policy, array(), '7d', 1_700_000_000, array() );
		$html = Audit_Evidence::build_html( $data );

		$this->assertStringContainsString( '<!DOCTYPE html>', $html );
		$this->assertStringContainsString( '@media print', $html );
		$this->assertStringContainsString( 'page-break', $html );
		$this->assertStringContainsString( 'Policy snapshot', $html );
		$this->assertStringContainsString( 'Policy change history is not available in this report.', $html );
		$this->assertStringContainsString( 'Download CSV', $html );
		$this->assertDoesNotMatchRegularExpression( '/<link[^>]+stylesheet/i', $html );
		$this->assertDoesNotMatchRegularExpression( '/<script[^>]+src=/i', $html );
	}

	public function test_logging_disabled_activity_status_propagates(): void {
		$policy = array(
			'default'     => 'allow',
			'log_enabled' => false,
			'audit_only'  => false,
		);
		$data = Audit_Evidence::build_report_data( $policy, array(), '7d', 1_700_000_000, array() );
		$this->assertSame( 'logging_disabled', $data['activity']['status'] );

		$html = Audit_Evidence::build_html( $data );
		$this->assertStringContainsString( 'Activity logging and Learn mode are both off', $html );
	}

	public function test_threshold_snapshot_marks_crossed_site_threshold(): void {
		$summary = Rest::build_activity_summary(
			array(
				'log_enabled'          => true,
				'spend_threshold_site' => 10.0,
			),
			array(
				array(
					'ts'            => time(),
					'decision'      => 'allow',
					'plugin'        => 'a/a.php',
					'input_tokens'  => 5_000_000,
					'output_tokens' => 0,
				),
			),
			'7d',
			time()
		);

		$rows = Audit_Evidence::threshold_snapshot(
			array( 'spend_threshold_site' => 10.0 ),
			$summary
		);
		$this->assertNotEmpty( $rows );
		$this->assertTrue( $rows[0]['crossed'] );
	}
}
