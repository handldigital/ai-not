<?php
/**
 * Unit tests for WP Dashboard governance widget (AICAC-WIDGET / #110).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Dashboard_Widget;
use HandL\AICAC\Plugin;
use HandL\AICAC\Rest;
use PHPUnit\Framework\TestCase;

final class DashboardWidgetTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['handl_aicac_test_options']    = array();
		$GLOBALS['handl_aicac_test_transients'] = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		unset( $GLOBALS['handl_aicac_test_added_actions'] );
	}

	public function test_register_hooks_dashboard_setup_only_for_manage_options(): void {
		$widget = Dashboard_Widget::instance();
		$widget->init();
		$this->assertContains( 'wp_dashboard_setup', $GLOBALS['handl_aicac_test_added_actions'] ?? array() );

		$GLOBALS['handl_aicac_test_current_user_can'] = false;
		$before = $GLOBALS['handl_aicac_test_added_actions'] ?? array();
		// register() itself must no-op without capability (no fatal).
		$widget->register();
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_added_actions'] ?? array() );
	}

	public function test_build_snapshot_matches_rest_1d_window_counts(): void {
		$now = 1_700_000_000;
		$log = array(
			array(
				'ts'            => $now - 100,
				'decision'      => 'allow',
				'plugin'        => 'acme/acme.php',
				'provider'      => 'openai',
				'input_tokens'  => 1_000_000,
				'output_tokens' => 0,
			),
			array(
				'ts'       => $now - 50,
				'decision' => 'deny',
				'plugin'   => 'acme/acme.php',
			),
			array(
				'ts'       => $now - 40,
				'decision' => 'allow',
				'plugin'   => 'other/other.php',
			),
			array(
				'ts'       => $now - 30,
				'channel'  => 'direct_http',
				'decision' => 'deny',
				'count'    => 2,
				'plugin'   => 'shadow/shadow.php',
			),
			array(
				'ts'       => $now - 20,
				'channel'  => 'direct_http',
				'decision' => 'observe',
				'count'    => 1,
				'plugin'   => 'shadow/shadow.php',
			),
			// Outside 1d window — must not count.
			array(
				'ts'       => $now - 200_000,
				'decision' => 'deny',
				'plugin'   => 'old/old.php',
			),
		);
		$policy = array(
			'log_enabled'         => true,
			'est_usd_input_per_m' => 2.50,
			'est_usd_output_per_m'=> 10.00,
		);

		$rest = Rest::build_activity_summary( $policy, $log, '1d', $now );
		$snap = Dashboard_Widget::build_snapshot( $policy, $log, $now );

		$this->assertSame( $rest['status'], $snap['activity']['status'] );
		$this->assertSame( $rest['ai_client_call_count'], $snap['activity']['ai_client_call_count'] );
		$this->assertSame( $rest['calls_by_decision'], $snap['activity']['calls_by_decision'] );
		$this->assertSame( 2, $snap['activity']['shadow_ai_block_count'] );
		$this->assertSame( 3, $snap['activity']['shadow_ai_observation_count'] );

		// Top by calls: acme=2, other=1.
		$this->assertCount( 2, $snap['top'] );
		$this->assertSame( 'acme/acme.php', $snap['top'][0]['plugin'] );
		$this->assertSame( 2, $snap['top'][0]['calls'] );
		$this->assertSame( 'other/other.php', $snap['top'][1]['plugin'] );
	}

	public function test_render_html_shows_emergency_stop_copy_and_review_link(): void {
		$policy = array(
			'audit_only'  => false,
			'kill_switch' => true,
			'log_enabled' => true,
		);
		$snapshot = array(
			'activity' => array( 'status' => 'no_data' ),
			'top'      => array(),
		);

		ob_start();
		Dashboard_Widget::render_html( $snapshot, $policy );
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'Emergency stop is on. All AI Client calls are blocked except listed plugins.', $html );
		$this->assertStringContainsString( 'Review policy', $html );
		$this->assertStringContainsString( 'handl_aicac_tab=rules', $html );
		$this->assertStringContainsString( 'Enforce', $html );
	}

	public function test_get_snapshot_uses_transient_cache(): void {
		$now = 1_700_000_000;
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
			)
		);
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => $now - 10,
					'decision' => 'allow',
					'plugin'   => 'acme/acme.php',
				),
			)
		);

		// Seed empty retained path via direct log option; get_retained_log reads it.
		$first = Dashboard_Widget::get_snapshot( array( 'log_enabled' => true ), $now );
		$this->assertFalse( $first['cached'] );
		$this->assertArrayHasKey( Dashboard_Widget::CACHE_KEY, $GLOBALS['handl_aicac_test_transients'] );

		$second = Dashboard_Widget::get_snapshot( array( 'log_enabled' => true ), $now );
		$this->assertTrue( $second['cached'] );

		Dashboard_Widget::bust_cache();
		$this->assertArrayNotHasKey( Dashboard_Widget::CACHE_KEY, $GLOBALS['handl_aicac_test_transients'] );
	}
}
