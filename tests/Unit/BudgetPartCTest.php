<?php
/**
 * AICAC-BUDGET-C (#168): UI helpers, hit email copy, Site Health.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Budget;
use HandL\AICAC\Plugin;
use HandL\AICAC\Site_Health;
use PHPUnit\Framework\TestCase;

final class BudgetPartCTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Budget::SPEND_OPTION_KEY );
		delete_option( Budget::FIRED_OPTION_KEY );
	}

	protected function tearDown(): void {
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Budget::SPEND_OPTION_KEY );
		delete_option( Budget::FIRED_OPTION_KEY );
		parent::tearDown();
	}

	public function test_over_budget_list_and_progress_fill(): void {
		$plugin = 'acme/acme.php';
		$policy = array(
			'plugin_budgets'       => array( $plugin => 10.0 ),
			'plugin_budget_modes'  => array( $plugin => Budget::MODE_DENY ),
		);
		$tz = new \DateTimeZone( 'UTC' );
		$ts = ( new \DateTimeImmutable( '2026-08-15 12:00:00', $tz ) )->getTimestamp();
		Budget::add_estimated_spend( $plugin, 12.0, $ts, $tz );

		$list = Budget::over_budget_list( $policy, $ts, $tz );
		$this->assertCount( 1, $list );
		$this->assertSame( $plugin, $list[0]['plugin'] );
		$this->assertSame( Budget::MODE_DENY, $list[0]['mode'] );

		$status = Budget::status( $policy, $plugin, $ts, $tz );
		$this->assertSame( 100, Budget::progress_fill_percent( $status ) );
	}

	public function test_hit_email_copy_requires_estimated(): void {
		$subject = Budget::build_hit_subject( 'acme/acme.php' );
		$body    = Budget::build_hit_body( 'acme/acme.php', 12.5, 10.0, '2026-08', Budget::MODE_OBSERVE );

		$this->assertStringContainsString( 'estimated budget', strtolower( $subject ) );
		$this->assertStringContainsString( 'Estimated budget:', $body );
		$this->assertStringContainsString( 'Current estimated spend:', $body );
		$this->assertStringContainsString( 'estimates', strtolower( $body ) );
		$this->assertStringContainsString( 'Observe-only', $body );
	}

	public function test_site_health_flags_over_budget(): void {
		$plugin = 'acme/acme.php';
		$policy = array(
			'kill_switch'         => false,
			'log_enabled'         => true,
			'audit_only'          => false,
			'plugin_budgets'      => array( $plugin => 5.0 ),
			'plugin_budget_modes' => array( $plugin => Budget::MODE_OBSERVE ),
		);
		$tz = new \DateTimeZone( 'UTC' );
		$ts = ( new \DateTimeImmutable( '2026-08-15 12:00:00', $tz ) )->getTimestamp();
		Budget::add_estimated_spend( $plugin, 5.0, $ts, $tz );

		// Freeze "now" by writing spend under current period id from wall clock —
		// status() uses time(); seed current period instead.
		$period = Budget::period_id();
		$map    = array( $period => array( $plugin => 5.0 ) );
		Budget::save_spend_map( $map );

		$installed = array(
			'ai/ai.php'            => array( 'Name' => 'AI' ),
			'example/consumer.php' => array(
				'Name'            => 'Example AI Consumer',
				'RequiresPlugins' => 'ai',
			),
		);
		$active = array(
			'ai/ai.php' => true,
		);

		$snapshot = Site_Health::build_snapshot( $policy, $installed, $active );
		$this->assertSame( 'over_budget', $snapshot['issue'] );
		$this->assertSame( 'recommended', $snapshot['status'] );
		$this->assertSame( 'rules', $snapshot['settings_tab'] );
		$this->assertSame( 1, $snapshot['over_budget_count'] );

		$result = Site_Health::format_site_health_result( $snapshot );
		$this->assertStringContainsString( 'estimated budget', strtolower( (string) $result['label'] ) );
		$this->assertStringContainsString( 'estimated budget', strtolower( strip_tags( (string) $result['description'] ) ) );
	}
}
