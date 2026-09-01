<?php
/**
 * AICAC-BUDGET-B (#167): estimated-spend budget enforcement.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Budget;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Policy_Simulator;
use HandL\AICAC\Spend_Threshold;
use PHPUnit\Framework\TestCase;

final class BudgetEnforcementTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Budget::SPEND_OPTION_KEY );
		delete_option( Spend_Threshold::FIRED_OPTION_KEY );
		update_option( 'admin_email', 'admin@example.com' );
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);
			return true;
		};
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Budget::SPEND_OPTION_KEY );
		delete_option( Spend_Threshold::FIRED_OPTION_KEY );
		parent::tearDown();
	}

	public function test_hard_deny_blocks_when_over_budget(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$ts     = ( new \DateTimeImmutable( '2026-08-15 12:00:00', $tz ) )->getTimestamp();
		Budget::add_estimated_spend( $plugin, 10.0, $ts, $tz );

		$policy = array(
			'default'        => 'allow',
			'plugins'        => array( $plugin => 'allow' ),
			'plugin_budgets' => array( $plugin => 5.0 ),
		);

		$eval = Policy::evaluate( $policy, $plugin, 'generate_text', null, null, $ts );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( 'budget', $eval['reason'] );

		$verdict = Policy_Simulator::verdict_from_eval( $eval );
		$this->assertFalse( $verdict['allowed'] );
		$this->assertStringContainsString( 'budget', strtolower( $verdict['chip'] ) );
	}

	public function test_observe_mode_allows_but_surfaces_over_budget(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$ts     = ( new \DateTimeImmutable( '2026-08-15 12:00:00', $tz ) )->getTimestamp();
		Budget::add_estimated_spend( $plugin, 10.0, $ts, $tz );

		$policy = array(
			'default'             => 'allow',
			'plugin_budgets'      => array( $plugin => 5.0 ),
			'plugin_budget_modes' => array( $plugin => Budget::MODE_OBSERVE ),
		);

		$eval = Policy::evaluate( $policy, $plugin, 'generate_text', null, null, $ts );
		$this->assertFalse( $eval['prevent'] );
		$this->assertTrue( ! empty( $eval['budget_over'] ) );
		$this->assertSame( Budget::MODE_OBSERVE, $eval['budget_mode'] ?? '' );
		$this->assertSame( 'budget', $eval['reason'] );

		$verdict = Policy_Simulator::verdict_from_eval( $eval );
		$this->assertTrue( $verdict['allowed'] );
		$this->assertSame( 'budget', $verdict['reason'] );
	}

	public function test_temp_allow_does_not_pierce_budget(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$ts     = ( new \DateTimeImmutable( '2026-08-15 12:00:00', $tz ) )->getTimestamp();
		Budget::add_estimated_spend( $plugin, 12.0, $ts, $tz );

		$policy = array(
			'default'         => 'deny',
			'plugins'         => array( $plugin => 'allow' ),
			// Far-future expiry = active temp allow.
			'plugin_expires'  => array( $plugin => $ts + 365 * DAY_IN_SECONDS ),
			'plugin_budgets'  => array( $plugin => 5.0 ),
		);

		$eval = Policy::evaluate( $policy, $plugin, 'generate_text', null, null, $ts );
		$this->assertTrue( $eval['prevent'], 'Budget must win over temporary Allow' );
		$this->assertSame( 'budget', $eval['reason'] );
	}

	public function test_under_budget_does_not_gate(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$ts     = ( new \DateTimeImmutable( '2026-08-15 12:00:00', $tz ) )->getTimestamp();
		Budget::add_estimated_spend( $plugin, 1.0, $ts, $tz );

		$policy = array(
			'default'        => 'allow',
			'plugin_budgets' => array( $plugin => 10.0 ),
		);
		$eval = Policy::evaluate( $policy, $plugin, 'generate_text', null, null, $ts );
		$this->assertFalse( $eval['prevent'] );
		$this->assertSame( '', $eval['reason'] );
		$this->assertTrue( empty( $eval['budget_over'] ) );
	}

	public function test_soft_warn_threshold_at_80_percent_of_budget(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$ts     = ( new \DateTimeImmutable( '2026-08-15 12:00:00', $tz ) )->getTimestamp();
		// Budget $10 → soft warn at $8.
		Budget::add_estimated_spend( $plugin, 8.5, $ts, $tz );

		$policy = array(
			'log_enabled'    => true,
			'alert_email'    => 'admin@example.com',
			'plugin_budgets' => array( $plugin => 10.0 ),
		);
		Policy::save_policy( $policy );
		$policy = Policy::get_policy();

		$this->assertTrue( Spend_Threshold::has_any_threshold( $policy ) );
		$soft = Budget::soft_warn_thresholds( $policy );
		$this->assertSame( 8.0, $soft[ $plugin ] );

		Spend_Threshold::maybe_evaluate( $policy, $ts );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'estimated spend alert', strtolower( self::$mails[0]['subject'] ) );

		// Explicit threshold replaces auto soft-warn for that plugin.
		$policy['spend_threshold_plugins'] = array( $plugin => 9.0 );
		$soft2 = Budget::soft_warn_thresholds( $policy );
		$this->assertArrayNotHasKey( $plugin, $soft2 );
	}
}
