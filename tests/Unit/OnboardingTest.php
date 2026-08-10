<?php
/**
 * Unit tests for Onboarding (AICAC-ONBOARD).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Onboarding;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class OnboardingTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['handl_aicac_test_options'] = array();
		unset( $GLOBALS['handl_aicac_test_filters'] );
		parent::setUp();
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options'] = array();
		unset( $GLOBALS['handl_aicac_test_filters'] );
		parent::tearDown();
	}

	public function test_fresh_install_becomes_active_eligible(): void {
		$this->assertTrue( Onboarding::is_fresh_install() );
		$state = Onboarding::ensure_initialized();
		$this->assertTrue( $state['eligible'] );
		$this->assertSame( Onboarding::STATUS_ACTIVE, $state['status'] );
		$this->assertSame( 1, $state['step'] );
		$this->assertTrue( Onboarding::should_auto_show( $state ) );
	}

	public function test_upgrade_install_is_ineligible(): void {
		update_option( Plugin::OPTION_KEY, array( 'default' => 'allow' ) );
		$this->assertFalse( Onboarding::is_fresh_install() );
		$state = Onboarding::ensure_initialized();
		$this->assertFalse( $state['eligible'] );
		$this->assertSame( Onboarding::STATUS_INELIGIBLE, $state['status'] );
		$this->assertFalse( Onboarding::should_auto_show( $state ) );
		$this->assertFalse( Onboarding::should_show_reentry( $state ) );
	}

	public function test_apply_observe_mode_uses_existing_policy_keys(): void {
		$policy = Onboarding::apply_mode_to_policy(
			Policy::get_policy(),
			Onboarding::MODE_OBSERVE,
			10
		);
		$this->assertTrue( $policy['audit_only'] );
		$this->assertTrue( $policy['log_enabled'] );
		$this->assertSame( 10, $policy['log_max_age_days'] );
	}

	public function test_apply_enforce_mode_keeps_logging_on(): void {
		$policy = Onboarding::apply_mode_to_policy(
			array(
				'audit_only'  => true,
				'log_enabled' => false,
			),
			Onboarding::MODE_ENFORCE,
			14
		);
		$this->assertFalse( $policy['audit_only'] );
		$this->assertTrue( $policy['log_enabled'] );
	}

	public function test_apply_alerts_uses_existing_alert_keys(): void {
		$policy = Onboarding::apply_alerts_to_policy(
			Policy::get_policy(),
			'haktan+onboard@handldigital.com',
			true
		);
		$this->assertSame( 'haktan+onboard@handldigital.com', $policy['alert_email'] );
		$this->assertTrue( $policy['alert_on_deny'] );
	}

	public function test_wizard_copy_and_test_email_stay_on_step_two(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringContainsString(
			'Your watch period has ended. Review Activity to see which plugins used AI, then use Rules to allow or block them.',
			$src
		);
		$this->assertStringContainsString(
			'Step %d of 3: set up monitoring and alerts in about two minutes.',
			$src
		);
		$this->assertStringContainsString( '1. How do you want to start?', $src );
		$this->assertStringContainsString(
			'Your network admin controls the site-wide AI mode. You can still set alerts and a review reminder.',
			$src
		);
		$this->assertStringContainsString(
			'Log AI activity without blocking it. Start here while you learn which plugins need access.',
			$src
		);
		$this->assertStringContainsString(
			'Apply your Rules immediately. Choose this only if your policy is already set.',
			$src
		);
		$this->assertStringContainsString(
			'Watch first keeps 7–14 days of activity. Older entries are deleted.',
			$src
		);
		$this->assertStringContainsString( '2. Where should we send alerts?', $src );
		$this->assertStringContainsString(
			'Choose where to send blocked-call alerts. You can also send a test email.',
			$src
		);
		$this->assertStringContainsString(
			'After %d days, show a Dashboard reminder to review Activity and update Rules.',
			$src
		);
		$this->assertStringContainsString( "value=\"onboard_test_email\"", $src );
		$this->assertStringContainsString( 'handle_onboard_test_email', $src );
		$this->assertStringNotContainsString(
			'Send test email uses your current saved alert address',
			$src
		);
		$this->assertStringNotContainsString( 'handl-aicac-onboard-test-email', $src );
	}

	public function test_dismiss_then_reentry(): void {
		$state = Onboarding::ensure_initialized();
		$state['status'] = Onboarding::STATUS_DISMISSED;
		Onboarding::save_state( $state );
		$saved = Onboarding::get_state();
		$this->assertFalse( Onboarding::should_auto_show( $saved ) );
		$this->assertTrue( Onboarding::should_show_reentry( $saved ) );
	}

	public function test_review_notice_only_after_due(): void {
		$state = Onboarding::sanitize_state(
			array(
				'status'        => Onboarding::STATUS_COMPLETE,
				'eligible'      => true,
				'review_due_ts' => 1000,
			)
		);
		$this->assertFalse( Onboarding::should_show_review_notice( $state, 999 ) );
		$this->assertTrue( Onboarding::should_show_review_notice( $state, 1000 ) );
	}

	public function test_network_enforced_filter_defaults_false(): void {
		$this->assertFalse( Onboarding::is_network_enforced() );
		$GLOBALS['handl_aicac_test_filters']['handl_aicac_onboard_network_enforced'] = static function (): bool {
			return true;
		};
		$this->assertTrue( Onboarding::is_network_enforced() );
	}

	public function test_only_wizard_progress_option_key_is_new(): void {
		$this->assertSame( 'handl_aicac_onboard', Onboarding::OPTION_KEY );
		$this->assertNotSame( Plugin::OPTION_KEY, Onboarding::OPTION_KEY );
	}
}
