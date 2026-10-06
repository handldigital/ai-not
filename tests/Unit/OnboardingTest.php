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
use HandL\AICAC\Preflight_Scan;
use PHPUnit\Framework\TestCase;

final class OnboardingTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['handl_aicac_test_options'] = array();
		unset( $GLOBALS['handl_aicac_test_filters'], $GLOBALS['handl_aicac_test_plugins'] );
		if ( class_exists( Preflight_Scan::class ) ) {
			Preflight_Scan::reset_for_tests();
		}
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
			'Step %d of 4: set up monitoring, alerts, and a first look at AI plugins.',
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
		$this->assertStringContainsString( 'Onboarding::render_scan_step', $src );
		$onboard = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-onboarding.php' );
		$this->assertStringContainsString( '4. Plugins that mention AI', $onboard );
		$this->assertStringContainsString( 'Skip this scan', $onboard );
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

	public function test_sanitize_step_allows_scan_step(): void {
		$this->assertSame( 4, Onboarding::sanitize_step( 4 ) );
		$this->assertSame( 4, Onboarding::sanitize_step( 99 ) );
	}

	public function test_skip_scan_completes_without_activity_row(): void {
		$state = Onboarding::ensure_initialized();
		$state['eligible'] = true;
		$state['scan_status'] = Onboarding::SCAN_SKIPPED;
		$out = Onboarding::complete( $state );
		$this->assertSame( Onboarding::STATUS_COMPLETE, $out['status'] );
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertSame( array(), is_array( $log ) ? $log : array() );
	}

	public function test_scan_error_still_completes(): void {
		$GLOBALS['handl_aicac_test_filters'][ Onboarding::FILTER_SCAN_ERROR ] = static function () {
			return true;
		};
		$result = Onboarding::run_site_scan();
		$this->assertFalse( $result['ok'] );
		$this->assertSame( Onboarding::SCAN_ERROR_COPY, $result['error'] );
		$state = Onboarding::ensure_initialized();
		$state['scan_status'] = Onboarding::SCAN_ERROR;
		$out = Onboarding::complete( $state );
		$this->assertSame( Onboarding::STATUS_COMPLETE, $out['status'] );
		ob_start();
		Onboarding::render_scan_step( $state );
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( Onboarding::SCAN_ERROR_COPY, $html );
		$this->assertStringContainsString( 'Finish setup', $html );
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertSame( array(), is_array( $log ) ? $log : array() );
	}

	public function test_wizard_scan_lists_fixtures_and_policy_tools_does_not_duplicate_log(): void {
		Preflight_Scan::reset_for_tests();
		update_option( Plugin::OPTION_KEY, array( 'log_enabled' => true, 'log_limit' => 200 ), false );
		delete_option( Plugin::LOG_OPTION_KEY );
		$GLOBALS['handl_aicac_test_plugins'] = array(
			'openai-plug/openai-plug.php'       => array( 'Name' => 'OpenAI Plug' ),
			'anthropic-plug/anthropic-plug.php' => array( 'Name' => 'Anthropic Plug' ),
		);
		$this->write_plugin( 'openai-plug', "<?php\n\$u='https://api.openai.com/v1';\n" );
		$this->write_plugin( 'anthropic-plug', "<?php\n\$u='https://api.anthropic.com/v1';\n" );

		$out = Onboarding::run_site_scan();
		$this->assertTrue( $out['ok'] );
		$this->assertFalse( $out['reused'] );
		$ids = array_map(
			static function ( array $row ): string {
				return (string) $row['id'];
			},
			$out['run']['hits']
		);
		$this->assertContains( 'openai-plug/openai-plug.php', $ids );
		$this->assertContains( 'anthropic-plug/anthropic-plug.php', $ids );

		$state = Onboarding::ensure_initialized();
		$state['scan_status'] = Onboarding::SCAN_RAN;
		ob_start();
		Onboarding::render_scan_step( $state );
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'OpenAI Plug', $html );
		$this->assertStringContainsString( 'Anthropic Plug', $html );
		$this->assertStringContainsString( 'Add a Deny rule', $html );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertCount( 1, $log );
		$this->assertSame( 'scan_all', $log[0]['operation'] ?? '' );

		$again = Onboarding::run_site_scan();
		$this->assertTrue( $again['reused'] );
		ob_start();
		Preflight_Scan::render_policy_tools_section();
		$tools = (string) ob_get_clean();
		$this->assertStringContainsString( 'OpenAI Plug', $tools );
		$this->assertCount( 1, get_option( Plugin::LOG_OPTION_KEY ) );

		Onboarding::complete( $state );
		$this->assertCount( 1, get_option( Plugin::LOG_OPTION_KEY ) );
	}

	public function test_progress_copy_before_scan(): void {
		ob_start();
		Onboarding::render_scan_step( array( 'scan_status' => Onboarding::SCAN_NONE ) );
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( Onboarding::SCAN_PROGRESS, $html );
		$this->assertStringContainsString( Onboarding::SCAN_SKIP, $html );
	}

	private function write_plugin( string $slug, string $body ): void {
		$root = defined( 'WP_PLUGIN_DIR' ) ? (string) WP_PLUGIN_DIR : sys_get_temp_dir() . '/handl-aicac-plugins';
		$dir  = $root . '/' . $slug;
		if ( ! is_dir( $dir ) ) {
			mkdir( $dir, 0777, true );
		}
		file_put_contents( $dir . '/' . $slug . '.php', $body );
	}
}
