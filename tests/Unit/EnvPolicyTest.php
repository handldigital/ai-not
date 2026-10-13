<?php
/**
 * AICAC-ENV-POLICY (#363).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Env_Policy;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class EnvPolicyTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Env_Policy::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'deny',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'haktan+aicac-env-policy@handldigital.com',
			)
		);
	}

	protected function tearDown(): void {
		Env_Policy::reset_for_tests();
		$GLOBALS['handl_aicac_test_options'] = array();
		unset( $GLOBALS['handl_aicac_test_current_user_can'] );
		parent::tearDown();
	}

	public function test_defaults_off_and_noop_save_leaves_options_byte_identical(): void {
		$this->assertFalse( Env_Policy::is_enabled() );
		$this->assertSame( Env_Policy::defaults(), Env_Policy::get_settings() );
		$before = $GLOBALS['handl_aicac_test_options'];
		$this->assertFalse( Env_Policy::save_settings( Env_Policy::defaults() ) );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] );
		$this->assertFalse( (bool) get_option( Env_Policy::SETTINGS_OPTION, false ) );
	}

	public function test_save_defaults_after_enable_deletes_option(): void {
		Env_Policy::save_settings(
			array(
				'enabled'  => true,
				'overlays' => array( 'staging' => Env_Policy::MODE_DENY ),
			)
		);
		$this->assertTrue( Env_Policy::is_enabled() );
		$this->assertSame( Env_Policy::MODE_DENY, Env_Policy::get_settings()['overlays']['staging'] );
		Env_Policy::save_settings( Env_Policy::defaults() );
		$this->assertFalse( (bool) get_option( Env_Policy::SETTINGS_OPTION, false ) );
		$this->assertFalse( Env_Policy::is_enabled() );
	}

	public function test_off_evaluate_is_identity_on_deny_default(): void {
		Env_Policy::init();
		$policy = get_option( Plugin::OPTION_KEY, array() );
		$result = Policy::evaluate( is_array( $policy ) ? $policy : array(), 'alpha/alpha.php' );
		$this->assertTrue( $result['prevent'] );
		$this->assertSame( 'plugin', $result['reason'] );
		$this->assertArrayNotHasKey( 'env_overlay', $result );
	}

	public function test_staging_observe_flips_deny_and_production_does_not(): void {
		Env_Policy::init();
		Env_Policy::save_settings(
			array(
				'enabled'  => true,
				'overlays' => array(
					'staging'    => Env_Policy::MODE_OBSERVE,
					'production' => Env_Policy::MODE_INHERIT,
				),
			)
		);
		$policy = get_option( Plugin::OPTION_KEY, array() );
		$policy = is_array( $policy ) ? $policy : array();

		$GLOBALS['handl_aicac_test_environment_type'] = 'staging';
		$staging = Policy::evaluate( $policy, 'alpha/alpha.php' );
		$this->assertFalse( $staging['prevent'] );
		$this->assertSame( Env_Policy::REASON, $staging['reason'] );
		$this->assertSame( 'staging:observe', $staging['env_overlay'] );

		$GLOBALS['handl_aicac_test_environment_type'] = 'production';
		$prod = Policy::evaluate( $policy, 'alpha/alpha.php' );
		$this->assertTrue( $prod['prevent'] );
		$this->assertSame( 'plugin', $prod['reason'] );
		$this->assertArrayNotHasKey( 'env_overlay', $prod );
	}

	public function test_staging_deny_flips_allow_and_production_does_not(): void {
		Env_Policy::init();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
			)
		);
		Env_Policy::save_settings(
			array(
				'enabled'  => true,
				'overlays' => array(
					'staging'    => Env_Policy::MODE_DENY,
					'production' => Env_Policy::MODE_INHERIT,
				),
			)
		);
		$policy = get_option( Plugin::OPTION_KEY, array() );
		$policy = is_array( $policy ) ? $policy : array();

		$GLOBALS['handl_aicac_test_environment_type'] = 'staging';
		$staging = Policy::evaluate( $policy, 'beta/beta.php' );
		$this->assertTrue( $staging['prevent'] );
		$this->assertSame( Env_Policy::REASON, $staging['reason'] );
		$this->assertSame( 'staging:deny', $staging['env_overlay'] );

		$GLOBALS['handl_aicac_test_environment_type'] = 'production';
		$prod = Policy::evaluate( $policy, 'beta/beta.php' );
		$this->assertFalse( $prod['prevent'] );
		$this->assertArrayNotHasKey( 'env_overlay', $prod );
	}

	public function test_enabled_inherit_is_identity(): void {
		Env_Policy::init();
		Env_Policy::save_settings(
			array(
				'enabled'  => true,
				'overlays' => array( 'staging' => Env_Policy::MODE_INHERIT ),
			)
		);
		$GLOBALS['handl_aicac_test_environment_type'] = 'staging';
		$policy = get_option( Plugin::OPTION_KEY, array() );
		$result = Policy::evaluate( is_array( $policy ) ? $policy : array(), 'alpha/alpha.php' );
		$this->assertTrue( $result['prevent'] );
		$this->assertSame( 'plugin', $result['reason'] );
	}

	public function test_page_shows_environment_badge_and_off_copy(): void {
		$GLOBALS['handl_aicac_test_environment_type'] = 'staging';
		ob_start();
		Env_Policy::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Environment policy', $html );
		$this->assertStringContainsString( 'This site is staging', $html );
		$this->assertStringContainsString( 'Use extra rules per environment', $html );
		$this->assertStringContainsString( 'Extra environment rules are off', $html );
		$this->assertStringContainsString( 'Use the site policy', $html );
		$this->assertStringContainsString( 'Deny AI calls', $html );
		$this->assertStringContainsString( 'Allow and log', $html );
		$this->assertStringContainsString( 'Save environment policy', $html );
	}

	public function test_production_loose_findings_only_on_production(): void {
		$GLOBALS['handl_aicac_test_environment_type'] = 'staging';
		$this->assertSame( array(), Env_Policy::production_loose_findings() );

		$GLOBALS['handl_aicac_test_environment_type'] = 'production';
		$findings = Env_Policy::production_loose_findings(
			array(
				'default'     => 'allow',
				'audit_only'  => true,
				'alert_email' => '',
			)
		);
		$this->assertCount( 3, $findings );
		$this->assertSame( 'Enforcement is off. AI calls are logged only.', $findings[0] );
		$this->assertSame( 'Unknown plugins are allowed.', $findings[1] );
		$this->assertSame( 'No alert email is set.', $findings[2] );
	}

	public function test_status_line_off_and_on(): void {
		$GLOBALS['handl_aicac_test_environment_type'] = 'staging';
		$this->assertSame( 'Environment rules are turned off. This site: staging.', Env_Policy::status_line() );
		Env_Policy::save_settings(
			array(
				'enabled'  => true,
				'overlays' => array( 'staging' => Env_Policy::MODE_DENY ),
			)
		);
		$this->assertSame( 'This site: staging. Rule: Deny AI calls.', Env_Policy::status_line() );
	}

	public function test_unknown_environment_falls_back_to_production(): void {
		$GLOBALS['handl_aicac_test_environment_type'] = 'qa';
		$this->assertSame( 'production', Env_Policy::environment_type() );
	}
}
