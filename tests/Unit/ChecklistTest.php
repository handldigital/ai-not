<?php
/**
 * AICAC-CHECKLIST (#190): post-wizard getting-started checklist.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Checklist;
use HandL\AICAC\Onboarding;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy_Packs;
use PHPUnit\Framework\TestCase;

final class ChecklistTest extends TestCase {

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

	public function test_empty_site_shows_open_items_and_skips_plugins(): void {
		$out  = Checklist::compute( $this->base_policy(), array() );
		$by   = $this->by_id( $out['items'] );
		$this->assertFalse( $out['dismissed'] );
		$this->assertFalse( $out['all_applicable_done'] );
		$this->assertFalse( $by['plugins']['applicable'] );
		$this->assertSame( 'No plugin has used AI yet.', $by['plugins']['detail'] );
		$this->assertFalse( $by['pack']['done'] );
		$this->assertFalse( $by['alert_email']['done'] );
		$this->assertFalse( $by['simulator']['done'] );
		$this->assertFalse( $by['digest']['done'] );
		$this->assertSame( 'Review plugins that used AI', $by['plugins']['label'] );
		$this->assertSame( 'Choose a starter policy pack', $by['pack']['label'] );
		$this->assertSame( 'Save an alert email', $by['alert_email']['label'] );
		$this->assertSame( 'Try the policy tester', $by['simulator']['label'] );
		$this->assertSame( 'Turn on the weekly digest', $by['digest']['label'] );
	}

	public function test_complete_config_hides_panel_and_regresses_when_email_cleared(): void {
		$policy = $this->observe_first_policy();
		$policy['alert_email']                 = 'ops@example.com';
		$policy['governance_digest_enabled']   = true;
		Checklist::mark_simulator_tried();

		$out = Checklist::compute( $policy, array() );
		$this->assertTrue( $out['all_applicable_done'] );
		$this->assertTrue( $this->by_id( $out['items'] )['pack']['done'] );
		$this->assertTrue( $this->by_id( $out['items'] )['simulator']['done'] );

		update_option( Plugin::OPTION_KEY, array( 'default' => 'allow' ) );
		$onboard = Onboarding::ensure_initialized();
		$this->assertFalse( Checklist::should_render( $policy, array(), $onboard ) );

		$policy['alert_email'] = '';
		$out                   = Checklist::compute( $policy, array() );
		$this->assertFalse( $out['all_applicable_done'] );
		$this->assertFalse( $this->by_id( $out['items'] )['alert_email']['done'] );
		$this->assertTrue( Checklist::should_render( $policy, array(), $onboard ) );
	}

	public function test_dismiss_hides_even_when_items_are_open(): void {
		update_option( Plugin::OPTION_KEY, array( 'default' => 'allow' ) );
		$onboard = Onboarding::ensure_initialized();
		$policy  = $this->base_policy();
		$this->assertTrue( Checklist::should_render( $policy, array(), $onboard ) );
		Checklist::dismiss();
		$this->assertTrue( Checklist::get_state()['dismissed'] );
		$this->assertFalse( Checklist::should_render( $policy, array(), $onboard ) );
		$out = Checklist::compute( $policy, array() );
		$this->assertTrue( $out['dismissed'] );
		$this->assertFalse( $out['all_applicable_done'] );
	}

	public function test_wizard_hides_checklist(): void {
		$onboard = Onboarding::ensure_initialized();
		$this->assertTrue( Onboarding::should_render_wizard( $onboard ) );
		$this->assertFalse( Checklist::should_render( $this->base_policy(), array(), $onboard ) );
	}

	public function test_ai_active_plugin_without_rule_stays_open(): void {
		$log = array(
			array(
				'plugin'   => 'woo/woo.php',
				'channel'  => 'ai_client',
				'decision' => 'allow',
			),
		);
		$out = Checklist::compute( $this->base_policy(), $log );
		$by  = $this->by_id( $out['items'] );
		$this->assertTrue( $by['plugins']['applicable'] );
		$this->assertFalse( $by['plugins']['done'] );
		$this->assertStringContainsString( '1 plugin still needs', $by['plugins']['detail'] );

		$policy            = $this->base_policy();
		$policy['plugins'] = array( 'woo/woo.php' => 'allow' );
		$out               = Checklist::compute( $policy, $log );
		$this->assertTrue( $this->by_id( $out['items'] )['plugins']['done'] );
	}

	/**
	 * @return array<string,mixed>
	 */
	private function base_policy(): array {
		return array(
			'default'                    => 'allow',
			'audit_only'                 => false,
			'log_enabled'                => true,
			'kill_switch'                => false,
			'shadow_block_enabled'       => false,
			'unknown_operation'          => 'inherit',
			'alert_on_deny'              => false,
			'alert_on_shadow'            => false,
			'alert_mode'                 => 'immediate',
			'alert_email'                => '',
			'governance_digest_enabled'  => false,
			'plugins'                    => array(),
			'new_plugin_review_enabled'  => false,
			'new_plugin_pending'         => array(),
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	private function observe_first_policy(): array {
		$policy = $this->base_policy();
		$def    = Policy_Packs::get( 'observe_first' );
		$this->assertIsArray( $def );
		$policy = array_merge( $policy, $def['patch'] );
		$this->assertTrue( Policy_Packs::is_active( 'observe_first', $policy ) );
		return $policy;
	}

	/**
	 * @param list<array<string,mixed>> $items
	 * @return array<string,array<string,mixed>>
	 */
	private function by_id( array $items ): array {
		$out = array();
		foreach ( $items as $item ) {
			$out[ (string) $item['id'] ] = $item;
		}
		return $out;
	}
}
