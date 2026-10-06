<?php
/**
 * AICAC-WHY (#287): Activity decision explainer.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Budget;
use HandL\AICAC\Freeze;
use HandL\AICAC\New_Plugin;
use HandL\AICAC\Plugin;
use HandL\AICAC\Plugin_Profile;
use HandL\AICAC\Policy;
use HandL\AICAC\Quiet_Hours;
use HandL\AICAC\Rate_Cap;
use HandL\AICAC\Why;
use PHPUnit\Framework\TestCase;

final class WhyTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		Why::reset_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Freeze::OPTION_KEY );
		delete_option( Budget::SPEND_OPTION_KEY );
		Rate_Cap::clear_warned();
		Rate_Cap::clear_counts();
		unset(
			$GLOBALS['handl_aicac_test_user_id'],
			$GLOBALS['handl_aicac_test_user_roles']
		);
	}

	protected function tearDown(): void {
		Why::reset_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Freeze::OPTION_KEY );
		delete_option( Budget::SPEND_OPTION_KEY );
		Rate_Cap::clear_warned();
		Rate_Cap::clear_counts();
		unset(
			$GLOBALS['handl_aicac_test_user_id'],
			$GLOBALS['handl_aicac_test_user_roles']
		);
		parent::tearDown();
	}

	public function test_init_is_idempotent_noop(): void {
		Why::init();
		Why::init();
		$this->assertTrue( true );
	}

	/**
	 * Explicit per-plugin Deny.
	 */
	public function test_source_explicit_rule_deny(): void {
		$plugin = 'blocked/plugin.php';
		$policy = array(
			'default' => 'allow',
			'plugins' => array( $plugin => 'deny' ),
		);
		$eval = Policy::evaluate( $policy, $plugin, 'generate_text' );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( 'rule:explicit-deny', Why::source_for_event( $this->event_from_eval( $eval, $plugin ), $policy ) );
	}

	/**
	 * Role gate deny.
	 */
	public function test_source_role_gate(): void {
		$GLOBALS['handl_aicac_test_user_id']    = 7;
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'author' );
		$plugin                                 = 'any/plugin.php';
		$policy                                 = array(
			'default'           => 'allow',
			'plugins'           => array(),
			'role_gate_enabled' => true,
			'allowed_roles'     => array( 'administrator' ),
		);
		$eval = Policy::evaluate( $policy, $plugin, 'generate_text' );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( 'role', $eval['reason'] );
		$this->assertSame( 'role', Why::source_for_event( $this->event_from_eval( $eval, $plugin ), $policy ) );
	}

	/**
	 * Hourly rate cap deny via apply_to_event.
	 */
	public function test_source_rate_cap_hourly(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$now    = ( new \DateTimeImmutable( '2026-09-22 10:30:00', $tz ) )->getTimestamp();
		$bounds = Rate_Cap::window_bounds( Rate_Cap::WINDOW_HOUR, $now, $tz );
		Rate_Cap::set_window_count( $plugin, Rate_Cap::WINDOW_HOUR, $bounds['key'], 5 );

		$policy = array(
			'default'               => 'allow',
			'plugins'               => array( $plugin => 'allow' ),
			'plugin_rate_caps_hour' => array( $plugin => 5 ),
		);
		$event = array(
			'ts'       => $now,
			'plugin'   => $plugin,
			'decision' => 'allow',
		);
		$rc = Rate_Cap::apply_to_event( $event, $policy, null, $now );
		$this->assertTrue( $rc['prevent'] );
		$event['decision']      = 'deny';
		$event['denial_reason'] = Rate_Cap::REASON;
		Why::stamp( $event, $policy );
		$this->assertSame( 'rate_cap:hourly', $event['decision_source'] );
		$this->assertStringContainsString( 'hourly rate cap (5 calls)', Why::explain_line( $event ) );
	}

	/**
	 * Hard budget deny.
	 */
	public function test_source_budget_hard(): void {
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
		$this->assertSame( 'budget:hard', Why::source_for_event( $this->event_from_eval( $eval, $plugin, $ts ), $policy ) );
	}

	/**
	 * Panic freeze denials are freeze, not Emergency stop.
	 */
	public function test_source_freeze_overrides_kill_switch(): void {
		$now = 1_700_000_000;
		Policy::save_policy(
			array(
				'default'     => 'allow',
				'plugins'     => array( 'acme/acme.php' => 'allow' ),
				'kill_switch' => false,
				'log_enabled' => true,
			)
		);
		$out = Freeze::start( 60, 'Spend spike', $now );
		$this->assertTrue( $out['ok'] );
		$this->assertTrue( Freeze::is_active( $now + 60 ) );

		$policy = Policy::get_policy();
		$eval   = Policy::evaluate( $policy, 'acme/acme.php', 'generate_text', array(), null, $now + 60 );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( 'kill_switch', $eval['reason'] );

		$event = $this->event_from_eval( $eval, 'acme/acme.php', $now + 60 );
		$this->assertSame( 'freeze', Why::source_for_event( $event, $policy, true ) );
		$this->assertSame( 'kill_switch', Why::source_for_event( $event, $policy, false ) );
	}

	/**
	 * Newcomer hold deny-mode.
	 */
	public function test_source_newcomer_hold(): void {
		$plugin = 'gallery/gallery.php';
		$policy = array(
			'default'               => 'allow',
			'plugins'               => array(),
			'newcomer_hold_enabled' => true,
			'newcomer_hold_mode'    => 'deny',
		);
		$eval = Policy::evaluate( $policy, $plugin, 'generate_text' );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( New_Plugin::REASON, $eval['reason'] );
		$this->assertSame( 'newcomer_hold', Why::source_for_event( $this->event_from_eval( $eval, $plugin ), $policy ) );
	}

	/**
	 * Quiet hours deny window.
	 */
	public function test_source_quiet_hours(): void {
		$tz  = new \DateTimeZone( 'UTC' );
		$now = ( new \DateTimeImmutable( '2026-08-12 14:30:00', $tz ) )->getTimestamp();
		$plugin = 'demo/demo.php';
		$policy = array(
			'default'     => 'allow',
			'plugins'     => array(),
			'quiet_hours' => array(
				array(
					'name'  => 'Afternoon block',
					'days'  => array( 3 ),
					'start' => '14:00',
					'end'   => '16:00',
					'mode'  => Quiet_Hours::MODE_DENY,
				),
			),
		);
		$eval = Policy::evaluate( $policy, $plugin, 'generate_text', null, null, $now );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( 'quiet_hours', $eval['reason'] );
		$event = $this->event_from_eval( $eval, $plugin, $now );
		$event['quiet_hours_window'] = 'Afternoon block';
		Why::stamp( $event, $policy );
		$this->assertSame( 'quiet_hours', $event['decision_source'] );
		$this->assertStringContainsString( 'Afternoon block', Why::explain_line( $event ) );
	}

	/**
	 * Unexpired temporary Allow.
	 */
	public function test_source_temporary_allow(): void {
		$now    = 1_700_000_000;
		$plugin = 'ok/plugin.php';
		$policy = array(
			'default'        => 'deny',
			'plugins'        => array( $plugin => 'allow' ),
			'plugin_expires' => array( $plugin => $now + DAY_IN_SECONDS ),
		);
		$eval = Policy::evaluate( $policy, $plugin, 'generate_text', null, null, $now );
		$this->assertFalse( $eval['prevent'] );
		$this->assertSame( 'temp_allow', Why::source_for_event( $this->event_from_eval( $eval, $plugin, $now ), $policy ) );
	}

	/**
	 * Site default Allow with no explicit rule.
	 */
	public function test_source_default_policy_allow(): void {
		$plugin = 'unknown/plugin.php';
		$policy = array(
			'default' => 'allow',
			'plugins' => array(),
		);
		$eval = Policy::evaluate( $policy, $plugin, 'generate_text' );
		$this->assertFalse( $eval['prevent'] );
		$this->assertSame( 'default:allow', Why::source_for_event( $this->event_from_eval( $eval, $plugin ), $policy ) );
	}

	public function test_source_default_policy_deny(): void {
		$plugin = 'unknown/plugin.php';
		$policy = array(
			'default' => 'deny',
			'plugins' => array(),
		);
		$eval = Policy::evaluate( $policy, $plugin, 'generate_text' );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( 'default:deny', Why::source_for_event( $this->event_from_eval( $eval, $plugin ), $policy ) );
	}

	public function test_source_explicit_allow(): void {
		$plugin = 'trusted/plugin.php';
		$policy = array(
			'default' => 'deny',
			'plugins' => array( $plugin => 'allow' ),
		);
		$eval = Policy::evaluate( $policy, $plugin, 'generate_text' );
		$this->assertFalse( $eval['prevent'] );
		$this->assertSame( 'rule:explicit-allow', Why::source_for_event( $this->event_from_eval( $eval, $plugin ), $policy ) );
	}

	public function test_observe_is_not_stamped(): void {
		$event = array(
			'decision' => 'observe',
			'plugin'   => 'shadow/shadow.php',
		);
		Why::stamp( $event, array( 'default' => 'allow' ) );
		$this->assertArrayNotHasKey( 'decision_source', $event );
		$this->assertSame( '', Why::render_expander( $event ) );
	}

	public function test_existing_source_is_not_overwritten(): void {
		$event = array(
			'decision'        => 'deny',
			'plugin'          => 'blocked/plugin.php',
			'denial_reason'   => 'plugin',
			'decision_source' => 'freeze',
		);
		$policy = array(
			'default' => 'allow',
			'plugins' => array( 'blocked/plugin.php' => 'deny' ),
		);
		Why::stamp( $event, $policy );
		$this->assertSame( 'freeze', $event['decision_source'] );
	}

	public function test_append_log_event_persists_source(): void {
		$plugin = 'blocked/plugin.php';
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'plugins'     => array( $plugin => 'deny' ),
				'log_enabled' => true,
				'log_limit'   => 200,
			),
			false
		);

		Policy::append_log_event(
			array(
				'ts'            => 1_700_000_000,
				'plugin'        => $plugin,
				'decision'      => 'deny',
				'denial_reason' => 'plugin',
			)
		);

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertSame( 'rule:explicit-deny', $log[0]['decision_source'] ?? '' );
	}

	public function test_expander_legacy_copy_when_key_missing(): void {
		$html = Why::render_expander(
			array(
				'decision' => 'deny',
				'plugin'   => 'old/old.php',
			)
		);
		$this->assertStringContainsString( 'Why?', $html );
		$this->assertStringContainsString( Why::LEGACY_COPY, $html );
		$this->assertStringNotContainsString( 'Open this setting', $html );
		$this->assertStringContainsString( 'handl-aicac-why', $html );
	}

	public function test_expander_links_to_protections_and_rules(): void {
		$plugin = 'blocked/plugin.php';
		$deny   = array(
			'decision'        => 'deny',
			'plugin'          => $plugin,
			'decision_source' => 'rule:explicit-deny',
		);
		$html = Why::render_expander( $deny );
		$this->assertStringContainsString( 'Denied because this plugin has a Deny rule.', $html );
		$this->assertStringContainsString( 'Open this setting', $html );
		$this->assertStringContainsString( Plugin_Profile::rules_url( $plugin ), $html );

		$role = array(
			'decision'        => 'deny',
			'decision_source' => 'role',
		);
		$role_html = Why::render_expander( $role );
		$this->assertStringContainsString( 'handl-aicac-protections', $role_html );
		$this->assertStringContainsString( 'handl-aicac-role-gate-enabled', $role_html );
		$this->assertStringContainsString( 'this user role is not allowed', $role_html );
	}

	public function test_plugin_php_requires_and_inits_why_at_end(): void {
		$src   = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$feed  = strpos( $src, "require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-threat-feed.php'" );
		$why   = strpos( $src, "require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-why.php'" );
		$init  = strpos( $src, 'Why::init()' );
		$tinit = strpos( $src, 'Threat_Feed::init()' );
		$this->assertNotFalse( $feed );
		$this->assertNotFalse( $why );
		$this->assertGreaterThan( $feed, $why );
		$this->assertNotFalse( $init );
		$this->assertGreaterThan( $tinit, $init );
	}

	/**
	 * @param array<string,mixed> $eval
	 * @return array<string,mixed>
	 */
	private function event_from_eval( array $eval, string $plugin, int $ts = 1_700_000_000 ): array {
		$event = array(
			'ts'            => $ts,
			'plugin'        => $plugin,
			'decision'      => ! empty( $eval['prevent'] ) ? 'deny' : 'allow',
			'denial_reason' => (string) ( $eval['reason'] ?? '' ),
		);
		if ( ! empty( $eval['budget_over'] ) ) {
			$event['budget_over'] = true;
		}
		if ( isset( $eval['budget_mode'] ) ) {
			$event['budget_mode'] = (string) $eval['budget_mode'];
		}
		return $event;
	}
}
