<?php
/**
 * AICAC-DETOUR (#489).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Budget;
use HandL\AICAC\Detour;
use HandL\AICAC\Operations;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-detour.php';
require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class DetourTest extends TestCase {

	private const PLUGIN = 'demo-connector/demo-connector.php';

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		Detour::reset_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Budget::SPEND_OPTION_KEY );
	}

	protected function tearDown(): void {
		Detour::reset_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Budget::SPEND_OPTION_KEY );
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		parent::tearDown();
	}

	public function test_init_registers_admin_footer_once(): void {
		Detour::init();
		Detour::init();
		$hooks = $GLOBALS['handl_aicac_test_added_actions'];
		$this->assertSame( array( 'admin_footer', 'admin_footer' ), $hooks );
	}

	public function test_plugin_bootstrap_wires_detour_at_bottom(): void {
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-detour.php', $plugin );
		$this->assertStringContainsString( 'Detour::init()', $plugin );
		$req_pos  = strpos( $plugin, 'class-handl-aicac-detour.php' );
		$room_pos = strpos( $plugin, 'class-handl-aicac-roommates.php' );
		$this->assertNotFalse( $req_pos );
		$this->assertNotFalse( $room_pos );
		$this->assertGreaterThan( $room_pos, $req_pos );
	}

	public function test_operation_blocked_suggests_enable_operation_with_settings_link(): void {
		$policy = array(
			'default'    => 'allow',
			'plugins'    => array( self::PLUGIN => 'allow' ),
			'operations' => array(
				self::PLUGIN => array(
					Operations::FAMILY_TEXT => 'deny',
				),
			),
		);
		Detour::set_test_policy( $policy );
		Detour::set_test_can_manage( true );

		$eval = Policy::evaluate( $policy, self::PLUGIN, 'generate_text', array(), Operations::FAMILY_TEXT );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( 'capability_family', $eval['reason'] );

		$event = array(
			'decision'           => 'deny',
			'denial_reason'      => 'capability_family',
			'decision_source'    => 'capability_family',
			'plugin'             => self::PLUGIN,
			'operation'          => 'generate_text',
			'capability_family'  => Operations::FAMILY_TEXT,
		);

		$before = $GLOBALS['handl_aicac_test_options'];
		$sug    = Detour::suggest( $event );
		$after  = $GLOBALS['handl_aicac_test_options'];
		$this->assertSame( $before, $after, 'suggest must not write options' );

		$this->assertIsArray( $sug );
		$this->assertSame( 'operation', $sug['kind'] );
		$this->assertStringContainsString( 'Set AI type Text to Allow', $sug['message'] );
		$this->assertStringContainsString( self::PLUGIN, $sug['message'] );
		$this->assertNotSame( '', $sug['url'] );

		$html = Detour::render_line( $event );
		$this->assertStringContainsString( 'What would allow this', $html );
		$this->assertStringContainsString( 'Set AI type Text to Allow', $html );
		$this->assertStringContainsString( 'Open this setting', $html );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] );
	}

	public function test_budget_blocked_names_cap_raise_from_ask_cost(): void {
		$policy = array(
			'default'        => 'allow',
			'plugins'        => array( self::PLUGIN => 'allow' ),
			'plugin_budgets' => array( self::PLUGIN => 1.0 ),
		);
		update_option(
			Budget::SPEND_OPTION_KEY,
			array(
				Budget::period_id() => array( self::PLUGIN => 1.0 ),
			),
			false
		);
		Detour::set_test_policy( $policy );
		Detour::set_test_can_manage( true );

		$eval = Policy::evaluate( $policy, self::PLUGIN, 'generate_text' );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( 'budget', $eval['reason'] );

		$event = array(
			'decision'      => 'deny',
			'denial_reason' => 'budget',
			'decision_source' => 'budget:hard',
			'plugin'        => self::PLUGIN,
			'operation'     => 'generate_text',
			'estimated_usd' => 0.40,
		);

		$before = $GLOBALS['handl_aicac_test_options'];
		$sug    = Detour::suggest( $event );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] );

		$this->assertIsArray( $sug );
		$this->assertSame( 'budget', $sug['kind'] );
		// Display final budget ($1.00 spend/cap + $0.40 ask = $1.40), not the raise alone.
		$this->assertStringContainsString( '1.4', $sug['message'] );
		$this->assertStringContainsString( 'Set the estimated budget', $sug['message'] );
		$this->assertStringContainsString( self::PLUGIN, $sug['message'] );
	}

	public function test_multi_blocker_renders_no_single_change(): void {
		$policy = array(
			'default'     => 'allow',
			'kill_switch' => true,
			'plugins'     => array( self::PLUGIN => 'deny' ),
		);
		Detour::set_test_policy( $policy );
		Detour::set_test_can_manage( true );

		$event = array(
			'decision'        => 'deny',
			'denial_reason'   => 'kill_switch',
			'decision_source' => 'kill_switch',
			'plugin'          => self::PLUGIN,
			'operation'       => 'generate_text',
		);

		// Turning off kill switch alone still leaves plugin deny; allowing plugin alone leaves kill switch.
		$sug = Detour::suggest( $event );
		$this->assertIsArray( $sug );
		$this->assertSame( 'none', $sug['kind'] );
		$this->assertSame( 'No single setting change found.', $sug['message'] );
		$this->assertSame( Detour::NONE_COPY, $sug['message'] );

		$html = Detour::render_line( $event );
		$this->assertStringContainsString( 'No single setting change found.', $html );
		$this->assertStringNotContainsString( 'Open this setting', $html );
	}

	public function test_capability_gate_hides_suggestion_and_writes_nothing(): void {
		$policy = array(
			'default' => 'allow',
			'plugins' => array( self::PLUGIN => 'deny' ),
		);
		Detour::set_test_policy( $policy );
		Detour::set_test_can_manage( false );

		$event = array(
			'decision'        => 'deny',
			'denial_reason'   => 'plugin',
			'decision_source' => 'rule:explicit-deny',
			'plugin'          => self::PLUGIN,
			'operation'       => 'generate_text',
		);

		$before = $GLOBALS['handl_aicac_test_options'];
		$this->assertNull( Detour::suggest( $event ) );
		$this->assertSame( '', Detour::render_line( $event ) );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] );
	}

	public function test_activity_inject_script_finds_plugin_without_column_plugin_class(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-detour.php' );
		$this->assertStringContainsString( 'td.column-plugin code', $src );
		// Activity markup often omits .column-plugin; matcher must prefer path-like <code>.
		$this->assertStringContainsString( 'ct.indexOf("/")!==-1', $src );
		$this->assertStringNotContainsString(
			'td.column-plugin code, td code',
			$src,
			'Broad td code fallback matches Operation before Plugin'
		);
	}

	public function test_append_to_why_html_injects_detour_after_expander(): void {
		$policy = array(
			'default' => 'allow',
			'plugins' => array( self::PLUGIN => 'deny' ),
		);
		Detour::set_test_policy( $policy );
		Detour::set_test_can_manage( true );

		$event = array(
			'decision'        => 'deny',
			'denial_reason'   => 'plugin',
			'decision_source' => 'rule:explicit-deny',
			'plugin'          => self::PLUGIN,
			'operation'       => 'generate_text',
		);

		$why = ' <details class="handl-aicac-why"><summary>Why?</summary><p>Denied.</p></details>';
		$out = Detour::append_to_why_html( $why, $event );
		$this->assertStringStartsWith( $why, $out );
		$this->assertStringContainsString( 'handl-aicac-detour', $out );
		$this->assertStringContainsString( 'Set connector', $out );
	}

	public function test_readme_free_fence(): void {
		$diff = array(
			'includes/class-handl-aicac-detour.php',
			'tests/Unit/DetourTest.php',
			'includes/class-handl-aicac-plugin.php',
		);
		foreach ( $diff as $path ) {
			$this->assertFileExists( HANDL_AICAC_DIR . '/' . $path );
		}
		$this->assertFileDoesNotExist( HANDL_AICAC_DIR . '/includes/class-handl-aicac-why.php.bak' );
		$why = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-why.php' );
		$this->assertStringNotContainsString( 'Detour::', $why );
		$deny = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-deny-receipt.php' );
		$this->assertStringNotContainsString( 'Detour::', $deny );
		$sim = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy-simulator.php' );
		$this->assertStringNotContainsString( 'Detour::', $sim );
	}
}
