<?php
/**
 * Unit tests for AICAC-MCP-GATE (#239).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alerts;
use HandL\AICAC\Attribution;
use HandL\AICAC\Mcp_Gate;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy_Simulator;
use PHPUnit\Framework\TestCase;

final class McpGateTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		Mcp_Gate::reset_for_tests();
		delete_option( Mcp_Gate::OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		unset( $GLOBALS['handl_aicac_test_mcp_surfaces'] );
		Attribution::force_plugin( null );
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
		Mcp_Gate::reset_for_tests();
		Attribution::force_plugin( null );
		unset( $GLOBALS['handl_aicac_wp_mail'], $GLOBALS['handl_aicac_test_mcp_surfaces'] );
		delete_option( Mcp_Gate::OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		parent::tearDown();
	}

	public function test_fresh_install_inherit_allows(): void {
		$result = Mcp_Gate::evaluate( 'acme/acme.php' );
		$this->assertFalse( $result['prevent'] );
		$this->assertSame( '', $result['reason'] );
		$this->assertSame( Mcp_Gate::RULE_ALLOW, $result['decision'] );
		$this->assertSame( Mcp_Gate::RULE_INHERIT, $result['rule'] );
	}

	public function test_plugin_deny_blocks_with_mcp_reason(): void {
		$settings = array(
			'default' => 'inherit',
			'plugins' => array( 'blocked/plugin.php' => 'deny' ),
		);
		$result = Mcp_Gate::evaluate( 'blocked/plugin.php', $settings );
		$this->assertTrue( $result['prevent'] );
		$this->assertSame( Mcp_Gate::REASON, $result['reason'] );
		$this->assertSame( Mcp_Gate::RULE_DENY, $result['decision'] );
	}

	public function test_plugin_allow_overrides_default_deny(): void {
		$settings = array(
			'default' => 'deny',
			'plugins' => array( 'trusted/plugin.php' => 'allow' ),
		);
		$result = Mcp_Gate::evaluate( 'trusted/plugin.php', $settings );
		$this->assertFalse( $result['prevent'] );
		$this->assertSame( '', $result['reason'] );
	}

	public function test_inherit_follows_default_deny(): void {
		$settings = array(
			'default' => 'deny',
			'plugins' => array(),
		);
		$result = Mcp_Gate::evaluate( 'unknown/plugin.php', $settings );
		$this->assertTrue( $result['prevent'] );
		$this->assertSame( Mcp_Gate::REASON, $result['reason'] );
	}

	public function test_absent_api_skip_selftest_does_not_fail(): void {
		$GLOBALS['handl_aicac_test_mcp_surfaces'] = false;
		$probe = Mcp_Gate::selftest_probe();
		$this->assertSame( 'skipped', $probe['status'] );
		$this->assertTrue( $probe['pass'] );
		$this->assertStringContainsString( 'skipped', $probe['label'] );
	}

	public function test_present_api_selftest_deny_and_allow(): void {
		$GLOBALS['handl_aicac_test_mcp_surfaces'] = true;
		Attribution::force_plugin( 'handl-aicac-selftest/selftest.php' );
		$probe = Mcp_Gate::selftest_probe();
		$this->assertTrue( $probe['pass'], $probe['label'] );
		$this->assertSame( 'pass', $probe['status'] );
		$this->assertNull( get_option( Mcp_Gate::OPTION_KEY, null ) );
	}

	public function test_init_does_not_fatal_when_apis_absent(): void {
		$GLOBALS['handl_aicac_test_mcp_surfaces'] = false;
		Mcp_Gate::instance()->init();
		$this->assertFalse( Mcp_Gate::surfaces_present() );
	}

	public function test_register_filter_strips_mcp_exposure_on_deny(): void {
		Mcp_Gate::save_settings(
			array(
				'default' => 'inherit',
				'plugins' => array( 'acme/acme.php' => 'deny' ),
			)
		);
		Attribution::force_plugin( 'acme/acme.php' );
		update_option( Plugin::OPTION_KEY, array( 'log_enabled' => true ), false );

		$out = Mcp_Gate::instance()->filter_register_ability_args(
			array(
				'label' => 'Demo',
				'meta'  => array(
					'public' => true,
					'mcp'    => array( 'public' => true ),
				),
			),
			'acme/demo-tool'
		);

		$this->assertFalse( $out['meta']['public'] );
		$this->assertFalse( $out['meta']['mcp']['public'] );
		$this->assertTrue( is_callable( $out['permission_callback'] ) );
		$denied = call_user_func( $out['permission_callback'], null );
		$this->assertInstanceOf( \WP_Error::class, $denied );
		$this->assertSame( Mcp_Gate::BLOCK_ERROR_CODE, $denied->code );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $log );
		$this->assertNotEmpty( $log );
		$row = $log[ count( $log ) - 1 ];
		$this->assertSame( 'deny', $row['decision'] );
		$this->assertSame( Mcp_Gate::REASON, $row['denial_reason'] );
		$this->assertSame( Mcp_Gate::ACTION_REGISTER, $row['mcp_action'] );
	}

	public function test_register_filter_allows_when_inherit(): void {
		Attribution::force_plugin( 'acme/acme.php' );
		$in  = array(
			'label' => 'Demo',
			'meta'  => array( 'public' => true ),
		);
		$out = Mcp_Gate::instance()->filter_register_ability_args( $in, 'acme/demo-tool' );
		$this->assertTrue( $out['meta']['public'] );
		$this->assertSame( 'acme/acme.php', Mcp_Gate::owner_for_ability( 'acme/demo-tool' ) );
	}

	public function test_pre_tool_call_blocks_denied_owner(): void {
		Mcp_Gate::save_settings(
			array(
				'plugins' => array( 'acme/acme.php' => 'deny' ),
			)
		);
		Mcp_Gate::remember_owner( 'acme/demo-tool', 'acme/acme.php' );
		update_option( Plugin::OPTION_KEY, array( 'log_enabled' => true, 'alert_on_deny' => true ), false );

		$result = Mcp_Gate::instance()->filter_pre_tool_call( array( 'x' => 1 ), 'acme-demo-tool', null, null );
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( Mcp_Gate::BLOCK_ERROR_CODE, $result->code );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertNotEmpty( $log );
		$row = $log[ count( $log ) - 1 ];
		$this->assertSame( Mcp_Gate::REASON, $row['denial_reason'] );
		$this->assertSame( Mcp_Gate::ACTION_CALL, $row['mcp_action'] );
	}

	public function test_pre_tool_call_allows_when_not_denied(): void {
		$args   = array( 'x' => 1 );
		$result = Mcp_Gate::instance()->filter_pre_tool_call( $args, 'acme-demo-tool', null, null );
		$this->assertSame( $args, $result );
	}

	public function test_http_outbound_mcp_blocked_for_denied_plugin(): void {
		Mcp_Gate::save_settings(
			array(
				'plugins' => array( 'acme/acme.php' => 'deny' ),
			)
		);
		Attribution::force_plugin( 'acme/acme.php' );
		update_option( Plugin::OPTION_KEY, array( 'log_enabled' => true ), false );

		$body = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"remote-tool"}}';
		$result = Mcp_Gate::instance()->filter_http_request(
			false,
			array( 'body' => $body ),
			'https://example.test/mcp'
		);
		$this->assertInstanceOf( \WP_Error::class, $result );
	}

	public function test_http_non_mcp_never_blocked(): void {
		Mcp_Gate::save_settings(
			array(
				'plugins' => array( 'acme/acme.php' => 'deny' ),
			)
		);
		Attribution::force_plugin( 'acme/acme.php' );
		$result = Mcp_Gate::instance()->filter_http_request(
			false,
			array( 'body' => '{"hello":"world"}' ),
			'https://example.test/api'
		);
		$this->assertFalse( $result );
	}

	public function test_looks_like_mcp_request(): void {
		$this->assertTrue(
			Mcp_Gate::looks_like_mcp_request(
				array( 'body' => '{"jsonrpc":"2.0","method":"tools/list"}' )
			)
		);
		$this->assertFalse(
			Mcp_Gate::looks_like_mcp_request(
				array( 'body' => '{"jsonrpc":"2.0","method":"ping"}' )
			)
		);
		$this->assertFalse( Mcp_Gate::looks_like_mcp_request( array() ) );
	}

	public function test_simulator_covers_mcp_reason(): void {
		$this->assertSame( 'MCP rule', Policy_Simulator::reason_label( Mcp_Gate::REASON ) );
		Mcp_Gate::save_settings(
			array(
				'plugins' => array( 'acme/acme.php' => 'deny' ),
			)
		);
		$eval = Policy_Simulator::evaluate_mcp( 'acme/acme.php' );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( Mcp_Gate::REASON, $eval['reason'] );
		$verdict = Policy_Simulator::verdict_from_eval( $eval );
		$this->assertFalse( $verdict['allowed'] );
		$this->assertSame( Mcp_Gate::REASON, $verdict['reason'] );
		$this->assertStringContainsString( 'MCP rule', $verdict['chip'] );
	}

	public function test_plugin_php_requires_mcp_gate(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-mcp-gate.php', $src );
		$this->assertStringContainsString( 'Mcp_Gate::instance()->init()', $src );
	}

	public function test_alerts_path_used_on_denial(): void {
		$this->assertTrue( method_exists( Alerts::class, 'maybe_notify_denial' ) );
		Mcp_Gate::save_settings(
			array(
				'plugins' => array( 'acme/acme.php' => 'deny' ),
			)
		);
		Attribution::force_plugin( 'acme/acme.php' );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled'   => true,
				'alert_on_deny' => true,
				'alert_email'   => 'ops@example.test',
			),
			false
		);
		Mcp_Gate::instance()->filter_pre_tool_call( array(), 'acme-tool', null, null );
		$this->assertNotEmpty( get_option( Plugin::LOG_OPTION_KEY, array() ) );
	}
}
