<?php
/**
 * Unit tests for AICAC-PROFILE per-plugin drill-down.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Operations;
use HandL\AICAC\Plugin_Profile;
use HandL\AICAC\Policy_Simulator;
use PHPUnit\Framework\TestCase;

final class PluginProfileTest extends TestCase {

	public function test_sanitize_plugin_rejects_traversal_and_junk(): void {
		$this->assertSame( '', Plugin_Profile::sanitize_plugin( '../evil.php' ) );
		$this->assertSame( '', Plugin_Profile::sanitize_plugin( '/abs/path.php' ) );
		$this->assertSame( '', Plugin_Profile::sanitize_plugin( 'nope' ) );
		$this->assertSame( '', Plugin_Profile::sanitize_plugin( '' ) );
		$this->assertSame( 'akismet/akismet.php', Plugin_Profile::sanitize_plugin( 'akismet/akismet.php' ) );
		$this->assertSame( 'hello.php', Plugin_Profile::sanitize_plugin( 'hello.php' ) );
	}

	public function test_build_marks_deleted_plugin_inactive_and_still_aggregates(): void {
		$plugin = 'gone/gone.php';
		$log    = array(
			array(
				'ts'            => 1700000000,
				'plugin'        => $plugin,
				'decision'      => 'allow',
				'operation'     => 'generate_text',
				'provider'      => 'openai',
				'model'         => 'gpt-4o-mini',
				'input_tokens'  => 1000,
				'output_tokens' => 500,
			),
			array(
				'ts'       => 1700000100,
				'plugin'   => $plugin,
				'decision' => 'deny',
				'operation'=> 'generate_text',
				'denial_reason' => 'plugin',
			),
			array(
				'ts'      => 1700000200,
				'plugin'  => $plugin,
				'channel' => 'direct_http',
				'host'    => 'api.openai.com',
				'count'   => 3,
				'decision'=> 'observe',
			),
		);

		$policy = array(
			'default'      => 'allow',
			'plugins'      => array( $plugin => 'deny' ),
			'operations'   => array(),
			'log_enabled'  => true,
			'kill_switch'  => false,
		);

		$profile = Plugin_Profile::build( $plugin, $log, $policy, array(), array() );

		$this->assertFalse( $profile['installed'] );
		$this->assertFalse( $profile['active'] );
		$this->assertSame( 3, $profile['row_count'] );
		$this->assertSame( 1700000000, $profile['first_ts'] );
		$this->assertSame( 1700000200, $profile['last_ts'] );
		$this->assertSame( 2, $profile['usage']['calls'] );
		$this->assertSame( 1, $profile['incidents']['denial_count'] );
		$this->assertSame( 3, $profile['incidents']['shadow_call_count'] );
		$this->assertTrue( $profile['effective']['plugin_eval']['prevent'] );
		$this->assertSame( 'plugin', $profile['effective']['plugin_eval']['reason'] );
	}

	public function test_effective_ruleset_uses_policy_evaluate_parity(): void {
		$plugin = 'demo/demo.php';
		$policy = array(
			'default'     => 'allow',
			'plugins'     => array( $plugin => 'allow' ),
			'operations'  => array(
				$plugin => array(
					Operations::FAMILY_IMAGE => 'deny',
				),
			),
			'kill_switch' => false,
		);

		$ruleset = Plugin_Profile::effective_ruleset( $policy, $plugin );
		$this->assertFalse( $ruleset['plugin_eval']['prevent'] );

		$text = null;
		$image = null;
		foreach ( $ruleset['families'] as $fam ) {
			if ( Operations::FAMILY_TEXT === $fam['family'] ) {
				$text = $fam;
			}
			if ( Operations::FAMILY_IMAGE === $fam['family'] ) {
				$image = $fam;
			}
		}
		$this->assertNotNull( $text );
		$this->assertNotNull( $image );
		$this->assertFalse( $text['eval']['prevent'] );
		$this->assertTrue( $image['eval']['prevent'] );
		$this->assertSame( 'capability_family', $image['eval']['reason'] );

		// Same result as calling Policy_Simulator / Policy::evaluate directly.
		$direct = Policy_Simulator::evaluate_call(
			$policy,
			$plugin,
			Operations::canonical_operation_for_family( Operations::FAMILY_IMAGE ),
			null,
			Operations::FAMILY_IMAGE
		);
		$this->assertSame( $direct, $image['eval'] );
	}

	public function test_logging_off_skips_history_but_keeps_rules(): void {
		$plugin = 'demo/demo.php';
		$log    = array(
			array(
				'ts'       => 1,
				'plugin'   => $plugin,
				'decision' => 'allow',
				'operation'=> 'generate_text',
			),
		);
		$policy = array(
			'default'     => 'deny',
			'plugins'     => array(),
			'log_enabled' => false,
			'audit_only'  => false,
		);

		$profile = Plugin_Profile::build(
			$plugin,
			$log,
			$policy,
			array( $plugin => array( 'Name' => 'Demo' ) ),
			array( $plugin => true )
		);

		$this->assertFalse( $profile['logging_enabled'] );
		$this->assertSame( 0, $profile['row_count'] );
		$this->assertSame( 0, $profile['usage']['calls'] );
		$this->assertTrue( $profile['effective']['plugin_eval']['prevent'] );
		$this->assertTrue( $profile['installed'] );
		$this->assertTrue( $profile['active'] );
		$this->assertSame( 'Demo', $profile['label'] );
	}

	public function test_admin_wires_profile_tab_and_links(): void {
		$source = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringContainsString( 'render_plugin_profile_tab', $source );
		$this->assertStringContainsString( "'profile'", $source );
		$this->assertStringContainsString( 'Plugin_Profile::profile_url', $source );
		$this->assertStringContainsString( 'handl-aicac-rule-', $source );
		$this->assertStringContainsString( 'Download this plugin’s activity as CSV', $source );
		// Activity action must be a GET form submit (not a lone <a>) so it leaves the profile screen.
		$this->assertStringContainsString( "SCREEN_SLUGS['activity']", $source );
		$this->assertMatchesRegularExpression(
			'/View this plugin in Activity.*?<\/button>/s',
			$source
		);
	}

	public function test_activity_url_filters_plugin_and_leaves_profile_args(): void {
		$url = Plugin_Profile::activity_url( 'woocommerce/woocommerce.php' );
		$this->assertStringContainsString( 'page=handl-aicac-activity', $url );
		$this->assertStringContainsString( 'handl_aicac_log_plugin=', $url );
		$this->assertStringContainsString( 'woocommerce', $url );
		$this->assertStringNotContainsString( 'handl_aicac_plugin=', $url );
		$this->assertStringContainsString( '#handl-aicac-log-wrap', $url );
	}
}
