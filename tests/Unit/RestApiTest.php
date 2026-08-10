<?php
/**
 * Unit tests for read-only REST payloads (AICAC-REST).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Rest;
use HandL\AICAC\Site_Health;
use PHPUnit\Framework\TestCase;

final class RestApiTest extends TestCase {

	public function test_route_definitions_are_get_only(): void {
		$routes = Rest::route_definitions();
		$this->assertNotEmpty( $routes );

		$paths = array();
		foreach ( $routes as $def ) {
			$this->assertSame( 'GET', $def['methods'] );
			$this->assertStringStartsWith( '/', $def['route'] );
			$paths[] = $def['route'];
		}

		$this->assertContains( '/policy', $paths );
		$this->assertContains( '/activity/summary', $paths );
		$this->assertContains( '/health', $paths );
		$this->assertCount( 3, $routes );
	}

	public function test_namespace_constant(): void {
		$this->assertSame( 'handl-aicac/v1', Rest::NAMESPACE );
	}

	public function test_build_policy_payload_counts_and_flags(): void {
		$policy = array(
			'default'                => 'deny',
			'plugins'                => array(
				'a/a.php' => 'allow',
				'b/b.php' => 'deny',
				'c/c.php' => 'deny',
			),
			'operations'             => array(
				'a/a.php' => array(
					'text'  => 'allow',
					'image' => 'deny',
				),
			),
			'denied_tools'           => array( 'tool-one', 'tool-two' ),
			'kill_switch'            => true,
			'kill_switch_exceptions' => array( 'a/a.php' ),
			'role_gate_enabled'      => true,
			'allowed_roles'          => array( 'administrator', 'editor' ),
			'log_enabled'            => true,
			'audit_only'             => false,
			'log_limit'              => 100,
			'log_max_age_days'       => 14,
		);

		$payload = Rest::build_policy_payload( $policy );

		$this->assertSame( 'deny', $payload['default'] );
		$this->assertSame( array( 'allow' => 1, 'deny' => 2 ), $payload['plugin_rules_by_decision'] );
		$this->assertSame( array( 'allow' => 1, 'deny' => 1 ), $payload['operation_rules_by_decision'] );
		$this->assertSame( 2, $payload['denied_tools_count'] );
		$this->assertTrue( $payload['kill_switch']['enabled'] );
		$this->assertSame( 1, $payload['kill_switch']['exception_count'] );
		$this->assertTrue( $payload['role_gate']['enabled'] );
		$this->assertSame( 2, $payload['role_gate']['allowed_role_count'] );
		$this->assertTrue( $payload['log_enabled'] );
		$this->assertFalse( $payload['audit_only'] );
		$this->assertSame( 100, $payload['log_limit'] );
		$this->assertSame( 14, $payload['log_max_age_days'] );

		// Aggregates only — no raw rule maps.
		$this->assertArrayNotHasKey( 'plugins', $payload );
		$this->assertArrayNotHasKey( 'operations', $payload );
		$this->assertArrayNotHasKey( 'denied_tools', $payload );
		$this->assertArrayNotHasKey( 'alert_email', $payload );
		$this->assertArrayNotHasKey( 'alert_webhook_url', $payload );
	}

	public function test_activity_summary_logging_disabled_has_no_fabricated_zeros(): void {
		$policy = array(
			'log_enabled' => false,
			'audit_only'  => false,
		);

		$payload = Rest::build_activity_summary( $policy, array(), '7d', time() );

		$this->assertSame( 'logging_disabled', $payload['status'] );
		$this->assertSame( '7d', $payload['window'] );
		$this->assertArrayNotHasKey( 'calls_by_decision', $payload );
		$this->assertArrayNotHasKey( 'estimated_spend_usd', $payload );
		$this->assertArrayNotHasKey( 'top_plugins', $payload );
		$this->assertArrayNotHasKey( 'shadow_ai_observation_count', $payload );
	}

	public function test_activity_summary_no_data_when_window_empty(): void {
		$now  = 1_700_000_000;
		$log  = array(
			array(
				'ts'       => $now - 900_000, // outside 7d
				'decision' => 'allow',
				'plugin'   => 'old/old.php',
			),
		);
		$policy = array(
			'log_enabled' => true,
			'audit_only'  => false,
		);

		$payload = Rest::build_activity_summary( $policy, $log, '7d', $now );

		$this->assertSame( 'no_data', $payload['status'] );
		$this->assertArrayNotHasKey( 'calls_by_decision', $payload );
	}

	public function test_activity_summary_ok_aggregates_without_pii(): void {
		$now = 1_700_000_000;
		$log = array(
			array(
				'ts'            => $now - 100,
				'decision'      => 'allow',
				'plugin'        => 'acme/acme.php',
				'provider'      => 'openai',
				'input_tokens'  => 1_000_000,
				'output_tokens' => 0,
				'prompt'        => 'SECRET PROMPT MUST NOT LEAK',
				'uri'           => '/wp-admin/secret?token=abc',
				'user_id'       => 42,
			),
			array(
				'ts'       => $now - 50,
				'decision' => 'deny',
				'plugin'   => 'acme/acme.php',
			),
			array(
				'ts'              => $now - 40,
				'channel'         => 'direct_http',
				'decision'        => 'observe',
				'count'           => 3,
				'shadow_provider' => 'anthropic',
				'plugin'          => 'shadow/shadow.php',
			),
			array(
				'ts'       => $now - 30,
				'decision' => 'allow',
				'plugin'   => 'other/other.php',
			),
		);

		$policy = array(
			'log_enabled'         => true,
			'est_usd_input_per_m' => 2.50,
			'est_usd_output_per_m'=> 10.00,
		);

		$payload = Rest::build_activity_summary( $policy, $log, '7d', $now );

		$this->assertSame( 'ok', $payload['status'] );
		$this->assertSame( array( 'allow' => 2, 'deny' => 1 ), $payload['calls_by_decision'] );
		$this->assertSame( 3, $payload['ai_client_call_count'] );
		$this->assertSame( 3, $payload['shadow_ai_observation_count'] );
		$this->assertSame( 2.5, $payload['estimated_spend_usd'] );

		$this->assertNotEmpty( $payload['top_plugins'] );
		$this->assertSame( 'acme/acme.php', $payload['top_plugins'][0]['plugin'] );

		$json = wp_json_encode( $payload );
		$this->assertIsString( $json );
		$this->assertStringNotContainsString( 'SECRET PROMPT', $json );
		$this->assertStringNotContainsString( 'token=abc', $json );
		$this->assertStringNotContainsString( '"user_id"', $json );
	}

	public function test_window_sanitize_and_filter(): void {
		$this->assertSame( '7d', Rest::sanitize_window( 'nope' ) );
		$this->assertSame( '1d', Rest::sanitize_window( '1d' ) );
		$this->assertSame( 'all', Rest::sanitize_window( 'ALL' ) );

		$now = 1_700_000_000;
		$log = array(
			array( 'ts' => $now - 100, 'decision' => 'allow' ),
			array( 'ts' => $now - 200_000, 'decision' => 'deny' ), // outside 1d
		);

		$day = Rest::filter_log_by_window( $log, '1d', $now );
		$this->assertCount( 1, $day );
		$this->assertSame( $now - 100, $day[0]['ts'] );

		$all = Rest::filter_log_by_window( $log, 'all', $now );
		$this->assertCount( 2, $all );
	}

	public function test_health_payload_matches_site_health_snapshot(): void {
		$policy = array(
			'kill_switch'            => true,
			'kill_switch_exceptions' => array(),
			'log_enabled'            => true,
			'audit_only'             => false,
			'default'                => 'allow',
			'plugins'                => array( 'x/x.php' => 'deny' ),
		);

		$installed = array(
			'ai/ai.php' => array( 'Name' => 'AI' ),
		);
		$active = array( 'ai/ai.php' => true );

		$from_rest  = Rest::build_health_payload( $policy, $installed, $active );
		$from_health = Site_Health::build_snapshot( $policy, $installed, $active );

		$this->assertSame( $from_health, $from_rest );
		$this->assertSame( 'recommended', $from_rest['status'] );
		$this->assertSame( 'kill_switch_zero_exceptions', $from_rest['issue'] );
	}

	public function test_permission_check_requires_manage_options(): void {
		$rest = Rest::instance();

		$GLOBALS['handl_aicac_test_current_user_can'] = false;
		$this->assertFalse( $rest->permission_check() );

		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$this->assertTrue( $rest->permission_check() );

		unset( $GLOBALS['handl_aicac_test_current_user_can'] );
	}
}
