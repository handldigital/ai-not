<?php
/**
 * Unit tests for Site_Health classification (AICAC-HEALTH).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Site_Health;
use PHPUnit\Framework\TestCase;

final class SiteHealthTest extends TestCase {

	/**
	 * @return array<string,bool>
	 */
	private function active( string ...$basenames ): array {
		$out = array();
		foreach ( $basenames as $basename ) {
			$out[ $basename ] = true;
		}
		return $out;
	}

	/**
	 * @return array<string,array<string,mixed>>
	 */
	private function installed_ai_consumer(): array {
		return array(
			'ai/ai.php'           => array( 'Name' => 'AI' ),
			'example/consumer.php' => array(
				'Name'             => 'Example AI Consumer',
				'RequiresPlugins'  => 'ai',
			),
		);
	}

	public function test_enforcing_ok_when_logging_and_ai_client_present(): void {
		$policy = array(
			'kill_switch' => false,
			'log_enabled' => true,
			'audit_only'  => false,
			'default'     => 'allow',
			'plugins'     => array( 'foo/foo.php' => 'deny' ),
		);

		$snapshot = Site_Health::build_snapshot(
			$policy,
			$this->installed_ai_consumer(),
			$this->active( 'ai/ai.php' )
		);

		$this->assertSame( 'good', $snapshot['status'] );
		$this->assertSame( 'ok', $snapshot['issue'] );
		$this->assertSame( 1, $snapshot['deny_rule_count'] );
		$this->assertTrue( $snapshot['has_ai_client_plugins'] );
	}

	public function test_observing_ok_in_learn_mode(): void {
		$policy = array(
			'kill_switch' => false,
			'audit_only'  => true,
			'log_enabled' => false,
		);

		$snapshot = Site_Health::build_snapshot(
			$policy,
			$this->installed_ai_consumer(),
			$this->active( 'ai/ai.php' )
		);

		$this->assertSame( 'good', $snapshot['status'] );
		$this->assertSame( 'observing', $snapshot['issue'] );
		$this->assertSame( 'activity', $snapshot['settings_tab'] );
		$this->assertTrue( $snapshot['logging_active'] );
	}

	public function test_recommended_kill_switch_with_zero_exceptions(): void {
		$policy = array(
			'kill_switch'             => true,
			'kill_switch_exceptions'  => array(),
			'log_enabled'             => true,
		);

		$snapshot = Site_Health::build_snapshot(
			$policy,
			$this->installed_ai_consumer(),
			$this->active( 'ai/ai.php' )
		);

		$this->assertSame( 'recommended', $snapshot['status'] );
		$this->assertSame( 'kill_switch_zero_exceptions', $snapshot['issue'] );
		$this->assertSame( 'rules', $snapshot['settings_tab'] );
	}

	public function test_kill_switch_with_exceptions_is_not_recommended(): void {
		$policy = array(
			'kill_switch'            => true,
			'kill_switch_exceptions' => array( 'foo/foo.php' ),
			'log_enabled'            => true,
		);

		$snapshot = Site_Health::build_snapshot(
			$policy,
			$this->installed_ai_consumer(),
			$this->active( 'ai/ai.php' )
		);

		$this->assertSame( 'good', $snapshot['status'] );
		$this->assertSame( 'ok', $snapshot['issue'] );
		$this->assertSame( 1, $snapshot['kill_switch_exceptions'] );
	}

	public function test_recommended_alerts_without_logging(): void {
		$policy = array(
			'kill_switch'     => false,
			'log_enabled'   => false,
			'audit_only'    => false,
			'alert_on_deny' => true,
		);

		$snapshot = Site_Health::build_snapshot(
			$policy,
			$this->installed_ai_consumer(),
			$this->active( 'ai/ai.php' )
		);

		$this->assertSame( 'recommended', $snapshot['status'] );
		$this->assertSame( 'alerts_without_logging', $snapshot['issue'] );
		$this->assertSame( 'activity', $snapshot['settings_tab'] );
	}

	public function test_informational_when_no_ai_client_plugins(): void {
		$policy = array(
			'kill_switch' => false,
			'log_enabled' => true,
		);

		$snapshot = Site_Health::build_snapshot(
			$policy,
			array( 'hello/hello.php' => array( 'Name' => 'Hello Dolly' ) ),
			$this->active( 'hello/hello.php' )
		);

		$this->assertSame( 'good', $snapshot['status'] );
		$this->assertSame( 'no_ai_client_plugins', $snapshot['issue'] );
		$this->assertFalse( $snapshot['has_ai_client_plugins'] );
	}

	public function test_detects_ai_client_via_requires_plugins(): void {
		$installed = array(
			'example/consumer.php' => array(
				'Name'            => 'Consumer',
				'RequiresPlugins' => 'ai',
			),
		);

		$this->assertTrue(
			Site_Health::has_ai_client_plugins(
				$installed,
				$this->active( 'example/consumer.php' )
			)
		);
	}

	public function test_count_deny_rules_includes_default_plugin_and_family(): void {
		$policy = array(
			'default'    => 'deny',
			'plugins'    => array( 'a/a.php' => 'deny', 'b/b.php' => 'allow' ),
			'operations' => array(
				'a/a.php' => array( 'text' => 'deny', 'image' => 'allow' ),
			),
		);

		$this->assertSame( 3, Site_Health::count_deny_rules( $policy ) );
	}

	public function test_alerts_configured_for_webhook_and_weekly(): void {
		$this->assertTrue(
			Site_Health::alerts_configured(
				array( 'alert_webhook_url' => 'https://example.test/hook' )
			)
		);
		$this->assertTrue(
			Site_Health::alerts_configured(
				array( 'weekly_report_enabled' => true )
			)
		);
	}

	public function test_format_result_links_to_settings_for_recommended(): void {
		$result = Site_Health::format_site_health_result(
			array(
				'status'                => 'recommended',
				'issue'                 => 'alerts_without_logging',
				'settings_tab'          => 'activity',
				'kill_switch'           => false,
				'logging_active'        => false,
				'deny_rule_count'       => 0,
				'has_ai_client_plugins' => true,
			)
		);

		$this->assertSame( 'recommended', $result['status'] );
		$this->assertStringContainsString( 'handl_aicac_tab=activity', $result['actions'] );
		$this->assertSame( Site_Health::TEST_SLUG, $result['test'] );
	}
}
