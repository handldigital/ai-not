<?php
/**
 * Unit tests for AICAC-SELFTEST (#218).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Analytics;
use HandL\AICAC\Attribution;
use HandL\AICAC\CLI_Selftest;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Selftest;
use HandL\AICAC\Site_Health;
use HandL\AICAC\Usage_Trends;
use PHPUnit\Framework\TestCase;

final class SelftestTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-selftest.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-cli-selftest.php';
		self::$mails = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		unset( $GLOBALS['handl_aicac_test_gate_registered'] );
		unset( $_SERVER['REQUEST_URI'] );
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
		Attribution::force_plugin( null );
		unset( $GLOBALS['handl_aicac_wp_mail'], $GLOBALS['handl_aicac_test_gate_registered'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		parent::tearDown();
	}

	/**
	 * @param array<string,mixed> $overrides
	 */
	private function persist_policy( array $overrides = array() ): void {
		$base = array_merge(
			array(
				'default'      => 'allow',
				'log_enabled'  => true,
				'audit_only'   => false,
				'kill_switch'  => false,
				'alert_on_deny'=> true,
				'alert_email'  => 'ops@example.test',
				'plugins'      => array(
					'acme/acme.php' => 'allow',
				),
			),
			$overrides
		);
		update_option( Plugin::OPTION_KEY, $base, false );
	}

	public function test_healthy_run_passes_both_directions_and_restores_policy(): void {
		$this->persist_policy();
		$before = get_option( Plugin::OPTION_KEY );

		$report = Selftest::run();

		$this->assertTrue( $report['ok'], (string) $report['message'] );
		$this->assertSame( '', $report['issue'] );
		$this->assertTrue( $report['policy_identical'] );
		$this->assertSame( $before, get_option( Plugin::OPTION_KEY ) );

		$by = array();
		foreach ( $report['links'] as $link ) {
			$by[ $link['id'] ] = $link;
		}
		foreach ( array( 'gate', 'rule', 'deny', 'allow', 'log', 'alerts', 'policy_restored' ) as $id ) {
			$this->assertTrue( $by[ $id ]['pass'], $id . ' should pass' );
		}

		$this->assertSame( array(), self::$mails, 'selftest must not send alert mail' );
		$this->assertNotSame( Selftest::PLUGIN_BASENAME, Attribution::resolve_from_backtrace()['plugin'] );
	}

	public function test_second_run_leaves_policy_byte_identical(): void {
		$this->persist_policy();
		$first = Selftest::run();
		$this->assertTrue( $first['ok'] );
		$snapshot = get_option( Plugin::OPTION_KEY );
		$second   = Selftest::run();
		$this->assertTrue( $second['ok'] );
		$this->assertSame( $snapshot, get_option( Plugin::OPTION_KEY ) );
	}

	public function test_learn_mode_fails_and_names_activity_tab(): void {
		$this->persist_policy(
			array(
				'audit_only'  => true,
				'log_enabled' => true,
			)
		);
		$before = get_option( Plugin::OPTION_KEY );
		$report = Selftest::run();
		$this->assertFalse( $report['ok'] );
		$this->assertSame( 'learn_mode', $report['issue'] );
		$this->assertSame( 'activity', $report['settings_tab'] );
		$this->assertStringContainsString( 'Learn mode', $report['message'] );
		$this->assertSame( $before, get_option( Plugin::OPTION_KEY ) );
	}

	public function test_kill_switch_fails_and_names_rules_tab(): void {
		$this->persist_policy( array( 'kill_switch' => true ) );
		$report = Selftest::run();
		$this->assertFalse( $report['ok'] );
		$this->assertSame( 'kill_switch', $report['issue'] );
		$this->assertSame( 'rules', $report['settings_tab'] );
		$this->assertStringContainsString( 'Emergency stop', $report['message'] );
	}

	public function test_unregistered_gate_fails_with_named_issue(): void {
		$this->persist_policy();
		$GLOBALS['handl_aicac_test_gate_registered'] = false;
		$report = Selftest::run();
		$this->assertFalse( $report['ok'] );
		$this->assertSame( 'gate_unregistered', $report['issue'] );
		$this->assertStringContainsString( 'AI blocking is unavailable', $report['message'] );
	}

	public function test_synthetic_rows_are_excluded_from_totals(): void {
		$this->persist_policy();
		Selftest::run();
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $log );

		$synthetic = 0;
		foreach ( $log as $row ) {
			if ( is_array( $row ) && Selftest::is_synthetic_row( $row ) ) {
				++$synthetic;
				$this->assertFalse( Usage_Trends::is_activity_row( $row ) );
			}
		}
		$this->assertGreaterThanOrEqual( 2, $synthetic );

		$plugins = array( 'acme/acme.php' => array( 'Name' => 'Acme' ) );
		$agg     = Analytics::aggregate_from_log( $log, $plugins );
		$this->assertSame( 0, $agg['summary']['calls'] );
	}

	public function test_cli_execute_success_and_failure(): void {
		$this->persist_policy();
		$ok = CLI_Selftest::execute();
		$this->assertSame( 0, $ok['exit_code'] );
		$this->assertSame( 'Enforcement check passed.', $ok['success'] ?? '' );

		$this->persist_policy( array( 'audit_only' => true, 'log_enabled' => true ) );
		$fail = CLI_Selftest::execute();
		$this->assertSame( 1, $fail['exit_code'] );
		$this->assertStringContainsString( 'Learn mode', (string) ( $fail['error'] ?? '' ) );
	}

	public function test_site_health_formats_pass_and_fail(): void {
		$pass = Selftest::format_site_health_result(
			array(
				'ok'           => true,
				'settings_tab' => 'dashboard',
				'message'      => '',
				'links'        => array(
					array(
						'id'    => 'deny',
						'pass'  => true,
						'label' => 'Blocked',
					),
				),
			)
		);
		$this->assertSame( 'good', $pass['status'] );
		$this->assertSame( 'AI blocking is working', $pass['label'] );
		$this->assertSame( Selftest::SITE_HEALTH_SLUG, $pass['test'] );

		$fail = Selftest::format_site_health_result(
			array(
				'ok'           => false,
				'settings_tab' => 'activity',
				'message'      => 'Learn mode is on.',
				'links'        => array(),
			)
		);
		$this->assertSame( 'critical', $fail['status'] );
		$this->assertSame( 'AI blocking did not work', $fail['label'] );
		$this->assertStringContainsString( 'Learn mode is on.', $fail['description'] );
		$this->assertStringContainsString( 'page=handl-aicac-activity', $fail['actions'] );
	}

	public function test_site_health_registers_selftest(): void {
		$tests = Site_Health::instance()->register_tests( array() );
		$this->assertArrayHasKey( Selftest::SITE_HEALTH_SLUG, $tests['direct'] );
		$this->assertArrayHasKey( Site_Health::TEST_SLUG, $tests['direct'] );
	}
}
