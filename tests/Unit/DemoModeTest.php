<?php
/**
 * AICAC-DEMO-MODE (#300).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alerts;
use HandL\AICAC\Audit_Export;
use HandL\AICAC\Chat_Notify;
use HandL\AICAC\Demo_Mode;
use HandL\AICAC\Governance_Coverage;
use HandL\AICAC\Incident;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Siem;
use HandL\AICAC\Usage_Trends;
use PHPUnit\Framework\TestCase;

final class DemoModeTest extends TestCase {

	/** @var list<array{url:string,args:array<string,mixed>}> */
	public static array $posts = array();

	/** @var int */
	public static int $mail_calls = 0;

	/** @var list<string> */
	private array $syslog = array();

	protected function setUp(): void {
		parent::setUp();
		self::$posts      = array();
		self::$mail_calls = 0;
		$this->syslog     = array();
		Demo_Mode::reset_for_tests();
		Chat_Notify::reset_for_tests();
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_syslog']             = function ( string $line ): void {
			$this->syslog[] = $line;
		};
		$GLOBALS['handl_aicac_wp_remote_post'] = static function ( string $url, array $args ) {
			DemoModeTest::$posts[] = array(
				'url'  => $url,
				'args' => $args,
			);
			return array(
				'response' => array( 'code' => 200 ),
				'body'     => 'ok',
			);
		};
		$GLOBALS['handl_aicac_wp_mail'] = static function () {
			++DemoModeTest::$mail_calls;
			return true;
		};
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Demo_Mode::OPTION_KEY );
		delete_option( Siem::FILE_PATH_OPTION );
	}

	protected function tearDown(): void {
		Demo_Mode::reset_for_tests();
		Chat_Notify::reset_for_tests();
		unset(
			$GLOBALS['handl_aicac_wp_remote_post'],
			$GLOBALS['handl_aicac_wp_mail'],
			$GLOBALS['handl_aicac_syslog']
		);
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Demo_Mode::OPTION_KEY );
		parent::tearDown();
	}

	/**
	 * @return array<string,mixed>
	 */
	private function options_snapshot(): array {
		$opts = $GLOBALS['handl_aicac_test_options'] ?? array();
		ksort( $opts );

		return $opts;
	}

	/**
	 * @return array{decision:string,operation:string,provider:string,model:string,plugin:string}
	 */
	private function empty_filters(): array {
		return array(
			'decision'  => '',
			'operation' => '',
			'provider'  => '',
			'model'     => '',
			'plugin'    => '',
		);
	}

	public function test_init_registers_expire_cron(): void {
		Demo_Mode::init();
		$actions = $GLOBALS['handl_aicac_test_added_actions'] ?? array();
		$this->assertContains( Demo_Mode::CRON_HOOK, $actions );
	}

	public function test_seed_remove_round_trip_is_byte_identical(): void {
		Policy::save_policy(
			array(
				'plugins'     => array( 'real/real.php' => 'allow' ),
				'default'     => 'observe',
				'log_enabled' => true,
			)
		);
		$before = $this->options_snapshot();
		$now    = 1_700_000_000;
		$out    = Demo_Mode::seed( $now );
		$this->assertTrue( $out['ok'] );
		$this->assertGreaterThan( 0, $out['seeded'] );
		$this->assertNotSame( $before, $this->options_snapshot() );
		$this->assertSame( array( 'real/real.php' => 'allow' ), Policy::get_policy()['plugins'] );

		$removed = Demo_Mode::remove();
		$this->assertTrue( $removed['ok'] );
		$this->assertSame( $before, $this->options_snapshot() );
	}

	public function test_seed_never_writes_demo_plugins_into_rules(): void {
		Policy::save_policy(
			array(
				'plugins' => array( 'keep/keep.php' => 'deny' ),
				'default' => 'observe',
			)
		);
		Demo_Mode::seed( 1_700_000_000 );
		$policy = Policy::get_policy();
		$this->assertSame( array( 'keep/keep.php' => 'deny' ), $policy['plugins'] );
		$this->assertArrayNotHasKey( Demo_Mode::PLUGIN_SEO, $policy['plugins'] );
		$this->assertArrayNotHasKey( Demo_Mode::PLUGIN_CHAT, $policy['plugins'] );
	}

	public function test_activity_incident_trends_nonempty_after_seed(): void {
		$now = 1_700_000_000;
		Demo_Mode::seed( $now );
		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertNotEmpty( $log );
		foreach ( $log as $row ) {
			$this->assertTrue( Demo_Mode::is_demo_row( $row ) );
		}

		$incidents = Incident::list( $log );
		$this->assertNotEmpty( $incidents );

		$trends = Usage_Trends::compute( $log, Policy::get_policy(), array(), $now );
		$this->assertIsArray( $trends );
		$this->assertGreaterThanOrEqual( Usage_Trends::MIN_WEEKS_WITH_DATA, (int) $trends['weeks_with_data'] );
	}

	public function test_alerts_skip_demo_rows(): void {
		$event = array(
			'decision' => 'deny',
			'ts'       => 1_700_000_000,
			'plugin'   => Demo_Mode::PLUGIN_CHAT,
			'demo'     => true,
		);
		$policy = array(
			'alert_on_deny' => true,
			'alert_mode'    => 'immediate',
			'alert_email'   => 'admin@example.com',
			'audit_only'    => false,
		);
		Alerts::maybe_notify_denial( $event, $policy );
		Alerts::flush_deferred();
		$this->assertSame( 0, self::$mail_calls );
	}

	public function test_siem_skips_demo_rows(): void {
		$policy = array(
			'siem_syslog_enabled' => true,
			'siem_format'         => Siem::FORMAT_JSON,
		);
		$ok = Siem::observe(
			array(
				'decision' => 'deny',
				'plugin'   => Demo_Mode::PLUGIN_CHAT,
				'demo'     => true,
			),
			$policy
		);
		$this->assertFalse( $ok );
		$this->assertSame( array(), $this->syslog );
	}

	public function test_chat_notify_skips_demo_rows(): void {
		Chat_Notify::save_config(
			array(
				'slack_url' => 'https://hooks.slack.com/services/T00/B00/xxx',
			)
		);
		Chat_Notify::observe(
			array(
				'retry_storm' => true,
				'plugin'      => Demo_Mode::PLUGIN_CHAT,
				'demo'        => true,
			),
			array()
		);
		$this->assertCount( 0, self::$posts );
	}

	public function test_export_digest_and_score_skip_demo_rows(): void {
		$now = 1_700_000_000;
		Demo_Mode::seed( $now );
		$log    = get_option( Plugin::LOG_OPTION_KEY );
		$policy = Policy::get_policy();
		$this->assertIsArray( $log );

		$csv_rows = Audit_Export::filtered_rows( $log, $this->empty_filters() );
		$this->assertSame( array(), $csv_rows );

		$this->assertSame( array(), Governance_Coverage::ai_active_plugins( $log ) );
		$this->assertSame( array(), Governance_Coverage::plugins_with_recorded_spend( $log, $policy ) );

		$real_only = Demo_Mode::without_demo( $log );
		$this->assertSame( array(), $real_only );
	}

	public function test_copy_strings(): void {
		$this->assertSame( 'Showing sample data', Demo_Mode::BANNER );
		$this->assertSame( 'Preview with sample data', Demo_Mode::CTA_SEED );
		$this->assertSame( 'Remove sample data', Demo_Mode::CTA_REMOVE );
	}

	public function test_expires_after_seven_days(): void {
		$now = 1_700_000_000;
		Demo_Mode::seed( $now );
		$this->assertTrue( Demo_Mode::is_active() );
		Demo_Mode::maybe_expire( $now + Demo_Mode::TTL_SECONDS );
		$this->assertFalse( Demo_Mode::is_active() );
		$this->assertFalse( get_option( Plugin::LOG_OPTION_KEY, false ) );
	}

	public function test_remove_keeps_real_rows_added_before_seed(): void {
		$real = array(
			'ts'       => 1_699_000_000,
			'plugin'   => 'real/real.php',
			'decision' => 'allow',
		);
		update_option( Plugin::LOG_OPTION_KEY, array( $real ), false );
		Demo_Mode::seed( 1_700_000_000 );
		Demo_Mode::remove();
		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertSame( array( $real ), $log );
	}

	public function test_append_log_event_does_not_emit_demo(): void {
		Policy::save_policy(
			array(
				'log_enabled'         => true,
				'siem_syslog_enabled' => true,
				'alert_on_deny'       => true,
				'alert_email'         => 'admin@example.com',
			)
		);
		Chat_Notify::save_config(
			array(
				'slack_url' => 'https://hooks.slack.com/services/T00/B00/xxx',
			)
		);
		Policy::append_log_event(
			array(
				'ts'          => 1_700_000_000,
				'plugin'      => Demo_Mode::PLUGIN_CHAT,
				'decision'    => 'deny',
				'retry_storm' => true,
				'demo'        => true,
			)
		);
		Alerts::flush_deferred();
		$this->assertSame( array(), $this->syslog );
		$this->assertCount( 0, self::$posts );
		$this->assertSame( 0, self::$mail_calls );
	}
}
