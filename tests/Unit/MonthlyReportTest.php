<?php
/**
 * AICAC-REPORT-SCHED: monthly audit evidence email (#138).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Health;
use HandL\AICAC\Audit_Evidence;
use HandL\AICAC\Monthly_Report;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class MonthlyReportTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string,attachments:array}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		$GLOBALS['handl_aicac_test_cron'] = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Monthly_Report::SENT_OPTION_KEY );
		delete_option( Alert_Health::OPTION_KEY );
		update_option( 'admin_email', 'admin@example.com' );

		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message, $headers = '', $attachments = array() ) {
			self::$mails[] = array(
				'to'          => (string) $to,
				'subject'     => (string) $subject,
				'message'     => (string) $message,
				'attachments' => is_array( $attachments ) ? $attachments : array(),
			);
			return true;
		};
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'], $GLOBALS['handl_aicac_test_cron'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Monthly_Report::SENT_OPTION_KEY );
		delete_option( Alert_Health::OPTION_KEY );
		parent::tearDown();
	}

	public function test_disabled_does_not_schedule_or_send(): void {
		$policy = $this->persist_policy( array( 'monthly_report_enabled' => false ) );
		Monthly_Report::maybe_schedule( $policy );
		$this->assertFalse( wp_next_scheduled( Monthly_Report::CRON_HOOK ) );

		$out = Monthly_Report::send_if_due( $policy, array(), strtotime( '2026-08-01 12:00:00 UTC' ) );
		$this->assertFalse( $out['sent'] );
		$this->assertSame( 'inactive', $out['status'] );
		$this->assertSame( array(), self::$mails );
	}

	public function test_enabled_schedules_daily_and_sends_once_per_month(): void {
		$now = strtotime( '2026-08-01 12:00:00 UTC' );
		$log = array(
			$this->spend_row( 'a/a.php', 2.0, strtotime( '2026-07-15 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-07-20 10:00:00 UTC' ) ),
		);
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
		$policy = $this->persist_policy(
			array(
				'monthly_report_enabled' => true,
				'log_enabled'            => true,
				'alert_email'            => 'ops@example.com',
			)
		);

		Monthly_Report::maybe_schedule( $policy );
		$this->assertNotFalse( wp_next_scheduled( Monthly_Report::CRON_HOOK ) );

		$first = Monthly_Report::send_if_due( $policy, array( 'a/a.php' => array( 'Name' => 'A' ) ), $now );
		$this->assertTrue( $first['sent'] );
		$this->assertSame( 'report', $first['status'] );
		$this->assertSame( '2026-08', $first['period_ym'] );
		$this->assertCount( 1, self::$mails );
		$this->assertSame( 'ops@example.com', self::$mails[0]['to'] );
		$this->assertStringContainsString( 'monthly audit report', strtolower( self::$mails[0]['subject'] ) );
		$this->assertStringContainsString( 'Calls', self::$mails[0]['message'] );
		$this->assertNotEmpty( self::$mails[0]['attachments'] );

		$second = Monthly_Report::send_if_due( $policy, array(), $now + 3600 );
		$this->assertFalse( $second['sent'] );
		$this->assertSame( 'already_sent', $second['status'] );
		$this->assertCount( 1, self::$mails );
	}

	public function test_disable_unschedules(): void {
		$policy_on = $this->persist_policy(
			array(
				'monthly_report_enabled' => true,
				'log_enabled'            => true,
			)
		);
		Monthly_Report::maybe_schedule( $policy_on );
		$this->assertNotFalse( wp_next_scheduled( Monthly_Report::CRON_HOOK ) );

		$policy_off = $this->persist_policy(
			array(
				'monthly_report_enabled' => false,
				'log_enabled'            => true,
			)
		);
		Monthly_Report::maybe_schedule( $policy_off );
		$this->assertFalse( wp_next_scheduled( Monthly_Report::CRON_HOOK ) );
	}

	public function test_attachment_html_matches_on_demand_report(): void {
		$now = strtotime( '2026-08-01 12:00:00 UTC' );
		$log = array(
			$this->spend_row( 'a/a.php', 3.0, strtotime( '2026-07-10 10:00:00 UTC' ) ),
			$this->spend_row( 'b/b.php', 1.0, strtotime( '2026-07-18 10:00:00 UTC' ) ),
		);
		$policy  = $this->persist_policy( array( 'log_enabled' => true ) );
		$plugins = array(
			'a/a.php' => array( 'Name' => 'Plugin A' ),
			'b/b.php' => array( 'Name' => 'Plugin B' ),
		);

		$expected = Audit_Evidence::build_html(
			Audit_Evidence::build_report_data( $policy, $log, Monthly_Report::REPORT_WINDOW, $now, $plugins )
		);
		$actual = Monthly_Report::build_attachment_html( $policy, $log, $plugins, $now );
		$this->assertSame( $expected, $actual );
		$this->assertStringContainsString( 'AI governance report', $actual );
	}

	public function test_skip_path_when_no_retained_activity(): void {
		$now    = strtotime( '2026-08-01 12:00:00 UTC' );
		$policy = $this->persist_policy(
			array(
				'monthly_report_enabled' => true,
				'log_enabled'            => true,
				'alert_email'            => 'ops@example.com',
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );

		$out = Monthly_Report::send_if_due( $policy, array(), $now );
		$this->assertTrue( $out['sent'] );
		$this->assertSame( 'no_activity', $out['status'] );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'no activity', strtolower( self::$mails[0]['subject'] ) );
		$this->assertStringContainsString( 'No activity recorded', self::$mails[0]['message'] );
		$this->assertSame( array(), self::$mails[0]['attachments'] );
	}

	public function test_delivery_failure_records_alert_health(): void {
		$GLOBALS['handl_aicac_wp_mail'] = static function () {
			return false;
		};
		$now    = strtotime( '2026-08-01 12:00:00 UTC' );
		$policy = $this->persist_policy(
			array(
				'monthly_report_enabled' => true,
				'log_enabled'            => true,
				'alert_email'            => 'ops@example.com',
			)
		);
		update_option(
			Plugin::LOG_OPTION_KEY,
			array( $this->spend_row( 'a/a.php', 1.0, strtotime( '2026-07-10 10:00:00 UTC' ) ) ),
			false
		);

		$out = Monthly_Report::send_if_due( $policy, array(), $now );
		$this->assertFalse( $out['sent'] );
		$this->assertSame( 'failed', $out['status'] );

		$state = Alert_Health::get_state();
		$this->assertGreaterThanOrEqual( 1, (int) $state['email']['consecutive_failures'] );
		$this->assertTrue(
			Alert_Health::channel_configured( Alert_Health::CHANNEL_EMAIL, $policy )
		);
	}

	/**
	 * @param array<string,mixed> $extra
	 * @return array<string,mixed>
	 */
	private function persist_policy( array $extra ): array {
		$policy = array_merge(
			array(
				'log_enabled'             => true,
				'audit_only'              => false,
				'alert_email'             => 'ops@example.com',
				'monthly_report_enabled'  => false,
				'est_usd_input_per_m'     => 2.50,
				'est_usd_output_per_m'    => 10.00,
				'est_usd_provider_rates'  => array(),
				'log_limit'               => 200,
			),
			$extra
		);
		update_option( Plugin::OPTION_KEY, $policy, false );

		return Policy::get_policy();
	}

	/**
	 * @return array<string,mixed>
	 */
	private function spend_row( string $plugin, float $usd, int $ts ): array {
		$out_tokens = (int) round( $usd * 100000 );

		return array(
			'ts'            => $ts,
			'plugin'        => $plugin,
			'decision'      => 'allow',
			'operation'     => 'generate_text',
			'provider'      => 'openai',
			'input_tokens'  => 0,
			'output_tokens' => $out_tokens,
		);
	}
}
