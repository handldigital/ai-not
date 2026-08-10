<?php
/**
 * Unit tests for AICAC-ANOMALY baseline-deviation alerts.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Anomaly;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class AnomalyAlertTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Anomaly::FIRED_OPTION_KEY );
		update_option( 'admin_email', 'admin@example.com' );

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
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Anomaly::FIRED_OPTION_KEY );
		parent::tearDown();
	}

	public function test_decide_cold_start_no_baseline(): void {
		$d = Anomaly::decide_spike( array( 0, 0, 0, 0, 0, 0, 0 ), 100.0, 3.0, 20.0 );
		$this->assertTrue( $d['cold_start'] );
		$this->assertFalse( $d['alert'] );
	}

	public function test_decide_quiet_plugin_below_floor(): void {
		// Average 5/day, 3× = 15, floor 20 → threshold 20; today 15 → no alert.
		$d = Anomaly::decide_spike( array( 5, 5, 5, 5, 5, 5, 5 ), 15.0, 3.0, 20.0 );
		$this->assertFalse( $d['cold_start'] );
		$this->assertFalse( $d['alert'] );
		$this->assertSame( 20.0, $d['threshold'] );
	}

	public function test_decide_genuine_three_x_spike(): void {
		// Average 100/day, 3× = 300, floor 20 → threshold 300; today 350 → alert.
		$d = Anomaly::decide_spike( array( 100, 100, 100, 100, 100, 100, 100 ), 350.0, 3.0, 20.0 );
		$this->assertFalse( $d['cold_start'] );
		$this->assertTrue( $d['alert'] );
		$this->assertSame( 100.0, $d['baseline'] );
		$this->assertSame( 300.0, $d['threshold'] );
		$this->assertSame( 350.0, $d['observed'] );
	}

	public function test_readiness_logging_off_and_ttl_too_short(): void {
		$off = Anomaly::readiness(
			array(
				'anomaly_alert_enabled' => true,
				'log_enabled'           => false,
				'audit_only'            => false,
			)
		);
		$this->assertFalse( $off['ok'] );
		$this->assertSame( 'logging_off', $off['reason'] );
		$this->assertNotSame( '', Anomaly::degradation_notice(
			array(
				'anomaly_alert_enabled' => true,
				'log_enabled'           => false,
				'audit_only'            => false,
			)
		) );

		$ttl = Anomaly::readiness(
			array(
				'anomaly_alert_enabled' => true,
				'log_enabled'           => true,
				'log_max_age_days'      => 3,
			)
		);
		$this->assertFalse( $ttl['ok'] );
		$this->assertSame( 'ttl_too_short', $ttl['reason'] );
	}

	public function test_integration_spike_fires_email_with_plugin_and_activity_link(): void {
		$now  = strtotime( '2026-08-10 15:00:00 UTC' );
		$log  = array();
		// 7 prior days: 10 calls each with tokens.
		for ( $d = 1; $d <= 7; $d++ ) {
			$day_ts = strtotime( sprintf( '2026-08-%02d 12:00:00 UTC', 10 - $d ) );
			for ( $i = 0; $i < 10; $i++ ) {
				$log[] = array(
					'ts'            => $day_ts + $i,
					'plugin'        => 'acme/acme.php',
					'decision'      => 'allow',
					'input_tokens'  => 1000,
					'output_tokens' => 0,
					'provider'      => 'openai',
				);
			}
		}
		// Today: 50 calls (5× baseline of 10, well above floor 20).
		for ( $i = 0; $i < 50; $i++ ) {
			$log[] = array(
				'ts'            => strtotime( '2026-08-10 10:00:00 UTC' ) + $i,
				'plugin'        => 'acme/acme.php',
				'decision'      => 'allow',
				'input_tokens'  => 1000,
				'output_tokens' => 0,
				'provider'      => 'openai',
			);
		}
		update_option( Plugin::LOG_OPTION_KEY, $log, false );

		$policy = array(
			'log_enabled'            => true,
			'audit_only'             => false,
			'anomaly_alert_enabled'  => true,
			'anomaly_multiplier'     => 3.0,
			'anomaly_floor_calls'    => 20,
			'anomaly_floor_spend'    => 1.0,
			'alert_email'            => 'admin@example.com',
			'est_usd_input_per_m'    => 2.5,
			'est_usd_output_per_m'   => 10.0,
		);
		update_option( Plugin::OPTION_KEY, $policy, false );

		Anomaly::maybe_evaluate( Policy::get_policy(), $now );

		$this->assertNotEmpty( self::$mails );
		$mail = self::$mails[0];
		$this->assertStringContainsString( 'usage spike', strtolower( $mail['subject'] ) );
		$this->assertStringContainsString( 'acme/acme.php', $mail['message'] );
		$this->assertStringContainsString( 'handl_aicac_log_plugin', $mail['message'] );
		$this->assertStringContainsString( 'Recent daily average', $mail['message'] );
		$this->assertStringContainsString( 'Today so far', $mail['message'] );

		// 24h dedupe.
		$before = count( self::$mails );
		Anomaly::maybe_evaluate( Policy::get_policy(), $now );
		$this->assertSame( $before, count( self::$mails ) );
	}

	public function test_disabled_never_fires(): void {
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => time(),
					'plugin'   => 'acme/acme.php',
					'decision' => 'allow',
				),
			),
			false
		);
		$policy = array(
			'log_enabled'           => true,
			'anomaly_alert_enabled' => false,
		);
		Anomaly::maybe_evaluate( $policy );
		$this->assertSame( array(), self::$mails );
	}

	public function test_activity_url_includes_plugin_filter(): void {
		$url = Anomaly::activity_url_for_plugin( 'foo/bar.php' );
		$this->assertStringContainsString( 'handl_aicac_tab=activity', $url );
		$this->assertStringContainsString( 'handl_aicac_log_plugin', $url );
		$this->assertStringContainsString( 'foo', $url );
	}
}
