<?php
/**
 * AICAC-TAMPER (#222): deactivation dead-man's switch.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Site_Health;
use HandL\AICAC\Tamper;
use PHPUnit\Framework\TestCase;

final class TamperTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Tamper::DEACTIVATED_AT_OPTION );
		delete_option( Tamper::DEACTIVATED_BY_OPTION );
		delete_option( Tamper::NOTICE_OPTION );
		unset( $GLOBALS['handl_aicac_test_actor'] );
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
		unset( $GLOBALS['handl_aicac_wp_mail'], $GLOBALS['handl_aicac_test_actor'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Tamper::DEACTIVATED_AT_OPTION );
		delete_option( Tamper::DEACTIVATED_BY_OPTION );
		delete_option( Tamper::NOTICE_OPTION );
		parent::tearDown();
	}

	public function test_deactivate_logs_and_emails_even_when_logging_off(): void {
		Policy::save_policy(
			array(
				'log_enabled' => false,
				'audit_only'  => false,
				'alert_email' => 'ops@example.com',
			)
		);
		$GLOBALS['handl_aicac_test_actor'] = 'alice';

		Tamper::on_deactivate( 1_700_000_000 );

		$this->assertSame( 1_700_000_000, (int) get_option( Tamper::DEACTIVATED_AT_OPTION ) );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertCount( 1, $log );
		$this->assertSame( Tamper::DECISION_STOPPED, $log[0]['decision'] );
		$this->assertSame( Tamper::CHANNEL, $log[0]['channel'] );
		$this->assertSame( 'alice', $log[0]['actor'] );
		$this->assertSame( 1_700_000_000, (int) $log[0]['ts'] );

		$this->assertCount( 1, self::$mails );
		$this->assertSame( 'ops@example.com', self::$mails[0]['to'] );
		$this->assertStringContainsString( 'deactivated', strtolower( self::$mails[0]['subject'] ) );
		$this->assertStringContainsString( 'alice', self::$mails[0]['message'] );
		$this->assertStringContainsString(
			'Deny rules and budgets are no longer enforced, and alerts will not be sent.',
			self::$mails[0]['message']
		);
	}

	public function test_deactivate_records_wp_cli_actor(): void {
		Policy::save_policy( array( 'alert_email' => 'ops@example.com' ) );
		$GLOBALS['handl_aicac_test_actor'] = 'wp-cli';

		Tamper::on_deactivate( 1_700_000_100 );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertSame( 'wp-cli', $log[0]['actor'] );
	}

	public function test_activate_without_prior_deactivation_is_noop(): void {
		Tamper::on_activate( 1_700_000_200 );
		$this->assertFalse( get_option( Tamper::NOTICE_OPTION, false ) );
		$this->assertSame( array(), get_option( Plugin::LOG_OPTION_KEY, array() ) );
	}

	public function test_reactivate_logs_gap_and_sets_notice(): void {
		Policy::save_policy( array( 'log_enabled' => false ) );
		$GLOBALS['handl_aicac_test_actor'] = 'alice';

		Tamper::on_deactivate( 1_700_000_000 );
		self::$mails = array();

		// Different user reactivates — notice must still name the stopper.
		$GLOBALS['handl_aicac_test_actor'] = 'bob';
		Tamper::on_activate( 1_700_000_500 );

		$this->assertFalse( get_option( Tamper::DEACTIVATED_AT_OPTION, false ) );
		$this->assertFalse( get_option( Tamper::DEACTIVATED_BY_OPTION, false ) );

		$notice = get_option( Tamper::NOTICE_OPTION );
		$this->assertIsArray( $notice );
		$this->assertSame( 1_700_000_000, (int) $notice['from'] );
		$this->assertSame( 1_700_000_500, (int) $notice['to'] );
		$this->assertSame( 'alice', $notice['actor'] );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertCount( 2, $log );
		$this->assertSame( Tamper::DECISION_RESUMED, $log[1]['decision'] );
		$this->assertSame( 1_700_000_000, (int) $log[1]['deactivated_at'] );
		$this->assertSame( 'bob', $log[1]['actor'] );
		$this->assertSame( 'alice', $log[1]['stopped_by'] );
		$this->assertSame( array(), self::$mails );
	}

	public function test_recent_gap_windows_from_log(): void {
		$now = 1_700_100_000;
		$log = array(
			array(
				'ts'             => $now - 100,
				'decision'       => Tamper::DECISION_RESUMED,
				'channel'        => Tamper::CHANNEL,
				'deactivated_at' => $now - 1000,
				'actor'          => 'alice',
			),
			array(
				'ts'       => $now - 50,
				'decision' => 'allow',
				'channel'  => 'ai_client',
			),
		);

		$gaps = Tamper::recent_gap_windows( $log, $now );
		$this->assertCount( 1, $gaps );
		$this->assertSame( $now - 1000, $gaps[0]['from'] );
		$this->assertSame( $now - 100, $gaps[0]['to'] );
	}

	public function test_site_health_recommends_when_gap_in_log(): void {
		$now = time();
		$log = array(
			array(
				'ts'             => $now - 60,
				'decision'       => Tamper::DECISION_RESUMED,
				'channel'        => Tamper::CHANNEL,
				'deactivated_at' => $now - 3600,
				'actor'          => 'alice',
			),
		);

		$snapshot = Site_Health::build_snapshot(
			array(
				'kill_switch' => false,
				'log_enabled' => true,
				'audit_only'  => false,
			),
			array(
				'ai/ai.php'            => array( 'Name' => 'AI' ),
				'example/consumer.php' => array(
					'Name'            => 'Example',
					'RequiresPlugins' => 'ai',
				),
			),
			array( 'ai/ai.php' => true ),
			$log
		);

		$this->assertSame( 'recommended', $snapshot['status'] );
		$this->assertSame( 'enforcement_interrupted', $snapshot['issue'] );
		$this->assertSame( 1, $snapshot['enforcement_gap_count'] );
	}

	public function test_format_gap_window_includes_bounds(): void {
		$text = Tamper::format_gap_window( 1_700_000_000, 1_700_000_500 );
		$this->assertStringContainsString( 'Enforcement was off from', $text );
	}
}
