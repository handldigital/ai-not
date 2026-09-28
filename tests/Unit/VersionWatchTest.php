<?php
/**
 * AICAC-VERSION-WATCH (#283).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Snooze;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Review_Due;
use HandL\AICAC\Version_Watch;
use PHPUnit\Framework\TestCase;

final class VersionWatchTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Review_Due::OPTION_KEY );
		delete_option( Version_Watch::VERSION_OPTION_KEY );
		delete_option( Version_Watch::ALERTED_OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		delete_transient( Version_Watch::SCAN_TRANSIENT_KEY );
		unset( $GLOBALS['handl_aicac_test_plugins'] );
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
		unset( $GLOBALS['handl_aicac_wp_mail'], $GLOBALS['handl_aicac_test_plugins'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Review_Due::OPTION_KEY );
		delete_option( Version_Watch::VERSION_OPTION_KEY );
		delete_option( Version_Watch::ALERTED_OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		delete_transient( Version_Watch::SCAN_TRANSIENT_KEY );
		parent::tearDown();
	}

	/**
	 * @return array<string,array<string,mixed>>
	 */
	private function installed( string $version = '1.0.0' ): array {
		return array(
			'acme/acme.php' => array(
				'Name'    => 'Acme',
				'Version' => $version,
			),
		);
	}

	public function test_stamp_on_allow_save_and_unchanged_keeps_version(): void {
		$installed = $this->installed( '1.0.0' );
		$GLOBALS['handl_aicac_test_plugins'] = $installed;

		Version_Watch::stamp_on_rule_changes(
			array( 'plugins' => array( 'acme/acme.php' => 'allow' ) ),
			array(),
			$installed
		);
		$this->assertSame( '1.0.0', Version_Watch::get_versions()['acme/acme.php'] );

		$GLOBALS['handl_aicac_test_plugins'] = $this->installed( '2.0.0' );
		Version_Watch::stamp_on_rule_changes(
			array( 'plugins' => array( 'acme/acme.php' => 'allow' ) ),
			array( 'plugins' => array( 'acme/acme.php' => 'allow' ) ),
			$GLOBALS['handl_aicac_test_plugins']
		);
		// Unchanged Allow must keep the trust version (1.0.0), not silently advance.
		$this->assertSame( '1.0.0', Version_Watch::get_versions()['acme/acme.php'] );
	}

	public function test_deny_rules_are_not_version_stamped(): void {
		$installed = $this->installed( '1.0.0' );
		Version_Watch::stamp_on_rule_changes(
			array( 'plugins' => array( 'acme/acme.php' => 'deny' ) ),
			array(),
			$installed
		);
		$this->assertSame( array(), Version_Watch::get_versions() );
	}

	public function test_version_change_marks_review_due_and_alerts_once(): void {
		$policy = array(
			'plugins'         => array( 'acme/acme.php' => 'allow' ),
			'review_due_days' => 90,
			'default'         => 'observe',
			'log_enabled'     => true,
			'alert_email'     => 'admin@example.com',
		);
		Policy::save_policy( $policy );
		// save_policy may stamp via Review_Due; force known version stamp.
		Version_Watch::put_versions( array( 'acme/acme.php' => '1.0.0' ) );
		Review_Due::put_stamps( array( 'acme/acme.php' => 1_700_000_000 ) );

		$v2 = $this->installed( '2.0.0' );
		$GLOBALS['handl_aicac_test_plugins'] = $v2;

		$now  = 1_700_000_000;
		$stat = Version_Watch::scan( Policy::get_policy(), $v2, $now );
		$this->assertSame( 1, $stat['mismatched'] );
		$this->assertSame( 1, $stat['alerted'] );
		$this->assertCount( 1, self::$mails );
		$this->assertSame( '2.0.0', Version_Watch::get_alerted()['acme/acme.php'] );

		$snap = Review_Due::snapshot( Policy::get_policy(), $v2, $now );
		$this->assertSame( 1, $snap['due'] );
		$this->assertTrue( $snap['rows'][0]['version_due'] );

		// Second scan: same plugin+version must not re-alert.
		$stat2 = Version_Watch::scan( Policy::get_policy(), $v2, $now + 10 );
		$this->assertSame( 1, $stat2['mismatched'] );
		$this->assertSame( 0, $stat2['alerted'] );
		$this->assertCount( 1, self::$mails );

		// Allow/deny untouched.
		$this->assertSame( 'allow', Policy::get_policy()['plugins']['acme/acme.php'] );
	}

	public function test_confirm_restamps_version_and_clears_due(): void {
		$policy = array(
			'plugins'         => array( 'acme/acme.php' => 'allow' ),
			'review_due_days' => 90,
			'default'         => 'observe',
			'log_enabled'     => true,
		);
		Policy::save_policy( $policy );
		Version_Watch::put_versions( array( 'acme/acme.php' => '1.0.0' ) );
		Review_Due::put_stamps( array( 'acme/acme.php' => 1_600_000_000 ) );

		$v2 = $this->installed( '2.0.0' );
		$GLOBALS['handl_aicac_test_plugins'] = $v2;
		$now = 1_700_000_000;

		$this->assertTrue( Version_Watch::is_mismatch( 'acme/acme.php', $v2 ) );
		Review_Due::confirm( Policy::get_policy(), array( 'acme/acme.php' ), $now );

		$this->assertSame( '2.0.0', Version_Watch::get_versions()['acme/acme.php'] );
		$this->assertFalse( Version_Watch::is_mismatch( 'acme/acme.php', $v2 ) );
		$snap = Review_Due::snapshot( Policy::get_policy(), $v2, $now );
		$this->assertSame( 0, $snap['due'] );
		$this->assertSame( 'allow', Policy::get_policy()['plugins']['acme/acme.php'] );
	}

	public function test_snooze_suppresses_alert_without_mutating_rule(): void {
		$policy = array(
			'plugins'         => array( 'acme/acme.php' => 'allow' ),
			'review_due_days' => 90,
			'default'         => 'observe',
			'log_enabled'     => true,
			'alert_email'     => 'admin@example.com',
		);
		Policy::save_policy( $policy );
		Version_Watch::put_versions( array( 'acme/acme.php' => '1.0.0' ) );

		$now = 1_700_000_000;
		Alert_Snooze::set( 'acme/acme.php', '24h', $now );

		$v2 = $this->installed( '2.0.0' );
		$GLOBALS['handl_aicac_test_plugins'] = $v2;
		$stat = Version_Watch::scan( Policy::get_policy(), $v2, $now );

		$this->assertSame( 1, $stat['mismatched'] );
		$this->assertSame( 0, $stat['alerted'] );
		$this->assertSame( array(), self::$mails );
		$this->assertSame( 'allow', Policy::get_policy()['plugins']['acme/acme.php'] );
		$this->assertTrue( Version_Watch::is_mismatch( 'acme/acme.php', $v2 ) );
	}

	public function test_upgrader_hook_processes_plugin_update(): void {
		$policy = array(
			'plugins'         => array( 'acme/acme.php' => 'allow' ),
			'review_due_days' => 90,
			'default'         => 'observe',
			'log_enabled'     => true,
			'alert_email'     => 'admin@example.com',
		);
		Policy::save_policy( $policy );
		Version_Watch::put_versions( array( 'acme/acme.php' => '1.0.0' ) );

		$GLOBALS['handl_aicac_test_plugins'] = $this->installed( '3.1.0' );
		Version_Watch::on_upgrader_process_complete(
			null,
			array(
				'type'   => 'plugin',
				'action' => 'update',
				'plugin' => 'acme/acme.php',
			)
		);

		$this->assertCount( 1, self::$mails );
		$this->assertTrue( Version_Watch::is_mismatch( 'acme/acme.php', $GLOBALS['handl_aicac_test_plugins'] ) );
		$status = Version_Watch::status_for( 'acme/acme.php', $GLOBALS['handl_aicac_test_plugins'] );
		$this->assertTrue( $status['due'] );
		$this->assertSame( '1.0.0', $status['stamped'] );
		$this->assertSame( '3.1.0', $status['installed'] );
		$this->assertNotSame( '', $status['label'] );
	}

	public function test_baseline_missing_stamp_does_not_alert(): void {
		$policy = array(
			'plugins'         => array( 'acme/acme.php' => 'allow' ),
			'review_due_days' => 90,
			'alert_email'     => 'admin@example.com',
		);
		$v1 = $this->installed( '1.0.0' );
		$stat = Version_Watch::scan( $policy, $v1, 1_700_000_000 );
		$this->assertSame( 1, $stat['baselined'] );
		$this->assertSame( 0, $stat['alerted'] );
		$this->assertSame( '1.0.0', Version_Watch::get_versions()['acme/acme.php'] );
		$this->assertSame( array(), self::$mails );
	}
}
