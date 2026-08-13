<?php
/**
 * AICAC-SCHED-EXPORT (#179): weekly policy JSON backup email.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Policy_Backup;
use HandL\AICAC\Policy_Transfer;
use PHPUnit\Framework\TestCase;

final class PolicyBackupTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string,attachments:array}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		$GLOBALS['handl_aicac_test_cron']    = array();
		$GLOBALS['handl_aicac_test_options'] = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Policy_Backup::LATEST_OPTION );
		delete_option( Policy_Backup::SENT_OPTION );
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
		$GLOBALS['handl_aicac_test_options'] = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Policy_Backup::LATEST_OPTION );
		delete_option( Policy_Backup::SENT_OPTION );
		parent::tearDown();
	}

	public function test_default_off_does_not_schedule_or_send(): void {
		$policy = $this->persist_policy( array( 'policy_backup_email_enabled' => false ) );
		Policy_Backup::maybe_schedule( $policy );
		$this->assertFalse( wp_next_scheduled( Policy_Backup::CRON_HOOK ) );

		$out = Policy_Backup::send_if_due( $policy, strtotime( '2026-08-12 12:00:00 UTC' ) );
		$this->assertTrue( $out['ok'] );
		$this->assertSame( 'disabled', $out['status'] );
		$this->assertSame( array(), self::$mails );
		$this->assertNull( Policy_Backup::get_latest() );
	}

	public function test_enabled_schedules_and_sends_once_per_iso_week(): void {
		$now = strtotime( '2026-08-12 12:00:00 UTC' );
		$policy = $this->persist_policy(
			array(
				'policy_backup_email_enabled' => true,
				'alert_email'                 => 'ops@example.com',
			)
		);

		Policy_Backup::maybe_schedule( $policy );
		$this->assertNotFalse( wp_next_scheduled( Policy_Backup::CRON_HOOK ) );

		$first = Policy_Backup::send_if_due( $policy, $now );
		$this->assertTrue( $first['ok'] );
		$this->assertSame( 'sent', $first['status'] );
		$this->assertCount( 1, self::$mails );
		$this->assertSame( 'ops@example.com', self::$mails[0]['to'] );
		$this->assertStringContainsString( 'rules backup', strtolower( self::$mails[0]['subject'] ) );
		$this->assertNotEmpty( self::$mails[0]['attachments'] );

		$latest = Policy_Backup::get_latest();
		$this->assertNotNull( $latest );
		$this->assertSame( $now, $latest['ts'] );
		$this->assertNotSame( '', $latest['json'] );

		$second = Policy_Backup::send_if_due( $policy, $now + 3600 );
		$this->assertTrue( $second['ok'] );
		$this->assertSame( 'already_sent', $second['status'] );
		$this->assertCount( 1, self::$mails );
	}

	public function test_disable_unschedules(): void {
		$on = $this->persist_policy( array( 'policy_backup_email_enabled' => true ) );
		Policy_Backup::maybe_schedule( $on );
		$this->assertNotFalse( wp_next_scheduled( Policy_Backup::CRON_HOOK ) );

		$off = $this->persist_policy( array( 'policy_backup_email_enabled' => false ) );
		Policy_Backup::maybe_schedule( $off );
		$this->assertFalse( wp_next_scheduled( Policy_Backup::CRON_HOOK ) );
	}

	public function test_export_bytes_match_manual_export_for_identical_state(): void {
		$policy = $this->persist_policy(
			array(
				'default'                     => 'deny',
				'policy_backup_email_enabled' => true,
				'alert_email'                 => 'ops@example.com',
			)
		);
		$version     = '9.9.9-test';
		$exported_at = '2026-08-12T15:00:00+00:00';

		$manual = Policy_Transfer::encode_export(
			Policy_Transfer::build_export( $policy, $version, $exported_at )
		);
		$scheduled = Policy_Backup::build_export_json( $policy, $version, $exported_at );

		$this->assertSame( $manual, $scheduled );
	}

	public function test_store_latest_keeps_only_most_recent(): void {
		Policy_Backup::store_latest( '{"a":1}', 100, '2026-01-01T00:00:00+00:00', 'old.json' );
		Policy_Backup::store_latest( '{"b":2}', 200, '2026-01-02T00:00:00+00:00', 'new.json' );

		$latest = Policy_Backup::get_latest();
		$this->assertNotNull( $latest );
		$this->assertSame( 200, $latest['ts'] );
		$this->assertSame( '{"b":2}', $latest['json'] );
		$this->assertSame( 'new.json', $latest['filename'] );
	}

	public function test_send_stores_attachment_bytes_matching_build_export(): void {
		$now = strtotime( '2026-08-12 12:00:00 UTC' );
		$policy = $this->persist_policy(
			array(
				'policy_backup_email_enabled' => true,
				'alert_email'                 => 'ops@example.com',
				'default'                     => 'allow',
			)
		);

		$out = Policy_Backup::send_if_due( $policy, $now );
		$this->assertSame( 'sent', $out['status'] );
		$this->assertArrayHasKey( 'json', $out );

		$latest = Policy_Backup::get_latest();
		$this->assertNotNull( $latest );
		$this->assertSame( $out['json'], $latest['json'] );

		$expected = Policy_Backup::build_export_json(
			$policy,
			defined( 'HANDL_AICAC_VERSION' ) ? (string) HANDL_AICAC_VERSION : '',
			gmdate( 'c', $now )
		);
		$this->assertSame( $expected, $latest['json'] );
	}

	/**
	 * @param array<string,mixed> $extra
	 * @return array<string,mixed>
	 */
	private function persist_policy( array $extra ): array {
		$policy = array_merge(
			array(
				'log_enabled'                 => true,
				'audit_only'                  => false,
				'alert_email'                 => 'ops@example.com',
				'policy_backup_email_enabled' => false,
				'default'                     => 'allow',
				'est_usd_input_per_m'         => 2.50,
				'est_usd_output_per_m'        => 10.00,
				'est_usd_provider_rates'      => array(),
				'log_limit'                   => 200,
			),
			$extra
		);
		update_option( Plugin::OPTION_KEY, $policy, false );

		return Policy::get_policy();
	}
}
