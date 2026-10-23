<?php
/**
 * AICAC-POSTCARD (#427).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Postcard;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class PostcardTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12 UTC.

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$GLOBALS['handl_aicac_test_cron']             = array();
		Postcard::reset_for_tests();
		update_option( 'admin_email', 'owner@prod.example.com' );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'alert_email' => 'alerts@gmail.com',
			)
		);
		Postcard::set_test_now( self::NOW );
		Postcard::set_test_policy(
			array(
				'default'                    => 'allow',
				'alert_email'                => 'alerts@gmail.com',
				'alert_webhook_url'          => 'https://hooks.example-automation.com/hook',
				'alert_on_deny'              => true,
				'governance_digest_enabled'  => true,
				'log_enabled'                => true,
				'weekly_report_enabled'      => false,
				'monthly_report_enabled'     => false,
				'policy_backup_email_enabled'=> false,
				'anomaly_alert_enabled'      => false,
				'latency_alert_enabled'      => false,
			)
		);
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_cron']          = array();
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		Postcard::reset_for_tests();
		parent::tearDown();
	}

	private function enable( bool $outbound = false ): void {
		Postcard::save_settings(
			array(
				'enabled'        => true,
				'outbound_alert' => $outbound,
			)
		);
	}

	public function test_defaults_off_and_constants(): void {
		$this->assertFalse( Postcard::is_enabled() );
		$this->assertFalse( Postcard::is_outbound_enabled() );
		$this->assertSame( 'report_only_never_edits_senders', Postcard::FRAMING );
		$this->assertSame( 'handl-aicac-postcard', Postcard::PAGE_SLUG );
		$this->assertSame( 'handl_aicac_postcard', Postcard::SETTINGS_OPTION );
		$this->assertSame( 'handl_aicac_postcard_state', Postcard::STATE_OPTION );
		$this->assertSame( Postcard::defaults(), Postcard::sanitize_settings( 'junk' ) );

		$this->assertTrue( Postcard::save_settings( array( 'enabled' => true ) ) );
		$this->assertTrue( Postcard::is_enabled() );
		$this->assertFalse( Postcard::is_outbound_enabled() );
		$this->assertTrue( Postcard::save_settings( Postcard::defaults() ) );
		$this->assertFalse( (bool) get_option( Postcard::SETTINGS_OPTION, false ) );
	}

	public function test_disabled_does_nothing(): void {
		$this->assertFalse( Postcard::maybe_check( self::NOW, true ) );
		$this->assertFalse( Postcard::maybe_fire_alerts( self::NOW ) );
		$this->assertFalse( get_option( Postcard::STATE_OPTION, false ) );
	}

	public function test_bundled_senders_filterable_and_have_categories(): void {
		$senders = Postcard::bundled_senders();
		$this->assertNotEmpty( $senders );
		$ids = array();
		foreach ( $senders as $row ) {
			$ids[] = $row['id'];
			$this->assertNotEmpty( $row['categories'] );
		}
		$this->assertContains( 'deny_alert_email', $ids );
		$this->assertContains( 'deny_alert_webhook', $ids );
		$this->assertContains( 'governance_digest', $ids );

		$GLOBALS['handl_aicac_test_filters']['handl_aicac_postcard_senders'] = static function ( $rows ) {
			$rows[] = array(
				'id'          => 'custom_sender',
				'label'       => 'Custom',
				'channel'     => 'email',
				'categories'  => array( Postcard::CAT_USERNAMES ),
				'policy_flag' => 'alert_on_deny',
			);
			return $rows;
		};
		$ids2 = array_column( Postcard::bundled_senders(), 'id' );
		$this->assertContains( 'custom_sender', $ids2 );
		unset( $GLOBALS['handl_aicac_test_filters']['handl_aicac_postcard_senders'] );
	}

	public function test_findings_destination_times_category_plain_language(): void {
		$this->enable();
		$findings = Postcard::findings();
		$this->assertNotEmpty( $findings );

		$summaries = array_column( $findings, 'summary' );
		$joined    = implode( ' ', $summaries );
		$this->assertStringContainsString( '@gmail.com', $joined );
		$this->assertStringContainsString( 'example-automation.com', $joined );
		$this->assertStringContainsString( 'deny reasons', $joined );
		$this->assertStringNotContainsString( 'alerts@gmail.com', $joined );
		$this->assertStringNotContainsString( 'https://hooks', $joined );

		foreach ( $findings as $row ) {
			$this->assertArrayHasKey( 'key', $row );
			$this->assertArrayHasKey( 'suggestion', $row );
			$this->assertArrayHasKey( 'category', $row );
		}
	}

	public function test_acknowledge_quiets_until_new_destination_or_category(): void {
		$this->enable();
		$keys = array_column( Postcard::findings(), 'key' );
		$this->assertNotEmpty( $keys );
		$this->assertGreaterThan( 0, Postcard::acknowledge( $keys ) );
		$this->assertSame( 0, count( Postcard::findings() ) );

		// Same destinations/categories stay quiet.
		Postcard::maybe_check( self::NOW + 400, true );
		$this->assertSame( 0, count( Postcard::findings() ) );

		// New destination re-arms.
		Postcard::set_test_policy(
			array(
				'default'                   => 'allow',
				'alert_email'               => 'ops@other-inbox.com',
				'alert_webhook_url'         => 'https://hooks.example-automation.com/hook',
				'alert_on_deny'             => true,
				'governance_digest_enabled' => true,
				'log_enabled'               => true,
			)
		);
		$new = Postcard::findings();
		$this->assertNotEmpty( $new );
		$joined = implode( ' ', array_column( $new, 'summary' ) );
		$this->assertStringContainsString( '@other-inbox.com', $joined );
	}

	public function test_one_rearming_alert_categories_only_no_sample_content(): void {
		$this->enable( true );
		$GLOBALS['handl_aicac_wp_mail'] = true;

		$this->assertTrue( Postcard::maybe_fire_alerts( self::NOW ) );
		$this->assertTrue( Postcard::is_alerted() );
		$this->assertFalse( Postcard::maybe_fire_alerts( self::NOW + 10 ), 'latched until re-arm' );

		$mails = Postcard::test_mails();
		$this->assertNotEmpty( $mails );
		$body = (string) $mails[0]['body'];
		$this->assertStringContainsString( '[POSTCARD]', (string) $mails[0]['subject'] );
		$this->assertStringContainsString( 'Categories involved:', $body );
		$this->assertStringNotContainsString( 'alerts@gmail.com', $body );
		$this->assertStringNotContainsString( 'https://hooks.example-automation.com', $body );

		// Acknowledge clears latch; new pairing can fire again.
		Postcard::acknowledge( array_column( Postcard::findings(), 'key' ) );
		$this->assertFalse( Postcard::is_alerted() );
	}

	public function test_throttle_skips_within_window(): void {
		$this->enable();
		$this->assertTrue( Postcard::maybe_check( self::NOW, false ) );
		$this->assertFalse( Postcard::maybe_check( self::NOW + 60, false ) );
		$this->assertTrue( Postcard::maybe_check( self::NOW + 400, false ) );
	}

	public function test_csv_and_snapshot_include_inventory(): void {
		$this->enable();
		$snap = Postcard::snapshot( self::NOW );
		$this->assertGreaterThan( 0, $snap['unacknowledged_count'] );
		$this->assertNotEmpty( $snap['inventory'] );
		$csv = Postcard::csv_for_snapshot( $snap );
		$this->assertStringContainsString( 'inventory', $csv );
		$this->assertStringContainsString( 'finding', $csv );
		$this->assertStringContainsString( Postcard::FRAMING, $csv );
	}

	public function test_email_domain_and_url_host_helpers(): void {
		$this->assertSame( 'gmail.com', Postcard::email_domain( 'alerts@gmail.com' ) );
		$this->assertSame( 'hooks.example.com', Postcard::url_host( 'https://hooks.example.com/path?x=1' ) );
		$this->assertSame( '', Postcard::email_domain( 'not-an-email' ) );
	}
}
