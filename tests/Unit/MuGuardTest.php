<?php
/**
 * AICAC-MU-GUARD (#226) Phase 1 unit tests.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Mu_Guard;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Site_Health;
use HandL\AICAC\Tamper;
use PHPUnit\Framework\TestCase;

final class MuGuardTest extends TestCase {

	private string $mu_dir = '';

	protected function setUp(): void {
		parent::setUp();
		$this->mu_dir = sys_get_temp_dir() . '/handl-aicac-mu-guard-' . uniqid( '', true );
		mkdir( $this->mu_dir, 0755, true );

		delete_option( Mu_Guard::MODE_OPTION );
		delete_option( Mu_Guard::FALLBACK_LOG_OPTION );
		delete_option( Mu_Guard::ALERT_FOR_OPTION );
		delete_option( Tamper::DEACTIVATED_AT_OPTION );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
	}

	protected function tearDown(): void {
		Mu_Guard::disable( $this->mu_dir );
		if ( is_dir( $this->mu_dir ) ) {
			$stub = $this->mu_dir . '/' . Mu_Guard::STUB_FILENAME;
			if ( is_file( $stub ) ) {
				unlink( $stub );
			}
			rmdir( $this->mu_dir );
		}
		delete_option( Mu_Guard::MODE_OPTION );
		delete_option( Mu_Guard::FALLBACK_LOG_OPTION );
		delete_option( Mu_Guard::ALERT_FOR_OPTION );
		delete_option( Tamper::DEACTIVATED_AT_OPTION );
		parent::tearDown();
	}

	public function test_enable_writes_versioned_stub_and_disable_removes_it(): void {
		$result = Mu_Guard::enable( Mu_Guard::MODE_FAIL_CLOSED, $this->mu_dir );
		$this->assertTrue( $result['ok'] );
		$this->assertSame( Mu_Guard::MODE_FAIL_CLOSED, Mu_Guard::get_mode() );

		$path = Mu_Guard::stub_path( $this->mu_dir );
		$this->assertFileExists( $path );
		$this->assertSame( Mu_Guard::STUB_VERSION, Mu_Guard::read_stub_version( $path ) );

		$status = Mu_Guard::status( $this->mu_dir );
		$this->assertTrue( $status['enabled'] );
		$this->assertTrue( $status['stub_present'] );
		$this->assertTrue( $status['stub_current'] );

		$off = Mu_Guard::disable( $this->mu_dir );
		$this->assertTrue( $off['ok'] );
		$this->assertSame( Mu_Guard::MODE_OFF, Mu_Guard::get_mode() );
		$this->assertFileDoesNotExist( $path );
	}

	public function test_enable_rejects_invalid_mode_and_does_not_write(): void {
		$result = Mu_Guard::enable( 'block-everything', $this->mu_dir );
		$this->assertFalse( $result['ok'] );
		$this->assertSame( 'invalid_mode', $result['error'] ?? null );
		$this->assertFileDoesNotExist( Mu_Guard::stub_path( $this->mu_dir ) );
		$this->assertSame( Mu_Guard::MODE_OFF, Mu_Guard::get_mode() );
	}

	public function test_stub_fail_closed_mode_is_stored_for_inactive_enforcement(): void {
		Mu_Guard::enable( Mu_Guard::MODE_FAIL_CLOSED, $this->mu_dir );
		$path = Mu_Guard::stub_path( $this->mu_dir );
		$this->assertFileExists( $path );

		$raw = (string) file_get_contents( $path );
		$this->assertStringContainsString( "define( 'HANDL_AICAC_GUARD_STUB_VERSION', '1' )", $raw );
		$this->assertStringContainsString( 'wp_ai_client_prevent_prompt', $raw );
		$this->assertStringContainsString( 'fail_closed', $raw );
		$this->assertSame( Mu_Guard::MODE_FAIL_CLOSED, Mu_Guard::get_mode() );
	}

	public function test_stub_watch_logs_and_alerts_once_per_tamper_stamp(): void {
		update_option( 'admin_email', 'admin@example.test' );
		Policy::save_policy( array( 'alert_email' => 'ops@example.test' ) );
		update_option( Tamper::DEACTIVATED_AT_OPTION, 1_700_000_000, false );

		$mails = array();
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) use ( &$mails ) {
			$mails[] = array( $to, $subject, $message );
			return true;
		};

		Mu_Guard::enable( Mu_Guard::MODE_WATCH, $this->mu_dir );
		require_once Mu_Guard::stub_path( $this->mu_dir );

		handl_aicac_guard_append_fallback(
			array(
				'ts'       => 1_700_000_100,
				'decision' => 'allow',
				'channel'  => 'hardened_guard',
				'mode'     => 'watch',
			)
		);
		handl_aicac_guard_maybe_alert( 1_700_000_100 );
		handl_aicac_guard_maybe_alert( 1_700_000_200 );

		$log = get_option( Mu_Guard::FALLBACK_LOG_OPTION );
		$this->assertIsArray( $log );
		$this->assertCount( 1, $log );
		$this->assertSame( 'allow', $log[0]['decision'] );

		$this->assertCount( 1, $mails );
		$this->assertSame( 'ops@example.test', $mails[0][0] );
		$this->assertSame( 1_700_000_000, (int) get_option( Mu_Guard::ALERT_FOR_OPTION ) );

		unset( $GLOBALS['handl_aicac_wp_mail'] );
	}

	public function test_site_health_flags_missing_stub_when_hardened_on(): void {
		update_option( Mu_Guard::MODE_OPTION, Mu_Guard::MODE_FAIL_CLOSED, false );
		// No stub written → drift.

		$snap = Site_Health::build_snapshot(
			array(
				'kill_switch' => false,
				'log_enabled' => true,
				'audit_only'  => false,
				'plugins'     => array(),
			),
			array(
				'ai-plugin/ai.php' => array( 'Name' => 'AI Plugin' ),
			),
			array(
				'ai-plugin/ai.php' => true,
			)
		);

		// has_ai_client detection may or may not treat ai-plugin as AI Client;
		// hardened drift must still win when enabled + stub missing.
		$this->assertSame( 'hardened_stub_drift', $snap['issue'] );
		$this->assertSame( 'recommended', $snap['status'] );
		$this->assertSame( Mu_Guard::MODE_FAIL_CLOSED, $snap['hardened_mode'] );
		$this->assertFalse( $snap['hardened_stub_present'] );
	}

	public function test_status_reports_open_tamper_gap(): void {
		update_option( Tamper::DEACTIVATED_AT_OPTION, 1_700_000_000, false );
		$status = Mu_Guard::status( $this->mu_dir );
		$this->assertTrue( $status['open_tamper_gap'] );
	}
}
