<?php
/**
 * AICAC-ROLLBACK (#377).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Rollback;
use PHPUnit\Framework\TestCase;

final class RollbackTest extends TestCase {

	/** @var string */
	private $tmpdir;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Rollback::reset_for_tests();
		$this->tmpdir = sys_get_temp_dir() . '/handl-aicac-rollback-test-' . uniqid( '', true );
		mkdir( $this->tmpdir, 0755, true );
		Rollback::set_test_dir( $this->tmpdir );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
	}

	protected function tearDown(): void {
		Rollback::purge_files();
		Rollback::reset_for_tests();
		if ( is_dir( $this->tmpdir ) ) {
			foreach ( glob( $this->tmpdir . '/*' ) ?: array() as $f ) {
				@unlink( $f );
			}
			@rmdir( $this->tmpdir );
		}
		unset( $GLOBALS['handl_aicac_test_current_user_can'], $GLOBALS['handl_aicac_wp_mail'] );
		$GLOBALS['handl_aicac_test_options'] = array();
		parent::tearDown();
	}

	public function test_defaults_are_off_and_save_defaults_deletes_option(): void {
		$this->assertFalse( Rollback::is_enabled() );
		$this->assertSame( Rollback::defaults(), Rollback::get_settings() );
		Rollback::save_settings( array( 'enabled' => true ) );
		$this->assertTrue( Rollback::is_enabled() );
		Rollback::save_settings( array( 'enabled' => false ) );
		$this->assertFalse( (bool) get_option( Rollback::SETTINGS_OPTION, false ) );
	}

	public function test_feature_off_skips_detect_and_persist_and_file_writes(): void {
		$path = Rollback::file_path();
		$out  = Rollback::maybe_detect( 1_700_000_000 );
		$this->assertSame( 'off', $out['status'] );
		$this->assertFalse( is_file( $path ) );
		Rollback::maybe_persist( 1_700_000_100 );
		$this->assertFalse( is_file( $path ) );
		$this->assertNull( Rollback::get_db_watermark() );
	}

	public function test_first_enable_seeds_quietly(): void {
		Rollback::save_settings( array( 'enabled' => true ) );
		$out = Rollback::maybe_detect( 1_700_000_000 );
		$this->assertSame( 'seed', $out['status'] );
		$this->assertFalse( $out['fired'] );
		$this->assertNotNull( Rollback::get_db_watermark() );
		$this->assertTrue( is_file( Rollback::file_path() ) );
		$this->assertNull( Rollback::get_incident() );
		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertSame( array(), $log );
	}

	public function test_file_missing_quiet_reseeds(): void {
		Rollback::save_settings( array( 'enabled' => true ) );
		Rollback::maybe_detect( 1_700_000_000 );
		@unlink( Rollback::file_path() );
		$out = Rollback::maybe_detect( 1_700_000_060 );
		$this->assertSame( 'reseed', $out['status'] );
		$this->assertFalse( $out['fired'] );
		$this->assertNull( Rollback::get_incident() );
		$this->assertTrue( is_file( Rollback::file_path() ) );
	}

	public function test_file_older_than_db_quiet_reseeds(): void {
		Rollback::save_settings( array( 'enabled' => true ) );
		$older = array(
			'ts'             => 1_700_000_000,
			'log_ts'         => 0,
			'log_count'      => 0,
			'policy_version' => 'aaaaaaaaaaaaaaaa',
			'grants'         => 0,
			'acks'           => 0,
		);
		$newer = array(
			'ts'             => 1_700_000_100,
			'log_ts'         => 0,
			'log_count'      => 0,
			'policy_version' => 'aaaaaaaaaaaaaaaa',
			'grants'         => 0,
			'acks'           => 0,
		);
		Rollback::put_db_watermark( $newer );
		Rollback::write_file_watermark( $older );
		$out = Rollback::maybe_detect( 1_700_000_120 );
		$this->assertSame( 'reseed', $out['status'] );
		$this->assertFalse( $out['fired'] );
		$this->assertNull( Rollback::get_incident() );
	}

	public function test_db_older_than_file_fires_once_notice_log_and_alert(): void {
		$mails = array();
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $body ) use ( &$mails ) {
			$mails[] = array( $to, $subject, $body );

			return true;
		};
		update_option( 'admin_email', 'haktan+aicac-rollback@handldigital.com' );

		Rollback::save_settings( array( 'enabled' => true ) );
		$file = array(
			'ts'             => 1_700_000_200,
			'log_ts'         => 1_700_000_180,
			'log_count'      => 10,
			'policy_version' => 'bbbbbbbbbbbbbbbb',
			'grants'         => 3,
			'acks'           => 5,
		);
		$db = array(
			'ts'             => 1_700_000_100,
			'log_ts'         => 1_700_000_050,
			'log_count'      => 4,
			'policy_version' => 'aaaaaaaaaaaaaaaa',
			'grants'         => 1,
			'acks'           => 2,
		);
		Rollback::put_db_watermark( $db );
		Rollback::write_file_watermark( $file );

		$first = Rollback::maybe_detect( 1_700_000_250 );
		$this->assertSame( 'rollback', $first['status'] );
		$this->assertTrue( $first['fired'] );
		$this->assertNotNull( Rollback::get_incident() );
		$this->assertArrayHasKey( 'log_count', $first['gaps'] );
		$this->assertArrayHasKey( 'grants', $first['gaps'] );
		$this->assertArrayHasKey( 'acks', $first['gaps'] );
		$this->assertArrayHasKey( 'policy_version', $first['gaps'] );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertCount( 1, $log );
		$this->assertSame( 'rollback', $log[0]['channel'] );
		$this->assertSame( 'detected', $log[0]['decision'] );
		$this->assertSame( 'rollback=detected', $log[0]['reason'] );

		$this->assertNotEmpty( Rollback::test_mails() );
		$this->assertNotEmpty( $mails );

		$second = Rollback::maybe_detect( 1_700_000_260 );
		$this->assertSame( 'rollback', $second['status'] );
		$this->assertFalse( $second['fired'] );
		$this->assertCount( 1, get_option( Plugin::LOG_OPTION_KEY ) );
		$this->assertCount( 1, Rollback::test_mails() );
	}

	public function test_persist_throttled_and_blocked_during_incident(): void {
		Rollback::save_settings( array( 'enabled' => true ) );
		Rollback::maybe_detect( 1_700_000_000 );
		$db1 = Rollback::get_db_watermark();
		$this->assertNotNull( $db1 );

		Rollback::maybe_persist( 1_700_000_030 );
		$db2 = Rollback::get_db_watermark();
		$this->assertSame( (int) $db1['ts'], (int) $db2['ts'] );

		Rollback::maybe_persist( 1_700_000_070 );
		$db3 = Rollback::get_db_watermark();
		$this->assertSame( 1_700_000_070, (int) $db3['ts'] );

		// Open an incident — persist must not advance watermarks.
		$file = $db3;
		$file['ts'] = 1_700_000_200;
		$file['log_count'] = 99;
		Rollback::write_file_watermark( $file );
		Rollback::put_db_watermark(
			array(
				'ts'             => 1_700_000_100,
				'log_ts'         => 0,
				'log_count'      => 1,
				'policy_version' => $db3['policy_version'],
				'grants'         => 0,
				'acks'           => 0,
			)
		);
		Rollback::maybe_detect( 1_700_000_210 );
		$this->assertNotNull( Rollback::get_incident() );
		$before = Rollback::get_db_watermark();
		Rollback::maybe_persist( 1_700_000_400 );
		$after = Rollback::get_db_watermark();
		$this->assertSame( (int) $before['ts'], (int) $after['ts'] );
	}

	public function test_reseed_clears_incident_and_aligns(): void {
		Rollback::save_settings( array( 'enabled' => true ) );
		Rollback::put_db_watermark(
			array(
				'ts'             => 100,
				'log_ts'         => 0,
				'log_count'      => 1,
				'policy_version' => 'aaaaaaaaaaaaaaaa',
				'grants'         => 0,
				'acks'           => 0,
			)
		);
		Rollback::write_file_watermark(
			array(
				'ts'             => 200,
				'log_ts'         => 0,
				'log_count'      => 9,
				'policy_version' => 'bbbbbbbbbbbbbbbb',
				'grants'         => 2,
				'acks'           => 3,
			)
		);
		Rollback::maybe_detect( 250 );
		$this->assertTrue( Rollback::is_rollback_active() );
		$snap = Rollback::reseed( 300 );
		$this->assertSame( 300, (int) $snap['ts'] );
		$this->assertNull( Rollback::get_incident() );
		$this->assertFalse( Rollback::is_rollback_active() );
		$file = Rollback::read_file_watermark();
		$this->assertNotNull( $file );
		$this->assertSame( 300, (int) $file['ts'] );
	}

	public function test_disable_purges_files(): void {
		Rollback::save_settings( array( 'enabled' => true ) );
		Rollback::maybe_detect( 1_700_000_000 );
		$this->assertTrue( is_file( Rollback::file_path() ) );
		Rollback::save_settings( array( 'enabled' => false ) );
		$this->assertFalse( is_file( Rollback::file_path() ) );
	}

	public function test_capture_snapshot_reads_log_grants_and_acks(): void {
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array( 'ts' => 50, 'decision' => 'allow' ),
				array( 'ts' => 80, 'decision' => 'deny' ),
			),
			false
		);
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'         => 'allow',
				'plugin_expires'  => array(
					'a/a.php' => 1_800_000_000,
					'b/b.php' => 0,
				),
			),
			false
		);
		update_option(
			'handl_aicac_aup_ack_index',
			array(
				'1' => array( 'ts' => 1 ),
				'2' => array( 'ts' => 2 ),
			),
			false
		);
		$snap = Rollback::capture_snapshot( 100 );
		$this->assertSame( 100, $snap['ts'] );
		$this->assertSame( 80, $snap['log_ts'] );
		$this->assertSame( 2, $snap['log_count'] );
		$this->assertSame( 1, $snap['grants'] );
		$this->assertSame( 2, $snap['acks'] );
		$this->assertNotSame( '', $snap['policy_version'] );
	}

	public function test_compare_gap_report_keys(): void {
		$db = array(
			'ts'             => 100,
			'log_ts'         => 10,
			'log_count'      => 2,
			'policy_version' => 'aaa',
			'grants'         => 0,
			'acks'           => 0,
		);
		$file = array(
			'ts'             => 200,
			'log_ts'         => 20,
			'log_count'      => 5,
			'policy_version' => 'bbb',
			'grants'         => 2,
			'acks'           => 1,
		);
		$cmp = Rollback::compare( $db, $file );
		$this->assertSame( 'rollback', $cmp['status'] );
		$this->assertArrayHasKey( 'log_ts', $cmp['gaps'] );
		$this->assertArrayHasKey( 'log_count', $cmp['gaps'] );
		$this->assertArrayHasKey( 'grants', $cmp['gaps'] );
		$this->assertArrayHasKey( 'acks', $cmp['gaps'] );
		$this->assertArrayHasKey( 'policy_version', $cmp['gaps'] );
		$this->assertArrayHasKey( 'ts', $cmp['gaps'] );
	}

	public function test_purge_files_removes_watermark(): void {
		Rollback::save_settings( array( 'enabled' => true ) );
		Rollback::maybe_detect( 1_700_000_000 );
		$path = Rollback::file_path();
		$this->assertTrue( is_file( $path ) );
		Rollback::purge_files();
		$this->assertFalse( is_file( $path ) );
	}
}
