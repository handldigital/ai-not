<?php
/**
 * AICAC-WAITING-ROOM (#464).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Attribution;
use HandL\AICAC\Plugin;
use HandL\AICAC\Waiting_Room;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class WaitingRoomTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Waiting_Room::reset_for_tests();
		Attribution::force_plugin( 'alpha/alpha.php' );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'haktan+aicac-waiting-room@handldigital.com',
			)
		);
	}

	protected function tearDown(): void {
		Attribution::force_plugin( null );
		Waiting_Room::reset_for_tests();
		unset( $GLOBALS['handl_aicac_test_current_user_can'], $GLOBALS['handl_aicac_wp_mail'] );
		$GLOBALS['handl_aicac_test_options'] = array();
		parent::tearDown();
	}

	public function test_defaults_off_and_noop_save_invariant(): void {
		$this->assertFalse( Waiting_Room::is_enabled() );
		$this->assertSame( Waiting_Room::defaults(), Waiting_Room::get_settings() );
		$this->assertFalse( Waiting_Room::save_settings( Waiting_Room::defaults() ) );
		$this->assertFalse( (bool) get_option( Waiting_Room::SETTINGS_OPTION, false ) );

		Waiting_Room::save_settings( array( 'enabled' => true ) );
		$this->assertTrue( Waiting_Room::is_enabled() );
		$serialized = serialize( get_option( Waiting_Room::SETTINGS_OPTION ) );
		$this->assertFalse( Waiting_Room::save_settings( array( 'enabled' => true ) ) );
		$this->assertSame( $serialized, serialize( get_option( Waiting_Room::SETTINGS_OPTION ) ) );

		Waiting_Room::save_settings( Waiting_Room::defaults() );
		$this->assertFalse( (bool) get_option( Waiting_Room::SETTINGS_OPTION, false ) );
	}

	public function test_off_records_nothing(): void {
		$this->assertNull( Waiting_Room::record_sample( 'alpha/alpha.php', Waiting_Room::SURFACE_FRONT, 500 ) );
		$this->assertFalse( (bool) get_option( Waiting_Room::STATS_OPTION, false ) );
		$this->assertSame( array(), Waiting_Room::test_mails() );
	}

	public function test_surface_classification_front_admin_cron_cli_rest(): void {
		$this->assertSame(
			Waiting_Room::SURFACE_CRON,
			Waiting_Room::detect_surface( array( 'doing_cron' => true, 'is_admin' => true ) )
		);
		$this->assertSame(
			Waiting_Room::SURFACE_CLI,
			Waiting_Room::detect_surface( array( 'doing_cli' => true, 'is_admin' => true ) )
		);
		$this->assertSame(
			Waiting_Room::SURFACE_REST,
			Waiting_Room::detect_surface( array( 'rest' => true, 'is_admin' => true ) )
		);
		$this->assertSame(
			Waiting_Room::SURFACE_ADMIN,
			Waiting_Room::detect_surface( array( 'is_admin' => true ) )
		);
		$this->assertSame(
			Waiting_Room::SURFACE_FRONT,
			Waiting_Room::detect_surface( array() )
		);
	}

	public function test_unmeasured_interval_skipped_never_guessed(): void {
		Waiting_Room::save_settings( array( 'enabled' => true ) );
		Waiting_Room::on_after_generate( (object) array() );
		$this->assertFalse( (bool) get_option( Waiting_Room::STATS_OPTION, false ) );
	}

	public function test_grades_including_invisible_with_heavy_cron(): void {
		Waiting_Room::save_settings( array( 'enabled' => true ) );
		// Cron-heavy plugin: many cron samples, zero front → INVISIBLE.
		for ( $i = 0; $i < 10; $i++ ) {
			Waiting_Room::record_sample( 'cronny/cronny.php', Waiting_Room::SURFACE_CRON, 5000 );
		}
		$this->assertSame( Waiting_Room::GRADE_INVISIBLE, Waiting_Room::grade_plugin( 'cronny/cronny.php' ) );

		Waiting_Room::record_sample( 'polite/polite.php', Waiting_Room::SURFACE_FRONT, 50 );
		Waiting_Room::record_sample( 'polite/polite.php', Waiting_Room::SURFACE_FRONT, 80 );
		$this->assertSame( Waiting_Room::GRADE_POLITE, Waiting_Room::grade_plugin( 'polite/polite.php' ) );

		Waiting_Room::record_sample( 'notice/notice.php', Waiting_Room::SURFACE_FRONT, 400 );
		Waiting_Room::record_sample( 'notice/notice.php', Waiting_Room::SURFACE_FRONT, 500 );
		$this->assertSame( Waiting_Room::GRADE_NOTICEABLE, Waiting_Room::grade_plugin( 'notice/notice.php' ) );

		Waiting_Room::record_sample( 'block/block.php', Waiting_Room::SURFACE_FRONT, 2500 );
		Waiting_Room::record_sample( 'block/block.php', Waiting_Room::SURFACE_FRONT, 3000 );
		$this->assertSame( Waiting_Room::GRADE_BLOCKING, Waiting_Room::grade_plugin( 'block/block.php' ) );

		$by = array();
		foreach ( Waiting_Room::roster() as $row ) {
			$by[ $row['plugin'] ] = $row;
		}
		$this->assertSame( Waiting_Room::GRADE_INVISIBLE, $by['cronny/cronny.php']['grade'] );
		$this->assertSame( 0, (int) $by['cronny/cronny.php']['front_calls'] );
		$this->assertGreaterThan( 0, (int) $by['cronny/cronny.php']['cron_ms'] );
		$this->assertSame( Waiting_Room::GRADE_BLOCKING, $by['block/block.php']['grade'] );
	}

	public function test_blocking_alert_fires_once_per_plugin_day(): void {
		Waiting_Room::save_settings( array( 'enabled' => true ) );
		$now = strtotime( '2026-10-12 12:00:00 UTC' );
		$cell = Waiting_Room::record_sample( 'block/block.php', Waiting_Room::SURFACE_FRONT, 2500, $now );
		$this->assertNotNull( $cell );
		$this->assertCount( 1, Waiting_Room::test_mails() );
		$subject = (string) Waiting_Room::test_mails()[0]['subject'];
		$this->assertStringContainsString( 'block/block.php', $subject );
		$this->assertStringContainsString( 'p95', strtolower( $subject ) );

		// Second BLOCKING sample same day — deduped.
		Waiting_Room::record_sample( 'block/block.php', Waiting_Room::SURFACE_FRONT, 4000, $now + 60 );
		$this->assertCount( 1, Waiting_Room::test_mails() );

		// Explicit double-trigger of maybe_alert_blocking also dedupes.
		$fired = Waiting_Room::maybe_alert_blocking(
			'block/block.php',
			array(
				'count'    => 2,
				'total_ms' => 6500,
				'max_ms'   => 4000,
				'samples'  => array( 2500, 4000 ),
			),
			$now + 120
		);
		$this->assertFalse( $fired );
		$this->assertCount( 1, Waiting_Room::test_mails() );
	}

	public function test_csv_matches_roster_with_grade_column(): void {
		Waiting_Room::save_settings( array( 'enabled' => true ) );
		Waiting_Room::record_sample( 'alpha/alpha.php', Waiting_Room::SURFACE_FRONT, 100 );
		Waiting_Room::record_sample( 'beta/beta.php', Waiting_Room::SURFACE_CRON, 9000 );
		$rows = Waiting_Room::roster();
		$csv  = Waiting_Room::csv_for_roster( $rows );
		$this->assertStringContainsString( 'plugin,grade,front_calls', $csv );
		$this->assertStringContainsString( 'alpha/alpha.php', $csv );
		$this->assertStringContainsString( Waiting_Room::GRADE_POLITE, $csv );
		$this->assertStringContainsString( 'beta/beta.php', $csv );
		$this->assertStringContainsString( Waiting_Room::GRADE_INVISIBLE, $csv );

		$_GET['page'] = Waiting_Room::PAGE_SLUG;
		ob_start();
		Waiting_Room::render_page();
		$html = (string) ob_get_clean();
		unset( $_GET['page'] );
		$this->assertStringContainsString( 'Waiting room', $html );
		$this->assertStringContainsString( 'alpha/alpha.php', $html );
		$this->assertStringContainsString( Waiting_Room::GRADE_POLITE, $html );
	}

	public function test_timing_hooks_measure_pending_interval(): void {
		Waiting_Room::save_settings( array( 'enabled' => true ) );
		Waiting_Room::set_test_surface( Waiting_Room::SURFACE_FRONT );
		Attribution::force_plugin( 'hooked/hooked.php' );
		$prevent = Waiting_Room::on_prevent_prompt( false, null );
		$this->assertFalse( $prevent );
		usleep( 2000 );
		Waiting_Room::on_after_generate( (object) array() );
		$stats = Waiting_Room::get_stats();
		$this->assertArrayHasKey( 'hooked/hooked.php', $stats['plugins'] );
		$this->assertGreaterThan( 0, (int) $stats['plugins']['hooked/hooked.php'][ Waiting_Room::SURFACE_FRONT ]['count'] );
	}
}
