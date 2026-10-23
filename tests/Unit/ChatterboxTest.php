<?php
/**
 * AICAC-CHATTERBOX (#472).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Chatterbox;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class ChatterboxTest extends TestCase {

	private const SOLO   = 'solo/solo.php';
	private const FAN    = 'fan/fan.php';
	private const RETRY  = 'retry/retry.php';
	private const SPARSE = 'sparse/sparse.php';

	private const T0 = 1_700_000_000;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_filters']          = array();
		Chatterbox::reset_for_tests();
		Chatterbox::set_test_now( self::T0 );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
	}

	protected function tearDown(): void {
		Chatterbox::reset_for_tests();
		$GLOBALS['handl_aicac_test_options'] = array();
		parent::tearDown();
	}

	public function test_census_renders_all_four_grades(): void {
		$t = self::T0;
		Chatterbox::set_test_log(
			array(
				// SOLO: two isolated calls (20s gap) → max burst 1.
				array( 'plugin' => self::SOLO, 'ts' => $t, 'host' => 'api.solo.test' ),
				array( 'plugin' => self::SOLO, 'ts' => $t + 20, 'host' => 'api.solo.test' ),
				// CHATTERBOX fan-out: 6 calls, 3s gaps, distinct hosts.
				array( 'plugin' => self::FAN, 'ts' => $t, 'host' => 'a.example' ),
				array( 'plugin' => self::FAN, 'ts' => $t + 3, 'host' => 'b.example' ),
				array( 'plugin' => self::FAN, 'ts' => $t + 6, 'host' => 'c.example' ),
				array( 'plugin' => self::FAN, 'ts' => $t + 9, 'host' => 'd.example' ),
				array( 'plugin' => self::FAN, 'ts' => $t + 12, 'host' => 'e.example' ),
				array( 'plugin' => self::FAN, 'ts' => $t + 15, 'host' => 'f.example' ),
				// TALKATIVE same-endpoint (retry-like): 3 calls, same host.
				array( 'plugin' => self::RETRY, 'ts' => $t, 'host' => 'api.retry.test' ),
				array( 'plugin' => self::RETRY, 'ts' => $t + 2, 'host' => 'api.retry.test' ),
				array( 'plugin' => self::RETRY, 'ts' => $t + 4, 'host' => 'api.retry.test' ),
				// INSUFFICIENT-DATA: only one logged call.
				array( 'plugin' => self::SPARSE, 'ts' => $t, 'host' => 'api.sparse.test' ),
			)
		);

		$data = Chatterbox::census();
		$by   = array();
		foreach ( $data['rows'] as $row ) {
			$by[ $row['plugin'] ] = $row;
		}

		$this->assertTrue( $data['available'] );
		$this->assertSame( Chatterbox::GRADE_SOLO, $by[ self::SOLO ]['grade'] );
		$this->assertSame( 1, $by[ self::SOLO ]['max_burst'] );
		$this->assertSame( 2, $by[ self::SOLO ]['bursts'] );

		$this->assertSame( Chatterbox::GRADE_CHATTERBOX, $by[ self::FAN ]['grade'] );
		$this->assertSame( 6, $by[ self::FAN ]['max_burst'] );
		$this->assertSame( 6, $by[ self::FAN ]['largest_endpoints'] );
		$this->assertTrue( $by[ self::FAN ]['fan_out'] );
		$this->assertStringContainsString( 'fan-out', $by[ self::FAN ]['note'] );

		$this->assertSame( Chatterbox::GRADE_TALKATIVE, $by[ self::RETRY ]['grade'] );
		$this->assertSame( 3, $by[ self::RETRY ]['max_burst'] );
		$this->assertSame( 1, $by[ self::RETRY ]['largest_endpoints'] );
		$this->assertTrue( $by[ self::RETRY ]['same_endpoint'] );
		$this->assertStringContainsString( 'Retry-storm', $by[ self::RETRY ]['note'] );

		$this->assertSame( Chatterbox::GRADE_INSUFFICIENT, $by[ self::SPARSE ]['grade'] );
		$this->assertSame( 1, $by[ self::SPARSE ]['calls'] );
	}

	public function test_burst_clustering_gap_splits(): void {
		$t = self::T0;
		// 6 calls with 3s gaps = one burst of 6.
		$six = array();
		for ( $i = 0; $i < 6; $i++ ) {
			$six[] = array(
				'ts'       => $t + ( $i * 3 ),
				'endpoint' => 'api.example',
			);
		}
		$bursts = Chatterbox::cluster_bursts( $six, Chatterbox::GAP_SECONDS );
		$this->assertCount( 1, $bursts );
		$this->assertSame( 6, $bursts[0]['size'] );

		// A 20s gap splits bursts.
		$split = array(
			array( 'ts' => $t, 'endpoint' => 'a' ),
			array( 'ts' => $t + 3, 'endpoint' => 'a' ),
			array( 'ts' => $t + 23, 'endpoint' => 'a' ),
			array( 'ts' => $t + 26, 'endpoint' => 'a' ),
		);
		$bursts2 = Chatterbox::cluster_bursts( $split, Chatterbox::GAP_SECONDS );
		$this->assertCount( 2, $bursts2 );
		$this->assertSame( 2, $bursts2[0]['size'] );
		$this->assertSame( 2, $bursts2[1]['size'] );
	}

	public function test_fan_out_vs_retry_distinction_on_page(): void {
		$t = self::T0;
		Chatterbox::set_test_log(
			array(
				array( 'plugin' => self::FAN, 'ts' => $t, 'host' => 'a.example' ),
				array( 'plugin' => self::FAN, 'ts' => $t + 2, 'host' => 'b.example' ),
				array( 'plugin' => self::FAN, 'ts' => $t + 4, 'host' => 'c.example' ),
				array( 'plugin' => self::FAN, 'ts' => $t + 6, 'host' => 'd.example' ),
				array( 'plugin' => self::FAN, 'ts' => $t + 8, 'host' => 'e.example' ),
				array( 'plugin' => self::RETRY, 'ts' => $t, 'host' => 'same.example' ),
				array( 'plugin' => self::RETRY, 'ts' => $t + 2, 'host' => 'same.example' ),
				array( 'plugin' => self::RETRY, 'ts' => $t + 4, 'host' => 'same.example' ),
			)
		);
		ob_start();
		Chatterbox::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'CHATTERBOX', $html );
		$this->assertStringContainsString( 'TALKATIVE', $html );
		$this->assertStringContainsString( 'fan-out', $html );
		$this->assertStringContainsString( 'Retry-storm', $html );
		$this->assertStringContainsString( self::FAN, $html );
		$this->assertStringContainsString( self::RETRY, $html );
	}

	public function test_zero_writes_to_activity_log_or_any_option(): void {
		$log = array(
			array( 'plugin' => self::SOLO, 'ts' => self::T0, 'host' => 'a' ),
			array( 'plugin' => self::SOLO, 'ts' => self::T0 + 20, 'host' => 'a' ),
		);
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
		update_option( Plugin::OPTION_KEY, array( 'keep' => true ), false );
		$before_log    = get_option( Plugin::LOG_OPTION_KEY, null );
		$before_policy = get_option( Plugin::OPTION_KEY, null );
		$before_keys   = array_keys( $GLOBALS['handl_aicac_test_options'] ?? array() );

		Chatterbox::set_test_log( null );
		Chatterbox::census();
		ob_start();
		Chatterbox::render_page();
		ob_end_clean();

		$this->assertSame( $before_log, get_option( Plugin::LOG_OPTION_KEY, null ) );
		$this->assertSame( $before_policy, get_option( Plugin::OPTION_KEY, null ) );
		$after_keys = array_keys( $GLOBALS['handl_aicac_test_options'] ?? array() );
		sort( $before_keys );
		sort( $after_keys );
		$this->assertSame( $before_keys, $after_keys );

		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-chatterbox.php' );
		$this->assertStringNotContainsString( 'update_option', $src );
		$this->assertStringNotContainsString( 'delete_option', $src );
		$this->assertStringNotContainsString( 'add_option', $src );
		$this->assertStringNotContainsString( 'Retry_Storm', $src );
	}

	public function test_plugin_bootstrap_wires_chatterbox_at_bottom(): void {
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-chatterbox.php', $plugin );
		$this->assertStringContainsString( 'Chatterbox::init()', $plugin );
		$this->assertGreaterThan(
			strrpos( $plugin, 'Rescan_Schedule::init()' ),
			strrpos( $plugin, 'Chatterbox::init()' )
		);
	}

	public function test_unavailable_log_shows_insufficient_data(): void {
		Chatterbox::set_test_log( array() );
		Chatterbox::set_test_log_available( false );
		ob_start();
		Chatterbox::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'INSUFFICIENT-DATA', $html );
		$this->assertStringContainsString( 'unavailable', $html );
	}

	public function test_gap_constant_is_five_seconds(): void {
		$this->assertSame( 5, Chatterbox::GAP_SECONDS );
	}
}
