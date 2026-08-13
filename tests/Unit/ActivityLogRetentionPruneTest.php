<?php
/**
 * Unit tests for AICAC-RETENTION (#174) scheduled prune + export gate.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Log_Retention;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class ActivityLogRetentionPruneTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_crons']   = array();
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_crons']   = array();
		parent::tearDown();
	}

	public function test_boundary_row_at_cutoff_is_kept(): void {
		$now  = 1_700_000_000;
		$day  = Policy::day_in_seconds();
		$days = 30;
		$cutoff = $now - ( $days * $day );

		$log = array(
			array( 'ts' => $cutoff - 1, 'plugin' => 'gone' ),
			array( 'ts' => $cutoff, 'plugin' => 'edge' ),
			array( 'ts' => $cutoff + 1, 'plugin' => 'keep' ),
		);

		$doomed = Log_Retention::rows_past_retention( $log, $days, $now );
		$this->assertCount( 1, $doomed );
		$this->assertSame( 'gone', $doomed[0]['plugin'] );
	}

	public function test_after_settings_saved_gates_export_when_rows_would_be_removed(): void {
		$now = 1_700_000_000;
		$day = Policy::day_in_seconds();

		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array( 'ts' => $now - ( 100 * $day ), 'plugin' => 'old' ),
				array( 'ts' => $now - 10, 'plugin' => 'new' ),
			),
			false
		);

		$previous = array( 'log_max_age_days' => null );
		$saved    = array( 'log_max_age_days' => 30 );

		Log_Retention::after_settings_saved( $previous, $saved, $now );
		$this->assertTrue( Log_Retention::is_export_pending() );

		$result = Log_Retention::run_prune_batch( $saved, $now );
		$this->assertSame( 'waiting_export', $result['status'] );
		$this->assertSame( 0, $result['removed'] );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertCount( 2, $log );
	}

	public function test_batched_prune_removes_oldest_expired_first(): void {
		$now = 1_700_000_000;
		$day = Policy::day_in_seconds();

		$log = array();
		for ( $i = 0; $i < 5; $i++ ) {
			$log[] = array( 'ts' => $now - ( ( 200 - $i ) * $day ), 'plugin' => 'old-' . $i );
		}
		$log[] = array( 'ts' => $now - 10, 'plugin' => 'fresh' );
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_limit'        => 200,
				'log_max_age_days' => 30,
			),
			false
		);

		Log_Retention::save_meta( array( 'export_pending' => false ) );

		// Shrink batch via reflection-free approach: prune with small doomed set already.
		$result = Log_Retention::run_prune_batch( Policy::get_policy(), $now );
		$this->assertSame( 'pruned', $result['status'] );
		$this->assertGreaterThan( 0, $result['removed'] );
		$this->assertLessThanOrEqual( Log_Retention::BATCH_SIZE, $result['removed'] );

		$kept = get_option( Plugin::LOG_OPTION_KEY );
		$plugins = array_map(
			static function ( $row ) {
				return is_array( $row ) ? (string) ( $row['plugin'] ?? '' ) : '';
			},
			is_array( $kept ) ? $kept : array()
		);
		$this->assertContains( 'fresh', $plugins );
		$this->assertGreaterThan( 0, Log_Retention::meta()['last_prune_ts'] );
	}

	public function test_forever_clears_export_gate_and_does_not_schedule_needlessly(): void {
		$previous = array( 'log_max_age_days' => 90 );
		$saved    = array( 'log_max_age_days' => null );
		Log_Retention::save_meta(
			array(
				'export_pending'     => true,
				'export_period_days' => 90,
			)
		);
		Log_Retention::after_settings_saved( $previous, $saved, time() );
		$this->assertFalse( Log_Retention::is_export_pending() );

		$result = Log_Retention::run_prune_batch( $saved, time() );
		$this->assertSame( 'disabled', $result['status'] );
	}

	public function test_get_retained_log_defers_ttl_while_export_pending(): void {
		$now = 1_700_000_000;
		$day = Policy::day_in_seconds();

		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled'      => true,
				'log_limit'        => 200,
				'log_max_age_days' => 1,
			),
			false
		);
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array( 'ts' => $now - ( 5 * $day ), 'plugin' => 'stale' ),
				array( 'ts' => $now - 10, 'plugin' => 'fresh' ),
			),
			false
		);
		Log_Retention::save_meta(
			array(
				'export_pending'     => true,
				'export_period_days' => 1,
			)
		);

		$log = Policy::get_retained_log( $now );
		$plugins = array_map(
			static function ( $row ) {
				return is_array( $row ) ? (string) ( $row['plugin'] ?? '' ) : '';
			},
			$log
		);
		$this->assertContains( 'stale', $plugins );
		$this->assertContains( 'fresh', $plugins );
	}

	public function test_mark_export_completed_allows_prune(): void {
		$now = 1_700_000_000;
		$day = Policy::day_in_seconds();

		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_limit'        => 200,
				'log_max_age_days' => 7,
			),
			false
		);
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array( 'ts' => $now - ( 40 * $day ), 'plugin' => 'old' ),
				array( 'ts' => $now - 60, 'plugin' => 'new' ),
			),
			false
		);
		Log_Retention::save_meta( array( 'export_pending' => true ) );
		Log_Retention::mark_export_completed();
		$this->assertFalse( Log_Retention::is_export_pending() );

		$result = Log_Retention::run_prune_batch( Policy::get_policy(), $now );
		$this->assertSame( 'pruned', $result['status'] );
		$this->assertSame( 1, $result['removed'] );
	}
}
