<?php
/**
 * Unit tests for AICAC-STORAGE footprint + retention estimator (#150).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Log_Storage;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Usage_Trends;
use PHPUnit\Framework\TestCase;

final class LogStorageTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options'] = array();
		unset( $GLOBALS['wpdb'] );
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options'] = array();
		unset( $GLOBALS['wpdb'] );
		parent::tearDown();
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private function fixture_log( int $now ): array {
		$day = Policy::day_in_seconds();
		$log = array();
		// 10 rows/week for 10 weeks (70 days of history).
		for ( $w = 0; $w < 10; $w++ ) {
			for ( $i = 0; $i < 10; $i++ ) {
				$log[] = array(
					'ts'       => $now - ( $w * 7 * $day ) - ( $i * 3600 ),
					'decision' => 'allow',
					'plugin'   => 'demo/demo.php',
					'channel'  => 'ai_client',
				);
			}
		}

		return $log;
	}

	public function test_footprint_count_matches_log_and_bytes_match_serialize(): void {
		$now = 1_700_000_000;
		$log = $this->fixture_log( $now );

		$fp = Log_Storage::footprint( $log, $now );

		$this->assertSame( 100, $fp['row_count'] );
		$this->assertSame( strlen( serialize( $log ) ), $fp['approx_bytes'] );
		$this->assertNotNull( $fp['oldest_ts'] );
		$this->assertGreaterThan( 60.0, (float) $fp['oldest_age_days'] );
		$this->assertNotNull( $fp['rows_per_week'] );
		$this->assertSame( 10.0, (float) $fp['rows_per_week'] );
	}

	public function test_approx_bytes_prefers_db_length_when_wpdb_available(): void {
		$log = array(
			array( 'ts' => 1, 'plugin' => 'a/a.php' ),
		);
		$GLOBALS['wpdb'] = new class() {
			public string $options = 'wp_options';

			public function prepare( $query, ...$args ) {
				return $query;
			}

			public function get_var( $query ) {
				unset( $query );
				return '4242';
			}
		};

		$this->assertSame( 4242, Log_Storage::approx_bytes( $log ) );
		$this->assertSame( strlen( serialize( $log ) ), Log_Storage::serialized_bytes( $log ) );
	}

	public function test_estimate_if_retention_days_within_fixture_math(): void {
		$now = 1_700_000_000;
		$log = $this->fixture_log( $now );

		$est30 = Log_Storage::estimate_if_retention_days( $log, 30, $now );
		// Weeks 5–9 (0-indexed from newest) fall outside 30 days → 50 purged, 50 kept.
		$this->assertSame( 30, $est30['days'] );
		$this->assertSame( 50, $est30['rows_kept'] );
		$this->assertSame( 50, $est30['rows_purged'] );
		$this->assertSame( strlen( serialize( array_slice( $log, 0, 50 ) ) ), $est30['approx_bytes_kept'] );
		$this->assertSame(
			strlen( serialize( $log ) ) - $est30['approx_bytes_kept'],
			$est30['approx_bytes_saved']
		);

		$est7 = Log_Storage::estimate_if_retention_days( $log, 7, $now );
		// Week-0 rows (10) stay; the row exactly at the 7-day cutoff is kept (< cutoff only).
		$this->assertSame( 11, $est7['rows_kept'] );
		$this->assertSame( 89, $est7['rows_purged'] );
	}

	public function test_suggested_retention_when_older_rows_exist(): void {
		$now     = 1_700_000_000;
		$log     = $this->fixture_log( $now );
		$policy  = array( 'log_limit' => 200, 'log_max_age_days' => null );

		$this->assertSame( 56, Log_Storage::suggested_retention_days( $log, $policy, $now ) );

		$policy['log_max_age_days'] = 30;
		$this->assertNull( Log_Storage::suggested_retention_days( $log, $policy, $now ) );

		$short = array_slice( $log, 0, 20 ); // ~2 weeks only.
		$policy['log_max_age_days'] = null;
		$this->assertNull( Log_Storage::suggested_retention_days( $short, $policy, $now ) );
	}

	public function test_insights_purge_warning_fires_only_when_applicable(): void {
		$now = 1_700_000_000;
		$day = Policy::day_in_seconds();
		$log = array();
		// Spread AI Client activity across 8 distinct weeks so Insights renders.
		for ( $w = 0; $w < 8; $w++ ) {
			for ( $i = 0; $i < 3; $i++ ) {
				$log[] = array(
					'ts'       => $now - ( $w * 7 * $day ) - ( $i * 3600 ),
					'decision' => 'allow',
					'plugin'   => 'demo/demo.php',
					'channel'  => 'ai_client',
				);
			}
		}

		$policy = array(
			'log_limit'        => 200,
			'log_max_age_days' => null,
		);

		$before = Usage_Trends::compute( $log, $policy, array(), $now );
		$this->assertNotNull( $before );
		$this->assertGreaterThanOrEqual( Usage_Trends::MIN_WEEKS_WITH_DATA, (int) $before['weeks_with_data'] );

		// 7-day TTL collapses Insights coverage → warning.
		$warn = Log_Storage::insights_purge_warning( $log, $policy, 7, $now );
		$this->assertNotNull( $warn );
		$this->assertTrue( $warn['would_purge'] );
		$this->assertGreaterThan( 0, $warn['rows_purged_in_window'] );
		$this->assertLessThan( $warn['weeks_with_data_before'], $warn['weeks_with_data_after'] );

		// 56-day TTL keeps the Insights window → no warning.
		$this->assertNull( Log_Storage::insights_purge_warning( $log, $policy, 56, $now ) );

		// Empty / no Insights → no warning.
		$this->assertNull( Log_Storage::insights_purge_warning( array(), $policy, 7, $now ) );
	}

	public function test_format_bytes(): void {
		$this->assertSame( '0 B', Log_Storage::format_bytes( 0 ) );
		$this->assertSame( '500 B', Log_Storage::format_bytes( 500 ) );
		$this->assertSame( '1.5 KB', Log_Storage::format_bytes( 1536 ) );
		$this->assertSame( '2 MB', Log_Storage::format_bytes( 2 * 1024 * 1024 ) );
	}

	public function test_prefill_never_mutates_policy_option(): void {
		$now = 1_700_000_000;
		$log = $this->fixture_log( $now );
		update_option( Plugin::OPTION_KEY, array( 'log_max_age_days' => null, 'log_limit' => 200 ), false );
		update_option( Plugin::LOG_OPTION_KEY, $log, false );

		$suggested = Log_Storage::suggested_retention_days( $log, Policy::get_policy(), $now );
		$this->assertSame( 56, $suggested );

		// Calling estimator / suggestion must not persist a TTL.
		Log_Storage::estimate_if_retention_days( $log, 56, $now );
		$policy = Policy::get_policy();
		$this->assertNull( Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null ) );
		$this->assertSame( $log, get_option( Plugin::LOG_OPTION_KEY ) );
	}
}
