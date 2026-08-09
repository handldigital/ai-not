<?php
/**
 * Unit tests for optional time-based audit-log retention (AICAC-TTL / #57).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class LogRetentionTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options'] = array();
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options'] = array();
		parent::tearDown();
	}

	public function test_sanitize_log_max_age_days_empty_is_off(): void {
		$this->assertNull( Policy::sanitize_log_max_age_days( null ) );
		$this->assertNull( Policy::sanitize_log_max_age_days( '' ) );
		$this->assertNull( Policy::sanitize_log_max_age_days( '   ' ) );
		$this->assertNull( Policy::sanitize_log_max_age_days( 0 ) );
		$this->assertNull( Policy::sanitize_log_max_age_days( -3 ) );
		$this->assertNull( Policy::sanitize_log_max_age_days( 'nope' ) );
	}

	public function test_sanitize_log_max_age_days_accepts_positive_integers(): void {
		$this->assertSame( 1, Policy::sanitize_log_max_age_days( 1 ) );
		$this->assertSame( 30, Policy::sanitize_log_max_age_days( '30' ) );
		$this->assertSame( 3650, Policy::sanitize_log_max_age_days( 99999 ) );
	}

	public function test_ttl_prunes_entries_older_than_threshold(): void {
		$now  = 1_700_000_000;
		$day  = Policy::day_in_seconds();
		$log  = array(
			array( 'ts' => $now - ( 10 * $day ), 'decision' => 'allow', 'plugin' => 'old/a.php' ),
			array( 'ts' => $now - ( 2 * $day ), 'decision' => 'deny', 'plugin' => 'keep/b.php' ),
			array( 'ts' => $now - 60, 'decision' => 'allow', 'plugin' => 'keep/c.php' ),
		);
		$policy = array(
			'log_limit'         => 200,
			'log_max_age_days'  => 7,
		);

		$out = Policy::apply_log_retention( $log, $policy, $now );

		$this->assertCount( 2, $out );
		$this->assertSame( 'keep/b.php', $out[0]['plugin'] );
		$this->assertSame( 'keep/c.php', $out[1]['plugin'] );
	}

	public function test_entry_count_and_ttl_both_apply_stricter_wins(): void {
		$now = 1_700_000_000;
		$day = Policy::day_in_seconds();
		// 25 recent rows (all within TTL) plus 5 ancient — TTL drops ancient; count keeps 20 newest.
		$log = array();
		for ( $i = 0; $i < 5; $i++ ) {
			$log[] = array( 'ts' => $now - ( 40 * $day ), 'plugin' => 'ancient-' . $i );
		}
		for ( $i = 0; $i < 25; $i++ ) {
			$log[] = array( 'ts' => $now - $i, 'plugin' => 'recent-' . $i );
		}

		$policy = array(
			'log_limit'        => 20,
			'log_max_age_days' => 30,
		);

		$out = Policy::apply_log_retention( $log, $policy, $now );

		$this->assertCount( 20, $out );
		foreach ( $out as $row ) {
			$this->assertStringStartsWith( 'recent-', (string) $row['plugin'] );
		}
		// Newest 20 of the recent-* series (indices 5..24 of original recent block = last 20).
		$this->assertSame( 'recent-5', $out[0]['plugin'] );
		$this->assertSame( 'recent-24', $out[19]['plugin'] );
	}

	public function test_ttl_off_keeps_old_rows_until_count_cap(): void {
		$now = 1_700_000_000;
		$day = Policy::day_in_seconds();
		$log = array(
			array( 'ts' => $now - ( 400 * $day ), 'plugin' => 'old' ),
			array( 'ts' => $now, 'plugin' => 'new' ),
		);
		$policy = array(
			'log_limit'        => 200,
			'log_max_age_days' => null,
		);

		$out = Policy::apply_log_retention( $log, $policy, $now );
		$this->assertCount( 2, $out );
	}

	public function test_append_log_event_prunes_by_ttl(): void {
		$now = 1_700_000_000;
		$day = Policy::day_in_seconds();

		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled'      => true,
				'log_limit'        => 200,
				'log_max_age_days' => 3,
			),
			false
		);
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array( 'ts' => $now - ( 10 * $day ), 'plugin' => 'stale', 'decision' => 'allow' ),
				array( 'ts' => $now - $day, 'plugin' => 'keep', 'decision' => 'deny' ),
			),
			false
		);

		Policy::append_log_event(
			array(
				'ts'       => $now,
				'plugin'   => 'fresh',
				'decision' => 'allow',
			)
		);

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$plugins = array_map(
			static function ( $row ) {
				return is_array( $row ) ? (string) ( $row['plugin'] ?? '' ) : '';
			},
			$log
		);
		$this->assertNotContains( 'stale', $plugins );
		$this->assertContains( 'keep', $plugins );
		$this->assertContains( 'fresh', $plugins );
	}

	public function test_get_retained_log_persists_prune(): void {
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
				array( 'ts' => $now - ( 5 * $day ), 'plugin' => 'gone' ),
				array( 'ts' => $now - 10, 'plugin' => 'stay' ),
			),
			false
		);

		$out = Policy::get_retained_log( $now );
		$this->assertCount( 1, $out );
		$this->assertSame( 'stay', $out[0]['plugin'] );

		$stored = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertCount( 1, $stored );
		$this->assertSame( 'stay', $stored[0]['plugin'] );
	}

	public function test_collapse_of_active_direct_http_survives_ttl_prune(): void {
		$now = 1_700_000_000;
		$day = Policy::day_in_seconds();

		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled'      => true,
				'log_limit'        => 200,
				'log_max_age_days' => 7,
			),
			false
		);
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'channel' => 'direct_http',
					'host'    => 'api.openai.com',
					'plugin'  => 'caller/x.php',
					'ts'      => $now - 30,
					'count'   => 2,
					'decision'=> 'observe',
				),
				array(
					'channel'  => 'ai_client',
					'ts'       => $now - ( 20 * $day ),
					'plugin'   => 'ancient/ai.php',
					'decision' => 'allow',
				),
			),
			false
		);

		Policy::append_log_event(
			array(
				'channel'  => 'direct_http',
				'host'     => 'api.openai.com',
				'plugin'   => 'caller/x.php',
				'ts'       => $now,
				'count'    => 1,
				'decision' => 'observe',
			)
		);

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		// Ancient AI Client row pruned by TTL; direct_http cluster collapsed (count 3).
		$this->assertCount( 1, $log );
		$this->assertSame( 'direct_http', $log[0]['channel'] );
		$this->assertSame( 3, (int) $log[0]['count'] );
		$this->assertSame( $now, (int) $log[0]['ts'] );
	}
}
