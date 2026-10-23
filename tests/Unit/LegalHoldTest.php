<?php
/**
 * AICAC-LEGAL-HOLD (#383).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Legal_Hold;
use HandL\AICAC\Log_Retention;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class LegalHoldTest extends TestCase {

	/** @var string */
	private $tmpdir = '';

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Legal_Hold::reset_for_tests();
		$this->tmpdir = sys_get_temp_dir() . '/aicac-legal-hold-' . uniqid( '', true );
		mkdir( $this->tmpdir, 0755, true );
		Legal_Hold::set_test_dir( $this->tmpdir );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'          => 'allow',
				'log_enabled'      => true,
				'audit_only'       => false,
				'log_limit'        => 200,
				'log_max_age_days' => 7,
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
		Log_Retention::save_meta( array( 'export_pending' => false ) );
		// Test harness add_filter is a recorder only; wire the prune filter explicitly.
		$GLOBALS['handl_aicac_test_filters']['handl_aicac_log_retention_kept_rows'] = array( Legal_Hold::class, 'filter_kept_rows' );
		Legal_Hold::init();
	}

	protected function tearDown(): void {
		Legal_Hold::purge_snapshot_files( $this->tmpdir );
		if ( is_dir( $this->tmpdir ) ) {
			Legal_Hold::purge_snapshot_files( $this->tmpdir );
			@rmdir( $this->tmpdir );
		}
		Legal_Hold::reset_for_tests();
		$GLOBALS['handl_aicac_test_options'] = array();
		unset( $GLOBALS['handl_aicac_test_current_user_can'], $GLOBALS['handl_aicac_test_filters']['handl_aicac_log_retention_kept_rows'] );
		parent::tearDown();
	}

	public function test_inert_with_zero_holds(): void {
		$this->assertFalse( Legal_Hold::has_active_holds() );
		$summary = Legal_Hold::status_summary();
		$this->assertSame( 0, $summary['active'] );
		$this->assertSame( 0, $summary['held_rows'] );

		$now = 1_700_000_000;
		$day = Policy::day_in_seconds();
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => $now - ( 40 * $day ),
					'plugin'   => 'old/old.php',
					'decision' => 'allow',
					'provider' => 'openai',
					'user_id'  => 9,
				),
			),
			false
		);
		$result = Log_Retention::run_prune_batch( Policy::get_policy(), $now );
		$this->assertSame( 'pruned', $result['status'] );
		$this->assertSame( 1, $result['removed'] );
	}

	public function test_create_appends_ledger_and_writes_snapshot(): void {
		$now = 1_700_000_100;
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => $now - 100,
					'plugin'   => 'acme/acme.php',
					'decision' => 'allow',
					'provider' => 'openai',
					'user_id'  => 12,
					'operation'=> 'generate_text',
				),
				array(
					'ts'       => $now - 50,
					'plugin'   => 'other/other.php',
					'decision' => 'allow',
					'provider' => 'anthropic',
					'user_id'  => 99,
					'operation'=> 'generate_text',
				),
			),
			false
		);

		$result = Legal_Hold::create_hold(
			array(
				'name'    => 'Counsel hold',
				'scope'   => Legal_Hold::SCOPE_USER,
				'users'   => array( 12 ),
				'reason'  => 'Preserve user 12',
			),
			7,
			$now
		);
		$this->assertTrue( $result['ok'] );
		$this->assertSame( 1, $result['matched'] );
		$this->assertNotEmpty( $result['id'] );

		$holds = Legal_Hold::get_active_holds();
		$this->assertCount( 1, $holds );
		$ledger = Legal_Hold::get_ledger();
		$this->assertCount( 1, $ledger );
		$this->assertSame( 'create', $ledger[0]['action'] );
		$this->assertSame( 7, $ledger[0]['actor'] );

		$dir = Legal_Hold::hold_dir( (string) $result['id'] );
		$this->assertFileExists( $dir . '/manifest.json' );
		$this->assertFileExists( $dir . '/activity.csv' );
		$this->assertFileExists( $dir . '/activity.json' );
	}

	public function test_user_scope_survives_prune_batch(): void {
		$now = 1_700_000_200;
		$day = Policy::day_in_seconds();
		$held = array(
			'ts'       => $now - ( 40 * $day ),
			'plugin'   => 'acme/acme.php',
			'decision' => 'allow',
			'provider' => 'openai',
			'user_id'  => 12,
			'operation'=> 'generate_text',
		);
		$other = array(
			'ts'       => $now - ( 40 * $day ),
			'plugin'   => 'other/other.php',
			'decision' => 'allow',
			'provider' => 'openai',
			'user_id'  => 99,
			'operation'=> 'generate_text',
		);
		$fresh = array(
			'ts'       => $now - 30,
			'plugin'   => 'fresh/fresh.php',
			'decision' => 'allow',
			'provider' => 'openai',
			'user_id'  => 1,
			'operation'=> 'generate_text',
		);
		update_option( Plugin::LOG_OPTION_KEY, array( $held, $other, $fresh ), false );

		$created = Legal_Hold::create_hold(
			array(
				'scope'  => Legal_Hold::SCOPE_USER,
				'users'  => array( 12 ),
				'reason' => 'Hold user 12',
			),
			1,
			$now
		);
		$this->assertTrue( $created['ok'] );

		$result = Log_Retention::run_prune_batch( Policy::get_policy(), $now );
		$this->assertSame( 'pruned', $result['status'] );
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$plugins = array_map(
			static function ( $row ) {
				return is_array( $row ) ? (string) ( $row['plugin'] ?? '' ) : '';
			},
			is_array( $log ) ? $log : array()
		);
		$this->assertContains( 'acme/acme.php', $plugins );
		$this->assertNotContains( 'other/other.php', $plugins );
		$this->assertContains( 'fresh/fresh.php', $plugins );
	}

	public function test_site_scope_keeps_all_rows_through_entry_cap(): void {
		$now = 1_700_000_300;
		$day = Policy::day_in_seconds();
		$log = array();
		for ( $i = 0; $i < 5; $i++ ) {
			$log[] = array(
				'ts'       => $now - ( ( 20 + $i ) * $day ),
				'plugin'   => 'p' . $i . '/p.php',
				'decision' => 'allow',
				'provider' => 'openai',
				'user_id'  => $i + 1,
				'operation'=> 'generate_text',
			);
		}
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled'      => true,
				'log_limit'        => 2,
				'log_max_age_days' => 7,
			),
			false
		);
		update_option( Plugin::LOG_OPTION_KEY, $log, false );

		$created = Legal_Hold::create_hold(
			array(
				'scope'  => Legal_Hold::SCOPE_SITE,
				'reason' => 'Site-wide hold',
			),
			1,
			$now
		);
		$this->assertTrue( $created['ok'] );

		$result = Log_Retention::run_prune_batch( Policy::get_policy(), $now );
		$this->assertSame( 'pruned', $result['status'] );
		$after = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $after );
		$this->assertCount( 5, $after );
	}

	public function test_release_restores_purge(): void {
		$now = 1_700_000_400;
		$day = Policy::day_in_seconds();
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => $now - ( 40 * $day ),
					'plugin'   => 'acme/acme.php',
					'decision' => 'allow',
					'provider' => 'openai',
					'user_id'  => 12,
					'operation'=> 'generate_text',
				),
			),
			false
		);
		$created = Legal_Hold::create_hold(
			array(
				'scope'  => Legal_Hold::SCOPE_PLUGIN,
				'plugin' => 'acme/acme.php',
				'reason' => 'Hold plugin',
			),
			1,
			$now
		);
		$this->assertTrue( $created['ok'] );
		$id = (string) $created['id'];

		$blocked = Log_Retention::run_prune_batch( Policy::get_policy(), $now );
		$this->assertSame( 'pruned', $blocked['status'] );
		// Prune may count a drop before the hold filter re-merges; the log must still keep the row.
		$this->assertCount( 1, get_option( Plugin::LOG_OPTION_KEY, array() ) );

		$released = Legal_Hold::release_hold( $id, 'Matter closed', 2, $now + 10 );
		$this->assertTrue( $released['ok'] );
		$ledger = Legal_Hold::get_ledger();
		$this->assertSame( 'release', $ledger[ count( $ledger ) - 1 ]['action'] );

		$pruned = Log_Retention::run_prune_batch( Policy::get_policy(), $now );
		$this->assertSame( 'pruned', $pruned['status'] );
		$this->assertSame( 1, $pruned['removed'] );
		$this->assertCount( 0, get_option( Plugin::LOG_OPTION_KEY, array() ) );
	}

	public function test_roster_csv_includes_active_hold(): void {
		$created = Legal_Hold::create_hold(
			array(
				'name'     => 'Provider hold',
				'scope'    => Legal_Hold::SCOPE_PROVIDER,
				'provider' => 'openai',
				'reason'   => 'Vendor matter',
			),
			3,
			1_700_000_500
		);
		$this->assertTrue( $created['ok'] );
		$csv = Legal_Hold::csv_for_roster();
		$this->assertStringContainsString( 'Provider hold', $csv );
		$this->assertStringContainsString( 'provider:openai', $csv );
		$this->assertStringContainsString( 'active', $csv );
	}

	public function test_csv_rfc_escapes_backslash_comma_quote(): void {
		$csv = Legal_Hold::csv_for_roster(
			array(
				array(
					'id'            => 'h1',
					'name'          => 'Acme, "Inc" \hold',
					'scope'         => Legal_Hold::SCOPE_SITE,
					'status'        => 'active',
					'scope_detail'  => 'site',
					'reason'        => 'path \foo, "bar"',
					'created_at'    => 1700000500,
					'created_by'    => 3,
					'released_at'   => 0,
					'matched_count' => 0,
					'snapshot_path' => '',
				),
			)
		);
		$this->assertStringContainsString( '"Acme, ""Inc"" \hold"', $csv );
		$this->assertStringContainsString( '"path \foo, ""bar"""', $csv );
		$this->assertStringNotContainsString( '\\"', $csv );
	}

	public function test_reason_required(): void {
		$result = Legal_Hold::create_hold(
			array(
				'scope' => Legal_Hold::SCOPE_SITE,
				'reason'=> '',
			)
		);
		$this->assertFalse( $result['ok'] );
		$this->assertSame( 'reason_required', $result['error'] );
	}
}
