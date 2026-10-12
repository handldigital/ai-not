<?php
/**
 * AICAC-SUNDIAL (#417).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Sundial;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class SundialTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12 UTC.

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$GLOBALS['handl_aicac_test_cron']             = array();
		unset( $GLOBALS['wpdb'] );
		Sundial::reset_for_tests();
		update_option( 'admin_email', 'haktan+aicac-sundial@handldigital.com' );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'alert_email' => 'haktan+aicac-sundial@handldigital.com',
			)
		);
		Sundial::set_test_now( self::NOW );
		Sundial::set_test_db_time( self::NOW );
		Sundial::set_test_log( array() );
		Sundial::set_test_php_timezone( 'UTC' );
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_test_filters'][ Sundial::FILTER_SKEW_THRESHOLD ], $GLOBALS['wpdb'] );
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_cron']          = array();
		Sundial::reset_for_tests();
		parent::tearDown();
	}

	private function enable( int $threshold = 120, int $tolerance = 60 ): void {
		Sundial::save_settings(
			array(
				'enabled'              => true,
				'skew_threshold_sec'   => $threshold,
				'future_tolerance_sec' => $tolerance,
			)
		);
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 * @return list<string>
	 */
	private function codes( array $snap ): array {
		$codes = array();
		foreach ( $snap['findings'] as $row ) {
			$codes[] = $row['code'];
		}

		return $codes;
	}

	public function test_defaults_off_save_defaults_deletes_and_noop_byte_identical(): void {
		$this->assertFalse( Sundial::is_enabled() );
		$this->assertSame( Sundial::defaults(), Sundial::get_settings() );
		$this->assertSame( 120, Sundial::defaults()['skew_threshold_sec'] );
		$this->assertSame( 60, Sundial::defaults()['future_tolerance_sec'] );
		$this->assertSame( 'report_only_never_adjusts_clock', Sundial::FRAMING );
		$this->assertSame( 'handl-aicac-sundial', Sundial::PAGE_SLUG );

		$this->assertTrue( Sundial::save_settings( array( 'enabled' => true ) ) );
		$this->assertTrue( Sundial::is_enabled() );
		$before  = get_option( Sundial::SETTINGS_OPTION );
		$changed = Sundial::save_settings( array( 'enabled' => true ) );
		$this->assertFalse( $changed );
		$this->assertSame( $before, get_option( Sundial::SETTINGS_OPTION ) );

		Sundial::save_settings( Sundial::defaults() );
		$this->assertFalse( (bool) get_option( Sundial::SETTINGS_OPTION, false ) );
		$this->assertFalse( Sundial::save_settings( Sundial::defaults() ) );
	}

	public function test_threshold_sanitize_clamp_and_filter(): void {
		$this->assertSame( 30, Sundial::sanitize_skew_threshold( 0 ) );
		$this->assertSame( 30, Sundial::sanitize_skew_threshold( -50 ) );
		$this->assertSame( 3600, Sundial::sanitize_skew_threshold( 999999 ) );
		$this->assertSame( 120, Sundial::sanitize_skew_threshold( 'nope' ) );
		$this->assertSame( 120, Sundial::sanitize_skew_threshold( NAN ) );
		$this->assertSame( 300, Sundial::sanitize_skew_threshold( ' 300 ' ) );
		$this->assertSame( 0, Sundial::sanitize_future_tolerance( -5 ) );
		$this->assertSame( 3600, Sundial::sanitize_future_tolerance( 99999 ) );
		$this->assertSame( 60, Sundial::sanitize_future_tolerance( 'x' ) );

		$this->enable( 300 );
		$this->assertSame( 300, Sundial::skew_threshold() );
		$GLOBALS['handl_aicac_test_filters'][ Sundial::FILTER_SKEW_THRESHOLD ] = static function (): int {
			return 45;
		};
		$this->assertSame( 45, Sundial::skew_threshold() );
		$GLOBALS['handl_aicac_test_filters'][ Sundial::FILTER_SKEW_THRESHOLD ] = static function (): int {
			return 5;
		};
		$this->assertSame( 30, Sundial::skew_threshold(), 'Filter output is clamped.' );
	}

	public function test_clean_environment_has_no_findings(): void {
		$this->enable();
		$snap = Sundial::snapshot();
		$this->assertSame( 0, $snap['finding_count'] );
		$this->assertSame( array(), $snap['findings'] );
		$this->assertSame( 0, $snap['skew_sec'] );
		$this->assertSame( self::NOW, $snap['php_time'] );
		$this->assertSame( self::NOW, $snap['db_time'] );
		$this->assertSame( Sundial::FRAMING, $snap['framing'] );
		$this->assertTrue( $snap['enabled'] );
		$this->assertFalse( $snap['alerted'] );
	}

	public function test_skew_finding_when_php_fast_at_or_over_threshold(): void {
		$this->enable( 120 );
		Sundial::set_test_db_time( self::NOW - 120 );
		$snap = Sundial::snapshot();
		$this->assertSame( array( 'php_db_skew' ), $this->codes( $snap ) );
		$row = $snap['findings'][0];
		$this->assertSame( 120, $row['delta_sec'] );
		$this->assertSame( 'php_fast', $row['direction'] );
		$this->assertSame( 120, $snap['skew_sec'] );
		$this->assertStringContainsString( 'early', $row['impact'] );
		$this->assertStringContainsString( 'untrustworthy', $row['impact'] );
		$names = array_column( $row['controls'], 'name' );
		foreach ( array( 'Temp_Allow', 'Freeze', 'Break_Glass', 'Log_Retention', 'Recert' ) as $name ) {
			$this->assertContains( $name, $names );
		}
	}

	public function test_skew_finding_when_php_slow(): void {
		$this->enable( 120 );
		Sundial::set_test_db_time( self::NOW + 900 );
		$snap = Sundial::snapshot();
		$row  = $snap['findings'][0];
		$this->assertSame( 'php_slow', $row['direction'] );
		$this->assertSame( -900, $row['delta_sec'] );
		$this->assertStringContainsString( 'retention overshoots', $row['impact'] );
		$this->assertStringContainsString( 'SLA', $row['impact'] );
		$this->assertContains( 'Log_Retention', array_column( $row['controls'], 'name' ) );
	}

	public function test_no_skew_finding_under_threshold_or_db_unavailable(): void {
		$this->enable( 120 );
		Sundial::set_test_db_time( self::NOW - 119 );
		$this->assertSame( 0, Sundial::snapshot()['finding_count'] );
		Sundial::set_test_db_time( self::NOW + 119 );
		$this->assertSame( 0, Sundial::snapshot()['finding_count'] );

		Sundial::set_test_db_time( null );
		$snap = Sundial::snapshot();
		$this->assertSame( 0, $snap['finding_count'] );
		$this->assertNull( $snap['db_time'] );
		$this->assertNull( $snap['skew_sec'] );
		$this->assertTrue( $snap['disable_flags']['db_time_unavailable'] );
	}

	public function test_threshold_setting_drives_skew_detection(): void {
		$this->enable( 600 );
		Sundial::set_test_db_time( self::NOW - 300 );
		$this->assertSame( 0, Sundial::snapshot()['finding_count'] );
		$this->enable( 200 );
		$this->assertSame( 1, Sundial::snapshot()['finding_count'] );
	}

	public function test_timezone_not_utc_finding_case_insensitive(): void {
		$this->enable();
		Sundial::set_test_php_timezone( 'America/Chicago' );
		$snap = Sundial::snapshot();
		$this->assertSame( array( 'timezone_not_utc' ), $this->codes( $snap ) );
		$this->assertSame( 'timezone_not_utc', $snap['findings'][0]['direction'] );
		$this->assertStringContainsString( 'America/Chicago', $snap['findings'][0]['summary'] );
		$this->assertStringContainsString( 'corrupted', $snap['findings'][0]['impact'] );

		foreach ( array( 'UTC', 'utc', 'Utc', 'Etc/UTC' ) as $ok ) {
			Sundial::set_test_php_timezone( $ok );
			$this->assertSame( 0, Sundial::snapshot()['finding_count'], $ok );
		}
	}

	public function test_wp_timezone_option_mismatch_heuristics(): void {
		$this->enable();

		// Consistent: Chicago in October is CDT (-5).
		update_option( 'timezone_string', 'America/Chicago' );
		update_option( 'gmt_offset', -5 );
		$this->assertSame( 0, Sundial::snapshot()['finding_count'] );

		// One-hour DST drift is tolerated.
		update_option( 'gmt_offset', -6 );
		$this->assertSame( 0, Sundial::snapshot()['finding_count'] );

		// Beyond 1h disagrees.
		update_option( 'gmt_offset', 3 );
		$snap = Sundial::snapshot();
		$this->assertSame( array( 'timezone_option_mismatch' ), $this->codes( $snap ) );
		$this->assertSame( 8 * 3600, $snap['findings'][0]['delta_sec'] );

		// Invalid timezone string.
		update_option( 'timezone_string', 'Mars/Olympus' );
		$this->assertSame( array( 'timezone_option_mismatch' ), $this->codes( Sundial::snapshot() ) );

		// Empty string with a plausible manual offset is fine; weird ones are not.
		update_option( 'timezone_string', '' );
		update_option( 'gmt_offset', 5.5 );
		$this->assertSame( 0, Sundial::snapshot()['finding_count'] );
		update_option( 'gmt_offset', 0 );
		$this->assertSame( 0, Sundial::snapshot()['finding_count'] );
		update_option( 'gmt_offset', 3.37 );
		$this->assertSame( array( 'timezone_option_mismatch' ), $this->codes( Sundial::snapshot() ) );
		update_option( 'gmt_offset', 30 );
		$this->assertSame( array( 'timezone_option_mismatch' ), $this->codes( Sundial::snapshot() ) );
	}

	public function test_future_dated_ledger_rows_finding(): void {
		$this->enable( 120, 60 );
		Sundial::set_test_log(
			array(
				array( 'ts' => self::NOW - 100 ),
				array( 'ts' => self::NOW + 60 ), // At tolerance: fine.
				array( 'ts' => self::NOW + 61 ),
				array( 'ts' => self::NOW + 3600 ),
				'not-a-row',
				array( 'plugin' => 'no-ts' ),
			)
		);
		$snap = Sundial::snapshot();
		$this->assertSame( array( 'future_rows' ), $this->codes( $snap ) );
		$future = $snap['findings'][0];
		$this->assertSame( 'future_rows', $future['code'] );
		$this->assertSame( 2, $future['count'] );
		$this->assertSame( 3600, $future['delta_sec'] );
		$this->assertCount( 2, $future['samples'] );
		$this->assertSame( 2, $future['samples'][0]['index'] );
		$this->assertStringContainsString( 'integrity', $future['impact'] );

		// Larger tolerance clears the small one.
		$this->enable( 120, 3600 );
		$snap = Sundial::snapshot();
		$this->assertNotContains( 'future_rows', $this->codes( $snap ) );
	}

	public function test_ordering_regression_finding_and_cap(): void {
		$this->enable();
		// Append order is oldest-first (new rows at the tail): ts must not decrease.
		Sundial::set_test_log(
			array(
				array( 'ts' => self::NOW - 500 ),
				array( 'ts' => self::NOW - 400 ),
				array( 'ts' => self::NOW - 450 ), // Regression of 50.
				array( 'ts' => self::NOW - 300 ),
				array( 'ts' => self::NOW - 301 ), // Within concurrent-write tolerance.
			)
		);
		$snap = Sundial::snapshot();
		$this->assertSame( array( 'order_regression' ), $this->codes( $snap ) );
		$row = $snap['findings'][0];
		$this->assertSame( 1, $row['count'] );
		$this->assertSame( -50, $row['delta_sec'] );
		$this->assertSame( 2, $row['samples'][0]['index'] );
		$this->assertSame( 1, $row['samples'][0]['prev_index'] );
		$this->assertStringContainsString( 'backwards', $row['impact'] );

		// Newest-first (reverse) ledger is a regression at every step; reports are capped.
		$log = array();
		for ( $i = 0; $i < 50; $i++ ) {
			$log[] = array( 'ts' => self::NOW - ( $i * 10 ) );
		}
		Sundial::set_test_log( $log );
		$row = Sundial::snapshot()['findings'][0];
		$this->assertSame( 49, $row['count'] );
		$this->assertCount( Sundial::ANOMALY_CAP, $row['samples'] );
	}

	public function test_clean_ledger_has_no_anomalies(): void {
		$this->enable();
		$log = array();
		for ( $i = 0; $i < 30; $i++ ) {
			$log[] = array( 'ts' => self::NOW - 3000 + ( $i * 10 ) );
		}
		$log[] = array( 'ts' => self::NOW - 3000 + 290 ); // Equal ts is fine.
		Sundial::set_test_log( $log );
		$this->assertSame( 0, Sundial::snapshot()['finding_count'] );
	}

	public function test_ledger_reads_real_option_without_override(): void {
		$this->enable();
		Sundial::set_test_log( null );
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array( 'ts' => self::NOW + 9999 ),
			)
		);
		$this->assertSame( array( 'future_rows' ), $this->codes( Sundial::snapshot() ) );
	}

	public function test_alert_fires_once_and_rearms_after_clean(): void {
		$this->enable();
		Sundial::set_test_db_time( self::NOW - 500 );

		$this->assertTrue( Sundial::maybe_fire_alerts( self::NOW ) );
		$mails = Sundial::test_mails();
		$this->assertCount( 1, $mails );
		$this->assertStringContainsString( '[SUNDIAL]', $mails[0]['subject'] );
		$this->assertStringContainsString( 'php_db_skew', $mails[0]['subject'] );
		$this->assertStringContainsString( 'Report only', $mails[0]['body'] );
		$this->assertStringContainsString( '500s', $mails[0]['body'] );
		$this->assertTrue( Sundial::is_alerted() );
		$history = Sundial::get_state()['history'];
		$this->assertCount( 1, $history );
		$this->assertSame( 'php_db_skew', $history[0]['codes'] );
		$this->assertSame( 500, $history[0]['skew_sec'] );

		// Latched: still failing, no second alert.
		$this->assertFalse( Sundial::maybe_fire_alerts( self::NOW + 10 ) );
		$this->assertCount( 1, Sundial::test_mails() );

		// Clean clears the latch.
		Sundial::set_test_db_time( self::NOW );
		$this->assertFalse( Sundial::maybe_fire_alerts( self::NOW + 20 ) );
		$this->assertFalse( Sundial::is_alerted() );

		// New problem alerts again.
		Sundial::set_test_php_timezone( 'Europe/Paris' );
		$this->assertTrue( Sundial::maybe_fire_alerts( self::NOW + 30 ) );
		$this->assertCount( 2, Sundial::test_mails() );
		$this->assertCount( 2, Sundial::get_state()['history'] );
	}

	public function test_no_alert_when_clean_or_disabled(): void {
		$this->enable();
		$this->assertFalse( Sundial::maybe_fire_alerts( self::NOW ) );
		$this->assertCount( 0, Sundial::test_mails() );
		$this->assertFalse( Sundial::is_alerted() );

		Sundial::save_settings( Sundial::defaults() );
		Sundial::set_test_db_time( self::NOW - 9999 );
		$this->assertFalse( Sundial::maybe_fire_alerts( self::NOW ) );
		$this->assertFalse( Sundial::maybe_check( self::NOW, true ) );
		$this->assertCount( 0, Sundial::test_mails() );
	}

	public function test_maybe_check_is_throttled_and_fires_alert(): void {
		$this->enable();
		Sundial::set_test_db_time( self::NOW - 500 );

		$this->assertTrue( Sundial::maybe_check( self::NOW ) );
		$this->assertCount( 1, Sundial::test_mails() );
		$this->assertSame( self::NOW, Sundial::get_state()['last_check_ts'] );

		$this->assertFalse( Sundial::maybe_check( self::NOW + Sundial::CHECK_THROTTLE_SECONDS - 1 ) );

		Sundial::set_test_db_time( self::NOW + Sundial::CHECK_THROTTLE_SECONDS );
		$this->assertTrue( Sundial::maybe_check( self::NOW + Sundial::CHECK_THROTTLE_SECONDS ) );
		$this->assertFalse( Sundial::is_alerted() );

		$this->assertTrue( Sundial::maybe_check( self::NOW + Sundial::CHECK_THROTTLE_SECONDS + 1, true ) );
	}

	public function test_detection_runs_on_admin_init_and_never_schedules_cron(): void {
		$this->enable();
		Sundial::init();

		$added = $GLOBALS['handl_aicac_test_added_actions'];
		$this->assertContains( 'admin_init', $added );
		foreach ( $added as $hook ) {
			$this->assertStringStartsNotWith( 'handl_aicac_sundial', (string) $hook, 'No own cron hook.' );
		}

		Sundial::set_test_db_time( self::NOW - 999 );
		Sundial::maybe_check( self::NOW, true );
		$this->assertSame( array(), $GLOBALS['handl_aicac_test_cron'] );

		$source = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-sundial.php' );
		$this->assertStringNotContainsString( 'wp_schedule_event', $source );
		$this->assertStringNotContainsString( 'wp_schedule_single_event', $source );
		$this->assertStringNotContainsString( 'wp_clear_scheduled_hook', $source );
		$this->assertStringNotContainsString( 'wp_unschedule_event', $source );
		$this->assertDoesNotMatchRegularExpression( '/const\s+CRON_HOOK\b/', $source );
	}

	public function test_init_attaches_no_check_when_disabled(): void {
		Sundial::init();
		$added = $GLOBALS['handl_aicac_test_added_actions'];
		$this->assertContains( 'admin_menu', $added );
		$count_admin_init = count( array_filter( $added, static fn( $h ) => 'admin_init' === $h ) );
		$this->assertSame( 2, $count_admin_init, 'Only csv/print handlers, no check.' );
	}

	public function test_writes_confined_to_own_two_options(): void {
		$this->enable();
		update_option( 'timezone_string', 'America/Chicago' );
		update_option( 'gmt_offset', 3 );
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array( 'ts' => self::NOW + 9999 ),
				array( 'ts' => self::NOW - 9999 ),
			)
		);
		Sundial::set_test_log( null );
		Sundial::set_test_db_time( self::NOW - 777 );
		Sundial::set_test_php_timezone( 'Asia/Tokyo' );

		$before = $GLOBALS['handl_aicac_test_options'];
		Sundial::maybe_check( self::NOW, true );
		Sundial::csv_for_snapshot();
		Sundial::build_print_html( Sundial::snapshot() );
		$after = $GLOBALS['handl_aicac_test_options'];

		$changed = array();
		foreach ( array_unique( array_merge( array_keys( $before ), array_keys( $after ) ) ) as $key ) {
			if ( ( $before[ $key ] ?? null ) !== ( $after[ $key ] ?? null ) ) {
				$changed[] = $key;
			}
		}
		// The guarded Alerts mail helper keeps its own delivery bookkeeping; Sundial writes nothing else.
		$changed = array_values( array_diff( $changed, array( 'handl_aicac_alert_health' ) ) );
		$this->assertSame( array( Sundial::STATE_OPTION ), $changed, 'Only own state option written.' );
		$this->assertSame( self::NOW, Sundial::get_state()['last_check_ts'] );
		$this->assertSame( self::NOW - 777, Sundial::db_time() );

		$source = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-sundial.php' );
		preg_match_all( '/(?:update_option|delete_option|add_option)\(\s*([^,)\s]+)/', $source, $m );
		foreach ( $m[1] as $arg ) {
			$this->assertContains( $arg, array( 'self::SETTINGS_OPTION', 'self::STATE_OPTION' ), 'Write target ' . $arg );
		}
		$this->assertSame( 0, preg_match( '/\$wpdb->(query|insert|update|delete|replace)\b/', $source ) );
	}

	public function test_db_query_uses_injected_time_never_real_wpdb(): void {
		$GLOBALS['wpdb'] = new class() {
			public int $calls = 0;

			public function prepare( $query, ...$args ) {
				unset( $query, $args );
				++$this->calls;
				return 'x';
			}

			public function get_var( $query ) {
				unset( $query );
				++$this->calls;
				return (string) ( 1791800000 - 1000 );
			}
		};

		// Injected value wins; the wpdb stub is never touched.
		Sundial::set_test_db_time( self::NOW - 5 );
		$this->assertSame( self::NOW - 5, Sundial::db_time() );
		$this->assertSame( 0, $GLOBALS['wpdb']->calls );

		// No injection and no wpdb: unavailable rather than fatal.
		unset( $GLOBALS['wpdb'] );
		Sundial::reset_for_tests();
		$this->assertNull( Sundial::db_time() );
	}

	public function test_db_query_is_exactly_one_prepared_read_only_select(): void {
		$GLOBALS['wpdb'] = new class() {
			/** @var list<string> */
			public array $prepared = array();
			/** @var list<string> */
			public array $ran = array();

			public function prepare( $query, ...$args ) {
				$this->prepared[] = (string) $query;
				return sprintf( str_replace( '%d', '%d', (string) $query ), ...$args );
			}

			public function get_var( $query ) {
				$this->ran[] = (string) $query;
				return '1791799000';
			}
		};
		Sundial::reset_for_tests();
		$this->assertSame( 1791799000, Sundial::db_time() );
		$this->assertCount( 1, $GLOBALS['wpdb']->prepared );
		$this->assertCount( 1, $GLOBALS['wpdb']->ran );
		$this->assertMatchesRegularExpression( '/^SELECT\s+UNIX_TIMESTAMP\(\)/i', $GLOBALS['wpdb']->prepared[0] );
		$this->assertDoesNotMatchRegularExpression( '/\b(INSERT|UPDATE|DELETE|REPLACE|ALTER|DROP)\b/i', $GLOBALS['wpdb']->prepared[0] );

		$source = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-sundial.php' );
		$this->assertSame( 1, substr_count( $source, '->prepare(' ) );
		$this->assertSame( 1, substr_count( $source, '->get_var(' ) );

		// Bad result reads as unavailable.
		$GLOBALS['wpdb'] = new class() {
			public function prepare( $query, ...$args ) {
				unset( $args );
				return (string) $query;
			}

			public function get_var( $query ) {
				unset( $query );
				return null;
			}
		};
		$this->assertNull( Sundial::db_time() );
	}

	public function test_csv_contains_framing_and_findings(): void {
		$this->enable();
		Sundial::set_test_db_time( self::NOW - 400 );
		Sundial::set_test_php_timezone( 'Europe/Paris' );
		$csv = Sundial::csv_for_snapshot();

		$this->assertStringContainsString( 'section,code,direction,delta_sec,count,summary,impact,controls,framing', $csv );
		$this->assertStringContainsString( 'report_only_never_adjusts_clock', $csv );
		$this->assertStringContainsString( 'finding,php_db_skew,php_fast,400', $csv );
		$this->assertStringContainsString( 'finding,timezone_not_utc,timezone_not_utc', $csv );
		$this->assertStringContainsString( 'Temp_Allow Freeze Break_Glass Log_Retention Recert', $csv );
		$this->assertStringContainsString( 'summary,,,400,2', $csv );
		$this->assertStringContainsString( 'php_timezone=Europe/Paris', $csv );
		$this->assertStringContainsString( 'db_time=', $csv );

		// Formula injection is neutralized.
		$this->assertSame( "'=cmd", Sundial::csv_line( array( '=cmd' ) ) );
		$this->assertSame( '"a,b"', Sundial::csv_line( array( 'a,b' ) ) );
	}

	public function test_print_html_lists_findings_and_framing(): void {
		$this->enable();
		Sundial::set_test_db_time( self::NOW + 300 );
		$html = Sundial::build_print_html( Sundial::snapshot() );
		$this->assertStringContainsString( 'never adjusts any clock', $html );
		$this->assertStringContainsString( 'php_db_skew', $html );
		$this->assertStringContainsString( 'Log_Retention', $html );

		$this->assertStringContainsString( 'No clock-sanity findings.', Sundial::build_print_html( array( 'findings' => array() ) ) );
	}

	public function test_snapshot_shape(): void {
		$this->enable();
		$snap = Sundial::snapshot();
		foreach ( array( 'enabled', 'skew_threshold_sec', 'findings', 'finding_count', 'php_time', 'db_time', 'skew_sec', 'disable_flags', 'framing', 'alerted', 'history' ) as $key ) {
			$this->assertArrayHasKey( $key, $snap );
		}
		$this->assertSame( 120, $snap['skew_threshold_sec'] );
	}

	public function test_format_duration(): void {
		$this->assertSame( '45s', Sundial::format_duration( 45 ) );
		$this->assertSame( '5m', Sundial::format_duration( -300 ) );
		$this->assertSame( '2h 5m', Sundial::format_duration( 7500 ) );
		$this->assertSame( '1d 1h', Sundial::format_duration( 90000 ) );
	}
}
