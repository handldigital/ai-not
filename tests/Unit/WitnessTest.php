<?php
/**
 * AICAC-WITNESS (#419).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Legal_Hold;
use HandL\AICAC\Plugin;
use HandL\AICAC\Witness;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class WitnessTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12 UTC.

	private const DAY = 86400;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$GLOBALS['handl_aicac_test_cron']             = array();
		Witness::reset_for_tests();
		Legal_Hold::reset_for_tests();
		update_option( 'admin_email', 'haktan+aicac-witness@handldigital.com' );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'alert_email' => 'haktan+aicac-witness@handldigital.com',
			)
		);
		Witness::set_test_now( self::NOW );
		Witness::set_test_log( array() );
		Witness::set_test_retention_meta(
			array(
				'last_prune_ts'      => 0,
				'export_pending'     => false,
				'export_period_days' => null,
			)
		);
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_test_filters'][ Witness::FILTER_SECRET ] );
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_cron']          = array();
		Witness::reset_for_tests();
		Legal_Hold::reset_for_tests();
		parent::tearDown();
	}

	private function enable(): void {
		Witness::save_settings( array( 'enabled' => true ) );
	}

	/**
	 * Rows carry bodies the witness must never copy into its state.
	 *
	 * @param list<int> $stamps Timestamps.
	 * @return list<array<string,mixed>>
	 */
	private function rows( array $stamps ): array {
		$rows = array();
		foreach ( $stamps as $ts ) {
			$rows[] = array(
				'ts'       => $ts,
				'plugin'   => 'evil-plugin/secret-path.php',
				'decision' => 'deny',
				'prompt'   => 'TOP SECRET PROMPT BODY',
			);
		}

		return $rows;
	}

	/**
	 * @param int $count Row count.
	 * @param int $end   Newest timestamp.
	 * @return list<int>
	 */
	private function recent( int $count, int $end = self::NOW - 60 ): array {
		$out = array();
		for ( $i = $count - 1; $i >= 0; $i-- ) {
			$out[] = $end - ( $i * 60 );
		}

		return $out;
	}

	/**
	 * Baseline check at NOW with the given stamps, then switch the log.
	 *
	 * @param list<int> $stamps Baseline timestamps.
	 */
	private function baseline( array $stamps ): void {
		$this->enable();
		Witness::set_test_log( $this->rows( $stamps ) );
		$this->assertTrue( Witness::maybe_check( self::NOW, true ) );
	}

	/**
	 * @param list<int> $stamps Live timestamps.
	 */
	private function recheck( array $stamps, int $at = self::NOW + 300 ): void {
		Witness::set_test_log( $this->rows( $stamps ) );
		$this->assertTrue( Witness::maybe_check( $at, true ) );
	}

	/**
	 * @return array<string,mixed>
	 */
	private function only_finding(): array {
		$snap = Witness::snapshot( self::NOW + 400 );
		$this->assertCount( 1, $snap['findings'] );

		return $snap['findings'][0];
	}

	public function test_defaults_off_save_defaults_deletes_and_noop_byte_identical(): void {
		$this->assertFalse( Witness::is_enabled() );
		$this->assertSame( array( 'enabled' => false ), Witness::defaults() );
		$this->assertSame( Witness::defaults(), Witness::get_settings() );
		$this->assertSame( 'report_only_never_repairs_log', Witness::FRAMING );
		$this->assertSame( 'handl-aicac-witness', Witness::PAGE_SLUG );
		$this->assertSame( 'handl_aicac_witness', Witness::SETTINGS_OPTION );
		$this->assertSame( 'handl_aicac_witness_state', Witness::STATE_OPTION );

		$this->assertTrue( Witness::save_settings( array( 'enabled' => true ) ) );
		$this->assertTrue( Witness::is_enabled() );
		$before = get_option( Witness::SETTINGS_OPTION );
		$this->assertFalse( Witness::save_settings( array( 'enabled' => true ) ) );
		$this->assertSame( $before, get_option( Witness::SETTINGS_OPTION ) );

		$this->assertTrue( Witness::save_settings( Witness::defaults() ) );
		$this->assertFalse( (bool) get_option( Witness::SETTINGS_OPTION, false ) );
		$this->assertFalse( Witness::save_settings( Witness::defaults() ) );
		$this->assertSame( Witness::defaults(), Witness::sanitize_settings( 'junk' ) );
	}

	public function test_disabled_does_nothing(): void {
		Witness::set_test_log( $this->rows( $this->recent( 5 ) ) );
		$this->assertFalse( Witness::maybe_check( self::NOW, true ) );
		$this->assertFalse( get_option( Witness::STATE_OPTION, false ) );
		$this->assertFalse( Witness::maybe_fire_alerts( self::NOW ) );
	}

	public function test_checkpoint_records_count_newest_digest_and_no_bodies(): void {
		$stamps = $this->recent( 5 );
		$this->baseline( $stamps );

		$state = Witness::get_state();
		$this->assertCount( 1, $state['history'] );
		$cp = $state['history'][0];
		$this->assertSame( self::NOW, $cp['ts'] );
		$this->assertSame( 5, $cp['row_count'] );
		$this->assertSame( end( $stamps ), $cp['newest_ts'] );
		$this->assertSame( $stamps[0], $cp['oldest_ts'] );
		$this->assertMatchesRegularExpression( '/^[a-f0-9]{64}$/', $cp['digest'] );
		$this->assertArrayNotHasKey( 'stamps', $cp, 'History rows carry no timestamp list.' );
		$this->assertSame( self::NOW, $state['last_check_ts'] );
		$this->assertSame( 5, $state['last']['row_count'] );
		$this->assertSame( $cp['digest'], $state['last']['digest'] );

		$raw = (string) wp_json_encode( get_option( Witness::STATE_OPTION ) );
		foreach ( array( 'TOP SECRET', 'secret-path', 'evil-plugin', 'deny', 'prompt' ) as $needle ) {
			$this->assertStringNotContainsString( $needle, $raw );
		}
		$this->assertSame( array(), Witness::snapshot()['findings'] );
	}

	public function test_digest_is_salted_and_stable_and_order_independent(): void {
		$stamps = $this->recent( 4 );
		$a      = Witness::summarize( $this->rows( $stamps ), 'secret-one' );
		$b      = Witness::summarize( $this->rows( array_reverse( $stamps ) ), 'secret-one' );
		$c      = Witness::summarize( $this->rows( $stamps ), 'secret-two' );
		$d      = Witness::summarize( $this->rows( array_slice( $stamps, 1 ) ), 'secret-one' );
		$this->assertSame( $a['digest'], $b['digest'] );
		$this->assertNotSame( $a['digest'], $c['digest'] );
		$this->assertNotSame( $a['digest'], $d['digest'] );
		$this->assertSame( 4, $a['row_count'] );
		$this->assertSame( array(), Witness::summarize( array(), 's' )['stamps'] );
		$this->assertSame( 0, Witness::summarize( array( 'x', 5 ), 's' )['row_count'] );
	}

	public function test_secret_filter_and_stored_salt_fallback(): void {
		$stamps = $this->recent( 3 );
		$this->baseline( $stamps );
		$with_wp_salt = Witness::get_state()['last']['digest'];
		$this->assertSame( '', Witness::get_state()['salt'], 'wp_salt present: no stored salt.' );

		Witness::reset_for_tests();
		Witness::set_test_now( self::NOW );
		Witness::set_test_retention_meta( array() );
		$GLOBALS['handl_aicac_test_filters'][ Witness::FILTER_SECRET ] = static function (): string {
			return 'filtered-secret';
		};
		$this->baseline( $stamps );
		$filtered = Witness::get_state()['last']['digest'];
		$this->assertNotSame( $with_wp_salt, $filtered );
		$this->assertSame( hash_hmac( 'sha256', $this->summary_string( $stamps ), 'filtered-secret' ), $filtered );

		unset( $GLOBALS['handl_aicac_test_filters'][ Witness::FILTER_SECRET ] );
		Witness::reset_for_tests();
		Witness::set_test_now( self::NOW );
		Witness::set_test_retention_meta( array() );
		Witness::set_test_force_stored_salt( true );
		$this->baseline( $stamps );
		$salt = Witness::get_state()['salt'];
		$this->assertMatchesRegularExpression( '/^[a-f0-9]{64}$/', $salt );
		$this->recheck( $stamps );
		$this->assertSame( $salt, Witness::get_state()['salt'], 'Salt is created once.' );
		$this->assertStringNotContainsString( $salt, Witness::csv_for_snapshot() );
		$this->assertStringNotContainsString( $salt, Witness::build_print_html( Witness::snapshot() ) );
		$this->assertSame( array(), Witness::snapshot()['findings'] );
	}

	/**
	 * @param list<int> $stamps Timestamps.
	 */
	private function summary_string( array $stamps ): string {
		sort( $stamps );
		$days = array();
		$roll = '';
		foreach ( $stamps as $ts ) {
			$day          = gmdate( 'Y-m-d', $ts );
			$days[ $day ] = ( $days[ $day ] ?? 0 ) + 1;
			$roll         = hash( 'sha256', $roll . '|' . $ts );
		}
		ksort( $days );
		$buckets = array();
		foreach ( $days as $day => $count ) {
			$buckets[] = $day . ':' . $count;
		}

		return 'v1|n=' . count( $stamps ) . '|t=' . count( $stamps ) . '|d=' . implode( ',', $buckets ) . '|r=' . $roll;
	}

	public function test_secret_change_rebaselines_without_finding(): void {
		$stamps = $this->recent( 6 );
		$this->baseline( $stamps );
		$GLOBALS['handl_aicac_test_filters'][ Witness::FILTER_SECRET ] = static function (): string {
			return 'rotated-auth-key';
		};
		$this->recheck( $stamps );
		$this->assertSame( array(), Witness::snapshot()['findings'] );
		$this->assertCount( 2, Witness::get_state()['history'] );
	}

	public function test_throttle(): void {
		$this->baseline( $this->recent( 3 ) );
		$this->assertFalse( Witness::maybe_check( self::NOW + Witness::CHECK_THROTTLE_SECONDS - 1 ) );
		$this->assertTrue( Witness::maybe_check( self::NOW + Witness::CHECK_THROTTLE_SECONDS ) );
		$this->assertSame( self::NOW + Witness::CHECK_THROTTLE_SECONDS, Witness::get_state()['last_check_ts'] );
	}

	public function test_growth_is_clean(): void {
		$base = $this->recent( 5 );
		$this->baseline( $base );
		$grown = array_merge( $base, array( self::NOW + 100, self::NOW + 200 ) );
		$this->recheck( $grown );

		$snap = Witness::snapshot( self::NOW + 400 );
		$this->assertSame( array(), $snap['findings'] );
		$this->assertSame( 0, $snap['unsanctioned_count'] );
		$this->assertCount( 2, Witness::get_state()['history'] );
		$this->assertSame( 7, Witness::get_state()['last']['row_count'] );
		$this->assertCount( 0, Witness::test_mails() );
	}

	public function test_unchanged_log_does_not_grow_the_ledger(): void {
		$base = $this->recent( 5 );
		$this->baseline( $base );
		$this->recheck( $base );
		$this->recheck( $base, self::NOW + 700 );
		$state = Witness::get_state();
		$this->assertCount( 1, $state['history'] );
		$this->assertSame( self::NOW + 700, $state['last']['ts'], 'Comparison pointer still advances.' );
		$this->assertSame( array(), $state['findings'] );
	}

	public function test_history_is_capped(): void {
		$this->enable();
		$stamps = array();
		for ( $i = 0; $i < Witness::HISTORY_CAP + 10; $i++ ) {
			$stamps[] = self::NOW - 100000 + $i;
			Witness::set_test_log( $this->rows( $stamps ) );
			Witness::maybe_check( self::NOW + ( $i * 300 ), true );
		}
		$this->assertCount( Witness::HISTORY_CAP, Witness::get_state()['history'] );
		$this->assertSame( array(), Witness::get_state()['findings'] );
	}

	public function test_sanctioned_drop_when_prune_recorded_and_old_rows_removed(): void {
		$old    = array( self::NOW - ( 45 * self::DAY ), self::NOW - ( 41 * self::DAY ), self::NOW - ( 40 * self::DAY ) );
		$recent = $this->recent( 4 );
		$this->baseline( array_merge( $old, $recent ) );

		Witness::set_test_retention_meta(
			array(
				'last_prune_ts'      => self::NOW + 120,
				'export_pending'     => false,
				'export_period_days' => 30,
			)
		);
		$this->recheck( $recent );

		$finding = $this->only_finding();
		$this->assertSame( 'sanctioned', $finding['classification'] );
		$this->assertSame( 'retention_prune', $finding['code'] );
		$this->assertSame( -3, $finding['row_delta'] );
		$this->assertSame( 3, $finding['rows_removed'] );
		$this->assertSame( self::NOW, $finding['window_start'] );
		$this->assertSame( self::NOW + 300, $finding['window_end'] );
		$this->assertStringContainsString( '30-day', $finding['summary'] );

		$snap = Witness::snapshot( self::NOW + 400 );
		$this->assertSame( 0, $snap['unsanctioned_count'] );
		$this->assertSame( 1, $snap['sanctioned_count'] );
	}

	public function test_sanctioned_prune_uses_policy_window_when_set(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'          => 'allow',
				'log_max_age_days' => 30,
				'alert_email'      => 'haktan+aicac-witness@handldigital.com',
			)
		);
		$old    = array( self::NOW - ( 90 * self::DAY ) );
		$recent = $this->recent( 3 );
		$this->baseline( array_merge( $old, $recent ) );
		Witness::set_test_retention_meta( array( 'last_prune_ts' => self::NOW + 10 ) );
		$this->recheck( $recent );

		$this->assertSame( 'retention_prune', $this->only_finding()['code'] );
	}

	public function test_prune_recorded_but_rows_inside_window_is_unsanctioned(): void {
		$inside = array( self::NOW - ( 10 * self::DAY ), self::NOW - ( 9 * self::DAY ) );
		$recent = $this->recent( 4 );
		$this->baseline( array_merge( $inside, $recent ) );

		Witness::set_test_retention_meta(
			array(
				'last_prune_ts'      => self::NOW + 120,
				'export_period_days' => 30,
			)
		);
		$this->recheck( $recent );

		$finding = $this->only_finding();
		$this->assertSame( 'unsanctioned', $finding['classification'] );
		$this->assertSame( 'rows_missing_in_window', $finding['code'] );
		$this->assertSame( -2, $finding['row_delta'] );
	}

	public function test_prune_before_checkpoint_window_does_not_sanction(): void {
		$old    = array( self::NOW - ( 45 * self::DAY ) );
		$recent = $this->recent( 4 );
		$this->baseline( array_merge( $old, $recent ) );

		Witness::set_test_retention_meta(
			array(
				'last_prune_ts'      => self::NOW - 5000, // Before the previous checkpoint.
				'export_period_days' => 30,
			)
		);
		$this->recheck( $recent );

		$this->assertSame( 'rows_removed_unexplained', $this->only_finding()['code'] );
	}

	public function test_unsanctioned_drop_when_count_falls_with_no_prune_meta(): void {
		$base = $this->recent( 8 );
		$this->baseline( $base );
		$this->recheck( array_slice( $base, 3 ) );

		$finding = $this->only_finding();
		$this->assertSame( 'unsanctioned', $finding['classification'] );
		$this->assertSame( 'rows_removed_unexplained', $finding['code'] );
		$this->assertSame( -3, $finding['row_delta'] );
		$this->assertStringContainsString( '8 to 5 rows', $finding['summary'] );
		$this->assertStringContainsString( '2026-10-12', $finding['summary'] );
		$this->assertStringContainsString( 'UTC', $finding['summary'] );
		$this->assertSame( 1, Witness::snapshot( self::NOW + 400 )['unsanctioned_count'] );
	}

	public function test_rows_missing_from_inside_window_with_newest_present_is_unsanctioned(): void {
		$base = $this->recent( 8 );
		$this->baseline( $base );
		$live = $base;
		unset( $live[3], $live[4] );
		$this->recheck( array_values( $live ) );

		$finding = $this->only_finding();
		$this->assertSame( 'unsanctioned', $finding['classification'] );
		$this->assertSame( 'rows_missing_in_window', $finding['code'] );
		$this->assertSame( -2, $finding['row_delta'] );
	}

	public function test_newest_going_backwards_is_unsanctioned(): void {
		$base = $this->recent( 8 );
		$this->baseline( $base );
		$this->recheck( array_slice( $base, 0, 6 ) );

		$finding = $this->only_finding();
		$this->assertSame( 'unsanctioned', $finding['classification'] );
		$this->assertSame( 'newest_regressed', $finding['code'] );
	}

	public function test_full_wipe_is_unsanctioned_without_evidence(): void {
		$base = $this->recent( 5 );
		$this->baseline( $base );
		$this->recheck( array() );

		$finding = $this->only_finding();
		$this->assertSame( 'unsanctioned', $finding['classification'] );
		$this->assertSame( -5, $finding['row_delta'] );
	}

	public function test_digest_mismatch_with_same_count_is_unsanctioned(): void {
		$base = $this->recent( 6 );
		$this->baseline( $base );
		$rewritten    = $base;
		$rewritten[2] = $base[2] + 7;
		$this->recheck( $rewritten );

		$finding = $this->only_finding();
		$this->assertSame( 'unsanctioned', $finding['classification'] );
		$this->assertSame( 'content_rewrite', $finding['code'] );
		$this->assertSame( 0, $finding['row_delta'] );
		$this->assertStringContainsString( 'fingerprint changed', $finding['summary'] );
	}

	public function test_oldest_rows_replaced_at_stable_count_without_reason_is_unsanctioned(): void {
		$base = $this->recent( 6 );
		$this->baseline( $base );
		$live = array_merge( array_slice( $base, 2 ), array( self::NOW + 10, self::NOW + 20 ) );
		$this->recheck( $live );

		$this->assertSame( 'content_rewrite', $this->only_finding()['code'] );
	}

	public function test_backdated_rows_are_unsanctioned_but_small_skew_is_not(): void {
		$base = $this->recent( 5 );
		$this->baseline( $base );
		$newest = (int) end( $base );

		$this->recheck( array_merge( $base, array( $newest - 30 ) ) );
		$this->assertSame( array(), Witness::snapshot( self::NOW + 400 )['findings'], 'Concurrent-write skew tolerated.' );

		$this->recheck( array_merge( $base, array( $newest - 30, $newest - 5000 ) ), self::NOW + 700 );
		$finding = Witness::snapshot( self::NOW + 800 )['findings'][0];
		$this->assertSame( 'backdated_rows', $finding['code'] );
		$this->assertSame( 'unsanctioned', $finding['classification'] );
	}

	public function test_ring_buffer_rollover_at_limit_is_sanctioned(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'   => 'allow',
				'log_limit' => 20,
			)
		);
		$base = $this->recent( 20 );
		$this->baseline( $base );
		$live = array_merge( array_slice( $base, 3 ), array( self::NOW + 10, self::NOW + 20, self::NOW + 30 ) );
		$this->recheck( $live );

		$finding = $this->only_finding();
		$this->assertSame( 'sanctioned', $finding['classification'] );
		$this->assertSame( 'ring_cap', $finding['code'] );
		$this->assertSame( 0, $finding['row_delta'] );
		$this->assertSame( 0, Witness::snapshot( self::NOW + 400 )['unsanctioned_count'] );
	}

	public function test_ttl_aged_out_on_write_is_sanctioned(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'          => 'allow',
				'log_max_age_days' => 30,
			)
		);
		$old    = array( self::NOW - ( 50 * self::DAY ), self::NOW - ( 49 * self::DAY ) );
		$recent = $this->recent( 4 );
		$this->baseline( array_merge( $old, $recent ) );
		$this->recheck( array_merge( $recent, array( self::NOW + 50 ) ) );

		$finding = $this->only_finding();
		$this->assertSame( 'sanctioned', $finding['classification'] );
		$this->assertSame( 'ttl_on_write', $finding['code'] );
	}

	public function test_legal_hold_blocking_the_prune_makes_it_unsanctioned(): void {
		$old    = array( self::NOW - ( 45 * self::DAY ), self::NOW - ( 44 * self::DAY ) );
		$recent = $this->recent( 3 );
		$this->baseline( array_merge( $old, $recent ) );
		Witness::set_test_retention_meta(
			array(
				'last_prune_ts'      => self::NOW + 100,
				'export_period_days' => 30,
			)
		);
		Witness::set_test_hold_check(
			static function ( array $row ): bool {
				return (int) $row['ts'] === self::NOW - ( 44 * self::DAY );
			}
		);
		$this->recheck( $recent );

		$finding = $this->only_finding();
		$this->assertSame( 'unsanctioned', $finding['classification'] );
		$this->assertSame( 'prune_despite_legal_hold', $finding['code'] );
		$this->assertStringContainsString( 'legal hold', $finding['summary'] );
	}

	public function test_legal_hold_that_does_not_apply_keeps_prune_sanctioned(): void {
		$old    = array( self::NOW - ( 45 * self::DAY ) );
		$recent = $this->recent( 3 );
		$this->baseline( array_merge( $old, $recent ) );
		Witness::set_test_retention_meta(
			array(
				'last_prune_ts'      => self::NOW + 100,
				'export_period_days' => 30,
			)
		);
		Witness::set_test_hold_check(
			static function (): bool {
				return false;
			}
		);
		$this->recheck( $recent );

		$this->assertSame( 'retention_prune', $this->only_finding()['code'] );
	}

	public function test_legal_hold_class_absent_means_no_hold_info(): void {
		// Absent-class guard (held_count → 0) cannot be exercised in-process
		// once Legal_Hold is loaded. Union: seed a real site-wide hold so
		// Witness::held_count reads Legal_Hold::has_active_holds / row_is_held.
		$this->assertTrue( class_exists( Legal_Hold::class, false ) );
		$this->assertTrue( method_exists( Legal_Hold::class, 'has_active_holds' ) );
		$this->assertTrue( method_exists( Legal_Hold::class, 'row_is_held' ) );
		update_option(
			Legal_Hold::HOLDS_OPTION,
			array(
				'unionhold' => array(
					'id'         => 'unionhold',
					'name'       => 'Union hold',
					'scope'      => Legal_Hold::SCOPE_SITE,
					'reason'     => 'union tests',
					'created_at' => self::NOW,
					'created_by' => 1,
				),
			),
			false
		);
		$this->assertTrue( Legal_Hold::has_active_holds() );

		$old    = array( self::NOW - ( 45 * self::DAY ) );
		$recent = $this->recent( 3 );
		$this->baseline( array_merge( $old, $recent ) );
		Witness::set_test_retention_meta(
			array(
				'last_prune_ts'      => self::NOW + 100,
				'export_period_days' => 30,
			)
		);
		$this->recheck( $recent );

		$finding = $this->only_finding();
		$this->assertSame( 'unsanctioned', $finding['classification'] );
		$this->assertSame( 'prune_despite_legal_hold', $finding['code'] );
		$this->assertStringContainsString( 'legal hold', $finding['summary'] );
	}

	public function test_finding_links_to_retention_screen_when_available(): void {
		$this->baseline( $this->recent( 5 ) );
		$this->recheck( array() );
		$snap = Witness::snapshot( self::NOW + 400 );
		$this->assertArrayHasKey( 'retention_url', $snap['findings'][0] );
		if ( class_exists( 'HandL\\AICAC\\Admin', false ) && method_exists( 'HandL\\AICAC\\Admin', 'screen_url' ) ) {
			$this->assertNotSame( '', $snap['retention_url'] );
			$this->assertSame( $snap['retention_url'], $snap['findings'][0]['retention_url'] );
			$this->assertStringContainsString( $snap['retention_url'], Witness::build_body( $snap ) );
		}
	}

	public function test_alert_fires_once_and_rearms(): void {
		$base = $this->recent( 10 );
		$this->baseline( $base );
		$this->assertCount( 0, Witness::test_mails() );

		$this->recheck( array_slice( $base, 2 ), self::NOW + 300 );
		$this->assertCount( 1, Witness::test_mails() );
		$this->assertTrue( Witness::is_alerted() );
		$this->assertStringContainsString( '[WITNESS]', Witness::test_mails()[0]['subject'] );
		$this->assertStringContainsString( 'haktan+aicac-witness@handldigital.com', Witness::test_mails()[0]['to'] );
		$this->assertStringContainsString( 'never writes, repairs or restores', Witness::test_mails()[0]['body'] );

		// Further unsanctioned findings while latched: no second mail.
		$this->recheck( array_slice( $base, 4 ), self::NOW + 600 );
		$this->assertSame( 2, Witness::snapshot( self::NOW + 700 )['unsanctioned_count'] );
		$this->assertCount( 1, Witness::test_mails() );

		// Findings age out of the open set: latch clears.
		$later = self::NOW + 600 + Witness::FINDING_OPEN_SECONDS + 10;
		$this->recheck( array_slice( $base, 4 ), $later );
		$this->assertFalse( Witness::is_alerted() );
		$this->assertSame( 0, Witness::snapshot( $later )['unsanctioned_count'] );
		$this->assertCount( 1, Witness::test_mails() );

		// A new unsanctioned finding re-arms the alert.
		$this->recheck( array_slice( $base, 7 ), $later + 300 );
		$this->assertCount( 2, Witness::test_mails() );
		$this->assertTrue( Witness::is_alerted() );
	}

	public function test_no_alert_when_clean_or_sanctioned_only(): void {
		$base = $this->recent( 5 );
		$this->baseline( $base );
		$this->recheck( array_merge( $base, array( self::NOW + 10 ) ) );
		$this->assertCount( 0, Witness::test_mails() );
		$this->assertFalse( Witness::is_alerted() );

		$this->baseline_sanctioned_only();
		$this->assertCount( 0, Witness::test_mails() );
		$this->assertFalse( Witness::is_alerted() );
		$this->assertSame( 1, Witness::snapshot( self::NOW + 400 )['sanctioned_count'] );
	}

	private function baseline_sanctioned_only(): void {
		Witness::reset_for_tests();
		Witness::set_test_now( self::NOW );
		$old    = array( self::NOW - ( 45 * self::DAY ) );
		$recent = $this->recent( 3 );
		$this->baseline( array_merge( $old, $recent ) );
		Witness::set_test_retention_meta(
			array(
				'last_prune_ts'      => self::NOW + 100,
				'export_period_days' => 30,
			)
		);
		$this->recheck( $recent );
	}

	public function test_alert_delivery_failure_does_not_latch(): void {
		update_option( 'admin_email', '' );
		update_option( Plugin::OPTION_KEY, array( 'default' => 'allow' ) );
		$base = $this->recent( 6 );
		$this->baseline( $base );
		$this->recheck( array_slice( $base, 3 ) );
		$this->assertFalse( Witness::is_alerted() );
		$this->assertCount( 0, Witness::test_mails() );
	}

	public function test_detection_runs_on_admin_init_and_never_schedules_cron(): void {
		$this->enable();
		Witness::init();

		$added = $GLOBALS['handl_aicac_test_added_actions'];
		$this->assertContains( 'admin_init', $added );
		$this->assertSame( 3, count( array_filter( $added, static fn( $h ) => 'admin_init' === $h ) ), 'csv, print and the throttled check.' );
		foreach ( $added as $hook ) {
			$this->assertStringStartsNotWith( 'handl_aicac_witness', (string) $hook, 'No own cron hook.' );
		}

		$base = $this->recent( 8 );
		Witness::set_test_log( $this->rows( $base ) );
		Witness::maybe_check( self::NOW, true );
		Witness::set_test_log( $this->rows( array_slice( $base, 4 ) ) );
		Witness::maybe_check( self::NOW + 300, true );
		$this->assertSame( array(), $GLOBALS['handl_aicac_test_cron'] );

		$source = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-witness.php' );
		$this->assertStringNotContainsString( 'wp_schedule_event', $source );
		$this->assertStringNotContainsString( 'wp_schedule_single_event', $source );
		$this->assertStringNotContainsString( 'wp_clear_scheduled_hook', $source );
		$this->assertStringNotContainsString( 'wp_unschedule_event', $source );
		$this->assertDoesNotMatchRegularExpression( '/const\s+CRON_HOOK\b/', $source );
	}

	public function test_init_attaches_no_check_when_disabled(): void {
		Witness::init();
		$added = $GLOBALS['handl_aicac_test_added_actions'];
		$this->assertContains( 'admin_menu', $added );
		$this->assertSame( 2, count( array_filter( $added, static fn( $h ) => 'admin_init' === $h ) ), 'Only csv/print handlers, no check.' );
	}

	public function test_writes_confined_to_own_two_options_and_log_never_touched(): void {
		$this->enable();
		$log = $this->rows( $this->recent( 12 ) );
		update_option( Plugin::LOG_OPTION_KEY, $log );
		Witness::set_test_log( null ); // Read the real option.

		Witness::maybe_check( self::NOW, true );
		$shrunk = array_slice( $log, 6 );
		update_option( Plugin::LOG_OPTION_KEY, $shrunk );

		$before = $GLOBALS['handl_aicac_test_options'];
		Witness::maybe_check( self::NOW + 300, true );
		Witness::csv_for_snapshot();
		Witness::build_print_html( Witness::snapshot() );
		$after = $GLOBALS['handl_aicac_test_options'];

		$changed = array();
		foreach ( array_unique( array_merge( array_keys( $before ), array_keys( $after ) ) ) as $key ) {
			if ( ( $before[ $key ] ?? null ) !== ( $after[ $key ] ?? null ) ) {
				$changed[] = $key;
			}
		}
		$changed = array_values( array_diff( $changed, array( 'handl_aicac_alert_health' ) ) );
		$this->assertSame( array( Witness::STATE_OPTION ), $changed, 'Only own state option written.' );
		$this->assertSame( $shrunk, get_option( Plugin::LOG_OPTION_KEY ), 'Log is read-only: not repaired or restored.' );
		$this->assertSame( 1, Witness::snapshot( self::NOW + 400 )['unsanctioned_count'] );

		$source = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-witness.php' );
		preg_match_all( '/(?:update_option|delete_option|add_option)\(\s*([^,)\s]+)/', $source, $m );
		$this->assertNotEmpty( $m[1] );
		foreach ( $m[1] as $arg ) {
			$this->assertContains( $arg, array( 'self::SETTINGS_OPTION', 'self::STATE_OPTION' ), 'Write target ' . $arg );
		}
		$this->assertSame( 0, preg_match( '/\$wpdb->(query|insert|update|delete|replace)\b/', $source ) );
		$this->assertSame( 0, preg_match( '/(update|delete|add)_option\(\s*[^)]*LOG_OPTION_KEY/', $source ) );
	}

	public function test_wp_die_only_in_own_save_handler(): void {
		$source = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-witness.php' );
		$start  = (int) strpos( $source, 'public static function handle_save' );
		$end    = (int) strpos( $source, 'public static function register_cli' );
		$this->assertGreaterThan( 0, $start );
		$this->assertGreaterThan( $start, $end );
		$before = substr( $source, 0, $start );
		$after  = substr( $source, $end );
		$this->assertStringNotContainsString( 'wp_die(', $before );
		$this->assertStringNotContainsString( 'wp_die(', $after );
		$this->assertStringContainsString( 'wp_die(', substr( $source, $start, $end - $start ) );
	}

	public function test_csv_contains_framing_checkpoints_and_findings(): void {
		$base = $this->recent( 6 );
		$this->baseline( $base );
		$this->recheck( array_slice( $base, 2 ) );
		$csv = Witness::csv_for_snapshot();

		$this->assertStringContainsString( 'section,code,classification,ts,window_start,window_end,row_count,row_delta,newest_ts,oldest_ts,digest,summary,retention_url,framing', $csv );
		$this->assertStringContainsString( 'report_only_never_repairs_log', $csv );
		$this->assertStringContainsString( 'checkpoint,,,2026-10-12', $csv );
		$this->assertStringContainsString( 'finding,rows_removed_unexplained,unsanctioned,', $csv );
		$this->assertStringContainsString( ',-2,', $csv );
		$this->assertStringContainsString( 'checkpoints=2 findings=1 unsanctioned=1 sanctioned=0', $csv );
		$state = Witness::get_state();
		$this->assertStringContainsString( $state['last']['digest'], $csv );
		$lines = explode( "\n", trim( $csv ) );
		array_shift( $lines );
		foreach ( $lines as $line ) {
			$this->assertStringEndsWith( 'report_only_never_repairs_log', $line );
		}
		$this->assertStringNotContainsString( 'TOP SECRET', $csv );

		$this->assertSame( "'=cmd", Witness::csv_line( array( '=cmd' ) ) );
		$this->assertSame( '"a,b"', Witness::csv_line( array( 'a,b' ) ) );
	}

	public function test_print_html_lists_findings_checkpoints_and_framing(): void {
		$base = $this->recent( 6 );
		$this->baseline( $base );
		$this->recheck( array_slice( $base, 2 ) );
		$html = Witness::build_print_html( Witness::snapshot( self::NOW + 400 ) );
		$this->assertStringContainsString( 'never writes, repairs or restores', $html );
		$this->assertStringContainsString( 'rows_removed_unexplained', $html );
		$this->assertStringContainsString( 'Checkpoint ledger', $html );
		$this->assertStringContainsString( 'No continuity findings.', Witness::build_print_html( array( 'findings' => array() ) ) );
		$this->assertStringContainsString( 'No checkpoints recorded yet.', Witness::build_print_html( array() ) );
	}

	public function test_snapshot_shape_and_state_sanitization(): void {
		$this->enable();
		$snap = Witness::snapshot();
		foreach ( array( 'enabled', 'checkpoints', 'last', 'findings', 'unsanctioned_count', 'sanctioned_count', 'alerted', 'framing' ) as $key ) {
			$this->assertArrayHasKey( $key, $snap );
		}
		$this->assertNull( $snap['last'] );

		$bad = Witness::sanitize_state(
			array(
				'history'  => array( 'x', array( 'ts' => 0 ), array( 'ts' => 5, 'row_count' => -4, 'digest' => 'ZZ-nothex' ) ),
				'findings' => array( array( 'ts' => 5, 'classification' => 'bogus' ), array( 'ts' => 5, 'classification' => 'sanctioned', 'code' => 'Ring Cap!' ) ),
				'last'     => array( 'ts' => 9, 'stamps' => array( 5, 'x', -1, 3 ) ),
				'salt'     => 'XYZ123abc',
			)
		);
		$this->assertCount( 1, $bad['history'] );
		$this->assertSame( 0, $bad['history'][0]['row_count'] );
		$this->assertCount( 1, $bad['findings'] );
		$this->assertSame( 'ringcap', $bad['findings'][0]['code'] );
		$this->assertSame( array( 3, 5 ), $bad['last']['stamps'] );
		$this->assertSame( '123abc', $bad['salt'] );
		$this->assertSame( Witness::defaults_state(), Witness::sanitize_state( 'nope' ) );
	}

	public function test_coarse_comparison_when_previous_checkpoint_has_no_timestamp_list(): void {
		$this->enable();
		$prev = array(
			'ts'        => self::NOW,
			'row_count' => 6,
			'newest_ts' => self::NOW - 60,
			'oldest_ts' => self::NOW - ( 50 * self::DAY ),
			'digest'    => str_repeat( 'a', 64 ),
			'secret_fp' => '',
		);
		$live = Witness::summarize( $this->rows( $this->recent( 3 ) ), 'k' );

		$f = Witness::classify( $prev, $live, self::NOW + 300 );
		$this->assertSame( 'unsanctioned', $f['classification'] );

		Witness::set_test_retention_meta(
			array(
				'last_prune_ts'      => self::NOW + 100,
				'export_period_days' => 30,
			)
		);
		$f = Witness::classify( $prev, $live, self::NOW + 300 );
		$this->assertSame( 'sanctioned', $f['classification'] );
		$this->assertSame( 'retention_prune', $f['code'] );

		$live_back = Witness::summarize( $this->rows( array( self::NOW - 5000 ) ), 'k' );
		$this->assertSame( 'newest_regressed', Witness::classify( $prev, $live_back, self::NOW + 300 )['code'] );
	}

	public function test_classify_clean_returns_null(): void {
		$base = Witness::summarize( $this->rows( $this->recent( 4 ) ), 'k' );
		$prev = array_merge( $base, array( 'ts' => self::NOW ) );
		$this->assertNull( Witness::classify( $prev, $base, self::NOW + 300 ) );
	}
}
