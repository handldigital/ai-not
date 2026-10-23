<?php
/**
 * AICAC-DRILL (#397).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Health;
use HandL\AICAC\Drill;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class DrillTest extends TestCase {

	private const EMAIL = 'haktan+aicac-drill@handldigital.com';

	private const T0 = 1791813600; // 2026-10-12 12:40:00 UTC (fixed clock for runs).

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_cron']             = array();
		unset( $GLOBALS['handl_aicac_test_caps'] );
		Drill::reset_for_tests();
		$this->seed_policy( array() );
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_filters'][ Drill::FILTER_SCENARIOS ],
			$GLOBALS['handl_aicac_test_filters'][ Drill::FILTER_ACK_WINDOW ],
			$GLOBALS['handl_aicac_test_current_user_can'],
			$GLOBALS['handl_aicac_test_cron'],
			$GLOBALS['handl_aicac_test_user_id']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		Drill::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * @param array<string,mixed> $extra Policy overrides.
	 */
	private function seed_policy( array $extra ): void {
		update_option(
			Plugin::OPTION_KEY,
			array_merge(
				array(
					'default'       => 'allow',
					'log_enabled'   => true,
					'audit_only'    => false,
					'alert_email'   => self::EMAIL,
					'alert_on_deny' => true,
				),
				$extra
			)
		);
	}

	private function enable( array $extra = array() ): void {
		Drill::save_settings( array_merge( array( 'enabled' => true ), $extra ) );
	}

	/**
	 * @param array<string,mixed> $run Run.
	 * @return array<string,array<string,string>>
	 */
	private function by_control( array $run ): array {
		$out = array();
		foreach ( $run['scorecard'] as $row ) {
			$out[ $row['control'] ] = $row;
		}

		return $out;
	}

	public function test_defaults_off_and_noop_save_byte_identical(): void {
		$this->assertFalse( Drill::is_enabled() );
		$this->assertSame(
			array(
				'enabled'          => false,
				'schedule_enabled' => false,
				'ack_window_hours' => 72,
				'default_scenario' => 'provider_outage',
			),
			Drill::get_settings()
		);
		$this->assertSame( Drill::defaults(), Drill::get_settings() );
		$this->assertSame( array(), Drill::run( 'provider_outage', self::T0 ), 'run is a no-op while off' );
		$this->assertSame( array(), Drill::get_history() );

		Drill::save_settings(
			array(
				'enabled'          => true,
				'schedule_enabled' => false,
				'ack_window_hours' => 72,
				'default_scenario' => 'provider_outage',
			)
		);
		$this->assertTrue( Drill::is_enabled() );
		$before  = get_option( Drill::SETTINGS_OPTION );
		$changed = Drill::save_settings(
			array(
				'enabled'          => true,
				'schedule_enabled' => false,
				'ack_window_hours' => 72,
				'default_scenario' => 'provider_outage',
			)
		);
		$this->assertFalse( $changed );
		$this->assertSame( $before, get_option( Drill::SETTINGS_OPTION ) );

		Drill::save_settings( Drill::defaults() );
		$this->assertFalse( (bool) get_option( Drill::SETTINGS_OPTION, false ) );
		$this->assertSame( 72, Drill::sanitize_ack_window_hours( 'junk' ) );
		$this->assertSame( 720, Drill::sanitize_ack_window_hours( 99999 ) );
		$this->assertSame( 1, Drill::sanitize_ack_window_hours( 0 ) );
		$this->assertSame( 'provider_outage', Drill::sanitize_scenario_id( 'nope' ) );
	}

	public function test_scenarios_filter_and_scorecard_fire_vs_dead_end(): void {
		$scenarios = Drill::scenarios();
		$this->assertSame(
			array( 'provider_outage', 'leaked_key', 'budget_blowout', 'train_by_default_provider' ),
			array_keys( $scenarios )
		);
		$this->assertSame( array( 'circuit_breaker', 'alerts', 'policy_backup' ), $scenarios['provider_outage']['controls'] );
		$this->assertSame( array( 'canary', 'alerts', 'keyscan' ), $scenarios['leaked_key']['controls'] );
		$this->assertSame( array( 'budget', 'alerts' ), $scenarios['budget_blowout']['controls'] );
		$this->assertSame( array( 'policy_default_deny', 'new_plugin', 'alerts' ), $scenarios['train_by_default_provider']['controls'] );

		$GLOBALS['handl_aicac_test_filters'][ Drill::FILTER_SCENARIOS ] = static function ( array $table ): array {
			$table['custom'] = array(
				'id'          => 'custom',
				'label'       => 'Custom',
				'description' => 'x',
				'controls'    => array( 'alerts', 'keyscan' ),
			);
			return $table;
		};
		$this->assertArrayHasKey( 'custom', Drill::scenarios() );
		$this->assertSame( 'custom', Drill::sanitize_scenario_id( 'custom' ) );

		// Leaked key: alerts on + recipient → fire; keyscan class loaded → fire; canary has no token → dead end.
		$rows = Drill::evaluate_scorecard( 'leaked_key' );
		$map  = array();
		foreach ( $rows as $row ) {
			$map[ $row['control'] ] = $row;
			$this->assertContains( $row['status'], array( 'fire', 'dead_end' ) );
			$this->assertSame( array( 'control', 'label', 'status', 'reason', 'deep_link' ), array_keys( $row ) );
			$this->assertNotSame( '', $row['deep_link'] );
		}
		$this->assertSame( 'fire', $map['alerts']['status'] );
		$this->assertSame( 'ready', $map['alerts']['reason'] );
		$this->assertSame( 'fire', $map['keyscan']['status'] );
		$this->assertSame( 'dead_end', $map['canary']['status'] );
		$this->assertSame( 'control_off', $map['canary']['reason'] );
		$this->assertStringContainsString( 'handl-aicac-protections', $map['canary']['deep_link'] );
		$this->assertStringContainsString( 'handl-aicac-alerts', $map['alerts']['deep_link'] );

		// Canary armed → fires (recipient resolves through the default address).
		update_option( \HandL\AICAC\Canary::REGISTRY_OPTION, array( 'token' => 'cnry_abc', 'option' => 'x', 'created' => 1 ), false );
		$map = $this->index_rows( Drill::evaluate_scorecard( 'leaked_key' ) );
		$this->assertSame( 'fire', $map['canary']['status'] );

		// Alerts: off vs no recipient.
		$this->seed_policy( array( 'alert_on_deny' => false ) );
		$map = $this->index_rows( Drill::evaluate_scorecard( 'budget_blowout' ) );
		$this->assertSame( 'dead_end', $map['alerts']['status'] );
		$this->assertSame( 'control_off', $map['alerts']['reason'] );

		$this->seed_policy( array( 'alert_email' => '' ) );
		update_option( 'admin_email', '' );
		$map = $this->index_rows( Drill::evaluate_scorecard( 'budget_blowout' ) );
		$this->assertSame( 'dead_end', $map['alerts']['status'] );
		$this->assertSame( 'no_recipient', $map['alerts']['reason'] );

		// Budget configured → fires; default deny.
		$this->seed_policy( array( 'plugin_budgets' => array( 'alpha/alpha.php' => 5 ) ) );
		$map = $this->index_rows( Drill::evaluate_scorecard( 'budget_blowout' ) );
		$this->assertSame( 'fire', $map['budget']['status'] );

		$map = $this->index_rows( Drill::evaluate_scorecard( 'train_by_default_provider' ) );
		$this->assertSame( 'dead_end', $map['policy_default_deny']['status'] );
		$this->assertSame( 'default_allow', $map['policy_default_deny']['reason'] );
		$this->assertStringContainsString( 'handl-aicac-rules', $map['policy_default_deny']['deep_link'] );
		$this->seed_policy( array( 'default' => 'deny', 'new_plugin_review_enabled' => true ) );
		$map = $this->index_rows( Drill::evaluate_scorecard( 'train_by_default_provider' ) );
		$this->assertSame( 'fire', $map['policy_default_deny']['status'] );
		$this->assertSame( 'fire', $map['new_plugin']['status'] );

		// Policy backup: enabled + recipient → fire.
		$this->seed_policy( array( 'policy_backup_email_enabled' => true ) );
		$map = $this->index_rows( Drill::evaluate_scorecard( 'provider_outage' ) );
		$this->assertSame( 'fire', $map['policy_backup']['status'] );
	}

	/**
	 * @param list<array<string,string>> $rows Rows.
	 * @return array<string,array<string,string>>
	 */
	private function index_rows( array $rows ): array {
		$out = array();
		foreach ( $rows as $row ) {
			$out[ $row['control'] ] = $row;
		}

		return $out;
	}

	public function test_all_controls_off_all_dead_ends_run_completes_no_control_mutation(): void {
		update_option( 'admin_email', '' );
		$this->seed_policy(
			array(
				'alert_on_deny' => false,
				'alert_email'   => '',
				'default'       => 'allow',
			)
		);
		$this->enable();
		$policy_before = get_option( Plugin::OPTION_KEY );

		$run = Drill::run( 'train_by_default_provider', self::T0 );
		$this->assertNotSame( array(), $run );
		$this->assertSame( 3, $run['dead_end_count'] );
		foreach ( $run['scorecard'] as $row ) {
			$this->assertSame( 'dead_end', $row['status'] );
		}
		$this->assertFalse( $run['alert_sent'], 'no recipient → no mail' );
		$this->assertSame( array(), Drill::$test_mails );
		$this->assertSame( $policy_before, get_option( Plugin::OPTION_KEY ) );
		$this->assertCount( 1, Drill::get_history() );

		// Circuit breaker is absent on this branch → unavailable dead end (never a fatal).
		if ( ! class_exists( '\HandL\AICAC\Circuit_Breaker', false ) ) {
			$run = Drill::run( 'provider_outage', self::T0 + 60 );
			$cb  = $this->by_control( $run )['circuit_breaker'];
			$this->assertSame( 'dead_end', $cb['status'] );
			$this->assertSame( 'control_unavailable', $cb['reason'] );
		}
	}

	public function test_alert_fires_once_per_run_with_drill_subject(): void {
		$this->enable();
		$run = Drill::run( 'provider_outage', self::T0 );
		$mails = Drill::test_mails();
		$this->assertCount( 1, $mails );
		$this->assertTrue( $run['alert_sent'] );
		$this->assertSame( self::EMAIL, $mails[0]['to'] );
		$this->assertStringStartsWith( '[DRILL]', $mails[0]['subject'] );
		$this->assertStringContainsString( 'SIMULATION', $mails[0]['body'] );
		$this->assertStringContainsString( 'admin-post.php', $mails[0]['body'] );
		$this->assertStringContainsString( Drill::ACTION_ACK, $mails[0]['body'] );
		$this->assertStringContainsString( $run['ack_nonce'], $mails[0]['body'] );

		Drill::run( 'budget_blowout', self::T0 + 10 );
		$this->assertCount( 2, Drill::test_mails() );
		$this->assertSame( 20, strlen( Drill::get_history()[0]['ack_nonce'] ) );
		$this->assertCount( 2, Drill::get_history() );
		$this->assertSame( 0, Drill::get_history()[0]['ack_ts'] );
		$this->assertSame( 0, Drill::get_history()[0]['ack_user_id'] );
		$this->assertFalse( Drill::get_history()[0]['followup_sent'] );
	}

	public function test_ack_records_time_to_ack(): void {
		$this->enable();
		$run = Drill::run( 'provider_outage', self::T0 );

		$this->assertFalse( Drill::acknowledge( $run['id'], 'wrong-token', 5, self::T0 + 60 ) );
		$this->assertSame( 0, Drill::latest_run()['ack_ts'] );

		$this->assertTrue( Drill::acknowledge( $run['id'], $run['ack_nonce'], 5, self::T0 + 600 ) );
		$latest = Drill::latest_run();
		$this->assertSame( self::T0 + 600, $latest['ack_ts'] );
		$this->assertSame( 5, $latest['ack_user_id'] );
		$this->assertSame( 600, $latest['time_to_ack_seconds'] );

		// Single-shot.
		$this->assertFalse( Drill::acknowledge( $run['id'], $run['ack_nonce'], 6, self::T0 + 900 ) );
		$this->assertSame( 600, Drill::latest_run()['time_to_ack_seconds'] );
	}

	public function test_followup_fires_once_when_ack_window_expires(): void {
		$this->enable( array( 'ack_window_hours' => 1 ) );
		$this->assertSame( 3600, Drill::ack_window_seconds() );
		$run = Drill::run( 'provider_outage', self::T0 );
		$this->assertCount( 1, Drill::test_mails() );

		$this->assertSame( array(), Drill::maybe_send_followups( self::T0 + 3000 ) );
		$this->assertCount( 1, Drill::test_mails() );

		$fired = Drill::maybe_send_followups( self::T0 + 3601 );
		$this->assertSame( array( $run['id'] ), $fired );
		$mails = Drill::test_mails();
		$this->assertCount( 2, $mails );
		$this->assertStringStartsWith( '[DRILL]', $mails[1]['subject'] );
		$this->assertTrue( $mails[1]['followup'] );
		$this->assertTrue( Drill::latest_run()['followup_sent'] );

		$this->assertSame( array(), Drill::maybe_send_followups( self::T0 + 99999 ) );
		$this->assertCount( 2, Drill::test_mails() );

		// Acknowledged runs never get a follow-up.
		$run2 = Drill::run( 'budget_blowout', self::T0 + 100000 );
		Drill::acknowledge( $run2['id'], $run2['ack_nonce'], 1, self::T0 + 100100 );
		$this->assertSame( array(), Drill::maybe_send_followups( self::T0 + 999999 ) );
		$this->assertCount( 3, Drill::test_mails() );

		// Ack window filter.
		$GLOBALS['handl_aicac_test_filters'][ Drill::FILTER_ACK_WINDOW ] = static function (): int {
			return 120;
		};
		$this->assertSame( 120, Drill::ack_window_seconds() );
	}

	public function test_run_writes_no_activity_log(): void {
		$this->enable();
		$log_before = get_option( Plugin::LOG_OPTION_KEY );
		$keys_before = array_keys( $GLOBALS['handl_aicac_test_options'] );

		$run = Drill::run( 'leaked_key', self::T0 );
		Drill::acknowledge( $run['id'], $run['ack_nonce'], 1, self::T0 + 5 );
		Drill::maybe_send_followups( self::T0 + 999999 );

		$this->assertSame( $log_before, get_option( Plugin::LOG_OPTION_KEY ) );
		$new_keys = array_diff( array_keys( $GLOBALS['handl_aicac_test_options'] ), $keys_before );
		foreach ( $new_keys as $key ) {
			$this->assertContains(
				$key,
				array( Drill::HISTORY_OPTION, Drill::SETTINGS_OPTION, Alert_Health::OPTION_KEY ),
				'unexpected option written: ' . $key
			);
		}
	}

	public function test_csv_matches_history_and_disabled_page_shows_off_notice(): void {
		$this->enable();
		$run_a = Drill::run( 'provider_outage', self::T0 );
		$run_b = Drill::run( 'budget_blowout', self::T0 + 3600 );
		Drill::acknowledge( $run_b['id'], $run_b['ack_nonce'], 9, self::T0 + 3700 );

		$csv   = Drill::csv_for_history();
		$lines = array_values( array_filter( explode( "\n", $csv ) ) );
		$this->assertCount( 3, $lines );
		$this->assertStringStartsWith( 'run_id,ts,iso_ts,scenario,trigger', $lines[0] );
		$this->assertStringContainsString( $run_a['id'], $lines[1] );
		$this->assertStringContainsString( 'provider_outage', $lines[1] );
		$this->assertStringContainsString( $run_b['id'], $lines[2] );
		$this->assertStringContainsString( 'budget_blowout', $lines[2] );
		$cols = str_getcsv( $lines[2] );
		$this->assertSame( 'yes', $cols[11], 'acknowledged column' );
		$this->assertSame( '9', $cols[13], 'ack_user_id column' );
		$this->assertSame( '100', $cols[14], 'time_to_ack_seconds column' );

		$html = Drill::build_print_html( Drill::get_history() );
		$this->assertStringContainsString( 'SIMULATION', $html );
		$this->assertStringContainsString( 'Budget blowout', $html );

		ob_start();
		Drill::render_page();
		$on = (string) ob_get_clean();
		$this->assertStringContainsString( 'Latest scorecard', $on );
		$this->assertStringContainsString( 'Run drill', $on );
		$this->assertStringNotContainsString( 'Incident drills are off', $on );

		Drill::save_settings( Drill::defaults() );
		ob_start();
		Drill::render_page();
		$off = (string) ob_get_clean();
		$this->assertStringContainsString( 'Incident drills are off', $off );
		$this->assertStringNotContainsString( 'Run drill', $off );
		$this->assertStringNotContainsString( 'Latest scorecard', $off );
	}

	public function test_history_capped_at_fifty(): void {
		$this->enable();
		for ( $i = 0; $i < 55; $i++ ) {
			Drill::run( 'budget_blowout', self::T0 + $i );
		}
		$history = Drill::get_history();
		$this->assertCount( Drill::HISTORY_CAP, $history );
		$this->assertSame( self::T0 + 54, $history[ count( $history ) - 1 ]['ts'] );
	}

	public function test_schedule_enabled_schedules_and_disable_clears(): void {
		$this->assertFalse( wp_next_scheduled( Drill::CRON_HOOK ) );

		// Feature on but schedule off → nothing scheduled.
		$this->enable();
		$this->assertFalse( wp_next_scheduled( Drill::CRON_HOOK ) );

		Drill::save_settings( array( 'enabled' => true, 'schedule_enabled' => true ) );
		$this->assertNotFalse( wp_next_scheduled( Drill::CRON_HOOK ) );

		Drill::save_settings( array( 'enabled' => true, 'schedule_enabled' => false ) );
		$this->assertFalse( wp_next_scheduled( Drill::CRON_HOOK ) );

		// enabled=false clears even if schedule_enabled stays true.
		Drill::save_settings( array( 'enabled' => true, 'schedule_enabled' => true ) );
		$this->assertNotFalse( wp_next_scheduled( Drill::CRON_HOOK ) );
		Drill::save_settings( array( 'enabled' => false, 'schedule_enabled' => true ) );
		$this->assertFalse( wp_next_scheduled( Drill::CRON_HOOK ) );
		$this->assertTrue( Drill::get_settings()['schedule_enabled'] );

		// Self-heal never schedules when not wanted; saving defaults clears.
		Drill::maybe_schedule();
		$this->assertFalse( wp_next_scheduled( Drill::CRON_HOOK ) );
		Drill::save_settings( array( 'enabled' => true, 'schedule_enabled' => true ) );
		Drill::save_settings( Drill::defaults() );
		$this->assertFalse( (bool) get_option( Drill::SETTINGS_OPTION, false ) );
		$this->assertFalse( wp_next_scheduled( Drill::CRON_HOOK ) );

		// Deactivation hook callback clears a live schedule.
		Drill::save_settings( array( 'enabled' => true, 'schedule_enabled' => true ) );
		$this->assertNotFalse( wp_next_scheduled( Drill::CRON_HOOK ) );
		Drill::on_deactivate();
		$this->assertFalse( wp_next_scheduled( Drill::CRON_HOOK ) );
	}

	public function test_cron_runs_default_scenario_once_per_calendar_month(): void {
		// Not wanted → no run.
		$this->enable();
		$this->assertSame( array(), Drill::cron_run( self::T0 ) );
		$this->assertSame( array(), Drill::get_history() );

		Drill::save_settings(
			array(
				'enabled'          => true,
				'schedule_enabled' => true,
				'default_scenario' => 'budget_blowout',
			)
		);
		$first = Drill::cron_run( self::T0 );
		$this->assertSame( 'budget_blowout', $first['scenario'] );
		$this->assertSame( 'schedule', $first['trigger'] );
		$this->assertSame( '2026-10', Drill::last_scheduled_run_ym() );
		$this->assertCount( 1, Drill::test_mails() );

		// Same month: gated (no double fire).
		$this->assertSame( array(), Drill::cron_run( self::T0 + 86400 * 3 ) );
		$this->assertCount( 1, Drill::get_history() );

		// Next month: fires again.
		$next = Drill::cron_run( self::T0 + 86400 * 30 );
		$this->assertSame( '2026-11', $next['ym'] );
		$this->assertCount( 2, Drill::get_history() );

		// A manual run never consumes the monthly gate.
		Drill::run( 'budget_blowout', self::T0 + 86400 * 62 );
		$this->assertSame( '2026-11', Drill::last_scheduled_run_ym() );
	}

	public function test_cli_status_failure_helper(): void {
		$this->assertFalse( Drill::has_status_failure() );

		$this->enable( array( 'ack_window_hours' => 1 ) );
		// Clean scorecard (alerts + keyscan fire; canary armed).
		update_option( \HandL\AICAC\Canary::REGISTRY_OPTION, array( 'token' => 'cnry_abc', 'option' => 'x', 'created' => 1 ), false );
		$run = Drill::run( 'leaked_key', self::T0 );
		$this->assertSame( 0, $run['dead_end_count'] );
		$this->assertFalse( Drill::has_status_failure( null, self::T0 + 60 ) );

		// Unacked past window → failure.
		$this->assertTrue( Drill::has_status_failure( null, self::T0 + 3601 ) );

		// Acked → clean again.
		Drill::acknowledge( $run['id'], $run['ack_nonce'], 1, self::T0 + 120 );
		$this->assertFalse( Drill::has_status_failure( null, self::T0 + 999999 ) );

		// Dead ends → failure regardless of ack.
		$this->assertTrue( Drill::has_status_failure( array( 'dead_end_count' => 2, 'ack_ts' => 5, 'ts' => self::T0 ), self::T0 ) );
		$this->assertFalse( Drill::has_status_failure( array( 'dead_end_count' => 0, 'ack_ts' => 5, 'ts' => self::T0 ), self::T0 + 999999 ) );
		$this->assertTrue( Drill::has_status_failure( array( 'dead_end_count' => 0, 'ack_ts' => 0, 'ts' => self::T0 ), self::T0 + 3601 ) );
	}

	public function test_cap_gate_and_unknown_scenario_falls_back_to_default(): void {
		$this->enable( array( 'default_scenario' => 'budget_blowout' ) );
		$run = Drill::run( 'does_not_exist', self::T0 );
		$this->assertSame( 'budget_blowout', $run['scenario'] );

		$GLOBALS['handl_aicac_test_current_user_can'] = false;
		ob_start();
		Drill::render_page();
		$this->assertSame( '', (string) ob_get_clean(), 'no view cap → renders nothing' );
	}
}
