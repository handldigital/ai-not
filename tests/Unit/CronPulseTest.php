<?php
/**
 * AICAC-CRON-PULSE (#415).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Cron_Pulse;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class CronPulseTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12 UTC.

	private const HOURLY = 'handl_test_hourly_job';

	private const WEEKLY = 'handl_test_weekly_job';

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$GLOBALS['handl_aicac_test_cron']             = array();
		Cron_Pulse::reset_for_tests();
		update_option( 'admin_email', 'haktan+aicac-cron-pulse@handldigital.com' );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'alert_email' => 'haktan+aicac-cron-pulse@handldigital.com',
			)
		);
		Cron_Pulse::set_test_now( self::NOW );
		Cron_Pulse::set_test_policy( array() );
		Cron_Pulse::set_test_disable_wp_cron( false );
		Cron_Pulse::set_test_next_scheduled( array() );
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_filters'][ Cron_Pulse::FILTER_HOOKS ],
			$GLOBALS['handl_aicac_test_filters'][ Cron_Pulse::FILTER_GRACE_MULTIPLIER ]
		);
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_cron']          = array();
		Cron_Pulse::reset_for_tests();
		parent::tearDown();
	}

	private function enable( float $multiplier = 2.0 ): void {
		Cron_Pulse::save_settings(
			array(
				'enabled'          => true,
				'grace_multiplier' => $multiplier,
			)
		);
	}

	/**
	 * Replace the registry with two deterministic recurring jobs.
	 */
	private function use_test_registry(): void {
		$GLOBALS['handl_aicac_test_filters'][ Cron_Pulse::FILTER_HOOKS ] = static function (): array {
			return array(
				array(
					'hook'             => self::HOURLY,
					'schedule'         => 'hourly',
					'label'            => 'Hourly job',
					'interval_seconds' => 3600,
				),
				array(
					'hook'             => self::WEEKLY,
					'schedule'         => 'weekly',
					'label'            => 'Weekly job',
					'interval_seconds' => 604800,
				),
			);
		};
	}

	/**
	 * @param array<string,int|false> $map Next scheduled map.
	 */
	private function schedule( array $map ): void {
		Cron_Pulse::set_test_next_scheduled( $map );
	}

	/**
	 * Both test jobs healthy and in the future.
	 *
	 * @return array<string,int>
	 */
	private function healthy(): array {
		return array(
			self::HOURLY => self::NOW + 600,
			self::WEEKLY => self::NOW + 86400,
		);
	}

	public function test_defaults_off_save_defaults_deletes_and_noop_byte_identical(): void {
		$this->assertFalse( Cron_Pulse::is_enabled() );
		$this->assertSame( Cron_Pulse::defaults(), Cron_Pulse::get_settings() );
		$this->assertSame( 2.0, Cron_Pulse::defaults()['grace_multiplier'] );
		$this->assertSame( 'report_only_never_depends_on_cron', Cron_Pulse::FRAMING );

		$this->assertTrue( Cron_Pulse::save_settings( array( 'enabled' => true, 'grace_multiplier' => 2.0 ) ) );
		$this->assertTrue( Cron_Pulse::is_enabled() );
		$before  = get_option( Cron_Pulse::SETTINGS_OPTION );
		$changed = Cron_Pulse::save_settings( array( 'enabled' => true, 'grace_multiplier' => 2.0 ) );
		$this->assertFalse( $changed );
		$this->assertSame( $before, get_option( Cron_Pulse::SETTINGS_OPTION ) );

		Cron_Pulse::save_settings( Cron_Pulse::defaults() );
		$this->assertFalse( (bool) get_option( Cron_Pulse::SETTINGS_OPTION, false ) );
	}

	public function test_grace_sanitize_filter_and_floor(): void {
		$this->assertSame( 1.0, Cron_Pulse::sanitize_grace_multiplier( 0 ) );
		$this->assertSame( 1.0, Cron_Pulse::sanitize_grace_multiplier( -3 ) );
		$this->assertSame( 10.0, Cron_Pulse::sanitize_grace_multiplier( 999 ) );
		$this->assertSame( 2.0, Cron_Pulse::sanitize_grace_multiplier( 'nope' ) );
		$this->assertSame( 2.0, Cron_Pulse::sanitize_grace_multiplier( NAN ) );
		$this->assertSame( 2.5, Cron_Pulse::sanitize_grace_multiplier( '2,5' ) );
		$this->assertSame( 3.33, Cron_Pulse::sanitize_grace_multiplier( '3.333' ) );

		// Min grace is 15 minutes regardless of interval x multiplier.
		$this->assertSame( 900, Cron_Pulse::grace_seconds( 60, 2.0 ) );
		$this->assertSame( 900, Cron_Pulse::grace_seconds( 0, 2.0 ) );
		$this->assertSame( 7200, Cron_Pulse::grace_seconds( 3600, 2.0 ) );
		$this->assertSame( 1209600, Cron_Pulse::grace_seconds( 604800, 2.0 ) );

		$this->enable( 3.0 );
		$this->assertSame( 3.0, Cron_Pulse::grace_multiplier() );
		$this->assertSame( 10800, Cron_Pulse::grace_seconds( 3600 ) );
		$GLOBALS['handl_aicac_test_filters'][ Cron_Pulse::FILTER_GRACE_MULTIPLIER ] = static function (): float {
			return 1.5;
		};
		$this->assertSame( 1.5, Cron_Pulse::grace_multiplier() );
		$this->assertSame( 5400, Cron_Pulse::grace_seconds( 3600 ) );
	}

	public function test_bundled_registry_covers_recurring_and_single_hooks(): void {
		$hooks = array();
		foreach ( Cron_Pulse::registry() as $row ) {
			$hooks[ $row['hook'] ] = $row;
		}
		foreach (
			array(
				'handl_aicac_send_denial_digest'    => 'hourly',
				'handl_aicac_send_weekly_report'    => 'weekly',
				'handl_aicac_send_monthly_report'   => 'daily',
				'handl_aicac_send_governance_digest' => 'weekly',
				'handl_aicac_keyscan_weekly'        => 'weekly',
				'handl_aicac_threat_feed_daily'     => 'daily',
				'handl_aicac_rescan_weekly'         => 'weekly',
				'handl_aicac_send_policy_backup'    => 'weekly',
				'handl_aicac_prune_activity_log'    => 'daily',
				'handl_aicac_sweep_expired_allows'  => 'hourly',
				'handl_aicac_demo_expire'           => 'daily',
				'handl_aicac_freeze_expire'         => 'single',
				'handl_aicac_break_glass_expire'    => 'single',
			) as $hook => $schedule
		) {
			$this->assertArrayHasKey( $hook, $hooks, $hook );
			$this->assertSame( $schedule, $hooks[ $hook ]['schedule'], $hook );
			$this->assertGreaterThan( 0, $hooks[ $hook ]['interval_seconds'], $hook );
			$this->assertNotSame( '', $hooks[ $hook ]['label'], $hook );
		}
		$this->assertSame( 3600, $hooks['handl_aicac_send_denial_digest']['interval_seconds'] );
		$this->assertSame( 604800, $hooks['handl_aicac_keyscan_weekly']['interval_seconds'] );
		$this->assertTrue( $hooks['handl_aicac_keyscan_weekly']['expected'] );
		// Conditionally scheduled features are idle when the site has them off.
		$this->assertFalse( $hooks['handl_aicac_send_weekly_report']['expected'] );
		$this->assertFalse( $hooks['handl_aicac_freeze_expire']['expected'] );
	}

	public function test_bundled_registry_expected_follows_owning_feature_policy(): void {
		Cron_Pulse::set_test_policy( array( 'alert_on_deny' => true ) );
		$by_hook = array();
		foreach ( Cron_Pulse::registry() as $row ) {
			$by_hook[ $row['hook'] ] = $row;
		}
		$this->assertTrue( $by_hook['handl_aicac_send_denial_digest']['expected'] );

		// Off feature + unscheduled -> idle, never overdue.
		$this->schedule( array() );
		$this->enable();
		$statuses = array();
		foreach ( Cron_Pulse::snapshot( self::NOW )['hooks'] as $row ) {
			$statuses[ $row['hook'] ] = $row['status'];
		}
		$this->assertSame( Cron_Pulse::STATUS_UNSCHEDULED, $statuses['handl_aicac_send_denial_digest'] );
		$this->assertSame( Cron_Pulse::STATUS_IDLE, $statuses['handl_aicac_send_weekly_report'] );
		$this->assertSame( Cron_Pulse::STATUS_IDLE, $statuses['handl_aicac_freeze_expire'] );
	}

	public function test_registry_filter_extends_hooks_and_sanitizes_rows(): void {
		$GLOBALS['handl_aicac_test_filters'][ Cron_Pulse::FILTER_HOOKS ] = static function ( array $rows ): array {
			$rows[] = array(
				'hook'     => 'My_Custom_Hook',
				'schedule' => 'twicedaily',
				'label'    => 'Custom <b>job</b>',
			);
			$rows[] = array( 'hook' => '', 'schedule' => 'daily' );
			$rows[] = 'junk';
			return $rows;
		};
		$by_hook = array();
		foreach ( Cron_Pulse::registry() as $row ) {
			$by_hook[ $row['hook'] ] = $row;
		}
		$this->assertArrayHasKey( 'my_custom_hook', $by_hook );
		$this->assertArrayHasKey( 'handl_aicac_keyscan_weekly', $by_hook );
		$this->assertSame( 43200, $by_hook['my_custom_hook']['interval_seconds'] );
		$this->assertTrue( $by_hook['my_custom_hook']['expected'] );
		$this->assertStringNotContainsString( '<b>', $by_hook['my_custom_hook']['label'] );

		$single = Cron_Pulse::sanitize_entry( array( 'hook' => 'x_once', 'schedule' => 'single' ) );
		$this->assertIsArray( $single );
		$this->assertFalse( $single['expected'] );
		$this->assertSame( 3600, $single['interval_seconds'] );
	}

	public function test_overdue_when_next_scheduled_in_past_beyond_grace(): void {
		$this->use_test_registry();
		$this->enable( 2.0 ); // Hourly grace = 7200s.
		$this->schedule(
			array(
				self::HOURLY => self::NOW - 7201,
				self::WEEKLY => self::NOW + 100,
			)
		);
		$snap = Cron_Pulse::snapshot( self::NOW );
		$this->assertSame( 1, $snap['overdue_count'] );
		$this->assertSame( self::HOURLY, $snap['roster'][0]['hook'] );
		$this->assertSame( 7201, $snap['roster'][0]['overdue_by_seconds'] );
		$this->assertSame( Cron_Pulse::STATUS_OVERDUE, $snap['roster'][0]['status'] );
		$this->assertSame( 'hourly', $snap['roster'][0]['schedule'] );
		$this->assertSame( 'Hourly job', $snap['roster'][0]['label'] );
		$this->assertSame( self::NOW - 7201, $snap['roster'][0]['next_due'] );
		$this->assertSame( $snap['roster'][0], $snap['oldest'] );

		// Exactly at the grace boundary is not yet overdue.
		$this->schedule( array_merge( $this->healthy(), array( self::HOURLY => self::NOW - 7200 ) ) );
		$this->assertSame( 0, Cron_Pulse::snapshot( self::NOW )['overdue_count'] );
	}

	public function test_not_overdue_when_next_in_future_or_within_grace(): void {
		$this->use_test_registry();
		$this->enable();
		$this->schedule( $this->healthy() );
		$snap = Cron_Pulse::snapshot( self::NOW );
		$this->assertSame( 0, $snap['overdue_count'] );
		$this->assertSame( array(), $snap['roster'] );
		$this->assertNull( $snap['oldest'] );
		$this->assertSame( 2, $snap['watched_count'] );

		// Slightly late but inside grace.
		$this->schedule( array_merge( $this->healthy(), array( self::HOURLY => self::NOW - 600 ) ) );
		$this->assertSame( 0, Cron_Pulse::snapshot( self::NOW )['overdue_count'] );
	}

	public function test_min_grace_floor_applies_to_short_intervals(): void {
		$GLOBALS['handl_aicac_test_filters'][ Cron_Pulse::FILTER_HOOKS ] = static function (): array {
			return array( array( 'hook' => 'handl_test_fast', 'schedule' => 'fast', 'interval_seconds' => 60 ) );
		};
		$this->enable( 2.0 ); // 60 x 2 = 120s, floored to 900s.
		$this->schedule( array( 'handl_test_fast' => self::NOW - 899 ) );
		$this->assertSame( 0, Cron_Pulse::snapshot( self::NOW )['overdue_count'] );
		$this->schedule( array( 'handl_test_fast' => self::NOW - 901 ) );
		$this->assertSame( 1, Cron_Pulse::snapshot( self::NOW )['overdue_count'] );
	}

	public function test_unscheduled_recurring_hook_counts_overdue(): void {
		$this->use_test_registry();
		$this->enable();
		$this->schedule( array( self::WEEKLY => self::NOW + 100 ) ); // Hourly missing.
		$snap = Cron_Pulse::snapshot( self::NOW );
		$this->assertSame( 1, $snap['overdue_count'] );
		$this->assertSame( self::HOURLY, $snap['roster'][0]['hook'] );
		$this->assertSame( Cron_Pulse::STATUS_UNSCHEDULED, $snap['roster'][0]['status'] );
		$this->assertSame( 0, $snap['roster'][0]['next_due'] );

		// With a last-fired observation, overdue_by is time since it last fired.
		Cron_Pulse::record_fire( self::HOURLY, self::NOW - 5000 );
		$snap = Cron_Pulse::snapshot( self::NOW );
		$this->assertSame( 5000, $snap['roster'][0]['overdue_by_seconds'] );
		$this->assertSame( self::NOW - 5000, $snap['roster'][0]['last_fired'] );
	}

	public function test_roster_orders_oldest_overdue_first(): void {
		$this->use_test_registry();
		$this->enable();
		$this->schedule(
			array(
				self::HOURLY => self::NOW - 8000,
				self::WEEKLY => self::NOW - ( 14 * 86400 ) - 500,
			)
		);
		$roster = Cron_Pulse::snapshot( self::NOW )['roster'];
		$this->assertCount( 2, $roster );
		$this->assertSame( self::WEEKLY, $roster[0]['hook'] );
		$this->assertSame( self::HOURLY, $roster[1]['hook'] );
	}

	public function test_live_wp_next_scheduled_is_used_without_override(): void {
		$this->use_test_registry();
		$this->enable();
		Cron_Pulse::set_test_next_scheduled( null );
		$GLOBALS['handl_aicac_test_cron'] = array(
			self::HOURLY => self::NOW - 20000,
			self::WEEKLY => self::NOW + 10,
		);
		$snap = Cron_Pulse::snapshot( self::NOW );
		$this->assertSame( 1, $snap['overdue_count'] );
		$this->assertSame( self::HOURLY, $snap['roster'][0]['hook'] );
	}

	public function test_alert_fires_once_and_rearms_after_recovery(): void {
		$this->use_test_registry();
		$this->enable();
		$this->schedule( array_merge( $this->healthy(), array( self::HOURLY => self::NOW - 20000 ) ) );

		$this->assertTrue( Cron_Pulse::maybe_fire_alerts( self::NOW ) );
		$mails = Cron_Pulse::test_mails();
		$this->assertCount( 1, $mails );
		$this->assertStringContainsString( '[CRON-PULSE]', $mails[0]['subject'] );
		$this->assertStringContainsString( self::HOURLY, $mails[0]['subject'] );
		$this->assertStringContainsString( self::HOURLY, $mails[0]['body'] );
		$this->assertStringContainsString( 'Report only', $mails[0]['body'] );
		$this->assertTrue( Cron_Pulse::is_alerted() );
		$this->assertCount( 1, Cron_Pulse::get_state()['history'] );

		// Latched: still overdue, no second alert.
		$this->assertFalse( Cron_Pulse::maybe_fire_alerts( self::NOW + 10 ) );
		$this->assertCount( 1, Cron_Pulse::test_mails() );

		// Recovery re-arms.
		$this->schedule( $this->healthy() );
		$this->assertFalse( Cron_Pulse::maybe_fire_alerts( self::NOW + 20 ) );
		$this->assertFalse( Cron_Pulse::is_alerted() );

		// New overdue alerts again.
		$this->schedule( array_merge( $this->healthy(), array( self::WEEKLY => self::NOW - ( 30 * 86400 ) ) ) );
		$this->assertTrue( Cron_Pulse::maybe_fire_alerts( self::NOW + 30 ) );
		$this->assertCount( 2, Cron_Pulse::test_mails() );
		$this->assertCount( 2, Cron_Pulse::get_state()['history'] );
		$this->assertSame( self::WEEKLY, Cron_Pulse::get_state()['history'][1]['oldest_hook'] );
	}

	public function test_no_alert_when_nothing_overdue_or_disabled(): void {
		$this->use_test_registry();
		$this->enable();
		$this->schedule( $this->healthy() );
		$this->assertFalse( Cron_Pulse::maybe_fire_alerts( self::NOW ) );
		$this->assertCount( 0, Cron_Pulse::test_mails() );

		// Inside grace: still no alert.
		$this->schedule( array_merge( $this->healthy(), array( self::HOURLY => self::NOW - 7000 ) ) );
		$this->assertFalse( Cron_Pulse::maybe_fire_alerts( self::NOW ) );
		$this->assertCount( 0, Cron_Pulse::test_mails() );

		// Disabled -> never alerts even when overdue.
		Cron_Pulse::save_settings( Cron_Pulse::defaults() );
		$this->schedule( array_merge( $this->healthy(), array( self::HOURLY => self::NOW - 20000 ) ) );
		$this->assertFalse( Cron_Pulse::maybe_fire_alerts( self::NOW ) );
		$this->assertFalse( Cron_Pulse::maybe_check( self::NOW, true ) );
		$this->assertCount( 0, Cron_Pulse::test_mails() );
	}

	public function test_maybe_check_is_throttled_and_fires_alert(): void {
		$this->use_test_registry();
		$this->enable();
		$this->schedule( array_merge( $this->healthy(), array( self::HOURLY => self::NOW - 20000 ) ) );

		$this->assertTrue( Cron_Pulse::maybe_check( self::NOW ) );
		$this->assertCount( 1, Cron_Pulse::test_mails() );
		$this->assertSame( self::NOW, Cron_Pulse::get_state()['last_check_ts'] );

		// Within throttle: no check at all.
		$this->assertFalse( Cron_Pulse::maybe_check( self::NOW + Cron_Pulse::CHECK_THROTTLE_SECONDS - 1 ) );
		$this->assertSame( self::NOW, Cron_Pulse::get_state()['last_check_ts'] );

		// Recovery is noticed on the next throttled window and re-arms.
		$this->schedule( $this->healthy() );
		$this->assertTrue( Cron_Pulse::maybe_check( self::NOW + Cron_Pulse::CHECK_THROTTLE_SECONDS ) );
		$this->assertFalse( Cron_Pulse::is_alerted() );

		// Force bypasses the throttle.
		$this->assertTrue( Cron_Pulse::maybe_check( self::NOW + Cron_Pulse::CHECK_THROTTLE_SECONDS + 1, true ) );
	}

	public function test_detection_runs_on_admin_init_and_never_schedules_cron(): void {
		$this->enable();
		Cron_Pulse::init();

		$added = $GLOBALS['handl_aicac_test_added_actions'];
		$this->assertContains( 'admin_init', $added );
		foreach ( $added as $hook ) {
			$this->assertStringStartsNotWith( 'handl_aicac_cron_pulse', (string) $hook, 'No own cron hook.' );
		}

		// Init (even with an overdue environment) never schedules anything itself.
		$this->assertSame( array(), $GLOBALS['handl_aicac_test_cron'] );
		Cron_Pulse::maybe_check( self::NOW, true );
		$this->assertSame( array(), $GLOBALS['handl_aicac_test_cron'] );

		$source = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-cron-pulse.php' );
		$this->assertStringNotContainsString( 'wp_schedule_event', $source );
		$this->assertStringNotContainsString( 'wp_schedule_single_event', $source );
		$this->assertStringNotContainsString( 'wp_clear_scheduled_hook', $source );
		$this->assertStringNotContainsString( 'wp_unschedule_event', $source );
		$this->assertDoesNotMatchRegularExpression( '/const\s+CRON_HOOK\b/', $source );
	}

	public function test_init_attaches_nothing_but_admin_surfaces_when_disabled(): void {
		Cron_Pulse::init();
		$added = $GLOBALS['handl_aicac_test_added_actions'];
		$this->assertContains( 'admin_menu', $added );
		$this->assertNotContains( 'init', $added );
		$count_admin_init = count( array_filter( $added, static fn( $h ) => 'admin_init' === $h ) );
		$this->assertSame( 2, $count_admin_init, 'Only csv/print handlers, no check.' );
	}

	public function test_listeners_attach_to_every_watched_hook(): void {
		$this->use_test_registry();
		$this->enable();
		Cron_Pulse::register_listeners();
		$added = $GLOBALS['handl_aicac_test_added_actions'];
		$this->assertContains( self::HOURLY, $added );
		$this->assertContains( self::WEEKLY, $added );

		// Disabled -> no listeners.
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		Cron_Pulse::save_settings( Cron_Pulse::defaults() );
		Cron_Pulse::register_listeners();
		$this->assertSame( array(), $GLOBALS['handl_aicac_test_added_actions'] );
	}

	public function test_record_fire_tracks_last_fired_and_feeds_roster(): void {
		$this->use_test_registry();
		$this->enable();
		$this->assertTrue( Cron_Pulse::record_fire( self::HOURLY, self::NOW - 100 ) );
		$this->assertFalse( Cron_Pulse::record_fire( self::HOURLY, self::NOW - 100 ), 'Identical write is a no-op.' );
		$this->assertTrue( Cron_Pulse::record_fire( 'Handl_Test_Weekly_Job', self::NOW - 50 ) );
		$this->assertFalse( Cron_Pulse::record_fire( '', self::NOW ) );

		$fired = Cron_Pulse::get_state()['last_fired'];
		$this->assertSame( self::NOW - 100, $fired[ self::HOURLY ] );
		$this->assertSame( self::NOW - 50, $fired[ self::WEEKLY ] );

		$this->schedule( array_merge( $this->healthy(), array( self::HOURLY => self::NOW - 20000 ) ) );
		$row = Cron_Pulse::snapshot( self::NOW )['roster'][0];
		$this->assertSame( self::NOW - 100, $row['last_fired'] );
		$this->assertStringContainsString( 'UTC', $row['last_fired_utc'] );

		// Default "now" resolves from the test clock.
		Cron_Pulse::record_fire( self::HOURLY );
		$this->assertSame( self::NOW, Cron_Pulse::get_state()['last_fired'][ self::HOURLY ] );
	}

	public function test_last_fired_map_is_capped_and_sanitized(): void {
		$map = array();
		for ( $i = 1; $i <= Cron_Pulse::LAST_FIRED_CAP + 20; $i++ ) {
			$map[ 'hook_' . $i ] = self::NOW + $i;
		}
		$map['bad']  = 0;
		$map['neg']  = -5;
		$state       = Cron_Pulse::sanitize_state( array( 'last_fired' => $map, 'alerted' => true ) );
		$this->assertCount( Cron_Pulse::LAST_FIRED_CAP, $state['last_fired'] );
		$this->assertArrayHasKey( 'hook_' . ( Cron_Pulse::LAST_FIRED_CAP + 20 ), $state['last_fired'] );
		$this->assertArrayNotHasKey( 'hook_1', $state['last_fired'] );
		$this->assertArrayNotHasKey( 'bad', $state['last_fired'] );

		$history = array();
		for ( $i = 1; $i <= 60; $i++ ) {
			$history[] = array( 'ts' => self::NOW + $i, 'overdue_count' => 1 );
		}
		$state = Cron_Pulse::sanitize_state( array( 'history' => $history ) );
		$this->assertCount( Cron_Pulse::HISTORY_CAP, $state['history'] );
		$this->assertSame( self::NOW + 60, $state['history'][ Cron_Pulse::HISTORY_CAP - 1 ]['ts'] );
	}

	public function test_disable_wp_cron_advice_in_snapshot_csv_and_alert(): void {
		$this->use_test_registry();
		$this->enable();
		$this->schedule( array_merge( $this->healthy(), array( self::HOURLY => self::NOW - 20000 ) ) );

		$snap = Cron_Pulse::snapshot( self::NOW );
		$this->assertFalse( $snap['disable_wp_cron'] );
		$this->assertSame( '', $snap['advice'] );
		$csv = Cron_Pulse::csv_for_snapshot( $snap );
		$this->assertStringContainsString( 'DISABLE_WP_CRON,,,,,,,,not_set,no', $csv );

		Cron_Pulse::set_test_disable_wp_cron( true );
		$snap = Cron_Pulse::snapshot( self::NOW );
		$this->assertTrue( $snap['disable_wp_cron'] );
		$this->assertStringContainsString( 'wp-cron.php', $snap['advice'] );
		$this->assertStringContainsString( 'system cron', $snap['advice'] );

		$csv = Cron_Pulse::csv_for_snapshot( $snap );
		$this->assertStringContainsString( 'disable_wp_cron,advice,framing', $csv );
		$this->assertStringContainsString( 'DISABLE_WP_CRON,,,,,,,,set,yes', $csv );
		$this->assertStringContainsString( 'system cron must request wp-cron.php', $csv );

		$this->assertTrue( Cron_Pulse::maybe_fire_alerts( self::NOW ) );
		$this->assertStringContainsString( 'system cron', Cron_Pulse::test_mails()[0]['body'] );
		$this->assertStringContainsString( 'DISABLE_WP_CRON', Cron_Pulse::build_print_html( $snap ) );
	}

	public function test_csv_contains_roster_framing_and_neutralizes_formulas(): void {
		$GLOBALS['handl_aicac_test_filters'][ Cron_Pulse::FILTER_HOOKS ] = static function (): array {
			return array(
				array( 'hook' => self::HOURLY, 'schedule' => 'hourly', 'label' => '=cmd|calc, "x"' ),
				array( 'hook' => self::WEEKLY, 'schedule' => 'weekly', 'label' => 'Weekly job' ),
			);
		};
		$this->enable();
		Cron_Pulse::record_fire( self::HOURLY, self::NOW - 30000 );
		$this->schedule( array_merge( $this->healthy(), array( self::HOURLY => self::NOW - 20000 ) ) );

		$csv = Cron_Pulse::csv_for_snapshot( Cron_Pulse::snapshot( self::NOW ) );
		$this->assertStringContainsString( 'section,hook,label,schedule,interval_seconds,grace_seconds,last_fired_utc,next_due_utc,overdue_by_seconds,status', $csv );
		$this->assertStringContainsString( 'summary', $csv );
		$this->assertStringContainsString( 'overdue=1 watched=2', $csv );
		$this->assertStringContainsString( 'overdue,' . self::HOURLY, $csv );
		$this->assertStringContainsString( 'watched,' . self::WEEKLY, $csv );
		$this->assertStringContainsString( ',20000,overdue,', $csv );
		$this->assertStringContainsString( Cron_Pulse::FRAMING, $csv );
		$this->assertStringContainsString( '"\'=cmd|calc, ""x"""', $csv );
		$this->assertStringContainsString( 'UTC', $csv );
	}

	public function test_print_html_lists_roster(): void {
		$this->use_test_registry();
		$this->enable();
		$this->schedule( array_merge( $this->healthy(), array( self::HOURLY => self::NOW - 20000 ) ) );
		$html = Cron_Pulse::build_print_html( Cron_Pulse::snapshot( self::NOW ) );
		$this->assertStringContainsString( self::HOURLY, $html );
		$this->assertStringContainsString( 'Hourly job', $html );
		$this->assertStringContainsString( 'overdue', $html );
	}

	public function test_format_duration(): void {
		$this->assertSame( '45s', Cron_Pulse::format_duration( 45 ) );
		$this->assertSame( '5m', Cron_Pulse::format_duration( 300 ) );
		$this->assertSame( '2h 5m', Cron_Pulse::format_duration( 7500 ) );
		$this->assertSame( '3h', Cron_Pulse::format_duration( 10800 ) );
		$this->assertSame( '2d 1h', Cron_Pulse::format_duration( 2 * 86400 + 3600 ) );
	}

	public function test_writes_confined_to_own_options(): void {
		$this->use_test_registry();
		$this->enable();
		$this->schedule( array_merge( $this->healthy(), array( self::HOURLY => self::NOW - 20000 ) ) );

		$before_policy = get_option( Plugin::OPTION_KEY );
		$before_keys   = array_keys( $GLOBALS['handl_aicac_test_options'] );

		Cron_Pulse::record_fire( self::HOURLY, self::NOW - 40000 );
		Cron_Pulse::snapshot( self::NOW );
		$this->assertTrue( Cron_Pulse::maybe_check( self::NOW, true ) );

		$this->assertSame( $before_policy, get_option( Plugin::OPTION_KEY ) );
		$this->assertNotFalse( get_option( Cron_Pulse::SETTINGS_OPTION, false ) );
		$this->assertNotFalse( get_option( Cron_Pulse::STATE_OPTION, false ) );
		$this->assertSame( array(), $GLOBALS['handl_aicac_test_cron'], 'Never schedules or unschedules.' );

		// Only our state option plus Alerts' own delivery-health bookkeeping (via safe_wp_mail).
		$new_keys = array_values( array_diff( array_keys( $GLOBALS['handl_aicac_test_options'] ), $before_keys ) );
		sort( $new_keys );
		$this->assertSame( array( 'handl_aicac_alert_health', Cron_Pulse::STATE_OPTION ), $new_keys );
	}
}
