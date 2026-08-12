<?php
/**
 * Unit tests for AICAC-HOURS quiet hours / maintenance windows (#132).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Policy;
use HandL\AICAC\Quiet_Hours;
use PHPUnit\Framework\TestCase;

final class QuietHoursTest extends TestCase {

	public function test_empty_schedule_is_noop(): void {
		$policy = array(
			'default'     => 'allow',
			'plugins'     => array(),
			'quiet_hours' => array(),
		);
		$this->assertNull( Quiet_Hours::active_window( $policy, time() ) );
		$this->assertNull( Quiet_Hours::evaluate_gate( $policy, time() ) );
		$eval = Policy::evaluate( $policy, 'demo/demo.php', 'generate_text', null, null, time() );
		$this->assertFalse( $eval['prevent'] );
		$this->assertSame( '', $eval['reason'] );
	}

	public function test_deny_window_blocks_with_quiet_hours_reason(): void {
		$tz  = new \DateTimeZone( 'UTC' );
		$now = ( new \DateTimeImmutable( '2026-08-12 14:30:00', $tz ) )->getTimestamp(); // Wednesday
		$policy = array(
			'default'     => 'allow',
			'plugins'     => array(),
			'quiet_hours' => array(
				array(
					'name'  => 'Afternoon block',
					'days'  => array( 3 ), // Wed
					'start' => '14:00',
					'end'   => '16:00',
					'mode'  => Quiet_Hours::MODE_DENY,
				),
			),
		);

		$active = Quiet_Hours::active_window( $policy, $now, $tz );
		$this->assertNotNull( $active );
		$this->assertSame( 'Afternoon block', $active['name'] );
		$this->assertSame( '16:00', $active['ends_label'] );

		$eval = Policy::evaluate( $policy, 'demo/demo.php', 'generate_text', null, null, $now );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( 'quiet_hours', $eval['reason'] );
	}

	public function test_observe_window_never_blocks(): void {
		$tz  = new \DateTimeZone( 'UTC' );
		$now = ( new \DateTimeImmutable( '2026-08-12 14:30:00', $tz ) )->getTimestamp();
		$policy = array(
			'default'     => 'allow',
			'plugins'     => array(),
			'quiet_hours' => array(
				array(
					'name'  => 'Watch only',
					'days'  => array( 3 ),
					'start' => '14:00',
					'end'   => '16:00',
					'mode'  => Quiet_Hours::MODE_OBSERVE,
				),
			),
		);

		$active = Quiet_Hours::active_window( $policy, $now, $tz );
		$this->assertNotNull( $active );
		$this->assertSame( Quiet_Hours::MODE_OBSERVE, $active['mode'] );
		$this->assertNull( Quiet_Hours::evaluate_gate( $policy, $now, $tz ) );

		$eval = Policy::evaluate( $policy, 'demo/demo.php', 'generate_text', null, null, $now );
		$this->assertFalse( $eval['prevent'] );
		$this->assertSame( '', $eval['reason'] );
	}

	public function test_window_spanning_midnight(): void {
		$tz = new \DateTimeZone( 'UTC' );
		// Monday 22:00–06:00 overnight.
		$win = array(
			'name'  => 'Overnight',
			'days'  => array( 1 ), // Mon
			'start' => '22:00',
			'end'   => '06:00',
			'mode'  => Quiet_Hours::MODE_DENY,
		);
		$policy = array( 'quiet_hours' => array( $win ) );

		$mon_late = ( new \DateTimeImmutable( '2026-08-10 23:15:00', $tz ) )->getTimestamp(); // Mon
		$tue_early = ( new \DateTimeImmutable( '2026-08-11 05:30:00', $tz ) )->getTimestamp(); // Tue
		$tue_after = ( new \DateTimeImmutable( '2026-08-11 06:00:00', $tz ) )->getTimestamp();
		$sun_late  = ( new \DateTimeImmutable( '2026-08-09 23:15:00', $tz ) )->getTimestamp(); // Sun — not selected

		$this->assertNotNull( Quiet_Hours::active_window( $policy, $mon_late, $tz ) );
		$this->assertNotNull( Quiet_Hours::active_window( $policy, $tue_early, $tz ) );
		$this->assertNull( Quiet_Hours::active_window( $policy, $tue_after, $tz ) );
		$this->assertNull( Quiet_Hours::active_window( $policy, $sun_late, $tz ) );

		$active = Quiet_Hours::active_window( $policy, $mon_late, $tz );
		$this->assertSame( '06:00', $active['ends_label'] );
	}

	public function test_dst_spring_forward_day_in_america_new_york(): void {
		// US DST spring forward 2026-03-08: 02:00 → 03:00 local.
		$tz = new \DateTimeZone( 'America/New_York' );
		$win = array(
			'name'  => 'DST morning',
			'days'  => array( 0 ), // Sunday
			'start' => '01:30',
			'end'   => '04:00',
			'mode'  => Quiet_Hours::MODE_DENY,
		);
		$policy = array( 'quiet_hours' => array( $win ) );

		$before_gap = ( new \DateTimeImmutable( '2026-03-08 01:45:00', $tz ) )->getTimestamp();
		$after_gap  = ( new \DateTimeImmutable( '2026-03-08 03:15:00', $tz ) )->getTimestamp();
		$after_end  = ( new \DateTimeImmutable( '2026-03-08 04:00:00', $tz ) )->getTimestamp();

		$this->assertNotNull( Quiet_Hours::active_window( $policy, $before_gap, $tz ) );
		$this->assertNotNull( Quiet_Hours::active_window( $policy, $after_gap, $tz ) );
		$this->assertNull( Quiet_Hours::active_window( $policy, $after_end, $tz ) );
	}

	public function test_kill_switch_still_wins_over_quiet_hours(): void {
		$tz  = new \DateTimeZone( 'UTC' );
		$now = ( new \DateTimeImmutable( '2026-08-12 14:30:00', $tz ) )->getTimestamp();
		$policy = array(
			'default'     => 'allow',
			'plugins'     => array(),
			'kill_switch' => true,
			'quiet_hours' => array(
				array(
					'name'  => 'Afternoon',
					'days'  => array( 3 ),
					'start' => '14:00',
					'end'   => '16:00',
					'mode'  => Quiet_Hours::MODE_DENY,
				),
			),
		);
		$eval = Policy::evaluate( $policy, 'demo/demo.php', 'generate_text', null, null, $now );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( 'kill_switch', $eval['reason'] );
	}

	public function test_deny_wins_when_deny_and_observe_overlap(): void {
		$tz  = new \DateTimeZone( 'UTC' );
		$now = ( new \DateTimeImmutable( '2026-08-12 14:30:00', $tz ) )->getTimestamp();
		$policy = array(
			'quiet_hours' => array(
				array(
					'name'  => 'Observe first',
					'days'  => array( 3 ),
					'start' => '14:00',
					'end'   => '16:00',
					'mode'  => Quiet_Hours::MODE_OBSERVE,
				),
				array(
					'name'  => 'Deny second',
					'days'  => array( 3 ),
					'start' => '14:00',
					'end'   => '16:00',
					'mode'  => Quiet_Hours::MODE_DENY,
				),
			),
		);
		$active = Quiet_Hours::active_window( $policy, $now, $tz );
		$this->assertNotNull( $active );
		$this->assertSame( 'Deny second', $active['name'] );
		$this->assertSame( Quiet_Hours::MODE_DENY, $active['mode'] );
	}

	public function test_sanitize_drops_incomplete_rows(): void {
		$out = Quiet_Hours::sanitize_windows(
			array(
				array( 'name' => '', 'days' => array( 1 ), 'start' => '10:00', 'end' => '11:00', 'mode' => 'deny' ),
				array( 'name' => 'OK', 'days' => array( 1 ), 'start' => '10:00', 'end' => '11:00', 'mode' => 'observe' ),
				array( 'name' => 'Bad time', 'days' => array( 1 ), 'start' => '25:00', 'end' => '11:00', 'mode' => 'deny' ),
			)
		);
		$this->assertCount( 1, $out );
		$this->assertSame( 'OK', $out[0]['name'] );
		$this->assertSame( Quiet_Hours::MODE_OBSERVE, $out[0]['mode'] );
	}
}
