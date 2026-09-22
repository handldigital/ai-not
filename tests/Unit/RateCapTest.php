<?php
/**
 * AICAC-RATE-CAP (#275): per-plugin call ceilings.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Quiet_Hours;
use HandL\AICAC\Rate_Cap;
use PHPUnit\Framework\TestCase;

final class RateCapTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		Rate_Cap::clear_warned();
		update_option( 'admin_email', 'admin@example.com' );
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);
			return true;
		};
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		Rate_Cap::clear_warned();
		parent::tearDown();
	}

	public function test_sanitize_cap_empty_is_unlimited(): void {
		$this->assertNull( Rate_Cap::sanitize_cap( '' ) );
		$this->assertNull( Rate_Cap::sanitize_cap( 0 ) );
		$this->assertNull( Rate_Cap::sanitize_cap( -1 ) );
		$this->assertSame( 10, Rate_Cap::sanitize_cap( 10 ) );
		$this->assertSame( Rate_Cap::MAX_CAP, Rate_Cap::sanitize_cap( Rate_Cap::MAX_CAP + 5 ) );
	}

	public function test_unset_caps_are_noop(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$now    = ( new \DateTimeImmutable( '2026-09-22 10:30:00', $tz ) )->getTimestamp();
		$log    = $this->seed_calls( $plugin, $now, 50 );

		$eval = Rate_Cap::evaluate( array( 'default' => 'allow' ), $plugin, $log, $now, $tz );
		$this->assertFalse( $eval['prevent'] );
		$this->assertFalse( $eval['soft_warn'] );
		$this->assertNull( $eval['hour']['limit'] );
		$this->assertNull( $eval['day']['limit'] );
	}

	public function test_hard_deny_at_hour_cap(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$now    = ( new \DateTimeImmutable( '2026-09-22 10:30:00', $tz ) )->getTimestamp();
		$log    = $this->seed_calls( $plugin, $now, 5 );

		$policy = array(
			'default'               => 'allow',
			'plugins'               => array( $plugin => 'allow' ),
			'plugin_rate_caps_hour' => array( $plugin => 5 ),
			'log_enabled'           => true,
		);

		$eval = Rate_Cap::evaluate( $policy, $plugin, $log, $now, $tz );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( Rate_Cap::REASON, $eval['reason'] );
		$this->assertSame( Rate_Cap::WINDOW_HOUR, $eval['window'] );
		$this->assertSame( 5, $eval['count'] );
	}

	public function test_soft_warn_once_per_window_at_eighty_percent(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$now    = ( new \DateTimeImmutable( '2026-09-22 10:30:00', $tz ) )->getTimestamp();
		$log    = $this->seed_calls( $plugin, $now, 8 );

		$policy = array(
			'default'               => 'allow',
			'plugin_rate_caps_hour' => array( $plugin => 10 ),
			'log_enabled'           => true,
			'alert_on_deny'         => true,
			'alert_email'           => 'ops@example.com',
		);
		Policy::save_policy( $policy );

		$event = array(
			'ts'       => $now,
			'plugin'   => $plugin,
			'decision' => 'allow',
			'provider' => 'openai',
		);
		$rc = Rate_Cap::apply_to_event( $event, $policy, $log, $now );
		$this->assertFalse( $rc['prevent'] );
		$this->assertTrue( $rc['soft_warn'] );
		$this->assertTrue( ! empty( $event['rate_warn'] ) );
		$this->assertCount( 1, self::$mails );

		// Second call in same window must not re-fire.
		$rc2 = Rate_Cap::apply_to_event( $event, $policy, $log, $now );
		$this->assertFalse( $rc2['soft_warn'] );
		$this->assertCount( 1, self::$mails );

		$stored = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $stored );
		$warn_rows = array_filter(
			$stored,
			static function ( $row ): bool {
				return is_array( $row ) && Rate_Cap::CHANNEL_WARN === ( $row['channel'] ?? '' );
			}
		);
		$this->assertCount( 1, $warn_rows );
	}

	public function test_window_rollover_hour_and_day(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'America/New_York' );
		$hour_a = ( new \DateTimeImmutable( '2026-09-22 10:50:00', $tz ) )->getTimestamp();
		$hour_b = ( new \DateTimeImmutable( '2026-09-22 11:05:00', $tz ) )->getTimestamp();
		$day_b  = ( new \DateTimeImmutable( '2026-09-23 00:05:00', $tz ) )->getTimestamp();

		$log = array(
			array(
				'ts'       => $hour_a,
				'plugin'   => $plugin,
				'decision' => 'allow',
			),
			array(
				'ts'       => $hour_a + 10,
				'plugin'   => $plugin,
				'decision' => 'allow',
			),
		);

		$hour_policy = array(
			'plugin_rate_caps_hour' => array( $plugin => 2 ),
		);
		$capped = Rate_Cap::evaluate( $hour_policy, $plugin, $log, $hour_a + 20, $tz );
		$this->assertTrue( $capped['prevent'] );

		$rolled_hour = Rate_Cap::evaluate( $hour_policy, $plugin, $log, $hour_b, $tz );
		$this->assertFalse( $rolled_hour['prevent'] );
		$this->assertSame( 0, $rolled_hour['hour']['count'] );

		$day_policy = array(
			'plugin_rate_caps_day' => array( $plugin => 2 ),
		);
		$day_capped = Rate_Cap::evaluate( $day_policy, $plugin, $log, $hour_b, $tz );
		$this->assertTrue( $day_capped['prevent'] );
		$this->assertSame( 2, $day_capped['day']['count'] );

		// Day rollover clears day count.
		$rolled_day = Rate_Cap::evaluate( $day_policy, $plugin, $log, $day_b, $tz );
		$this->assertFalse( $rolled_day['prevent'] );
		$this->assertSame( 0, $rolled_day['day']['count'] );
	}

	public function test_rate_cap_denials_do_not_inflate_count(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$now    = ( new \DateTimeImmutable( '2026-09-22 10:30:00', $tz ) )->getTimestamp();
		$log    = $this->seed_calls( $plugin, $now, 3 );
		$log[]  = array(
			'ts'            => $now + 3,
			'plugin'        => $plugin,
			'decision'      => 'deny',
			'denial_reason' => Rate_Cap::REASON,
		);
		$log[]  = array(
			'ts'       => $now + 4,
			'plugin'   => $plugin,
			'decision' => Rate_Cap::CHANNEL_WARN,
			'channel'  => Rate_Cap::CHANNEL_WARN,
		);

		$policy = array( 'plugin_rate_caps_hour' => array( $plugin => 5 ) );
		$eval   = Rate_Cap::evaluate( $policy, $plugin, $log, $now + 5, $tz );
		$this->assertSame( 3, $eval['hour']['count'] );
		$this->assertFalse( $eval['prevent'] );
	}

	public function test_apply_to_event_sets_denial_fields_on_prevent(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$now    = ( new \DateTimeImmutable( '2026-09-22 10:30:00', $tz ) )->getTimestamp();
		$log    = $this->seed_calls( $plugin, $now, 2 );
		$policy = array( 'plugin_rate_caps_hour' => array( $plugin => 2 ) );

		$event = array(
			'ts'       => $now,
			'plugin'   => $plugin,
			'decision' => 'allow',
		);
		$rc = Rate_Cap::apply_to_event( $event, $policy, $log, $now );
		$this->assertTrue( $rc['prevent'] );
		$this->assertSame( Rate_Cap::REASON, $rc['reason'] );
		$this->assertTrue( ! empty( $event['rate_capped'] ) );
	}

	public function test_policy_wire_after_residency_in_source(): void {
		$path = HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy.php';
		$body = (string) file_get_contents( $path );
		$res  = strpos( $body, 'Residency::apply_to_event' );
		$rate = strpos( $body, 'Rate_Cap::apply_to_event' );
		$pii  = strpos( $body, 'Pii_Warn::apply_to_event' );
		$this->assertNotFalse( $res );
		$this->assertNotFalse( $rate );
		$this->assertNotFalse( $pii );
		$this->assertGreaterThan( $res, $rate );
		$this->assertGreaterThan( $rate, $pii );
	}

	public function test_soft_warn_threshold(): void {
		$this->assertSame( 8, Rate_Cap::soft_warn_threshold( 10 ) );
		$this->assertSame( 1, Rate_Cap::soft_warn_threshold( 1 ) );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private function seed_calls( string $plugin, int $base_ts, int $n ): array {
		$log = array();
		for ( $i = 0; $i < $n; $i++ ) {
			$log[] = array(
				'ts'       => $base_ts + $i,
				'plugin'   => $plugin,
				'decision' => 'allow',
				'provider' => 'openai',
				'operation'=> 'generate_text',
			);
		}

		return $log;
	}
}
