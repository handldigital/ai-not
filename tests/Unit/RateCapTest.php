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
		Rate_Cap::clear_counts();
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
		Rate_Cap::clear_counts();
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
		$bounds = Rate_Cap::window_bounds( Rate_Cap::WINDOW_HOUR, $now, $tz );
		Rate_Cap::set_window_count( $plugin, Rate_Cap::WINDOW_HOUR, $bounds['key'], 50 );

		$eval = Rate_Cap::evaluate( array( 'default' => 'allow' ), $plugin, null, $now, $tz );
		$this->assertFalse( $eval['prevent'] );
		$this->assertFalse( $eval['soft_warn'] );
		$this->assertNull( $eval['hour']['limit'] );
		$this->assertNull( $eval['day']['limit'] );
	}

	public function test_hard_deny_at_hour_cap(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$now    = ( new \DateTimeImmutable( '2026-09-22 10:30:00', $tz ) )->getTimestamp();
		$bounds = Rate_Cap::window_bounds( Rate_Cap::WINDOW_HOUR, $now, $tz );
		Rate_Cap::set_window_count( $plugin, Rate_Cap::WINDOW_HOUR, $bounds['key'], 5 );

		$policy = array(
			'default'               => 'allow',
			'plugins'               => array( $plugin => 'allow' ),
			'plugin_rate_caps_hour' => array( $plugin => 5 ),
			'log_enabled'           => true,
		);

		$eval = Rate_Cap::evaluate( $policy, $plugin, null, $now, $tz );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( Rate_Cap::REASON, $eval['reason'] );
		$this->assertSame( Rate_Cap::WINDOW_HOUR, $eval['window'] );
		$this->assertSame( 5, $eval['count'] );
	}

	public function test_durable_counter_works_when_activity_log_is_off(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$now    = ( new \DateTimeImmutable( '2026-09-22 10:30:00', $tz ) )->getTimestamp();

		$policy = array(
			'default'               => 'allow',
			'plugin_rate_caps_hour' => array( $plugin => 2 ),
			'log_enabled'           => false,
			'audit_only'            => false,
		);

		$event = array(
			'ts'       => $now,
			'plugin'   => $plugin,
			'decision' => 'allow',
		);
		$rc1 = Rate_Cap::apply_to_event( $event, $policy, null, $now );
		$this->assertFalse( $rc1['prevent'] );
		$rc2 = Rate_Cap::apply_to_event( $event, $policy, null, $now );
		$this->assertFalse( $rc2['prevent'] );
		$rc3 = Rate_Cap::apply_to_event( $event, $policy, null, $now );
		$this->assertTrue( $rc3['prevent'] );
		$this->assertSame( Rate_Cap::REASON, $rc3['reason'] );
		$this->assertSame( array(), get_option( Plugin::LOG_OPTION_KEY, array() ) );
	}

	public function test_soft_warn_once_per_window_at_eighty_percent(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$now    = ( new \DateTimeImmutable( '2026-09-22 10:30:00', $tz ) )->getTimestamp();
		$bounds = Rate_Cap::window_bounds( Rate_Cap::WINDOW_HOUR, $now, $tz );
		// Soft threshold for 10 is 8; seed 7 so the next allowed call crosses 80%.
		Rate_Cap::set_window_count( $plugin, Rate_Cap::WINDOW_HOUR, $bounds['key'], 7 );

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
		$rc = Rate_Cap::apply_to_event( $event, $policy, null, $now );
		$this->assertFalse( $rc['prevent'] );
		$this->assertTrue( $rc['soft_warn'] );
		$this->assertTrue( ! empty( $event['rate_warn'] ) );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'AI call limit warning', self::$mails[0]['message'] );
		$this->assertStringContainsString( 'Usage: 8 of 10 calls', self::$mails[0]['message'] );
		$this->assertStringNotContainsString( '80%', self::$mails[0]['message'] );

		$rc2 = Rate_Cap::apply_to_event( $event, $policy, null, $now );
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

	public function test_observe_mode_email_footer_does_not_promise_block(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$now    = ( new \DateTimeImmutable( '2026-09-22 10:30:00', $tz ) )->getTimestamp();
		$bounds = Rate_Cap::window_bounds( Rate_Cap::WINDOW_HOUR, $now, $tz );
		Rate_Cap::set_window_count( $plugin, Rate_Cap::WINDOW_HOUR, $bounds['key'], 7 );

		$policy = array(
			'default'               => 'allow',
			'plugin_rate_caps_hour' => array( $plugin => 10 ),
			'log_enabled'           => true,
			'audit_only'            => true,
			'alert_on_deny'         => true,
			'alert_email'           => 'ops@example.com',
		);
		Policy::save_policy( $policy );

		$event = array(
			'ts'     => $now,
			'plugin' => $plugin,
		);
		Rate_Cap::apply_to_event( $event, $policy, null, $now );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'Observe mode is on. Calls will continue even if the cap is reached.', self::$mails[0]['message'] );
		$this->assertStringNotContainsString( 'New calls will be blocked', self::$mails[0]['message'] );
	}

	public function test_window_rollover_hour_and_day(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'America/New_York' );
		$hour_a = ( new \DateTimeImmutable( '2026-09-22 10:50:00', $tz ) )->getTimestamp();
		$hour_b = ( new \DateTimeImmutable( '2026-09-22 11:05:00', $tz ) )->getTimestamp();
		$day_b  = ( new \DateTimeImmutable( '2026-09-23 00:05:00', $tz ) )->getTimestamp();

		$hour_key_a = Rate_Cap::window_bounds( Rate_Cap::WINDOW_HOUR, $hour_a, $tz )['key'];
		$day_key_a  = Rate_Cap::window_bounds( Rate_Cap::WINDOW_DAY, $hour_a, $tz )['key'];
		Rate_Cap::set_window_count( $plugin, Rate_Cap::WINDOW_HOUR, $hour_key_a, 2 );
		Rate_Cap::set_window_count( $plugin, Rate_Cap::WINDOW_DAY, $day_key_a, 2 );

		$hour_policy = array(
			'plugin_rate_caps_hour' => array( $plugin => 2 ),
		);
		$capped = Rate_Cap::evaluate( $hour_policy, $plugin, null, $hour_a + 20, $tz );
		$this->assertTrue( $capped['prevent'] );

		$rolled_hour = Rate_Cap::evaluate( $hour_policy, $plugin, null, $hour_b, $tz );
		$this->assertFalse( $rolled_hour['prevent'] );
		$this->assertSame( 0, $rolled_hour['hour']['count'] );

		$day_policy = array(
			'plugin_rate_caps_day' => array( $plugin => 2 ),
		);
		$day_capped = Rate_Cap::evaluate( $day_policy, $plugin, null, $hour_b, $tz );
		$this->assertTrue( $day_capped['prevent'] );
		$this->assertSame( 2, $day_capped['day']['count'] );

		$rolled_day = Rate_Cap::evaluate( $day_policy, $plugin, null, $day_b, $tz );
		$this->assertFalse( $rolled_day['prevent'] );
		$this->assertSame( 0, $rolled_day['day']['count'] );
	}

	public function test_admin_and_rate_cap_rows_excluded_from_log_reconstruction(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$now    = ( new \DateTimeImmutable( '2026-09-22 10:30:00', $tz ) )->getTimestamp();
		$log    = array(
			array(
				'ts'       => $now,
				'plugin'   => $plugin,
				'decision' => 'allow',
			),
			array(
				'ts'       => $now + 1,
				'plugin'   => $plugin,
				'decision' => 'allow',
				'channel'  => 'access_request',
			),
			array(
				'ts'            => $now + 2,
				'plugin'        => $plugin,
				'decision'      => 'deny',
				'denial_reason' => Rate_Cap::REASON,
				'count'         => 4,
			),
			array(
				'ts'       => $now + 3,
				'plugin'   => $plugin,
				'decision' => 'deny',
				'count'    => 3,
			),
		);

		$n = Rate_Cap::count_plugin_calls_in_window( $log, $plugin, $now, $now + 10 );
		$this->assertSame( 4, $n ); // 1 allow + 3 grouped deny; admin + rate_cap sticky excluded.
	}

	public function test_profile_counts_only_actual_denied_blocks(): void {
		$plugin = 'acme/acme.php';
		$log    = array(
			array(
				'ts'       => 1,
				'plugin'   => $plugin,
				'channel'  => Rate_Cap::CHANNEL_WARN,
				'decision' => Rate_Cap::CHANNEL_WARN,
				'count'    => 2,
			),
			array(
				'ts'            => 2,
				'plugin'        => $plugin,
				'decision'      => 'allow',
				'denial_reason' => Rate_Cap::REASON, // Observe tag — not an actual block.
			),
			array(
				'ts'            => 3,
				'plugin'        => $plugin,
				'decision'      => 'deny',
				'denial_reason' => Rate_Cap::REASON,
				'count'         => 5,
			),
		);

		$profile = Rate_Cap::profile_counts( array(), $plugin, $log );
		$this->assertSame( 2, $profile['warn_count'] );
		$this->assertSame( 5, $profile['capped_count'] );
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

	public function test_observe_mode_keeps_counting_past_cap(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$now    = ( new \DateTimeImmutable( '2026-09-22 10:30:00', $tz ) )->getTimestamp();

		$policy = array(
			'default'               => 'allow',
			'plugin_rate_caps_hour' => array( $plugin => 2 ),
			'plugin_rate_caps_day'  => array( $plugin => 10 ),
			'audit_only'            => true,
			'log_enabled'           => true,
		);

		$event = array(
			'ts'       => $now,
			'plugin'   => $plugin,
			'decision' => 'allow',
		);

		// Three Observe calls with hour=2: all continue, counters keep rising.
		$rc1 = Rate_Cap::apply_to_event( $event, $policy, null, $now );
		$this->assertFalse( $rc1['prevent'] );
		$rc2 = Rate_Cap::apply_to_event( $event, $policy, null, $now );
		$this->assertFalse( $rc2['prevent'] );
		$rc3 = Rate_Cap::apply_to_event( $event, $policy, null, $now );
		$this->assertTrue( $rc3['prevent'] ); // would-deny tag
		$this->assertSame( 3, (int) $event['rate_cap_hour_count'] );
		$this->assertSame( 3, (int) $event['rate_cap_day_count'] );

		$eval = Rate_Cap::evaluate( $policy, $plugin, null, $now, $tz );
		$this->assertSame( 3, $eval['hour']['count'] );
		$this->assertSame( 3, $eval['day']['count'] );
	}

	public function test_enforcing_mode_does_not_count_blocked_calls(): void {
		$plugin = 'acme/acme.php';
		$tz     = new \DateTimeZone( 'UTC' );
		$now    = ( new \DateTimeImmutable( '2026-09-22 10:30:00', $tz ) )->getTimestamp();

		$policy = array(
			'default'               => 'allow',
			'plugin_rate_caps_hour' => array( $plugin => 2 ),
			'audit_only'            => false,
		);

		$event = array(
			'ts'     => $now,
			'plugin' => $plugin,
		);
		Rate_Cap::apply_to_event( $event, $policy, null, $now );
		Rate_Cap::apply_to_event( $event, $policy, null, $now );
		$rc3 = Rate_Cap::apply_to_event( $event, $policy, null, $now );
		$this->assertTrue( $rc3['prevent'] );

		$eval = Rate_Cap::evaluate( $policy, $plugin, null, $now, $tz );
		$this->assertSame( 2, $eval['hour']['count'] );
	}

	public function test_soft_warn_threshold(): void {
		$this->assertSame( 8, Rate_Cap::soft_warn_threshold( 10 ) );
		$this->assertSame( 1, Rate_Cap::soft_warn_threshold( 1 ) );
	}
}
