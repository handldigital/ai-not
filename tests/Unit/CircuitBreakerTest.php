<?php
/**
 * AICAC-CIRCUIT-BREAKER (#361).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Circuit_Breaker;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class CircuitBreakerTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_user_id'] = 12;
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);
			return true;
		};
		Circuit_Breaker::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'admin@example.com',
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
		update_option( 'admin_email', 'admin@example.com' );
		Circuit_Breaker::save_settings(
			array(
				'enabled'           => true,
				'failure_threshold' => 3,
				'error_rate_pct'    => 0,
				'window_seconds'    => 300,
				'cooldown_seconds'  => 60,
				'use_latency_p95'   => false,
			)
		);
		$GLOBALS['handl_aicac_test_filters']['handl_aicac_circuit_breaker_provider'] = static function () {
			return 'openai';
		};
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_wp_mail'],
			$GLOBALS['handl_aicac_test_filters'],
			$GLOBALS['handl_aicac_test_current_user_can']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_user_id'] = 0;
		Circuit_Breaker::reset_for_tests();
		parent::tearDown();
	}

	public function test_disabled_never_trips_or_prevents(): void {
		Circuit_Breaker::save_settings( array_merge( Circuit_Breaker::get_settings(), array( 'enabled' => false ) ) );
		$now = 1_700_000_000;
		Circuit_Breaker::record_outcome( 'openai', false, false, $now );
		Circuit_Breaker::record_outcome( 'openai', false, false, $now + 1 );
		Circuit_Breaker::record_outcome( 'openai', false, false, $now + 2 );
		$this->assertSame( Circuit_Breaker::STATE_CLOSED, Circuit_Breaker::provider_state( 'openai', $now + 3 ) );
		$this->assertFalse( Circuit_Breaker::maybe_prevent_prompt( false, new \stdClass() ) );
	}

	public function test_consecutive_failures_trip_and_gate_denies(): void {
		$now = 1_700_000_000;
		Circuit_Breaker::record_outcome( 'openai', false, false, $now );
		Circuit_Breaker::record_outcome( 'openai', false, false, $now + 1 );
		Circuit_Breaker::record_outcome( 'openai', false, false, $now + 2 );

		$this->assertSame( Circuit_Breaker::STATE_OPEN, Circuit_Breaker::provider_state( 'openai', $now + 3 ) );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$trips = array_values(
			array_filter(
				$log,
				static function ( $row ) {
					return is_array( $row )
						&& ( $row['decision'] ?? '' ) === Circuit_Breaker::CHANNEL
						&& ( $row['circuit_action'] ?? '' ) === 'open';
				}
			)
		);
		$this->assertCount( 1, $trips );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'Circuit open', self::$mails[0]['subject'] );

		Policy::append_log_event(
			array(
				'ts'       => $now + 4,
				'decision' => 'allow',
				'provider' => 'openai',
				'user_id'  => 12,
			)
		);

		putenv( 'HANDL_AICAC_TEST_NOW=' . (string) ( $now + 4 ) );
		$prevent = Circuit_Breaker::maybe_prevent_prompt( false, new \stdClass() );
		putenv( 'HANDL_AICAC_TEST_NOW' );

		$this->assertTrue( $prevent );
		$log  = get_option( Plugin::LOG_OPTION_KEY, array() );
		$last = $log[ count( $log ) - 1 ];
		$this->assertSame( 'deny', $last['decision'] ?? '' );
		$this->assertStringContainsString( 'provider circuit open', (string) ( $last['denial_reason'] ?? '' ) );
		$this->assertSame( Circuit_Breaker::REASON, $last['decision_source'] ?? '' );
	}

	public function test_trip_alert_deduped_within_window(): void {
		$now = 1_700_000_000;
		Circuit_Breaker::trip( 'openai', 'manual', 1, $now );
		Circuit_Breaker::reset_provider( 'openai', 'manual', 1, $now + 1 );
		Circuit_Breaker::trip( 'openai', 'manual', 1, $now + 2 );
		$open_mails = array_values(
			array_filter(
				self::$mails,
				static function ( $m ) {
					return false !== strpos( $m['subject'], 'Circuit open' );
				}
			)
		);
		$this->assertCount( 1, $open_mails );
	}

	public function test_half_open_probe_success_closes(): void {
		$now = 1_700_000_000;
		Circuit_Breaker::save_settings(
			array_merge(
				Circuit_Breaker::get_settings(),
				array( 'cooldown_seconds' => 10 )
			)
		);
		Circuit_Breaker::trip( 'openai', 'auto', null, $now );
		// Advance past cooldown → half_open.
		$this->assertSame( Circuit_Breaker::STATE_HALF_OPEN, Circuit_Breaker::provider_state( 'openai', $now + 11 ) );

		putenv( 'HANDL_AICAC_TEST_NOW=' . (string) ( $now + 11 ) );
		$first = Circuit_Breaker::maybe_prevent_prompt( false, new \stdClass() );
		$this->assertFalse( $first ); // probe allowed
		$second = Circuit_Breaker::maybe_prevent_prompt( false, new \stdClass() );
		$this->assertTrue( $second ); // second denied while probe in flight
		putenv( 'HANDL_AICAC_TEST_NOW' );

		Circuit_Breaker::record_outcome( 'openai', true, true, $now + 12 );
		$this->assertSame( Circuit_Breaker::STATE_CLOSED, Circuit_Breaker::provider_state( 'openai', $now + 13 ) );

		$recover_mails = array_values(
			array_filter(
				self::$mails,
				static function ( $m ) {
					return false !== strpos( $m['subject'], 'Circuit closed' );
				}
			)
		);
		$this->assertCount( 1, $recover_mails );
	}

	public function test_half_open_probe_failure_reopens(): void {
		$now = 1_700_000_000;
		Circuit_Breaker::save_settings(
			array_merge(
				Circuit_Breaker::get_settings(),
				array( 'cooldown_seconds' => 5 )
			)
		);
		Circuit_Breaker::trip( 'openai', 'auto', null, $now );
		Circuit_Breaker::provider_state( 'openai', $now + 6 ); // half_open
		Circuit_Breaker::record_outcome( 'openai', false, true, $now + 7 );
		$this->assertSame( Circuit_Breaker::STATE_OPEN, Circuit_Breaker::provider_state( 'openai', $now + 8 ) );
	}

	public function test_manual_reset_closes(): void {
		$now = 1_700_000_000;
		Circuit_Breaker::trip( 'openai', 'admin', 1, $now );
		$this->assertTrue( Circuit_Breaker::reset_provider( 'openai', 'admin', 1, $now + 1 ) );
		$this->assertSame( Circuit_Breaker::STATE_CLOSED, Circuit_Breaker::provider_state( 'openai', $now + 2 ) );
	}

	public function test_prior_prevent_unchanged(): void {
		$this->assertTrue( Circuit_Breaker::maybe_prevent_prompt( true, new \stdClass() ) );
	}

	public function test_audit_only_skips_prevent(): void {
		$now = 1_700_000_000;
		Circuit_Breaker::trip( 'openai', 'manual', null, $now );
		Policy::save_policy(
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => true,
				'alert_email' => 'admin@example.com',
			)
		);
		$this->assertFalse( Circuit_Breaker::maybe_prevent_prompt( false, new \stdClass() ) );
	}

	public function test_settings_noop_when_present_absent(): void {
		$before = Circuit_Breaker::get_settings();
		$_POST  = array(); // no POST_PRESENT
		$policy = array( 'default' => 'allow' );
		$out    = Circuit_Breaker::capture_settings_on_policy_save( $policy, $policy );
		$this->assertSame( $policy, $out );
		$this->assertSame( $before, Circuit_Breaker::get_settings() );
		unset( $_POST );
	}

	public function test_settings_save_when_present(): void {
		$_POST = array(
			Circuit_Breaker::POST_PRESENT           => '1',
			Circuit_Breaker::POST_ENABLED           => '1',
			Circuit_Breaker::POST_FAILURE_THRESHOLD => '7',
			Circuit_Breaker::POST_ERROR_RATE        => '50',
			Circuit_Breaker::POST_WINDOW            => '120',
			Circuit_Breaker::POST_COOLDOWN          => '30',
		);
		Circuit_Breaker::capture_settings_on_policy_save( array(), array() );
		$s = Circuit_Breaker::get_settings();
		$this->assertTrue( $s['enabled'] );
		$this->assertSame( 7, $s['failure_threshold'] );
		$this->assertSame( 50, $s['error_rate_pct'] );
		$this->assertSame( 120, $s['window_seconds'] );
		$this->assertSame( 30, $s['cooldown_seconds'] );
		unset( $_POST );
	}

	public function test_save_settings_noop_when_identical(): void {
		$s = Circuit_Breaker::get_settings();
		$this->assertFalse( Circuit_Breaker::save_settings( $s ) );
	}

	public function test_init_idempotent(): void {
		Circuit_Breaker::init();
		Circuit_Breaker::init();
		$this->assertTrue( true );
	}

	public function test_status_rows_sorted(): void {
		$now = 1_700_000_000;
		Circuit_Breaker::trip( 'openai', 'manual', null, $now );
		Circuit_Breaker::trip( 'anthropic', 'manual', null, $now );
		$rows = Circuit_Breaker::status_rows( $now );
		$this->assertSame( 'anthropic', $rows[0]['provider'] );
		$this->assertSame( 'openai', $rows[1]['provider'] );
	}
}
