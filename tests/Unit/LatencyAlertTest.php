<?php
/**
 * Unit tests for AICAC-LATENCY (#302).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Clock;
use HandL\AICAC\Latency;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class LatencyAlertTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		Latency::reset_pending_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Latency::SAMPLES_OPTION_KEY );
		delete_option( Latency::FIRED_OPTION_KEY );
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
		Latency::reset_pending_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Latency::SAMPLES_OPTION_KEY );
		delete_option( Latency::FIRED_OPTION_KEY );
		parent::tearDown();
	}

	public function test_percentile_p50_and_p95(): void {
		$ms = array( 100, 200, 300, 400, 500, 600, 700, 800, 900, 10000 );
		$this->assertSame( 500, Latency::percentile_ms( $ms, 50 ) );
		$this->assertSame( 10000, Latency::percentile_ms( $ms, 95 ) );
	}

	public function test_untimed_calls_skipped_in_stats(): void {
		$now = 1_700_000_000;
		// Only explicit samples count — log rows without duration are ignored.
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => $now,
					'provider' => 'openai',
					'decision' => 'allow',
					// no duration_ms
				),
			),
			false
		);

		$this->assertSame( array(), Latency::provider_stats( $now ) );
	}

	public function test_record_sample_builds_provider_stats(): void {
		$now = 1_700_000_000;
		Latency::record_sample( 'openai', 100, $now );
		Latency::record_sample( 'openai', 200, $now + 1 );
		Latency::record_sample( 'openai', 12000, $now + 2 );
		Latency::record_sample( 'Anthropic!', 50, $now + 3 );

		$stats = Latency::provider_stats( $now + 10 );
		$this->assertCount( 2, $stats );
		$this->assertSame( 'anthropic', $stats[0]['provider'] );
		$this->assertSame( 1, $stats[0]['count'] );
		$this->assertSame( 'openai', $stats[1]['provider'] );
		$this->assertSame( 3, $stats[1]['count'] );
		$this->assertSame( 200, $stats[1]['p50'] );
		$this->assertSame( 12000, $stats[1]['p95'] );
	}

	public function test_old_samples_outside_window_drop_out(): void {
		$now = 1_700_000_000;
		Latency::record_sample( 'openai', 99999, $now - Latency::WINDOW_SECONDS - 10 );
		Latency::record_sample( 'openai', 100, $now );
		$stats = Latency::provider_stats( $now );
		$this->assertCount( 1, $stats );
		$this->assertSame( 1, $stats[0]['count'] );
		$this->assertSame( 100, $stats[0]['p95'] );
	}

	public function test_p95_breach_fires_once_per_window(): void {
		$now = 1_700_000_000;
		for ( $i = 0; $i < 5; $i++ ) {
			Latency::record_sample( 'openai', 15000, $now + $i );
		}

		$policy = array(
			'log_enabled'                => true,
			'latency_alert_enabled'      => true,
			'latency_p95_threshold_ms'   => 10000,
			'latency_min_samples'        => 5,
			'alert_email'                => 'admin@example.com',
		);
		update_option( Plugin::OPTION_KEY, $policy, false );

		Latency::maybe_evaluate( Policy::get_policy(), $now + 10 );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'slow ai', strtolower( self::$mails[0]['subject'] ) );
		$this->assertStringContainsString( 'openai', self::$mails[0]['message'] );

		Latency::maybe_evaluate( Policy::get_policy(), $now + 20 );
		$this->assertCount( 1, self::$mails, 'dedupe: one alert per provider per window' );
	}

	public function test_below_min_samples_never_fires(): void {
		$now = 1_700_000_000;
		Latency::record_sample( 'openai', 50000, $now );
		Latency::record_sample( 'openai', 50000, $now + 1 );

		Latency::maybe_evaluate(
			array(
				'log_enabled'              => true,
				'latency_alert_enabled'    => true,
				'latency_p95_threshold_ms' => 10000,
				'latency_min_samples'      => 5,
				'alert_email'              => 'admin@example.com',
			),
			$now + 5
		);
		$this->assertSame( array(), self::$mails );
	}

	public function test_disabled_never_fires(): void {
		$now = 1_700_000_000;
		for ( $i = 0; $i < 5; $i++ ) {
			Latency::record_sample( 'openai', 20000, $now + $i );
		}
		Latency::maybe_evaluate(
			array(
				'log_enabled'           => true,
				'latency_alert_enabled' => false,
				'alert_email'           => 'admin@example.com',
			),
			$now + 5
		);
		$this->assertSame( array(), self::$mails );
	}

	public function test_duration_patch_on_log_row(): void {
		$log_key = 'aicac_test_latency_1';
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => Clock::now(),
					'log_key'  => $log_key,
					'provider' => 'openai',
					'decision' => 'allow',
				),
			),
			false
		);
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
			),
			false
		);

		Latency::mark_start( $log_key );
		usleep( 2000 );
		Latency::instance()->maybe_record_duration( (object) array() );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertArrayHasKey( 'duration_ms', $log[0] );
		$this->assertGreaterThanOrEqual( 1, (int) $log[0]['duration_ms'] );

		$stats = Latency::provider_stats();
		$this->assertNotEmpty( $stats );
		$this->assertSame( 'openai', $stats[0]['provider'] );
	}

	public function test_cli_empty_state_message_constant(): void {
		$this->assertSame(
			'No timed calls yet.',
			__( 'No timed calls yet.', 'handl-ai-connector-access-control' )
		);
		$this->assertSame( array(), Latency::provider_stats( 1_700_000_000 ) );
	}
}
