<?php
/**
 * AICAC-SPOT-CHECK (#381).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Spot_Check;
use PHPUnit\Framework\TestCase;

final class SpotCheckTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Spot_Check::reset_for_tests();
		Spot_Check::set_test_salt( 'unit-test-spot-check-salt' );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'haktan+aicac-spot-check@handldigital.com',
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_test_current_user_can'], $GLOBALS['handl_aicac_wp_mail'] );
		$GLOBALS['handl_aicac_test_options'] = array();
		Spot_Check::reset_for_tests();
		parent::tearDown();
	}

	public function test_defaults_are_off_and_save_defaults_deletes_option(): void {
		$this->assertFalse( Spot_Check::is_enabled() );
		$this->assertSame( Spot_Check::defaults(), Spot_Check::get_settings() );
		Spot_Check::save_settings(
			array(
				'enabled'      => true,
				'sample_rate'  => 0.05,
				'rows_per_day' => 10,
			)
		);
		$this->assertTrue( Spot_Check::is_enabled() );
		$this->assertSame( 0.05, Spot_Check::get_settings()['sample_rate'] );
		Spot_Check::save_settings( Spot_Check::defaults() );
		$this->assertFalse( (bool) get_option( Spot_Check::SETTINGS_OPTION, false ) );
	}

	public function test_sample_rate_accepts_percent_strings(): void {
		$this->assertSame( 0.01, Spot_Check::sanitize_sample_rate( '1%' ) );
		$this->assertSame( 0.05, Spot_Check::sanitize_sample_rate( 5 ) );
		$this->assertSame( 0.25, Spot_Check::sanitize_sample_rate( 0.25 ) );
		$this->assertSame( 1.0, Spot_Check::sanitize_sample_rate( 1.0 ) );
	}

	public function test_sampling_is_deterministic_and_idempotent(): void {
		Spot_Check::save_settings(
			array(
				'enabled'      => true,
				'sample_rate'  => 1.0,
				'rows_per_day' => 50,
			)
		);
		$now = 1_720_000_100;
		$log = array(
			array(
				'ts'       => $now,
				'plugin'   => 'alpha/alpha.php',
				'provider' => 'openai',
				'model'    => 'gpt-test',
				'decision' => 'allow',
				'operation'=> 'generate_text',
			),
			array(
				'ts'       => $now + 1,
				'plugin'   => 'beta/beta.php',
				'provider' => 'anthropic',
				'model'    => 'claude-test',
				'decision' => 'allow',
				'operation'=> 'generate_text',
			),
			array(
				'ts'       => $now,
				'plugin'   => 'alpha/alpha.php',
				'provider' => 'openai',
				'decision' => 'deny',
				'operation'=> 'generate_text',
			),
			array(
				'ts'       => $now,
				'plugin'   => 'gamma/gamma.php',
				'provider' => 'openai',
				'decision' => 'allow',
				'channel'  => 'direct_http',
			),
		);

		$first = Spot_Check::maybe_sample( $log, $now );
		$this->assertSame( 2, $first['candidates'] );
		$this->assertSame( 2, $first['added'] );
		$queue1 = Spot_Check::get_queue();
		$this->assertCount( 2, $queue1 );
		$ids1 = array_column( $queue1, 'id' );

		$second = Spot_Check::maybe_sample( $log, $now );
		$this->assertSame( 0, $second['added'] );
		$queue2 = Spot_Check::get_queue();
		$this->assertSame( $ids1, array_column( $queue2, 'id' ) );
	}

	public function test_rows_per_day_cap_keeps_lowest_scores(): void {
		Spot_Check::save_settings(
			array(
				'enabled'      => true,
				'sample_rate'  => 1.0,
				'rows_per_day' => 1,
			)
		);
		$now = 1_720_000_200;
		$log = array();
		for ( $i = 0; $i < 5; $i++ ) {
			$log[] = array(
				'ts'       => $now + $i,
				'plugin'   => 'p' . $i . '/p.php',
				'provider' => 'openai',
				'model'    => 'm' . $i,
				'decision' => 'allow',
				'operation'=> 'generate_text',
			);
		}
		$out = Spot_Check::maybe_sample( $log, $now );
		$this->assertSame( 1, $out['added'] );
		$queue = Spot_Check::get_queue();
		$this->assertCount( 1, $queue );
	}

	public function test_looks_right_verdict_does_not_alert_or_log_concern(): void {
		Spot_Check::save_settings( array( 'enabled' => true, 'sample_rate' => 1.0 ) );
		$now = 1_720_000_300;
		$log = array(
			array(
				'ts'       => $now,
				'plugin'   => 'alpha/alpha.php',
				'provider' => 'openai',
				'model'    => 'gpt-ok',
				'decision' => 'allow',
				'operation'=> 'generate_text',
			),
		);
		Spot_Check::maybe_sample( $log, $now );
		$id = (string) Spot_Check::get_queue()[0]['id'];
		$before = get_option( Plugin::LOG_OPTION_KEY, array() );
		$result = Spot_Check::record_verdict( $id, Spot_Check::VERDICT_LOOKS_RIGHT, 'fine', 7, $now + 10 );
		$this->assertTrue( $result['ok'] );
		$this->assertSame( array(), Spot_Check::test_mails() );
		$after = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertSame( count( $before ), count( $after ) );
		$row = Spot_Check::get_queue()[0];
		$this->assertSame( Spot_Check::VERDICT_LOOKS_RIGHT, $row['verdict'] );
		$this->assertSame( 7, (int) $row['reviewer_id'] );
	}

	public function test_concern_appends_log_and_alerts_once_per_fingerprint(): void {
		Spot_Check::save_settings( array( 'enabled' => true, 'sample_rate' => 1.0 ) );
		$GLOBALS['handl_aicac_wp_mail'] = static function () {
			return true;
		};
		$now = 1_720_000_400;
		$log = array(
			array(
				'ts'       => $now,
				'plugin'   => 'alpha/alpha.php',
				'provider' => 'openai',
				'model'    => 'gpt-bad',
				'decision' => 'allow',
				'operation'=> 'generate_text',
				'pii_match'=> array( 'types' => array( 'email' => 1 ), 'mode' => 'warn' ),
			),
		);
		Spot_Check::maybe_sample( $log, $now );
		$id = (string) Spot_Check::get_queue()[0]['id'];

		$first = Spot_Check::record_verdict( $id, Spot_Check::VERDICT_CONCERN, 'odd payload', 9, $now + 5 );
		$this->assertTrue( $first['ok'] );
		$this->assertCount( 1, Spot_Check::test_mails() );

		$stored = get_option( Plugin::LOG_OPTION_KEY, array() );
		$found  = false;
		foreach ( $stored as $row ) {
			if ( is_array( $row ) && isset( $row['spot_check'] ) && 'concern' === $row['spot_check'] ) {
				$found = true;
				$this->assertSame( 'spot_check', $row['channel'] );
			}
		}
		$this->assertTrue( $found );

		// Re-emit concern path should not double-alert.
		Spot_Check::emit_concern( Spot_Check::get_queue()[0], $now + 6 );
		$this->assertCount( 1, Spot_Check::test_mails() );

		$second = Spot_Check::record_verdict( $id, Spot_Check::VERDICT_CONCERN, 'again', 9, $now + 7 );
		$this->assertFalse( $second['ok'] );
		$this->assertSame( 'already_reviewed', $second['error'] );
	}

	public function test_coverage_ledger_and_csv_print(): void {
		Spot_Check::save_settings( array( 'enabled' => true, 'sample_rate' => 1.0 ) );
		$now = 1_720_000_500;
		$log = array(
			array(
				'ts'       => $now,
				'plugin'   => 'alpha/alpha.php',
				'provider' => 'openai',
				'model'    => 'gpt-a',
				'decision' => 'allow',
				'operation'=> 'generate_text',
			),
			array(
				'ts'       => $now + 1,
				'plugin'   => 'beta/beta.php',
				'provider' => 'anthropic',
				'model'    => 'claude-a',
				'decision' => 'allow',
				'operation'=> 'generate_text',
			),
		);
		Spot_Check::maybe_sample( $log, $now );
		$queue = Spot_Check::get_queue();
		Spot_Check::record_verdict( (string) $queue[0]['id'], Spot_Check::VERDICT_LOOKS_RIGHT, '', 1, $now + 30 );
		$ledger = Spot_Check::coverage_ledger( $log, Spot_Check::get_queue(), $now );
		$this->assertSame( 2, $ledger['sampled'] );
		$this->assertSame( 1, $ledger['reviewed'] );
		$this->assertSame( 1, $ledger['pending'] );
		$this->assertSame( 1, $ledger['looks_right'] );
		$this->assertNotNull( $ledger['reviewed_pct'] );

		$csv = Spot_Check::csv_for_queue();
		$this->assertStringContainsString( 'plugin', $csv );
		$this->assertStringContainsString( 'alpha/alpha.php', $csv );

		$html = Spot_Check::build_print_html( $ledger, Spot_Check::get_queue() );
		$this->assertStringContainsString( 'Spot-check coverage ledger', $html );
		$this->assertStringContainsString( 'alpha/alpha.php', $html );
	}

	public function test_stale_pending_and_no_gate_filter(): void {
		Spot_Check::save_settings( array( 'enabled' => true, 'sample_rate' => 1.0 ) );
		$now = 1_720_000_600;
		$log = array(
			array(
				'ts'       => $now,
				'plugin'   => 'alpha/alpha.php',
				'provider' => 'openai',
				'decision' => 'allow',
				'operation'=> 'generate_text',
			),
		);
		Spot_Check::maybe_sample( $log, $now );
		$stale = Spot_Check::stale_pending( null, $now + ( Spot_Check::STALE_AFTER_DAYS * DAY_IN_SECONDS ) + 10 );
		$this->assertCount( 1, $stale );

		Spot_Check::reset_for_tests();
		Spot_Check::init();
		global $wp_filter;
		$hooks = $wp_filter['wp_ai_client_prevent_prompt'] ?? null;
		if ( is_array( $hooks ) ) {
			foreach ( $hooks as $callbacks ) {
				foreach ( (array) $callbacks as $cb ) {
					$fn = $cb['function'] ?? null;
					if ( is_array( $fn ) && ( $fn[0] ?? null ) === Spot_Check::class ) {
						$this->fail( 'Spot_Check must stay read-only against the gate' );
					}
				}
			}
		}
		$this->assertTrue( true );
	}
}
