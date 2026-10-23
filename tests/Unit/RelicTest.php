<?php
/**
 * AICAC-RELIC (#431).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\CLI_Relic;
use HandL\AICAC\Plugin;
use HandL\AICAC\Relic;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class RelicTest extends TestCase {

	/** 2026-10-23 12:00:00 UTC — after gpt-4-0314 (2024-06-06), before gpt-4-turbo (2025-12-17) is wrong;
	 *  use a fixed "now" inside the AGING window for turbo and past for 0314. */
	private const NOW = 1761220800; // 2025-10-23 12:00:00 UTC.

	/** @var array<int,true> */
	private static $seed_ids = array();

	/** @var array<int,list<array<string,mixed>>> */
	private static $seed_hist = array();

	protected function setUp(): void {
		parent::setUp();
		self::$seed_ids  = array();
		self::$seed_hist = array();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$GLOBALS['handl_aicac_test_post_meta']        = array();
		Relic::reset_for_tests();
		Relic::set_test_now( self::NOW );
		update_option( 'admin_email', 'haktan+aicac-relic@handldigital.com' );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
				'log_limit'   => 200,
				'default'     => 'observe',
				'alert_email' => 'haktan+aicac-relic@handldigital.com',
			),
			false
		);
		Relic::set_test_calendar(
			array(
				array(
					'provider'    => 'openai',
					'model'       => 'gpt-4-0314',
					'eol'         => '2024-06-06',
					'replacement' => 'gpt-4o',
					'source'      => 'test',
				),
				array(
					'provider'    => 'openai',
					'model'       => 'gpt-4-turbo',
					'eol'         => '2025-12-17',
					'replacement' => 'gpt-4o',
					'source'      => 'test',
				),
				array(
					'provider'    => 'openai',
					'model'       => 'gpt-4o',
					'eol'         => '2027-01-01',
					'replacement' => '',
					'source'      => 'test',
				),
			)
		);
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_post_meta']     = array();
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		Relic::reset_for_tests();
		parent::tearDown();
	}

	private function enable(): void {
		Relic::save_settings( array( 'enabled' => true ) );
	}

	/**
	 * @param list<array{provider:string,model:string,ts?:int}> $touches
	 */
	private function seed_post( int $post_id, array $touches ): void {
		$history = array();
		foreach ( $touches as $t ) {
			$history[] = array(
				'ts'         => (int) ( $t['ts'] ?? self::NOW - 100 ),
				'provider'   => (string) $t['provider'],
				'model'      => (string) $t['model'],
				'capability' => 'text',
				'user_id'    => 1,
				'outcome'    => 'success',
			);
		}
		self::$seed_ids[ $post_id ]  = true;
		self::$seed_hist[ $post_id ] = $history;
		Relic::set_test_post_ids( array_map( 'intval', array_keys( self::$seed_ids ) ) );
		Relic::set_test_histories( self::$seed_hist );
	}

	public function test_defaults_off_and_disabled_skips_ledger(): void {
		$this->assertFalse( Relic::is_enabled() );
		$this->assertSame( array( 'enabled' => false ), Relic::defaults() );
		$this->assertSame( 'handl_aicac_relic', Relic::SETTINGS_OPTION );
		$this->assertSame( 'handl_aicac_relic_state', Relic::STATE_OPTION );

		// Seed data that would otherwise produce findings — disabled must ignore it.
		$this->seed_post(
			42,
			array(
				array(
					'provider' => 'openai',
					'model'    => 'gpt-4-0314',
				),
			)
		);

		$snap = Relic::snapshot( self::NOW );
		$this->assertFalse( $snap['enabled'] );
		$this->assertSame( array(), $snap['findings'] );
		$this->assertFalse( Relic::maybe_check( self::NOW, true ) );
		$this->assertFalse( (bool) get_option( Relic::STATE_OPTION, false ) );

		$this->assertTrue( Relic::save_settings( array( 'enabled' => true ) ) );
		$this->assertTrue( Relic::is_enabled() );
		$before = get_option( Relic::SETTINGS_OPTION );
		$this->assertFalse( Relic::save_settings( array( 'enabled' => true ) ) );
		$this->assertSame( $before, get_option( Relic::SETTINGS_OPTION ) );

		$this->assertTrue( Relic::save_settings( Relic::defaults() ) );
		$this->assertFalse( (bool) get_option( Relic::SETTINGS_OPTION, false ) );
	}

	public function test_retired_model_fixture_produces_relic_with_date(): void {
		$this->enable();
		$this->seed_post(
			42,
			array(
				array(
					'provider' => 'openai',
					'model'    => 'gpt-4-0314',
				),
			)
		);

		$snap = Relic::snapshot( self::NOW );
		$this->assertSame( 1, $snap['relic_count'] );
		$this->assertSame( 0, $snap['aging_count'] );
		$this->assertSame( 1, $snap['unacked_relic'] );
		$row = $snap['findings'][0];
		$this->assertSame( Relic::VERDICT_RELIC, $row['verdict'] );
		$this->assertSame( '2024-06-06', $row['eol'] );
		$this->assertSame( 'gpt-4-0314', $row['model'] );
		$this->assertStringContainsString( '2024-06-06', $row['summary'] );
		$this->assertStringContainsString( 'RELIC', $row['summary'] );
		$this->assertStringContainsString( '#42', $row['summary'] );
	}

	public function test_aging_within_90_days(): void {
		$this->enable();
		// NOW = 2025-10-23; gpt-4-turbo retires 2025-12-17 → ~55 days → AGING.
		$this->seed_post(
			7,
			array(
				array(
					'provider' => 'openai',
					'model'    => 'gpt-4-turbo',
				),
			)
		);

		$snap = Relic::snapshot( self::NOW );
		$this->assertSame( 0, $snap['relic_count'] );
		$this->assertSame( 1, $snap['aging_count'] );
		$this->assertSame( Relic::VERDICT_AGING, $snap['findings'][0]['verdict'] );
		$this->assertSame( '2025-12-17', $snap['findings'][0]['eol'] );
		$this->assertStringContainsString( 'AGING', $snap['findings'][0]['summary'] );
	}

	public function test_far_future_model_not_listed(): void {
		$this->enable();
		$this->seed_post(
			9,
			array(
				array(
					'provider' => 'openai',
					'model'    => 'gpt-4o',
				),
			)
		);
		$snap = Relic::snapshot( self::NOW );
		$this->assertSame( array(), $snap['findings'] );
	}

	public function test_skip_not_enough_provenance(): void {
		$this->enable();
		$row = Relic::classify_post( 11, array(), array(), null, self::NOW );
		$this->assertSame( Relic::VERDICT_SKIP, $row['verdict'] );
		$this->assertSame( 'not enough provenance history', $row['skip_reason'] );

		$row2 = Relic::classify_post(
			12,
			array(
				array(
					'ts'       => self::NOW,
					'provider' => 'openai',
					'model'    => '',
				),
			),
			array(),
			null,
			self::NOW
		);
		$this->assertSame( Relic::VERDICT_SKIP, $row2['verdict'] );
		$this->assertSame( 'not enough provenance history', $row2['skip_reason'] );
	}

	public function test_ack_silences_then_second_eol_model_rearms(): void {
		$this->enable();
		$this->seed_post(
			42,
			array(
				array(
					'provider' => 'openai',
					'model'    => 'gpt-4-0314',
				),
			)
		);

		$snap = Relic::snapshot( self::NOW );
		$this->assertSame( 1, $snap['unacked_relic'] );
		$this->assertTrue( Relic::ack_post( 42, null, self::NOW ) );

		$snap2 = Relic::snapshot( self::NOW );
		$this->assertSame( 0, $snap2['unacked_relic'] );
		$this->assertTrue( $snap2['findings'][0]['acked'] );

		// Later touch by another retiring/retired model re-opens the row.
		$this->seed_post(
			42,
			array(
				array(
					'provider' => 'openai',
					'model'    => 'gpt-4-0314',
					'ts'       => self::NOW - 200,
				),
				array(
					'provider' => 'openai',
					'model'    => 'gpt-4-turbo',
					'ts'       => self::NOW - 10,
				),
			)
		);

		$snap3 = Relic::snapshot( self::NOW );
		$this->assertFalse( $snap3['findings'][0]['acked'] );
		$this->assertGreaterThan( 0, $snap3['unacked_total'] );
	}

	public function test_rearming_alert_fires_once_then_clears_on_ack(): void {
		$this->enable();
		$this->seed_post(
			42,
			array(
				array(
					'provider' => 'openai',
					'model'    => 'gpt-4-0314',
				),
			)
		);

		$mails = array();
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) use ( &$mails ): bool {
			$mails[] = compact( 'to', 'subject', 'message' );
			return true;
		};

		$this->assertTrue( Relic::maybe_fire_alerts( self::NOW ) );
		$this->assertCount( 1, $mails );
		$this->assertStringContainsString( '[RELIC]', $mails[0]['subject'] );
		$this->assertFalse( Relic::maybe_fire_alerts( self::NOW ) ); // latched

		Relic::ack_post( 42, null, self::NOW + 1 );
		$snap = Relic::snapshot( self::NOW + 1 );
		$this->assertSame( 0, $snap['unacked_total'] );
		$this->assertFalse( $snap['alerted'] ); // re-armed (cleared)

		// New finding episode fires again.
		$this->seed_post(
			99,
			array(
				array(
					'provider' => 'openai',
					'model'    => 'gpt-4-0314',
				),
			)
		);
		$this->assertTrue( Relic::maybe_fire_alerts( self::NOW + 2 ) );
		$this->assertCount( 2, $mails );
	}

	public function test_csv_columns_and_cli_exit_on_unacked_relic(): void {
		$this->enable();
		$this->seed_post(
			42,
			array(
				array(
					'provider' => 'openai',
					'model'    => 'gpt-4-0314',
				),
			)
		);
		$csv = Relic::csv_for_snapshot();
		$this->assertStringContainsString( 'post_id,model,provider,retire_date,verdict,ack_state', $csv );
		$this->assertStringContainsString( 'RELIC', $csv );
		$this->assertStringContainsString( 'unacked', $csv );

		$snap = Relic::snapshot( self::NOW );
		$this->assertSame( 1, CLI_Relic::exit_code( $snap ) );
		Relic::ack_post( 42, null, self::NOW );
		$this->assertSame( 0, CLI_Relic::exit_code( Relic::snapshot( self::NOW ) ) );
	}

	public function test_throttle_skips_second_check_within_window(): void {
		$this->enable();
		$this->seed_post(
			1,
			array(
				array(
					'provider' => 'openai',
					'model'    => 'gpt-4-0314',
				),
			)
		);
		$this->assertTrue( Relic::maybe_check( self::NOW, false ) );
		$this->assertFalse( Relic::maybe_check( self::NOW + 60, false ) );
		$this->assertTrue( Relic::maybe_check( self::NOW + Relic::CHECK_THROTTLE_SECONDS + 1, false ) );
	}
}
