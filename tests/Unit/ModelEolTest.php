<?php
/**
 * AICAC-MODEL-EOL (#379).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Model_Eol;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class ModelEolTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Model_Eol::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'haktan+aicac-model-eol@handldigital.com',
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_filters'][ Model_Eol::FILTER_CALENDAR ],
			$GLOBALS['handl_aicac_test_current_user_can'],
			$GLOBALS['handl_aicac_wp_mail']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		Model_Eol::reset_for_tests();
		parent::tearDown();
	}

	public function test_defaults_are_off_and_save_defaults_deletes_option(): void {
		$this->assertFalse( Model_Eol::is_enabled() );
		$this->assertSame( Model_Eol::defaults(), Model_Eol::get_settings() );
		Model_Eol::save_settings( array( 'enabled' => true ) );
		$this->assertTrue( Model_Eol::is_enabled() );
		Model_Eol::save_settings( array( 'enabled' => false ) );
		$this->assertFalse( (bool) get_option( Model_Eol::SETTINGS_OPTION, false ) );
	}

	public function test_feature_off_skips_alerts(): void {
		$log = array(
			array(
				'ts'       => 1_700_000_100,
				'plugin'   => 'alpha/alpha.php',
				'provider' => 'openai',
				'model'    => 'gpt-4-0314',
				'decision' => 'allow',
				'operation'=> 'generate_text',
			),
		);
		$out = Model_Eol::maybe_fire_alerts( $log, null, 1_720_000_000 );
		$this->assertSame( 0, $out['fired'] );
		$this->assertSame( array(), Model_Eol::test_mails() );
	}

	public function test_past_eol_flags_roster_and_check_failures(): void {
		Model_Eol::save_settings( array( 'enabled' => true ) );
		$log = array(
			array(
				'ts'       => 1_700_000_100,
				'plugin'   => 'alpha/alpha.php',
				'provider' => 'openai',
				'model'    => 'gpt-4-0314',
				'decision' => 'allow',
				'operation'=> 'generate_text',
				'count'    => 2,
			),
		);
		// 2026-10-12-ish: gpt-4-0314 retired 2024-06-06 → past.
		$now  = strtotime( '2026-10-12 12:00:00 UTC' );
		$rows = Model_Eol::build_rows( $log, null, $now );
		$this->assertNotEmpty( $rows );
		$this->assertSame( 'gpt-4-0314', $rows[0]['model'] );
		$this->assertTrue( $rows[0]['past'] );
		$this->assertTrue( $rows[0]['within_14'] );
		$this->assertSame( array( 'alpha/alpha.php' ), $rows[0]['plugins'] );
		$this->assertSame( 2, $rows[0]['calls'] );

		$failures = Model_Eol::check_failures( $log, null, $now );
		$this->assertCount( 1, $failures );
	}

	public function test_filter_override_wins_over_bundled_row(): void {
		$GLOBALS['handl_aicac_test_filters'][ Model_Eol::FILTER_CALENDAR ] = static function ( array $rows ): array {
			foreach ( $rows as $i => $row ) {
				if ( ( $row['provider'] ?? '' ) === 'openai' && ( $row['model'] ?? '' ) === 'gpt-4-0314' ) {
					$rows[ $i ]['eol']         = '2099-01-01';
					$rows[ $i ]['replacement'] = 'gpt-custom';
					$rows[ $i ]['source']      = 'filter';
				}
			}

			return $rows;
		};
		$log = array(
			array(
				'ts'       => 1_700_000_100,
				'plugin'   => 'alpha/alpha.php',
				'provider' => 'openai',
				'model'    => 'gpt-4-0314',
				'decision' => 'allow',
				'operation'=> 'generate_text',
			),
		);
		$now  = strtotime( '2026-10-12 12:00:00 UTC' );
		$rows = Model_Eol::build_rows( $log, null, $now );
		$this->assertSame( '2099-01-01', $rows[0]['eol'] );
		$this->assertSame( 'gpt-custom', $rows[0]['replacement'] );
		$this->assertSame( 'filter', $rows[0]['source'] );
		$this->assertFalse( $rows[0]['within_60'] );
	}

	public function test_feed_refresh_updates_calendar_age(): void {
		$shipped = strtotime( Model_Eol::BUNDLED_SHIPPED . ' 00:00:00 UTC' );
		$this->assertSame( $shipped, Model_Eol::calendar_age_ts() );

		$refresh = strtotime( '2026-11-01 00:00:00 UTC' );
		Model_Eol::apply_remote_calendar(
			array(
				array(
					'provider'    => 'openai',
					'model'       => 'gpt-future-test',
					'eol'         => '2027-01-01',
					'replacement' => 'gpt-next',
				),
			),
			$refresh
		);
		$this->assertSame( $refresh, Model_Eol::calendar_age_ts() );
		$this->assertFalse( Model_Eol::is_calendar_stale( $refresh + ( 30 * DAY_IN_SECONDS ) ) );
		$this->assertTrue( Model_Eol::is_calendar_stale( $refresh + ( 121 * DAY_IN_SECONDS ) ) );
	}

	public function test_alerts_fire_once_per_model_threshold(): void {
		Model_Eol::save_settings( array( 'enabled' => true ) );
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) {
			return true;
		};

		// Craft a calendar row 10 days out via filter (within 14 and 60).
		$GLOBALS['handl_aicac_test_filters'][ Model_Eol::FILTER_CALENDAR ] = static function (): array {
			return array(
				array(
					'provider'    => 'openai',
					'model'       => 'gpt-alert-test',
					'eol'         => '2026-10-22',
					'replacement' => 'gpt-4o',
					'source'      => 'filter',
				),
			);
		};
		$log = array(
			array(
				'ts'       => 1_700_000_100,
				'plugin'   => 'alpha/alpha.php',
				'provider' => 'openai',
				'model'    => 'gpt-alert-test',
				'decision' => 'allow',
				'operation'=> 'generate_text',
			),
		);
		$now = strtotime( '2026-10-12 12:00:00 UTC' );
		$first = Model_Eol::maybe_fire_alerts( $log, null, $now );
		$this->assertSame( 2, $first['fired'] ); // 60 + 14
		$this->assertCount( 2, Model_Eol::test_mails() );

		$second = Model_Eol::maybe_fire_alerts( $log, null, $now );
		$this->assertSame( 0, $second['fired'] );
		$this->assertSame( 2, $second['skipped'] );
		$this->assertCount( 2, Model_Eol::test_mails() );
	}

	public function test_pinned_model_gets_loud_alert_variant(): void {
		Model_Eol::save_settings( array( 'enabled' => true ) );
		$GLOBALS['handl_aicac_wp_mail'] = static function () {
			return true;
		};
		$GLOBALS['handl_aicac_test_filters'][ Model_Eol::FILTER_CALENDAR ] = static function (): array {
			return array(
				array(
					'provider'    => 'openai',
					'model'       => 'gpt-pin-test',
					'eol'         => '2026-10-20',
					'replacement' => 'gpt-4o',
					'source'      => 'filter',
				),
			);
		};
		$policy = array(
			'default'             => 'allow',
			'log_enabled'         => true,
			'alert_email'         => 'haktan+aicac-model-eol@handldigital.com',
			'model_force_plugins' => array(
				'alpha/alpha.php' => array(
					'provider' => 'openai',
					'model'    => 'gpt-pin-test',
				),
			),
		);
		update_option( Plugin::OPTION_KEY, $policy, false );

		$now = strtotime( '2026-10-12 12:00:00 UTC' );
		$rows = Model_Eol::build_rows( array(), $policy, $now );
		$this->assertNotEmpty( $rows );
		$this->assertTrue( $rows[0]['pinned'] );

		Model_Eol::maybe_fire_alerts( array(), $policy, $now );
		$mails = Model_Eol::test_mails();
		$this->assertNotEmpty( $mails );
		$subjects = array_column( $mails, 'subject' );
		$joined   = implode( "\n", $subjects );
		$this->assertStringContainsString( 'URGENT', $joined );
		$this->assertStringContainsString( 'fail-close', $joined );
		$bodies = array_column( $mails, 'body' );
		$this->assertStringContainsString( 'fail-close', implode( "\n", $bodies ) );
	}

	public function test_off_page_shows_enable_prompt_not_roster(): void {
		$_GET['page'] = Model_Eol::PAGE_SLUG;
		ob_start();
		Model_Eol::render_page();
		$html = ob_get_clean();
		$this->assertStringContainsString( 'Model retirement watch is off', $html );
		$this->assertStringNotContainsString( 'Days left', $html );
		unset( $_GET['page'] );
	}
}
