<?php
/**
 * AICAC-TRAIN-EXPOSURE (#389).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Train_Exposure;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class TrainExposureTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Train_Exposure::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'haktan+aicac-train-exposure@handldigital.com',
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_filters'][ Train_Exposure::FILTER_TABLE ],
			$GLOBALS['handl_aicac_test_current_user_can']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		Train_Exposure::reset_for_tests();
		parent::tearDown();
	}

	public function test_defaults_off_and_save_defaults_deletes_option(): void {
		$this->assertFalse( Train_Exposure::is_enabled() );
		$this->assertSame( Train_Exposure::defaults(), Train_Exposure::get_settings() );
		Train_Exposure::save_settings( array( 'enabled' => true ) );
		$this->assertTrue( Train_Exposure::is_enabled() );
		Train_Exposure::save_settings( array( 'enabled' => false ) );
		$this->assertFalse( (bool) get_option( Train_Exposure::SETTINGS_OPTION, false ) );
	}

	public function test_feature_off_skips_alerts(): void {
		$log = array(
			array(
				'ts'       => 1_720_000_000,
				'plugin'   => 'alpha/alpha.php',
				'provider' => 'cohere',
				'decision' => 'allow',
				'operation'=> 'generate_text',
			),
		);
		$out = Train_Exposure::maybe_fire_alerts( $log, null, 1_720_000_000 );
		$this->assertSame( 0, $out['fired'] );
		$this->assertSame( array(), Train_Exposure::test_mails() );
	}

	public function test_filter_override_and_staleness_age(): void {
		$GLOBALS['handl_aicac_test_filters'][ Train_Exposure::FILTER_TABLE ] = static function (): array {
			return array(
				'shipped'   => '2026-11-01',
				'providers' => array(
					'custom-ai' => array(
						'trains_by_default' => 'yes',
						'opt_out'           => 'email legal@example.com',
						'zero_retention'    => 'no',
					),
				),
			);
		};
		$table = Train_Exposure::table();
		$this->assertSame( '2026-11-01', $table['shipped'] );
		$this->assertArrayHasKey( 'custom-ai', $table['providers'] );
		$age = strtotime( '2026-11-01 UTC' );
		$this->assertSame( $age, Train_Exposure::table_age_ts() );
		$this->assertFalse( Train_Exposure::is_table_stale( $age + ( 30 * DAY_IN_SECONDS ) ) );
		$this->assertTrue( Train_Exposure::is_table_stale( $age + ( 121 * DAY_IN_SECONDS ) ) );
	}

	public function test_exposure_roster_flags_train_by_default_without_attestation(): void {
		Train_Exposure::save_settings( array( 'enabled' => true ) );
		$now = strtotime( '2026-10-12 12:00:00 UTC' );
		$log = array(
			array(
				'ts'        => $now,
				'plugin'    => 'alpha/alpha.php',
				'provider'  => 'cohere',
				'decision'  => 'allow',
				'operation' => 'generate_text',
			),
			array(
				'ts'        => $now,
				'plugin'    => 'beta/beta.php',
				'provider'  => 'openai',
				'decision'  => 'allow',
				'operation' => 'generate_text',
			),
		);
		$exposed = Train_Exposure::exposure_roster( $log );
		$by_pair = array();
		foreach ( $exposed as $row ) {
			$by_pair[ $row['plugin'] . '|' . $row['provider'] ] = $row;
		}
		$this->assertArrayHasKey( 'alpha/alpha.php|cohere', $by_pair );
		$this->assertArrayNotHasKey( 'beta/beta.php|openai', $by_pair );

		Train_Exposure::record_attestation(
			'cohere',
			array(
				'requested_at' => '2026-09-01',
				'requested_by' => 'Counsel',
				'reference'    => 'TICKET-1',
			),
			$now
		);
		$exposed2 = Train_Exposure::exposure_roster( $log );
		$this->assertSame( array(), $exposed2 );

		$providers = Train_Exposure::provider_roster( $log );
		$by_prov   = array();
		foreach ( $providers as $row ) {
			$by_prov[ $row['provider'] ] = $row;
		}
		$this->assertTrue( ! empty( $by_prov['cohere']['attested'] ) );
		$this->assertFalse( ! empty( $by_prov['cohere']['exposed'] ) );
	}

	public function test_attestation_history_is_append_only(): void {
		Train_Exposure::record_attestation(
			'deepseek',
			array(
				'requested_at' => '2026-01-01',
				'requested_by' => 'Alice',
				'reference'    => 'v1',
			),
			1_700_000_000
		);
		Train_Exposure::record_attestation(
			'deepseek',
			array(
				'requested_at' => '2026-02-01',
				'requested_by' => 'Bob',
				'reference'    => 'v2',
			),
			1_700_100_000
		);
		$map = Train_Exposure::get_attestations();
		$this->assertSame( '2026-02-01', $map['deepseek']['requested_at'] );
		$this->assertSame( 'Bob', $map['deepseek']['requested_by'] );
		$this->assertCount( 1, $map['deepseek']['history'] );
		$this->assertSame( '2026-01-01', $map['deepseek']['history'][0]['requested_at'] );
		$this->assertSame( 'Alice', $map['deepseek']['history'][0]['requested_by'] );
	}

	public function test_alerts_fire_once_per_train_by_default_provider(): void {
		Train_Exposure::save_settings( array( 'enabled' => true ) );
		$now = strtotime( '2026-10-12 12:00:00 UTC' );
		$log = array(
			array(
				'ts'        => $now,
				'plugin'    => 'alpha/alpha.php',
				'provider'  => 'deepseek',
				'decision'  => 'allow',
				'operation' => 'generate_text',
			),
		);
		$first = Train_Exposure::maybe_fire_alerts( $log, null, $now );
		$this->assertSame( 1, $first['fired'] );
		$this->assertCount( 1, Train_Exposure::test_mails() );
		$this->assertStringContainsString( 'deepseek', strtolower( Train_Exposure::test_mails()[0]['subject'] ) );

		$second = Train_Exposure::maybe_fire_alerts( $log, null, $now );
		$this->assertSame( 0, $second['fired'] );
		$this->assertGreaterThan( 0, $second['skipped'] );
		$this->assertCount( 1, Train_Exposure::test_mails() );
	}

	public function test_csv_and_off_page(): void {
		Train_Exposure::save_settings( array( 'enabled' => true ) );
		$now = strtotime( '2026-10-12 12:00:00 UTC' );
		$log = array(
			array(
				'ts'        => $now,
				'plugin'    => 'alpha/alpha.php',
				'provider'  => 'cohere',
				'decision'  => 'allow',
				'operation' => 'generate_text',
			),
		);
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
		$csv = Train_Exposure::csv_for_exposure( Train_Exposure::exposure_roster( $log ) );
		$this->assertStringContainsString( 'assertion_not_legal_advice', $csv );
		$this->assertStringContainsString( 'alpha/alpha.php', $csv );
		$this->assertStringContainsString( 'cohere', $csv );

		Train_Exposure::save_settings( array( 'enabled' => false ) );
		$_GET['page'] = Train_Exposure::PAGE_SLUG;
		ob_start();
		Train_Exposure::render_page();
		$html = ob_get_clean();
		$this->assertStringContainsString( 'Training exposure is off', $html );
		$this->assertStringNotContainsString( 'Exposed (train-by-default', $html );
		unset( $_GET['page'] );
	}

	public function test_enabled_page_shows_assertion_framing(): void {
		Train_Exposure::save_settings( array( 'enabled' => true ) );
		$now = strtotime( '2026-10-12 12:00:00 UTC' );
		$log = array(
			array(
				'ts'        => $now,
				'plugin'    => 'alpha/alpha.php',
				'provider'  => 'cohere',
				'decision'  => 'allow',
				'operation' => 'generate_text',
			),
		);
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
		$_GET['page'] = Train_Exposure::PAGE_SLUG;
		ob_start();
		Train_Exposure::render_page();
		$html = ob_get_clean();
		$this->assertStringContainsString( 'Assertion framing', $html );
		$this->assertStringContainsString( 'not legal advice', $html );
		$this->assertStringContainsString( 'cohere', $html );
		unset( $_GET['page'] );
	}
}
