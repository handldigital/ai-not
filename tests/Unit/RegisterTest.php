<?php
/**
 * AICAC-REGISTER (#375).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Register;
use PHPUnit\Framework\TestCase;

final class RegisterTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Register::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_test_current_user_can'] );
		$GLOBALS['handl_aicac_test_options'] = array();
		Register::reset_for_tests();
		parent::tearDown();
	}

	public function test_defaults_are_off_and_save_defaults_deletes_option(): void {
		$this->assertFalse( Register::is_enabled() );
		$this->assertSame( Register::defaults(), Register::get_settings() );
		Register::save_settings( array( 'enabled' => true ) );
		$this->assertTrue( Register::is_enabled() );
		Register::save_settings( array( 'enabled' => false ) );
		$this->assertFalse( (bool) get_option( Register::SETTINGS_OPTION, false ) );
	}

	public function test_empty_log_yields_no_rows(): void {
		$this->assertSame( array(), Register::build_rows() );
	}

	public function test_aggregates_calls_denies_plugins_families_and_pii(): void {
		$log = array(
			array(
				'ts'                 => 1_700_000_100,
				'plugin'             => 'alpha/alpha.php',
				'provider'           => 'OpenAI',
				'decision'           => 'allow',
				'capability_family'  => 'text',
				'operation'          => 'generate_text',
				'count'              => 2,
			),
			array(
				'ts'                => 1_700_000_200,
				'plugin'            => 'beta/beta.php',
				'provider'          => 'openai',
				'decision'          => 'deny',
				'capability_family' => 'image',
				'operation'         => 'generate_image',
				'denial_reason'     => 'policy',
				'pii_match'         => array(
					'types' => array( 'email' => 1 ),
					'mode'  => 'warn',
				),
				'count'             => 3,
			),
			array(
				'ts'       => 1_700_000_050,
				'plugin'   => 'alpha/alpha.php',
				'provider' => 'openai',
				'decision' => 'allow',
				'operation'=> 'generate_text',
			),
			// Non-activity channel ignored.
			array(
				'ts'       => 1_700_000_300,
				'plugin'   => 'alpha/alpha.php',
				'provider' => 'openai',
				'decision' => 'allow',
				'channel'  => 'direct_http',
			),
		);

		$stats = Register::compute_provider_stats( $log );
		$this->assertArrayHasKey( 'openai', $stats );
		$row = $stats['openai'];
		$this->assertSame( 1_700_000_050, $row['first_seen'] );
		$this->assertSame( 1_700_000_200, $row['last_seen'] );
		$this->assertSame( 3, $row['calls'] ); // 2 + 1 allows
		$this->assertSame( 3, $row['denies'] );
		$this->assertSame( array( 'alpha/alpha.php', 'beta/beta.php' ), $row['plugins'] );
		$this->assertContains( 'text', $row['families'] );
		$this->assertContains( 'image', $row['families'] );
		$this->assertTrue( $row['pii_flagged'] );
		$this->assertContains( 'email', $row['pii_types'] );
		$this->assertContains( 'log', $row['sources'] );
	}

	public function test_admin_fields_merge_and_sanitize(): void {
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => 1_700_000_100,
					'plugin'   => 'alpha/alpha.php',
					'provider' => 'anthropic',
					'decision' => 'allow',
					'operation'=> 'generate_text',
				),
			),
			false
		);

		Register::save_fields(
			array(
				'anthropic' => array(
					'dpa_on_file' => '1',
					'dpa_date'    => '2026-01-15',
					'dpa_url'     => 'https://example.test/dpa',
					'purpose'     => 'Support chatbot',
					'residency'   => 'US',
					'contact'     => 'dpo@example.test',
					'review_date' => '2026-06-01',
					'status'      => 'approved',
				),
				'bogus'     => array(
					'status' => 'not-a-status',
				),
			)
		);

		$rows = Register::build_rows( null, 1_700_000_000 );
		$by = array();
		foreach ( $rows as $r ) {
			$by[ $r['provider'] ] = $r;
		}
		$this->assertArrayHasKey( 'anthropic', $by );
		$this->assertTrue( $by['anthropic']['dpa_on_file'] );
		$this->assertSame( '2026-01-15', $by['anthropic']['dpa_date'] );
		$this->assertSame( 'https://example.test/dpa', $by['anthropic']['dpa_url'] );
		$this->assertSame( 'Support chatbot', $by['anthropic']['purpose'] );
		$this->assertSame( Register::STATUS_APPROVED, $by['anthropic']['status'] );
		// now = 1700000000 => 2023-11-14; review 2026-06-01 is future => not stale
		$this->assertFalse( $by['anthropic']['stale'] );
		$this->assertArrayHasKey( 'bogus', $by );
		$this->assertSame( '', $by['bogus']['status'] );
	}

	public function test_stale_when_review_date_passed_and_notice_gated_on_enabled(): void {
		Register::save_fields(
			array(
				'openai' => array(
					'review_date' => '2020-01-01',
					'status'      => Register::STATUS_UNDER_REVIEW,
				),
			)
		);
		$this->assertTrue( Register::is_stale( '2020-01-01', 1_700_000_000 ) );
		$this->assertFalse( Register::is_stale( '2099-01-01', 1_700_000_000 ) );
		$this->assertFalse( Register::is_stale( '', 1_700_000_000 ) );

		$stale = Register::stale_rows( 1_700_000_000 );
		$this->assertCount( 1, $stale );
		$this->assertSame( 'openai', $stale[0]['provider'] );

		// Notice only when enabled + on register page.
		Register::save_settings( array( 'enabled' => false ) );
		$_GET['page'] = Register::PAGE_SLUG;
		ob_start();
		Register::maybe_staleness_notice();
		$off = ob_get_clean();
		$this->assertSame( '', $off );

		Register::save_settings( array( 'enabled' => true ) );
		ob_start();
		Register::maybe_staleness_notice();
		$on = ob_get_clean();
		$this->assertStringContainsString( 'review date has passed', $on );

		$_GET['page'] = 'handl-aicac';
		ob_start();
		Register::maybe_staleness_notice();
		$other = ob_get_clean();
		$this->assertSame( '', $other );
		unset( $_GET['page'] );
	}

	public function test_prohibited_status_does_not_register_gate_filter(): void {
		Register::reset_for_tests();
		Register::init();
		global $wp_filter;
		$hooks = $wp_filter['wp_ai_client_prevent_prompt'] ?? null;
		if ( is_array( $hooks ) ) {
			foreach ( $hooks as $prio => $callbacks ) {
				foreach ( (array) $callbacks as $cb ) {
					$fn = $cb['function'] ?? null;
					if ( is_array( $fn ) && ( $fn[0] ?? null ) === Register::class ) {
						$this->fail( 'Register must stay read-only against the gate' );
					}
				}
			}
		}
		$this->assertTrue( true );
		Register::save_fields(
			array(
				'openai' => array( 'status' => Register::STATUS_PROHIBITED ),
			)
		);
		$rows = Register::build_rows();
		$this->assertSame( Register::STATUS_PROHIBITED, $rows[0]['status'] ?? '' );
	}

	public function test_csv_and_print_contain_provider_columns(): void {
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => 1_700_000_100,
					'plugin'   => 'alpha/alpha.php',
					'provider' => 'openai',
					'decision' => 'allow',
					'operation'=> 'generate_text',
					'count'    => 1,
				),
			),
			false
		);
		Register::save_fields(
			array(
				'openai' => array(
					'dpa_on_file' => true,
					'dpa_date'    => '2026-01-01',
					'purpose'     => 'Assist',
					'status'      => Register::STATUS_APPROVED,
				),
			)
		);

		$csv = Register::csv_for_register();
		$this->assertStringContainsString( 'provider,label,first_seen', $csv );
		$this->assertStringContainsString( 'openai', $csv );
		$this->assertStringContainsString( 'Assist', $csv );

		$html = Register::build_print_html( Register::build_rows() );
		$this->assertStringContainsString( 'AI processor register', $html );
		$this->assertStringContainsString( 'openai', $html );
		$this->assertStringContainsString( '@media print', $html );
	}

	public function test_save_fields_empty_deletes_option(): void {
		Register::save_fields(
			array(
				'openai' => array( 'purpose' => 'x' ),
			)
		);
		$this->assertNotFalse( get_option( Register::FIELDS_OPTION, false ) );
		Register::save_fields( array() );
		$this->assertFalse( (bool) get_option( Register::FIELDS_OPTION, false ) );
	}

	public function test_invalid_dates_are_dropped(): void {
		$row = Register::sanitize_field_row(
			array(
				'dpa_date'    => '01-15-2026',
				'review_date' => '2026-13-40',
				'status'      => 'approved',
			)
		);
		$this->assertSame( '', $row['dpa_date'] );
		$this->assertSame( '', $row['review_date'] );
		$this->assertSame( Register::STATUS_APPROVED, $row['status'] );
	}
}
