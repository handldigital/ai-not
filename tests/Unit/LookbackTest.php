<?php
/**
 * AICAC-LOOKBACK (#503): provider incident exposure report.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Audit_Export;
use HandL\AICAC\Cost;
use HandL\AICAC\Lookback;
use HandL\AICAC\Luggage;
use HandL\AICAC\Pii_Warn;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class LookbackTest extends TestCase {

	private const NOW      = 1791800000;
	private const PLUGIN_A = 'alpha/alpha.php';
	private const PLUGIN_B = 'beta/beta.php';
	private const EMAIL    = 'alice@example.com';

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$GLOBALS['handl_aicac_test_plugins']          = array(
			self::PLUGIN_A => array( 'Name' => 'Alpha AI' ),
			self::PLUGIN_B => array( 'Name' => 'Beta AI' ),
		);
		$_GET  = array();
		$_POST = array();
		Lookback::reset_for_tests();
		Lookback::set_test_now( self::NOW );
		if ( class_exists( Luggage::class, false ) ) {
			Luggage::reset_for_tests();
			Luggage::set_skip_cache( true );
			Luggage::set_test_now( self::NOW );
		}
	}

	protected function tearDown(): void {
		$_GET  = array();
		$_POST = array();
		Lookback::reset_for_tests();
		if ( class_exists( Luggage::class, false ) ) {
			Luggage::reset_for_tests();
		}
		unset(
			$GLOBALS['handl_aicac_test_added_actions'],
			$GLOBALS['handl_aicac_test_plugins']
		);
		parent::tearDown();
	}

	public function test_plugin_bootstrap_wires_lookback_after_taint(): void {
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-lookback.php', $plugin );
		$this->assertStringContainsString( 'Lookback::init()', $plugin );
		$this->assertGreaterThan(
			(int) strrpos( $plugin, 'Taint::init()' ),
			(int) strrpos( $plugin, 'Lookback::init()' )
		);
		$boot = (string) file_get_contents( HANDL_AICAC_DIR . '/tests/bootstrap.php' );
		$this->assertStringContainsString( 'class-handl-aicac-lookback.php', $boot );
		$readme = (string) file_get_contents( HANDL_AICAC_DIR . '/readme.txt' );
		$this->assertStringNotContainsString( 'lookback', strtolower( $readme ) );
		$admin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringNotContainsString( 'Lookback', $admin );
		$pii = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-pii-warn.php' );
		$this->assertStringNotContainsString( 'Lookback', $pii );
		$luggage = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-luggage.php' );
		$this->assertStringNotContainsString( 'Lookback', $luggage );
		$incident = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-incident.php' );
		$this->assertStringNotContainsString( 'Lookback', $incident );
		$cost = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-cost.php' );
		$this->assertStringNotContainsString( 'Lookback', $cost );
	}

	public function test_init_registers_menu_export_and_footer_once(): void {
		Lookback::init();
		Lookback::init();
		$this->assertSame(
			array( 'admin_menu', 'admin_post_' . Lookback::ACTION_EXPORT, 'admin_footer' ),
			$GLOBALS['handl_aicac_test_added_actions']
		);
		$this->assertSame( Lookback::FRAMING, 'report_only_never_collects' );
		$this->assertSame( 'handl-aicac-lookback', Lookback::PAGE_SLUG );
		$this->assertSame( 'lookback', Lookback::CONTEXT_TAG );
	}

	public function test_report_scopes_calls_plugins_pii_media_and_spend(): void {
		$in_window  = self::NOW - 86400;
		$out_window = self::NOW - ( 20 * 86400 );
		Lookback::set_test_log(
			array(
				array(
					'ts'            => $in_window,
					'decision'      => 'allow',
					'plugin'        => self::PLUGIN_A,
					'provider'      => 'OpenAI',
					'operation'     => 'generate_text',
					'input_tokens'  => 1_000_000,
					'output_tokens' => 0,
					'prompt_preview'=> '[redacted-email] wrote a summary',
					'pii_match'     => array(
						'types' => array( Pii_Warn::PATTERN_EMAIL => 1 ),
						'mode'  => 'warn',
						'text'  => self::EMAIL,
					),
				),
				array(
					'ts'           => $in_window + 60,
					'decision'     => 'allow',
					'plugin'       => self::PLUGIN_B,
					'provider'     => 'openai',
					'operation'    => 'generate_text',
					'input_tokens' => 0,
					'output_tokens'=> 0,
				),
				array(
					'ts'       => $out_window,
					'decision' => 'allow',
					'plugin'   => self::PLUGIN_A,
					'provider' => 'openai',
					'operation'=> 'generate_text',
				),
				array(
					'ts'       => $in_window,
					'decision' => 'allow',
					'plugin'   => self::PLUGIN_A,
					'provider' => 'anthropic',
					'operation'=> 'generate_text',
				),
			)
		);
		Lookback::set_test_shipments(
			array(
				array(
					'plugin'   => self::PLUGIN_A,
					'provider' => 'openai',
					'filename' => 'hero.png',
					'kind'     => Luggage::KIND_PACKED,
					'ts'       => $in_window,
				),
			)
		);

		$from = $in_window - 3600;
		$to   = $in_window + 3600;
		$rep  = Lookback::report( 'openai', $from, $to );

		$this->assertSame( 2, $rep['call_count'] );
		$this->assertSame( array( self::PLUGIN_A, self::PLUGIN_B ), $rep['plugins'] );
		$this->assertSame( 1, $rep['pii_hits'][ Pii_Warn::PATTERN_EMAIL ] ?? 0 );
		$this->assertArrayNotHasKey( 'text', $rep['pii_hits'] );
		$this->assertSame( 2.5, $rep['spend_usd'] );
		$this->assertNotEmpty( $rep['media_grades'] );
		$grades = array();
		foreach ( $rep['media_grades'] as $item ) {
			$grades[ $item['plugin'] ] = $item['grade'];
		}
		$this->assertSame( Luggage::GRADE_PACKED, $grades[ self::PLUGIN_A ] ?? '' );
		$this->assertSame( Luggage::GRADE_HOMEBODY, $grades[ self::PLUGIN_B ] ?? '' );

		$encoded = wp_json_encode( $rep );
		$this->assertIsString( $encoded );
		$this->assertStringNotContainsString( self::EMAIL, strtolower( $encoded ) );
		$this->assertStringContainsString( 'hero.png', $encoded );
	}

	public function test_shadow_provider_and_plugin_filter(): void {
		$ts = self::NOW - 100;
		Lookback::set_test_log(
			array(
				array(
					'ts'              => $ts,
					'decision'        => 'allow',
					'plugin'          => self::PLUGIN_A,
					'provider'        => '',
					'shadow_provider' => 'openai',
					'channel'         => 'direct_http',
					'operation'       => 'POST',
				),
				array(
					'ts'       => $ts,
					'decision' => 'allow',
					'plugin'   => self::PLUGIN_B,
					'provider' => 'openai',
					'operation'=> 'generate_text',
				),
			)
		);
		$all = Lookback::report( 'openai', $ts - 10, $ts + 10 );
		$this->assertSame( 2, $all['call_count'] );
		$one = Lookback::report( 'openai', $ts - 10, $ts + 10, self::PLUGIN_A );
		$this->assertSame( 1, $one['call_count'] );
		$this->assertSame( array( self::PLUGIN_A ), $one['plugins'] );
	}

	public function test_retention_notice_when_window_precedes_saved_log(): void {
		Lookback::set_test_policy( array( 'log_max_age_days' => 30 ) );
		$oldest = self::NOW - ( 25 * 86400 );
		Lookback::set_test_log(
			array(
				array(
					'ts'       => $oldest,
					'decision' => 'allow',
					'plugin'   => self::PLUGIN_A,
					'provider' => 'openai',
				),
			)
		);
		$from = self::NOW - ( 40 * 86400 );
		$to   = self::NOW - ( 5 * 86400 );
		$rep  = Lookback::report( 'openai', $from, $to );
		$this->assertGreaterThan( 0, $rep['retention_precede_days'] );
		$this->assertStringContainsString( 'days of this window precede retention', $rep['retention_notice'] );
		$this->assertSame(
			$rep['retention_precede_days'] . ' days of this window precede retention. Saved Activity does not cover those days, so this report cannot show what happened then.',
			$rep['retention_notice']
		);
	}

	public function test_csv_uses_audit_export_and_lookback_filename(): void {
		$ts = self::NOW - 50;
		Lookback::set_test_log(
			array(
				array(
					'ts'             => $ts,
					'decision'       => 'allow',
					'plugin'         => self::PLUGIN_A,
					'provider'       => 'openai',
					'operation'      => 'generate_text',
					'prompt_preview' => 'safe preview',
				),
				array(
					'ts'       => $ts - 10_000,
					'decision' => 'allow',
					'plugin'   => self::PLUGIN_A,
					'provider' => 'openai',
					'operation'=> 'generate_text',
					'prompt_preview' => 'outside-window-row',
				),
			)
		);
		$csv  = Lookback::csv( 'openai', $ts - 100, $ts + 100 );
		$name = Lookback::export_filename( 'openai', $ts - 100, $ts + 100 );
		$this->assertStringStartsWith( 'Time,', $csv );
		$this->assertStringContainsString( 'openai', $csv );
		$this->assertStringContainsString( 'alpha/alpha.php', $csv );
		$this->assertStringContainsString( 'safe preview', $csv );
		$this->assertStringNotContainsString( 'outside-window-row', $csv );
		$this->assertSame( Audit_Export::column_headers()[0], 'Time' );
		$this->assertStringStartsWith( 'aicac-lookback-openai-', $name );
		$this->assertStringEndsWith( '.csv', $name );
		$this->assertStringContainsString( Lookback::CONTEXT_TAG, $name );
	}

	public function test_empty_page_asks_for_provider_and_window(): void {
		Lookback::init();
		ob_start();
		Lookback::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Exposure lookback', $html );
		$this->assertStringContainsString( 'Choose a provider and date window.', $html );
		$this->assertStringContainsString( 'Run lookback', $html );
		$this->assertStringContainsString( 'Review saved Activity for one AI provider in a date window.', $html );
		$this->assertStringContainsString( 'This report only reads saved Activity and media records.', $html );
		$this->assertStringContainsString( 'Records may include blocked attempts and do not confirm delivery or exposure.', $html );
		$this->assertStringContainsString( 'Dates use UTC and include the full start and end days.', $html );
		$this->assertStringContainsString( 'Enter the plugin file path shown in Activity, for example my-plugin/my-plugin.php. Leave blank for all plugins.', $html );
		$this->assertStringNotContainsString( 'Download CSV', $html );
	}

	public function test_rendered_report_hides_matched_pii_text_and_shows_retention(): void {
		$in = self::NOW - 86400;
		Lookback::set_test_policy( array( 'log_max_age_days' => 30 ) );
		Lookback::set_test_log(
			array(
				array(
					'ts'             => $in,
					'decision'       => 'allow',
					'plugin'         => self::PLUGIN_A,
					'provider'       => 'openai',
					'operation'      => 'generate_text',
					'input_tokens'   => 100,
					'output_tokens'  => 20,
					'prompt_preview' => '[redacted-email]',
					'pii_match'      => array(
						'types' => array( Pii_Warn::PATTERN_EMAIL => 2 ),
						'mode'  => 'warn',
						'text'  => self::EMAIL,
					),
				),
			)
		);
		Lookback::set_test_shipments(
			array(
				array(
					'plugin'   => self::PLUGIN_A,
					'provider' => 'openai',
					'filename' => 'invoice.pdf',
					'kind'     => Luggage::KIND_URL,
					'ts'       => $in,
				),
			)
		);
		$_GET = array(
			'page'     => Lookback::PAGE_SLUG,
			'provider' => 'openai',
			'from'     => gmdate( 'Y-m-d', self::NOW - ( 40 * 86400 ) ),
			'to'       => gmdate( 'Y-m-d', self::NOW ),
		);
		ob_start();
		Lookback::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Exposure lookback', $html );
		$this->assertStringContainsString( 'Saved Activity in this window', $html );
		$this->assertStringContainsString( 'Saved Activity entries', $html );
		$this->assertStringContainsString( 'days of this window precede retention', $html );
		$this->assertStringContainsString( 'Saved Activity does not cover those days, so this report cannot show what happened then.', $html );
		$this->assertStringContainsString( 'Email address', $html );
		$this->assertStringContainsString( 'Download CSV', $html );
		$this->assertStringContainsString( Lookback::ACTION_EXPORT, $html );
		$this->assertStringContainsString( 'invoice.pdf', $html );
		$this->assertStringNotContainsString( self::EMAIL, $html );
		$this->assertStringContainsString( 'Personal information pattern hits', $html );
		$this->assertStringContainsString( 'Outbound media', $html );
		$this->assertStringContainsString( 'Pattern counts show recorded matches, not confirmed personal information.', $html );
		$this->assertStringContainsString( 'Saved content references (up to 20)', $html );
		$this->assertStringNotContainsString( 'Exposure in this window', $html );
		$this->assertStringNotContainsString( 'No matching calls in this window.', $html );
	}

	public function test_incident_query_prefills_window(): void {
		$started = self::NOW - ( 3 * 86400 );
		$ended   = self::NOW - 86400;
		Lookback::set_test_incidents(
			array(
				'inc_testlook' => array(
					'id'         => 'inc_testlook',
					'started_ts' => $started,
					'ended_ts'   => $ended,
				),
			)
		);
		$_GET = array(
			'page'     => Lookback::PAGE_SLUG,
			'incident' => 'inc_testlook',
			'provider' => 'openai',
		);
		$input = Lookback::request_input();
		$this->assertSame( gmdate( 'Y-m-d', $started ), $input['from'] );
		$this->assertSame( gmdate( 'Y-m-d', $ended ), $input['to'] );
		$this->assertTrue( $input['ready'] );
	}

	public function test_insights_footer_injects_run_exposure_lookback(): void {
		$_GET['page'] = 'handl-aicac-insights';
		ob_start();
		Lookback::maybe_inject_provider_map();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'handl-aicac-lookback-map', $html );
		$this->assertStringContainsString( 'Run exposure lookback', $html );
		$this->assertStringContainsString( 'handl-aicac-provider-map-table', $html );
		$this->assertStringContainsString( Lookback::PAGE_SLUG, $html );
	}
}
