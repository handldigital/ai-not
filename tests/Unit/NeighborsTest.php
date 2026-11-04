<?php
/**
 * AICAC-NEIGHBORS (#492).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Neighbors;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class NeighborsTest extends TestCase {

	private const NOW   = 1791800000;
	private const WEEK  = 604800;
	private const POSTS = 80;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_filters']          = array();
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$GLOBALS['handl_aicac_test_added_filters']    = array();
		Neighbors::reset_for_tests();
		Neighbors::set_skip_cache( true );
		Neighbors::set_test_now( self::NOW );
		Neighbors::set_test_posts( self::POSTS );
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_filters']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_added_filters'] = array();
		Neighbors::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private function week_of_activity( int $allows, int $denies, float $usd_each = 0.42 ): array {
		$rows  = array();
		$total = $allows + $denies;
		for ( $i = 0; $i < $total; $i++ ) {
			$deny = $i < $denies;
			$ts   = ( 1 === $total )
				? self::NOW
				: self::NOW - self::WEEK + (int) round( ( $i / ( $total - 1 ) ) * self::WEEK );
			$rows[] = array(
				'ts'            => $ts,
				'decision'      => $deny ? 'deny' : 'allow',
				'plugin'        => 'alpha/alpha.php',
				'provider'      => 'openai',
				'estimated_usd' => $usd_each,
			);
		}

		return $rows;
	}

	public function test_init_registers_menu_dashboard_and_save_once(): void {
		Neighbors::init();
		Neighbors::init();
		$hooks = $GLOBALS['handl_aicac_test_added_actions'];
		$this->assertSame(
			array( 'admin_menu', 'wp_dashboard_setup', 'admin_post_' . Neighbors::ACTION_SAVE ),
			$hooks
		);
		$this->assertSame( Neighbors::FRAMING, 'report_only_never_sends_telemetry' );
		$this->assertSame( 0, strpos( Neighbors::SETTINGS_OPTION, 'handl_aicac_neighbors' ) );
		$this->assertSame( 0, strpos( Neighbors::CENSUS_OPTION, 'handl_aicac_neighbors' ) );
	}

	public function test_plugin_bootstrap_wires_neighbors_at_bottom(): void {
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-neighbors.php', $plugin );
		$this->assertStringContainsString( 'Neighbors::init()', $plugin );
		$this->assertGreaterThan(
			(int) strrpos( $plugin, 'Detour::init()' ),
			(int) strrpos( $plugin, 'Neighbors::init()' )
		);
		$boot = (string) file_get_contents( HANDL_AICAC_DIR . '/tests/bootstrap.php' );
		$this->assertStringContainsString( 'class-handl-aicac-neighbors.php', $boot );
		$readme = (string) file_get_contents( HANDL_AICAC_DIR . '/readme.txt' );
		$this->assertStringNotContainsString( 'neighbors', strtolower( $readme ) );
	}

	public function test_off_by_default_and_enable_renders_percentile_sentences(): void {
		$this->assertFalse( Neighbors::is_enabled() );
		Neighbors::set_test_log( $this->week_of_activity( 89, 11 ) );
		ob_start();
		Neighbors::render_page();
		$off = (string) ob_get_clean();
		$this->assertStringContainsString( 'Peer comparison is off.', $off );
		$this->assertStringNotContainsString( 'you deny', $off );
		$this->assertStringNotContainsString( 'OFF', $off );

		Neighbors::save_settings( array( 'enabled' => true ) );
		$this->assertTrue( Neighbors::is_enabled() );
		ob_start();
		Neighbors::render_page();
		$on = (string) ob_get_clean();
		$this->assertStringContainsString( 'Sites your size typically deny 2%–5% of AI calls — you deny 11%.', $on );
		$this->assertStringContainsString( 'Nothing is sent from this site.', $on );
		$this->assertStringNotContainsString( 'INSUFFICIENT-DATA', $on );

		ob_start();
		Neighbors::render_dashboard();
		$dash = (string) ob_get_clean();
		$this->assertStringContainsString( 'Sites your size typically deny 2%–5% of AI calls — you deny 11%.', $dash );
		$this->assertStringContainsString( 'handl-aicac-neighbors-dash', $dash );
	}

	public function test_zero_outbound_http_in_class_and_table(): void {
		$class = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-neighbors.php' );
		$table = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/data/neighbors-table.php' );
		foreach ( array( $class, $table ) as $src ) {
			$this->assertStringNotContainsString( 'wp_remote_get', $src );
			$this->assertStringNotContainsString( 'wp_remote_post', $src );
			$this->assertStringNotContainsString( 'wp_remote_request', $src );
			$this->assertStringNotContainsString( 'wp_remote_', $src );
			$this->assertStringNotContainsString( 'wp_safe_remote', $src );
		}
		$this->assertSame( Neighbors::TABLE_VERSION, Neighbors::table_version() );
		$this->assertSame( Neighbors::TABLE_FORMAT, Neighbors::table()['format'] );
	}

	public function test_bands_and_percentiles_are_deterministic_from_bundled_table(): void {
		Neighbors::save_settings( array( 'enabled' => true ) );
		Neighbors::set_test_log( $this->week_of_activity( 89, 11 ) );
		$a = Neighbors::census();
		$b = Neighbors::census();
		$this->assertSame( $a, $b );
		$this->assertSame( 1, $a['table_version'] );
		$this->assertSame( Neighbors::TABLE_FORMAT, $a['table_format'] );
		$this->assertSame( 's', $a['site_size'] );
		$this->assertSame( 100, $a['weekly_calls'] );
		$this->assertSame( 11, $a['denies'] );
		$this->assertEqualsWithDelta( 0.11, $a['deny_rate'], 0.00001 );
		$this->assertSame( 'steady', $a['weekly_call_band'] );
		$this->assertSame( 'high', $a['deny_rate_band'] );
		$this->assertSame( Neighbors::STATUS_OK, $a['status'] );
		$this->assertSame( 0.02, $a['deny_typical']['p25'] );
		$this->assertSame( 0.05, $a['deny_typical']['p75'] );
		$this->assertGreaterThanOrEqual( 90, $a['deny_percentile'] );
		$this->assertSame(
			Neighbors::percentile_rank( 0.11, Neighbors::table()['distributions']['s']['deny_rate'] ),
			$a['deny_percentile']
		);
	}

	public function test_empty_and_insufficient_render_without_warnings_or_codes(): void {
		Neighbors::save_settings( array( 'enabled' => true ) );
		Neighbors::set_test_log( array() );
		ob_start();
		Neighbors::render_page();
		$empty = (string) ob_get_clean();
		$this->assertStringContainsString( 'No AI activity is available for this report yet.', $empty );
		$this->assertStringNotContainsString( 'EMPTY', $empty );
		$this->assertStringNotContainsString( 'INSUFFICIENT-DATA', $empty );
		$this->assertSame( Neighbors::STATUS_EMPTY, Neighbors::census()['status'] );

		$short = array();
		for ( $i = 0; $i < 8; $i++ ) {
			$short[] = array(
				'ts'       => self::NOW - ( 86400 * 2 ) + $i,
				'decision' => 'allow',
				'plugin'   => 'alpha/alpha.php',
				'provider' => 'openai',
			);
		}
		Neighbors::set_test_log( $short );
		ob_start();
		Neighbors::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Not enough activity yet. Peer comparison needs at least one week of AI activity.', $html );
		$this->assertStringNotContainsString( 'INSUFFICIENT-DATA', $html );
		$this->assertSame( Neighbors::STATUS_INSUFFICIENT, Neighbors::census()['status'] );
		$this->assertSame( array(), Neighbors::sentences( Neighbors::census() ) );
	}

	public function test_uninstall_cleans_neighbors_options(): void {
		if ( ! defined( 'HANDL_AICAC_UNINSTALL_HELPERS' ) ) {
			define( 'HANDL_AICAC_UNINSTALL_HELPERS', true );
		}
		require_once HANDL_AICAC_DIR . '/uninstall.php';

		Neighbors::save_settings( array( 'enabled' => true ) );
		update_option( Neighbors::CENSUS_OPTION, array( 'status' => 'OK' ), false );
		update_option( Neighbors::GENERATED_OPTION, self::NOW, false );
		$this->assertNotFalse( get_option( Neighbors::SETTINGS_OPTION, false ) );
		$this->assertNotFalse( get_option( Neighbors::CENSUS_OPTION, false ) );

		update_option( 'handl_aicac_uninstall_policy', 'purge', false );
		\handl_aicac_uninstall_purge();

		$this->assertFalse( get_option( Neighbors::SETTINGS_OPTION, false ) );
		$this->assertFalse( get_option( Neighbors::CENSUS_OPTION, false ) );
		$this->assertFalse( get_option( Neighbors::GENERATED_OPTION, false ) );
	}

	public function test_render_is_read_only_on_policy_and_log(): void {
		Neighbors::save_settings( array( 'enabled' => true ) );
		update_option( Plugin::OPTION_KEY, array( 'default' => 'deny', 'keep' => true ), false );
		$log = $this->week_of_activity( 89, 11 );
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
		Neighbors::set_test_log( $log );
		$before_policy = get_option( Plugin::OPTION_KEY, null );
		$before_log    = get_option( Plugin::LOG_OPTION_KEY, null );
		ob_start();
		Neighbors::render_page();
		ob_end_clean();
		$this->assertSame( $before_policy, get_option( Plugin::OPTION_KEY, null ) );
		$this->assertSame( $before_log, get_option( Plugin::LOG_OPTION_KEY, null ) );
	}

	public function test_digest_skipped_when_no_existing_filter_and_line_available(): void {
		$digest = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-governance-digest.php' );
		$weekly = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-weekly-report.php' );
		$this->assertStringNotContainsString( 'neighbors', strtolower( $digest ) );
		$this->assertStringNotContainsString( 'neighbors', strtolower( $weekly ) );

		Neighbors::init();
		$this->assertNotContains( 'handl_aicac_digest_extra_lines', $GLOBALS['handl_aicac_test_added_filters'] );
		$this->assertNotContains( 'handl_aicac_weekly_digest_lines', $GLOBALS['handl_aicac_test_added_filters'] );

		Neighbors::save_settings( array( 'enabled' => true ) );
		Neighbors::set_test_log( $this->week_of_activity( 89, 11 ) );
		$line = Neighbors::digest_line();
		$this->assertStringContainsString( 'you deny 11%', $line );
		$appended = Neighbors::append_digest_line( array( 'keep' ) );
		$this->assertSame( 'keep', $appended[0] );
		$this->assertSame( $line, $appended[1] );
	}

	public function test_dashboard_widget_registers_only_when_enabled(): void {
		Neighbors::save_settings( array( 'enabled' => false ) );
		Neighbors::register_dashboard();
		Neighbors::save_settings( array( 'enabled' => true ) );
		Neighbors::register_dashboard();
		$this->assertTrue( Neighbors::is_enabled() );
	}
}
