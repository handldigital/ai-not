<?php
/**
 * AICAC-ROOMMATES (#474).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Keyscan;
use HandL\AICAC\Plugin;
use HandL\AICAC\Roommates;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class RoommatesTest extends TestCase {

	private const KEY = 'sk-roommatesSHAREDKEY0001abcd';

	private const P1 = 'alpha/alpha.php';
	private const P2 = 'bravo/bravo.php';
	private const P3 = 'charlie/charlie.php';

	private const NOW = 1791800000;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_filters']          = array();
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		Roommates::reset_for_tests();
		Roommates::set_skip_cache( true );
		Roommates::set_test_now( self::NOW );
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_filters']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		Roommates::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private function three_plugin_hits(): array {
		return array(
			array(
				'plugin'   => self::P1,
				'provider' => 'openai',
				'key'      => self::KEY,
			),
			array(
				'plugin'   => self::P2,
				'provider' => 'openai',
				'key'      => self::KEY,
			),
			array(
				'plugin'   => self::P3,
				'provider' => 'openai',
				'key'      => self::KEY,
			),
		);
	}

	public function test_init_registers_admin_menu_once(): void {
		Roommates::init();
		Roommates::init();
		$hooks = $GLOBALS['handl_aicac_test_added_actions'];
		$this->assertSame( array( 'admin_menu' ), $hooks );
	}

	public function test_plugin_bootstrap_wires_roommates_at_bottom(): void {
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-roommates.php', $plugin );
		$this->assertStringContainsString( 'Roommates::init()', $plugin );
		$this->assertGreaterThan(
			(int) strrpos( $plugin, 'Deny_Receipt::init()' ),
			(int) strrpos( $plugin, 'Roommates::init()' )
		);
		$boot = (string) file_get_contents( HANDL_AICAC_DIR . '/tests/bootstrap.php' );
		$this->assertStringContainsString( 'class-handl-aicac-roommates.php', $boot );
	}

	public function test_three_plugins_one_credential_is_skeleton_key(): void {
		Roommates::set_test_hits( $this->three_plugin_hits() );
		Roommates::set_test_log(
			array(
				array(
					'ts'       => self::NOW - 60,
					'decision' => 'allow',
					'plugin'   => self::P1,
					'provider' => 'openai',
				),
				array(
					'ts'       => self::NOW - 30,
					'decision' => 'deny',
					'plugin'   => self::P2,
					'provider' => 'openai',
				),
				array(
					'ts'       => self::NOW - 10,
					'decision' => 'allow',
					'plugin'   => self::P3,
					'provider' => 'openai',
				),
				array(
					'ts'       => self::NOW - 5,
					'decision' => 'allow',
					'plugin'   => self::P1,
					'provider' => 'openai',
				),
				array(
					'ts'       => self::NOW - 1,
					'decision' => 'allow',
					'plugin'   => self::P2,
					'provider' => 'openai',
				),
			)
		);
		$data = Roommates::census();
		$this->assertCount( 1, $data['findings'] );
		$row = $data['findings'][0];
		$this->assertSame( Roommates::GRADE_SKELETON, $row['grade'] );
		$this->assertSame( array( self::P1, self::P2, self::P3 ), $row['plugins'] );
		$this->assertSame( array( 'openai' ), $row['providers'] );
		$this->assertSame( Roommates::fingerprint( self::KEY ), $row['fingerprint'] );
		$this->assertSame( Roommates::short_fingerprint( $row['fingerprint'] ), $row['short'] );
		$this->assertSame( self::NOW - 1, $row['last_seen'] );
		$this->assertSame( '', $data['status'] );
	}

	public function test_two_plugins_are_shared_one_is_solo(): void {
		$solo = 'sk-roommatesSOLOKEY0002wxyz';
		Roommates::set_test_hits(
			array(
				array(
					'plugin'   => self::P1,
					'provider' => 'openai',
					'key'      => self::KEY,
				),
				array(
					'plugin'   => self::P2,
					'provider' => 'openai',
					'key'      => self::KEY,
				),
				array(
					'plugin'   => self::P3,
					'provider' => 'anthropic',
					'key'      => $solo,
				),
			)
		);
		$data = Roommates::census();
		$this->assertCount( 2, $data['findings'] );
		$this->assertSame( Roommates::GRADE_SHARED, $data['findings'][0]['grade'] );
		$this->assertSame( array( self::P1, self::P2 ), $data['findings'][0]['plugins'] );
		$this->assertSame( Roommates::GRADE_SOLO, $data['findings'][1]['grade'] );
		$this->assertSame( array( self::P3 ), $data['findings'][1]['plugins'] );
	}

	public function test_raw_key_never_in_option_or_html(): void {
		Roommates::set_skip_cache( false );
		Roommates::set_test_hits( $this->three_plugin_hits() );
		ob_start();
		Roommates::render_page();
		$html = (string) ob_get_clean();
		$stored = get_option( Roommates::CENSUS_OPTION, array() );
		$this->assertStringNotContainsString( self::KEY, $html );
		$this->assertStringNotContainsString( 'SHAREDKEY', $html );
		$this->assertFalse( Roommates::stored_contains_raw_key( $stored, self::KEY ) );
		$this->assertStringContainsString( 'SKELETON-KEY', $html );
		$this->assertStringContainsString( self::P1, $html );
		$this->assertStringContainsString( self::P2, $html );
		$this->assertStringContainsString( self::P3, $html );
		$fp = Roommates::fingerprint( self::KEY );
		$this->assertStringContainsString( Roommates::short_fingerprint( $fp ), $html );
		$this->assertArrayHasKey( 'findings', is_array( $stored ) ? $stored : array() );
		$this->assertSame( $fp, $stored['findings'][0]['fingerprint'] );
	}

	public function test_render_is_read_only_on_policy_and_log(): void {
		Roommates::set_test_hits( $this->three_plugin_hits() );
		update_option( Plugin::OPTION_KEY, array( 'default' => 'deny', 'keep' => true ), false );
		$log = array(
			array(
				'ts'       => self::NOW,
				'decision' => 'allow',
				'plugin'   => self::P1,
				'provider' => 'openai',
			),
		);
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
		Roommates::set_test_log( $log );
		$before_policy = get_option( Plugin::OPTION_KEY, null );
		$before_log    = get_option( Plugin::LOG_OPTION_KEY, null );
		ob_start();
		Roommates::render_page();
		ob_end_clean();
		$this->assertSame( $before_policy, get_option( Plugin::OPTION_KEY, null ) );
		$this->assertSame( $before_log, get_option( Plugin::LOG_OPTION_KEY, null ) );
	}

	public function test_insufficient_data_when_too_few_logged_calls(): void {
		Roommates::set_test_hits( array() );
		Roommates::set_test_log(
			array(
				array(
					'ts'       => self::NOW,
					'decision' => 'allow',
					'plugin'   => self::P1,
					'provider' => 'openai',
				),
			)
		);
		$data = Roommates::census();
		$this->assertSame( Roommates::GRADE_INSUFFICIENT, $data['status'] );
		$this->assertSame( array(), $data['findings'] );
		ob_start();
		Roommates::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'INSUFFICIENT-DATA', $html );
		$this->assertStringNotContainsString( 'No API credentials found.', $html );
	}

	public function test_empty_state_when_enough_calls_and_no_keys(): void {
		$log = array();
		for ( $i = 0; $i < 5; $i++ ) {
			$log[] = array(
				'ts'       => self::NOW - $i,
				'decision' => 'allow',
				'plugin'   => self::P1,
				'provider' => 'openai',
			);
		}
		Roommates::set_test_hits( array() );
		Roommates::set_test_log( $log );
		ob_start();
		Roommates::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'No API credentials found.', $html );
		$this->assertStringNotContainsString( '<tbody>', $html );
	}

	public function test_log_scan_consumes_keyscan_scan_text(): void {
		$this->assertTrue( class_exists( Keyscan::class, false ) );
		$this->assertTrue( method_exists( Keyscan::class, 'scan_text' ) );
		$hits = Keyscan::scan_text( 'bearer ' . self::KEY );
		$this->assertNotSame( array(), $hits );
		Roommates::set_test_hits( null );
		Roommates::set_test_log(
			array(
				array(
					'ts'       => self::NOW - 4,
					'decision' => 'allow',
					'plugin'   => self::P1,
					'provider' => 'openai',
					'prompt'   => 'using ' . self::KEY,
				),
				array(
					'ts'       => self::NOW - 3,
					'decision' => 'allow',
					'plugin'   => self::P2,
					'provider' => 'openai',
					'prompt'   => 'using ' . self::KEY,
				),
				array(
					'ts'       => self::NOW - 2,
					'decision' => 'allow',
					'plugin'   => self::P3,
					'provider' => 'openai',
					'prompt'   => 'using ' . self::KEY,
				),
				array(
					'ts'       => self::NOW - 1,
					'decision' => 'allow',
					'plugin'   => self::P1,
					'provider' => 'openai',
				),
				array(
					'ts'       => self::NOW,
					'decision' => 'allow',
					'plugin'   => self::P2,
					'provider' => 'openai',
				),
			)
		);
		$data = Roommates::census();
		$this->assertCount( 1, $data['findings'] );
		$this->assertSame( Roommates::GRADE_SKELETON, $data['findings'][0]['grade'] );
		$this->assertSame( array( self::P1, self::P2, self::P3 ), $data['findings'][0]['plugins'] );
		ob_start();
		Roommates::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringNotContainsString( self::KEY, $html );
	}

	public function test_fingerprint_is_salted_hmac_not_raw(): void {
		$fp = Roommates::fingerprint( self::KEY );
		$this->assertSame( 64, strlen( $fp ) );
		$this->assertSame( $fp, hash_hmac( 'sha256', self::KEY, wp_salt( 'auth' ) ) );
		$this->assertNotSame( self::KEY, $fp );
		$this->assertSame( 12, strlen( Roommates::short_fingerprint( $fp ) ) );
	}
}
