<?php
/**
 * AICAC-LUGGAGE (#475).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Luggage;
use HandL\AICAC\Plugin;
use HandL\AICAC\Touched;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class LuggageTest extends TestCase {

	private const PACKED_PLUGIN = 'vision/vision.php';
	private const URL_PLUGIN    = 'caption/caption.php';
	private const HOME_PLUGIN   = 'chat/chat.php';
	private const NOW           = 1791800000;
	private const AI_URL        = 'https://api.openai.com/v1/chat/completions';
	private const PAYLOAD       = 'SECRET-PAYLOAD-BYTES-SHOULD-NEVER-PERSIST';
	private const FILE          = 'hero.png';
	private const MIME          = 'image/png';
	private const SIZE          = 4096;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_filters']          = array();
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$GLOBALS['handl_aicac_test_added_filters']    = array();
		Luggage::reset_for_tests();
		Luggage::set_skip_cache( true );
		Luggage::set_test_now( self::NOW );
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_filters']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_added_filters'] = array();
		Luggage::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * @return array<string,mixed>
	 */
	private function packed_args(): array {
		return array(
			'timeout'   => 5,
			'sslverify' => true,
			'headers'   => array(
				'content-type' => 'multipart/form-data; boundary=----luggage',
			),
			'body'      => array(
				'file' => array(
					'name'     => self::FILE,
					'type'     => self::MIME,
					'tmp_name' => '/var/www/wp-content/uploads/2026/10/' . self::FILE,
					'size'     => self::SIZE,
					'error'    => 0,
					'bits'     => self::PAYLOAD,
				),
			),
			'_probe'    => 'keep-me',
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	private function url_args(): array {
		return array(
			'timeout'   => 5,
			'sslverify' => true,
			'body'      => '{"image":"https://example.com/wp-content/uploads/2026/09/cat.jpg","prompt":"' . self::PAYLOAD . '"}',
			'_probe'    => 'keep-me',
		);
	}

	public function test_init_registers_http_filter_and_admin_menu_once(): void {
		Luggage::init();
		Luggage::init();
		$this->assertSame( array( 'http_request_args' ), $GLOBALS['handl_aicac_test_added_filters'] );
		$this->assertSame( array( 'admin_menu' ), $GLOBALS['handl_aicac_test_added_actions'] );
		$this->assertSame( Luggage::FRAMING, 'report_only_never_mutates_request_args' );
		$this->assertSame( 0, strpos( Luggage::CENSUS_OPTION, 'handl_aicac_luggage' ) );
		$this->assertSame( 0, strpos( Luggage::SHIPMENTS_OPTION, 'handl_aicac_luggage' ) );
	}

	public function test_plugin_bootstrap_wires_luggage_at_bottom(): void {
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-luggage.php', $plugin );
		$this->assertStringContainsString( 'Luggage::init()', $plugin );
		$this->assertGreaterThan(
			(int) strrpos( $plugin, 'Roommates::init()' ),
			(int) strrpos( $plugin, 'Luggage::init()' )
		);
		$boot = (string) file_get_contents( HANDL_AICAC_DIR . '/tests/bootstrap.php' );
		$this->assertStringContainsString( 'class-handl-aicac-luggage.php', $boot );
	}

	public function test_observe_returns_args_unchanged(): void {
		$args = $this->packed_args();
		$copy = $args;
		Luggage::set_test_plugin( self::PACKED_PLUGIN );
		$out  = Luggage::observe( $args, self::AI_URL );
		$this->assertSame( $copy, $out );
		$this->assertSame( $copy, $args );
		$this->assertSame( 'keep-me', $out['_probe'] );
		$this->assertSame( self::PAYLOAD, $out['body']['file']['bits'] );
	}

	public function test_multipart_uploads_file_is_packed_suitcase(): void {
		Luggage::set_test_plugin( self::PACKED_PLUGIN );
		Luggage::observe( $this->packed_args(), self::AI_URL );
		Luggage::set_test_log(
			array(
				array(
					'ts'       => self::NOW,
					'decision' => 'allow',
					'plugin'   => self::PACKED_PLUGIN,
					'provider' => 'openai',
				),
			)
		);
		$data = Luggage::census();
		$this->assertCount( 1, $data['findings'] );
		$row = $data['findings'][0];
		$this->assertSame( Luggage::GRADE_PACKED, $row['grade'] );
		$this->assertSame( self::PACKED_PLUGIN, $row['plugin'] );
		$this->assertSame( array( 'openai' ), $row['providers'] );
		$this->assertSame( self::SIZE, $row['bytes'] );
		$this->assertSame( self::FILE, $row['files'][0]['filename'] );
		$this->assertSame( self::MIME, $row['files'][0]['mime'] );
		$this->assertSame( self::SIZE, $row['files'][0]['size'] );
		$this->assertContains( self::MIME, $row['types'] );
		$this->assertSame( self::NOW, $row['last_shipment'] );
	}

	public function test_url_reference_is_day_tripper_and_no_media_is_homebody(): void {
		Luggage::set_test_plugin( self::URL_PLUGIN );
		Luggage::observe( $this->url_args(), self::AI_URL );
		Luggage::set_test_log(
			array(
				array(
					'ts'       => self::NOW - 20,
					'decision' => 'allow',
					'plugin'   => self::URL_PLUGIN,
					'provider' => 'openai',
				),
				array(
					'ts'       => self::NOW - 10,
					'decision' => 'allow',
					'plugin'   => self::HOME_PLUGIN,
					'provider' => 'anthropic',
				),
			)
		);
		$data = Luggage::census();
		$by   = array();
		foreach ( $data['findings'] as $row ) {
			$by[ $row['plugin'] ] = $row;
		}
		$this->assertSame( Luggage::GRADE_DAYTRIP, $by[ self::URL_PLUGIN ]['grade'] );
		$this->assertSame( 'cat.jpg', $by[ self::URL_PLUGIN ]['files'][0]['filename'] );
		$this->assertSame( 0, $by[ self::URL_PLUGIN ]['bytes'] );
		$this->assertSame( Luggage::GRADE_HOMEBODY, $by[ self::HOME_PLUGIN ]['grade'] );
		$this->assertSame( array(), $by[ self::HOME_PLUGIN ]['files'] );
		$this->assertSame( array( 'anthropic' ), $by[ self::HOME_PLUGIN ]['providers'] );
	}

	public function test_payload_contents_never_stored(): void {
		Luggage::set_skip_cache( false );
		Luggage::set_test_plugin( self::PACKED_PLUGIN );
		Luggage::observe( $this->packed_args(), self::AI_URL );
		Luggage::set_test_plugin( self::URL_PLUGIN );
		Luggage::observe( $this->url_args(), self::AI_URL );
		ob_start();
		Luggage::render_page();
		$html      = (string) ob_get_clean();
		$census    = get_option( Luggage::CENSUS_OPTION, array() );
		$shipments = get_option( Luggage::SHIPMENTS_OPTION, array() );
		$this->assertFalse( Luggage::stored_contains_payload( $census, self::PAYLOAD ) );
		$this->assertFalse( Luggage::stored_contains_payload( $shipments, self::PAYLOAD ) );
		$this->assertStringNotContainsString( self::PAYLOAD, $html );
		$this->assertStringNotContainsString( 'SECRET-PAYLOAD', $html );
		$json = (string) wp_json_encode( array( $census, $shipments ) );
		$this->assertStringNotContainsString( self::PAYLOAD, $json );
		$this->assertStringNotContainsString( '"bits"', $json );
		$this->assertStringContainsString( self::FILE, $html );
		$this->assertStringContainsString( Luggage::GRADE_PACKED, $html );
	}

	public function test_activity_log_upload_url_is_day_tripper_without_http_observe(): void {
		Luggage::set_test_log(
			array(
				array(
					'ts'       => self::NOW,
					'decision' => 'allow',
					'plugin'   => self::URL_PLUGIN,
					'provider' => 'openai',
					'url'      => 'https://site.example/wp-content/uploads/2026/01/logo.webp',
				),
			)
		);
		$data = Luggage::census();
		$this->assertSame( Luggage::GRADE_DAYTRIP, $data['findings'][0]['grade'] );
		$this->assertSame( 'logo.webp', $data['findings'][0]['files'][0]['filename'] );
	}

	public function test_empty_state_copy(): void {
		ob_start();
		Luggage::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Outbound media', $html );
		$this->assertStringContainsString( 'No AI calls in the activity log yet.', $html );
		$this->assertStringNotContainsString( '<tbody>', $html );
	}

	public function test_render_is_read_only_on_policy_and_log(): void {
		Luggage::set_test_plugin( self::PACKED_PLUGIN );
		update_option( Plugin::OPTION_KEY, array( 'default' => 'deny', 'keep' => true ), false );
		$log = array(
			array(
				'ts'       => self::NOW,
				'decision' => 'allow',
				'plugin'   => self::PACKED_PLUGIN,
				'provider' => 'openai',
			),
		);
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
		$before_policy = get_option( Plugin::OPTION_KEY, null );
		$before_log    = get_option( Plugin::LOG_OPTION_KEY, null );
		Luggage::observe( $this->packed_args(), self::AI_URL );
		ob_start();
		Luggage::render_page();
		ob_end_clean();
		$this->assertSame( $before_policy, get_option( Plugin::OPTION_KEY, null ) );
		$this->assertSame( $before_log, get_option( Plugin::LOG_OPTION_KEY, null ) );
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-luggage.php' );
		$this->assertStringNotContainsString( 'admin_post_', $src );
		$this->assertStringNotContainsString( 'policy.php', $src );
	}

	public function test_non_provider_host_is_not_sampled(): void {
		Luggage::set_test_plugin( self::PACKED_PLUGIN );
		Luggage::observe( $this->packed_args(), 'https://wordpress.org/news/' );
		$this->assertSame( array(), Luggage::read_shipments() );
	}

	public function test_attachment_id_is_day_tripper_and_touched_is_read_only(): void {
		Luggage::set_test_plugin( self::URL_PLUGIN );
		update_option( Touched::INDEX_OPTION, array( 42 ), false );
		$args = array(
			'body' => 'describe attachment_id=42 please',
		);
		Luggage::observe( $args, self::AI_URL );
		$ships = Luggage::read_shipments();
		$this->assertCount( 1, $ships );
		$this->assertSame( Luggage::KIND_ATTACHMENT, $ships[0]['kind'] );
		$this->assertSame( 42, $ships[0]['attachment_id'] );
		$this->assertTrue( $ships[0]['touched'] );
		$before = get_option( Touched::INDEX_OPTION, null );
		Luggage::census();
		$this->assertSame( $before, get_option( Touched::INDEX_OPTION, null ) );
	}

	public function test_fence_files_untouched(): void {
		$plugin = HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php';
		$boot   = HANDL_AICAC_DIR . '/tests/bootstrap.php';
		$files  = array(
			HANDL_AICAC_DIR . '/includes/class-handl-aicac-handshake.php',
			HANDL_AICAC_DIR . '/includes/class-handl-aicac-touched.php',
			HANDL_AICAC_DIR . '/includes/class-handl-aicac-provider-map.php',
			HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php',
			HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy.php',
			HANDL_AICAC_DIR . '/readme.txt',
		);
		foreach ( $files as $file ) {
			$this->assertFileExists( $file );
		}
		$this->assertStringContainsString( 'class-handl-aicac-luggage.php', (string) file_get_contents( $plugin ) );
		$this->assertStringContainsString( 'class-handl-aicac-luggage.php', (string) file_get_contents( $boot ) );
	}
}
