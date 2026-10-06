<?php
/**
 * AICAC-SIGNATURE-FEED (#318).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Preflight_Scan;
use HandL\AICAC\Provider_Map;
use HandL\AICAC\Threat_Feed;
use PHPUnit\Framework\TestCase;

final class SignatureFeedTest extends TestCase {

	/** Test-only Ed25519 secret key (hex). Production key is not this value. */
	private const TEST_SK = '2c2972afb959602dfcf714921c496c86655b725bce3286c6de4d55c429ffc1375e4ad62aa0895f60b9eab237b544845c7e13da9348d2b6b3808bdc12b4597470';

	private const TEST_PK = '5e4ad62aa0895f60b9eab237b544845c7e13da9348d2b6b3808bdc12b4597470';

	/** @var list<string> */
	private array $created_slugs = array();

	protected function setUp(): void {
		parent::setUp();
		Threat_Feed::reset_for_tests();
		Preflight_Scan::reset_for_tests();
		$this->created_slugs = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Threat_Feed::OPTION_KEY );
		delete_option( Threat_Feed::SIGNATURE_OPTION_KEY );
		unset( $GLOBALS['handl_aicac_test_plugins'], $GLOBALS['handl_aicac_threat_feed_http'] );
		$GLOBALS['handl_aicac_test_filters'] = array(
			Threat_Feed::FILTER_PUBKEY => static function ( $pk ) {
				unset( $pk );
				return self::TEST_PK;
			},
		);
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
				'log_limit'   => 200,
				'default'     => 'observe',
			),
			false
		);
		$root = $this->plugin_root();
		if ( ! is_dir( $root ) ) {
			mkdir( $root, 0777, true );
		}
	}

	protected function tearDown(): void {
		Threat_Feed::reset_for_tests();
		Preflight_Scan::reset_for_tests();
		foreach ( $this->created_slugs as $slug ) {
			$this->rm_rf( $this->plugin_root() . '/' . $slug );
		}
		$this->created_slugs = array();
		unset(
			$GLOBALS['handl_aicac_test_plugins'],
			$GLOBALS['handl_aicac_threat_feed_http'],
			$GLOBALS['handl_aicac_test_filters']
		);
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Threat_Feed::OPTION_KEY );
		delete_option( Threat_Feed::SIGNATURE_OPTION_KEY );
		parent::tearDown();
	}

	private function rm_rf( string $dir ): void {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$it = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ( $it as $f ) {
			/** @var \SplFileInfo $f */
			$f->isDir() ? @rmdir( $f->getPathname() ) : @unlink( $f->getPathname() );
		}
		@rmdir( $dir );
	}

	private function plugin_root(): string {
		$root = defined( 'WP_PLUGIN_DIR' ) ? (string) WP_PLUGIN_DIR : sys_get_temp_dir() . '/handl-aicac-plugins';
		if ( ! is_dir( $root ) ) {
			mkdir( $root, 0777, true );
		}
		return $root;
	}

	/**
	 * @param array<string,string> $files
	 */
	private function plugin_tree( string $slug, array $files ): string {
		$this->created_slugs[] = $slug;
		$root = $this->plugin_root() . '/' . $slug;
		foreach ( $files as $rel => $body ) {
			$path = $root . '/' . $rel;
			$dir  = dirname( $path );
			if ( ! is_dir( $dir ) ) {
				mkdir( $dir, 0777, true );
			}
			file_put_contents( $path, $body );
		}
		return $root;
	}

	/**
	 * @param array<string,mixed> $payload
	 */
	private function sign_envelope( array $payload ): string {
		$canonical = json_encode( $payload, Threat_Feed::SIGN_FLAGS );
		$sk        = hex2bin( self::TEST_SK );
		$this->assertIsString( $canonical );
		$this->assertIsString( $sk );
		$sig = sodium_crypto_sign_detached( $canonical, $sk );

		return json_encode(
			array(
				'payload'   => $payload,
				'signature' => bin2hex( $sig ),
			),
			Threat_Feed::SIGN_FLAGS
		);
	}

	/**
	 * @param array<string,mixed> $extra
	 * @return array<string,mixed>
	 */
	private function base_payload( array $extra = array() ): array {
		return array_merge(
			array(
				'version'      => 1,
				'generated_at' => '2026-10-06T00:00:00Z',
				'advisories'   => array(),
			),
			$extra
		);
	}

	private function stub_http( int $code, string $body, string $etag = '"sig-v1"' ): void {
		$GLOBALS['handl_aicac_threat_feed_http'] = static function ( $url, $args ) use ( $code, $body, $etag ) {
			unset( $url, $args );
			return array(
				'response' => array( 'code' => $code ),
				'body'     => $body,
				'headers'  => array( 'etag' => $etag ),
			);
		};
	}

	/**
	 * @return array<string,mixed>
	 */
	private function newai_row(): array {
		return array(
			'id'      => 'newai',
			'label'   => 'NewAI',
			'hosts'   => array( 'newai.example' ),
			'needles' => array(),
		);
	}

	private function fetch_newai(): void {
		$body = $this->sign_envelope(
			$this->base_payload(
				array(
					'signatures' => array( $this->newai_row() ),
				)
			)
		);
		$this->stub_http( 200, $body );
		$stat = Threat_Feed::run( 1_700_000_100 );
		$this->assertSame( '', $stat['error'] );
		$this->assertTrue( $stat['fetched'] );
	}

	/**
	 * @param string $reason
	 * @return list<array<string,mixed>>
	 */
	private function log_rows_with_reason( string $reason ): array {
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		if ( ! is_array( $log ) ) {
			return array();
		}
		$out = array();
		foreach ( $log as $row ) {
			if ( is_array( $row ) && $reason === (string) ( $row['denial_reason'] ?? '' ) ) {
				$out[] = $row;
			}
		}
		return $out;
	}

	public function test_signed_newai_host_is_flagged_on_bulk_scan_with_payload_label(): void {
		$this->fetch_newai();
		$map = Provider_Map::endpoint_signatures();
		$this->assertArrayHasKey( 'newai', $map );
		$this->assertSame( 'NewAI', $map['newai']['label'] );
		$this->assertContains( 'newai.example', $map['newai']['hosts'] );
		$this->assertSame( 'NewAI', Provider_Map::signature_label( 'newai' ) );

		$GLOBALS['handl_aicac_test_plugins'] = array(
			'newai-plug/newai-plug.php' => array( 'Name' => 'NewAI Plug' ),
		);
		$this->plugin_tree(
			'newai-plug',
			array( 'newai-plug.php' => "<?php\n\$u='https://newai.example/v1';\n" )
		);
		$run = Preflight_Scan::scan_all( false );
		$this->assertSame( 1, $run['hit_count'] );
		$this->assertContains( 'newai', $run['hits'][0]['providers'] );
		$this->assertSame( 'NewAI', Preflight_Scan::provider_labels( array( 'newai' ) ) );
	}

	public function test_tampered_payload_is_rejected_before_parse_with_one_log_row(): void {
		$this->fetch_newai();
		$before = Threat_Feed::stored_signatures();
		$this->assertArrayHasKey( 'newai', $before );

		$payload = $this->base_payload(
			array(
				'signatures' => array(
					array(
						'id'    => 'evilai',
						'label' => 'EvilAI',
						'hosts' => array( 'evil.example' ),
					),
				),
			)
		);
		$envelope = json_decode( $this->sign_envelope( $payload ), true );
		$envelope['signature'] = str_repeat( 'ab', 64 );
		$this->stub_http( 200, json_encode( $envelope, Threat_Feed::SIGN_FLAGS ) );

		$stat = Threat_Feed::run( 1_700_000_200 );
		$this->assertSame( 'invalid_signature', $stat['error'] );
		$this->assertSame( $before, Threat_Feed::stored_signatures() );
		$this->assertArrayNotHasKey( 'evilai', Provider_Map::endpoint_signatures() );
		$rows = $this->log_rows_with_reason( 'invalid_signature' );
		$this->assertCount( 1, $rows );
		$this->assertSame( 'observe', $rows[0]['decision'] );
		$this->assertSame( 'threat_feed', $rows[0]['channel'] );
	}

	public function test_air_gap_skips_fetch_and_ignores_stored_additions(): void {
		$this->fetch_newai();
		$this->assertArrayHasKey( 'newai', Threat_Feed::stored_signatures() );

		$called = false;
		$GLOBALS['handl_aicac_threat_feed_http'] = static function () use ( &$called ) {
			$called = true;
			return array(
				'response' => array( 'code' => 200 ),
				'body'     => '{}',
			);
		};
		$GLOBALS['handl_aicac_test_filters'][ Threat_Feed::FILTER_DISABLED ] = static function () {
			return true;
		};

		$stat = Threat_Feed::run( 1_700_000_300 );
		$this->assertSame( 'disabled', $stat['error'] );
		$this->assertFalse( $called );
		$this->assertSame( array(), Threat_Feed::remote_signatures() );
		$this->assertArrayHasKey( 'newai', Threat_Feed::stored_signatures() );
		$this->assertArrayNotHasKey( 'newai', Provider_Map::endpoint_signatures() );
		$this->assertContains( 'api.openai.com', Provider_Map::endpoint_signatures()['openai']['hosts'] );

		$GLOBALS['handl_aicac_test_plugins'] = array(
			'newai-plug/newai-plug.php' => array( 'Name' => 'NewAI Plug' ),
		);
		$this->plugin_tree(
			'newai-plug',
			array( 'newai-plug.php' => "<?php\n\$u='https://newai.example/v1';\n" )
		);
		$run = Preflight_Scan::scan_all( false );
		$this->assertSame( 0, $run['hit_count'] );
	}

	public function test_remote_addition_never_shadows_bundled_provider_id(): void {
		$body = $this->sign_envelope(
			$this->base_payload(
				array(
					'signatures' => array(
						array(
							'id'    => 'openai',
							'label' => 'Shadow OpenAI',
							'hosts' => array( 'shadow.openai.example' ),
						),
						$this->newai_row(),
					),
				)
			)
		);
		$this->stub_http( 200, $body );
		$stat = Threat_Feed::run( 1_700_000_400 );
		$this->assertSame( '', $stat['error'] );

		$map = Provider_Map::endpoint_signatures();
		$this->assertSame( 'OpenAI', $map['openai']['label'] );
		$this->assertSame( array( 'api.openai.com' ), $map['openai']['hosts'] );
		$this->assertNotContains( 'shadow.openai.example', $map['openai']['hosts'] );
		$this->assertArrayHasKey( 'newai', $map );
		$this->assertSame( 'NewAI', $map['newai']['label'] );
		$this->assertArrayNotHasKey( 'openai', Threat_Feed::stored_signatures() );

		$rows = $this->log_rows_with_reason( 'signature_collision' );
		$this->assertCount( 1, $rows );
		$this->assertSame( 'openai', $rows[0]['provider'] );
	}

	public function test_omit_signatures_key_keeps_stored_set(): void {
		$this->fetch_newai();
		$body = $this->sign_envelope( $this->base_payload() );
		$this->stub_http( 200, $body, '"adv-only"' );
		$stat = Threat_Feed::run( 1_700_000_500 );
		$this->assertSame( '', $stat['error'] );
		$this->assertArrayHasKey( 'newai', Threat_Feed::stored_signatures() );
	}

	public function test_empty_signatures_array_clears_stored_set(): void {
		$this->fetch_newai();
		$body = $this->sign_envelope( $this->base_payload( array( 'signatures' => array() ) ) );
		$this->stub_http( 200, $body, '"sig-empty"' );
		$stat = Threat_Feed::run( 1_700_000_600 );
		$this->assertSame( '', $stat['error'] );
		$this->assertSame( array(), Threat_Feed::stored_signatures() );
		$this->assertArrayNotHasKey( 'newai', Provider_Map::endpoint_signatures() );
	}

	public function test_invalid_json_logs_once_and_keeps_store(): void {
		$this->fetch_newai();
		$before = Threat_Feed::stored_signatures();
		$this->stub_http( 200, '{not-json' );
		$stat = Threat_Feed::run( 1_700_000_700 );
		$this->assertSame( 'invalid_json', $stat['error'] );
		$this->assertSame( $before, Threat_Feed::stored_signatures() );
		$this->assertCount( 1, $this->log_rows_with_reason( 'invalid_json' ) );
	}

	public function test_cli_and_plugin_bootstrap_wire_threat_feed_status(): void {
		$cli = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-cli-threat-feed.php' );
		$this->assertStringContainsString( "add_command( 'handl-aicac threat-feed'", $cli );
		$this->assertStringContainsString( 'Threat feed is turned off.', $cli );
		$this->assertStringContainsString( 'No remote signatures stored.', $cli );
		$this->assertStringContainsString( 'Remote signatures: %d', $cli );
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-cli-threat-feed.php', $plugin );
		$this->assertStringContainsString( 'CLI_Threat_Feed::register()', $plugin );
		$this->assertGreaterThan(
			strrpos( $plugin, 'CLI_Rescan::register()' ),
			strrpos( $plugin, 'CLI_Threat_Feed::register()' )
		);
	}
}
