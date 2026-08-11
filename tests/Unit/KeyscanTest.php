<?php
/**
 * Unit tests for AICAC-KEYSCAN (#137).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Keyscan;
use PHPUnit\Framework\TestCase;

final class KeyscanTest extends TestCase {

	/** @var string */
	private string $tmpdir = '';

	protected function setUp(): void {
		$GLOBALS['handl_aicac_test_options'] = array();
		unset( $GLOBALS['handl_aicac_test_filters'] );
		delete_option( Keyscan::OPTION_KEY );
		$this->tmpdir = sys_get_temp_dir() . '/aicac-keyscan-' . getmypid();
		if ( ! is_dir( $this->tmpdir ) ) {
			mkdir( $this->tmpdir, 0777, true );
		}
	}

	protected function tearDown(): void {
		delete_option( Keyscan::OPTION_KEY );
		$this->rm_rf( $this->tmpdir );
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

	public function test_scan_text_detects_openai_anthropic_google(): void {
		$text = "const KEY = 'sk-abcdefghijklmnopqrstuvwxyz012345';\n"
			. "anthropic: sk-ant-api03-abcdefghijklmnopqrstuvwxyz\n"
			. 'google: AIzaSyA-abcdefghijklmnopqrstuvwxyz0123456789';
		$hits = Keyscan::scan_text( $text );
		$providers = array_column( $hits, 'provider' );
		$this->assertContains( 'openai', $providers );
		$this->assertContains( 'anthropic', $providers );
		$this->assertContains( 'google', $providers );
	}

	public function test_mask_shows_only_last_four(): void {
		$full = 'sk-abcdefghijklmnopqrstuvwxyz012345';
		$mask = Keyscan::mask( $full );
		$this->assertStringEndsWith( '2345', $mask );
		$this->assertStringNotContainsString( 'sk-abcdef', $mask );
		$this->assertSame( '2345', Keyscan::suffix_only( $full ) );
	}

	public function test_scan_file_detects_fixture_and_storage_never_has_full_key(): void {
		$plugin = 'fixture-ai-key/fixture-ai-key.php';
		$full   = 'sk-testfixturekeymaterialABCDEFG9999';
		$dir    = $this->tmpdir . '/fixture-ai-key';
		mkdir( $dir, 0777, true );
		file_put_contents( $dir . '/fixture-ai-key.php', "<?php\n// api key {$full}\n" );

		// Point WP_PLUGIN_DIR at our temp tree if possible — scan_file takes absolute path.
		$hits = Keyscan::scan_file( $dir . '/fixture-ai-key.php', $plugin, 'fixture-ai-key.php' );
		$this->assertNotEmpty( $hits );
		$this->assertSame( 'openai', $hits[0]['provider'] );
		$this->assertSame( $full, $hits[0]['key'] );

		// Merge via run_scan_chunk-like path: manually merge finding.
		$by_id = array();
		$ref   = new \ReflectionClass( Keyscan::class );
		$m     = $ref->getMethod( 'merge_finding' );
		$m->setAccessible( true );
		$m->invokeArgs( null, array( &$by_id, $hits[0], time() ) );

		$state = array( 'findings' => array_values( $by_id ) );
		update_option( Keyscan::OPTION_KEY, $state, false );

		$stored = get_option( Keyscan::OPTION_KEY );
		$this->assertFalse( Keyscan::state_contains_full_key( is_array( $stored ) ? $stored : array(), $full ) );
		$json = wp_json_encode( $stored );
		$this->assertIsString( $json );
		$this->assertStringNotContainsString( $full, $json );
		$this->assertStringContainsString( '9999', $json ); // last 4 only
	}

	public function test_active_findings_clear_when_plugin_deactivated(): void {
		$full = 'sk-clearwheninactivepluginKEY1234';
		update_option(
			Keyscan::OPTION_KEY,
			array(
				'findings'  => array(
					array(
						'id'         => 'x',
						'plugin'     => 'gone/plugin.php',
						'source'     => 'file',
						'location'   => 'a.php',
						'provider'   => 'openai',
						'suffix'     => '1234',
						'mask'       => '••••1234',
						'first_seen' => time(),
						'last_seen'  => time(),
					),
					array(
						'id'         => 'y',
						'plugin'     => 'active/plugin.php',
						'source'     => 'file',
						'location'   => 'b.php',
						'provider'   => 'openai',
						'suffix'     => 'abcd',
						'mask'       => '••••abcd',
						'first_seen' => time(),
						'last_seen'  => time(),
					),
				),
				'last_scan' => time(),
				'cursor'    => array(),
			),
			false
		);
		update_option( 'active_plugins', array( 'active/plugin.php' ), false );

		$active = Keyscan::active_findings();
		$this->assertCount( 1, $active );
		$this->assertSame( 'active/plugin.php', $active[0]['plugin'] );
		$this->assertFalse( Keyscan::state_contains_full_key( Keyscan::get_state(), $full ) );
	}

	public function test_list_plugin_files_skips_vendor_and_caps_extensions(): void {
		$root = $this->tmpdir . '/plug';
		mkdir( $root . '/vendor/pkg', 0777, true );
		mkdir( $root . '/includes', 0777, true );
		file_put_contents( $root . '/vendor/pkg/secret.php', 'sk-shouldnotlist' );
		file_put_contents( $root . '/includes/code.php', 'ok' );
		file_put_contents( $root . '/readme.md', 'skip ext' );

		$files = Keyscan::list_plugin_files( $root );
		$this->assertContains( 'includes/code.php', $files );
		foreach ( $files as $f ) {
			$this->assertStringNotContainsString( 'vendor/', $f );
		}
	}

	public function test_max_file_bytes_constant_is_capped(): void {
		$this->assertLessThanOrEqual( 512 * 1024, Keyscan::MAX_FILE_BYTES );
		$this->assertGreaterThan( 0, Keyscan::MAX_FILES_PER_CHUNK );
	}

	public function test_site_health_recommended_when_findings(): void {
		update_option(
			Keyscan::OPTION_KEY,
			array(
				'findings' => array(
					array(
						'id'       => 'z',
						'plugin'   => 'active/plugin.php',
						'source'   => 'file',
						'location' => 'x.php',
						'provider' => 'openai',
						'suffix'   => 'zzzz',
						'mask'     => '••••zzzz',
					),
				),
			),
			false
		);
		update_option( 'active_plugins', array( 'active/plugin.php' ), false );

		$ks  = Keyscan::instance();
		$res = $ks->run_site_health_test();
		$this->assertSame( 'recommended', $res['status'] );
		$this->assertStringNotContainsString( 'sk-', (string) ( $res['description'] ?? '' ) );
	}

	public function test_site_health_good_when_empty(): void {
		update_option( 'active_plugins', array(), false );
		delete_option( Keyscan::OPTION_KEY );
		$res = Keyscan::instance()->run_site_health_test();
		$this->assertSame( 'good', $res['status'] );
	}
}
