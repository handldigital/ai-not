<?php
/**
 * AICAC-PREFLIGHT-SCAN (#297).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Preflight_Scan;
use HandL\AICAC\Provider_Map;
use PHPUnit\Framework\TestCase;

final class PreflightScanTest extends TestCase {

	/** @var list<string> */
	private array $created_slugs = array();

	protected function setUp(): void {
		parent::setUp();
		Preflight_Scan::reset_for_tests();
		$GLOBALS['handl_aicac_test_options']        = array();
		$GLOBALS['handl_aicac_test_added_actions']  = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		unset( $GLOBALS['handl_aicac_test_filters'] );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		update_option( Plugin::OPTION_KEY, array( 'log_enabled' => true, 'log_limit' => 200 ), false );

		$this->created_slugs = array();
		$root = $this->plugin_root();
		if ( ! is_dir( $root ) ) {
			mkdir( $root, 0777, true );
		}
	}

	protected function tearDown(): void {
		Preflight_Scan::reset_for_tests();
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		foreach ( $this->created_slugs as $slug ) {
			$this->rm_rf( $this->plugin_root() . '/' . $slug );
		}
		$this->created_slugs = array();
		unset( $GLOBALS['handl_aicac_test_filters'], $GLOBALS['handl_aicac_test_plugins'], $GLOBALS['handl_aicac_test_themes'], $GLOBALS['handl_aicac_test_theme_root'] );
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

	private function plugin_root(): string {
		$root = defined( 'WP_PLUGIN_DIR' ) ? (string) WP_PLUGIN_DIR : sys_get_temp_dir() . '/handl-aicac-plugins';
		if ( ! is_dir( $root ) ) {
			mkdir( $root, 0777, true );
		}
		return $root;
	}

	public function test_init_registers_upgrader_hook(): void {
		Preflight_Scan::instance()->init();
		$actions = $GLOBALS['handl_aicac_test_added_actions'] ?? array();
		$this->assertContains( 'upgrader_process_complete', $actions );
		$this->assertContains( 'admin_notices', $actions );
		$this->assertContains( 'admin_post_' . Preflight_Scan::ACTION_STARTER, $actions );
	}

	public function test_signatures_include_issue_hosts(): void {
		$map = Provider_Map::endpoint_signatures();
		$this->assertContains( 'api.openai.com', $map['openai']['hosts'] );
		$this->assertContains( 'api.anthropic.com', $map['anthropic']['hosts'] );
		$this->assertContains( 'generativelanguage.googleapis.com', $map['google']['hosts'] );
	}

	public function test_match_text_reads_provider_map_table(): void {
		$ids = Provider_Map::match_text( "curl https://api.openai.com/v1/chat\nAnthropic\\Client" );
		$this->assertSame( array( 'anthropic', 'openai' ), $ids );
	}

	public function test_scan_uses_filterable_signature_table(): void {
		$GLOBALS['handl_aicac_test_filters'][ Provider_Map::FILTER_SIGNATURES ] = static function ( array $map ): array {
			$map['fakeai'] = array(
				'label'   => 'FakeAI',
				'hosts'   => array(),
				'needles' => array( 'fake-ai.example.test' ),
			);
			return $map;
		};
		$this->plugin_tree(
			'fake-plug',
			array(
				'fake-plug.php' => "<?php\n// fake-ai.example.test\n",
			)
		);
		$result = Preflight_Scan::scan_and_record( 'fake-plug/fake-plug.php', 'install' );
		$this->assertContains( 'fakeai', $result['providers'] );
		$this->assertTrue( $result['notice'] );
	}

	public function test_install_with_known_endpoint_notices_and_logs(): void {
		$GLOBALS['handl_aicac_test_plugins'] = array(
			'ai-caller/ai-caller.php' => array( 'Name' => 'AI Caller' ),
		);
		$this->plugin_tree(
			'ai-caller',
			array(
				'ai-caller.php'   => "<?php\n// bootstrap\n",
				'includes/api.php' => "<?php\n\$url = 'https://api.openai.com/v1/chat/completions';\n\$other = 'https://api.anthropic.com/v1/messages';\n",
			)
		);

		$result = Preflight_Scan::scan_and_record( 'ai-caller/ai-caller.php', 'install' );
		$this->assertTrue( $result['notice'] );
		$this->assertSame( array( 'anthropic', 'openai' ), $result['providers'] );
		$this->assertSame( 1, $result['file_count'] );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertNotEmpty( $log );
		$last = $log[ array_key_last( $log ) ];
		$this->assertSame( Preflight_Scan::CHANNEL, $last['channel'] );
		$this->assertSame( 'ai-caller/ai-caller.php', $last['plugin'] );
		$this->assertSame( array( 'anthropic', 'openai' ), $last['providers'] );

		ob_start();
		Preflight_Scan::instance()->maybe_admin_notice();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'AI Caller contains references to Anthropic and OpenAI in 1 file. This scan does not confirm that data was sent.', $html );
		$this->assertStringContainsString( 'Add a Deny rule', $html );
		$this->assertStringContainsString( 'Review rules', $html );
		$this->assertStringContainsString( 'Dismiss', $html );
	}

	public function test_update_notices_only_when_endpoint_added(): void {
		$this->plugin_tree(
			'grow',
			array(
				'grow.php' => "<?php\n\$u = 'https://api.openai.com/v1';\n",
			)
		);
		$first = Preflight_Scan::scan_and_record( 'grow/grow.php', 'install' );
		$this->assertTrue( $first['notice'] );
		Preflight_Scan::dismiss_notice( 'plugin', 'grow/grow.php' );

		file_put_contents(
			$this->plugin_root() . '/grow/grow.php',
			"<?php\n\$u = 'https://api.openai.com/v1';\n"
		);
		$same = Preflight_Scan::scan_and_record( 'grow/grow.php', 'update' );
		$this->assertFalse( $same['notice'] );
		$this->assertSame( array(), Preflight_Scan::pending_notices() );

		file_put_contents(
			$this->plugin_root() . '/grow/extra.php',
			"<?php\n\$g = 'https://generativelanguage.googleapis.com/v1beta';\n"
		);
		$added = Preflight_Scan::scan_and_record( 'grow/grow.php', 'update' );
		$this->assertTrue( $added['notice'] );
		$this->assertContains( 'google', $added['providers'] );
		$this->assertContains( 'google', $added['added'] );
	}

	public function test_clean_plugin_is_quiet_debug_only(): void {
		$this->plugin_tree(
			'clean-plug',
			array(
				'clean-plug.php' => "<?php\necho 'hello';\n",
			)
		);
		$result = Preflight_Scan::scan_and_record( 'clean-plug/clean-plug.php', 'install' );
		$this->assertFalse( $result['notice'] );
		$this->assertSame( array(), $result['providers'] );
		$this->assertSame( array(), Preflight_Scan::pending_notices() );
		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertTrue( ! is_array( $log ) || array() === $log );
		$this->assertContains( 'clean-plug/clean-plug.php', $GLOBALS['handl_aicac_preflight_debug'] ?? array() );

		ob_start();
		Preflight_Scan::instance()->maybe_admin_notice();
		$html = (string) ob_get_clean();
		$this->assertSame( '', $html );
	}

	public function test_skips_vendor_and_minified_bundles(): void {
		$root = $this->plugin_tree(
			'skipy',
			array(
				'skipy.php'                 => "<?php\n",
				'vendor/pkg/openai.php'     => "<?php\n\$u='https://api.openai.com/v1';\n",
				'assets/app.min.js'         => 'fetch("https://api.anthropic.com/v1")',
				'includes/real.php'         => "<?php\n\$u='https://api.mistral.ai/v1';\n",
			)
		);
		$files = Preflight_Scan::list_scan_files( $root );
		foreach ( $files as $rel ) {
			$this->assertStringNotContainsString( 'vendor/', $rel );
			$this->assertStringNotContainsString( '.min.js', $rel );
		}
		$hit = Preflight_Scan::scan_directory( $root );
		$this->assertSame( array( 'mistral' ), $hit['providers'] );
	}

	public function test_caps_are_bounded(): void {
		$this->assertLessThanOrEqual( 512 * 1024, Preflight_Scan::MAX_FILE_BYTES );
		$this->assertLessThanOrEqual( 200, Preflight_Scan::MAX_FILES );
		$this->assertLessThanOrEqual( 5.0, Preflight_Scan::MAX_SCAN_SECONDS );
		$this->assertGreaterThan( 0, Preflight_Scan::MAX_FILES );
	}

	public function test_starter_rule_lands_deny(): void {
		$GLOBALS['handl_aicac_test_plugins'] = array(
			'ai-caller/ai-caller.php' => array( 'Name' => 'AI Caller' ),
		);
		$this->plugin_tree(
			'ai-caller',
			array(
				'ai-caller.php' => "<?php\n\$u='https://api.openai.com/v1';\n",
			)
		);
		Preflight_Scan::scan_and_record( 'ai-caller/ai-caller.php', 'install' );
		$this->assertNotEmpty( Preflight_Scan::pending_notices() );

		$ok = Preflight_Scan::apply_starter_rule( 'ai-caller/ai-caller.php' );
		$this->assertTrue( $ok );
		$policy = Policy::get_policy();
		$this->assertSame( 'deny', $policy['plugins']['ai-caller/ai-caller.php'] ?? null );
		$this->assertSame( array(), Preflight_Scan::pending_notices() );
	}

	public function test_upgrader_hook_installs_plugin(): void {
		$this->plugin_tree(
			'hooked',
			array(
				'hooked.php' => "<?php\n\$u='https://api.x.ai/v1';\n",
			)
		);
		Preflight_Scan::instance()->on_upgrader(
			null,
			array(
				'type'   => 'plugin',
				'action' => 'install',
				'plugin' => 'hooked/hooked.php',
			)
		);
		$row = Preflight_Scan::findings_for_plugin( 'hooked/hooked.php' );
		$this->assertIsArray( $row );
		$this->assertContains( 'xai', $row['providers'] );
	}

	public function test_notice_message_pluralizes_files(): void {
		$one = Preflight_Scan::notice_message( 'Theme X', array( 'openai' ), 1 );
		$this->assertSame(
			'Theme X contains references to OpenAI in 1 file. This scan does not confirm that data was sent.',
			$one
		);
		$many = Preflight_Scan::notice_message( 'Theme X', array( 'anthropic', 'openai' ), 3 );
		$this->assertSame(
			'Theme X contains references to Anthropic and OpenAI in 3 files. This scan does not confirm that data was sent.',
			$many
		);
	}

	public function test_plugin_row_meta_lists_endpoints(): void {
		$this->plugin_tree(
			'chippy',
			array(
				'chippy.php' => "<?php\n\$u='https://api.groq.com/openai/v1';\n",
			)
		);
		Preflight_Scan::scan_and_record( 'chippy/chippy.php', 'install' );
		$meta = Preflight_Scan::instance()->filter_plugin_row_meta( array(), 'chippy/chippy.php' );
		$this->assertNotEmpty( $meta );
		$this->assertStringContainsString( 'AI references found: Groq', $meta[0] );
	}

	public function test_on_upgrader_never_throws(): void {
		Preflight_Scan::instance()->on_upgrader( null, 'bad' );
		Preflight_Scan::instance()->on_upgrader(
			null,
			array(
				'type'   => 'plugin',
				'action' => 'install',
				'plugin' => '../evil.php',
			)
		);
		$this->assertTrue( true );
	}

	public function test_scan_all_lists_two_hits_and_omits_clean(): void {
		$GLOBALS['handl_aicac_test_plugins'] = array(
			'openai-plug/openai-plug.php'       => array( 'Name' => 'OpenAI Plug' ),
			'anthropic-plug/anthropic-plug.php' => array( 'Name' => 'Anthropic Plug' ),
			'clean-plug/clean-plug.php'         => array( 'Name' => 'Clean Plug' ),
		);
		$this->plugin_tree(
			'openai-plug',
			array( 'openai-plug.php' => "<?php\n\$u='https://api.openai.com/v1';\n" )
		);
		$this->plugin_tree(
			'anthropic-plug',
			array( 'anthropic-plug.php' => "<?php\n\$u='https://api.anthropic.com/v1';\n" )
		);
		$this->plugin_tree(
			'clean-plug',
			array( 'clean-plug.php' => "<?php\necho 'ok';\n" )
		);

		$before_policy = Policy::get_policy();
		$run           = Preflight_Scan::scan_all();
		$this->assertSame( 3, $run['scanned'] );
		$this->assertSame( 2, $run['hit_count'] );
		$ids = array_map(
			static function ( array $row ): string {
				return (string) $row['id'];
			},
			$run['hits']
		);
		$this->assertContains( 'openai-plug/openai-plug.php', $ids );
		$this->assertContains( 'anthropic-plug/anthropic-plug.php', $ids );
		$this->assertNotContains( 'clean-plug/clean-plug.php', $ids );
		foreach ( $run['hits'] as $hit ) {
			if ( 'openai-plug/openai-plug.php' === $hit['id'] ) {
				$this->assertContains( 'openai', $hit['providers'] );
				$this->assertSame( 1, $hit['file_count'] );
			}
			if ( 'anthropic-plug/anthropic-plug.php' === $hit['id'] ) {
				$this->assertContains( 'anthropic', $hit['providers'] );
				$this->assertSame( 1, $hit['file_count'] );
			}
		}
		$this->assertSame( array(), Preflight_Scan::pending_notices() );
		$this->assertSame( $before_policy['plugins'] ?? array(), Policy::get_policy()['plugins'] ?? array() );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertCount( 1, $log );
		$this->assertSame( 'scan_all', $log[0]['operation'] ?? '' );
		$this->assertSame( 2, $log[0]['hit_count'] ?? 0 );

		ob_start();
		Preflight_Scan::render_policy_tools_section();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Scan all installed plugins and themes', $html );
		$this->assertStringContainsString( 'OpenAI Plug', $html );
		$this->assertStringContainsString( 'Anthropic Plug', $html );
		$this->assertStringNotContainsString( 'Clean Plug', $html );
		$this->assertStringContainsString( 'Add a Deny rule', $html );
		$this->assertStringContainsString( 'Review rules', $html );
		$this->assertStringContainsString( 'Dismiss', $html );
	}

	public function test_scan_all_rerun_adds_one_activity_row(): void {
		$GLOBALS['handl_aicac_test_plugins'] = array(
			'openai-plug/openai-plug.php' => array( 'Name' => 'OpenAI Plug' ),
		);
		$this->plugin_tree(
			'openai-plug',
			array( 'openai-plug.php' => "<?php\n\$u='https://api.openai.com/v1';\n" )
		);
		Preflight_Scan::scan_all();
		Preflight_Scan::scan_all();
		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertCount( 2, $log );
		foreach ( $log as $row ) {
			$this->assertIsArray( $row );
			$this->assertSame( 'scan_all', $row['operation'] ?? '' );
		}
		$this->assertSame( array(), Preflight_Scan::pending_notices() );
	}

	public function test_scan_all_zero_hits_empty_state_and_run_row(): void {
		$GLOBALS['handl_aicac_test_plugins'] = array(
			'clean-plug/clean-plug.php' => array( 'Name' => 'Clean Plug' ),
		);
		$this->plugin_tree(
			'clean-plug',
			array( 'clean-plug.php' => "<?php\necho 'ok';\n" )
		);
		$run = Preflight_Scan::scan_all();
		$this->assertSame( 1, $run['scanned'] );
		$this->assertSame( 0, $run['hit_count'] );
		$this->assertSame( array(), $run['hits'] );
		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertCount( 1, $log );
		$this->assertSame( 'scan_all', $log[0]['operation'] ?? '' );
		$this->assertSame( 0, $log[0]['hit_count'] ?? -1 );

		ob_start();
		Preflight_Scan::render_policy_tools_section();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'No AI provider references to show.', $html );
		$cli = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-cli.php' );
		$this->assertStringContainsString( 'No AI provider references found.', $cli );
		$this->assertStringNotContainsString( 'handl-aicac-scan-all-results', $html );
	}

	public function test_scan_all_batches_when_inventory_exceeds_batch_size(): void {
		$plugins = array();
		$count   = 101;
		for ( $i = 0; $i < $count; $i++ ) {
			$slug = sprintf( 'sa-%03d', $i );
			$file = $slug . '/' . $slug . '.php';
			$plugins[ $file ] = array( 'Name' => 'SA ' . $i );
			$body = 0 === $i
				? "<?php\n\$u='https://api.openai.com/v1';\n"
				: "<?php\necho 'ok';\n";
			$this->plugin_tree( $slug, array( $slug . '.php' => $body ) );
		}
		$GLOBALS['handl_aicac_test_plugins'] = $plugins;
		$run = Preflight_Scan::scan_all();
		$this->assertSame( $count, $run['scanned'] );
		$this->assertGreaterThan( 1, $run['batch_count'] );
		$this->assertSame( Preflight_Scan::SCAN_ALL_BATCH, $run['batch_size'] );
		$this->assertSame( 1, $run['hit_count'] );
		$this->assertSame( 'sa-000/sa-000.php', $run['hits'][0]['id'] ?? '' );
	}

	public function test_scan_all_includes_themes_and_skips_self(): void {
		$GLOBALS['handl_aicac_test_plugins'] = array(
			'handl-ai-connector-access-control/handl-ai-connector-access-control.php' => array( 'Name' => 'AICAC' ),
		);
		$this->plugin_tree(
			'handl-ai-connector-access-control',
			array( 'handl-ai-connector-access-control.php' => "<?php\n\$u='https://api.openai.com/v1';\n" )
		);
		$theme_root = sys_get_temp_dir() . '/handl-aicac-themes';
		$GLOBALS['handl_aicac_test_theme_root'] = $theme_root;
		$GLOBALS['handl_aicac_test_themes']     = array( 'hit-theme' => array( 'Name' => 'Hit Theme' ) );
		$dir = $theme_root . '/hit-theme';
		if ( ! is_dir( $dir ) ) {
			mkdir( $dir, 0777, true );
		}
		file_put_contents( $dir . '/functions.php', "<?php\n\$u='https://api.anthropic.com/v1';\n" );

		$run = Preflight_Scan::scan_all();
		$ids = array_map(
			static function ( array $row ): string {
				return (string) $row['id'];
			},
			$run['hits']
		);
		$this->assertContains( 'hit-theme', $ids );
		$this->assertNotContains( 'handl-ai-connector-access-control/handl-ai-connector-access-control.php', $ids );

		$this->rm_rf( $dir );
		unset( $GLOBALS['handl_aicac_test_theme_root'], $GLOBALS['handl_aicac_test_themes'] );
	}

	public function test_cli_and_admin_wire_scan_all(): void {
		$cli = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-cli.php' );
		$this->assertStringContainsString( "add_command( 'handl-aicac scan-all'", $cli );
		$admin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringContainsString( 'Preflight_Scan::render_policy_tools_section()', $admin );
		$this->assertStringContainsString( "'scan_all' === \$posted_action", $admin );
		$this->assertStringContainsString( 'function handle_scan_all(', $admin );
	}
}
