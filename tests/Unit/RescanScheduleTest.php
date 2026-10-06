<?php
/**
 * AICAC-RESCAN-SCHEDULE (#310).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Preflight_Scan;
use HandL\AICAC\Rescan_Schedule;
use PHPUnit\Framework\TestCase;

final class RescanScheduleTest extends TestCase {

	/** @var list<string> */
	private array $created_slugs = array();

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		Rescan_Schedule::reset_for_tests();
		Preflight_Scan::reset_for_tests();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$GLOBALS['handl_aicac_test_cron']             = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		unset( $GLOBALS['handl_aicac_test_filters'], $GLOBALS['handl_aicac_test_themes'], $GLOBALS['handl_aicac_test_theme_root'] );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Rescan_Schedule::OPTION_KEY );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
				'log_limit'   => 200,
				'alert_email' => 'ops@example.com',
			),
			false
		);
		update_option( 'admin_email', 'admin@example.com' );
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);
			return true;
		};
		$this->created_slugs = array();
		$root = $this->plugin_root();
		if ( ! is_dir( $root ) ) {
			mkdir( $root, 0777, true );
		}
	}

	protected function tearDown(): void {
		Rescan_Schedule::reset_for_tests();
		Preflight_Scan::reset_for_tests();
		foreach ( $this->created_slugs as $slug ) {
			$this->rm_rf( $this->plugin_root() . '/' . $slug );
		}
		$this->created_slugs = array();
		unset(
			$GLOBALS['handl_aicac_wp_mail'],
			$GLOBALS['handl_aicac_test_filters'],
			$GLOBALS['handl_aicac_test_plugins'],
			$GLOBALS['handl_aicac_test_themes'],
			$GLOBALS['handl_aicac_test_theme_root']
		);
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Rescan_Schedule::OPTION_KEY );
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

	private function plugin_tree( string $slug, array $files ): void {
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
	}

	public function test_init_registers_weekly_cron_and_site_health(): void {
		Rescan_Schedule::init();
		$actions = $GLOBALS['handl_aicac_test_added_actions'] ?? array();
		$this->assertContains( Rescan_Schedule::CRON_HOOK, $actions );
		$this->assertArrayHasKey( Rescan_Schedule::CRON_HOOK, $GLOBALS['handl_aicac_test_cron'] );
		$tests = Rescan_Schedule::register_site_health( array() );
		$this->assertArrayHasKey( Rescan_Schedule::SITE_HEALTH_SLUG, $tests['direct'] );
	}

	public function test_first_run_seeds_baseline_with_zero_alerts(): void {
		$GLOBALS['handl_aicac_test_plugins'] = array(
			'openai-plug/openai-plug.php' => array( 'Name' => 'OpenAI Plug' ),
			'clean-plug/clean-plug.php'   => array( 'Name' => 'Clean Plug' ),
		);
		$this->plugin_tree( 'openai-plug', array( 'openai-plug.php' => "<?php\n\$u='https://api.openai.com/v1';\n" ) );
		$this->plugin_tree( 'clean-plug', array( 'clean-plug.php' => "<?php\necho 'ok';\n" ) );
		$before_rules = Policy::get_policy()['plugins'] ?? array();

		$out = Rescan_Schedule::run( 1_700_000_000 );
		$this->assertTrue( $out['seeded'] );
		$this->assertSame( 0, $out['alerted'] );
		$this->assertSame( array(), self::$mails );
		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertTrue( ! is_array( $log ) || array() === $log );
		$state = Rescan_Schedule::get_state();
		$this->assertTrue( $state['seeded'] );
		$this->assertArrayHasKey( 'plugin:openai-plug/openai-plug.php:openai', $state['summary'] );
		$this->assertSame( $before_rules, Policy::get_policy()['plugins'] ?? array() );
	}

	public function test_new_plugin_alerts_once_then_silent(): void {
		$GLOBALS['handl_aicac_test_plugins'] = array(
			'clean-plug/clean-plug.php' => array( 'Name' => 'Clean Plug' ),
		);
		$this->plugin_tree( 'clean-plug', array( 'clean-plug.php' => "<?php\necho 'ok';\n" ) );
		$first = Rescan_Schedule::run( 1_700_000_000 );
		$this->assertSame( 0, $first['alerted'] );
		$this->assertSame( array(), self::$mails );

		$GLOBALS['handl_aicac_test_plugins']['openai-plug/openai-plug.php'] = array( 'Name' => 'OpenAI Plug' );
		$this->plugin_tree( 'openai-plug', array( 'openai-plug.php' => "<?php\n\$u='https://api.openai.com/v1';\n" ) );
		$before_rules = Policy::get_policy()['plugins'] ?? array();

		$second = Rescan_Schedule::run( 1_700_000_100 );
		$this->assertSame( 1, $second['alerted'] );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'New AI provider reference', self::$mails[0]['subject'] );
		$this->assertStringContainsString( 'does not confirm that data was sent', self::$mails[0]['message'] );
		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertCount( 1, $log );
		$this->assertSame( 'rescan_schedule', $log[0]['operation'] ?? '' );
		$this->assertSame( $before_rules, Policy::get_policy()['plugins'] ?? array() );

		self::$mails = array();
		$third       = Rescan_Schedule::run( 1_700_000_200 );
		$this->assertSame( 0, $third['alerted'] );
		$this->assertSame( array(), self::$mails );
		$log2 = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log2 );
		$this->assertCount( 1, $log2 );
	}

	public function test_unchanged_site_writes_only_timestamp(): void {
		$GLOBALS['handl_aicac_test_plugins'] = array(
			'clean-plug/clean-plug.php' => array( 'Name' => 'Clean Plug' ),
		);
		$this->plugin_tree( 'clean-plug', array( 'clean-plug.php' => "<?php\necho 'ok';\n" ) );
		Rescan_Schedule::run( 1_700_000_000 );
		$after_seed = Rescan_Schedule::get_state();
		Rescan_Schedule::run( 1_700_000_700 );
		$after_quiet = Rescan_Schedule::get_state();
		$this->assertSame( 1_700_000_700, $after_quiet['last_run_at'] );
		unset( $after_seed['last_run_at'], $after_quiet['last_run_at'] );
		$this->assertSame( $after_seed, $after_quiet );
	}

	public function test_collect_scan_does_not_write_scan_all_activity(): void {
		$GLOBALS['handl_aicac_test_plugins'] = array(
			'openai-plug/openai-plug.php' => array( 'Name' => 'OpenAI Plug' ),
		);
		$this->plugin_tree( 'openai-plug', array( 'openai-plug.php' => "<?php\n\$u='https://api.openai.com/v1';\n" ) );
		$run = Preflight_Scan::scan_all( false );
		$this->assertSame( 1, $run['hit_count'] );
		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertTrue( ! is_array( $log ) || array() === $log );
		$this->assertSame( array(), Preflight_Scan::last_run() );
	}

	public function test_disabled_unregisters_cron_and_skips_option_reads(): void {
		$GLOBALS['handl_aicac_test_filters'][ Rescan_Schedule::FILTER_DISABLED ] = static function () {
			return true;
		};
		$GLOBALS['handl_aicac_test_cron'][ Rescan_Schedule::CRON_HOOK ] = time() + 100;
		Rescan_Schedule::maybe_schedule();
		$this->assertArrayNotHasKey( Rescan_Schedule::CRON_HOOK, $GLOBALS['handl_aicac_test_cron'] );

		update_option( Rescan_Schedule::OPTION_KEY, array( 'seeded' => true, 'last_run_at' => 9 ), false );
		$before = get_option( Rescan_Schedule::OPTION_KEY );
		$reads  = Rescan_Schedule::option_reads();
		$out    = Rescan_Schedule::run( 1_700_000_000 );
		$this->assertTrue( $out['disabled'] );
		$this->assertSame( $reads, Rescan_Schedule::option_reads() );
		$this->assertSame( $before, get_option( Rescan_Schedule::OPTION_KEY ) );
		$this->assertSame( array(), self::$mails );

		$st = Rescan_Schedule::status();
		$this->assertTrue( $st['disabled'] );
		$snap = Rescan_Schedule::site_health_snapshot();
		$this->assertTrue( $snap['disabled'] );
		$line = Rescan_Schedule::site_health_line( $snap );
		$this->assertSame( 'Weekly plugin re-scan is turned off.', $line );
		$this->assertSame( $reads, Rescan_Schedule::option_reads() );
	}

	public function test_site_health_reports_last_scan_and_new_count(): void {
		$GLOBALS['handl_aicac_test_plugins'] = array(
			'clean-plug/clean-plug.php' => array( 'Name' => 'Clean Plug' ),
		);
		$this->plugin_tree( 'clean-plug', array( 'clean-plug.php' => "<?php\necho 'ok';\n" ) );
		Rescan_Schedule::run( 1_700_000_000 );
		$GLOBALS['handl_aicac_test_plugins']['openai-plug/openai-plug.php'] = array( 'Name' => 'OpenAI Plug' );
		$this->plugin_tree( 'openai-plug', array( 'openai-plug.php' => "<?php\n\$u='https://api.openai.com/v1';\n" ) );
		Rescan_Schedule::run( 1_700_000_100 );
		$snap = Rescan_Schedule::site_health_snapshot();
		$this->assertSame( 1_700_000_100, $snap['last_run_at'] );
		$this->assertSame( 1, $snap['new_findings'] );
		$line = Rescan_Schedule::site_health_line( $snap );
		$this->assertStringContainsString( 'Last scan:', $line );
		$this->assertStringContainsString( '1 new finding.', $line );
		$html = Rescan_Schedule::format_site_health_result( $snap );
		$this->assertSame( 'Weekly AI plugin re-scan', $html['label'] );
		$this->assertStringContainsString( '1 new finding.', $html['description'] );
	}

	public function test_cli_and_plugin_bootstrap_wire_rescan(): void {
		$cli = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-cli-rescan.php' );
		$this->assertStringContainsString( "add_command( 'handl-aicac rescan'", $cli );
		$this->assertStringContainsString( 'Weekly re-scan is turned off.', $cli );
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-rescan-schedule.php', $plugin );
		$this->assertStringContainsString( 'Rescan_Schedule::init()', $plugin );
		$this->assertGreaterThan(
			strrpos( $plugin, 'Why::init()' ),
			strrpos( $plugin, 'Rescan_Schedule::init()' )
		);
	}

	public function test_new_provider_on_known_plugin_alerts(): void {
		$GLOBALS['handl_aicac_test_plugins'] = array(
			'multi/multi.php' => array( 'Name' => 'Multi' ),
		);
		$this->plugin_tree( 'multi', array( 'multi.php' => "<?php\n\$u='https://api.openai.com/v1';\n" ) );
		Rescan_Schedule::run( 1_700_000_000 );
		$this->assertSame( array(), self::$mails );
		$this->plugin_tree(
			'multi',
			array( 'multi.php' => "<?php\n\$u='https://api.openai.com/v1';\n\$b='https://api.anthropic.com/v1';\n" )
		);
		$out = Rescan_Schedule::run( 1_700_000_100 );
		$this->assertSame( 1, $out['alerted'] );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'Anthropic', self::$mails[0]['message'] );
	}
}
