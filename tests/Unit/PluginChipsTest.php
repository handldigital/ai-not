<?php
/**
 * Unit tests for Plugins-screen AI status chips (AICAC-PLUGIN-ROW-CHIPS / #272).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Caps;
use HandL\AICAC\Plugin;
use HandL\AICAC\Plugin_Chips;
use PHPUnit\Framework\TestCase;

final class PluginChipsTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_caps']             = array(
			Caps::MANAGE => true,
			Caps::VIEW   => true,
		);
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$GLOBALS['handl_aicac_test_added_filters']    = array();
		unset( $GLOBALS['handl_aicac_test_filters'], $GLOBALS['handl_aicac_test_option_reads'] );
		Plugin_Chips::reset_cache();
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_options'],
			$GLOBALS['handl_aicac_test_caps'],
			$GLOBALS['handl_aicac_test_filters'],
			$GLOBALS['handl_aicac_test_added_actions'],
			$GLOBALS['handl_aicac_test_added_filters'],
			$GLOBALS['handl_aicac_test_option_reads']
		);
		Plugin_Chips::reset_cache();
	}

	public function test_init_registers_plugins_screen_hooks(): void {
		Plugin_Chips::instance()->init();
		$actions = $GLOBALS['handl_aicac_test_added_actions'] ?? array();
		$filters = $GLOBALS['handl_aicac_test_added_filters'] ?? array();
		$this->assertContains( 'admin_enqueue_scripts', $actions );
		$this->assertContains( 'after_plugin_row', $actions );
		$this->assertContains( 'plugin_row_meta', $filters );
	}

	public function test_build_index_statuses_match_acceptance_cases(): void {
		$now = 1_700_000_000;
		$policy = array(
			'plugins'    => array(
				'allow-me/allow-me.php' => 'allow',
				'deny-me/deny-me.php'   => 'deny',
			),
			'audit_only' => false,
		);
		$log = array(
			array(
				'ts'       => $now - 100,
				'decision' => 'allow',
				'plugin'   => 'allow-me/allow-me.php',
			),
			array(
				'ts'       => $now - 90,
				'decision' => 'allow',
				'plugin'   => 'watched/watched.php',
			),
			array(
				'ts'           => $now - 80,
				'decision'     => 'deny',
				'plugin'       => 'stormy/stormy.php',
				'retry_storm'  => true,
				'count'        => 12,
			),
			array(
				'ts'       => $now - 70,
				'decision' => 'deny',
				'plugin'   => 'deny-me/deny-me.php',
			),
			// Outside week — must not inflate deny count.
			array(
				'ts'       => $now - ( WEEK_IN_SECONDS + 100 ),
				'decision' => 'deny',
				'plugin'   => 'stormy/stormy.php',
				'count'    => 99,
			),
		);

		$index = Plugin_Chips::build_index( $policy, $log, $now );

		$this->assertSame( 'allowed', $index['allow-me/allow-me.php']['status'] );
		$this->assertSame( 'AI: Allowed', $index['allow-me/allow-me.php']['label'] );

		$this->assertSame( 'denied', $index['deny-me/deny-me.php']['status'] );
		$this->assertSame( 'AI: Denied', $index['deny-me/deny-me.php']['label'] );

		$this->assertSame( 'watched', $index['watched/watched.php']['status'] );
		$this->assertSame( 'AI: Watched', $index['watched/watched.php']['label'] );

		$this->assertSame( 'denies_week', $index['stormy/stormy.php']['status'] );
		$this->assertTrue( $index['stormy/stormy.php']['has_storm'] );
		$this->assertSame( 12, $index['stormy/stormy.php']['deny_count'] );
		$this->assertStringContainsString( '12 denies this week', $index['stormy/stormy.php']['label'] );

		$never = Plugin_Chips::chip_for_plugin( 'quiet/quiet.php', $policy, $policy['plugins'], false, false, 0, false );
		$this->assertSame( 'never_seen', $never['status'] );
		$this->assertSame( 'AI: never seen', $never['label'] );
	}

	public function test_chip_deep_links_to_rules_focus(): void {
		$chip = Plugin_Chips::chip_for_plugin(
			'acme/acme.php',
			array(),
			array( 'acme/acme.php' => 'deny' ),
			false,
			false,
			0,
			false
		);
		$html = Plugin_Chips::render_chip_anchor( $chip );
		$this->assertStringContainsString( 'handl_aicac_focus_plugin=', $chip['url'] );
		$this->assertStringContainsString( 'handl-aicac-rule-', $chip['url'] );
		$this->assertStringContainsString( 'href=', $html );
		$this->assertStringContainsString( 'title=', $html );
	}

	public function test_capability_gate_hides_chips_for_editor_without_caps(): void {
		$GLOBALS['handl_aicac_test_caps'] = array(
			Caps::MANAGE => false,
			Caps::VIEW   => false,
		);
		$GLOBALS['handl_aicac_test_options'] = array(
			Plugin::OPTION_KEY     => array( 'plugins' => array( 'x/x.php' => 'deny' ) ),
			Plugin::LOG_OPTION_KEY => array(),
		);

		$this->assertSame( '', Plugin_Chips::chip_html( 'x/x.php' ) );

		$chips = new Plugin_Chips();
		$meta  = $chips->filter_plugin_row_meta( array( 'Visit site' ), 'x/x.php' );
		$this->assertSame( array( 'Visit site' ), $meta );
	}

	public function test_auditor_view_cap_sees_chips(): void {
		$GLOBALS['handl_aicac_test_caps'] = array(
			Caps::MANAGE => false,
			Caps::VIEW   => true,
		);
		$GLOBALS['handl_aicac_test_options'] = array(
			Plugin::OPTION_KEY     => array(
				'plugins' => array( 'x/x.php' => 'deny' ),
			),
			Plugin::LOG_OPTION_KEY => array(),
		);
		Plugin_Chips::reset_cache();

		$html = Plugin_Chips::chip_html( 'x/x.php' );
		$this->assertStringContainsString( 'AI: Denied', $html );
		$this->assertStringContainsString( 'handl-aicac-plugin-chip--denied', $html );
	}

	public function test_filter_disables_chips(): void {
		$GLOBALS['handl_aicac_test_filters'][ Plugin_Chips::FILTER ] = static function () {
			return false;
		};
		$GLOBALS['handl_aicac_test_options'] = array(
			Plugin::OPTION_KEY     => array( 'plugins' => array( 'x/x.php' => 'deny' ) ),
			Plugin::LOG_OPTION_KEY => array(),
		);

		$this->assertFalse( Plugin_Chips::is_enabled() );
		$this->assertSame( '', Plugin_Chips::chip_html( 'x/x.php' ) );
	}

	public function test_warm_index_once_then_row_lookups_add_no_option_reads(): void {
		$now = 1_700_000_000;
		$GLOBALS['handl_aicac_test_options'] = array(
			Plugin::OPTION_KEY => array(
				'plugins'     => array(
					'a/a.php' => 'allow',
					'b/b.php' => 'deny',
				),
				'log_enabled' => true,
			),
			Plugin::LOG_OPTION_KEY => array(
				array(
					'ts'       => $now - 10,
					'decision' => 'allow',
					'plugin'   => 'a/a.php',
				),
			),
		);

		$reads = 0;
		$GLOBALS['handl_aicac_test_option_read_counter'] = &$reads;

		// Instrument via filter on get_option store access: wrap by recounting keys touched.
		Plugin_Chips::reset_cache();
		Plugin_Chips::warm_index( $now );

		$options_snapshot = $GLOBALS['handl_aicac_test_options'];
		// Empty the store — accidental get_option would return defaults / empty policy.
		$GLOBALS['handl_aicac_test_options'] = array();

		for ( $i = 0; $i < 40; $i++ ) {
			$html = Plugin_Chips::chip_html( 'a/a.php' );
			$this->assertStringContainsString( 'AI: Allowed', $html );
			$html = Plugin_Chips::chip_html( 'b/b.php' );
			$this->assertStringContainsString( 'AI: Denied', $html );
			$html = Plugin_Chips::chip_html( 'never/never.php' );
			$this->assertStringContainsString( 'AI: never seen', $html );
		}

		// Store still empty — warm path did not re-enter get_option/get_policy.
		$this->assertSame( array(), $GLOBALS['handl_aicac_test_options'] );
		$GLOBALS['handl_aicac_test_options'] = $options_snapshot;
	}

	public function test_css_asset_exists(): void {
		$path = HANDL_AICAC_DIR . '/assets/plugin-chips.css';
		$this->assertFileExists( $path );
		$css = (string) file_get_contents( $path );
		$this->assertStringContainsString( '.handl-aicac-plugin-chip', $css );
		$this->assertStringContainsString( 'handl-aicac-plugin-chip--never-seen', $css );
	}
}
