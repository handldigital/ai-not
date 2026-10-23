<?php
/**
 * AICAC-WALLFLOWER (#469).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Dead_Rules;
use HandL\AICAC\Plugin;
use HandL\AICAC\Preflight_Scan;
use HandL\AICAC\Wallflower;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class WallflowerTest extends TestCase {

	private const WALL  = 'wall/wall.php';
	private const COVER = 'cover/cover.php';
	private const ACT   = 'active/active.php';
	private const INSUF = 'insuf/insuf.php';

	private const NOW = 1_700_000_000;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_filters']          = array();
		Wallflower::reset_for_tests();
		Wallflower::set_skip_cache( true );
		Wallflower::set_test_now( self::NOW );
		delete_option( Preflight_Scan::OPTION_KEY );
		delete_option( Dead_Rules::MATCHED_OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
	}

	protected function tearDown(): void {
		Wallflower::reset_for_tests();
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_filters'] = array();
		parent::tearDown();
	}

	public function test_default_window_is_sixty_days(): void {
		$this->assertSame( 60, Wallflower::sanitize_days( null ) );
		$this->assertSame( 60, Wallflower::get_settings()['days'] );
		$this->assertSame( array( 30, 60, 90 ), Wallflower::DAY_OPTIONS );
	}

	public function test_census_renders_all_four_flag_states(): void {
		$day = DAY_IN_SECONDS;
		Wallflower::set_test_findings(
			array(
				self::WALL  => array( 'providers' => array( 'openai' ) ),
				self::COVER => array( 'providers' => array( 'anthropic' ) ),
				self::ACT   => array( 'providers' => array( 'google' ) ),
			)
		);
		Wallflower::set_test_rules(
			array(
				self::COVER => 'deny',
				self::ACT   => 'allow',
				self::INSUF => 'allow',
			)
		);
		Wallflower::set_test_log(
			array(
				array(
					'plugin' => self::ACT,
					'ts'     => self::NOW - ( 5 * $day ),
				),
			)
		);
		Wallflower::set_test_matched(
			array(
				self::INSUF => self::NOW - ( 10 * $day ),
			)
		);

		$data = Wallflower::census( 60, self::NOW );
		$by   = array();
		foreach ( $data['rows'] as $row ) {
			$by[ $row['plugin'] ] = $row;
		}

		$this->assertSame( Wallflower::FLAG_WALLFLOWER, $by[ self::WALL ]['flag'] );
		$this->assertSame( 'never', null === $by[ self::WALL ]['days_since'] ? 'never' : 'has' );
		$this->assertNull( $by[ self::WALL ]['days_since'] );
		$this->assertSame( array( 'openai' ), $by[ self::WALL ]['providers'] );
		$this->assertSame( 'none', $by[ self::WALL ]['rule'] );
		$this->assertStringContainsString( 'deny-by-default', $by[ self::WALL ]['suggestion'] );

		$this->assertSame( Wallflower::FLAG_COVERED, $by[ self::COVER ]['flag'] );
		$this->assertSame( 'deny', $by[ self::COVER ]['rule'] );

		$this->assertSame( Wallflower::FLAG_ACTIVE, $by[ self::ACT ]['flag'] );
		$this->assertSame( 5, $by[ self::ACT ]['days_since'] );

		$this->assertSame( Wallflower::FLAG_INSUFFICIENT_DATA, $by[ self::INSUF ]['flag'] );
		$this->assertSame( array(), $by[ self::INSUF ]['providers'] );
		$this->assertFalse( $data['empty_preflight'] );
	}

	public function test_empty_preflight_points_at_scan_all(): void {
		Wallflower::set_test_findings( array() );
		Wallflower::set_test_log( array() );
		Wallflower::set_test_matched( array() );
		Wallflower::set_test_rules( array() );

		ob_start();
		Wallflower::render_page();
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'No preflight findings yet', $html );
		$this->assertStringContainsString( 'Open Scan All', $html );
		$this->assertStringContainsString( 'Wallflower', $html );
		$this->assertStringNotContainsString( '<tbody>', $html );
	}

	public function test_read_only_on_preflight_activity_dead_rules_and_policy(): void {
		update_option(
			Preflight_Scan::OPTION_KEY,
			array(
				'items' => array(
					'plugin' => array(
						self::WALL => array( 'providers' => array( 'openai' ) ),
					),
				),
			),
			false
		);
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'plugin' => self::WALL,
					'ts'     => self::NOW - ( 100 * DAY_IN_SECONDS ),
				),
			),
			false
		);
		update_option( Dead_Rules::MATCHED_OPTION_KEY, array( self::WALL => self::NOW - ( 100 * DAY_IN_SECONDS ) ), false );
		update_option( Plugin::OPTION_KEY, array( 'plugins' => array( self::WALL => 'allow' ), 'default' => 'allow' ), false );

		$before_preflight = get_option( Preflight_Scan::OPTION_KEY, null );
		$before_log       = get_option( Plugin::LOG_OPTION_KEY, null );
		$before_matched   = get_option( Dead_Rules::MATCHED_OPTION_KEY, null );
		$before_policy    = get_option( Plugin::OPTION_KEY, null );

		Wallflower::set_test_findings( null );
		Wallflower::set_test_log( null );
		Wallflower::set_test_matched( null );
		Wallflower::set_test_rules( null );

		$data = Wallflower::census( 60, self::NOW );
		$this->assertNotEmpty( $data['rows'] );
		$this->assertSame( Wallflower::FLAG_WALLFLOWER, $data['rows'][0]['flag'] );

		ob_start();
		Wallflower::render_page();
		ob_end_clean();

		$this->assertSame( $before_preflight, get_option( Preflight_Scan::OPTION_KEY, null ) );
		$this->assertSame( $before_log, get_option( Plugin::LOG_OPTION_KEY, null ) );
		$this->assertSame( $before_matched, get_option( Dead_Rules::MATCHED_OPTION_KEY, null ) );
		$this->assertSame( $before_policy, get_option( Plugin::OPTION_KEY, null ) );

		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-wallflower.php' );
		$this->assertStringNotContainsString( 'Preflight_Scan::save_state', $src );
		$this->assertStringNotContainsString( 'Dead_Rules::put_matched', $src );
		$this->assertStringNotContainsString( 'Policy::save', $src );
		$this->assertStringNotContainsString( 'update_option( Plugin::OPTION_KEY', $src );
		$this->assertStringNotContainsString( 'update_option( Plugin::LOG_OPTION_KEY', $src );
	}

	public function test_cache_writes_only_own_options(): void {
		Wallflower::set_skip_cache( false );
		Wallflower::set_test_findings(
			array(
				self::WALL => array( 'providers' => array( 'openai' ) ),
			)
		);
		update_option( Plugin::OPTION_KEY, array( 'keep' => true ), false );
		$policy_before = get_option( Plugin::OPTION_KEY, null );

		$snap = Wallflower::snapshot( 60 );
		$this->assertFalse( $snap['cached'] );
		$this->assertNotFalse( get_option( Wallflower::CENSUS_OPTION, false ) );
		$this->assertGreaterThan( 0, (int) get_option( Wallflower::GENERATED_OPTION, 0 ) );
		$this->assertSame( $policy_before, get_option( Plugin::OPTION_KEY, null ) );

		$again = Wallflower::snapshot( 60 );
		$this->assertTrue( $again['cached'] );
	}

	public function test_plugin_bootstrap_wires_wallflower_at_bottom(): void {
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-wallflower.php', $plugin );
		$this->assertStringContainsString( 'Wallflower::init()', $plugin );
		$this->assertGreaterThan(
			strrpos( $plugin, 'Rescan_Schedule::init()' ),
			strrpos( $plugin, 'Wallflower::init()' )
		);
	}

	public function test_covered_beats_recent_activity(): void {
		Wallflower::set_test_findings(
			array(
				self::COVER => array( 'providers' => array( 'openai' ) ),
			)
		);
		Wallflower::set_test_rules( array( self::COVER => 'deny' ) );
		Wallflower::set_test_log(
			array(
				array(
					'plugin' => self::COVER,
					'ts'     => self::NOW - DAY_IN_SECONDS,
				),
			)
		);
		$data = Wallflower::census( 60, self::NOW );
		$this->assertSame( Wallflower::FLAG_COVERED, $data['rows'][0]['flag'] );
	}
}
