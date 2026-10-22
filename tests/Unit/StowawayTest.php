<?php
/**
 * AICAC-STOWAWAY (#461).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Stowaway;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class StowawayTest extends TestCase {

	private const GONE     = 'gone-ai/gone-ai.php';
	private const DORMANT  = 'dormant-ai/dormant-ai.php';
	private const ACTIVE   = 'active-ai/active-ai.php';
	private const SECRET   = 'sk-stowaway-SECRETVALUE-xyz12345';

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_filters']          = array();
		$GLOBALS['handl_aicac_test_plugins']          = array();
		Stowaway::reset_for_tests();
		Stowaway::set_skip_cache( true );
		Stowaway::set_test_signatures(
			array(
				array(
					'file'            => self::GONE,
					'name'            => 'Gone AI',
					'option_prefixes' => array( 'goneai_' ),
					'tables'          => array( 'goneai_logs' ),
				),
				array(
					'file'            => self::DORMANT,
					'name'            => 'Dormant AI',
					'option_prefixes' => array( 'dormai_' ),
					'tables'          => array(),
				),
				array(
					'file'            => self::ACTIVE,
					'name'            => 'Active AI',
					'option_prefixes' => array( 'actai_' ),
					'tables'          => array(),
				),
			)
		);
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_filters'] = array();
		$GLOBALS['handl_aicac_test_plugins'] = array();
		Stowaway::reset_for_tests();
		parent::tearDown();
	}

	public function test_gone_plugin_is_stowaway(): void {
		Stowaway::set_test_installed( array() );
		Stowaway::set_test_active( array() );
		Stowaway::set_test_option_rows(
			array(
				array(
					'name'  => 'goneai_endpoint',
					'value' => 'https://example.test/v1',
					'bytes' => 24,
				),
			)
		);
		$data = Stowaway::census();
		$this->assertCount( 1, $data['findings'] );
		$this->assertSame( Stowaway::GRADE_STOWAWAY, $data['findings'][0]['grade'] );
		$this->assertSame( 'Gone AI', $data['findings'][0]['name'] );
		$this->assertSame( 1, $data['findings'][0]['row_count'] );
		$this->assertSame( 24, $data['findings'][0]['byte_estimate'] );
	}

	public function test_active_plugin_is_not_reported(): void {
		Stowaway::set_test_installed( array( self::ACTIVE => true ) );
		Stowaway::set_test_active( array( self::ACTIVE => true ) );
		Stowaway::set_test_option_rows(
			array(
				array(
					'name'  => 'actai_model',
					'value' => 'gpt-4',
				),
			)
		);
		$data = Stowaway::census();
		$this->assertSame( array(), $data['findings'] );
	}

	public function test_inactive_installed_plugin_is_dormant_owner(): void {
		Stowaway::set_test_installed( array( self::DORMANT => true ) );
		Stowaway::set_test_active( array() );
		Stowaway::set_test_option_rows(
			array(
				array(
					'name'  => 'dormai_setting',
					'value' => 'on',
				),
			)
		);
		$data = Stowaway::census();
		$this->assertCount( 1, $data['findings'] );
		$this->assertSame( Stowaway::GRADE_DORMANT, $data['findings'][0]['grade'] );
		$this->assertSame( 'Dormant AI', $data['findings'][0]['name'] );
	}

	public function test_secret_values_never_rendered(): void {
		Stowaway::set_test_installed( array() );
		Stowaway::set_test_active( array() );
		Stowaway::set_test_option_rows(
			array(
				array(
					'name'  => 'goneai_api_key',
					'value' => self::SECRET,
				),
			)
		);
		ob_start();
		Stowaway::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringNotContainsString( self::SECRET, $html );
		$this->assertStringNotContainsString( 'SECRETVALUE', $html );
		$this->assertStringContainsString( 'set', $html );
		$this->assertStringContainsString( 'STOWAWAY', $html );
		$this->assertStringContainsString( 'Gone AI', $html );
	}

	public function test_empty_state_says_site_is_clean(): void {
		Stowaway::set_test_installed( array() );
		Stowaway::set_test_active( array() );
		Stowaway::set_test_option_rows( array() );
		ob_start();
		Stowaway::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'This site is clean', $html );
		$this->assertStringContainsString( 'Stowaway', $html );
		$this->assertStringNotContainsString( '<tbody>', $html );
	}

	public function test_census_is_read_only_on_foreign_options(): void {
		Stowaway::set_test_installed( array() );
		Stowaway::set_test_active( array() );
		update_option( 'goneai_keep', 'stay', false );
		update_option( Plugin::OPTION_KEY, array( 'keep' => true ), false );
		$before_gone   = get_option( 'goneai_keep', null );
		$before_policy = get_option( Plugin::OPTION_KEY, null );
		Stowaway::set_test_option_rows(
			array(
				array(
					'name'  => 'goneai_keep',
					'value' => 'stay',
				),
			)
		);
		ob_start();
		Stowaway::render_page();
		ob_end_clean();
		$this->assertSame( $before_gone, get_option( 'goneai_keep', null ) );
		$this->assertSame( $before_policy, get_option( Plugin::OPTION_KEY, null ) );

		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-stowaway.php' );
		$this->assertStringNotContainsString( '$wpdb->delete', $src );
		$this->assertStringNotContainsString( 'DROP TABLE', $src );
		$this->assertStringNotContainsString( 'DELETE FROM', $src );
		$this->assertStringNotContainsString( 'admin_post_', $src );
	}

	public function test_table_hit_counts_as_leftover_without_options(): void {
		Stowaway::set_test_installed( array() );
		Stowaway::set_test_active( array() );
		Stowaway::set_test_option_rows( array() );
		Stowaway::set_test_tables( array( 'wp_goneai_logs' ) );
		$data = Stowaway::census();
		$this->assertCount( 1, $data['findings'] );
		$this->assertSame( 1, $data['findings'][0]['table_count'] );
		$this->assertSame( Stowaway::GRADE_STOWAWAY, $data['findings'][0]['grade'] );
	}

	public function test_cache_writes_only_own_options(): void {
		Stowaway::set_skip_cache( false );
		Stowaway::set_test_installed( array() );
		Stowaway::set_test_active( array() );
		Stowaway::set_test_option_rows(
			array(
				array(
					'name'  => 'goneai_keep',
					'value' => 'stay',
				),
			)
		);
		update_option( Plugin::OPTION_KEY, array( 'keep' => true ), false );
		$policy_before = get_option( Plugin::OPTION_KEY, null );
		$snap          = Stowaway::snapshot();
		$this->assertFalse( $snap['cached'] );
		$this->assertNotFalse( get_option( Stowaway::CENSUS_OPTION, false ) );
		$this->assertGreaterThan( 0, (int) get_option( Stowaway::GENERATED_OPTION, 0 ) );
		$this->assertSame( $policy_before, get_option( Plugin::OPTION_KEY, null ) );
		$again = Stowaway::snapshot();
		$this->assertTrue( $again['cached'] );
	}

	public function test_plugin_bootstrap_wires_stowaway_at_bottom(): void {
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-stowaway.php', $plugin );
		$this->assertStringContainsString( 'Stowaway::init()', $plugin );
		$this->assertGreaterThan(
			strrpos( $plugin, 'Rescan_Schedule::init()' ),
			strrpos( $plugin, 'Stowaway::init()' )
		);
	}
}
