<?php
/**
 * Unit tests for the admin-bar protection badge (AICAC-ADMINBAR / #280).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Adminbar;
use HandL\AICAC\Caps;
use HandL\AICAC\Freeze;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

final class AdminbarTestBar {
	/** @var array<string,array<string,mixed>> */
	public array $nodes = array();

	/**
	 * @param array<string,mixed> $args
	 */
	public function add_node( array $args ): void {
		$id = isset( $args['id'] ) ? (string) $args['id'] : '';
		if ( '' === $id ) {
			return;
		}
		$this->nodes[ $id ] = $args;
	}
}

final class AdminbarTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_added_filters'] = array();
		$GLOBALS['handl_aicac_test_caps']          = array(
			Caps::MANAGE => true,
			Caps::VIEW   => true,
		);
		$_POST = array();
	}

	protected function tearDown(): void {
		$_POST = array();
		unset(
			$GLOBALS['handl_aicac_test_options'],
			$GLOBALS['handl_aicac_test_added_actions'],
			$GLOBALS['handl_aicac_test_added_filters'],
			$GLOBALS['handl_aicac_test_caps']
		);
	}

	public function test_init_registers_hooks_without_option_io(): void {
		$before = $GLOBALS['handl_aicac_test_options'] ?? array();
		Adminbar::instance()->init();
		$actions = $GLOBALS['handl_aicac_test_added_actions'] ?? array();
		$filters = $GLOBALS['handl_aicac_test_added_filters'] ?? array();
		$this->assertContains( 'admin_bar_menu', $actions );
		$this->assertContains( 'handl_aicac_protections_settings', $actions );
		$this->assertContains( 'pre_update_option_' . Plugin::OPTION_KEY, $filters );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] ?? array() );
	}

	public function test_populate_skips_without_view_capability(): void {
		$GLOBALS['handl_aicac_test_caps'] = array(
			Caps::MANAGE => false,
			Caps::VIEW   => false,
		);
		update_option( Plugin::OPTION_KEY, array( Adminbar::POLICY_KEY => true ) );
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => time(),
					'decision' => 'deny',
					'plugin'   => 'acme/acme.php',
				),
			)
		);
		$bar = new AdminbarTestBar();
		Adminbar::instance()->populate( $bar );
		$this->assertSame( array(), $bar->nodes );
	}

	public function test_populate_skips_when_badge_disabled(): void {
		update_option( Plugin::OPTION_KEY, array( Adminbar::POLICY_KEY => false ) );
		$bar = new AdminbarTestBar();
		Adminbar::instance()->populate( $bar );
		$this->assertSame( array(), $bar->nodes );
	}

	public function test_default_enabled_when_policy_key_absent(): void {
		$this->assertTrue( Adminbar::is_enabled( array() ) );
		$this->assertFalse( Adminbar::is_enabled( array( Adminbar::POLICY_KEY => false ) ) );
		$this->assertTrue( Adminbar::is_enabled( array( Adminbar::POLICY_KEY => true ) ) );
	}

	/**
	 * @return array<string,array<int,mixed>>
	 */
	public function badgeStateProvider(): array {
		$now   = 1_700_006_400;
		$today = Adminbar::today_start( $now );
		$log   = array(
			array(
				'ts'       => $today + 60,
				'decision' => 'deny',
				'plugin'   => 'acme/acme.php',
			),
			array(
				'ts'       => $today + 90,
				'decision' => 'allow',
				'plugin'   => 'acme/acme.php',
			),
			array(
				'ts'       => $today - 10,
				'decision' => 'deny',
				'plugin'   => 'old/old.php',
			),
		);

		return array(
			'normal' => array( 'normal', $log, array( 'buckets' => array() ), false, 1 ),
			'storm'  => array(
				'storm',
				$log,
				array(
					'buckets' => array(
						'acme|text' => array(
							'storm'        => true,
							'window_start' => $now - 5,
							'plugin'       => 'acme/acme.php',
							'family'       => 'text',
							'count'        => 6,
						),
					),
				),
				false,
				1,
			),
			'freeze' => array( 'freeze', $log, array( 'buckets' => array() ), true, 1 ),
		);
	}

	/**
	 * @dataProvider badgeStateProvider
	 * @param array<int,mixed>    $log
	 * @param array<string,mixed> $storm
	 */
	public function test_badge_states( string $expected, array $log, array $storm, bool $freeze, int $denies ): void {
		$now  = 1_700_006_400;
		$snap = Adminbar::build_snapshot( array(), $log, $storm, $freeze, $now );
		$this->assertSame( $expected, $snap['state'] );
		$this->assertSame( $denies, $snap['deny_count'] );
		$this->assertStringContainsString( 'AI Access', $snap['badge'] );
		$this->assertStringContainsString( (string) $denies, $snap['badge'] );
	}

	public function test_freeze_wins_over_live_storm(): void {
		$now = 1_700_006_400;
		$snap = Adminbar::build_snapshot(
			array(),
			array(),
			array(
				'buckets' => array(
					'x' => array(
						'storm'        => true,
						'window_start' => $now - 1,
					),
				),
			),
			true,
			$now
		);
		$this->assertSame( 'freeze', $snap['state'] );
	}

	public function test_last_three_denies_newest_first_skips_admin_and_synthetic(): void {
		$now   = 1_700_006_400;
		$today = Adminbar::today_start( $now );
		$log   = array(
			array(
				'ts'       => $today + 10,
				'decision' => 'deny',
				'plugin'   => 'one/one.php',
			),
			array(
				'ts'       => $today + 20,
				'decision' => 'deny',
				'plugin'   => 'two/two.php',
			),
			array(
				'ts'       => $today + 30,
				'decision' => 'deny',
				'plugin'   => 'three/three.php',
			),
			array(
				'ts'       => $today + 40,
				'decision' => 'deny',
				'plugin'   => 'four/four.php',
			),
			array(
				'ts'       => $today + 50,
				'decision' => 'deny',
				'plugin'   => 'admin/admin.php',
				'channel'  => 'policy_save',
			),
			array(
				'ts'        => $today + 60,
				'decision'  => 'deny',
				'plugin'    => 'self/self.php',
				'selftest'  => true,
			),
		);
		$snap = Adminbar::build_snapshot( array(), $log, array( 'buckets' => array() ), false, $now );
		$this->assertSame( 4, $snap['deny_count'] );
		$this->assertCount( 3, $snap['denies'] );
		$this->assertSame( 'four', $snap['denies'][0]['label'] );
		$this->assertSame( 'three', $snap['denies'][1]['label'] );
		$this->assertSame( 'two', $snap['denies'][2]['label'] );
	}

	public function test_retry_storm_row_counts_collapsed_attempts(): void {
		$now   = 1_700_006_400;
		$today = Adminbar::today_start( $now );
		$log   = array(
			array(
				'ts'          => $today + 80,
				'decision'    => 'deny',
				'plugin'      => 'stormy/stormy.php',
				'retry_storm' => true,
				'count'       => 12,
			),
		);
		$snap = Adminbar::build_snapshot( array(), $log, array( 'buckets' => array() ), false, $now );
		$this->assertSame( 12, $snap['deny_count'] );
	}

	public function test_add_nodes_marks_alert_states_red_and_links_screens(): void {
		$now  = 1_700_006_400;
		$snap = Adminbar::build_snapshot(
			array(),
			array(
				array(
					'ts'       => Adminbar::today_start( $now ) + 30,
					'decision' => 'deny',
					'plugin'   => 'acme/acme.php',
				),
			),
			array( 'buckets' => array() ),
			true,
			$now
		);
		$bar = new AdminbarTestBar();
		Adminbar::add_nodes( $bar, $snap );
		$root = $bar->nodes[ Adminbar::NODE_ID ];
		$this->assertSame( 'freeze', $snap['state'] );
		$this->assertStringContainsString( '#d63638', (string) $root['title'] );
		$this->assertStringContainsString( 'page=handl-aicac-activity', (string) $root['href'] );
		$this->assertArrayHasKey( Adminbar::NODE_ID . '-activity', $bar->nodes );
		$this->assertArrayHasKey( Adminbar::NODE_ID . '-protections', $bar->nodes );
		$this->assertArrayHasKey( Adminbar::NODE_ID . '-freeze', $bar->nodes );
		$this->assertStringContainsString( 'page=handl-aicac-protections', (string) $bar->nodes[ Adminbar::NODE_ID . '-freeze' ]['href'] );
		$this->assertSame( 'Panic freeze', $bar->nodes[ Adminbar::NODE_ID . '-freeze' ]['title'] );
		$this->assertSame( 'Activity', $bar->nodes[ Adminbar::NODE_ID . '-activity' ]['title'] );
		$this->assertSame( 'Protections', $bar->nodes[ Adminbar::NODE_ID . '-protections' ]['title'] );
	}

	public function test_populate_does_not_write_expired_freeze_state(): void {
		$now = 1_700_006_400;
		update_option( Plugin::OPTION_KEY, array() );
		update_option(
			Freeze::OPTION_KEY,
			array(
				'active'     => true,
				'expires_ts' => $now - 10,
				'started_ts' => $now - 100,
				'minutes'    => 15,
			)
		);
		$before = get_option( Freeze::OPTION_KEY );
		$bar    = new AdminbarTestBar();
		Adminbar::instance()->populate( $bar );
		$this->assertSame( $before, get_option( Freeze::OPTION_KEY ) );
		$root = $bar->nodes[ Adminbar::NODE_ID ] ?? null;
		$this->assertIsArray( $root );
		$this->assertStringNotContainsString( '#d63638', (string) $root['title'] );
	}

	public function test_merge_enabled_from_protections_post(): void {
		$_POST[ Adminbar::POST_PRESENT ] = '1';
		$on = Adminbar::merge_enabled_on_policy_save( array( 'default' => 'allow' ), array() );
		$this->assertFalse( $on[ Adminbar::POLICY_KEY ] );

		$_POST[ Adminbar::POST_ENABLED ] = '1';
		$on = Adminbar::merge_enabled_on_policy_save( array( 'default' => 'allow' ), array() );
		$this->assertTrue( $on[ Adminbar::POLICY_KEY ] );

		unset( $_POST[ Adminbar::POST_PRESENT ], $_POST[ Adminbar::POST_ENABLED ] );
		$kept = Adminbar::merge_enabled_on_policy_save(
			array( 'default' => 'deny' ),
			array( Adminbar::POLICY_KEY => false )
		);
		$this->assertFalse( $kept[ Adminbar::POLICY_KEY ] );
	}

	public function test_settings_copy_is_plain(): void {
		ob_start();
		Adminbar::instance()->render_settings( array() );
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Admin bar badge', $html );
		$this->assertStringContainsString( 'Show a protection badge in the admin bar', $html );
		$this->assertStringContainsString( 'Shows blocked AI calls from today. Turns red during a retry storm or panic freeze.', $html );
		$this->assertStringContainsString( 'name="' . Adminbar::POST_PRESENT . '"', $html );
		$this->assertStringContainsString( 'checked="checked"', $html );
	}

	public function test_populate_with_view_capability_adds_badge(): void {
		$GLOBALS['handl_aicac_test_caps'] = array(
			Caps::MANAGE => false,
			Caps::VIEW   => true,
		);
		update_option( Plugin::OPTION_KEY, array() );
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => time(),
					'decision' => 'deny',
					'plugin'   => 'acme/acme.php',
				),
			)
		);
		$bar = new AdminbarTestBar();
		Adminbar::instance()->populate( $bar );
		$this->assertArrayHasKey( Adminbar::NODE_ID, $bar->nodes );
	}
}
