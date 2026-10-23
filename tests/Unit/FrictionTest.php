<?php
/**
 * AICAC-FRICTION (#395).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Access_Request;
use HandL\AICAC\Friction;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class FrictionTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Friction::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'haktan+aicac-friction@handldigital.com',
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_filters'][ Friction::FILTER_STREAK_THRESHOLD ],
			$GLOBALS['handl_aicac_test_current_user_can']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		Friction::reset_for_tests();
		parent::tearDown();
	}

	public function test_defaults_off_and_noop_save_byte_identical(): void {
		$this->assertFalse( Friction::is_enabled() );
		$this->assertSame( Friction::defaults(), Friction::get_settings() );
		Friction::save_settings(
			array(
				'enabled'          => true,
				'streak_threshold' => 10,
			)
		);
		$this->assertTrue( Friction::is_enabled() );
		$before = get_option( Friction::SETTINGS_OPTION );
		$changed = Friction::save_settings(
			array(
				'enabled'          => true,
				'streak_threshold' => 10,
			)
		);
		$this->assertFalse( $changed );
		$this->assertSame( $before, get_option( Friction::SETTINGS_OPTION ) );
		Friction::save_settings( Friction::defaults() );
		$this->assertFalse( (bool) get_option( Friction::SETTINGS_OPTION, false ) );
	}

	public function test_threshold_filter_and_streak_detection(): void {
		Friction::save_settings(
			array(
				'enabled'          => true,
				'streak_threshold' => 10,
			)
		);
		$this->assertSame( 10, Friction::streak_threshold() );
		$GLOBALS['handl_aicac_test_filters'][ Friction::FILTER_STREAK_THRESHOLD ] = static function (): int {
			return 5;
		};
		$this->assertSame( 5, Friction::streak_threshold() );

		$now = strtotime( '2026-10-12 15:00:00 UTC' );
		$log = array();
		for ( $i = 0; $i < 10; $i++ ) {
			$log[] = array(
				'ts'            => $now - ( $i * 3600 ),
				'plugin'        => 'alpha/alpha.php',
				'user_id'       => 7,
				'decision'      => 'deny',
				'denial_reason' => 'plugin',
				'provider'      => 'openai',
				'operation'     => 'generate_text',
			);
		}
		// Below threshold for user 8.
		for ( $i = 0; $i < 3; $i++ ) {
			$log[] = array(
				'ts'            => $now,
				'plugin'        => 'alpha/alpha.php',
				'user_id'       => 8,
				'decision'      => 'deny',
				'denial_reason' => 'budget',
				'provider'      => 'openai',
				'operation'     => 'generate_text',
			);
		}

		$analysis = Friction::analyze_window( 30, $log, $now );
		$this->assertSame( 13, $analysis['total_denies'] );
		$this->assertSame( 1, $analysis['active_streaks'] );
		$by_user = array();
		foreach ( $analysis['pairs'] as $pair ) {
			$by_user[ (int) $pair['user_id'] ] = $pair;
		}
		$this->assertTrue( $by_user[7]['streak_active'] );
		$this->assertFalse( $by_user[8]['streak_active'] );
		$this->assertSame( 'rule', $by_user[7]['top_reason'] );
		$this->assertSame( 'budget', $by_user[8]['top_reason'] );
		$this->assertStringContainsString( 'handl-aicac-rules', (string) $by_user[7]['deep_link'] );
		$this->assertStringContainsString( 'handl-aicac-protections', (string) $by_user[8]['deep_link'] );
	}

	public function test_alert_fires_once_per_pair_window(): void {
		Friction::save_settings(
			array(
				'enabled'          => true,
				'streak_threshold' => 5,
			)
		);
		$now = strtotime( '2026-10-12 12:00:00 UTC' );
		$log = array();
		for ( $i = 0; $i < 5; $i++ ) {
			$log[] = array(
				'ts'            => $now,
				'plugin'        => 'beta/beta.php',
				'user_id'       => 3,
				'decision'      => 'deny',
				'denial_reason' => 'rate_cap',
				'provider'      => 'openai',
				'operation'     => 'generate_text',
			);
		}

		$first = Friction::maybe_fire_alerts( $log, $now );
		$this->assertNotEmpty( $first );
		$mails = count( Friction::test_mails() );
		$this->assertGreaterThan( 0, $mails );

		$second = Friction::maybe_fire_alerts( $log, $now );
		$this->assertSame( array(), $second );
		$this->assertSame( $mails, count( Friction::test_mails() ) );
	}

	public function test_access_request_and_shadow_cross_ref(): void {
		Friction::save_settings(
			array(
				'enabled'          => true,
				'streak_threshold' => 10,
			)
		);
		$now = strtotime( '2026-10-12 12:00:00 UTC' );
		$log = array(
			array(
				'ts'            => $now - 86400,
				'plugin'        => 'gamma/gamma.php',
				'user_id'       => 9,
				'decision'      => 'deny',
				'denial_reason' => 'plugin',
				'provider'      => 'openai',
				'operation'     => 'generate_text',
				'count'         => 12,
			),
			array(
				'ts'       => $now,
				'plugin'   => 'gamma/gamma.php',
				'user_id'  => 9,
				'channel'  => 'direct_http',
				'decision' => 'observe',
				'provider' => 'openai',
				'host'     => 'api.openai.com',
			),
		);
		update_option(
			Access_Request::OPTION_KEY,
			array(
				'req1' => array(
					'plugin'  => 'gamma/gamma.php',
					'user_id' => 9,
					'status'  => Access_Request::STATUS_DENIED,
					'reason'  => 'need access',
				),
			),
			false
		);

		$analysis = Friction::analyze_window( 30, $log, $now );
		$this->assertCount( 1, $analysis['pairs'] );
		$pair = $analysis['pairs'][0];
		$this->assertTrue( $pair['access_request'] );
		$this->assertTrue( $pair['shadow_ai_later'] );
		$this->assertTrue( $pair['streak_active'] );
	}

	public function test_readonly_aggregation_writes_nothing(): void {
		Friction::save_settings(
			array(
				'enabled'          => true,
				'streak_threshold' => 5,
			)
		);
		$now = strtotime( '2026-10-12 12:00:00 UTC' );
		$log = array();
		for ( $i = 0; $i < 5; $i++ ) {
			$log[] = array(
				'ts'            => $now,
				'plugin'        => 'delta/delta.php',
				'user_id'       => 2,
				'decision'      => 'deny',
				'denial_reason' => 'plugin',
				'provider'      => 'openai',
				'operation'     => 'generate_text',
			);
		}
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
		$before = $GLOBALS['handl_aicac_test_options'];

		Friction::roster( $log, $now );
		Friction::analyze_window( 30, $log, $now );
		Friction::csv_for_roster( Friction::roster( $log, $now ) );

		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] );

		Friction::maybe_fire_alerts( $log, $now );
		$after = $GLOBALS['handl_aicac_test_options'];
		$this->assertArrayHasKey( Friction::ALERTED_OPTION, $after );
		// Friction persists only SETTINGS + ALERTED; Alerts may touch alert_health on delivery.
		foreach ( array_keys( $after ) as $key ) {
			if ( in_array(
				$key,
				array(
					Plugin::OPTION_KEY,
					Plugin::LOG_OPTION_KEY,
					Friction::SETTINGS_OPTION,
					Friction::ALERTED_OPTION,
					'handl_aicac_alert_health',
				),
				true
			) ) {
				continue;
			}
			$this->assertSame(
				$before[ $key ] ?? null,
				$after[ $key ] ?? null,
				'Unexpected option write: ' . (string) $key
			);
		}
	}

	public function test_csv_and_off_page(): void {
		Friction::save_settings(
			array(
				'enabled'          => true,
				'streak_threshold' => 10,
			)
		);
		$now = strtotime( '2026-10-12 12:00:00 UTC' );
		$log = array(
			array(
				'ts'            => $now,
				'plugin'        => 'epsilon/epsilon.php',
				'user_id'       => 1,
				'decision'      => 'deny',
				'denial_reason' => 'plugin',
				'provider'      => 'openai',
				'operation'     => 'generate_text',
				'count'         => 11,
			),
		);
		$csv = Friction::csv_for_roster( Friction::roster( $log, $now ) );
		$this->assertStringContainsString( 'revisit_only_never_auto_relax', $csv );
		$this->assertStringContainsString( 'epsilon/epsilon.php', $csv );

		Friction::save_settings( Friction::defaults() );
		$_GET['page'] = Friction::PAGE_SLUG;
		ob_start();
		Friction::render_page();
		$html = ob_get_clean();
		$this->assertStringContainsString( 'Deny-friction report is off', $html );
		$this->assertStringNotContainsString( 'Friction hotspots', $html );
		unset( $_GET['page'] );
	}

	public function test_enabled_page_shows_revisit_framing(): void {
		Friction::save_settings(
			array(
				'enabled'          => true,
				'streak_threshold' => 10,
			)
		);
		$now = strtotime( '2026-10-12 12:00:00 UTC' );
		$log = array(
			array(
				'ts'            => $now,
				'plugin'        => 'zeta/zeta.php',
				'user_id'       => 4,
				'decision'      => 'deny',
				'denial_reason' => 'budget',
				'provider'      => 'openai',
				'operation'     => 'generate_text',
				'count'         => 12,
			),
		);
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
		$_GET['page'] = Friction::PAGE_SLUG;
		ob_start();
		Friction::render_page();
		$html = ob_get_clean();
		$this->assertStringContainsString( 'Revisit only', $html );
		$this->assertStringContainsString( 'zeta/zeta.php', $html );
		$this->assertStringContainsString( 'Friction hotspots', $html );
		unset( $_GET['page'] );
	}
}
