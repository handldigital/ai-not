<?php
/**
 * AICAC-DOSSIER (#435).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Access_Request;
use HandL\AICAC\Aup;
use HandL\AICAC\Clock;
use HandL\AICAC\Dossier;
use HandL\AICAC\Plugin;
use HandL\AICAC\User_Quota;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class DossierTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_user_id']          = 1;
		$GLOBALS['handl_aicac_test_users']            = array(
			12 => array(
				'ID'           => 12,
				'user_login'   => 'editor.jane',
				'display_name' => 'Jane Editor',
				'user_email'   => 'jane@example.com',
				'roles'        => array( 'editor' ),
			),
		);
		unset( $GLOBALS['handl_aicac_test_dossier_sources'] );
		Dossier::reset_for_tests();
		User_Quota::reset_for_tests();
		Aup::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'           => 'deny',
				'log_enabled'       => true,
				'role_gate_enabled' => true,
				'allowed_roles'     => array( 'editor', 'administrator' ),
			),
			false
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
		delete_option( Access_Request::OPTION_KEY );
	}

	protected function tearDown(): void {
		Dossier::reset_for_tests();
		User_Quota::reset_for_tests();
		Aup::reset_for_tests();
		$GLOBALS['handl_aicac_test_options'] = array();
		unset(
			$GLOBALS['handl_aicac_test_users'],
			$GLOBALS['handl_aicac_test_dossier_sources'],
			$GLOBALS['handl_aicac_test_current_user_can'],
			$GLOBALS['handl_aicac_test_caps'],
			$GLOBALS['handl_aicac_test_quota_eval'],
			$GLOBALS['handl_aicac_test_aup_status'],
			$GLOBALS['handl_aicac_test_user_meta']
		);
		parent::tearDown();
	}

	public function test_defaults_off_and_noop_save_leaves_options_byte_identical(): void {
		$this->assertFalse( Dossier::is_enabled() );
		$this->assertFalse( Dossier::is_cli_enabled() );
		$before = $GLOBALS['handl_aicac_test_options'];
		$this->assertFalse( Dossier::save_settings( Dossier::defaults() ) );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] );
		$this->assertFalse( (bool) get_option( Dossier::SETTINGS_OPTION, false ) );
	}

	public function test_save_defaults_after_enable_deletes_option(): void {
		Dossier::save_settings( array( 'enabled' => true, 'cli_enabled' => true ) );
		$this->assertTrue( Dossier::is_enabled() );
		$this->assertTrue( Dossier::is_cli_enabled() );
		Dossier::save_settings( Dossier::defaults() );
		$this->assertFalse( (bool) get_option( Dossier::SETTINGS_OPTION, false ) );
		$this->assertFalse( Dossier::is_enabled() );
	}

	public function test_unknown_user_join_is_null_and_cli_exits_nonzero(): void {
		Dossier::save_settings( array( 'enabled' => true, 'cli_enabled' => true ) );
		$this->assertNull( Dossier::join( 999 ) );
		$cli = Dossier::cli_print( 999 );
		$this->assertFalse( $cli['ok'] );
		$this->assertSame( 1, $cli['code'] );
		$this->assertSame( 'Unknown user', $cli['lines'][0] );
	}

	public function test_cli_off_exits_nonzero(): void {
		$cli = Dossier::cli_print( 12 );
		$this->assertFalse( $cli['ok'] );
		$this->assertSame( 1, $cli['code'] );
		$this->assertSame( 'User files CLI is off.', $cli['lines'][0] );
	}

	public function test_join_with_sources_absent(): void {
		$GLOBALS['handl_aicac_test_dossier_sources'] = array(
			'HandL\\AICAC\\User_Quota'      => false,
			'HandL\\AICAC\\Aup'             => false,
			'HandL\\AICAC\\Access_Request'  => false,
		);
		delete_option( Plugin::LOG_OPTION_KEY );
		$join = Dossier::join( 12 );
		$this->assertIsArray( $join );
		$this->assertSame( 12, $join['user_id'] );
		$this->assertSame( 'Jane Editor', $join['display'] );
		$this->assertTrue( $join['grants']['available'] );
		$this->assertSame( 'allowed', $join['grants']['role_gate'] );
		$this->assertFalse( $join['quota']['available'] );
		$this->assertSame( Dossier::SOURCE_UNAVAILABLE, $join['quota']['notice'] );
		$this->assertFalse( $join['activity']['available'] );
		$this->assertSame( Dossier::SOURCE_UNAVAILABLE, $join['activity']['notice'] );
		$this->assertFalse( $join['aup']['available'] );
		$this->assertFalse( $join['requests']['available'] );

		ob_start();
		Dossier::save_settings( array( 'enabled' => true ) );
		Dossier::render_join( $join );
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'source unavailable', $html );
		$this->assertStringContainsString( 'Role and grants', $html );
		$this->assertStringContainsString( 'This user is allowed by role.', $html );
	}

	public function test_join_with_all_sources_present(): void {
		// In-file User_Quota / Aup stubs only load when those classes are
		// absent. Union main always has the real classes; seed their options.
		$this->assertTrue( class_exists( User_Quota::class, false ) );
		$this->assertNotSame( __FILE__, ( new \ReflectionClass( User_Quota::class ) )->getFileName() );
		$now = 1_800_000_000;
		$policy                                   = get_option( Plugin::OPTION_KEY, array() );
		$policy                                   = is_array( $policy ) ? $policy : array();
		$policy[ User_Quota::POLICY_ROLE_LIMITS ] = array( 'editor' => 40 );
		update_option( Plugin::OPTION_KEY, $policy, false );
		User_Quota::set_window_count( 12, User_Quota::hour_key( Clock::now() ), 12 );
		Aup::save_settings(
			array(
				'enabled'     => true,
				'policy_text' => 'Use AI responsibly.',
				'grace_days'  => 7,
			),
			$now
		);
		Aup::accept_current( 12, $now, '127.0.0.1' );
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'            => $now - 60,
					'user_id'       => 12,
					'plugin'        => 'helper/helper.php',
					'decision'      => 'allow',
					'input_tokens'  => 1_000_000,
					'output_tokens' => 0,
				),
				array(
					'ts'       => $now - 30,
					'user_id'  => 12,
					'plugin'   => 'blocked/blocked.php',
					'decision' => 'deny',
				),
				array(
					'ts'       => $now - 10,
					'user_id'  => 99,
					'plugin'   => 'other/other.php',
					'decision' => 'allow',
				),
			),
			false
		);
		$GLOBALS['handl_aicac_test_dossier_sources'] = array(
			'HandL\\AICAC\\User_Quota'     => true,
			'HandL\\AICAC\\Aup'            => true,
			'HandL\\AICAC\\Access_Request' => true,
		);
		$req_id = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
		update_option(
			Access_Request::OPTION_KEY,
			array(
				$req_id => array(
					'id'      => $req_id,
					'plugin'  => 'blocked/blocked.php',
					'user_id' => 12,
					'status'  => Access_Request::STATUS_PENDING,
					'ts'      => $now,
				),
			),
			false
		);

		$join = Dossier::join( 12, $now );
		$this->assertIsArray( $join );
		$this->assertTrue( $join['quota']['available'] );
		$this->assertSame( 40, $join['quota']['limit'] );
		$this->assertSame( 12, $join['quota']['count'] );
		$this->assertStringContainsString( '12 / 40', $join['quota']['line'] );
		$this->assertTrue( $join['activity']['available'] );
		$this->assertSame( 1, $join['activity']['allows'] );
		$this->assertSame( 1, $join['activity']['denies'] );
		$this->assertNotNull( $join['activity']['est_usd'] );
		$this->assertTrue( $join['aup']['available'] );
		$this->assertSame( 'current', $join['aup']['status'] );
		$this->assertTrue( $join['requests']['available'] );
		$this->assertSame( 1, $join['requests']['count'] );

		Dossier::save_settings( array( 'enabled' => true, 'cli_enabled' => true ) );
		$cli = Dossier::cli_print( 12 );
		$this->assertTrue( $cli['ok'] );
		$this->assertSame( 0, $cli['code'] );
		$blob = implode( "\n", $cli['lines'] );
		$this->assertStringContainsString( 'quota: Usage (rolling 24h): 12 / 40', $blob );
		$this->assertStringContainsString( 'Allows: 1. Denies: 1.', $blob );
		$csv = Dossier::csv_for_join( $join );
		$this->assertStringContainsString( 'user_id,display,login', $csv );
		$this->assertStringContainsString( 'editor.jane', $csv );

		ob_start();
		Dossier::render_join( $join );
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Jane Editor', $html );
		$this->assertStringContainsString( 'Usage (rolling 24h): 12 / 40', $html );
		$this->assertStringNotContainsString( 'source unavailable', $html );
	}

	public function test_redacted_mode_hides_login_and_email(): void {
		unset( $GLOBALS['handl_aicac_test_current_user_can'] );
		$GLOBALS['handl_aicac_test_caps'] = array(
			'handl_aicac_view' => true,
			'manage_options'   => false,
		);
		$join = Dossier::join( 12 );
		$this->assertTrue( $join['redacted'] );
		$this->assertSame( '', $join['login'] );
		$this->assertSame( '', $join['email'] );
		$this->assertSame( 'user#12', $join['display'] );
	}

	public function test_page_shows_off_copy_and_needles(): void {
		ob_start();
		Dossier::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'User file', $html );
		$this->assertStringContainsString( 'Show user files', $html );
		$this->assertStringContainsString( 'Allow WP-CLI', $html );
		$this->assertStringContainsString( 'User files are off.', $html );
		$this->assertStringContainsString( 'Save user file settings', $html );
	}
}

namespace HandL\AICAC;

// Branch-scoped doubles. On union main the real classes are already loaded,
// so these blocks are no-ops (class_exists stubs cannot unload them in-process).
if ( ! class_exists( User_Quota::class, false ) ) {
	/**
	 * Test double for queued User_Quota (#339).
	 */
	final class User_Quota {
		/**
		 * @param array<string,mixed> $policy Policy.
		 * @param list<string>|null   $roles  Roles.
		 * @return array<string,mixed>
		 */
		public static function evaluate( array $policy, int $user_id, ?array $roles = null, ?int $now = null, $tz = null ): array {
			unset( $policy, $user_id, $roles, $now, $tz );
			$eval = $GLOBALS['handl_aicac_test_quota_eval'] ?? array(
				'prevent' => false,
				'reason'  => '',
				'limit'   => 40,
				'count'   => 12,
				'source'  => 'role',
			);

			return is_array( $eval ) ? $eval : array();
		}
	}
}

if ( ! class_exists( Aup::class, false ) ) {
	/**
	 * Test double for queued Aup (#369).
	 */
	final class Aup {
		public static function status_for_user( int $user_id, ?array $settings = null, ?int $now = null ): string {
			unset( $user_id, $settings, $now );

			return isset( $GLOBALS['handl_aicac_test_aup_status'] )
				? (string) $GLOBALS['handl_aicac_test_aup_status']
				: 'current';
		}

		public static function status_label( string $status ): string {
			$map = array(
				'current' => 'Current',
				'grace'   => 'Grace',
				'locked'  => 'Locked',
				'off'     => 'Off',
			);

			return $map[ $status ] ?? $status;
		}
	}
}
