<?php
/**
 * AICAC-KEY-CUSTODY (#335).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Attribution;
use HandL\AICAC\Key_Custody;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class KeyCustodyTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_user_id']          = 12;
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Key_Custody::reset_for_tests();
		Attribution::force_plugin( null );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'plugins'     => array(),
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
	}

	protected function tearDown(): void {
		Attribution::force_plugin( null );
		Key_Custody::reset_for_tests();
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_user_id'] = 0;
		unset( $GLOBALS['handl_aicac_test_current_user_can'] );
		parent::tearDown();
	}

	public function test_crypto_roundtrip_and_mask_never_echoes_full_key(): void {
		$this->assertTrue( Key_Custody::crypto_available() );
		$plain = 'sk-testkeycustodyabcdefghijklmnopqrstuvwxyz';
		$enc   = Key_Custody::encrypt( $plain );
		$this->assertIsArray( $enc );
		$this->assertNotSame( $plain, $enc['c'] );
		$this->assertSame( $plain, Key_Custody::decrypt( $enc['n'], $enc['c'] ) );

		Key_Custody::store_key( 'openai', $plain, 1_700_000_000 );
		$vault = Key_Custody::get_vault();
		$this->assertArrayHasKey( 'openai', $vault );
		$this->assertStringNotContainsString( $plain, wp_json_encode( $vault ) );
		$this->assertSame( 'wxyz', $vault['openai']['suffix'] );
		$this->assertSame( '••••wxyz', Key_Custody::mask_suffix( $vault['openai']['suffix'] ) );
		$this->assertSame( $plain, Key_Custody::plaintext_for( 'openai' ) );
	}

	public function test_disabled_never_injects(): void {
		Key_Custody::store_key( 'openai', 'sk-aaaaaaaaaaaaaaaaaaaaaaaa', 1 );
		Key_Custody::save_settings( array( 'enabled' => false ) );
		$out = Key_Custody::filter_pre_option( false, 'openai_api_key' );
		$this->assertFalse( $out );
	}

	public function test_enabled_injects_when_policy_allows(): void {
		$plain = 'sk-bbbbbbbbbbbbbbbbbbbbbbbb';
		Key_Custody::store_key( 'openai', $plain, 1 );
		Key_Custody::save_settings( array( 'enabled' => true ) );
		Attribution::force_plugin( 'demo-ai/demo-ai.php' );

		$out = Key_Custody::filter_pre_option( false, 'openai_api_key' );
		$this->assertSame( $plain, $out );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $log );
		$hits = array_values(
			array_filter(
				$log,
				static function ( $row ) {
					return is_array( $row )
						&& ( $row['key_source'] ?? '' ) === 'custody'
						&& ( $row['decision'] ?? '' ) === 'allow';
				}
			)
		);
		$this->assertNotEmpty( $hits );
	}

	public function test_revoke_returns_empty_and_logs_distinct_reason(): void {
		Key_Custody::store_key( 'anthropic', 'sk-ant-cccccccccccccccccccc', 1 );
		Key_Custody::save_settings( array( 'enabled' => true ) );
		Key_Custody::revoke_key( 'anthropic', 2 );
		Attribution::force_plugin( 'demo-ai/demo-ai.php' );

		$out = Key_Custody::filter_pre_option( false, 'anthropic_api_key' );
		$this->assertSame( '', $out );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$hits = array_values(
			array_filter(
				$log,
				static function ( $row ) {
					return is_array( $row )
						&& ( $row['decision_source'] ?? '' ) === Key_Custody::REASON
						&& ( $row['key_custody'] ?? '' ) === 'revoked';
				}
			)
		);
		$this->assertNotEmpty( $hits );
		$this->assertStringContainsString( 'revoked', (string) ( $hits[0]['denial_reason'] ?? '' ) );
	}

	public function test_policy_deny_blocks_handoff(): void {
		Key_Custody::store_key( 'google', 'AIzaSyDddddddddddddddddddddddddddddddd', 1 );
		Key_Custody::save_settings( array( 'enabled' => true ) );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'plugins'     => array(
					'blocked/plugin.php' => 'deny',
				),
			)
		);
		Attribution::force_plugin( 'blocked/plugin.php' );

		$out = Key_Custody::filter_pre_option( false, 'google_ai_api_key' );
		$this->assertSame( '', $out );

		$log  = get_option( Plugin::LOG_OPTION_KEY, array() );
		$hits = array_values(
			array_filter(
				$log,
				static function ( $row ) {
					return is_array( $row ) && ( $row['key_custody'] ?? '' ) === 'policy';
				}
			)
		);
		$this->assertNotEmpty( $hits );
	}

	public function test_migrate_option_stores_and_clears_source(): void {
		update_option( 'openai_api_key', 'sk-eeeeeeeeeeeeeeeeeeeeeeee', false );
		$result = Key_Custody::migrate_option( 'openai_api_key', true, 3 );
		$this->assertTrue( $result['ok'] );
		$this->assertSame( 'openai', $result['provider'] );
		$this->assertSame( 'sk-eeeeeeeeeeeeeeeeeeeeeeee', Key_Custody::plaintext_for( 'openai' ) );
		$this->assertFalse( get_option( 'openai_api_key', false ) );
	}

	public function test_noop_save_leaves_defaults_absent(): void {
		$this->assertFalse( get_option( Key_Custody::SETTINGS_OPTION, false ) );
		Key_Custody::save_settings( array( 'enabled' => false ) );
		$this->assertFalse( get_option( Key_Custody::SETTINGS_OPTION, false ) );
		Key_Custody::save_settings( Key_Custody::get_settings() );
		$this->assertFalse( get_option( Key_Custody::SETTINGS_OPTION, false ) );
	}

	public function test_no_vault_entry_falls_through(): void {
		Key_Custody::save_settings( array( 'enabled' => true ) );
		$out = Key_Custody::filter_pre_option( false, 'openai_api_key' );
		$this->assertFalse( $out );
	}

	public function test_selftest_caller_skips_inject(): void {
		Key_Custody::store_key( 'openai', 'sk-ffffffffffffffffffffffff', 1 );
		Key_Custody::save_settings( array( 'enabled' => true ) );
		Attribution::force_plugin( \HandL\AICAC\Selftest::PLUGIN_BASENAME );
		$out = Key_Custody::filter_pre_option( false, 'openai_api_key' );
		$this->assertFalse( $out );
	}

	public function test_would_prevent_consult_uses_policy_public_api(): void {
		$policy = array(
			'default' => 'allow',
			'plugins' => array( 'x/y.php' => 'deny' ),
		);
		$this->assertTrue( Policy::would_prevent( $policy, 'x/y.php' ) );
		$this->assertFalse( Policy::would_prevent( $policy, 'ok/plugin.php' ) );
	}
}
