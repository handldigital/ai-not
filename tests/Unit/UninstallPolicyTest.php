<?php
/**
 * Unit tests for AICAC-UNINSTALL (#163) Phase 1 keep vs purge.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\CLI;
use PHPUnit\Framework\TestCase;

final class UninstallPolicyTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		if ( ! defined( 'HANDL_AICAC_UNINSTALL_HELPERS' ) ) {
			define( 'HANDL_AICAC_UNINSTALL_HELPERS', true );
		}
		require_once HANDL_AICAC_DIR . '/uninstall.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-cli.php';
		$GLOBALS['handl_aicac_test_options']    = array();
		$GLOBALS['handl_aicac_test_transients'] = array();
		$GLOBALS['handl_aicac_test_cron']       = array();
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options']    = array();
		$GLOBALS['handl_aicac_test_transients'] = array();
		$GLOBALS['handl_aicac_test_cron']       = array();
		parent::tearDown();
	}

	private function seed_plugin_data(): void {
		update_option( 'handl_aicac_policy', array( 'default' => 'deny' ), false );
		update_option( 'handl_aicac_recent_calls', array( array( 'id' => 1 ) ), false );
		update_option( 'handl_aicac_alert_health', array( 'ok' => true ), false );
		update_option( 'unrelated_option', 'stay', false );
		set_transient( 'handl_aicac_rate', '1', 60 );
		$GLOBALS['handl_aicac_test_cron']['handl_aicac_send_denial_digest'] = time();
		$GLOBALS['handl_aicac_test_cron']['unrelated_cron']                 = time();
		update_option( 'handl_aigate_policy', array( 'legacy' => true ), false );
		update_option( 'ai_not_recent_calls', array( 'legacy' ), false );
	}

	/**
	 * @return list<string>
	 */
	private function prefixed_option_keys(): array {
		$out = array();
		foreach ( array_keys( $GLOBALS['handl_aicac_test_options'] ?? array() ) as $key ) {
			if ( 0 === strpos( (string) $key, 'handl_aicac_' ) ) {
				$out[] = (string) $key;
			}
		}
		sort( $out );
		return $out;
	}

	public function test_cli_option_key_matches_uninstall_helper(): void {
		$this->assertSame( CLI::UNINSTALL_OPTION_KEY, \handl_aicac_uninstall_option_key() );
	}

	public function test_missing_option_defaults_to_keep(): void {
		$this->assertSame( 'keep', \handl_aicac_uninstall_policy() );
		$this->assertSame( CLI::UNINSTALL_KEEP, CLI::get_uninstall_policy() );
	}

	public function test_unknown_stored_value_is_keep(): void {
		update_option( CLI::UNINSTALL_OPTION_KEY, 'delete-everything', false );
		$this->assertSame( 'keep', \handl_aicac_uninstall_policy() );
		$this->assertSame( CLI::UNINSTALL_KEEP, CLI::get_uninstall_policy() );
	}

	public function test_cli_set_rejects_unknown_mode(): void {
		$error = CLI::set_uninstall_policy( 'wipe' );
		$this->assertSame( 'Use keep or purge.', $error );
		$this->assertSame( CLI::UNINSTALL_KEEP, CLI::get_uninstall_policy() );
	}

	public function test_cli_set_keep_and_purge(): void {
		$this->assertNull( CLI::set_uninstall_policy( 'purge' ) );
		$this->assertSame( CLI::UNINSTALL_PURGE, CLI::get_uninstall_policy() );
		$this->assertSame( 'purge', \handl_aicac_uninstall_policy() );
		$this->assertSame( 'Uninstall will remove all plugin data.', CLI::uninstall_status_message( 'purge' ) );

		$this->assertNull( CLI::set_uninstall_policy( 'keep' ) );
		$this->assertSame( CLI::UNINSTALL_KEEP, CLI::get_uninstall_policy() );
		$this->assertSame( 'Uninstall will keep plugin data.', CLI::uninstall_status_message( 'keep' ) );
	}

	public function test_default_keep_leaves_data_on_uninstall(): void {
		$this->seed_plugin_data();
		\handl_aicac_run_uninstall();

		$this->assertSame( array( 'default' => 'deny' ), get_option( 'handl_aicac_policy' ) );
		$this->assertSame( array( array( 'id' => 1 ) ), get_option( 'handl_aicac_recent_calls' ) );
		$this->assertSame( 'stay', get_option( 'unrelated_option' ) );
		$this->assertSame( '1', get_transient( 'handl_aicac_rate' ) );
		$this->assertArrayHasKey( 'handl_aicac_send_denial_digest', $GLOBALS['handl_aicac_test_cron'] );
		$this->assertSame( array( 'legacy' => true ), get_option( 'handl_aigate_policy' ) );
	}

	public function test_explicit_keep_leaves_data_on_uninstall(): void {
		$this->seed_plugin_data();
		$this->assertNull( CLI::set_uninstall_policy( 'keep' ) );
		\handl_aicac_run_uninstall();

		$this->assertSame( array( 'default' => 'deny' ), get_option( 'handl_aicac_policy' ) );
		$this->assertSame( CLI::UNINSTALL_KEEP, get_option( CLI::UNINSTALL_OPTION_KEY ) );
		$this->assertNotSame( array(), $this->prefixed_option_keys() );
	}

	public function test_purge_removes_prefixed_options_transients_cron_and_legacy_keys(): void {
		$this->seed_plugin_data();
		$this->assertNull( CLI::set_uninstall_policy( 'purge' ) );
		\handl_aicac_run_uninstall();

		$this->assertSame( array(), $this->prefixed_option_keys() );
		$this->assertFalse( get_option( 'handl_aicac_policy', false ) );
		$this->assertFalse( get_option( CLI::UNINSTALL_OPTION_KEY, false ) );
		$this->assertFalse( get_transient( 'handl_aicac_rate' ) );
		$this->assertArrayNotHasKey( 'handl_aicac_send_denial_digest', $GLOBALS['handl_aicac_test_cron'] );
		$this->assertArrayHasKey( 'unrelated_cron', $GLOBALS['handl_aicac_test_cron'] );
		$this->assertSame( 'stay', get_option( 'unrelated_option' ) );
		$this->assertFalse( get_option( 'handl_aigate_policy', false ) );
		$this->assertFalse( get_option( 'ai_not_recent_calls', false ) );
	}
}
