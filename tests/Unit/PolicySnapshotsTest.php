<?php
/**
 * Unit tests for AICAC-UNDO policy snapshots (#130).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Policy_Snapshots;
use PHPUnit\Framework\TestCase;

final class PolicySnapshotsTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['handl_aicac_test_options'] = array();
		unset( $GLOBALS['handl_aicac_test_filters'], $GLOBALS['handl_aicac_test_user_id'], $GLOBALS['handl_aicac_test_users'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Policy_Snapshots::OPTION_KEY );
		delete_option( Policy_Snapshots::HISTORY_OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
	}

	protected function tearDown(): void {
		delete_option( Plugin::OPTION_KEY );
		delete_option( Policy_Snapshots::OPTION_KEY );
		delete_option( Policy_Snapshots::HISTORY_OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		unset( $GLOBALS['handl_aicac_test_user_id'], $GLOBALS['handl_aicac_test_users'] );
	}

	/**
	 * @return array<string,mixed>
	 */
	private function complex_policy( string $default = 'allow', int $plugin_n = 3 ): array {
		$plugins = array();
		for ( $i = 1; $i <= $plugin_n; $i++ ) {
			$plugins[ "acme-plugin-{$i}/plugin.php" ] = ( 0 === $i % 2 ) ? 'deny' : 'allow';
		}

		return array(
			'default'              => $default,
			'audit_only'           => false,
			'log_enabled'          => true,
			'kill_switch'          => false,
			'shadow_block_enabled' => false,
			'unknown_operation'    => 'inherit',
			'role_gate_enabled'    => false,
			'allowed_roles'        => array(),
			'alert_on_deny'        => true,
			'alert_on_shadow'      => false,
			'alert_mode'           => 'immediate',
			'plugins'              => $plugins,
			'operations'           => array(
				'acme-plugin-1/plugin.php' => array( 'text' => 'allow' ),
			),
			'denied_tools'         => array( 'wp_search' ),
			'model_force_plugins'  => array(),
			'log_limit'            => 200,
		);
	}

	public function test_save_policy_snapshots_and_retains_only_newest_five(): void {
		// Seed initial store without going through save (no prior snapshot).
		update_option( Plugin::OPTION_KEY, $this->complex_policy( 'allow', 1 ), false );

		for ( $i = 0; $i < 7; $i++ ) {
			$p = $this->complex_policy( 0 === $i % 2 ? 'allow' : 'deny', 1 + ( $i % 3 ) );
			$p['kill_switch'] = ( $i >= 5 );
			Policy::save_policy( $p );
		}

		$list = Policy_Snapshots::all();
		$this->assertCount( Policy_Snapshots::MAX, $list );
		// Newest first: last save's pre-state had kill_switch true (i=5 and i=6).
		// When i=6 saved, snapshot was the i=5 policy (kill_switch true).
		$this->assertTrue( ! empty( $list[0]['policy']['kill_switch'] ) );
	}

	public function test_restore_round_trips_complex_policy(): void {
		$original = $this->complex_policy( 'deny', 4 );
		$original['kill_switch'] = true;
		$original['operations']  = array(
			'acme-plugin-1/plugin.php' => array(
				'text'  => 'deny',
				'image' => 'allow',
			),
		);
		update_option( Plugin::OPTION_KEY, $original, false );

		// First save creates snapshot of original.
		$broken = $this->complex_policy( 'allow', 1 );
		$broken['kill_switch'] = false;
		$broken['plugins']     = array( 'other/plugin.php' => 'allow' );
		Policy::save_policy( $broken );

		$live = Policy::get_policy();
		$this->assertSame( 'allow', $live['default'] );
		$this->assertArrayHasKey( 'other/plugin.php', $live['plugins'] );

		$result = Policy_Snapshots::restore_latest();
		$this->assertTrue( $result['ok'] );
		$this->assertSame( 'restored', $result['status'] );

		$restored = Policy::get_policy();
		$this->assertSame( 'deny', $restored['default'] );
		$this->assertTrue( ! empty( $restored['kill_switch'] ) );
		$this->assertCount( 4, $restored['plugins'] );
		$this->assertSame( 'deny', $restored['operations']['acme-plugin-1/plugin.php']['text'] ?? null );
		$this->assertArrayNotHasKey( 'other/plugin.php', $restored['plugins'] );
	}

	public function test_restore_is_itself_snapshotted_undo_the_undo(): void {
		update_option( Plugin::OPTION_KEY, $this->complex_policy( 'allow', 2 ), false );

		$mid = $this->complex_policy( 'deny', 2 );
		$mid['kill_switch'] = true;
		Policy::save_policy( $mid );

		$live_mid = Policy::get_policy();
		$this->assertSame( 'deny', $live_mid['default'] );
		$this->assertTrue( ! empty( $live_mid['kill_switch'] ) );

		// Restore → back to allow / kill off.
		Policy_Snapshots::restore_latest();
		$after_first = Policy::get_policy();
		$this->assertSame( 'allow', $after_first['default'] );
		$this->assertFalse( ! empty( $after_first['kill_switch'] ) );

		// Restore again → undoes the restore (back to mid).
		Policy_Snapshots::restore_latest();
		$after_second = Policy::get_policy();
		$this->assertSame( 'deny', $after_second['default'] );
		$this->assertTrue( ! empty( $after_second['kill_switch'] ) );
	}

	public function test_diff_rows_lists_changed_settings(): void {
		$current = $this->complex_policy( 'allow', 1 );
		$snap    = $this->complex_policy( 'deny', 2 );
		$snap['kill_switch'] = true;

		$rows = Policy_Snapshots::diff_rows( $current, $snap );
		$keys = array_column( $rows, 'key' );
		$this->assertContains( 'default', $keys );
		$this->assertContains( 'kill_switch', $keys );
		$this->assertContains( 'plugins', $keys );
	}

	public function test_summary_line_counts_rules(): void {
		$policy = $this->complex_policy( 'allow', 3 );
		$line   = Policy_Snapshots::summary_line( $policy );
		$this->assertStringContainsString( '3', $line );
		$this->assertStringContainsString( 'Allow', $line );
		$this->assertStringContainsString( 'Emergency stop off', $line );
	}

	public function test_restore_writes_audit_row_when_logging_on(): void {
		$base = $this->complex_policy( 'allow', 1 );
		$base['log_enabled'] = true;
		update_option( Plugin::OPTION_KEY, $base, false );

		Policy::save_policy( $this->complex_policy( 'deny', 1 ) );
		Policy_Snapshots::restore_latest();

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$found = false;
		foreach ( $log as $row ) {
			if ( is_array( $row ) && ( $row['channel'] ?? '' ) === 'policy_restore' ) {
				$found = true;
				$this->assertSame( 'policy_restored', $row['decision'] ?? null );
				break;
			}
		}
		$this->assertTrue( $found, 'Expected policy_restore audit row in activity log' );
	}

	public function test_first_save_without_prior_option_does_not_snapshot(): void {
		// No option stored yet.
		Policy::save_policy( $this->complex_policy( 'allow', 1 ) );
		$this->assertSame( array(), Policy_Snapshots::all() );
		$this->assertSame( array(), Policy_Snapshots::history() );
	}

	public function test_history_records_actor_and_change_lines(): void {
		$GLOBALS['handl_aicac_test_user_id'] = 42;
		$GLOBALS['handl_aicac_test_users']   = array(
			42 => array(
				'ID'           => 42,
				'user_login'   => 'admin42',
				'display_name' => 'Ada Admin',
			),
		);

		update_option( Plugin::OPTION_KEY, $this->complex_policy( 'allow', 1 ), false );

		$next = $this->complex_policy( 'deny', 1 );
		$next['kill_switch'] = true;
		$next['log_enabled'] = false;
		Policy::save_policy( $next );

		$snaps = Policy_Snapshots::all();
		$this->assertCount( 1, $snaps );
		$this->assertSame( 'user', $snaps[0]['actor']['type'] ?? null );
		$this->assertSame( 42, (int) ( $snaps[0]['actor']['user_id'] ?? 0 ) );
		$this->assertNotEmpty( $snaps[0]['changes'] );

		$history = Policy_Snapshots::history();
		$this->assertCount( 1, $history );
		$this->assertSame( 42, (int) ( $history[0]['actor']['user_id'] ?? 0 ) );
		$joined = implode( ' ', $history[0]['changes'] );
		$this->assertStringContainsString( 'Emergency stop', $joined );
		$this->assertStringContainsString( 'Off', $joined );
		$this->assertStringContainsString( 'On', $joined );
		$this->assertSame( 'Ada Admin', Policy_Snapshots::actor_display( $history[0]['actor'] ) );
	}

	public function test_history_survives_full_snapshot_rotation(): void {
		update_option( Plugin::OPTION_KEY, $this->complex_policy( 'allow', 1 ), false );

		for ( $i = 0; $i < 8; $i++ ) {
			$p = $this->complex_policy( 0 === $i % 2 ? 'allow' : 'deny', 1 + ( $i % 3 ) );
			$p['kill_switch'] = ( 0 === $i % 2 );
			Policy::save_policy( $p );
		}

		$this->assertCount( Policy_Snapshots::MAX, Policy_Snapshots::all() );
		$this->assertGreaterThan( Policy_Snapshots::MAX, count( Policy_Snapshots::history() ) );
		$this->assertSame( 8, count( Policy_Snapshots::history() ) );
	}

	public function test_kill_switch_history_records_when_activity_logging_off(): void {
		$base = $this->complex_policy( 'allow', 1 );
		$base['log_enabled'] = false;
		$base['audit_only']  = false;
		$base['kill_switch'] = false;
		update_option( Plugin::OPTION_KEY, $base, false );

		$next = $base;
		$next['kill_switch'] = true;
		Policy::save_policy( $next );

		$history = Policy_Snapshots::history();
		$this->assertNotEmpty( $history );
		$joined = implode( ' ', $history[0]['changes'] );
		$this->assertStringContainsString( 'Emergency stop', $joined );
	}

	public function test_history_cap_retains_newest_only(): void {
		update_option( Plugin::OPTION_KEY, $this->complex_policy( 'allow', 1 ), false );

		// Direct append beyond MAX to avoid hundreds of save_policy sanitization cycles.
		for ( $i = 0; $i < Policy_Snapshots::HISTORY_MAX + 5; $i++ ) {
			Policy_Snapshots::append_history(
				array(
					'ts'      => 1700000000 + $i,
					'actor'   => array(
						'type'    => 'system',
						'user_id' => 0,
						'login'   => '',
					),
					'changes' => array( 'Emergency stop: Off → On' ),
					'summary' => 'Emergency stop: Off → On',
				)
			);
		}

		$list = Policy_Snapshots::history();
		$this->assertCount( Policy_Snapshots::HISTORY_MAX, $list );
		$this->assertSame( 1700000000 + Policy_Snapshots::HISTORY_MAX + 4, (int) $list[0]['ts'] );
	}
}
