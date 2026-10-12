<?php
/**
 * AICAC-TOMBSTONE (#425).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Access_Request;
use HandL\AICAC\CLI_Tombstone;
use HandL\AICAC\Plugin;
use HandL\AICAC\Tombstone;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class TombstoneTest extends TestCase {

	private const NOW  = 1791800000; // 2026-10-12 UTC.
	private const DAY  = 86400;
	private const GONE = 'gone-plugin/gone-plugin.php';
	private const LIVE = 'live-plugin/live-plugin.php';

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$GLOBALS['handl_aicac_test_cron']             = array();
		$GLOBALS['handl_aicac_test_users']            = array();
		Tombstone::reset_for_tests();
		update_option( 'admin_email', 'owner@prod.example.com' );
		$this->put_policy( array( self::GONE => 'allow', self::LIVE => 'allow' ) );
		Tombstone::set_test_now( self::NOW );
		Tombstone::set_test_installed_plugins( array( self::LIVE ) );
		Tombstone::set_test_log( array() );
		Tombstone::set_test_roles( null );
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_cron']          = array();
		$GLOBALS['handl_aicac_test_users']         = array();
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		Tombstone::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * Store (and inject) a policy with the given plugin rules.
	 *
	 * @param array<string,string> $rules Rules.
	 * @param array<string,mixed>  $extra Extra policy keys.
	 */
	private function put_policy( array $rules, array $extra = array() ): void {
		$policy = array_merge(
			array(
				'default'     => 'allow',
				'alert_email' => 'alerts@prod.example.com',
				'plugins'     => $rules,
			),
			$extra
		);
		update_option( Plugin::OPTION_KEY, $policy );
		Tombstone::set_test_policy( $policy );
	}

	private function enable(): void {
		Tombstone::save_settings( array( 'enabled' => true ) );
	}

	/**
	 * @return list<string>
	 */
	private function codes( int $at = self::NOW ): array {
		$codes = array();
		foreach ( Tombstone::snapshot( $at )['findings'] as $row ) {
			$codes[] = $row['code'] . ':' . $row['ref'];
		}

		return $codes;
	}

	/**
	 * Take the gone plugin through the full uninstall -> noticed -> reinstalled arc.
	 */
	private function reinstall_gone_plugin(): void {
		$this->enable();
		Tombstone::scan( self::NOW ); // GONE is dangling and noticed.
		Tombstone::set_test_installed_plugins( array( self::LIVE, self::GONE ) );
	}

	public function test_defaults_off_save_defaults_deletes_and_noop(): void {
		$this->assertFalse( Tombstone::is_enabled() );
		$this->assertSame( array( 'enabled' => false ), Tombstone::defaults() );
		$this->assertSame( Tombstone::defaults(), Tombstone::get_settings() );
		$this->assertSame( 'report_only_never_deletes', Tombstone::FRAMING );
		$this->assertSame( 'handl-aicac-tombstone', Tombstone::PAGE_SLUG );
		$this->assertSame( 'handl_aicac_tombstone', Tombstone::SETTINGS_OPTION );
		$this->assertSame( 'handl_aicac_tombstone_state', Tombstone::STATE_OPTION );

		$this->assertTrue( Tombstone::save_settings( array( 'enabled' => true ) ) );
		$this->assertTrue( Tombstone::is_enabled() );
		$before = get_option( Tombstone::SETTINGS_OPTION );
		$this->assertFalse( Tombstone::save_settings( array( 'enabled' => true ) ) );
		$this->assertSame( $before, get_option( Tombstone::SETTINGS_OPTION ) );

		$this->assertTrue( Tombstone::save_settings( Tombstone::defaults() ) );
		$this->assertFalse( (bool) get_option( Tombstone::SETTINGS_OPTION, false ) );
		$this->assertFalse( Tombstone::save_settings( Tombstone::defaults() ) );
		$this->assertSame( Tombstone::defaults(), Tombstone::sanitize_settings( 'junk' ) );
	}

	public function test_disabled_does_nothing(): void {
		$this->assertFalse( Tombstone::maybe_check( self::NOW, true ) );
		$this->assertFalse( Tombstone::on_activated_plugin( self::GONE ) );
		$this->assertFalse( Tombstone::maybe_fire_alerts( self::NOW ) );
		$this->assertFalse( get_option( Tombstone::STATE_OPTION, false ) );

		Tombstone::init();
		$this->assertNotContains( 'activated_plugin', $GLOBALS['handl_aicac_test_added_actions'] );
	}

	public function test_dangling_plugin_rule_detected_and_live_not_flagged(): void {
		$this->enable();
		$snap = Tombstone::snapshot( self::NOW );

		$this->assertSame( array( 'dangling_plugin_rule:' . self::GONE ), $this->codes() );
		$this->assertSame( 1, $snap['dangling_count'] );
		$this->assertSame( 0, $snap['resurrection_count'] );
		$this->assertFalse( $snap['has_resurrection'] );
		$this->assertSame( array( self::LIVE ), array_column( $snap['live'], 'plugin' ) );
		$this->assertSame( 'allow', $snap['findings'][0]['rule'] );
		$this->assertFalse( $snap['findings'][0]['alerts'] );
		$this->assertStringContainsString( 'no longer installed', $snap['findings'][0]['summary'] );
		$this->assertStringContainsString( 'handl-aicac-rules', $snap['findings'][0]['deep_link'] );
		$this->assertStringContainsString( 're-approve', Tombstone::build_body( array( 'findings' => array( array_merge( $snap['findings'][0], array( 'code' => 'resurrection', 'summary' => 're-approve' ) ) ), 'resurrection_count' => 1 ) ) );
	}

	public function test_deny_rule_and_kill_switch_exception_are_dangling_too(): void {
		$this->put_policy(
			array( 'old-deny/old-deny.php' => 'deny' ),
			array( 'kill_switch_exceptions' => array( 'old-exception/old-exception.php', self::LIVE ) )
		);
		$this->enable();

		$this->assertSame(
			array( 'dangling_plugin_rule:old-deny/old-deny.php', 'dangling_plugin_rule:old-exception/old-exception.php' ),
			$this->codes()
		);
		$this->assertStringContainsString( 'kill-switch exception', Tombstone::snapshot( self::NOW )['findings'][1]['summary'] );
	}

	public function test_age_comes_from_activity_log_then_scan_then_first_noticed(): void {
		$this->enable();
		$noticed = Tombstone::snapshot( self::NOW )['findings'][0];
		$this->assertSame( 'noticed', $noticed['age_source'] );
		$this->assertSame( 0, $noticed['age_days'] );

		Tombstone::set_test_log(
			array(
				array( 'plugin' => self::GONE, 'ts' => self::NOW - 40 * self::DAY ),
				array( 'plugin' => self::GONE, 'ts' => self::NOW - 12 * self::DAY ),
				array( 'plugin' => self::LIVE, 'ts' => self::NOW - 1 * self::DAY ),
				'junk',
			)
		);
		$logged = Tombstone::snapshot( self::NOW )['findings'][0];
		$this->assertSame( 'activity_log', $logged['age_source'] );
		$this->assertSame( 12, $logged['age_days'] );
		$this->assertStringContainsString( '12 days ago', $logged['summary'] );

		// Own last-seen map is used when there is no log row: GONE was installed at the first scan.
		Tombstone::set_test_log( array() );
		Tombstone::set_test_installed_plugins( array( self::LIVE, self::GONE ) );
		Tombstone::scan( self::NOW + 5 * self::DAY );
		Tombstone::set_test_installed_plugins( array( self::LIVE ) );
		$this->put_policy( array( self::GONE => 'deny', self::LIVE => 'allow' ) );
		$seen = Tombstone::snapshot( self::NOW + 9 * self::DAY )['findings'][0];
		$this->assertSame( 'installed_scan', $seen['age_source'] );
		$this->assertSame( 4, $seen['age_days'] );
	}

	public function test_installed_list_falls_back_to_get_plugins(): void {
		$this->enable();
		Tombstone::set_test_installed_plugins( null );
		$snap = Tombstone::snapshot( self::NOW );
		$this->assertTrue( function_exists( 'get_plugins' ) );
		// The stub get_plugins() returns an empty (but known) list; with it the rules dangle.
		$this->assertTrue( $snap['plugins_known'] );
	}

	public function test_dangling_role_when_role_gate_lists_missing_role(): void {
		$this->put_policy(
			array(),
			array(
				'role_gate_enabled' => true,
				'allowed_roles'     => array( 'editor', 'ghost_role' ),
			)
		);
		Tombstone::set_test_roles( array( 'administrator' => array( 'name' => 'Admin' ), 'editor' => array( 'name' => 'Editor' ) ) );
		$this->enable();

		$snap = Tombstone::snapshot( self::NOW );
		$this->assertSame( array( 'dangling_role:ghost_role' ), $this->codes() );
		$this->assertStringContainsString( 'ghost_role', $snap['findings'][0]['summary'] );
		$this->assertStringContainsString( 'handl-aicac-protections', $snap['findings'][0]['deep_link'] );
		$this->assertFalse( $snap['findings'][0]['alerts'] );

		// Gate off, or roles unknowable: no role finding.
		$this->put_policy( array(), array( 'role_gate_enabled' => false, 'allowed_roles' => array( 'ghost_role' ) ) );
		$this->assertSame( array(), $this->codes() );
	}

	public function test_dangling_user_ref_flags_pending_request_for_missing_user_only(): void {
		$GLOBALS['handl_aicac_test_users'] = array( 7 => array( 'user_login' => 'here' ) );
		update_option(
			Access_Request::OPTION_KEY,
			array(
				str_repeat( 'a', 32 ) => array( 'plugin' => self::LIVE, 'user_id' => 99, 'status' => 'pending', 'ts' => self::NOW - 3 * self::DAY ),
				str_repeat( 'b', 32 ) => array( 'plugin' => self::LIVE, 'user_id' => 7, 'status' => 'pending', 'ts' => self::NOW - 3 * self::DAY ),
				str_repeat( 'c', 32 ) => array( 'plugin' => self::LIVE, 'user_id' => 55, 'status' => 'approved', 'ts' => self::NOW - 3 * self::DAY ),
			)
		);
		$requests = get_option( Access_Request::OPTION_KEY );
		$this->put_policy( array() );
		$this->enable();

		$snap = Tombstone::snapshot( self::NOW );
		$this->assertSame( array( 'dangling_user_ref:99' ), $this->codes() );
		$this->assertSame( 3, $snap['findings'][0]['age_days'] );
		$this->assertStringContainsString( 'Offboard', $snap['findings'][0]['suggestion'] );
		$this->assertFalse( $snap['findings'][0]['alerts'] );
		Tombstone::scan( self::NOW );
		$this->assertSame( $requests, get_option( Access_Request::OPTION_KEY ), 'flag only: the request is never touched' );
	}

	public function test_resurrection_on_activated_plugin_with_prior_dangling_allow(): void {
		$this->reinstall_gone_plugin();
		$this->assertSame( array(), Tombstone::test_mails() );

		Tombstone::set_test_now( self::NOW + 3 * self::DAY );
		$this->assertTrue( Tombstone::on_activated_plugin( self::GONE ) );

		$state = Tombstone::get_state();
		$this->assertCount( 1, $state['history'] );
		$this->assertSame( self::GONE, $state['history'][0]['plugin'] );
		$this->assertSame( 'activation', $state['history'][0]['via'] );
		$this->assertSame( self::NOW, $state['history'][0]['dangling_since'] );
		$this->assertArrayNotHasKey( 'plugin:' . self::GONE, $state['dangling'] );

		$snap = Tombstone::snapshot( self::NOW + 3 * self::DAY );
		$this->assertSame( 1, $snap['resurrection_count'] );
		$this->assertTrue( $snap['has_resurrection'] );
		$this->assertSame( array( 'resurrection:' . self::GONE ), $this->codes( self::NOW + 3 * self::DAY ) );
		$this->assertTrue( $snap['findings'][0]['alerts'] );
		$this->assertSame( 'high', $snap['findings'][0]['severity'] );
		$this->assertTrue( Tombstone::is_alerted() );
		$this->assertCount( 1, Tombstone::test_mails() );
	}

	public function test_activation_of_a_plugin_that_was_never_dangling_is_not_a_resurrection(): void {
		$this->enable();
		$this->assertFalse( Tombstone::on_activated_plugin( self::LIVE ) );
		$this->assertFalse( Tombstone::on_activated_plugin( 'unknown/unknown.php' ) );
		$this->assertFalse( Tombstone::on_activated_plugin( '../bad' ) );
		$this->assertSame( 0, Tombstone::snapshot( self::NOW )['resurrection_count'] );
		$this->assertSame( array(), Tombstone::test_mails() );
	}

	public function test_reinstalled_plugin_whose_rule_is_deny_is_not_a_resurrection(): void {
		$this->put_policy( array( self::GONE => 'deny' ) );
		$this->enable();
		Tombstone::set_test_installed_plugins( array( self::GONE ) );

		$this->assertSame( array(), Tombstone::scan( self::NOW + 60 ) );
		$this->assertSame( array(), $this->codes() );
		$this->assertSame( array(), Tombstone::get_state()['history'] );
		$this->assertSame( array(), Tombstone::test_mails() );
	}

	public function test_resurrection_also_via_inventory_when_plugin_returns(): void {
		$this->reinstall_gone_plugin();

		$this->assertTrue( Tombstone::maybe_check( self::NOW + 600 ) );
		$state = Tombstone::get_state();
		$this->assertCount( 1, $state['history'] );
		$this->assertSame( 'inventory', $state['history'][0]['via'] );
		$this->assertSame( array( 'resurrection:' . self::GONE ), $this->codes( self::NOW + 600 ) );
		$this->assertTrue( Tombstone::is_alerted() );

		// A later activation hook for the same plugin does not duplicate the finding.
		Tombstone::on_activated_plugin( self::GONE );
		$this->assertCount( 1, Tombstone::get_state()['history'] );
	}

	public function test_alert_fires_once_for_resurrection_and_never_for_dangling_only(): void {
		$sent                           = array();
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject ) use ( &$sent ) {
			$sent[] = array( $to, $subject );

			return true;
		};
		$this->enable();
		$this->assertSame( 1, Tombstone::snapshot( self::NOW )['dangling_count'] );
		Tombstone::maybe_check( self::NOW + 400, true );
		Tombstone::maybe_check( self::NOW + 800, true );
		$this->assertSame( array(), $sent, 'dangling-only findings never alert' );
		$this->assertFalse( Tombstone::is_alerted() );
		$this->assertFalse( Tombstone::maybe_fire_alerts( self::NOW + 900 ) );

		Tombstone::set_test_installed_plugins( array( self::LIVE, self::GONE ) );
		Tombstone::maybe_check( self::NOW + 1200, true );
		Tombstone::maybe_check( self::NOW + 1600, true );
		Tombstone::on_activated_plugin( self::GONE );
		Tombstone::maybe_fire_alerts( self::NOW + 2000 );

		$this->assertCount( 1, $sent );
		$this->assertSame( 'alerts@prod.example.com', $sent[0][0] );
		$this->assertStringContainsString( '[TOMBSTONE]', $sent[0][1] );
		$this->assertStringContainsString( self::GONE, $sent[0][1] );
		$mail = Tombstone::test_mails()[0];
		$this->assertStringContainsString( self::GONE, $mail['body'] );
		$this->assertStringContainsString( 'never deletes', $mail['body'] );
		$this->assertSame( self::NOW + 1200, Tombstone::get_state()['last_alert_ts'] );
	}

	public function test_failed_mail_does_not_latch_so_it_retries(): void {
		$GLOBALS['handl_aicac_wp_mail'] = static function () {
			return false;
		};
		$this->reinstall_gone_plugin();
		Tombstone::maybe_check( self::NOW + 600, true );
		$this->assertFalse( Tombstone::is_alerted() );
		$this->assertSame( array( 'resurrection:' . self::GONE ), $this->codes( self::NOW + 600 ), 'finding stays on screen' );

		$GLOBALS['handl_aicac_wp_mail'] = static function () {
			return true;
		};
		Tombstone::maybe_check( self::NOW + 1200, true );
		$this->assertTrue( Tombstone::is_alerted() );
	}

	public function test_rearm_after_resurrection_cleared(): void {
		$this->reinstall_gone_plugin();
		Tombstone::maybe_check( self::NOW + 600, true );
		$this->assertTrue( Tombstone::is_alerted() );
		$this->assertCount( 1, Tombstone::test_mails() );

		// A human removes the Allow rule: the resurrection is cleared and the latch re-arms.
		$this->put_policy( array( self::LIVE => 'allow' ) );
		Tombstone::maybe_check( self::NOW + 1200, true );
		$state = Tombstone::get_state();
		$this->assertFalse( $state['alerted'] );
		$this->assertSame( self::NOW + 1200, $state['history'][0]['cleared_ts'] );
		$this->assertSame( 0, Tombstone::snapshot( self::NOW + 1200 )['resurrection_count'] );

		// The plugin leaves again, the rule comes back, and a second reinstall is a new episode.
		$this->put_policy( array( self::GONE => 'allow', self::LIVE => 'allow' ) );
		Tombstone::set_test_installed_plugins( array( self::LIVE ) );
		Tombstone::maybe_check( self::NOW + 1800, true );
		$this->assertCount( 1, Tombstone::test_mails() );
		Tombstone::set_test_installed_plugins( array( self::LIVE, self::GONE ) );
		Tombstone::maybe_check( self::NOW + 2400, true );

		$this->assertCount( 2, Tombstone::test_mails() );
		$this->assertCount( 2, Tombstone::get_state()['history'] );
		$this->assertTrue( Tombstone::is_alerted() );
	}

	public function test_resurrection_clears_when_the_plugin_leaves_again(): void {
		$this->reinstall_gone_plugin();
		Tombstone::maybe_check( self::NOW + 600, true );
		$this->assertSame( 1, Tombstone::snapshot( self::NOW + 600 )['resurrection_count'] );

		Tombstone::set_test_installed_plugins( array( self::LIVE ) );
		Tombstone::maybe_check( self::NOW + 1200, true );
		$this->assertFalse( Tombstone::is_alerted() );
		$this->assertSame( array( 'dangling_plugin_rule:' . self::GONE ), $this->codes( self::NOW + 1200 ) );
	}

	public function test_never_writes_policy_or_other_options_and_never_deletes_rules(): void {
		update_option( 'other_control_sentinel', 'keep' );
		update_option( Plugin::LOG_OPTION_KEY, array( array( 'plugin' => self::GONE, 'ts' => self::NOW - self::DAY ) ) );
		$GLOBALS['handl_aicac_test_users'] = array();
		update_option( Access_Request::OPTION_KEY, array( str_repeat( 'a', 32 ) => array( 'plugin' => self::LIVE, 'user_id' => 99, 'status' => 'pending', 'ts' => self::NOW ) ) );
		$this->put_policy(
			array( self::GONE => 'allow', self::LIVE => 'allow' ),
			array( 'role_gate_enabled' => true, 'allowed_roles' => array( 'ghost' ), 'kill_switch_exceptions' => array( 'x/x.php' ) )
		);
		Tombstone::set_test_roles( array( 'administrator' ) );
		Tombstone::set_test_log( null );

		$policy  = get_option( Plugin::OPTION_KEY );
		$others  = array(
			'admin_email'              => get_option( 'admin_email' ),
			'other_control_sentinel'   => get_option( 'other_control_sentinel' ),
			Plugin::LOG_OPTION_KEY     => get_option( Plugin::LOG_OPTION_KEY ),
			Access_Request::OPTION_KEY => get_option( Access_Request::OPTION_KEY ),
		);

		$this->enable();
		Tombstone::maybe_check( self::NOW + 400, true );
		Tombstone::set_test_installed_plugins( array( self::LIVE, self::GONE ) );
		Tombstone::maybe_check( self::NOW + 800, true );
		Tombstone::on_activated_plugin( self::GONE );
		Tombstone::csv_for_snapshot();
		Tombstone::build_print_html( Tombstone::snapshot() );

		$this->assertSame( $policy, get_option( Plugin::OPTION_KEY ), 'policy option untouched' );
		$this->assertSame( array( self::GONE => 'allow', self::LIVE => 'allow' ), get_option( Plugin::OPTION_KEY )['plugins'], 'no rule deleted' );
		foreach ( $others as $key => $value ) {
			$this->assertSame( $value, get_option( $key ), $key . ' untouched' );
		}

		// Alerts::safe_wp_mail records its own delivery health; that is Alerts' write, not ours.
		$keys = array_values( array_diff( array_keys( $GLOBALS['handl_aicac_test_options'] ), array( 'handl_aicac_alert_health' ) ) );
		sort( $keys );
		$expected = array_merge( array_keys( $others ), array( Plugin::OPTION_KEY, Tombstone::SETTINGS_OPTION, Tombstone::STATE_OPTION ) );
		sort( $expected );
		$this->assertSame( $expected, $keys, 'writes confined to the two own options' );
	}

	public function test_never_schedules_cron_and_hooks_admin_init_and_activation_only(): void {
		$this->reinstall_gone_plugin();
		Tombstone::maybe_check( self::NOW + 600, true );
		Tombstone::init();

		$this->assertSame( array(), $GLOBALS['handl_aicac_test_cron'] );
		$this->assertContains( 'admin_init', $GLOBALS['handl_aicac_test_added_actions'] );
		$this->assertContains( 'activated_plugin', $GLOBALS['handl_aicac_test_added_actions'] );
		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-handl-aicac-tombstone.php' );
		$this->assertStringNotContainsString( 'wp_schedule_event', $source );
		$this->assertStringNotContainsString( 'wp_schedule_single_event', $source );
		$this->assertStringNotContainsString( 'update_option( Plugin::OPTION_KEY', $source );
		$this->assertStringNotContainsString( 'delete_user', $source );
		$this->assertStringNotContainsString( 'remove_role', $source );
		$this->assertStringNotContainsString( 'deactivate_plugins', $source );
	}

	public function test_check_is_throttled_unless_forced(): void {
		$this->enable();
		$this->assertTrue( Tombstone::maybe_check( self::NOW + 400 ) );
		$this->assertFalse( Tombstone::maybe_check( self::NOW + 500 ) );
		$this->assertTrue( Tombstone::maybe_check( self::NOW + 400 + Tombstone::CHECK_THROTTLE_SECONDS ) );
		$this->assertTrue( Tombstone::maybe_check( self::NOW + 401, true ) );
	}

	public function test_csv_contains_framing_and_resurrection_rows(): void {
		$this->put_policy(
			array( self::GONE => 'allow', self::LIVE => 'allow', 'old/old.php' => 'deny' ),
			array( 'role_gate_enabled' => true, 'allowed_roles' => array( 'ghost' ) )
		);
		Tombstone::set_test_roles( array( 'administrator' ) );
		$this->reinstall_gone_plugin();
		Tombstone::maybe_check( self::NOW + 600, true );
		$csv = Tombstone::csv_for_snapshot( Tombstone::snapshot( self::NOW + 600 ) );

		$this->assertStringStartsWith( 'section,code,kind,reference,rule,age_days,since,detail,framing', $csv );
		$this->assertStringContainsString( 'report_only_never_deletes', $csv );
		$this->assertStringContainsString( 'finding,resurrection,plugin,' . self::GONE . ',allow,', $csv );
		$this->assertStringContainsString( 'finding,dangling_plugin_rule,plugin,old/old.php,deny,', $csv );
		$this->assertStringContainsString( 'finding,dangling_role,role,ghost,', $csv );
		$this->assertStringContainsString( 'live,,plugin,' . self::LIVE . ',allow', $csv );
		$this->assertStringContainsString( 'history,resurrection,plugin,' . self::GONE, $csv );
		$this->assertStringContainsString( 'resurrection=1', $csv );
	}

	public function test_csv_neutralizes_formula_injection(): void {
		$this->assertSame( "'=cmd", Tombstone::csv_line( array( '=cmd' ) ) );
		$this->assertSame( '"a,b"', Tombstone::csv_line( array( 'a,b' ) ) );
	}

	public function test_print_html_is_report_only_and_escaped(): void {
		$this->enable();
		$snap                        = Tombstone::snapshot( self::NOW );
		$snap['findings'][0]['summary'] = '<script>alert(1)</script>';
		$html                        = Tombstone::build_print_html( $snap );
		$this->assertStringContainsString( 'Report only', $html );
		$this->assertStringNotContainsString( '<script>', $html );
	}

	public function test_cli_exit_is_non_zero_only_on_resurrection(): void {
		$this->enable();
		$dangling = Tombstone::snapshot( self::NOW );
		$this->assertSame( 1, $dangling['dangling_count'] );
		$this->assertSame( 0, CLI_Tombstone::exit_code( $dangling ), 'dangling alone exits 0' );

		Tombstone::set_test_installed_plugins( array( self::LIVE, self::GONE ) );
		Tombstone::maybe_check( self::NOW + 600, true );
		$this->assertSame( 1, CLI_Tombstone::exit_code( Tombstone::snapshot( self::NOW + 600 ) ) );

		$this->put_policy( array( self::LIVE => 'allow' ) );
		Tombstone::maybe_check( self::NOW + 1200, true );
		$this->assertSame( 0, CLI_Tombstone::exit_code( Tombstone::snapshot( self::NOW + 1200 ) ) );
	}

	public function test_render_page_off_and_on(): void {
		ob_start();
		Tombstone::render_page();
		$off = (string) ob_get_clean();
		$this->assertStringContainsString( 'Tombstone is off', $off );

		$this->reinstall_gone_plugin();
		Tombstone::maybe_check( self::NOW + 600, true );
		ob_start();
		Tombstone::render_page();
		$on = (string) ob_get_clean();
		$this->assertStringContainsString( 'Report only', $on );
		$this->assertStringContainsString( self::GONE, $on );
		$this->assertStringContainsString( 'live again', $on );
	}

	public function test_state_sanitizer_drops_junk_and_caps_history(): void {
		$history = array();
		for ( $i = 0; $i < Tombstone::HISTORY_CAP + 10; $i++ ) {
			$history[] = array( 'plugin' => 'p' . $i . '/p' . $i . '.php', 'ts' => 5, 'via' => 'weird' );
		}
		$state = Tombstone::sanitize_state(
			array(
				'dangling' => array(
					'x'  => array( 'kind' => 'nope', 'ref' => 'a' ),
					'y'  => array( 'kind' => 'user', 'ref' => '0' ),
					'z'  => 'junk',
					'ok' => array( 'kind' => 'role', 'ref' => 'Ghost Role', 'rule' => 'allowed_role', 'since' => 5 ),
				),
				'history'  => $history,
			)
		);
		$this->assertSame( array( 'role:ghostrole' ), array_keys( $state['dangling'] ) );
		$this->assertCount( Tombstone::HISTORY_CAP, $state['history'] );
		$this->assertSame( 'inventory', $state['history'][0]['via'] );
		$this->assertSame( Tombstone::defaults_state(), Tombstone::sanitize_state( 'junk' ) );
	}

	public function test_plugin_wires_tombstone_after_rescan_schedule(): void {
		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-handl-aicac-plugin.php' );
		$this->assertLessThan(
			strpos( $source, 'Tombstone::init();' ),
			strpos( $source, 'Rescan_Schedule::init();' )
		);
		$this->assertLessThan(
			strpos( $source, "class-handl-aicac-tombstone.php'" ),
			strpos( $source, "class-handl-aicac-rescan-schedule.php'" )
		);
	}
}
