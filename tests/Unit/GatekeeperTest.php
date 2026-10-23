<?php
/**
 * AICAC-GATEKEEPER (#421).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Gatekeeper;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class GatekeeperTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12 UTC.

	private const DAY = 86400;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$GLOBALS['handl_aicac_test_cron']             = array();
		Gatekeeper::reset_for_tests();
		update_option( 'admin_email', 'haktan+aicac-gatekeeper@handldigital.com' );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'alert_email' => 'haktan+aicac-gatekeeper@handldigital.com',
			)
		);
		Gatekeeper::set_test_now( self::NOW );
		Gatekeeper::set_test_roster( array() );
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_test_roles'] );
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_cron']          = array();
		Gatekeeper::reset_for_tests();
		parent::tearDown();
	}

	private function enable(): void {
		Gatekeeper::save_settings( array( 'enabled' => true ) );
	}

	/**
	 * @param string $path  role|direct|both.
	 * @param string $login Login.
	 * @return array<string,mixed>
	 */
	private function user( int $id, string $login, string $path = 'role' ): array {
		return array(
			'user_id'      => $id,
			'login'        => $login,
			'display_name' => ucfirst( $login ) . ' Person',
			'roles'        => array( 'administrator' ),
			'grant_path'   => $path,
		);
	}

	/**
	 * @param list<array<string,mixed>> $roster Roster.
	 */
	private function roster( array $roster ): void {
		Gatekeeper::set_test_roster( $roster );
	}

	/**
	 * Enable, observe the roster, then acknowledge it as the baseline.
	 *
	 * @param list<array<string,mixed>> $roster Roster.
	 */
	private function baseline( array $roster ): void {
		$this->enable();
		$this->roster( $roster );
		$this->assertTrue( Gatekeeper::maybe_check( self::NOW, true ) );
		$this->assertTrue( Gatekeeper::acknowledge( self::NOW + 10 ) );
	}

	private function recheck( int $at = self::NOW + 300 ): void {
		$this->assertTrue( Gatekeeper::maybe_check( $at, true ) );
	}

	public function test_defaults_off_save_defaults_deletes_and_noop_byte_identical(): void {
		$this->assertFalse( Gatekeeper::is_enabled() );
		$this->assertSame( array( 'enabled' => false ), Gatekeeper::defaults() );
		$this->assertSame( Gatekeeper::defaults(), Gatekeeper::get_settings() );
		$this->assertSame( 'report_only_never_edits_roles', Gatekeeper::FRAMING );
		$this->assertSame( 'handl-aicac-gatekeeper', Gatekeeper::PAGE_SLUG );
		$this->assertSame( 'handl_aicac_gatekeeper', Gatekeeper::SETTINGS_OPTION );
		$this->assertSame( 'handl_aicac_gatekeeper_state', Gatekeeper::STATE_OPTION );
		$this->assertSame( 'handl_aicac_gatekeeper_ack', Gatekeeper::ACTION_ACK );

		$this->assertTrue( Gatekeeper::save_settings( array( 'enabled' => true ) ) );
		$this->assertTrue( Gatekeeper::is_enabled() );
		$before = get_option( Gatekeeper::SETTINGS_OPTION );
		$this->assertFalse( Gatekeeper::save_settings( array( 'enabled' => true ) ) );
		$this->assertSame( $before, get_option( Gatekeeper::SETTINGS_OPTION ) );

		$this->assertTrue( Gatekeeper::save_settings( Gatekeeper::defaults() ) );
		$this->assertFalse( (bool) get_option( Gatekeeper::SETTINGS_OPTION, false ) );
		$this->assertFalse( Gatekeeper::save_settings( Gatekeeper::defaults() ) );
		$this->assertSame( Gatekeeper::defaults(), Gatekeeper::sanitize_settings( 'junk' ) );
	}

	public function test_disabled_does_nothing(): void {
		$this->roster( array( $this->user( 1, 'admin' ) ) );
		$this->assertFalse( Gatekeeper::maybe_check( self::NOW, true ) );
		$this->assertFalse( Gatekeeper::acknowledge( self::NOW ) );
		$this->assertFalse( get_option( Gatekeeper::STATE_OPTION, false ) );
		$this->assertFalse( Gatekeeper::maybe_fire_alerts( self::NOW ) );
	}

	public function test_roster_classifies_role_direct_and_both(): void {
		$this->enable();
		$this->roster(
			array(
				$this->user( 3, 'carol', 'both' ),
				$this->user( 1, 'alice', 'role' ),
				$this->user( 2, 'bob', 'direct' ),
				array(
					'user_id'    => 4,
					'login'      => 'dave',
					'roles'      => array( 'editor' ),
					'role_grant' => false,
					'direct_cap' => true,
				),
				array(
					'user_id'    => 5,
					'login'      => 'erin',
					'roles'      => array( 'administrator' ),
					'role_grant' => true,
					'direct_cap' => true,
				),
				array(
					'user_id'    => 6,
					'login'      => 'frank',
					'roles'      => array( 'administrator' ),
					'role_grant' => true,
				),
				array( 'login' => 'no-id' ),
			)
		);
		$snap = Gatekeeper::snapshot( self::NOW );
		$map  = array();
		foreach ( $snap['roster'] as $row ) {
			$map[ $row['login'] ] = $row['grant_path'];
		}
		$this->assertSame(
			array(
				'alice' => 'role',
				'bob'   => 'direct',
				'carol' => 'both',
				'dave'  => 'direct',
				'erin'  => 'both',
				'frank' => 'role',
			),
			$map
		);
		$this->assertSame( 6, $snap['roster_count'] );
		$this->assertSame( 1, $snap['roster'][0]['user_id'], 'Roster sorted by user id.' );

		$this->assertSame( 'both', Gatekeeper::classify_grant( true, true, true ) );
		$this->assertSame( 'role', Gatekeeper::classify_grant( true, false, true ) );
		$this->assertSame( 'direct', Gatekeeper::classify_grant( false, true, true ) );
		$this->assertSame( 'direct', Gatekeeper::classify_grant( false, false, true ), 'Can manage but no role grants it.' );
	}

	public function test_row_from_user_reads_roles_and_direct_caps_without_mutating(): void {
		$admin_role = new class() {
			/** @var array<string,bool> */
			public $capabilities = array( 'manage_options' => true );
			public $mutations    = 0;
			public function has_cap( string $cap ): bool {
				return ! empty( $this->capabilities[ $cap ] );
			}
		};
		$editor_role = new class() {
			/** @var array<string,bool> */
			public $capabilities = array( 'edit_posts' => true );
			public $mutations    = 0;
			public function has_cap( string $cap ): bool {
				return ! empty( $this->capabilities[ $cap ] );
			}
		};
		$GLOBALS['handl_aicac_test_roles'] = array(
			'administrator' => $admin_role,
			'editor'        => $editor_role,
		);

		$make = static function ( int $id, string $login, array $roles, array $caps ): object {
			return (object) array(
				'ID'           => $id,
				'user_login'   => $login,
				'display_name' => $login,
				'roles'        => $roles,
				'caps'         => $caps,
			);
		};

		$role_only = Gatekeeper::row_from_user( $make( 1, 'ra', array( 'administrator' ), array( 'administrator' => true ) ) );
		$direct    = Gatekeeper::row_from_user( $make( 2, 'rb', array( 'editor' ), array( 'editor' => true, 'manage_options' => true ) ) );
		$both      = Gatekeeper::row_from_user( $make( 3, 'rc', array( 'administrator' ), array( 'administrator' => true, 'manage_options' => true ) ) );
		$false_cap = Gatekeeper::row_from_user( $make( 4, 'rd', array( 'editor' ), array( 'editor' => true, 'manage_options' => false ) ) );

		$this->assertSame( 'role', $role_only['grant_path'] );
		$this->assertSame( 'direct', $direct['grant_path'] );
		$this->assertSame( 'both', $both['grant_path'] );
		$this->assertSame( 'direct', $false_cap['grant_path'], 'Fell through the query: can manage with no role grant.' );
		$this->assertNull( Gatekeeper::row_from_user( $make( 0, 'x', array(), array() ) ) );
		$this->assertNull( Gatekeeper::row_from_user( 'nope' ) );
		$this->assertSame( array( 'administrator' ), $role_only['roles'] );
		$this->assertSame( array( 'manage_options' => true ), $admin_role->capabilities, 'Role untouched.' );
		$this->assertSame( array( 'edit_posts' => true ), $editor_role->capabilities, 'Role untouched.' );
	}

	public function test_first_enable_has_no_alert_without_baseline_then_no_findings_after_ack(): void {
		$this->enable();
		$this->roster( array( $this->user( 1, 'alice' ), $this->user( 2, 'bob', 'direct' ) ) );
		$this->assertTrue( Gatekeeper::maybe_check( self::NOW, true ) );

		$snap = Gatekeeper::snapshot( self::NOW + 60 );
		$this->assertTrue( $snap['baseline_pending'] );
		$this->assertSame( 0, $snap['unacknowledged_count'] );
		$this->assertSame( array(), $snap['findings'] );
		$this->assertSame( 2, $snap['roster_count'] );
		$this->assertCount( 0, Gatekeeper::test_mails() );
		$this->assertFalse( Gatekeeper::is_alerted() );
		$this->assertSame( array(), Gatekeeper::get_state()['baseline'], 'Nothing auto-seeded.' );

		// Even a change before any acknowledgement stays quiet.
		$this->roster( array( $this->user( 1, 'alice' ), $this->user( 7, 'mallory', 'direct' ) ) );
		$this->recheck();
		$this->assertCount( 0, Gatekeeper::test_mails() );

		$this->assertTrue( Gatekeeper::acknowledge( self::NOW + 400 ) );
		$snap = Gatekeeper::snapshot( self::NOW + 500 );
		$this->assertFalse( $snap['baseline_pending'] );
		$this->assertSame( 0, $snap['unacknowledged_count'] );
		$this->assertSame( self::NOW + 400, $snap['acked_ts'] );
		$this->assertCount( 2, Gatekeeper::get_state()['baseline'] );
		$this->recheck( self::NOW + 700 );
		$this->assertCount( 0, Gatekeeper::test_mails() );
	}

	public function test_new_gatekeeper_after_ack_is_a_finding_and_alerts_once(): void {
		$this->baseline( array( $this->user( 1, 'alice' ) ) );

		$this->roster( array( $this->user( 1, 'alice' ), $this->user( 9, 'newbie' ) ) );
		$this->recheck( self::NOW + 3600 );

		$snap = Gatekeeper::snapshot( self::NOW + 3700 );
		$this->assertSame( 1, $snap['unacknowledged_count'] );
		$finding = $snap['findings'][0];
		$this->assertSame( 'new', $finding['code'] );
		$this->assertSame( 9, $finding['user_id'] );
		$this->assertTrue( $finding['is_new'] );
		$this->assertStringContainsString( '"newbie"', $finding['summary'] );
		$this->assertStringContainsString( 'Grant path: role', $finding['summary'] );
		$this->assertStringContainsString( 'First seen 2026-10-12 UTC', $finding['summary'] );

		$this->assertCount( 1, Gatekeeper::test_mails() );
		$this->assertTrue( Gatekeeper::is_alerted() );
		$mail = Gatekeeper::test_mails()[0];
		$this->assertStringContainsString( '[GATEKEEPER]', $mail['subject'] );
		$this->assertStringContainsString( 'haktan+aicac-gatekeeper@handldigital.com', $mail['to'] );
		$this->assertStringContainsString( '"newbie"', $mail['body'] );
		$this->assertStringContainsString( 'never adds, removes or edits a role or capability', $mail['body'] );

		// Further changes while latched: no second mail.
		$this->roster( array( $this->user( 1, 'alice' ), $this->user( 9, 'newbie' ), $this->user( 10, 'another' ) ) );
		$this->recheck( self::NOW + 7200 );
		$this->assertSame( 2, Gatekeeper::snapshot( self::NOW + 7300 )['unacknowledged_count'] );
		$this->assertCount( 1, Gatekeeper::test_mails() );
	}

	public function test_departed_after_ack_is_a_finding(): void {
		$this->baseline( array( $this->user( 1, 'alice' ), $this->user( 2, 'bob', 'direct' ) ) );
		$this->roster( array( $this->user( 1, 'alice' ) ) );
		$this->recheck();

		$snap = Gatekeeper::snapshot( self::NOW + 400 );
		$this->assertSame( 1, $snap['unacknowledged_count'] );
		$finding = $snap['findings'][0];
		$this->assertSame( 'departed', $finding['code'] );
		$this->assertSame( 2, $finding['user_id'] );
		$this->assertSame( 'direct', $finding['grant_path'] );
		$this->assertStringContainsString( '"bob"', $finding['summary'] );
		$this->assertStringContainsString( 'no longer on the roster', $finding['summary'] );
		$this->assertStringContainsString( '2026-10-12', $finding['summary'] );
		$this->assertCount( 1, Gatekeeper::test_mails() );
	}

	public function test_direct_grant_quiet_backdoor_is_a_finding(): void {
		$this->baseline( array( $this->user( 1, 'alice' ), $this->user( 2, 'bob' ) ) );

		// Existing role-only manager quietly gains a direct grant; a brand-new
		// user shows up holding the capability directly.
		$this->roster(
			array(
				$this->user( 1, 'alice' ),
				$this->user( 2, 'bob', 'both' ),
				$this->user( 3, 'sneaky', 'direct' ),
			)
		);
		$this->recheck();

		$findings = Gatekeeper::snapshot( self::NOW + 400 )['findings'];
		$by_user  = array();
		foreach ( $findings as $finding ) {
			$by_user[ $finding['login'] ] = $finding;
		}
		$this->assertCount( 2, $findings );
		$this->assertSame( 'direct_grant', $by_user['bob']['code'] );
		$this->assertFalse( $by_user['bob']['is_new'] );
		$this->assertSame( 'role', $by_user['bob']['previous_grant_path'] );
		$this->assertStringContainsString( 'Grant path: both', $by_user['bob']['summary'] );
		$this->assertStringContainsString( 'quiet backdoor', $by_user['bob']['summary'] );
		$this->assertSame( 'direct_grant', $by_user['sneaky']['code'] );
		$this->assertTrue( $by_user['sneaky']['is_new'] );
		$this->assertStringContainsString( 'Grant path: direct', $by_user['sneaky']['summary'] );
		$this->assertStringContainsString( 'directly on the account', $by_user['sneaky']['summary'] );
		$this->assertCount( 1, Gatekeeper::test_mails() );
	}

	public function test_unchanged_or_benign_changes_are_quiet(): void {
		$this->baseline( array( $this->user( 1, 'alice', 'both' ), $this->user( 2, 'bob', 'direct' ) ) );
		// Direct grant already in the baseline, then the role is added or dropped.
		$this->roster( array( $this->user( 1, 'alice', 'direct' ), $this->user( 2, 'bob', 'both' ) ) );
		$this->recheck();
		$this->assertSame( 0, Gatekeeper::snapshot( self::NOW + 400 )['unacknowledged_count'] );
		$this->assertCount( 0, Gatekeeper::test_mails() );

		// Direct path dropping back to role only is not a finding either.
		$this->roster( array( $this->user( 1, 'alice', 'role' ), $this->user( 2, 'bob', 'role' ) ) );
		$this->recheck( self::NOW + 700 );
		$this->assertSame( 0, Gatekeeper::snapshot( self::NOW + 800 )['unacknowledged_count'] );
	}

	public function test_acknowledge_clears_findings_and_rearms_latch(): void {
		$this->baseline( array( $this->user( 1, 'alice' ) ) );
		$this->roster( array( $this->user( 1, 'alice' ), $this->user( 2, 'bob' ) ) );
		$this->recheck();
		$this->assertTrue( Gatekeeper::is_alerted() );
		$this->assertCount( 1, Gatekeeper::test_mails() );

		$this->assertTrue( Gatekeeper::acknowledge( self::NOW + 500 ) );
		$state = Gatekeeper::get_state();
		$this->assertFalse( $state['alerted'], 'Latch cleared by the acknowledgement.' );
		$this->assertSame( self::NOW + 500, $state['acked_ts'] );
		$this->assertCount( 2, $state['baseline'] );
		$this->assertSame( 0, Gatekeeper::snapshot( self::NOW + 600 )['unacknowledged_count'] );
		$this->recheck( self::NOW + 800 );
		$this->assertCount( 1, Gatekeeper::test_mails(), 'Nothing new after the ack.' );

		// The next change re-arms the alert.
		$this->roster( array( $this->user( 1, 'alice' ), $this->user( 2, 'bob' ), $this->user( 3, 'carol', 'direct' ) ) );
		$this->recheck( self::NOW + 1200 );
		$this->assertCount( 2, Gatekeeper::test_mails() );
		$this->assertTrue( Gatekeeper::is_alerted() );

		// The roster reverting by itself also clears the latch (count == 0 path).
		$this->roster( array( $this->user( 1, 'alice' ), $this->user( 2, 'bob' ) ) );
		$this->recheck( self::NOW + 1600 );
		$this->assertFalse( Gatekeeper::is_alerted() );
		$this->assertCount( 2, Gatekeeper::test_mails() );
	}

	public function test_acknowledge_never_touches_roles_or_caps(): void {
		$role = new class() {
			/** @var array<string,bool> */
			public $capabilities = array( 'manage_options' => true );
			public function has_cap( string $cap ): bool {
				return ! empty( $this->capabilities[ $cap ] );
			}
			public function add_cap(): void {
				throw new \RuntimeException( 'add_cap must not be called' );
			}
			public function remove_cap(): void {
				throw new \RuntimeException( 'remove_cap must not be called' );
			}
		};
		$GLOBALS['handl_aicac_test_roles']    = array( 'administrator' => $role );
		$GLOBALS['handl_aicac_test_users']    = array( 2 => array( 'user_login' => 'bob' ) );
		$GLOBALS['handl_aicac_test_user_meta'] = array();
		$users_before                          = $GLOBALS['handl_aicac_test_users'];

		$this->baseline( array( $this->user( 1, 'alice' ) ) );
		$this->roster( array( $this->user( 1, 'alice' ), $this->user( 2, 'bob', 'direct' ) ) );
		$this->recheck();
		Gatekeeper::acknowledge( self::NOW + 500 );

		$this->assertSame( array( 'manage_options' => true ), $role->capabilities );
		$this->assertSame( $users_before, $GLOBALS['handl_aicac_test_users'] );
		$this->assertSame( array(), $GLOBALS['handl_aicac_test_user_meta'] );
		unset( $GLOBALS['handl_aicac_test_users'], $GLOBALS['handl_aicac_test_user_meta'] );
	}

	public function test_first_seen_is_persisted_and_preserved_across_ack(): void {
		$this->enable();
		$this->roster( array( $this->user( 1, 'alice' ) ) );
		Gatekeeper::maybe_check( self::NOW, true );
		$this->assertSame( array( 1 => self::NOW ), Gatekeeper::get_state()['first_seen'] );

		$this->roster( array( $this->user( 1, 'alice' ), $this->user( 2, 'bob' ) ) );
		Gatekeeper::maybe_check( self::NOW + self::DAY, true );
		$this->assertSame(
			array(
				1 => self::NOW,
				2 => self::NOW + self::DAY,
			),
			Gatekeeper::get_state()['first_seen']
		);

		Gatekeeper::acknowledge( self::NOW + ( 2 * self::DAY ) );
		$baseline = Gatekeeper::get_state()['baseline'];
		$this->assertSame( self::NOW, $baseline[1]['first_seen'] );
		$this->assertSame( self::NOW + self::DAY, $baseline[2]['first_seen'] );

		// A departed user keeps its first-seen date in the finding.
		$this->roster( array( $this->user( 1, 'alice' ) ) );
		Gatekeeper::maybe_check( self::NOW + ( 3 * self::DAY ), true );
		$finding = Gatekeeper::snapshot( self::NOW + ( 3 * self::DAY ) )['findings'][0];
		$this->assertSame( self::NOW + self::DAY, $finding['first_seen'] );
		$this->assertStringContainsString( '2026-10-13', $finding['summary'] );
	}

	public function test_throttle(): void {
		$this->enable();
		$this->assertTrue( Gatekeeper::maybe_check( self::NOW, true ) );
		$this->assertFalse( Gatekeeper::maybe_check( self::NOW + Gatekeeper::CHECK_THROTTLE_SECONDS - 1 ) );
		$this->assertTrue( Gatekeeper::maybe_check( self::NOW + Gatekeeper::CHECK_THROTTLE_SECONDS ) );
		$this->assertSame( self::NOW + Gatekeeper::CHECK_THROTTLE_SECONDS, Gatekeeper::get_state()['last_check_ts'] );
	}

	public function test_roster_is_capped(): void {
		$rows = array();
		for ( $i = 1; $i <= Gatekeeper::ROSTER_CAP + 25; $i++ ) {
			$rows[] = $this->user( $i, 'u' . $i );
		}
		$this->roster( $rows );
		$scan = Gatekeeper::scan_roster();
		$this->assertCount( Gatekeeper::ROSTER_CAP, $scan['rows'] );
		$this->assertTrue( $scan['truncated'] );

		$this->enable();
		$this->assertTrue( Gatekeeper::acknowledge( self::NOW ) );
		$this->assertCount( Gatekeeper::ROSTER_CAP, Gatekeeper::get_state()['baseline'] );
		// Users beyond the capped window are not reported as departed.
		$this->assertSame( 0, Gatekeeper::snapshot( self::NOW )['unacknowledged_count'] );
	}

	public function test_detection_runs_on_admin_init_and_never_schedules_cron(): void {
		$this->enable();
		Gatekeeper::init();

		$added = $GLOBALS['handl_aicac_test_added_actions'];
		$this->assertContains( 'admin_init', $added );
		$this->assertContains( 'admin_post_handl_aicac_gatekeeper_ack', $added );
		$this->assertContains( 'admin_post_handl_aicac_gatekeeper_save', $added );
		$this->assertSame( 3, count( array_filter( $added, static fn( $h ) => 'admin_init' === $h ) ), 'csv, print and the throttled check.' );
		foreach ( $added as $hook ) {
			$this->assertStringStartsNotWith( 'handl_aicac_gatekeeper', (string) $hook, 'No own cron hook.' );
		}

		$this->roster( array( $this->user( 1, 'alice' ) ) );
		Gatekeeper::maybe_check( self::NOW, true );
		Gatekeeper::acknowledge( self::NOW + 10 );
		$this->roster( array() );
		Gatekeeper::maybe_check( self::NOW + 300, true );
		$this->assertSame( array(), $GLOBALS['handl_aicac_test_cron'] );

		$source = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-gatekeeper.php' );
		$this->assertStringNotContainsString( 'wp_schedule_event', $source );
		$this->assertStringNotContainsString( 'wp_schedule_single_event', $source );
		$this->assertStringNotContainsString( 'wp_clear_scheduled_hook', $source );
		$this->assertStringNotContainsString( 'wp_unschedule_event', $source );
		$this->assertDoesNotMatchRegularExpression( '/const\s+CRON_HOOK\b/', $source );
	}

	public function test_init_attaches_no_check_when_disabled(): void {
		Gatekeeper::init();
		$added = $GLOBALS['handl_aicac_test_added_actions'];
		$this->assertContains( 'admin_menu', $added );
		$this->assertSame( 2, count( array_filter( $added, static fn( $h ) => 'admin_init' === $h ) ), 'Only csv/print handlers, no check.' );
	}

	public function test_writes_confined_to_own_two_options_and_never_roles_or_caps(): void {
		$this->enable();
		$this->roster( array( $this->user( 1, 'alice' ) ) );
		Gatekeeper::maybe_check( self::NOW, true );
		Gatekeeper::acknowledge( self::NOW + 10 );
		update_option( 'wp_user_roles', array( 'administrator' => array( 'capabilities' => array( 'manage_options' => true ) ) ) );
		update_option( 'wp_capabilities_probe', array( 'x' => true ) );
		$this->roster( array( $this->user( 1, 'alice' ), $this->user( 2, 'bob', 'direct' ) ) );

		$before = $GLOBALS['handl_aicac_test_options'];
		Gatekeeper::maybe_check( self::NOW + 300, true );
		Gatekeeper::csv_for_snapshot();
		Gatekeeper::build_print_html( Gatekeeper::snapshot() );
		Gatekeeper::acknowledge( self::NOW + 600 );
		$after = $GLOBALS['handl_aicac_test_options'];

		$changed = array();
		foreach ( array_unique( array_merge( array_keys( $before ), array_keys( $after ) ) ) as $key ) {
			if ( ( $before[ $key ] ?? null ) !== ( $after[ $key ] ?? null ) ) {
				$changed[] = $key;
			}
		}
		$changed = array_values( array_diff( $changed, array( 'handl_aicac_alert_health' ) ) );
		$this->assertSame( array( Gatekeeper::STATE_OPTION ), $changed, 'Only own state option written.' );
		$this->assertSame( $before['wp_user_roles'], $after['wp_user_roles'] );

		$source = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-gatekeeper.php' );
		preg_match_all( '/(?:update_option|delete_option|add_option)\(\s*([^,)\s]+)/', $source, $m );
		$this->assertNotEmpty( $m[1] );
		foreach ( $m[1] as $arg ) {
			$this->assertContains( $arg, array( 'self::SETTINGS_OPTION', 'self::STATE_OPTION' ), 'Write target ' . $arg );
		}
		foreach ( array( 'add_cap', 'remove_cap', 'wp_update_user', 'WP_Roles', 'add_role', 'remove_role', 'set_role', 'update_user_meta', 'delete_user_meta', 'wp_insert_user', 'wp_delete_user', 'wp_roles(' ) as $needle ) {
			$this->assertStringNotContainsString( $needle, $source, 'Suggestion-only: ' . $needle );
		}
		$this->assertSame( 0, preg_match( '/\$wpdb->(query|insert|update|delete|replace)\b/', $source ) );
	}

	public function test_roster_is_current_site_only(): void {
		$source = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-gatekeeper.php' );
		$this->assertStringContainsString( 'get_current_blog_id', $source );
		$this->assertStringNotContainsString( 'get_super_admins', $source );
		$this->assertStringNotContainsString( 'get_sites', $source );
		$this->assertStringNotContainsString( 'switch_to_blog', $source );
		$this->assertStringNotContainsString( "'network'", $source );
		$this->assertStringNotContainsString( 'network_wide', $source );
	}

	public function test_wp_die_only_in_own_save_and_ack_handlers(): void {
		$source = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-gatekeeper.php' );
		$start  = (int) strpos( $source, 'public static function handle_save' );
		$end    = (int) strpos( $source, 'public static function register_cli' );
		$this->assertGreaterThan( 0, $start );
		$this->assertGreaterThan( $start, $end );
		$before = substr( $source, 0, $start );
		$after  = substr( $source, $end );
		$this->assertStringNotContainsString( 'wp_die(', $before );
		$this->assertStringNotContainsString( 'wp_die(', $after );
		$middle = substr( $source, $start, $end - $start );
		$this->assertSame( 3, substr_count( $middle, 'wp_die(' ), 'save (2) + ack (1).' );
		$ack = (int) strpos( $middle, 'public static function handle_ack' );
		$this->assertStringContainsString( 'Caps::user_can_manage()', substr( $middle, $ack ) );
		$this->assertStringContainsString( 'check_admin_referer( self::ACTION_ACK )', substr( $middle, $ack ) );
	}

	public function test_csv_contains_grant_path_first_seen_findings_and_framing(): void {
		$this->baseline( array( $this->user( 1, 'alice' ), $this->user( 2, 'bob' ) ) );
		$this->roster(
			array(
				$this->user( 1, 'alice' ),
				$this->user( 4, '=evil', 'direct' ),
			)
		);
		$this->recheck();
		$csv = Gatekeeper::csv_for_snapshot();

		$this->assertStringContainsString( 'section,code,user_id,login,display_name,roles,grant_path,first_seen,summary,framing', $csv );
		$this->assertStringContainsString( 'report_only_never_edits_roles', $csv );
		$this->assertStringContainsString( 'roster,,1,alice,Alice Person,administrator,role,2026-10-12', $csv );
		$this->assertStringContainsString( ',direct,2026-10-12', $csv );
		$this->assertStringContainsString( 'finding,direct_grant,4', $csv );
		$this->assertStringContainsString( 'finding,departed,2,bob', $csv );
		$this->assertStringContainsString( "'=evil", $csv, 'Formula injection neutralized.' );
		$this->assertStringContainsString( 'roster=2 baseline=2 unacknowledged=2', $csv );
		$lines = explode( "\n", trim( $csv ) );
		array_shift( $lines );
		foreach ( $lines as $line ) {
			$this->assertStringEndsWith( 'report_only_never_edits_roles', $line );
		}

		$this->assertSame( "'=cmd", Gatekeeper::csv_line( array( '=cmd' ) ) );
		$this->assertSame( '"a,b"', Gatekeeper::csv_line( array( 'a,b' ) ) );
	}

	public function test_csv_with_pending_baseline(): void {
		$this->enable();
		$this->roster( array( $this->user( 1, 'alice', 'both' ) ) );
		$csv = Gatekeeper::csv_for_snapshot();
		$this->assertStringContainsString( 'baseline=pending', $csv );
		$this->assertStringContainsString( ',both,', $csv );
		$this->assertStringNotContainsString( 'finding,', $csv );
	}

	public function test_print_html_lists_findings_roster_and_framing(): void {
		$this->baseline( array( $this->user( 1, 'alice' ) ) );
		$this->roster( array( $this->user( 1, 'alice' ), $this->user( 2, 'bob&co', 'direct' ) ) );
		$html = Gatekeeper::build_print_html( Gatekeeper::snapshot( self::NOW + 400 ) );
		$this->assertStringContainsString( 'never adds, removes or edits a role or capability', $html );
		$this->assertStringContainsString( 'Manager roster', $html );
		$this->assertStringContainsString( 'direct_grant', $html );
		$this->assertStringContainsString( 'bob&amp;co', $html );
		$this->assertStringNotContainsString( 'bob&co', $html );
		$this->assertStringContainsString( 'No unacknowledged roster changes.', Gatekeeper::build_print_html( array( 'findings' => array() ) ) );
		$this->assertStringContainsString( 'No managers found on this site.', Gatekeeper::build_print_html( array() ) );
	}

	public function test_alert_delivery_failure_does_not_latch(): void {
		update_option( 'admin_email', '' );
		update_option( Plugin::OPTION_KEY, array( 'default' => 'allow' ) );
		$this->baseline( array( $this->user( 1, 'alice' ) ) );
		$this->roster( array( $this->user( 1, 'alice' ), $this->user( 2, 'bob' ) ) );
		$this->recheck();
		$this->assertFalse( Gatekeeper::is_alerted() );
		$this->assertCount( 0, Gatekeeper::test_mails() );
	}

	public function test_state_sanitization(): void {
		$bad = Gatekeeper::sanitize_state(
			array(
				'baseline'   => array(
					'x',
					array( 'user_id' => 0, 'login' => 'zero' ),
					array( 'user_id' => 7, 'login' => '<i>seven</i>', 'roles' => array( 'Admin Role!', '' ), 'grant_path' => 'bogus', 'first_seen' => -4 ),
				),
				'first_seen' => array( 3 => 100, 0 => 5, 4 => 'x', 5 => -1 ),
				'acked_ts'   => -9,
			)
		);
		$this->assertCount( 1, $bad['baseline'] );
		$this->assertSame( 'seven', $bad['baseline'][7]['login'] );
		$this->assertSame( array( 'adminrole' ), $bad['baseline'][7]['roles'] );
		$this->assertSame( 'direct', $bad['baseline'][7]['grant_path'], 'Unknown path with no role grant falls back to direct.' );
		$this->assertSame( 0, $bad['baseline'][7]['first_seen'] );
		$this->assertSame( array( 3 => 100 ), $bad['first_seen'] );
		$this->assertSame( 0, $bad['acked_ts'] );
		$this->assertSame( Gatekeeper::defaults_state(), Gatekeeper::sanitize_state( 'nope' ) );
	}

	public function test_admin_page_renders_ack_cta_and_saves_nothing(): void {
		$this->enable();
		$this->roster( array( $this->user( 1, 'alice' ) ) );
		if ( ! function_exists( 'checked' ) ) {
			$this->markTestSkipped( 'checked() stub unavailable.' );
		}
		$before = $GLOBALS['handl_aicac_test_options'];
		ob_start();
		Gatekeeper::render_page();
		$out = (string) ob_get_clean();
		$this->assertStringContainsString( 'Acknowledge current roster', $out );
		$this->assertStringContainsString( 'handl_aicac_gatekeeper_ack', $out );
		$this->assertStringContainsString( 'alice', $out );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'], 'Rendering writes nothing.' );
	}
}
