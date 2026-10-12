<?php
/**
 * AICAC-RECERT (#359).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Recert;
use PHPUnit\Framework\TestCase;

final class RecertTest extends TestCase {

	private const DAY = 86400;

	/** @var int */
	private $now;

	protected function setUp(): void {
		parent::setUp();
		$this->now                           = time();
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_user_id'] = 1;
		$GLOBALS['handl_aicac_test_available_roles'] = array(
			'editor'  => 'Editor',
			'author'  => 'Author',
		);
		$GLOBALS['handl_aicac_wp_mail']      = static function ( $to, $subject, $message ) {
			$GLOBALS['handl_aicac_test_mails'][] = array(
				'to'      => $to,
				'subject' => $subject,
				'message' => $message,
			);
			return true;
		};
		$GLOBALS['handl_aicac_test_mails'] = array();

		Recert::reset_for_tests();
		$this->set_policy();
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_available_roles'],
			$GLOBALS['handl_aicac_wp_mail'],
			$GLOBALS['handl_aicac_test_mails'],
			$GLOBALS['handl_aicac_test_filters']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		Recert::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * @param array<string,mixed> $extra
	 */
	private function set_policy( array $extra = array() ): void {
		update_option(
			Plugin::OPTION_KEY,
			array_merge(
				array(
					'default'           => 'deny',
					'log_enabled'       => true,
					'alert_email'       => 'owner@example.com',
					'plugins'           => array(
						'perm/perm.php'  => 'allow',
						'temp/temp.php'  => 'allow',
						'gone/gone.php'  => 'allow',
						'deny/deny.php'  => 'deny',
					),
					'plugin_expires'    => array(
						'temp/temp.php' => $this->now + 400 * self::DAY,
						'gone/gone.php' => $this->now - 60,
					),
					'role_gate_enabled' => true,
					'allowed_roles'     => array( 'editor', 'author' ),
				),
				$extra
			)
		);
	}

	/**
	 * @return list<string>
	 */
	private function ids( array $inventory ): array {
		return array_map( static fn( $g ) => $g['grant_id'], $inventory );
	}

	/**
	 * @return array<string,mixed>
	 */
	private function enable( array $extra = array() ): void {
		Recert::save_settings( array_merge( array( 'enabled' => true ), $extra ) );
	}

	/**
	 * @return array{0:string,1:string}
	 */
	private function parse_url_token( string $url ): array {
		$query = (string) parse_url( $url, PHP_URL_QUERY );
		parse_str( $query, $q );
		return array( (string) ( $q['t'] ?? '' ), (string) ( $q['s'] ?? '' ) );
	}

	public function test_defaults_off_with_90_day_cycle(): void {
		$s = Recert::get_settings();
		$this->assertFalse( $s['enabled'] );
		$this->assertSame( 90, $s['cycle_days'] );
		$this->assertSame( 14, $s['grace_days'] );
		$this->assertFalse( $s['auto_suspend'] );
	}

	public function test_disabled_process_cycle_does_nothing(): void {
		$r = Recert::process_cycle( Policy::get_policy(), $this->now );
		$this->assertSame( 'inactive', $r['status'] );
		$this->assertSame( array(), $GLOBALS['handl_aicac_test_mails'] );
		$this->assertFalse( get_option( Recert::STATE_OPTION_KEY, false ) );
	}

	public function test_save_settings_is_noop_when_unchanged(): void {
		$this->assertFalse( Recert::save_settings( array() ) );
		$this->assertFalse( get_option( Recert::OPTION_KEY, false ), 'defaults must not write the option' );

		$this->assertTrue( Recert::save_settings( array( 'enabled' => true, 'cycle_days' => 30 ) ) );
		$stored = get_option( Recert::OPTION_KEY );
		$this->assertFalse( Recert::save_settings( array( 'enabled' => true, 'cycle_days' => 30 ) ) );
		$this->assertSame( $stored, get_option( Recert::OPTION_KEY ) );
		$this->assertSame( 30, Recert::get_settings()['cycle_days'] );
	}

	public function test_settings_are_clamped_and_state_is_separate(): void {
		Recert::save_settings( array( 'enabled' => true, 'cycle_days' => 99999, 'grace_days' => -4 ) );
		$s = Recert::get_settings();
		$this->assertSame( 365, $s['cycle_days'] );
		$this->assertSame( 0, $s['grace_days'] );
		$this->assertSame( array( 'enabled', 'cycle_days', 'grace_days', 'auto_suspend' ), array_keys( get_option( Recert::OPTION_KEY ) ) );
	}

	public function test_inventory_includes_temp_allow_and_role_gate_and_excludes_expired(): void {
		$inv = Recert::build_inventory( null, $this->now );
		$ids = $this->ids( $inv );

		$this->assertContains( 'temp_allow:perm/perm.php', $ids );
		$this->assertContains( 'temp_allow:temp/temp.php', $ids );
		$this->assertContains( 'role_gate:editor', $ids );
		$this->assertContains( 'role_gate:author', $ids );
		$this->assertNotContains( 'temp_allow:gone/gone.php', $ids, 'expired temp allow is not a grant' );
		$this->assertNotContains( 'temp_allow:deny/deny.php', $ids );

		$by = array_column( $inv, null, 'grant_id' );
		$this->assertNull( $by['temp_allow:perm/perm.php']['expires_at'] );
		$this->assertSame( $this->now + 400 * self::DAY, $by['temp_allow:temp/temp.php']['expires_at'] );
		$this->assertSame( 'Editor', $by['role_gate:editor']['label'] );
		$this->assertSame( 'unattested', $by['temp_allow:perm/perm.php']['status'] );
	}

	public function test_inventory_omits_role_gate_when_disabled(): void {
		$this->set_policy( array( 'role_gate_enabled' => false ) );
		$ids = $this->ids( Recert::build_inventory( null, $this->now ) );
		$this->assertNotContains( 'role_gate:editor', $ids );
	}

	public function test_inventory_attaches_last_used_ignoring_recert_rows(): void {
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array( 'ts' => $this->now - 500, 'plugin' => 'perm/perm.php', 'decision' => 'allow' ),
				array( 'ts' => $this->now - 100, 'plugin' => 'perm/perm.php', 'decision' => 'recert_confirm', 'channel' => 'recert' ),
				array( 'ts' => $this->now - 50, 'plugin' => 'perm/perm.php', 'decision' => 'x', 'channel' => 'direct_http' ),
			),
			false
		);
		$by = array_column( Recert::build_inventory( null, $this->now ), null, 'grant_id' );
		$this->assertSame( $this->now - 500, $by['temp_allow:perm/perm.php']['last_used_ts'] );
		$this->assertNull( $by['temp_allow:temp/temp.php']['last_used_ts'] );
	}

	public function test_filter_registers_extra_grant_source(): void {
		$GLOBALS['handl_aicac_test_filters']['handl_aicac_recert_grant_sources'] = static function ( $sources ) {
			$sources['custom'] = array(
				array(
					'grant_id' => 'custom:thing-1',
					'source'   => 'custom',
					'label'    => 'Custom thing',
				),
			);
			return $sources;
		};
		$by = array_column( Recert::build_inventory( null, $this->now ), null, 'grant_id' );
		$this->assertArrayHasKey( 'custom:thing-1', $by );
		$this->assertSame( 'Custom thing', $by['custom:thing-1']['label'] );
		$this->assertSame( 'custom', $by['custom:thing-1']['source'] );
	}

	public function test_confirm_grant_updates_state_and_audits(): void {
		$this->enable( array( 'cycle_days' => 30 ) );
		$this->assertTrue( Recert::confirm_grant( 'temp_allow:perm/perm.php', 9, $this->now ) );

		$row = Recert::get_state()['grants']['temp_allow:perm/perm.php'];
		$this->assertSame( $this->now, $row['confirmed_ts'] );
		$this->assertSame( $this->now + 30 * self::DAY, $row['next_due_ts'] );
		$this->assertFalse( $row['flagged'] );

		$by = array_column( Recert::build_inventory( null, $this->now ), null, 'grant_id' );
		$this->assertSame( 'ok', $by['temp_allow:perm/perm.php']['status'] );
		$this->assertFalse( $by['temp_allow:perm/perm.php']['unattested'] );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertNotEmpty( $log );
		$last = end( $log );
		$this->assertSame( 'recert_confirm', $last['decision'] );
		$this->assertSame( 'recert', $last['channel'] );
		$this->assertSame( 9, $last['actor_id'] );
		$this->assertSame( 'perm/perm.php', $last['plugin'] );
	}

	public function test_confirm_unknown_grant_fails(): void {
		$this->assertFalse( Recert::confirm_grant( 'temp_allow:nope/nope.php', 1, $this->now ) );
		$this->assertFalse( Recert::confirm_grant( 'garbage', 1, $this->now ) );
	}

	public function test_revoke_temp_allow_clears_plugin_rule(): void {
		Recert::confirm_grant( 'temp_allow:perm/perm.php', 1, $this->now );
		$this->assertTrue( Recert::revoke_grant( 'temp_allow:perm/perm.php', 3, $this->now ) );

		$policy = Policy::get_policy();
		$this->assertArrayNotHasKey( 'perm/perm.php', $policy['plugins'] );
		$this->assertArrayNotHasKey( 'temp_allow:perm/perm.php', Recert::get_state()['grants'] );

		$last = get_option( Plugin::LOG_OPTION_KEY );
		$last = end( $last );
		$this->assertSame( 'recert_revoke', $last['decision'] );
		$this->assertFalse( Recert::revoke_grant( 'temp_allow:perm/perm.php', 3, $this->now ), 'already gone' );
	}

	public function test_revoke_role_gate_removes_role(): void {
		$this->assertTrue( Recert::revoke_grant( 'role_gate:author', 3, $this->now ) );
		$policy = Policy::get_policy();
		$this->assertSame( array( 'editor' ), $policy['allowed_roles'] );
		$this->assertTrue( $policy['role_gate_enabled'] );
	}

	public function test_revoke_unknown_source_requires_filter_handler(): void {
		$GLOBALS['handl_aicac_test_filters']['handl_aicac_recert_grant_sources'] = static function ( $sources ) {
			$sources['custom'] = array( array( 'grant_id' => 'custom:x', 'source' => 'custom', 'label' => 'X' ) );
			return $sources;
		};
		$this->assertFalse( Recert::revoke_grant( 'custom:x', 1, $this->now ) );
	}

	public function test_cycle_start_seeds_state_and_emails_digest_with_links(): void {
		$this->enable();
		$r = Recert::process_cycle( Policy::get_policy(), $this->now );

		$this->assertTrue( $r['started'] );
		$this->assertTrue( $r['sent'] );
		$state = Recert::get_state();
		$this->assertNotSame( '', $state['cycle_id'] );
		$this->assertSame( $this->now, $state['cycle_started_ts'] );
		$this->assertCount( 4, $state['grants'] );
		$this->assertSame( $this->now, $state['grants']['role_gate:editor']['next_due_ts'] );

		$mails = $GLOBALS['handl_aicac_test_mails'];
		$this->assertCount( 1, $mails );
		$this->assertSame( 'owner@example.com', $mails[0]['to'] );
		// Multipart (plain + HTML) body: each link appears at least once per grant.
		$this->assertGreaterThanOrEqual( 4, substr_count( $mails[0]['message'], 'Confirm still needed:' ) );
		$this->assertGreaterThanOrEqual( 4, substr_count( $mails[0]['message'], 'Revoke:' ) );
		$this->assertCount( 8, get_option( Recert::TOKENS_OPTION_KEY ), 'one confirm + one revoke token per grant' );
		$this->assertStringContainsString( Recert::OPEN_HOOK, $mails[0]['message'] );
		$this->assertStringContainsString( 'perm/perm.php', $mails[0]['message'] );

		// Same cycle, next daily run: no second digest, no restart.
		$again = Recert::process_cycle( Policy::get_policy(), $this->now + self::DAY );
		$this->assertFalse( $again['started'] );
		$this->assertFalse( $again['sent'] );
		$this->assertCount( 1, $GLOBALS['handl_aicac_test_mails'] );
	}

	public function test_new_cycle_starts_after_cycle_days(): void {
		$this->enable( array( 'cycle_days' => 30 ) );
		Recert::process_cycle( Policy::get_policy(), $this->now );
		$first = Recert::get_state()['cycle_id'];

		$r = Recert::process_cycle( Policy::get_policy(), $this->now + 29 * self::DAY );
		$this->assertFalse( $r['started'] );

		$r = Recert::process_cycle( Policy::get_policy(), $this->now + 30 * self::DAY );
		$this->assertTrue( $r['started'] );
		$this->assertNotSame( $first, Recert::get_state()['cycle_id'] );
		$this->assertCount( 2, $GLOBALS['handl_aicac_test_mails'] );
	}

	public function test_digest_retries_when_mail_fails(): void {
		$GLOBALS['handl_aicac_wp_mail'] = static function () {
			return false;
		};
		$this->enable();
		$r = Recert::process_cycle( Policy::get_policy(), $this->now );
		$this->assertTrue( $r['started'] );
		$this->assertFalse( $r['sent'] );
		$this->assertSame( 0, Recert::get_state()['digest_sent_ts'] );

		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) {
			$GLOBALS['handl_aicac_test_mails'][] = compact( 'to', 'subject', 'message' );
			return true;
		};
		$r = Recert::process_cycle( Policy::get_policy(), $this->now + self::DAY );
		$this->assertFalse( $r['started'] );
		$this->assertTrue( $r['sent'] );
	}

	public function test_grace_sweep_flags_unattested_but_keeps_grant(): void {
		$this->enable( array( 'grace_days' => 14 ) );
		Recert::process_cycle( Policy::get_policy(), $this->now );
		Recert::confirm_grant( 'role_gate:editor', 1, $this->now + 100 );

		// Inside grace: nothing flagged.
		$r = Recert::grace_sweep( Policy::get_policy(), $this->now + 14 * self::DAY );
		$this->assertSame( 0, $r['flagged'] );

		$r = Recert::grace_sweep( Policy::get_policy(), $this->now + 14 * self::DAY + 1 );
		$this->assertSame( 3, $r['flagged'], 'editor confirmed; the other three are flagged' );
		$this->assertSame( 0, $r['suspended'] );

		$by = array_column( Recert::build_inventory( null, $this->now + 15 * self::DAY ), null, 'grant_id' );
		$this->assertSame( 'flagged', $by['temp_allow:perm/perm.php']['status'] );
		$this->assertSame( 'ok', $by['role_gate:editor']['status'] );
		$this->assertArrayHasKey( 'perm/perm.php', Policy::get_policy()['plugins'] );

		// Idempotent: already flagged grants are not re-flagged.
		$r = Recert::grace_sweep( Policy::get_policy(), $this->now + 20 * self::DAY );
		$this->assertSame( 0, $r['flagged'] );

		$decisions = array_column( get_option( Plugin::LOG_OPTION_KEY ), 'decision' );
		$this->assertSame( 3, count( array_keys( $decisions, 'recert_flagged', true ) ) );
	}

	public function test_auto_suspend_revokes_after_grace(): void {
		$this->enable( array( 'grace_days' => 7, 'auto_suspend' => true ) );
		Recert::process_cycle( Policy::get_policy(), $this->now );
		Recert::confirm_grant( 'temp_allow:perm/perm.php', 1, $this->now + 10 );

		$r = Recert::process_cycle( Policy::get_policy(), $this->now + 8 * self::DAY );
		$this->assertSame( 3, $r['flagged'] );
		$this->assertSame( 3, $r['suspended'] );

		$policy = Policy::get_policy();
		$this->assertArrayHasKey( 'perm/perm.php', $policy['plugins'] );
		$this->assertArrayNotHasKey( 'temp/temp.php', $policy['plugins'] );
		$this->assertSame( array(), $policy['allowed_roles'] );

		$decisions = array_column( get_option( Plugin::LOG_OPTION_KEY ), 'decision' );
		$this->assertContains( 'recert_auto_suspend', $decisions );
		$this->assertContains( 'recert_flagged', $decisions );
	}

	public function test_auto_suspend_off_never_revokes(): void {
		$this->enable( array( 'grace_days' => 1 ) );
		Recert::process_cycle( Policy::get_policy(), $this->now );
		$r = Recert::process_cycle( Policy::get_policy(), $this->now + 5 * self::DAY );
		$this->assertSame( 4, $r['flagged'] );
		$this->assertSame( 0, $r['suspended'] );
		$this->assertArrayHasKey( 'temp/temp.php', Policy::get_policy()['plugins'] );
	}

	public function test_mint_and_inspect_valid_token(): void {
		$url = Recert::mint_url( Recert::ACT_CONFIRM, 'temp_allow:perm/perm.php', 'owner@example.com', $this->now );
		[ $id, $sig ] = $this->parse_url_token( $url );
		$this->assertStringContainsString( 'action=' . Recert::OPEN_HOOK, $url );

		$got = Recert::inspect( $id, $sig, $this->now + 60 );
		$this->assertTrue( $got['ok'] );
		$this->assertSame( 'temp_allow:perm/perm.php', $got['row']['grant_id'] );
		$this->assertSame( Recert::ACT_CONFIRM, $got['row']['action'] );
		// Inspect is read-only (GET open must not consume).
		$this->assertTrue( Recert::inspect( $id, $sig, $this->now + 60 )['ok'] );
	}

	public function test_inspect_rejects_expired_used_and_bad_signature(): void {
		$url = Recert::mint_url( Recert::ACT_REVOKE, 'role_gate:editor', 'owner@example.com', $this->now );
		[ $id, $sig ] = $this->parse_url_token( $url );

		$this->assertSame( 'expired', Recert::inspect( $id, $sig, $this->now + 48 * 3600 )['error'] );
		$this->assertTrue( Recert::inspect( $id, $sig, $this->now + 48 * 3600 - 1 )['ok'] );

		$bad = str_repeat( 'a', 64 );
		$this->assertSame( 'invalid', Recert::inspect( $id, $bad, $this->now )['error'] );
		$this->assertSame( 'invalid', Recert::inspect( $id, 'short', $this->now )['error'] );
		$this->assertSame( 'invalid', Recert::inspect( str_repeat( 'b', 32 ), $sig, $this->now )['error'] );

		$got = Recert::inspect( $id, $sig, $this->now );
		$res = Recert::apply_verified( $got['row'], $id, 5, $this->now );
		$this->assertTrue( $res['ok'] );
		$this->assertSame( 'used', Recert::inspect( $id, $sig, $this->now )['error'] );
	}

	public function test_tampered_token_row_fails_signature(): void {
		$url = Recert::mint_url( Recert::ACT_CONFIRM, 'role_gate:editor', 'owner@example.com', $this->now );
		[ $id, $sig ] = $this->parse_url_token( $url );
		$map                       = get_option( Recert::TOKENS_OPTION_KEY );
		$map[ $id ]['grant_id']    = 'role_gate:author';
		update_option( Recert::TOKENS_OPTION_KEY, $map, false );
		$this->assertSame( 'invalid', Recert::inspect( $id, $sig, $this->now )['error'] );
	}

	public function test_apply_verified_confirm_and_revoke_via_token(): void {
		$map = Recert::mint_urls(
			array(
				array( 'grant_id' => 'role_gate:editor' ),
				array( 'grant_id' => 'temp_allow:temp/temp.php' ),
			),
			'owner@example.com',
			$this->now
		);
		$this->assertCount( 2, $map );

		[ $cid, $csig ] = $this->parse_url_token( $map['role_gate:editor']['confirm'] );
		$got            = Recert::inspect( $cid, $csig, $this->now );
		$this->assertTrue( Recert::apply_verified( $got['row'], $cid, 5, $this->now )['ok'] );
		$this->assertGreaterThan( 0, Recert::get_state()['grants']['role_gate:editor']['confirmed_ts'] );

		[ $rid, $rsig ] = $this->parse_url_token( $map['temp_allow:temp/temp.php']['revoke'] );
		$got            = Recert::inspect( $rid, $rsig, $this->now );
		$this->assertTrue( Recert::apply_verified( $got['row'], $rid, 5, $this->now )['ok'] );
		$this->assertArrayNotHasKey( 'temp/temp.php', Policy::get_policy()['plugins'] );

		// Revoke token for an already-removed grant is not consumed and reports gone.
		$again = Recert::mint_url( Recert::ACT_REVOKE, 'temp_allow:temp/temp.php', 'owner@example.com', $this->now );
		[ $id2, $sig2 ] = $this->parse_url_token( $again );
		$got2           = Recert::inspect( $id2, $sig2, $this->now );
		$res            = Recert::apply_verified( $got2['row'], $id2, 5, $this->now );
		$this->assertFalse( $res['ok'] );
		$this->assertSame( 'gone', $res['error'] );
		$this->assertTrue( Recert::inspect( $id2, $sig2, $this->now )['ok'] );
	}

	public function test_init_is_idempotent(): void {
		Recert::init();
		Recert::init();
		$this->assertTrue( true );
	}
}
