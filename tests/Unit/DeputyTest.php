<?php
/**
 * AICAC-DEPUTY (#357).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Access_Request;
use HandL\AICAC\Deputy;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class DeputyTest extends TestCase {

	private const NOW     = 1791800000; // 2026-10-12.
	private const REQ_ID  = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
	private const REQ_ID2 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
	private const PLUGIN  = 'blocked/plugin.php';
	private const DEPUTY  = 20;
	private const EDITOR  = 12;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_user_id']          = self::DEPUTY;
		$GLOBALS['handl_aicac_test_users']            = array(
			self::EDITOR => array(
				'ID'         => self::EDITOR,
				'user_login' => 'editor',
				'user_email' => 'editor@example.test',
				'roles'      => array( 'editor' ),
			),
			self::DEPUTY => array(
				'ID'         => self::DEPUTY,
				'user_login' => 'deputy',
				'user_email' => 'deputy@example.test',
				'roles'      => array( 'editor' ),
			),
			99           => array(
				'ID'         => 99,
				'user_login' => 'stranger',
				'user_email' => 'stranger@example.test',
				'roles'      => array( 'author' ),
			),
		);
		Deputy::reset_for_tests();
		putenv( 'HANDL_AICAC_TEST_NOW=' . (string) self::NOW );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'deny',
				'log_enabled' => true,
				'audit_only'  => false,
				'plugins'     => array(
					self::PLUGIN => 'deny',
				),
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
		delete_option( Access_Request::OPTION_KEY );
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_current_user_can'],
			$GLOBALS['handl_aicac_test_caps'],
			$GLOBALS['handl_aicac_test_users'],
			$GLOBALS['handl_aicac_test_user_id']
		);
		putenv( 'HANDL_AICAC_TEST_NOW' );
		$GLOBALS['handl_aicac_test_options'] = array();
		Deputy::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * @param array<string,mixed> $extra Extra settings.
	 */
	private function enable( array $extra = array() ): void {
		Deputy::save_settings(
			array_merge(
				array(
					'enabled'        => true,
					'deputy_user_id' => self::DEPUTY,
					'deputy_role'    => '',
					'sla_hours'      => 48,
					'expire_days'    => 0,
				),
				$extra
			)
		);
	}

	/**
	 * @param array<string,mixed> $extra Extra row fields.
	 */
	private function seed_pending( string $id, int $ts, array $extra = array() ): void {
		$map        = get_option( Access_Request::OPTION_KEY, array() );
		$map        = is_array( $map ) ? $map : array();
		$map[ $id ] = array_merge(
			array(
				'id'          => $id,
				'plugin'      => self::PLUGIN,
				'user_id'     => self::EDITOR,
				'user_login'  => 'editor',
				'reason'      => 'Need copy help',
				'status'      => Access_Request::STATUS_PENDING,
				'ts'          => $ts,
				'emailed_ts'  => $ts,
				'resolved_ts' => 0,
				'resolved_by' => 0,
			),
			$extra
		);
		update_option( Access_Request::OPTION_KEY, $map, false );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private function log_rows(): array {
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );

		return is_array( $log ) ? $log : array();
	}

	public function test_defaults_off_and_save_defaults_deletes(): void {
		$this->assertFalse( Deputy::is_enabled() );
		$this->assertSame( Deputy::defaults(), Deputy::get_settings() );
		$this->assertSame( 48, Deputy::defaults()['sla_hours'] );
		$this->assertSame( 0, Deputy::defaults()['expire_days'] );

		$this->assertTrue(
			Deputy::save_settings(
				array(
					'enabled'        => true,
					'deputy_user_id' => self::DEPUTY,
					'sla_hours'      => 48,
				)
			)
		);
		$this->assertTrue( Deputy::is_enabled() );
		$before  = get_option( Deputy::SETTINGS_OPTION );
		$changed = Deputy::save_settings(
			array(
				'enabled'        => true,
				'deputy_user_id' => self::DEPUTY,
				'sla_hours'      => 48,
			)
		);
		$this->assertFalse( $changed );
		$this->assertSame( $before, get_option( Deputy::SETTINGS_OPTION ) );

		Deputy::save_settings( Deputy::defaults() );
		$this->assertFalse( (bool) get_option( Deputy::SETTINGS_OPTION, false ) );
	}

	public function test_off_sweep_is_noop(): void {
		$hour = defined( 'HOUR_IN_SECONDS' ) ? (int) HOUR_IN_SECONDS : 3600;
		$this->seed_pending( self::REQ_ID, self::NOW - ( 50 * $hour ) );
		$result = Deputy::sweep( self::NOW );
		$this->assertSame( 0, $result['notified'] );
		$this->assertSame( 0, $result['expired'] );
		$this->assertCount( 0, Deputy::test_mails() );
		$this->assertCount( 1, Access_Request::pending_rows() );
	}

	public function test_pending_older_than_sla_notifies_once(): void {
		$hour = defined( 'HOUR_IN_SECONDS' ) ? (int) HOUR_IN_SECONDS : 3600;
		$this->enable();
		$this->seed_pending( self::REQ_ID, self::NOW - ( 50 * $hour ) );

		$first = Deputy::sweep( self::NOW );
		$this->assertSame( 1, $first['notified'] );
		$mails = Deputy::test_mails();
		$this->assertCount( 1, $mails );
		$this->assertSame( 'deputy@example.test', $mails[0]['to'] );
		$this->assertStringContainsString( '[DEPUTY]', $mails[0]['subject'] );
		$this->assertStringContainsString( 'admin-post.php', $mails[0]['body'] );
		$this->assertTrue( Deputy::was_notified( self::REQ_ID ) );

		$second = Deputy::sweep( self::NOW + 60 );
		$this->assertSame( 0, $second['notified'] );
		$this->assertCount( 1, Deputy::test_mails() );
	}

	public function test_pending_younger_than_sla_does_not_notify(): void {
		$hour = defined( 'HOUR_IN_SECONDS' ) ? (int) HOUR_IN_SECONDS : 3600;
		$this->enable();
		$this->seed_pending( self::REQ_ID, self::NOW - ( 10 * $hour ) );
		$result = Deputy::sweep( self::NOW );
		$this->assertSame( 0, $result['notified'] );
		$this->assertCount( 0, Deputy::test_mails() );
		$this->assertFalse( Deputy::was_notified( self::REQ_ID ) );
	}

	public function test_deputy_approve_without_manage_options_is_audit_logged(): void {
		$hour = defined( 'HOUR_IN_SECONDS' ) ? (int) HOUR_IN_SECONDS : 3600;
		$this->enable();
		$this->seed_pending( self::REQ_ID, self::NOW - ( 50 * $hour ) );
		$GLOBALS['handl_aicac_test_caps'] = array(
			'manage_options' => false,
		);
		$GLOBALS['handl_aicac_test_user_id'] = self::DEPUTY;

		$url = Deputy::mint_url( Deputy::ACT_APPROVE, self::REQ_ID, self::PLUGIN, self::NOW );
		$this->assertNotSame( '', $url );
		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $q );
		$got = Deputy::inspect( (string) ( $q['t'] ?? '' ), (string) ( $q['s'] ?? '' ), self::NOW );
		$this->assertTrue( $got['ok'] );

		$result = Deputy::apply_verified( $got['row'], (string) $q['t'], self::DEPUTY, self::NOW );
		$this->assertTrue( $result['ok'] );
		$this->assertSame( array(), Access_Request::pending_rows() );

		$reasons = array();
		foreach ( $this->log_rows() as $row ) {
			if ( 'deputy_approved' === ( $row['decision'] ?? '' ) ) {
				$reasons[] = (string) ( $row['reason'] ?? '' );
			}
		}
		$this->assertNotEmpty( $reasons );
		$this->assertStringContainsString( 'approved by deputy deputy (SLA breach, requester waited 50h)', $reasons[0] );

		$again = Deputy::inspect( (string) $q['t'], (string) $q['s'], self::NOW );
		$this->assertFalse( $again['ok'] );
		$this->assertSame( 'used', $again['error'] );
	}

	public function test_deputy_deny_without_manage_options(): void {
		$hour = defined( 'HOUR_IN_SECONDS' ) ? (int) HOUR_IN_SECONDS : 3600;
		$this->enable();
		$this->seed_pending( self::REQ_ID, self::NOW - ( 50 * $hour ) );
		$GLOBALS['handl_aicac_test_caps']    = array( 'manage_options' => false );
		$GLOBALS['handl_aicac_test_user_id'] = self::DEPUTY;

		$url = Deputy::mint_url( Deputy::ACT_DENY, self::REQ_ID, self::PLUGIN, self::NOW );
		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $q );
		$got    = Deputy::inspect( (string) ( $q['t'] ?? '' ), (string) ( $q['s'] ?? '' ), self::NOW );
		$result = Deputy::apply_verified( $got['row'], (string) $q['t'], self::DEPUTY, self::NOW );
		$this->assertTrue( $result['ok'] );
		$this->assertSame( array(), Access_Request::pending_rows() );

		$found = false;
		foreach ( $this->log_rows() as $row ) {
			if ( 'deputy_denied' === ( $row['decision'] ?? '' ) ) {
				$found = true;
				$this->assertStringContainsString( 'denied by deputy deputy (SLA breach, requester waited 50h)', (string) ( $row['reason'] ?? '' ) );
			}
		}
		$this->assertTrue( $found );
	}

	public function test_non_deputy_cannot_apply_valid_token(): void {
		$hour = defined( 'HOUR_IN_SECONDS' ) ? (int) HOUR_IN_SECONDS : 3600;
		$this->enable();
		$this->seed_pending( self::REQ_ID, self::NOW - ( 50 * $hour ) );
		$GLOBALS['handl_aicac_test_caps']    = array( 'manage_options' => false );
		$GLOBALS['handl_aicac_test_user_id'] = 99;

		$url = Deputy::mint_url( Deputy::ACT_APPROVE, self::REQ_ID, self::PLUGIN, self::NOW );
		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $q );
		$got    = Deputy::inspect( (string) ( $q['t'] ?? '' ), (string) ( $q['s'] ?? '' ), self::NOW );
		$result = Deputy::apply_verified( $got['row'], (string) $q['t'], 99, self::NOW );
		$this->assertFalse( $result['ok'] );
		$this->assertSame( 'cap', $result['error'] );
		$this->assertCount( 1, Access_Request::pending_rows() );
	}

	public function test_token_is_scoped_to_one_request(): void {
		$hour = defined( 'HOUR_IN_SECONDS' ) ? (int) HOUR_IN_SECONDS : 3600;
		$this->enable();
		$this->seed_pending( self::REQ_ID, self::NOW - ( 50 * $hour ) );
		$this->seed_pending( self::REQ_ID2, self::NOW - ( 50 * $hour ) );
		$GLOBALS['handl_aicac_test_caps'] = array( 'manage_options' => false );

		$url = Deputy::mint_url( Deputy::ACT_APPROVE, self::REQ_ID, self::PLUGIN, self::NOW );
		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $q );
		$got = Deputy::inspect( (string) ( $q['t'] ?? '' ), (string) ( $q['s'] ?? '' ), self::NOW );
		$this->assertSame( self::REQ_ID, $got['row']['request_id'] );

		Deputy::apply_verified( $got['row'], (string) $q['t'], self::DEPUTY, self::NOW );
		$pending = Access_Request::pending_rows();
		$this->assertCount( 1, $pending );
		$this->assertSame( self::REQ_ID2, (string) $pending[0]['id'] );
	}

	public function test_expired_token_does_not_apply(): void {
		$hour = defined( 'HOUR_IN_SECONDS' ) ? (int) HOUR_IN_SECONDS : 3600;
		$this->enable();
		$this->seed_pending( self::REQ_ID, self::NOW - ( 50 * $hour ) );
		$url = Deputy::mint_url( Deputy::ACT_APPROVE, self::REQ_ID, self::PLUGIN, self::NOW );
		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $q );
		$got = Deputy::inspect( (string) ( $q['t'] ?? '' ), (string) ( $q['s'] ?? '' ), self::NOW + Deputy::TOKEN_TTL + 1 );
		$this->assertFalse( $got['ok'] );
		$this->assertSame( 'expired', $got['error'] );
		$this->assertCount( 1, Access_Request::pending_rows() );
	}

	public function test_auto_expire_denies_with_reason_and_rerequest_link(): void {
		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
		$this->enable( array( 'expire_days' => 7 ) );
		$this->seed_pending( self::REQ_ID, self::NOW - ( 8 * $day ) );

		$result = Deputy::sweep( self::NOW );
		$this->assertSame( 1, $result['expired'] );
		$this->assertSame( 0, $result['notified'] );
		$this->assertSame( array(), Access_Request::pending_rows() );

		$kinds = array();
		foreach ( Deputy::test_mails() as $mail ) {
			$kinds[] = (string) ( $mail['kind'] ?? '' );
			if ( 'expired' === ( $mail['kind'] ?? '' ) ) {
				$this->assertSame( 'editor@example.test', $mail['to'] );
				$this->assertStringContainsString( 'expired', strtolower( (string) $mail['subject'] ) );
				$this->assertStringContainsString( 'wp-admin', (string) $mail['body'] );
				$this->assertStringContainsString( 'request access again', (string) $mail['body'] );
			}
		}
		$this->assertContains( 'expired', $kinds );

		$found = false;
		foreach ( $this->log_rows() as $row ) {
			if ( 'deputy_expired' === ( $row['decision'] ?? '' ) ) {
				$found = true;
				$this->assertStringContainsString( 'expired after 7 days', (string) ( $row['reason'] ?? '' ) );
			}
		}
		$this->assertTrue( $found );
	}

	public function test_auto_expire_off_does_not_expire(): void {
		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
		$this->enable( array( 'expire_days' => 0 ) );
		$this->seed_pending( self::REQ_ID, self::NOW - ( 30 * $day ) );
		$result = Deputy::sweep( self::NOW );
		$this->assertSame( 0, $result['expired'] );
		$this->assertSame( 1, $result['notified'] );
		$this->assertCount( 1, Access_Request::pending_rows() );
	}

	public function test_role_deputy_is_recognized(): void {
		$this->enable(
			array(
				'deputy_user_id' => 0,
				'deputy_role'    => 'editor',
			)
		);
		$this->assertTrue( Deputy::is_deputy( self::DEPUTY ) );
		$this->assertTrue( Deputy::is_deputy( self::EDITOR ) );
		$this->assertFalse( Deputy::is_deputy( 99 ) );
		$recs = Deputy::deputy_recipients();
		$emails = array();
		foreach ( $recs as $row ) {
			$emails[] = $row['email'];
		}
		$this->assertContains( 'deputy@example.test', $emails );
		$this->assertContains( 'editor@example.test', $emails );
	}

	public function test_render_page_off_and_overdue(): void {
		ob_start();
		Deputy::render_page();
		$off = (string) ob_get_clean();
		$this->assertStringContainsString( 'Deputy is off.', $off );
		$this->assertStringContainsString( 'Enable deputy', $off );

		$hour = defined( 'HOUR_IN_SECONDS' ) ? (int) HOUR_IN_SECONDS : 3600;
		$this->enable();
		$this->seed_pending( self::REQ_ID, self::NOW - ( 50 * $hour ) );
		Deputy::mark_notified( self::REQ_ID, 'deputy', self::NOW );
		ob_start();
		Deputy::render_page();
		$on = (string) ob_get_clean();
		$this->assertStringContainsString( 'Overdue requests', $on );
		$this->assertStringContainsString( self::PLUGIN, $on );
		$this->assertStringContainsString( '50h', $on );
		$this->assertStringContainsString( 'yes', $on );
		$this->assertStringContainsString( 'The site owner stays the primary approver', $on );
	}

	public function test_confirm_screen_is_scoped_copy(): void {
		$hour = defined( 'HOUR_IN_SECONDS' ) ? (int) HOUR_IN_SECONDS : 3600;
		$this->enable();
		$this->seed_pending( self::REQ_ID, self::NOW - ( 50 * $hour ) );
		$url = Deputy::mint_url( Deputy::ACT_APPROVE, self::REQ_ID, self::PLUGIN, self::NOW );
		parse_str( (string) parse_url( $url, PHP_URL_QUERY ), $q );
		$got = Deputy::inspect( (string) ( $q['t'] ?? '' ), (string) ( $q['s'] ?? '' ), self::NOW );
		ob_start();
		Deputy::render_confirm( (string) $q['t'], (string) $q['s'], $got['row'] );
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Deputy decision', $html );
		$this->assertStringContainsString( 'this one request', $html );
		$this->assertStringContainsString( '50 hours', $html );
		$this->assertStringContainsString( 'Approve for 24 hours', $html );
	}
}
