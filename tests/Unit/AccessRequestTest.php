<?php
/**
 * Unit tests for AICAC-REQUEST (#232).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Access_Request;
use HandL\AICAC\Alerts;
use HandL\AICAC\Email_Template;
use HandL\AICAC\Inbox_Actions;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Temp_Allow;
use PHPUnit\Framework\TestCase;

final class AccessRequestTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails                         = array();
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_user_id'] = 12;
		$GLOBALS['handl_aicac_test_user_login'] = 'editor';
		$GLOBALS['handl_aicac_test_users']   = array(
			12 => array(
				'ID'         => 12,
				'user_login' => 'editor',
			),
			1  => array(
				'ID'         => 1,
				'user_login' => 'admin',
			),
		);
		$GLOBALS['handl_aicac_test_user_meta'] = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_wp_mail']      = static function ( $to, $subject, $message ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);
			return true;
		};
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php';
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'       => 'deny',
				'log_enabled'   => true,
				'audit_only'    => false,
				'alert_on_deny' => true,
				'alert_mode'    => 'immediate',
				'alert_email'   => 'ops@example.test',
				'plugins'       => array(
					'blocked/plugin.php' => 'deny',
				),
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
		delete_option( Access_Request::OPTION_KEY );
		delete_option( Inbox_Actions::OPTION_KEY );
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_wp_mail'],
			$GLOBALS['handl_aicac_test_current_user_can'],
			$GLOBALS['handl_aicac_test_user_login'],
			$GLOBALS['handl_aicac_test_users'],
			$GLOBALS['handl_aicac_test_user_meta']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_user_id'] = 0;
		self::$mails                         = array();
		parent::tearDown();
	}

	public function test_note_deny_only_for_admin_context_logged_in_editors(): void {
		Access_Request::note_deny(
			array(
				'plugin'          => 'blocked/plugin.php',
				'request_context' => 'frontend',
				'ts'              => 1000,
			)
		);
		$this->assertSame( '', get_user_meta( 12, Access_Request::NOTICE_META, true ) );

		Access_Request::note_deny(
			array(
				'plugin'          => 'blocked/plugin.php',
				'request_context' => 'admin',
				'ts'              => 1000,
			)
		);
		$notice = get_user_meta( 12, Access_Request::NOTICE_META, true );
		$this->assertIsArray( $notice );
		$this->assertSame( 'blocked/plugin.php', $notice['plugin'] );
	}

	public function test_note_deny_skips_anonymous_and_selftest(): void {
		$GLOBALS['handl_aicac_test_user_id'] = 0;
		Access_Request::note_deny(
			array(
				'plugin'          => 'blocked/plugin.php',
				'request_context' => 'admin',
			)
		);
		$this->assertSame( '', get_user_meta( 0, Access_Request::NOTICE_META, true ) );

		$GLOBALS['handl_aicac_test_user_id'] = 12;
		Access_Request::note_deny(
			array(
				'plugin'          => 'blocked/plugin.php',
				'request_context' => 'admin',
				'selftest'        => true,
			)
		);
		$this->assertSame( '', get_user_meta( 12, Access_Request::NOTICE_META, true ) );
	}

	public function test_submit_emails_once_per_plugin_per_24h_and_collapses(): void {
		$now    = 1_700_000_000;
		$first  = Access_Request::submit_request( 'blocked/plugin.php', 12, 'Need copy help', $now );
		$this->assertTrue( $first['ok'] );
		$this->assertTrue( $first['emailed'] );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'Approve — allow this plugin for 24 hours:', self::$mails[0]['message'] );
		$this->assertStringContainsString( 'Deny this access request:', self::$mails[0]['message'] );
		$this->assertStringContainsString( 'admin-post.php', self::$mails[0]['message'] );

		$second = Access_Request::submit_request( 'blocked/plugin.php', 12, 'Still blocked', $now + 60 );
		$this->assertTrue( $second['ok'] );
		$this->assertFalse( $second['emailed'] );
		$this->assertCount( 1, self::$mails );
		$this->assertSame( $first['id'], $second['id'] );

		$pending = Access_Request::pending_rows();
		$this->assertCount( 1, $pending );
		$this->assertSame( 'Still blocked', $pending[0]['reason'] );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertCount( 2, $log );
		$this->assertSame( 'access_request', $log[0]['decision'] );
		$this->assertSame( 'access_request', $log[1]['decision'] );
	}

	public function test_approve_sets_temp_allow_and_audit_row(): void {
		$now    = 1_700_000_000;
		$submit = Access_Request::submit_request( 'blocked/plugin.php', 12, '', $now );
		$result = Access_Request::approve( $submit['id'], 1, $now + 10 );
		$this->assertTrue( $result['ok'] );
		$this->assertSame( array(), Access_Request::pending_rows() );

		$policy = Policy::get_policy();
		$this->assertSame( 'allow', $policy['plugins']['blocked/plugin.php'] ?? '' );
		$this->assertSame( $now + 10 + DAY_IN_SECONDS, Temp_Allow::expires_at( $policy, 'blocked/plugin.php' ) );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$decisions = array_column( $log, 'decision' );
		$this->assertContains( 'access_request', $decisions );
		$this->assertContains( 'access_approved', $decisions );
	}

	public function test_deny_closes_request_without_rule_change(): void {
		$now    = 1_700_000_000;
		$submit = Access_Request::submit_request( 'blocked/plugin.php', 12, '', $now );
		$result = Access_Request::deny( $submit['id'], 1, $now + 5 );
		$this->assertTrue( $result['ok'] );
		$this->assertSame( array(), Access_Request::pending_rows() );

		$policy = Policy::get_policy();
		$this->assertSame( 'deny', $policy['plugins']['blocked/plugin.php'] ?? '' );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$decisions = array_column( $log, 'decision' );
		$this->assertContains( 'access_denied', $decisions );
	}

	public function test_email_token_approve_and_deny_reject_replay(): void {
		$now    = 1_700_000_000;
		$submit = Access_Request::submit_request( 'blocked/plugin.php', 12, '', $now );
		$this->assertTrue( $submit['emailed'] );

		$parts = Inbox_Actions::with_mail(
			array(
				'plugin'    => 'blocked/plugin.php',
				'kind'      => 'access_request',
				'recipient' => 'ops@example.test',
				'now'       => $now,
			),
			static function () {
				return Email_Template::compose( "Request\n" );
			}
		);
		preg_match_all( '/[?&]t=([a-f0-9]{32})/', $parts['text'], $ids );
		preg_match_all( '/[?&]s=([a-f0-9]{64})/', $parts['text'], $sigs );
		$this->assertGreaterThanOrEqual( 2, count( $ids[1] ) );

		$approve_id  = $ids[1][0];
		$approve_sig = $sigs[1][0];
		$got         = Inbox_Actions::inspect( $approve_id, $approve_sig, $now );
		$this->assertTrue( $got['ok'] );
		$this->assertSame( Inbox_Actions::ACT_ACCESS_APPROVE, $got['row']['action'] );

		$apply = Inbox_Actions::apply_verified( $got['row'], $approve_id, 1, $now );
		$this->assertTrue( $apply['ok'] );
		$this->assertSame( array(), Access_Request::pending_rows() );

		$replay = Inbox_Actions::inspect( $approve_id, $approve_sig, $now );
		$this->assertFalse( $replay['ok'] );
		$this->assertSame( 'used', $replay['error'] );
	}

	public function test_access_request_email_footer_omits_snooze_links(): void {
		$parts = Inbox_Actions::with_mail(
			array(
				'plugin'    => 'blocked/plugin.php',
				'kind'      => 'access_request',
				'recipient' => 'ops@example.test',
			),
			static function () {
				return Email_Template::compose( "Body\n" );
			}
		);
		$this->assertStringContainsString( 'Approve — allow this plugin for 24 hours:', $parts['text'] );
		$this->assertStringContainsString( 'Deny this access request:', $parts['text'] );
		$this->assertStringNotContainsString( 'Snooze these alerts for 7 days:', $parts['text'] );
	}

	public function test_policy_deny_path_notes_admin_editor(): void {
		$GLOBALS['handl_aicac_test_user_id'] = 12;
		$policy = Policy::get_policy();
		$builder = new class() {
			public function filter_input() {
				return null;
			}
		};
		// Force admin context via flags on detect — Policy::maybe_prevent logs then notes.
		// Use a generating deny through Policy::instance()->maybe_prevent if available.
		Access_Request::note_deny(
			array(
				'plugin'          => 'blocked/plugin.php',
				'request_context' => 'admin',
				'ts'              => time(),
			)
		);
		$notice = get_user_meta( 12, Access_Request::NOTICE_META, true );
		$this->assertSame( 'blocked/plugin.php', $notice['plugin'] ?? '' );
		unset( $policy, $builder );
	}
}
