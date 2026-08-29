<?php
/**
 * Unit tests for AICAC-INBOX-ACTIONS (#225).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Snooze;
use HandL\AICAC\Alerts;
use HandL\AICAC\Email_Template;
use HandL\AICAC\Inbox_Actions;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Policy_Snapshots;
use PHPUnit\Framework\TestCase;

final class InboxActionsTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails                         = array();
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_user_id'] = 7;
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_wp_mail']      = static function ( $to, $subject, $message ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);
			return true;
		};
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
					'noisy/plugin.php' => 'deny',
				),
			)
		);
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'], $GLOBALS['handl_aicac_test_current_user_can'] );
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_user_id'] = 0;
		self::$mails                         = array();
		parent::tearDown();
	}

	public function test_compose_without_context_does_not_add_action_links(): void {
		$parts = Email_Template::compose( "Hello\n" );
		$this->assertSame( "Hello\n", Email_Template::extract_content( $parts['text'] ) );
		$this->assertStringNotContainsString( 'admin-post.php', $parts['text'] );
		$this->assertSame( array(), get_option( Inbox_Actions::OPTION_KEY, array() ) );
	}

	public function test_deny_email_embeds_signed_links_outside_content_block(): void {
		$content = "Denied body\n";
		$parts   = Inbox_Actions::with_mail(
			array(
				'plugin'    => 'noisy/plugin.php',
				'kind'      => 'denial',
				'recipient' => 'ops@example.test',
			),
			static function () use ( $content ) {
				return Email_Template::compose( $content );
			}
		);

		$this->assertSame( $content, Email_Template::extract_content( $parts['text'] ) );
		$this->assertStringContainsString( 'Allow this plugin for 24 hours:', $parts['text'] );
		$this->assertStringContainsString( 'Snooze these alerts for 7 days:', $parts['text'] );
		$this->assertStringContainsString( 'Open this plugin', $parts['text'] );
		$this->assertStringContainsString( 'admin-post.php', $parts['text'] );
		$this->assertStringContainsString( 'admin-post.php', $parts['html'] );
		$this->assertStringNotContainsString( 'ops@example.test', Email_Template::extract_content( $parts['text'] ) );
	}

	public function test_shadow_email_omits_allow_link(): void {
		$parts = Inbox_Actions::with_mail(
			array(
				'plugin'    => 'noisy/plugin.php',
				'kind'      => 'shadow',
				'recipient' => 'ops@example.test',
			),
			static function () {
				return Email_Template::compose( "Shadow\n" );
			}
		);
		$this->assertStringNotContainsString( 'Allow this plugin for 24 hours:', $parts['text'] );
		$this->assertStringContainsString( 'Snooze these alerts for 7 days:', $parts['text'] );
	}

	public function test_immediate_denial_mail_contains_links_and_preserves_body(): void {
		Alerts::maybe_notify_denial(
			array(
				'ts'        => time(),
				'plugin'    => 'noisy/plugin.php',
				'decision'  => 'deny',
				'operation' => 'generate_text',
			),
			Policy::get_policy()
		);
		Alerts::flush_deferred();
		$this->assertCount( 1, self::$mails );
		$msg = self::$mails[0]['message'];
		$this->assertStringContainsString( 'blocked an AI Client', self::$mails[0]['subject'] );
		$this->assertStringContainsString( 'admin-post.php', $msg );
		$this->assertStringContainsString( 'Allow this plugin for 24 hours:', $msg );
	}

	public function test_expired_and_replayed_tokens_change_nothing(): void {
		$now  = 1_700_000_000;
		$urls = $this->mint_urls( 'noisy/plugin.php', 'ops@example.test', 'denial', $now );
		$allow = $this->parse_token( $urls['allow_24h'] );

		$expired = Inbox_Actions::inspect( $allow['id'], $allow['sig'], $now + ( 49 * HOUR_IN_SECONDS ) );
		$this->assertFalse( $expired['ok'] );
		$this->assertSame( 'expired', $expired['error'] );

		$fresh = Inbox_Actions::inspect( $allow['id'], $allow['sig'], $now );
		$this->assertTrue( $fresh['ok'] );
		$this->assertIsArray( $fresh['row'] );

		$first = Inbox_Actions::apply_verified( $fresh['row'], $allow['id'], 7, $now );
		$this->assertTrue( $first['ok'] );

		$replay = Inbox_Actions::inspect( $allow['id'], $allow['sig'], $now + 10 );
		$this->assertFalse( $replay['ok'] );
		$this->assertSame( 'used', $replay['error'] );

		$tamper = Inbox_Actions::inspect( $allow['id'], str_repeat( 'a', 64 ), $now );
		$this->assertFalse( $tamper['ok'] );
		$this->assertSame( 'invalid', $tamper['error'] );
	}

	public function test_allow_24h_writes_policy_history_and_activity(): void {
		$now  = time();
		$urls = $this->mint_urls( 'noisy/plugin.php', 'ops@example.test', 'denial', $now );
		$tok  = $this->parse_token( $urls['allow_24h'] );
		$got  = Inbox_Actions::inspect( $tok['id'], $tok['sig'], $now );
		$this->assertTrue( $got['ok'] );

		$result = Inbox_Actions::apply_verified( $got['row'], $tok['id'], 7, $now );
		$this->assertTrue( $result['ok'] );
		$this->assertStringContainsString( '24 hours', $result['message'] );

		$policy = Policy::get_policy();
		$this->assertSame( 'allow', $policy['plugins']['noisy/plugin.php'] );
		$this->assertSame( $now + DAY_IN_SECONDS, (int) $policy['plugin_expires']['noisy/plugin.php'] );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $log );
		$last = $log[ count( $log ) - 1 ];
		$this->assertSame( 'inbox_allow_24h', $last['decision'] );
		$this->assertSame( 'email', $last['source'] );
		$this->assertSame( 7, (int) $last['actor_id'] );

		$history = get_option( Policy_Snapshots::HISTORY_OPTION_KEY, array() );
		$this->assertNotEmpty( $history );
	}

	public function test_snooze_7d_reuses_alert_snooze_engine(): void {
		$now  = time();
		$urls = $this->mint_urls( 'noisy/plugin.php', 'ops@example.test', 'shadow', $now );
		$tok  = $this->parse_token( $urls['snooze_7d'] );
		$got  = Inbox_Actions::inspect( $tok['id'], $tok['sig'], $now );
		$this->assertTrue( $got['ok'] );

		$result = Inbox_Actions::apply_verified( $got['row'], $tok['id'], 7, $now );
		$this->assertTrue( $result['ok'] );
		$this->assertTrue( Alert_Snooze::is_snoozed( 'noisy/plugin.php', $now + 10 ) );
		$this->assertSame( $now + WEEK_IN_SECONDS, (int) Alert_Snooze::until( 'noisy/plugin.php', $now + 10 ) );
	}

	public function test_open_rule_url_points_at_rules_tab(): void {
		$url = Inbox_Actions::rules_url( 'noisy/plugin.php' );
		$this->assertStringContainsString( 'page=handl-aicac-rules', $url );
		$this->assertStringContainsString( 'plugin=noisy', $url );
	}

	public function test_init_registers_admin_post_hooks_and_skips_nopriv_apply(): void {
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		Inbox_Actions::instance()->init();
		$hooks = $GLOBALS['handl_aicac_test_added_actions'];
		$this->assertContains( 'admin_post_handl_aicac_inbox', $hooks );
		$this->assertContains( 'admin_post_nopriv_handl_aicac_inbox', $hooks );
		$this->assertContains( 'admin_post_handl_aicac_inbox_apply', $hooks );
		$this->assertNotContains( 'admin_post_nopriv_handl_aicac_inbox_apply', $hooks );
	}

	/**
	 * @return array<string,string>
	 */
	private function mint_urls( string $plugin, string $recipient, string $kind, int $now ): array {
		$parts = Inbox_Actions::with_mail(
			array(
				'plugin'    => $plugin,
				'kind'      => $kind,
				'recipient' => $recipient,
				'now'       => $now,
			),
			static function () {
				return Email_Template::compose( "x\n" );
			}
		);
		$text = $parts['text'];
		$urls = array();
		if ( preg_match( '/Allow this plugin for 24 hours:\n(https?:\/\/\S+)/', $text, $m ) ) {
			$urls['allow_24h'] = $m[1];
		}
		if ( preg_match( '/Snooze these alerts for 7 days:\n(https?:\/\/\S+)/', $text, $m ) ) {
			$urls['snooze_7d'] = $m[1];
		}
		if ( preg_match( '/Open this plugin.+\n(https?:\/\/\S+)/', $text, $m ) ) {
			$urls['open_rule'] = $m[1];
		}

		return $urls;
	}

	/**
	 * @return array{id:string,sig:string}
	 */
	private function parse_token( string $url ): array {
		$parts = wp_parse_url( $url );
		parse_str( (string) ( $parts['query'] ?? '' ), $q );
		return array(
			'id'  => (string) ( $q['t'] ?? '' ),
			'sig' => (string) ( $q['s'] ?? '' ),
		);
	}
}
