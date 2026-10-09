<?php
/**
 * AICAC-FIRST-DENY (#326): one-time first-block explainer.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\First_Deny;
use HandL\AICAC\Inbox_Actions;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Quiet_Hours;
use HandL\AICAC\Temp_Allow;
use PHPUnit\Framework\TestCase;

final class FirstDenyTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		First_Deny::reset_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		update_option( 'admin_email', 'admin@example.com' );
		$GLOBALS['handl_aicac_test_plugins'] = array(
			'seo/seo.php' => array(
				'Name'    => 'SEO Writer',
				'Version' => '1.0.0',
			),
		);
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_wp_mail']               = static function ( $to, $subject, $message ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);
			return true;
		};
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_wp_mail'],
			$GLOBALS['handl_aicac_test_plugins'],
			$GLOBALS['handl_aicac_test_current_user_can']
		);
		First_Deny::reset_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		parent::tearDown();
	}

	public function test_fires_once_on_first_real_deny(): void {
		$policy = $this->persist_policy();
		$first  = First_Deny::observe( $this->deny_event(), $policy );
		$this->assertTrue( $first['fired'] );
		$this->assertSame( 'ok', $first['reason'] );

		$state = First_Deny::get_state();
		$this->assertTrue( $state['fired'] );
		$this->assertTrue( $state['pending'] );
		$this->assertSame( 'seo/seo.php', $state['plugin'] );
		$this->assertSame( 'rule', $state['source'] );

		$second = First_Deny::observe( $this->deny_event( array( 'ts' => 1_700_000_100 ) ), $policy );
		$this->assertFalse( $second['fired'] );
		$this->assertSame( 'already_fired', $second['reason'] );
	}

	public function test_skips_demo_selftest_and_storm_rows(): void {
		$policy = $this->persist_policy();

		$demo = First_Deny::observe(
			$this->deny_event( array( 'demo' => true ) ),
			$policy
		);
		$this->assertSame( 'demo', $demo['reason'] );

		$selftest = First_Deny::observe(
			$this->deny_event( array( 'selftest' => true ) ),
			$policy
		);
		$this->assertSame( 'selftest', $selftest['reason'] );

		$storm = First_Deny::observe(
			$this->deny_event( array( 'retry_storm' => true ) ),
			$policy
		);
		$this->assertSame( 'storm', $storm['reason'] );

		$collapsed = First_Deny::observe(
			$this->deny_event( array( 'retry_storm_collapsed' => true ) ),
			$policy
		);
		$this->assertSame( 'storm', $collapsed['reason'] );

		$this->assertFalse( First_Deny::get_state()['fired'] );
	}

	public function test_skips_allow_and_unknown_plugin(): void {
		$policy = $this->persist_policy();
		$allow  = First_Deny::observe(
			array(
				'ts'       => 1_700_000_000,
				'plugin'   => 'seo/seo.php',
				'decision' => 'allow',
				'source'   => 'rule',
			),
			$policy
		);
		$this->assertSame( 'not_deny', $allow['reason'] );

		$unknown = First_Deny::observe(
			$this->deny_event( array( 'plugin' => '' ) ),
			$policy
		);
		$this->assertSame( 'no_plugin', $unknown['reason'] );
	}

	public function test_dismiss_hides_notice_forever(): void {
		First_Deny::observe( $this->deny_event(), $this->persist_policy() );
		$this->assertTrue( First_Deny::get_state()['pending'] );

		First_Deny::dismiss();
		$state = First_Deny::get_state();
		$this->assertTrue( $state['fired'] );
		$this->assertFalse( $state['pending'] );

		ob_start();
		First_Deny::instance()->maybe_render_notice();
		$html = (string) ob_get_clean();
		$this->assertSame( '', $html );

		// Survives a second observe attempt.
		$again = First_Deny::observe( $this->deny_event( array( 'ts' => 1_700_000_200 ) ), $this->persist_policy() );
		$this->assertSame( 'already_fired', $again['reason'] );
		$this->assertFalse( First_Deny::get_state()['pending'] );
	}

	public function test_notice_renders_with_activity_link_and_actions(): void {
		First_Deny::observe( $this->deny_event(), $this->persist_policy() );

		ob_start();
		First_Deny::instance()->maybe_render_notice();
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'handl-aicac-first-deny-notice', $html );
		$this->assertStringContainsString( 'SEO Writer', $html );
		$this->assertStringContainsString( 'Explicit rule', $html );
		$this->assertStringContainsString( 'handl_aicac_log_decision=deny', $html );
		$this->assertStringContainsString( 'handl_aicac_log_plugin=seo%2Fseo.php', $html );
		$this->assertStringContainsString( 'Temporarily allow', $html );
		$this->assertStringContainsString( 'Keep blocking', $html );
		$this->assertStringContainsString( First_Deny::ACTION_TEMP_ALLOW, $html );
		$this->assertStringContainsString( First_Deny::ACTION_DISMISS, $html );
	}

	public function test_temp_allow_reuses_inbox_24h_path(): void {
		$now = 1_700_000_000;
		First_Deny::observe( $this->deny_event( array( 'ts' => $now ) ), $this->persist_policy() );

		$ok = Inbox_Actions::apply_temp_allow_24h( 'seo/seo.php', $now );
		$this->assertTrue( $ok );
		First_Deny::dismiss();

		$policy = Policy::get_policy();
		$this->assertSame( 'allow', $policy['plugins']['seo/seo.php'] ?? null );
		$expires = Temp_Allow::sanitize_plugin_expires( $policy['plugin_expires'] ?? array() );
		$this->assertSame( $now + DAY_IN_SECONDS, $expires['seo/seo.php'] ?? 0 );
		$this->assertFalse( First_Deny::get_state()['pending'] );
	}

	public function test_admin_notice_still_shows_during_quiet_hours(): void {
		$policy = $this->persist_policy(
			array(
				'quiet_hours' => array(
					array(
						'id'    => 'qa-window',
						'name'  => 'Always',
						'days'  => array( 0, 1, 2, 3, 4, 5, 6 ),
						'start' => '00:00',
						'end'   => '23:59',
						'mode'  => Quiet_Hours::MODE_OBSERVE,
					),
				),
			)
		);

		$this->assertNotNull( Quiet_Hours::active_window( $policy ) );

		$hit = First_Deny::observe( $this->deny_event(), $policy );
		$this->assertTrue( $hit['fired'] );
		$this->assertTrue( First_Deny::get_state()['pending'] );

		ob_start();
		First_Deny::instance()->maybe_render_notice();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'handl-aicac-first-deny-notice', $html );
		$this->assertSame( array(), self::$mails );
	}

	public function test_append_log_event_fires_once(): void {
		$this->persist_policy( array( 'alert_on_deny' => false ) );

		Policy::append_log_event( $this->deny_event() );
		$this->assertTrue( First_Deny::get_state()['fired'] );
		$this->assertTrue( First_Deny::get_state()['pending'] );

		Policy::append_log_event( $this->deny_event( array( 'ts' => 1_700_000_100 ) ) );
		$state = First_Deny::get_state();
		$this->assertTrue( $state['fired'] );
		$this->assertSame( 'seo/seo.php', $state['plugin'] );
	}

	/**
	 * @param array<string,mixed> $overrides
	 * @return array<string,mixed>
	 */
	private function persist_policy( array $overrides = array() ): array {
		$policy = array_merge(
			array(
				'log_enabled'  => true,
				'audit_only'   => false,
				'alert_on_deny'=> false,
				'alert_email'  => 'admin@example.com',
				'default'      => 'deny',
			),
			$overrides
		);
		Policy::save_policy( $policy );
		return Policy::get_policy();
	}

	/**
	 * @param array<string,mixed> $overrides
	 * @return array<string,mixed>
	 */
	private function deny_event( array $overrides = array() ): array {
		return array_merge(
			array(
				'ts'        => 1_700_000_000,
				'plugin'    => 'seo/seo.php',
				'decision'  => 'deny',
				'source'    => 'rule',
				'operation' => 'generate_text',
				'provider'  => 'openai',
				'caller'    => 'SEO\\Writer::run',
			),
			$overrides
		);
	}
}
