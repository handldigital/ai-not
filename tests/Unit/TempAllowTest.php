<?php
/**
 * Unit tests for temporary Allow expiry (AICAC-TEMP-ALLOW / #100).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Temp_Allow;
use PHPUnit\Framework\TestCase;

final class TempAllowTest extends TestCase {

	/** @var list<array{to:mixed,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_cron']    = array();
		self::$mails                        = array();
		$GLOBALS['handl_aicac_wp_mail']     = static function ( $to, $subject, $message ) {
			self::$mails[] = array(
				'to'      => $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);
			return true;
		};
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_cron']    = array();
		self::$mails                        = array();
		parent::tearDown();
	}

	public function test_expired_allow_falls_through_to_default_deny_at_decision_time(): void {
		$now    = 1_700_000_000;
		$plugin = 'campaign/plugin.php';
		$policy = array(
			'default'        => 'deny',
			'plugins'        => array( $plugin => 'allow' ),
			'plugin_expires' => array( $plugin => $now - 10 ),
		);

		$before = Policy::evaluate( $policy, $plugin, 'generate_text', null, null, $now - 100 );
		$this->assertFalse( $before['prevent'], 'Allow still valid before expiry' );

		$after = Policy::evaluate( $policy, $plugin, 'generate_text', null, null, $now );
		$this->assertTrue( $after['prevent'], 'Expired allow must stop allowing at decision time' );
		$this->assertSame( 'plugin', $after['reason'] );
	}

	public function test_unexpired_allow_still_overrides_default_deny(): void {
		$now    = 1_700_000_000;
		$plugin = 'ok/plugin.php';
		$policy = array(
			'default'        => 'deny',
			'plugins'        => array( $plugin => 'allow' ),
			'plugin_expires' => array( $plugin => $now + DAY_IN_SECONDS ),
		);

		$result = Policy::evaluate( $policy, $plugin, 'generate_text', null, null, $now );
		$this->assertFalse( $result['prevent'] );
	}

	public function test_permanent_allow_without_expiry_unaffected(): void {
		$plugin = 'forever/plugin.php';
		$policy = array(
			'default' => 'deny',
			'plugins' => array( $plugin => 'allow' ),
		);

		$result = Policy::evaluate( $policy, $plugin, 'generate_text', null, null, 1_700_000_000 );
		$this->assertFalse( $result['prevent'] );
	}

	public function test_resolve_posted_expiry_presets(): void {
		$now = 1_700_000_000;
		$this->assertNull( Temp_Allow::resolve_posted_expiry( '', '', $now ) );
		$this->assertSame( $now + DAY_IN_SECONDS, Temp_Allow::resolve_posted_expiry( '24h', '', $now ) );
		$this->assertSame( $now + ( 7 * DAY_IN_SECONDS ), Temp_Allow::resolve_posted_expiry( '7d', '', $now ) );
		$this->assertSame( $now + ( 30 * DAY_IN_SECONDS ), Temp_Allow::resolve_posted_expiry( '30d', '', $now ) );
	}

	public function test_remaining_label_expired_and_days(): void {
		$now    = 1_700_000_000;
		$plugin = 'x/y.php';
		$policy = array(
			'plugins'        => array( $plugin => 'allow' ),
			'plugin_expires' => array( $plugin => $now - 1 ),
		);
		$this->assertSame( 'Expired', Temp_Allow::remaining_label( $policy, $plugin, $now ) );

		$policy['plugin_expires'][ $plugin ] = $now + ( 3 * DAY_IN_SECONDS );
		$this->assertStringContainsString( '3 day', Temp_Allow::remaining_label( $policy, $plugin, $now ) );
	}

	public function test_sweep_removes_expired_writes_audit_and_emails_when_alerts_on(): void {
		$now    = 1_700_000_000;
		$plugin = 'temp/plugin.php';
		$policy = array(
			'default'        => 'deny',
			'plugins'        => array( $plugin => 'allow' ),
			'plugin_expires' => array( $plugin => $now - 5 ),
			'log_enabled'    => true,
			'alert_on_deny'  => true,
			'alert_email'    => 'haktan+temp-allow@handldigital.com',
		);
		update_option( Plugin::OPTION_KEY, $policy, false );
		update_option( Plugin::LOG_OPTION_KEY, array(), false );

		$result = Temp_Allow::sweep_expired( $policy, $now );

		$this->assertSame( array( $plugin ), $result['removed'] );
		$this->assertArrayNotHasKey( $plugin, $result['policy']['plugins'] );
		$this->assertArrayNotHasKey( $plugin, $result['policy']['plugin_expires'] );

		$stored = get_option( Plugin::OPTION_KEY );
		$this->assertIsArray( $stored );
		$this->assertArrayNotHasKey( $plugin, $stored['plugins'] ?? array() );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertNotEmpty( $log );
		$last = $log[ count( $log ) - 1 ];
		$this->assertSame( 'temp_allow_expired', $last['decision'] ?? '' );
		$this->assertSame( 'temp_allow', $last['channel'] ?? '' );
		$this->assertSame( $plugin, $last['plugin'] ?? '' );

		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'Temporary AI allow expired', self::$mails[0]['subject'] );
	}

	public function test_sweep_skips_email_when_alerts_disabled(): void {
		$now    = 1_700_000_000;
		$plugin = 'quiet/plugin.php';
		$policy = array(
			'default'        => 'allow',
			'plugins'        => array( $plugin => 'allow' ),
			'plugin_expires' => array( $plugin => $now - 1 ),
			'log_enabled'    => true,
			'alert_on_deny'  => false,
			'alert_on_shadow'=> false,
		);
		update_option( Plugin::OPTION_KEY, $policy, false );

		Temp_Allow::sweep_expired( $policy, $now );
		$this->assertSame( array(), self::$mails );
	}

	public function test_renew_extends_expiry_and_keeps_allow(): void {
		$now    = 1_700_000_000;
		$plugin = 'renew/me.php';
		$policy = array(
			'plugins'        => array( $plugin => 'allow' ),
			'plugin_expires' => array( $plugin => $now - 50 ),
		);

		$out = Temp_Allow::renew_allow_on_policy( $policy, $plugin, $now );
		$this->assertIsArray( $out );
		$this->assertSame( 'allow', $out['plugins'][ $plugin ] );
		$this->assertSame( $now + Temp_Allow::RENEW_SECONDS, $out['plugin_expires'][ $plugin ] );
	}

	public function test_normalize_drops_expiry_on_deny_rules(): void {
		$policy = array(
			'plugins'        => array( 'a/a.php' => 'deny' ),
			'plugin_expires' => array( 'a/a.php' => 999 ),
		);
		$out = Temp_Allow::normalize_expires_against_plugins( $policy );
		$this->assertSame( array(), $out['plugin_expires'] );
	}

	/** AICAC-EXPIRY-WARN (#142). */
	public function test_is_in_warn_window(): void {
		$now = 1_700_000_000;
		$this->assertFalse( Temp_Allow::is_in_warn_window( $now, $now ) );
		$this->assertFalse( Temp_Allow::is_in_warn_window( $now - 1, $now ) );
		$this->assertTrue( Temp_Allow::is_in_warn_window( $now + 1, $now ) );
		$this->assertTrue( Temp_Allow::is_in_warn_window( $now + Temp_Allow::WARN_WINDOW, $now ) );
		$this->assertFalse( Temp_Allow::is_in_warn_window( $now + Temp_Allow::WARN_WINDOW + 1, $now ) );
	}

	public function test_warn_sends_exactly_one_email_in_window_idempotent(): void {
		$now    = 1_700_000_000;
		$plugin = 'warn/me.php';
		$expiry = $now + ( 12 * HOUR_IN_SECONDS );
		$policy = array(
			'default'        => 'deny',
			'plugins'        => array( $plugin => 'allow' ),
			'plugin_expires' => array( $plugin => $expiry ),
			'alert_on_deny'  => true,
			'alert_email'    => 'haktan+expiry-warn@handldigital.com',
		);
		update_option( Plugin::OPTION_KEY, $policy, false );
		delete_option( Temp_Allow::WARNED_OPTION_KEY );

		$first = Temp_Allow::sweep_expired( $policy, $now );
		$this->assertSame( array( $plugin ), $first['warned'] );
		$this->assertSame( array(), $first['removed'] );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'expires within 24 hours', self::$mails[0]['subject'] );
		$this->assertStringContainsString( 'Expires:', self::$mails[0]['message'] );
		$this->assertStringContainsString( 'handl_aicac_tab=rules', self::$mails[0]['message'] );

		// Second sweep: no second mail.
		$second = Temp_Allow::sweep_expired( $policy, $now + 60 );
		$this->assertSame( array(), $second['warned'] );
		$this->assertCount( 1, self::$mails );
	}

	public function test_renew_clears_warned_flag_so_new_expiry_can_warn_again(): void {
		$now    = 1_700_000_000;
		$plugin = 'renew-warn/me.php';
		$expiry = $now + ( 6 * HOUR_IN_SECONDS );
		$policy = array(
			'plugins'        => array( $plugin => 'allow' ),
			'plugin_expires' => array( $plugin => $expiry ),
			'alert_on_deny'  => true,
			'alert_email'    => 'admin@example.com',
		);
		update_option( Plugin::OPTION_KEY, $policy, false );
		delete_option( Temp_Allow::WARNED_OPTION_KEY );

		Temp_Allow::sweep_expired( $policy, $now );
		$this->assertCount( 1, self::$mails );
		$map = Temp_Allow::get_warned_map();
		$this->assertSame( $expiry, $map[ $plugin ] ?? 0 );

		// Renew → new expiry far out; warned cleared.
		$renewed = Temp_Allow::renew_allow_on_policy( $policy, $plugin, $now );
		$this->assertIsArray( $renewed );
		$this->assertArrayNotHasKey( $plugin, Temp_Allow::get_warned_map() );

		// Approach new expiry (7d from now) — not yet in window.
		$new_exp = (int) $renewed['plugin_expires'][ $plugin ];
		self::$mails = array();
		$mid = Temp_Allow::sweep_expired( $renewed, $now + DAY_IN_SECONDS );
		$this->assertSame( array(), $mid['warned'] );
		$this->assertCount( 0, self::$mails );

		// Enter window for the new expiry.
		$near = $new_exp - ( 12 * HOUR_IN_SECONDS );
		$again = Temp_Allow::sweep_expired( $renewed, $near );
		$this->assertSame( array( $plugin ), $again['warned'] );
		$this->assertCount( 1, self::$mails );
	}

	public function test_warn_skipped_when_alerts_off(): void {
		$now    = 1_700_000_000;
		$plugin = 'noalert/plugin.php';
		$policy = array(
			'plugins'         => array( $plugin => 'allow' ),
			'plugin_expires'  => array( $plugin => $now + HOUR_IN_SECONDS ),
			'alert_on_deny'   => false,
			'alert_on_shadow' => false,
			'alert_email'     => 'x@example.com',
		);
		update_option( Plugin::OPTION_KEY, $policy, false );
		delete_option( Temp_Allow::WARNED_OPTION_KEY );

		$out = Temp_Allow::sweep_expired( $policy, $now );
		$this->assertSame( array(), $out['warned'] );
		$this->assertSame( array(), self::$mails );
	}
}
