<?php
/**
 * AICAC-PANIC-FREEZE (#267) unit tests.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Break_Glass;
use HandL\AICAC\Freeze;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Policy_Snapshots;
use HandL\AICAC\Presets;
use PHPUnit\Framework\TestCase;

final class FreezeTest extends TestCase {

	/** @var list<array{0:mixed,1:string,2:string}> */
	private array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		delete_option( Freeze::OPTION_KEY );
		delete_option( Break_Glass::OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Policy_Snapshots::OPTION_KEY );
		delete_option( Policy_Snapshots::HISTORY_OPTION_KEY );
		$GLOBALS['handl_aicac_test_cron'] = array();
		$this->mails                      = array();
		$GLOBALS['handl_aicac_wp_mail']   = function ( $to, $subject, $message ) {
			$this->mails[] = array( $to, $subject, $message );
			return true;
		};
		update_option( 'admin_email', 'admin@example.test' );

		Policy::save_policy(
			array(
				'default'              => 'allow',
				'plugins'              => array( 'acme/acme.php' => 'allow' ),
				'kill_switch'          => false,
				'shadow_block_enabled' => false,
				'audit_only'           => false,
				'log_enabled'          => true,
				'alert_email'          => 'ops@example.test',
				'alert_on_deny'        => true,
			)
		);
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		delete_option( Freeze::OPTION_KEY );
		delete_option( Break_Glass::OPTION_KEY );
		parent::tearDown();
	}

	public function test_start_requires_allowed_minutes(): void {
		$this->assertSame( 'invalid_minutes', Freeze::start( 45 )['error'] ?? null );
	}

	public function test_start_applies_lockdown_and_blocks_calls(): void {
		$now = 1_700_000_000;
		$out = Freeze::start( 60, 'Spend spike', $now );
		$this->assertTrue( $out['ok'] );
		$this->assertTrue( Freeze::is_active( $now + 60 ) );
		$this->assertTrue( Presets::is_active( 'lockdown', Policy::get_policy() ) );

		$eval = Policy::evaluate( Policy::get_policy(), 'acme/acme.php', 'generate_text', array(), null, $now + 60 );
		$this->assertTrue( $eval['prevent'] );

		$st = Freeze::status( $now + 60 );
		$this->assertTrue( $st['active'] );
		$this->assertSame( 60 * 60 - 60, $st['remaining_seconds'] );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $log );
		$this->assertNotEmpty( $log );
		$this->assertSame( 'freeze_started', (string) ( $log[ count( $log ) - 1 ]['decision'] ?? '' ) );
		$this->assertSame( 'freeze', (string) ( $log[ count( $log ) - 1 ]['channel'] ?? '' ) );

		$this->assertNotEmpty( $this->mails );
		$history = Policy_Snapshots::history();
		$this->assertNotEmpty( $history );
		$this->assertStringContainsString( 'Panic freeze started', (string) ( $history[0]['summary'] ?? '' ) );
	}

	public function test_freeze_clears_kill_switch_exceptions_for_deny_all(): void {
		$now = 1_700_000_000;
		Policy::save_policy(
			array(
				'default'               => 'allow',
				'plugins'               => array( 'excepted/plugin.php' => 'allow' ),
				'kill_switch'           => true,
				'kill_switch_exceptions'=> array( 'excepted/plugin.php' ),
				'shadow_block_enabled'  => false,
				'audit_only'            => false,
				'log_enabled'           => true,
				'alert_email'           => 'ops@example.test',
			)
		);

		$before = Policy::evaluate( Policy::get_policy(), 'excepted/plugin.php', 'generate_text', array(), null, $now );
		$this->assertFalse( $before['prevent'], 'exception should allow fall-through before freeze' );

		$this->assertTrue( Freeze::start( 15, '', $now )['ok'] );
		$frozen = Policy::get_policy();
		$this->assertSame( array(), Policy::get_kill_switch_exceptions( $frozen ) );
		$this->assertTrue( ! empty( $frozen['kill_switch'] ) );

		$eval = Policy::evaluate( $frozen, 'excepted/plugin.php', 'generate_text', array(), null, $now + 1 );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( 'kill_switch', (string) ( $eval['reason'] ?? '' ) );
	}

	public function test_freeze_restore_is_byte_identical_no_op_save(): void {
		$now    = 1_700_000_000;
		$before = get_option( Plugin::OPTION_KEY );

		Freeze::start( 15, '', $now );
		$this->assertNotSame( $before, get_option( Plugin::OPTION_KEY ) );

		$end = Freeze::end( $now + 10 );
		$this->assertTrue( $end['ok'] );
		$this->assertFalse( Freeze::is_active( $now + 10 ) );

		$after = get_option( Plugin::OPTION_KEY );
		$this->assertSame( $before, $after );

		$eval = Policy::evaluate( Policy::get_policy(), 'acme/acme.php', 'generate_text', array(), null, $now + 10 );
		$this->assertFalse( $eval['prevent'] );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$last = is_array( $log ) && $log ? $log[ count( $log ) - 1 ] : array();
		$this->assertSame( 'freeze_ended', (string) ( $last['decision'] ?? '' ) );
		$this->assertSame( 'manual', (string) ( $last['closed_cause'] ?? '' ) );
		$this->assertGreaterThanOrEqual( 2, count( $this->mails ) );
	}

	public function test_fail_safe_closes_when_cron_suppressed(): void {
		$now = 1_700_000_000;
		Freeze::start( 15, '', $now );
		$GLOBALS['handl_aicac_test_cron'] = array();

		$this->assertTrue( Freeze::is_active( $now + 60 ) );

		$past = $now + ( 15 * 60 ) + 1;
		$this->assertFalse( Freeze::is_active( $past ) );

		$eval = Policy::evaluate( Policy::get_policy(), 'acme/acme.php', 'generate_text', array(), null, $past );
		$this->assertFalse( $eval['prevent'] );
	}

	public function test_extend_requires_fresh_click_and_updates_deadline(): void {
		$now = 1_700_000_000;
		Freeze::start( 15, '', $now );
		// Resetting to 15 min with three hours not applicable — start was 15; reset to 240 then back to 15 shortens.
		$ext = Freeze::extend( 240, $now + 30 );
		$this->assertTrue( $ext['ok'] );
		$st = Freeze::status( $now + 30 );
		$this->assertSame( 240 * 60, $st['remaining_seconds'] );
		$this->assertSame( 240, $st['minutes'] );

		$shorten = Freeze::extend( 15, $now + 60 );
		$this->assertTrue( $shorten['ok'] );
		$st2 = Freeze::status( $now + 60 );
		$this->assertSame( 15 * 60, $st2['remaining_seconds'] );

		$history = Policy_Snapshots::history();
		$this->assertStringContainsString( 'AI freeze timer reset (15 min)', (string) ( $history[0]['summary'] ?? '' ) );
	}

	public function test_reactivation_restores_snapshot(): void {
		$now    = 1_700_000_000;
		$before = get_option( Plugin::OPTION_KEY );
		Freeze::start( 60, '', $now );
		$this->assertTrue( Freeze::is_active( $now + 1 ) );

		// Simulate mid-freeze deactivation: option state remains; lockdown policy is live.
		Freeze::on_activate( $now + 100 );
		$this->assertFalse( Freeze::is_active( $now + 100 ) );
		$this->assertSame( $before, get_option( Plugin::OPTION_KEY ) );
	}

	public function test_start_cancels_active_break_glass(): void {
		$now = 1_700_000_000;
		Policy::save_policy(
			array(
				'default'     => 'deny',
				'plugins'     => array( 'acme/acme.php' => 'deny' ),
				'kill_switch' => true,
				'log_enabled' => true,
				'alert_email' => 'ops@example.test',
			)
		);
		$this->assertTrue( Break_Glass::start( 30, 'triage', $now )['ok'] );
		$this->assertTrue( Break_Glass::is_active( $now + 1 ) );

		$this->assertTrue( Freeze::start( 15, '', $now + 2 )['ok'] );
		$this->assertFalse( Break_Glass::is_active( $now + 2 ) );
		$this->assertTrue( Freeze::is_active( $now + 2 ) );
		$this->assertTrue( Presets::is_active( 'lockdown', Policy::get_policy() ) );

		Freeze::end( $now + 3 );
		$policy = Policy::get_policy();
		$this->assertSame( 'deny', (string) ( $policy['default'] ?? '' ) );
		$this->assertTrue( ! empty( $policy['kill_switch'] ) );
		$this->assertFalse( Freeze::is_active( $now + 3 ) );
	}

	public function test_second_start_while_active_fails(): void {
		$now = 1_700_000_000;
		$this->assertTrue( Freeze::start( 60, '', $now )['ok'] );
		$this->assertSame( 'already_active', Freeze::start( 60, '', $now + 1 )['error'] ?? null );
	}

	public function test_notice_text_while_active(): void {
		$now = 1_700_000_000;
		$this->assertNull( Freeze::notice_text( $now ) );
		Freeze::start( 60, '', $now );
		$text = Freeze::notice_text( $now + 10 );
		$this->assertIsString( $text );
		$this->assertStringContainsString( 'AI freeze is active until', (string) $text );
		$this->assertStringNotContainsString( 'Extend', (string) $text );
	}

	public function test_manual_end_email_copy(): void {
		$now = 1_700_000_000;
		Freeze::start( 15, '', $now );
		$this->mails = array();
		Freeze::end( $now + 5 );
		$this->assertNotEmpty( $this->mails );
		$body = (string) ( $this->mails[0][2] ?? '' );
		$this->assertStringContainsString( 'AI freeze ended early. Your previous settings were restored.', $body );
		$this->assertStringNotContainsString( 'Panic freeze was restored early', $body );
	}
}
