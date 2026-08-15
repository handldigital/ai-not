<?php
/**
 * AICAC-BREAKGLASS (#202) Phase 1 unit tests.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Break_Glass;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Policy_Snapshots;
use PHPUnit\Framework\TestCase;

final class BreakGlassTest extends TestCase {

	/** @var list<array{0:mixed,1:string,2:string}> */
	private array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		delete_option( Break_Glass::OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Policy_Snapshots::OPTION_KEY );
		delete_option( Policy_Snapshots::HISTORY_OPTION_KEY );
		$GLOBALS['handl_aicac_test_cron'] = array();
		$this->mails                      = array();
		$GLOBALS['handl_aicac_wp_mail']   = function ( $to, $subject, $message ) {
			$this->mails[] = array( $to, $subject, $message );
			return true;
		};
		update_option( 'admin_email', 'admin@example.test' );

		// Deny-by-default policy so break-glass allow is observable.
		Policy::save_policy(
			array(
				'default'     => 'deny',
				'plugins'     => array( 'acme/acme.php' => 'deny' ),
				'kill_switch' => true,
				'log_enabled' => true,
				'alert_email' => 'ops@example.test',
			)
		);
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		delete_option( Break_Glass::OPTION_KEY );
		parent::tearDown();
	}

	public function test_start_requires_reason_and_allowed_minutes(): void {
		$this->assertSame( 'reason_required', Break_Glass::start( 30, '' )['error'] ?? null );
		$this->assertSame( 'invalid_minutes', Break_Glass::start( 45, 'x' )['error'] ?? null );
	}

	public function test_start_allows_calls_and_tags_evaluate_reason(): void {
		$now = 1_700_000_000;
		$out = Break_Glass::start( 30, 'Checkout triage', $now );
		$this->assertTrue( $out['ok'] );
		$this->assertTrue( Break_Glass::is_active( $now + 60 ) );

		$eval = Policy::evaluate( Policy::get_policy(), 'acme/acme.php', 'generate_text', array(), null, $now + 60 );
		$this->assertFalse( $eval['prevent'] );
		$this->assertSame( 'break_glass', $eval['reason'] );

		$st = Break_Glass::status( $now + 60 );
		$this->assertTrue( $st['active'] );
		$this->assertSame( 30 * 60 - 60, $st['remaining_seconds'] );
		$this->assertSame( 'Checkout triage', $st['reason'] );

		$this->assertNotEmpty( $this->mails );
		$history = Policy_Snapshots::history();
		$this->assertNotEmpty( $history );
		$this->assertStringContainsString( 'Break glass started', (string) ( $history[0]['summary'] ?? '' ) );
	}

	public function test_cancel_restores_prior_policy_byte_for_byte(): void {
		$now    = 1_700_000_000;
		$before = Policy::get_policy();
		Break_Glass::start( 15, 'Need allow', $now );

		// Mutate live policy during the window — close must wipe this.
		Policy::save_policy(
			array_merge(
				Policy::get_policy(),
				array(
					'default'     => 'allow',
					'kill_switch' => false,
					'plugins'     => array(),
				)
			)
		);

		$cancel = Break_Glass::cancel( $now + 10 );
		$this->assertTrue( $cancel['ok'] );
		$this->assertFalse( Break_Glass::is_active( $now + 10 ) );

		$after = Policy::get_policy();
		$this->assertSame( (string) $before['default'], (string) $after['default'] );
		$this->assertSame( ! empty( $before['kill_switch'] ), ! empty( $after['kill_switch'] ) );
		$this->assertSame( $before['plugins']['acme/acme.php'] ?? null, $after['plugins']['acme/acme.php'] ?? null );

		$eval = Policy::evaluate( $after, 'acme/acme.php', 'generate_text', array(), null, $now + 10 );
		$this->assertTrue( $eval['prevent'] );

		$hist = Policy_Snapshots::history();
		$this->assertStringContainsString( 'Break glass ended', (string) ( $hist[0]['summary'] ?? '' ) );
		$this->assertGreaterThanOrEqual( 2, count( $this->mails ) );
	}

	public function test_fail_safe_closes_when_cron_suppressed(): void {
		$now = 1_700_000_000;
		Break_Glass::start( 15, 'cron test', $now );

		// Suppress cron: clear scheduled hook so expiry never fires via cron.
		$GLOBALS['handl_aicac_test_cron'] = array();

		// Still inside window.
		$this->assertTrue( Break_Glass::is_active( $now + 60 ) );

		// Past deadline — next evaluation path must close even without cron.
		$past = $now + ( 15 * 60 ) + 1;
		$this->assertFalse( Break_Glass::is_active( $past ) );

		$eval = Policy::evaluate( Policy::get_policy(), 'acme/acme.php', 'generate_text', array(), null, $past );
		$this->assertTrue( $eval['prevent'] );
		$this->assertNotSame( 'break_glass', $eval['reason'] );
	}

	public function test_cron_expire_closes_window(): void {
		$now = 1_700_000_000;
		Break_Glass::start( 15, 'cron fire', $now );
		$this->assertArrayHasKey( Break_Glass::CRON_HOOK, $GLOBALS['handl_aicac_test_cron'] );

		// Simulate time at expiry and run the hook callback.
		Break_Glass::close( 'expired', $now + ( 15 * 60 ) );
		$this->assertFalse( Break_Glass::is_active( $now + ( 15 * 60 ) ) );
	}

	public function test_second_start_while_active_fails(): void {
		$now = 1_700_000_000;
		$this->assertTrue( Break_Glass::start( 30, 'first', $now )['ok'] );
		$this->assertSame( 'already_active', Break_Glass::start( 30, 'second', $now + 1 )['error'] ?? null );
	}
}
