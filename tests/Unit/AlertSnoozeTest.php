<?php
/**
 * Unit tests for per-plugin alert mute (AICAC-SNOOZE / #149).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Snooze;
use HandL\AICAC\Alerts;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class AlertSnoozeTest extends TestCase {

	/** @var list<array{to:mixed,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options'] = array();
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
		self::$mails                        = array();
		parent::tearDown();
	}

	public function test_suppression_window_and_other_plugin_unaffected(): void {
		// Use wall-clock time: maybe_notify_* gates call should_suppress() without a $now override.
		$now   = time();
		$noisy = 'noisy/plugin.php';
		$other = 'other/plugin.php';
		$policy = array(
			'alert_on_deny' => true,
			'audit_only'    => false,
			'alert_mode'    => 'immediate',
			'alert_email'   => 'admin@example.com',
			'log_enabled'   => true,
		);
		$GLOBALS['handl_aicac_test_options'][ Plugin::OPTION_KEY ] = $policy;

		$this->assertTrue( Alert_Snooze::set( $noisy, '1h', $now ) );
		$this->assertTrue( Alert_Snooze::is_snoozed( $noisy, $now + 10 ) );
		$this->assertFalse( Alert_Snooze::is_snoozed( $other, $now + 10 ) );

		// Snoozed plugin: denial notify is suppressed (no deferred send, no mail).
		Alerts::maybe_notify_denial(
			array(
				'ts'        => $now + 10,
				'plugin'    => $noisy,
				'decision'  => 'deny',
				'operation' => 'generate_text',
			),
			$policy
		);

		$map = Alert_Snooze::get_map();
		$this->assertArrayHasKey( $noisy, $map );
		$this->assertSame( 1, (int) $map[ $noisy ]['suppressed'] );
		$this->assertSame( 0, count( self::$mails ), 'Snoozed plugin must not send' );

		// Other plugin is not suppressed.
		$this->assertFalse( Alert_Snooze::should_suppress( $other, 'denial', $now + 10 ) );
	}

	public function test_should_suppress_counts_kinds(): void {
		$now    = 1_700_000_000;
		$plugin = 'batch/job.php';
		Alert_Snooze::set( $plugin, '8h', $now );

		$this->assertTrue( Alert_Snooze::should_suppress( $plugin, 'denial', $now + 1 ) );
		$this->assertTrue( Alert_Snooze::should_suppress( $plugin, 'shadow', $now + 1 ) );
		$this->assertTrue( Alert_Snooze::should_suppress( $plugin, 'spend', $now + 1 ) );
		$this->assertTrue( Alert_Snooze::should_suppress( $plugin, 'anomaly', $now + 1 ) );

		$map = Alert_Snooze::get_map();
		$this->assertSame( 4, (int) $map[ $plugin ]['suppressed'] );
		$this->assertSame( 1, (int) $map[ $plugin ]['by_kind']['denial'] );
		$this->assertSame( 1, (int) $map[ $plugin ]['by_kind']['shadow'] );
		$this->assertSame( 1, (int) $map[ $plugin ]['by_kind']['spend'] );
		$this->assertSame( 1, (int) $map[ $plugin ]['by_kind']['anomaly'] );
	}

	public function test_expiry_restores_alerting_and_summary_count(): void {
		$now    = 1_700_000_000;
		$plugin = 'temp/noise.php';
		Alert_Snooze::set( $plugin, '1h', $now );
		Alert_Snooze::should_suppress( $plugin, 'denial', $now + 5 );
		Alert_Snooze::should_suppress( $plugin, 'denial', $now + 6 );

		// Still active before expiry.
		$this->assertTrue( Alert_Snooze::is_snoozed( $plugin, $now + HOUR_IN_SECONDS - 1 ) );

		// After expiry: purge writes summary, no longer snoozed.
		$ended = Alert_Snooze::purge_expired( $now + HOUR_IN_SECONDS + 1 );
		$this->assertCount( 1, $ended );
		$this->assertSame( $plugin, $ended[0]['plugin'] );
		$this->assertSame( 2, $ended[0]['suppressed'] );
		$this->assertFalse( Alert_Snooze::is_snoozed( $plugin, $now + HOUR_IN_SECONDS + 2 ) );
		$this->assertSame( array(), Alert_Snooze::get_map() );
	}

	public function test_cancel_restores_alerting_with_summary(): void {
		$now    = 1_700_000_000;
		$plugin = 'cancel/me.php';
		Alert_Snooze::set( $plugin, '24h', $now );
		Alert_Snooze::should_suppress( $plugin, 'denial', $now + 1 );
		Alert_Snooze::should_suppress( $plugin, 'shadow', $now + 2 );

		$result = Alert_Snooze::cancel( $plugin, $now + 3 );
		$this->assertTrue( $result['cancelled'] );
		$this->assertSame( 2, $result['suppressed'] );
		$this->assertFalse( Alert_Snooze::is_snoozed( $plugin, $now + 4 ) );
	}

	public function test_enforcement_evaluate_unchanged_while_snoozed(): void {
		$now    = 1_700_000_000;
		$plugin = 'blocked/plugin.php';
		$policy = array(
			'default' => 'allow',
			'plugins' => array( $plugin => 'deny' ),
		);
		Alert_Snooze::set( $plugin, '7d', $now );

		$eval = Policy::evaluate( $policy, $plugin, 'generate_text' );
		$this->assertTrue( $eval['prevent'], 'Snooze must not weaken deny enforcement' );
		$this->assertSame( 'plugin', $eval['reason'] );
	}

	public function test_active_list_sorted_and_excludes_expired(): void {
		$now = 1_700_000_000;
		Alert_Snooze::set( 'b/late.php', '7d', $now );
		Alert_Snooze::set( 'a/soon.php', '1h', $now );

		$list = Alert_Snooze::active_list( $now + 10 );
		$this->assertCount( 2, $list );
		$this->assertSame( 'a/soon.php', $list[0]['plugin'] );
		$this->assertSame( 'b/late.php', $list[1]['plugin'] );

		// After 1h, only 7d remains.
		$list2 = Alert_Snooze::active_list( $now + HOUR_IN_SECONDS + 5 );
		$this->assertCount( 1, $list2 );
		$this->assertSame( 'b/late.php', $list2[0]['plugin'] );
	}

	public function test_invalid_preset_rejected(): void {
		$this->assertFalse( Alert_Snooze::set( 'x/y.php', 'nope', 1_700_000_000 ) );
		$this->assertSame( array(), Alert_Snooze::get_map() );
	}
}
