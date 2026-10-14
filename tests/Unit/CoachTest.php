<?php
/**
 * AICAC-COACH (#437).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Coach;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class CoachTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12 UTC.

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$GLOBALS['handl_aicac_test_users']            = array(
			7 => array(
				'ID'         => 7,
				'user_login' => 'denied_user',
				'user_email' => 'denied@example.com',
			),
		);
		Coach::reset_for_tests();
		Coach::set_test_now( self::NOW );
		Coach::set_test_access_request( true );
		unset( $GLOBALS['handl_aicac_wp_mail'] );
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_users']         = array();
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		Coach::reset_for_tests();
		parent::tearDown();
	}

	private function enable( int $threshold = 5 ): void {
		Coach::save_settings(
			array(
				'enabled'   => true,
				'threshold' => $threshold,
			)
		);
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private function deny_log( int $user_id, string $rule, int $count, int $spacing = 3600 ): array {
		$log = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$log[] = array(
				'ts'            => self::NOW - ( $i * $spacing ),
				'decision'      => 'deny',
				'user_id'       => $user_id,
				'denial_reason' => $rule,
				'plugin'        => 'acme/acme.php',
				'rule_note'     => 'Acme is blocked for editors.',
			);
		}

		return $log;
	}

	public function test_defaults_off_and_constants(): void {
		$this->assertFalse( Coach::is_enabled() );
		$this->assertSame( 5, Coach::threshold() );
		$this->assertSame( 'admin_initiated_never_auto_sends', Coach::FRAMING );
		$this->assertSame( 'handl-aicac-coach', Coach::PAGE_SLUG );
		$this->assertSame( Coach::defaults(), Coach::sanitize_settings( 'junk' ) );

		$this->assertTrue( Coach::save_settings( array( 'enabled' => true, 'threshold' => 7 ) ) );
		$this->assertTrue( Coach::is_enabled() );
		$this->assertSame( 7, Coach::threshold() );
		$this->assertTrue( Coach::save_settings( Coach::defaults() ) );
		$this->assertFalse( (bool) get_option( Coach::SETTINGS_OPTION, false ) );
	}

	public function test_streak_detection_window_and_threshold(): void {
		$this->enable( 5 );
		$day = defined( 'DAY_IN_SECONDS' ) ? DAY_IN_SECONDS : 86400;

		// 5 denies inside 14d window → candidate.
		Coach::set_test_log( $this->deny_log( 7, 'plugin', 5 ) );
		$streaks = Coach::detect_streaks( self::NOW, 5 );
		$this->assertCount( 1, $streaks );
		$this->assertSame( 5, (int) $streaks[0]['streak'] );
		$this->assertSame( '7|plugin', (string) $streaks[0]['key'] );

		$candidates = Coach::candidates( self::NOW );
		$this->assertCount( 1, $candidates );

		// 4 denies → under threshold.
		Coach::set_test_log( $this->deny_log( 7, 'plugin', 4 ) );
		$this->assertSame( array(), Coach::detect_streaks( self::NOW, 5 ) );
		$this->assertSame( array(), Coach::candidates( self::NOW ) );

		// Denies older than 14d ignored.
		$old = array(
			array(
				'ts'            => self::NOW - ( 15 * $day ),
				'decision'      => 'deny',
				'user_id'       => 7,
				'denial_reason' => 'plugin',
				'plugin'        => 'acme/acme.php',
			),
			array(
				'ts'            => self::NOW - ( 16 * $day ),
				'decision'      => 'deny',
				'user_id'       => 7,
				'denial_reason' => 'plugin',
				'plugin'        => 'acme/acme.php',
			),
			array(
				'ts'            => self::NOW - ( 17 * $day ),
				'decision'      => 'deny',
				'user_id'       => 7,
				'denial_reason' => 'plugin',
				'plugin'        => 'acme/acme.php',
			),
			array(
				'ts'            => self::NOW - ( 18 * $day ),
				'decision'      => 'deny',
				'user_id'       => 7,
				'denial_reason' => 'plugin',
				'plugin'        => 'acme/acme.php',
			),
			array(
				'ts'            => self::NOW - ( 19 * $day ),
				'decision'      => 'deny',
				'user_id'       => 7,
				'denial_reason' => 'plugin',
				'plugin'        => 'acme/acme.php',
			),
		);
		Coach::set_test_log( $old );
		$this->assertSame( array(), Coach::detect_streaks( self::NOW, 5 ) );
	}

	public function test_no_email_without_explicit_admin_action(): void {
		$this->enable( 5 );
		Coach::set_test_log( $this->deny_log( 7, 'budget', 6 ) );
		$GLOBALS['handl_aicac_wp_mail'] = static function (): bool {
			return true;
		};

		$this->assertTrue( Coach::maybe_scan( self::NOW, true ) );
		$this->assertSame( array(), Coach::test_mails() );
		$this->assertCount( 1, Coach::candidates( self::NOW ) );

		// Scan again still never mails.
		$this->assertTrue( Coach::maybe_scan( self::NOW + 400, true ) );
		$this->assertSame( array(), Coach::test_mails() );

		$row    = Coach::candidates( self::NOW )[0];
		$result = Coach::send_explainer( $row, self::NOW );
		$this->assertTrue( $result['sent'] );
		$this->assertCount( 1, Coach::test_mails() );
		$this->assertStringContainsString( 'budget', strtolower( Coach::test_mails()[0]['subject'] ) );
		$this->assertStringContainsString( 'denied@example.com', Coach::test_mails()[0]['to'] );
	}

	public function test_rearm_after_quiet_period(): void {
		$this->enable( 5 );
		$day = defined( 'DAY_IN_SECONDS' ) ? DAY_IN_SECONDS : 86400;
		Coach::set_test_log( $this->deny_log( 7, 'role', 5 ) );

		$row = Coach::candidates( self::NOW )[0];
		$GLOBALS['handl_aicac_wp_mail'] = static function (): bool {
			return true;
		};
		$this->assertTrue( Coach::send_explainer( $row, self::NOW )['sent'] );
		$this->assertSame( array(), Coach::candidates( self::NOW ) ); // quiet after send

		// Continued denies without quiet gap → still quiet.
		$continued = $this->deny_log( 7, 'role', 5, 1800 );
		Coach::set_test_log( $continued );
		$this->assertSame( array(), Coach::candidates( self::NOW + 60 ) );

		// After 14 quiet days with no denies, prune clears sent; new streak re-arms.
		Coach::set_test_now( self::NOW + ( 15 * $day ) );
		Coach::set_test_log( array() ); // no recent denies
		$this->assertGreaterThan( 0, Coach::prune_sent_state( self::NOW + ( 15 * $day ) ) );

		$fresh_now = self::NOW + ( 16 * $day );
		Coach::set_test_now( $fresh_now );
		$fresh = array();
		for ( $i = 0; $i < 5; $i++ ) {
			$fresh[] = array(
				'ts'            => $fresh_now - ( $i * 600 ),
				'decision'      => 'deny',
				'user_id'       => 7,
				'denial_reason' => 'role',
				'plugin'        => 'acme/acme.php',
			);
		}
		Coach::set_test_log( $fresh );
		$rearmed = Coach::candidates( $fresh_now );
		$this->assertCount( 1, $rearmed );
		$this->assertSame( '7|role', (string) $rearmed[0]['key'] );
	}

	public function test_compose_includes_rule_note_and_access_request(): void {
		$this->enable( 5 );
		Coach::set_test_log( $this->deny_log( 7, 'plugin', 5 ) );
		$row      = Coach::candidates( self::NOW )[0];
		$composed = Coach::compose_explainer( $row );
		$this->assertTrue( $composed['ok'] );
		$this->assertStringContainsString( 'Acme is blocked for editors.', $composed['body'] );
		$this->assertStringContainsString( 'access request', strtolower( $composed['body'] ) );

		Coach::set_test_access_request( false );
		$composed2 = Coach::compose_explainer( $row );
		$this->assertStringContainsString( 'site admin', strtolower( $composed2['body'] ) );
	}

	public function test_disabled_does_nothing(): void {
		Coach::set_test_log( $this->deny_log( 7, 'plugin', 9 ) );
		$this->assertFalse( Coach::maybe_scan( self::NOW, true ) );
		$this->assertSame( array(), Coach::test_mails() );
		$snap = Coach::snapshot( self::NOW );
		$this->assertFalse( $snap['enabled'] );
		$this->assertSame( 0, $snap['candidate_count'] );
	}
}
