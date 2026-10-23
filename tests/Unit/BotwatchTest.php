<?php
/**
 * AICAC-BOTWATCH (#441).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Botwatch;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class BotwatchTest extends TestCase {

	private const NOW = 1792165053;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		unset( $GLOBALS['handl_aicac_test_botwatch_ua'], $GLOBALS['handl_aicac_test_botwatch_path'], $GLOBALS['handl_aicac_wp_mail'] );
		Botwatch::reset_for_tests();
		Botwatch::set_test_now( self::NOW );
		Botwatch::set_test_frontend( true );
		Botwatch::set_test_robots(
			"User-agent: GPTBot\nDisallow: /private/\n\nUser-agent: *\nDisallow:\n"
		);
		update_option( 'admin_email', 'admin@example.com' );
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_botwatch_ua'],
			$GLOBALS['handl_aicac_test_botwatch_path'],
			$GLOBALS['handl_aicac_wp_mail']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		Botwatch::reset_for_tests();
		parent::tearDown();
	}

	public function test_gptbot_hit_updates_ledger_nonmatch_byte_identical(): void {
		$before = get_option( Botwatch::LEDGER_OPTION, null );
		$this->assertFalse( (bool) $before );

		$GLOBALS['handl_aicac_test_botwatch_ua']   = 'Mozilla/5.0 (compatible; GPTBot/1.0)';
		$GLOBALS['handl_aicac_test_botwatch_path'] = '/blog/hello';
		Botwatch::maybe_observe();

		$ledger = Botwatch::get_ledger();
		$this->assertArrayHasKey( 'gptbot', $ledger['bots'] );
		$row = $ledger['bots']['gptbot'];
		$this->assertSame( self::NOW, (int) $row['first_seen'] );
		$this->assertSame( self::NOW, (int) $row['last_seen'] );
		$this->assertSame( 1, (int) $row['hits'] );
		$this->assertContains( '/blog/hello', $row['paths'] );

		$serialized = get_option( Botwatch::LEDGER_OPTION, null );

		// Non-matching UA must leave ledger byte-identical.
		$GLOBALS['handl_aicac_test_botwatch_ua']   = 'Mozilla/5.0 (compatible; Googlebot/2.1)';
		$GLOBALS['handl_aicac_test_botwatch_path'] = '/other';
		Botwatch::maybe_observe();
		$this->assertSame( $serialized, get_option( Botwatch::LEDGER_OPTION, null ) );

		// Second GPTBot hit increments.
		Botwatch::set_test_now( self::NOW + 10 );
		$GLOBALS['handl_aicac_test_botwatch_ua']   = 'GPTBot';
		$GLOBALS['handl_aicac_test_botwatch_path'] = '/blog/hello';
		Botwatch::maybe_observe();
		$row2 = Botwatch::get_ledger()['bots']['gptbot'];
		$this->assertSame( self::NOW, (int) $row2['first_seen'] );
		$this->assertSame( self::NOW + 10, (int) $row2['last_seen'] );
		$this->assertSame( 2, (int) $row2['hits'] );
	}

	public function test_robots_disallowed_path_is_non_compliant_finding(): void {
		$bot = array(
			'id'    => 'gptbot',
			'label' => 'GPTBot',
			'ua'    => 'GPTBot',
		);
		$result = Botwatch::record_hit( $bot, '/private/secret', self::NOW );
		$this->assertTrue( $result['noncompliant'] );

		$snap = Botwatch::snapshot();
		$this->assertSame( 'non_compliant', $snap['bots'][0]['compliance'] );
		$this->assertCount( 1, $snap['findings'] );
		$this->assertSame( '/private/secret', $snap['findings'][0]['path'] );
		$this->assertSame( 'GPTBot', $snap['findings'][0]['label'] );
		$this->assertTrue( Botwatch::path_disallowed_for_ua( '/private/secret', 'GPTBot' ) );
		$this->assertFalse( Botwatch::path_disallowed_for_ua( '/blog/ok', 'GPTBot' ) );
	}

	public function test_admin_snapshot_and_caps_enforced(): void {
		$bot = array(
			'id'    => 'claudebot',
			'label' => 'ClaudeBot',
			'ua'    => 'ClaudeBot',
		);
		Botwatch::record_hit( $bot, '/notes', self::NOW );
		Botwatch::record_hit( $bot, '/private/x', self::NOW ); // also disallowed via GPTBot block? ClaudeBot uses * — empty disallow
		// Make ClaudeBot disallowed via robots.
		Botwatch::set_test_robots( "User-agent: ClaudeBot\nDisallow: /notes\n" );
		Botwatch::record_hit( $bot, '/notes', self::NOW + 1 );

		$snap = Botwatch::snapshot();
		$this->assertNotEmpty( $snap['bots'] );
		$this->assertSame( Botwatch::MAX_BOTS, 40 );
		$this->assertSame( Botwatch::MAX_PATHS_PER_BOT, 25 );
		$this->assertSame( Botwatch::MAX_FINDINGS_TOTAL, 200 );

		// Path sample cap.
		for ( $i = 0; $i < 40; $i++ ) {
			Botwatch::record_hit( $bot, '/p/' . $i, self::NOW + $i );
		}
		$paths = Botwatch::get_ledger()['bots']['claudebot']['paths'];
		$this->assertLessThanOrEqual( Botwatch::MAX_PATHS_PER_BOT, count( $paths ) );
	}

	public function test_noop_save_leaves_settings_byte_identical(): void {
		$this->assertSame( Botwatch::defaults(), Botwatch::get_settings() );
		$this->assertFalse( (bool) get_option( Botwatch::SETTINGS_OPTION, false ) );

		Botwatch::save_settings(
			array(
				'alert_first'        => true,
				'alert_noncompliant' => false,
			)
		);
		$stored = get_option( Botwatch::SETTINGS_OPTION, null );
		$this->assertIsArray( $stored );

		// No-op save (same values) must not rewrite.
		Botwatch::save_settings(
			array(
				'alert_first'        => true,
				'alert_noncompliant' => false,
			)
		);
		$this->assertSame( $stored, get_option( Botwatch::SETTINGS_OPTION, null ) );

		// Back to defaults deletes option.
		Botwatch::save_settings( Botwatch::defaults() );
		$this->assertFalse( (bool) get_option( Botwatch::SETTINGS_OPTION, false ) );
	}

	public function test_alerts_off_by_default_and_fire_when_enabled(): void {
		$bot = array(
			'id'    => 'gptbot',
			'label' => 'GPTBot',
			'ua'    => 'GPTBot',
		);
		Botwatch::record_hit( $bot, '/ok', self::NOW );
		$this->assertSame( array(), Botwatch::test_mails() );

		Botwatch::save_settings(
			array(
				'alert_first'        => true,
				'alert_noncompliant' => true,
			)
		);
		Botwatch::reset_for_tests();
		Botwatch::set_test_now( self::NOW );
		Botwatch::set_test_robots( "User-agent: GPTBot\nDisallow: /secret/\n" );
		Botwatch::save_settings(
			array(
				'alert_first'        => true,
				'alert_noncompliant' => true,
			)
		);

		$mails = array();
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) use ( &$mails ): bool {
			$mails[] = compact( 'to', 'subject', 'message' );
			return true;
		};

		Botwatch::record_hit( $bot, '/secret/x', self::NOW );
		$this->assertNotEmpty( Botwatch::test_mails() );
		$this->assertGreaterThanOrEqual( 1, count( $mails ) );
	}

	public function test_non_frontend_skips(): void {
		Botwatch::set_test_frontend( false );
		$GLOBALS['handl_aicac_test_botwatch_ua']   = 'GPTBot';
		$GLOBALS['handl_aicac_test_botwatch_path'] = '/x';
		Botwatch::maybe_observe();
		$this->assertFalse( (bool) get_option( Botwatch::LEDGER_OPTION, false ) );
	}
}
