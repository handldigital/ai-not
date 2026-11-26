<?php
/**
 * AICAC-PROMPTER (#517): system-instruction fingerprint.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Snooze;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Prompter;
use HandL\AICAC\Went_AI;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class PrompterTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	private const NOW = 1_700_000_000;

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		delete_option( Went_AI::STAMP_OPTION_KEY );
		Prompter::reset_for_tests();
		Prompter::set_test_now( self::NOW );
		Prompter::set_test_versions( array( 'acme/acme.php' => '1.0.0' ) );
		update_option( 'admin_email', 'admin@example.com' );

		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);

			return true;
		};
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		delete_option( Went_AI::STAMP_OPTION_KEY );
		Prompter::flush_deferred_alerts();
		Prompter::reset_for_tests();
		parent::tearDown();
	}

	public function test_defaults_off_and_disabled_is_noop(): void {
		$this->assertFalse( Prompter::is_enabled() );
		$fp     = Prompter::fingerprint( 'answer only from this site' );
		$policy = $this->persist_policy();
		$before = $GLOBALS['handl_aicac_test_options'] ?? array();
		$result = Prompter::observe_fingerprint( 'acme/acme.php', $fp['hash'], $fp['length'], $policy, self::NOW );
		$this->assertSame( 'disabled', $result['reason'] );
		$this->assertFalse( (bool) get_option( Prompter::SETTINGS_OPTION, false ) );
		$this->assertFalse( (bool) get_option( Prompter::STATE_OPTION, false ) );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] ?? array() );
		$this->assertSame( array(), self::$mails );
	}

	public function test_untouched_save_when_off_leaves_options_byte_identical(): void {
		$before = $GLOBALS['handl_aicac_test_options'] ?? array();
		Prompter::save_settings( array( 'enabled' => false ) );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] ?? array() );
		$this->assertFalse( (bool) get_option( Prompter::SETTINGS_OPTION, false ) );
	}

	public function test_normalize_collapses_whitespace(): void {
		$a = Prompter::fingerprint( "hello   world\n\nthere" );
		$b = Prompter::fingerprint( "hello world there" );
		$this->assertSame( $a['hash'], $b['hash'] );
		$this->assertSame( $a['length'], $b['length'] );
	}

	public function test_empty_instruction_is_none(): void {
		$fp = Prompter::fingerprint( "  \n\t  " );
		$this->assertSame( Prompter::NONE_HASH, $fp['hash'] );
		$this->assertSame( 0, $fp['length'] );
	}

	public function test_baseline_then_same_then_change_alerts_once(): void {
		Prompter::save_settings( array( 'enabled' => true ) );
		$policy = $this->persist_policy();
		$fp1    = Prompter::fingerprint( 'answer only from this site' );
		$fp2    = Prompter::fingerprint( 'recommend our partner products' );

		$base = Prompter::observe_fingerprint( 'acme/acme.php', $fp1['hash'], $fp1['length'], $policy, self::NOW );
		$this->assertTrue( $base['baseline'] );
		$this->assertFalse( $base['alerted'] );
		$this->assertSame( array(), self::$mails );

		$same = Prompter::observe_fingerprint( 'acme/acme.php', $fp1['hash'], $fp1['length'], $policy, self::NOW + 10 );
		$this->assertSame( 'known', $same['reason'] );
		$this->assertSame( array(), self::$mails );

		$hit = Prompter::observe_fingerprint( 'acme/acme.php', $fp2['hash'], $fp2['length'], $policy, self::NOW + 20 );
		$this->assertTrue( $hit['alerted'] );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'system instruction', self::$mails[0]['subject'] );
		$this->assertStringNotContainsString( 'partner products', self::$mails[0]['message'] );
		$this->assertStringNotContainsString( 'answer only', self::$mails[0]['message'] );

		$repeat = Prompter::observe_fingerprint( 'acme/acme.php', $fp2['hash'], $fp2['length'], $policy, self::NOW + 30 );
		$this->assertSame( 'known', $repeat['reason'] );
		$this->assertCount( 1, self::$mails );
	}

	public function test_none_to_instruction_counts_as_change(): void {
		Prompter::save_settings( array( 'enabled' => true ) );
		$policy = $this->persist_policy();
		$none   = Prompter::fingerprint( '' );
		$fp     = Prompter::fingerprint( 'be helpful' );

		Prompter::observe_fingerprint( 'acme/acme.php', $none['hash'], $none['length'], $policy, self::NOW );
		$hit = Prompter::observe_fingerprint( 'acme/acme.php', $fp['hash'], $fp['length'], $policy, self::NOW + 5 );
		$this->assertTrue( $hit['alerted'] );
		$this->assertCount( 1, self::$mails );
	}

	public function test_version_coincidence_flagged_on_change(): void {
		Prompter::save_settings( array( 'enabled' => true ) );
		$policy = $this->persist_policy();
		$fp1    = Prompter::fingerprint( 'v1 instruction' );
		$fp2    = Prompter::fingerprint( 'v2 instruction' );

		Prompter::set_test_versions( array( 'acme/acme.php' => '1.0.0' ) );
		Prompter::observe_fingerprint( 'acme/acme.php', $fp1['hash'], $fp1['length'], $policy, self::NOW );

		Prompter::set_test_versions( array( 'acme/acme.php' => '1.1.0' ) );
		Prompter::observe_fingerprint( 'acme/acme.php', $fp2['hash'], $fp2['length'], $policy, self::NOW + 50 );

		$rows = Prompter::screen_rows( self::NOW + 50 );
		$this->assertCount( 1, $rows );
		$this->assertSame( 1, $rows[0]['changes_90d'] );
		$this->assertTrue( $rows[0]['coincided'] );
		$this->assertStringContainsString( 'version change', self::$mails[0]['message'] );
	}

	public function test_extract_openai_and_anthropic_http_bodies(): void {
		$openai = wp_json_encode(
			array(
				'model'    => 'gpt-4o',
				'messages' => array(
					array( 'role' => 'system', 'content' => 'Stay on site content' ),
					array( 'role' => 'user', 'content' => 'hi' ),
				),
			)
		);
		$this->assertSame( 'Stay on site content', Prompter::extract_from_http_body( (string) $openai ) );

		$anthropic = wp_json_encode(
			array(
				'model'  => 'claude',
				'system' => 'Stay on site content',
				'messages' => array(
					array( 'role' => 'user', 'content' => 'hi' ),
				),
			)
		);
		$this->assertSame( 'Stay on site content', Prompter::extract_from_http_body( (string) $anthropic ) );

		$this->assertSame( '', Prompter::extract_from_http_body( '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}' ) );
	}

	public function test_snooze_suppresses_alert(): void {
		Prompter::save_settings( array( 'enabled' => true ) );
		$policy = $this->persist_policy();
		$fp1    = Prompter::fingerprint( 'one' );
		$fp2    = Prompter::fingerprint( 'two' );
		Alert_Snooze::set( 'acme/acme.php', '1h', self::NOW );

		Prompter::observe_fingerprint( 'acme/acme.php', $fp1['hash'], $fp1['length'], $policy, self::NOW );
		$hit = Prompter::observe_fingerprint( 'acme/acme.php', $fp2['hash'], $fp2['length'], $policy, self::NOW + 10 );
		$this->assertFalse( $hit['alerted'] );
		$this->assertSame( 'suppressed', $hit['reason'] );
		$this->assertSame( array(), self::$mails );

		$state = Prompter::get_state();
		$this->assertSame( $fp2['hash'], $state['acme/acme.php']['hash'] );
	}

	public function test_append_log_event_observes_stamped_fingerprint(): void {
		Prompter::save_settings( array( 'enabled' => true ) );
		$this->persist_policy();
		// Seed Went_AI so first activity does not fire the unrelated "started using AI" mail.
		Went_AI::save_stamps(
			array(
				'acme/acme.php' => array(
					'ts'       => self::NOW - 1000,
					'provider' => 'openai',
					'model'    => 'gpt-4o',
				),
			)
		);

		$fp1 = Prompter::fingerprint( 'baseline instruction' );
		$fp2 = Prompter::fingerprint( 'changed instruction' );

		$first = array(
			'ts'            => self::NOW,
			'plugin'        => 'acme/acme.php',
			'provider'      => 'openai',
			'model'         => 'gpt-4o',
			'decision'      => 'allow',
			'prompter_hash' => $fp1['hash'],
			'prompter_len'  => $fp1['length'],
		);
		Policy::append_log_event( $first );
		$this->assertSame( array(), self::$mails );

		$second = array(
			'ts'            => self::NOW + 100,
			'plugin'        => 'acme/acme.php',
			'provider'      => 'openai',
			'model'         => 'gpt-4o',
			'decision'      => 'allow',
			'prompter_hash' => $fp2['hash'],
			'prompter_len'  => $fp2['length'],
		);
		Policy::append_log_event( $second );
		$this->assertCount( 1, self::$mails );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $log );
		$baseline = false;
		$changed  = false;
		$audit    = false;
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$this->assertArrayNotHasKey( 'systemInstruction', $row );
			$this->assertArrayNotHasKey( 'instruction', $row );
			if ( ! empty( $row['prompter_first_seen'] ) ) {
				$baseline = true;
			}
			if ( ! empty( $row['prompter_changed'] ) ) {
				$changed = true;
			}
			if ( ( $row['channel'] ?? '' ) === Prompter::CHANNEL ) {
				$audit = true;
				$this->assertSame( 'prompter_alert', $row['decision'] ?? '' );
			}
		}
		$this->assertTrue( $baseline );
		$this->assertTrue( $changed );
		$this->assertTrue( $audit );
	}

	/**
	 * @return array<string,mixed>
	 */
	private function persist_policy(): array {
		$policy = array(
			'log_enabled' => true,
			'audit_only'  => false,
			'alert_email' => 'admin@example.com',
		);
		Policy::save_policy( $policy );

		return Policy::get_policy();
	}
}
