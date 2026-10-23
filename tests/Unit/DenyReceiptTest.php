<?php
/**
 * AICAC-DENY-RECEIPT (#430).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Deny_Receipt;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Why;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class DenyReceiptTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12 UTC.
	private const KEY = 'aicac_fixed-row-id';

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Deny_Receipt::reset_for_tests();
		update_option( self::SALT(), 'test-salt-deny-receipt-430', false );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
				'log_limit'   => 200,
				'default'     => 'deny',
			),
			false
		);
		delete_option( Plugin::LOG_OPTION_KEY );
	}

	protected function tearDown(): void {
		Deny_Receipt::reset_for_tests();
		$GLOBALS['handl_aicac_test_options'] = array();
		unset( $GLOBALS['handl_aicac_test_current_user_can'] );
		parent::tearDown();
	}

	private static function SALT(): string {
		return Deny_Receipt::SALT_OPTION;
	}

	public function test_defaults_off_and_noop_save_leaves_options_byte_identical(): void {
		$this->assertSame( Deny_Receipt::defaults(), Deny_Receipt::get_settings() );
		$this->assertFalse( (bool) get_option( Deny_Receipt::SETTINGS_OPTION, false ) );
		$this->assertFalse( Deny_Receipt::message_enabled() );
		$this->assertFalse( Deny_Receipt::lookup_enabled() );

		Deny_Receipt::save_settings(
			array(
				'message_enabled' => true,
				'lookup_enabled'  => true,
			)
		);
		$stored = get_option( Deny_Receipt::SETTINGS_OPTION, null );
		$this->assertIsArray( $stored );

		Deny_Receipt::save_settings(
			array(
				'message_enabled' => true,
				'lookup_enabled'  => true,
			)
		);
		$this->assertSame( $stored, get_option( Deny_Receipt::SETTINGS_OPTION, null ) );

		Deny_Receipt::save_settings( Deny_Receipt::defaults() );
		$this->assertFalse( (bool) get_option( Deny_Receipt::SETTINGS_OPTION, false ) );
	}

	public function test_same_deny_twice_same_day_same_code(): void {
		$a = Deny_Receipt::code_for( self::KEY, self::NOW );
		$b = Deny_Receipt::code_for( self::KEY, self::NOW + 3600 );
		$this->assertSame( $a, $b );
		$this->assertMatchesRegularExpression( '/^AICAC-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/', $a );
		$body = substr( $a, strlen( Deny_Receipt::PREFIX ) );
		$this->assertStringNotContainsString( 'I', $body );
		$this->assertStringNotContainsString( 'L', $body );
		$this->assertStringNotContainsString( 'O', $body );
		$this->assertStringNotContainsString( 'U', $body );
	}

	public function test_different_day_or_row_yields_different_code(): void {
		$base = Deny_Receipt::code_for( self::KEY, self::NOW );
		$next = Deny_Receipt::code_for( self::KEY, self::NOW + 86400 );
		$other = Deny_Receipt::code_for( 'aicac_other-row', self::NOW );
		$this->assertNotSame( $base, $next );
		$this->assertNotSame( $base, $other );
	}

	public function test_option_off_leaves_deny_message_byte_identical(): void {
		$msg   = Policy::caller_deny_error_message();
		$event = array(
			'ts'             => self::NOW,
			'decision'       => 'deny',
			'log_key'        => self::KEY,
			'plugin'         => 'demo/demo.php',
			'returned_error' => $msg,
		);
		Deny_Receipt::stamp( $event );
		$this->assertSame( $msg, $event['returned_error'] );
		$this->assertSame( Deny_Receipt::code_for( self::KEY, self::NOW ), $event['receipt'] );
	}

	public function test_option_on_suffixes_reference_on_returned_error(): void {
		Deny_Receipt::save_settings(
			array(
				'message_enabled' => true,
				'lookup_enabled'  => false,
			)
		);
		$msg   = Policy::caller_deny_error_message();
		$event = array(
			'ts'             => self::NOW,
			'decision'       => 'deny',
			'log_key'        => self::KEY,
			'plugin'         => 'demo/demo.php',
			'returned_error' => $msg,
		);
		Deny_Receipt::stamp( $event );
		$code = Deny_Receipt::code_for( self::KEY, self::NOW );
		$this->assertSame( $msg . ' Reference: ' . $code, $event['returned_error'] );
		$this->assertTrue( 0 === strpos( $event['returned_error'], $msg ) );
	}

	public function test_allow_is_noop(): void {
		$event = array(
			'ts'       => self::NOW,
			'decision' => 'allow',
			'plugin'   => 'demo/demo.php',
		);
		Deny_Receipt::stamp( $event );
		$this->assertArrayNotHasKey( 'receipt', $event );
		$this->assertArrayNotHasKey( 'log_key', $event );
	}

	public function test_lookup_round_trips_stored_row(): void {
		$event = array(
			'ts'              => self::NOW,
			'decision'        => 'deny',
			'log_key'         => self::KEY,
			'plugin'          => 'demo/demo.php',
			'decision_source' => 'rule:explicit-deny',
			'prompt_preview'  => 'secret prompt',
			'user_id'         => 12,
			'returned_error'  => Policy::caller_deny_error_message(),
		);
		Deny_Receipt::stamp( $event );
		update_option( Plugin::LOG_OPTION_KEY, array( $event ), false );

		$got = Deny_Receipt::lookup( $event['receipt'] );
		$this->assertIsArray( $got );
		$this->assertSame( $event['receipt'], $got['receipt'] );
		$this->assertSame( 'demo/demo.php', $got['plugin'] );
		$this->assertSame( 'secret prompt', $got['prompt_preview'] );

		$loose = Deny_Receipt::lookup( strtolower( str_replace( '-', '', $event['receipt'] ) ) );
		$this->assertIsArray( $loose );
		$this->assertSame( $event['receipt'], $loose['receipt'] );
	}

	public function test_unknown_code_returns_null(): void {
		$this->assertNull( Deny_Receipt::lookup( 'AICAC-ZZZZ-ZZZZ' ) );
		$this->assertNull( Deny_Receipt::lookup( 'not-a-code' ) );
		$this->assertSame( '', Deny_Receipt::normalize_code( 'short' ) );
	}

	public function test_redacted_lookup_keeps_code_hides_payload(): void {
		Deny_Receipt::set_test_redacted( true );
		$event = array(
			'ts'              => self::NOW,
			'decision'        => 'deny',
			'log_key'         => self::KEY,
			'plugin'          => 'demo/demo.php',
			'decision_source' => 'rule:explicit-deny',
			'prompt_preview'  => 'secret prompt',
			'uri'             => '/wp-admin/post.php',
			'user_id'         => 12,
			'user_role'       => 'editor',
			'caller'          => 'Demo::run',
		);
		Deny_Receipt::stamp( $event );
		update_option( Plugin::LOG_OPTION_KEY, array( $event ), false );

		$got = Deny_Receipt::lookup( $event['receipt'] );
		$this->assertIsArray( $got );
		$this->assertSame( $event['receipt'], $got['receipt'] );
		$this->assertSame( 'demo/demo.php', $got['plugin'] );
		$this->assertSame( '', $got['prompt_preview'] );
		$this->assertSame( '', $got['uri'] );
		$this->assertSame( 0, $got['user_id'] );
		$this->assertSame( '', $got['caller'] );
		$this->assertSame( 'rule:explicit-deny', $got['decision_source'] );
		$this->assertSame( 'Denied because this plugin has a Deny rule.', Why::explain_line( $got ) );
	}

	public function test_lookup_screen_off_hides_form_settings_render(): void {
		ob_start();
		Deny_Receipt::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Deny receipts are off', $html );
		$this->assertStringNotContainsString( 'Look up a code', $html );
		$this->assertStringContainsString( 'Show code to callers', $html );
	}

	public function test_lookup_screen_on_resolves_code_in_html(): void {
		Deny_Receipt::save_settings(
			array(
				'message_enabled' => false,
				'lookup_enabled'  => true,
			)
		);
		$event = array(
			'ts'              => self::NOW,
			'decision'        => 'deny',
			'log_key'         => self::KEY,
			'plugin'          => 'demo/demo.php',
			'decision_source' => 'kill_switch',
		);
		Deny_Receipt::stamp( $event );
		update_option( Plugin::LOG_OPTION_KEY, array( $event ), false );
		$_GET['receipt'] = $event['receipt'];

		ob_start();
		Deny_Receipt::render_page();
		$html = (string) ob_get_clean();
		unset( $_GET['receipt'] );

		$this->assertStringContainsString( 'Look up a code', $html );
		$this->assertStringContainsString( 'Match found', $html );
		$this->assertStringContainsString( $event['receipt'], $html );
		$this->assertStringContainsString( 'demo/demo.php', $html );
		$this->assertStringContainsString( 'Why?', $html );
	}

	public function test_policy_php_has_one_sanctioned_hook_line(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy.php' );
		$this->assertSame(
			1,
			substr_count( $src, 'Deny_Receipt::stamp( $event )' )
		);
		$this->assertStringContainsString(
			'AICAC-DENY-RECEIPT (#430) sanctioned one-line hook',
			$src
		);
	}

	public function test_caller_deny_error_message_unchanged_when_off(): void {
		$this->assertSame(
			'Prompt execution was prevented by a filter.',
			Policy::caller_deny_error_message()
		);
	}
}
