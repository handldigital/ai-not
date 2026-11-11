<?php
/**
 * AICAC-TRIPWIRE (#497): real-secret egress guard.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Snooze;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Tripwire;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class TripwireTest extends TestCase {

	private const PLUGIN = 'acme/acme.php';

	private const DB_SECRET = 'tw-db-s3cret-ZX9qK2mL';

	private const AUTH_SECRET = 'tw-auth-salt-ABCDEFGH12345678';

	private const PROVIDER_KEY = 'sk-twproviderKEY9xY8wV7uT6sR5q';

	private const CLEAN = 'Please summarize this blog post about garden tomatoes.';

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_plugins']          = array(
			self::PLUGIN => array(
				'Name'    => 'Acme AI',
				'Version' => '1.0.0',
			),
		);
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);
			return true;
		};
		Tripwire::reset_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		update_option( 'admin_email', 'admin@example.com' );
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'], $GLOBALS['handl_aicac_test_plugins'], $GLOBALS['handl_aicac_test_filters'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		Tripwire::reset_for_tests();
		parent::tearDown();
	}

	public function test_plugin_bootstrap_wires_tripwire_at_bottom(): void {
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-tripwire.php', $plugin );
		$this->assertStringContainsString( 'Tripwire::init()', $plugin );
		$this->assertGreaterThan(
			(int) strrpos( $plugin, 'Foyer::init()' ),
			(int) strrpos( $plugin, 'Tripwire::init()' )
		);
		$boot = (string) file_get_contents( HANDL_AICAC_DIR . '/tests/bootstrap.php' );
		$this->assertStringContainsString( 'class-handl-aicac-tripwire.php', $boot );
		$readme = (string) file_get_contents( HANDL_AICAC_DIR . '/readme.txt' );
		$this->assertStringNotContainsString( 'tripwire', strtolower( $readme ) );
		$admin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringNotContainsString( 'Tripwire', $admin );
		$keyscan = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-keyscan.php' );
		$this->assertStringNotContainsString( 'Tripwire', $keyscan );
		$pii = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-pii-warn.php' );
		$this->assertStringNotContainsString( 'Tripwire', $pii );
	}

	public function test_policy_wire_after_taint_in_source(): void {
		$body = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy.php' );
		$tnt  = strpos( $body, 'Taint::apply_to_event' );
		$tw   = strpos( $body, 'Tripwire::apply_to_event' );
		$this->assertNotFalse( $tnt );
		$this->assertNotFalse( $tw );
		$this->assertGreaterThan( $tnt, $tw );
		$this->assertNotFalse( strpos( $body, 'Tripwire::sanitize_plugin_modes' ) );
		$this->assertNotFalse( strpos( $body, 'Tripwire::maybe_alert' ) );
		$this->assertNotFalse( strpos( $body, "'tripwire'" ) );
	}

	public function test_deny_by_default_blocks_db_password_and_alerts(): void {
		Tripwire::set_test_secrets(
			array(
				array(
					'kind'  => Tripwire::KIND_DB,
					'value' => self::DB_SECRET,
				),
			)
		);
		$policy = array( 'plugins' => array( self::PLUGIN => 'allow' ) );
		$this->assertSame( Tripwire::MODE_DENY, Tripwire::mode_for_plugin( $policy, self::PLUGIN ) );
		$event  = array(
			'plugin'         => self::PLUGIN,
			'decision'       => 'allow',
			'prompt_preview' => 'Connect with ' . self::DB_SECRET . ' please.',
		);
		$result = Tripwire::apply_to_event( $event, $policy, null );
		$this->assertTrue( $result['active'] );
		$this->assertTrue( $result['prevent'] );
		$this->assertSame( Tripwire::MODE_DENY, $result['mode'] );
		$this->assertSame( 1, $result['matches'][ Tripwire::KIND_DB ] ?? 0 );
		$this->assertSame( Tripwire::KIND_DB, array_key_first( $event['tripwire_match']['kinds'] ) );
		$this->assertStringNotContainsString( self::DB_SECRET, (string) $event['prompt_preview'] );
		$this->assertStringContainsString( '[redacted-' . Tripwire::KIND_DB . ']', (string) $event['prompt_preview'] );
		$this->assertSame( 'Site secret detected', \HandL\AICAC\Policy_Simulator::reason_label( Tripwire::REASON ) );

		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
				'alert_email' => 'admin@example.com',
			),
			false
		);
		$event['ts']       = 1_700_000_000;
		$event['decision'] = 'deny';
		$event['denial_reason'] = Tripwire::REASON;
		Policy::append_log_event( $event );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'Database password', self::$mails[0]['message'] );
		$this->assertStringContainsString( 'Tripwire setting: Deny. This check blocks matching requests except in Learn mode.', self::$mails[0]['message'] );
		$this->assertStringContainsString( 'Review this plugin\'s AI request and remove any site secrets. This alert does not include secret values.', self::$mails[0]['message'] );
		$this->assertStringNotContainsString( self::DB_SECRET, self::$mails[0]['message'] );
	}

	public function test_provider_key_blocks_with_kind_provider_key(): void {
		Tripwire::set_test_secrets(
			array(
				array(
					'kind'  => Tripwire::KIND_PROVIDER,
					'value' => self::PROVIDER_KEY,
				),
			)
		);
		$policy = array();
		$event  = array(
			'plugin'         => self::PLUGIN,
			'decision'       => 'allow',
			'prompt_preview' => 'Use key ' . self::PROVIDER_KEY,
		);
		$result = Tripwire::apply_to_event( $event, $policy, null );
		$this->assertTrue( $result['prevent'] );
		$this->assertSame( 1, $result['matches'][ Tripwire::KIND_PROVIDER ] ?? 0 );
		$this->assertStringNotContainsString( self::PROVIDER_KEY, (string) $event['prompt_preview'] );
		$receipt = Tripwire::receipt_summary( $event['tripwire_match']['kinds'] );
		$this->assertStringContainsString( 'Provider API key', $receipt );
		$this->assertStringNotContainsString( self::PROVIDER_KEY, $receipt );
	}

	public function test_clean_payload_is_noop_and_digest_builds_once(): void {
		Tripwire::set_test_secrets(
			array(
				array(
					'kind'  => Tripwire::KIND_DB,
					'value' => self::DB_SECRET,
				),
				array(
					'kind'  => Tripwire::KIND_AUTH,
					'value' => self::AUTH_SECRET,
				),
				array(
					'kind'  => Tripwire::KIND_PROVIDER,
					'value' => self::PROVIDER_KEY,
				),
			)
		);
		$policy = array();
		$event  = array(
			'plugin'         => self::PLUGIN,
			'decision'       => 'allow',
			'prompt_preview' => self::CLEAN,
		);
		$first = Tripwire::apply_to_event( $event, $policy, null );
		$this->assertFalse( $first['prevent'] );
		$this->assertSame( array(), $first['matches'] );
		$this->assertArrayNotHasKey( 'tripwire_match', $event );
		$this->assertSame( self::CLEAN, $event['prompt_preview'] );
		$second = Tripwire::screen( self::CLEAN );
		$this->assertSame( array(), $second );
		$this->assertSame( 1, Tripwire::digest_build_count() );
	}

	public function test_warn_override_allows_logs_and_alerts(): void {
		Tripwire::set_test_secrets(
			array(
				array(
					'kind'  => Tripwire::KIND_AUTH,
					'value' => self::AUTH_SECRET,
				),
			)
		);
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled'      => true,
				'alert_email'      => 'admin@example.com',
				'tripwire_screen'  => array( self::PLUGIN => 'warn' ),
			),
			false
		);
		$policy = Policy::get_policy();
		$this->assertSame( Tripwire::MODE_WARN, Tripwire::mode_for_plugin( $policy, self::PLUGIN ) );
		$event  = array(
			'ts'             => 1_700_000_000,
			'plugin'         => self::PLUGIN,
			'decision'       => 'allow',
			'prompt_preview' => 'salt=' . self::AUTH_SECRET,
		);
		$result = Tripwire::apply_to_event( $event, $policy, null );
		$this->assertTrue( $result['active'] );
		$this->assertFalse( $result['prevent'] );
		$this->assertSame( Tripwire::MODE_WARN, $result['mode'] );
		$this->assertSame( 'allow', $event['decision'] );
		$this->assertSame( 1, $result['matches'][ Tripwire::KIND_AUTH ] ?? 0 );
		Policy::append_log_event( $event );
		$log = get_option( Plugin::LOG_OPTION_KEY );
		$encoded = wp_json_encode( $log );
		$this->assertIsString( $encoded );
		$this->assertStringNotContainsString( self::AUTH_SECRET, (string) $encoded );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'Authentication key', self::$mails[0]['message'] );
		$this->assertStringContainsString( 'Tripwire setting: Warn. This check does not block the request. Other rules still apply.', self::$mails[0]['message'] );
		$this->assertStringNotContainsString( self::AUTH_SECRET, self::$mails[0]['message'] );
	}

	public function test_secret_values_absent_from_log_alert_and_receipt(): void {
		Tripwire::set_test_secrets(
			array(
				array(
					'kind'  => Tripwire::KIND_DB,
					'value' => self::DB_SECRET,
				),
			)
		);
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
				'alert_email' => 'admin@example.com',
			),
			false
		);
		$event = array(
			'ts'             => 1_700_000_000,
			'plugin'         => self::PLUGIN,
			'decision'       => 'allow',
			'prompt_preview' => 'pw ' . self::DB_SECRET,
		);
		Tripwire::apply_to_event( $event, Policy::get_policy(), null );
		$event['decision']       = 'deny';
		$event['denial_reason']  = Tripwire::REASON;
		Policy::append_log_event( $event );

		$blob = wp_json_encode(
			array(
				'log'     => get_option( Plugin::LOG_OPTION_KEY ),
				'mails'   => self::$mails,
				'receipt' => Tripwire::receipt_summary( $event['tripwire_match']['kinds'] ),
				'event'   => $event,
			)
		);
		$this->assertIsString( $blob );
		$this->assertStringNotContainsString( self::DB_SECRET, (string) $blob );
		$this->assertStringNotContainsString( hash_hmac( 'sha256', self::DB_SECRET, 'handl-aicac-test-salt-auth' ), (string) $blob );
	}

	public function test_prefix_of_twelve_chars_matches(): void {
		Tripwire::set_test_secrets(
			array(
				array(
					'kind'  => Tripwire::KIND_AUTH,
					'value' => self::AUTH_SECRET,
				),
			)
		);
		$prefix = substr( self::AUTH_SECRET, 0, 12 );
		$this->assertSame( 12, strlen( $prefix ) );
		$hits = Tripwire::screen( 'leak ' . $prefix . ' end' );
		$this->assertSame( 1, $hits[ Tripwire::KIND_AUTH ] ?? 0 );
		$miss = Tripwire::screen( 'leak ' . substr( self::AUTH_SECRET, 0, 11 ) . ' end' );
		$this->assertSame( array(), $miss );
	}

	public function test_page_default_on_copy_and_save_label(): void {
		Tripwire::init();
		ob_start();
		Tripwire::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Secret tripwire', $html );
		$this->assertStringContainsString( 'Secret tripwire is on. Deny is the default; per-plugin Warn settings and Learn mode can allow matching requests.', $html );
		$this->assertStringContainsString( 'Save tripwire', $html );
		$this->assertStringContainsString( 'already found by Keyscan. On by default.', $html );
		$this->assertStringContainsString( 'Deny blocks matching requests unless Learn mode is on.', $html );
		$this->assertStringContainsString( 'This check does not save secret values', $html );
	}

	public function test_sanitize_plugin_modes_keeps_warn_only(): void {
		$map = Tripwire::sanitize_plugin_modes(
			array(
				self::PLUGIN      => 'warn',
				'other/other.php' => 'deny',
				'bad'             => 'warn',
				''                => 'warn',
			)
		);
		$this->assertSame( array( self::PLUGIN => 'warn' ), $map );
	}

	public function test_live_wp_config_constant_is_collected(): void {
		if ( ! defined( 'DB_PASSWORD' ) ) {
			define( 'DB_PASSWORD', self::DB_SECRET );
		}
		if ( DB_PASSWORD !== self::DB_SECRET ) {
			$this->markTestSkipped( 'DB_PASSWORD already defined to another value.' );
		}
		Tripwire::reset_for_tests();
		$hits = Tripwire::screen( 'dsn=' . self::DB_SECRET );
		$this->assertSame( 1, $hits[ Tripwire::KIND_DB ] ?? 0 );
	}
}
