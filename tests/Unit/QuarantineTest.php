<?php
/**
 * AICAC-QUARANTINE (#512).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Snooze;
use HandL\AICAC\Deny_Receipt;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Quarantine;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class QuarantineTest extends TestCase {

	private const PLUGIN = 'connector/plugin.php';

	private const NOW = 1791800000;

	private const OPENAI = 'https://api.openai.com/v1/chat/completions';

	private const HOSTILE = '<script>alert(1)</script><script>alert(2)</script>';

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_filters']          = array();
		$GLOBALS['handl_aicac_test_plugins']          = array(
			self::PLUGIN => array(
				'Name'    => 'Connector',
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
		Quarantine::reset_for_tests();
		Quarantine::set_test_now( self::NOW );
		Quarantine::set_test_plugin( self::PLUGIN );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
			)
		);
		update_option( 'admin_email', 'admin@example.com' );
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_filters'] = array();
		$GLOBALS['handl_aicac_test_plugins'] = array();
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		Quarantine::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * @param mixed $body Response body.
	 * @return array<string,mixed>
	 */
	private function response( $body ): array {
		return array(
			'headers'  => array(),
			'body'     => $body,
			'response' => array(
				'code'    => 200,
				'message' => 'OK',
			),
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	private function args(): array {
		return array(
			'timeout' => 5,
			'body'    => '{"model":"gpt-4"}',
			'_probe'  => 'keep-me',
		);
	}

	public function test_plugin_bootstrap_wires_quarantine_after_optout(): void {
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-quarantine.php', $plugin );
		$this->assertStringContainsString( 'Quarantine::init()', $plugin );
		$this->assertGreaterThan(
			(int) strrpos( $plugin, 'Optout::init()' ),
			(int) strrpos( $plugin, 'Quarantine::init()' )
		);
		$boot = (string) file_get_contents( HANDL_AICAC_DIR . '/tests/bootstrap.php' );
		$this->assertStringContainsString( 'class-handl-aicac-quarantine.php', $boot );
		$readme = (string) file_get_contents( HANDL_AICAC_DIR . '/readme.txt' );
		$this->assertStringNotContainsString( 'quarantine', strtolower( $readme ) );
		$admin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringNotContainsString( 'Quarantine', $admin );
		$policy = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy.php' );
		$this->assertStringNotContainsString( 'Quarantine', $policy );
		$trip = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-tripwire.php' );
		$this->assertStringNotContainsString( 'Quarantine', $trip );
		$opt = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-optout.php' );
		$this->assertStringNotContainsString( 'Quarantine', $opt );
	}

	public function test_off_by_default_is_noop(): void {
		$this->assertFalse( Quarantine::is_enabled() );
		$this->assertSame( Quarantine::defaults(), Quarantine::get_settings() );
		$resp = $this->response( self::HOSTILE );
		$copy = $resp;
		$args = $this->args();
		Quarantine::on_http_api_debug( $resp, 'response', 'WpOrg\Requests\Requests', $args, self::OPENAI );
		$out = Quarantine::on_http_response( $resp, $args, self::OPENAI );
		$this->assertSame( $copy, $out );
		$this->assertSame( $copy, $resp );
		$this->assertSame( array(), Quarantine::last_events() );
		$this->assertSame( array(), self::$mails );
	}

	public function test_warn_logs_script_tag_flag_alerts_and_leaves_response(): void {
		Quarantine::save_settings( array( 'enabled' => true ) );
		$resp = $this->response( self::HOSTILE );
		$copy = $resp;
		$args = $this->args();
		Quarantine::on_http_api_debug( $resp, 'response', 'WpOrg\Requests\Requests', $args, self::OPENAI );
		$out = Quarantine::on_http_response( $resp, $args, self::OPENAI );
		$this->assertSame( $copy, $out );
		$this->assertSame( self::HOSTILE, $out['body'] );
		$events = Quarantine::last_events();
		$this->assertCount( 1, $events );
		$this->assertSame( 'warn', $events[0]['decision'] );
		$this->assertSame( Quarantine::MODE_WARN, $events[0]['quarantine']['mode'] );
		$this->assertSame( 2, $events[0]['quarantine']['kinds'][ Quarantine::KIND_SCRIPT ] ?? 0 );
		$this->assertSame( 'Script tag (2)', $events[0]['detail'] );
		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$last = $log[ count( $log ) - 1 ];
		$this->assertArrayHasKey( 'quarantine', $last );
		$this->assertSame( 2, $last['quarantine']['kinds'][ Quarantine::KIND_SCRIPT ] );
		$quarantine_mail = null;
		foreach ( self::$mails as $mail ) {
			if ( false !== strpos( $mail['subject'], 'Possible active content in an AI reply used by' ) ) {
				$quarantine_mail = $mail;
				break;
			}
		}
		$this->assertNotNull( $quarantine_mail );
		$this->assertStringContainsString( 'found a matching active-content pattern', $quarantine_mail['message'] );
		$this->assertStringContainsString( 'Code examples can also match.', $quarantine_mail['message'] );
		$this->assertStringContainsString( 'Mode: Warn. The reply was left unchanged.', $quarantine_mail['message'] );
		$this->assertStringContainsString( 'Review how this plugin displays AI replies.', $quarantine_mail['message'] );
		$this->assertStringContainsString( 'Script tag (2)', $quarantine_mail['message'] );
		$this->assertStringNotContainsString( 'alert(1)', $quarantine_mail['message'] );
		$this->assertNotEmpty( Quarantine::test_mails() );
	}

	public function test_hard_replaces_response_with_wp_error_reason_quarantine(): void {
		Quarantine::save_settings(
			array(
				'enabled'      => true,
				'plugin_modes' => array( self::PLUGIN => Quarantine::MODE_HARD ),
			)
		);
		$resp = $this->response( self::HOSTILE );
		$args = $this->args();
		Quarantine::on_http_api_debug( $resp, 'response', 'WpOrg\Requests\Requests', $args, self::OPENAI );
		$out = Quarantine::on_http_response( $resp, $args, self::OPENAI );
		$this->assertInstanceOf( \WP_Error::class, $out );
		$this->assertSame( Quarantine::ERROR_CODE, $out->code );
		$this->assertStringContainsString( 'matched an active-content pattern:', $out->get_error_message() );
		$this->assertStringContainsString( 'Script tag (2)', $out->get_error_message() );
		$this->assertStringNotContainsString( 'alert(1)', $out->get_error_message() );
		$this->assertSame(
			'This AI reply was blocked because it matched an active-content pattern.',
			Quarantine::block_message( array() )
		);
		$events = Quarantine::last_events();
		$this->assertCount( 1, $events );
		$this->assertSame( 'deny', $events[0]['decision'] );
		$this->assertSame( Quarantine::REASON, $events[0]['denial_reason'] );
		$this->assertArrayHasKey( Deny_Receipt::ROW_KEY, $events[0] );
		$this->assertStringStartsWith( 'AICAC-', (string) $events[0][ Deny_Receipt::ROW_KEY ] );
		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertSame( 'deny', $log[ count( $log ) - 1 ]['decision'] ?? null );
		$this->assertNull( Quarantine::pending_hard() );
	}

	public function test_clean_response_has_zero_flags(): void {
		Quarantine::save_settings( array( 'enabled' => true ) );
		$resp = $this->response( '{"choices":[{"message":{"content":"Hello, how can I help?"}}]}' );
		$copy = $resp;
		$args = $this->args();
		Quarantine::on_http_api_debug( $resp, 'response', 'WpOrg\Requests\Requests', $args, self::OPENAI );
		$out = Quarantine::on_http_response( $resp, $args, self::OPENAI );
		$this->assertSame( $copy, $out );
		$this->assertSame( array(), Quarantine::last_events() );
		$this->assertSame( array(), self::$mails );
	}

	public function test_response_text_is_never_persisted(): void {
		Quarantine::save_settings( array( 'enabled' => true ) );
		$secret = '<script>steal("' . uniqid( 'tok', true ) . '")</script>';
		$resp   = $this->response( $secret );
		Quarantine::on_http_api_debug( $resp, 'response', 'WpOrg\Requests\Requests', $this->args(), self::OPENAI );
		$events = Quarantine::last_events();
		$json   = wp_json_encode( $events );
		$this->assertIsString( $json );
		$this->assertStringNotContainsString( $secret, $json );
		$this->assertStringNotContainsString( 'steal(', $json );
		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertStringNotContainsString( $secret, (string) wp_json_encode( $log ) );
		$opt = get_option( Quarantine::SETTINGS_OPTION );
		$this->assertStringNotContainsString( $secret, (string) wp_json_encode( $opt ) );
	}

	public function test_other_kinds_and_json_unicode_escape(): void {
		Quarantine::save_settings( array( 'enabled' => true ) );
		$html = '<img src=x onerror=boom> javascript:alert(1) data:text/html,x <iframe src=x></iframe>';
		$hits = Quarantine::screen( $html );
		$this->assertGreaterThan( 0, $hits[ Quarantine::KIND_EVENT ] ?? 0 );
		$this->assertGreaterThan( 0, $hits[ Quarantine::KIND_JS_URI ] ?? 0 );
		$this->assertGreaterThan( 0, $hits[ Quarantine::KIND_DATA_HTML ] ?? 0 );
		$this->assertGreaterThan( 0, $hits[ Quarantine::KIND_IFRAME ] ?? 0 );

		$escaped = '{"choices":[{"message":{"content":"\\u003cscript\\u003ealert(9)\\u003c/script\\u003e"}}]}';
		$resp    = $this->response( $escaped );
		Quarantine::on_http_api_debug( $resp, 'response', 'WpOrg\Requests\Requests', $this->args(), self::OPENAI );
		$events = Quarantine::last_events();
		$this->assertCount( 1, $events );
		$this->assertGreaterThan( 0, $events[0]['quarantine']['kinds'][ Quarantine::KIND_SCRIPT ] ?? 0 );
		$this->assertStringNotContainsString( 'alert(9)', (string) wp_json_encode( $events ) );
	}

	public function test_non_provider_host_is_untouched(): void {
		Quarantine::save_settings( array( 'enabled' => true ) );
		$resp = $this->response( self::HOSTILE );
		$copy = $resp;
		$out  = Quarantine::on_http_response( $resp, $this->args(), 'https://wordpress.org/news/' );
		$this->assertSame( $copy, $out );
		$this->assertSame( array(), Quarantine::last_events() );
	}

	public function test_per_plugin_off_skips_when_global_on(): void {
		Quarantine::save_settings(
			array(
				'enabled'      => true,
				'plugin_modes' => array( self::PLUGIN => Quarantine::MODE_OFF ),
			)
		);
		$resp = $this->response( self::HOSTILE );
		$out  = Quarantine::on_http_response( $resp, $this->args(), self::OPENAI );
		$this->assertSame( $resp, $out );
		$this->assertSame( array(), Quarantine::last_events() );
	}

	public function test_filter_adds_custom_kind(): void {
		Quarantine::save_settings( array( 'enabled' => true ) );
		$GLOBALS['handl_aicac_test_filters'][ Quarantine::FILTER ] = static function ( $table ) {
			if ( ! is_array( $table ) ) {
				$table = array();
			}
			$table['custom-bait'] = array( '/open the vault/i' );

			return $table;
		};
		$hits = Quarantine::screen( 'Please open the vault tonight.' );
		$this->assertSame( 1, $hits['custom-bait'] ?? 0 );
		Quarantine::on_http_api_debug(
			$this->response( 'Please open the vault tonight.' ),
			'response',
			'WpOrg\Requests\Requests',
			$this->args(),
			self::OPENAI
		);
		$events = Quarantine::last_events();
		$this->assertSame( 1, $events[0]['quarantine']['kinds']['custom-bait'] ?? 0 );
	}

	public function test_off_copy_renders(): void {
		ob_start();
		Quarantine::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Response quarantine', $html );
		$this->assertStringContainsString( 'Response quarantine is off. This feature is not checking AI replies.', $html );
		$this->assertStringContainsString( 'This feature records pattern types and match counts, not the reply text.', $html );
		$this->assertStringContainsString( 'Check replies from recognized AI providers for script tags and other patterns listed below.', $html );
		$this->assertStringContainsString( 'Checks are off until you configure them.', $html );
		$this->assertStringContainsString( 'Default for plugins without a setting.', $html );
		$this->assertStringContainsString( 'Use Warn for plugins without a saved mode.', $html );
		$this->assertStringContainsString( 'Saved per-plugin modes still apply.', $html );
		$this->assertStringContainsString( 'Code examples can also match these patterns.', $html );
		$this->assertStringContainsString( 'Only the first 512 KiB of the text being checked is scanned.', $html );
		$this->assertStringContainsString( 'Saved modes override the default above.', $html );
		$this->assertStringContainsString( 'Block returns an error instead of the reply.', $html );
		$this->assertStringContainsString( '>Block<', $html );
		$this->assertStringNotContainsString( '>Hard<', $html );
		$this->assertSame( 'hard', Quarantine::MODE_HARD );
		$this->assertSame( 'Block', Quarantine::mode_choices()[ Quarantine::MODE_HARD ] );
	}

	public function test_request_args_are_never_mutated(): void {
		Quarantine::save_settings( array( 'enabled' => true ) );
		$args = $this->args();
		$copy = $args;
		Quarantine::on_http_api_debug( $this->response( self::HOSTILE ), 'response', 'WpOrg\Requests\Requests', $args, self::OPENAI );
		Quarantine::on_http_response( $this->response( self::HOSTILE ), $args, self::OPENAI );
		$this->assertSame( $copy, $args );
	}
}
