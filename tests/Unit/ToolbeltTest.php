<?php
/**
 * AICAC-TOOLBELT (#519).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Snooze;
use HandL\AICAC\Plugin;
use HandL\AICAC\Toolbelt;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class ToolbeltTest extends TestCase {

	private const PLUGIN = 'chat/chat.php';

	private const NOW = 1793000000;

	private const SECRET = 'SECRET-DESCRIPTION-MUST-NOT-PERSIST';

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		self::$mails                                  = array();
		$GLOBALS['handl_aicac_wp_mail']               = static function ( $to, $subject, $message ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);
			return true;
		};
		Toolbelt::reset_for_tests();
		Toolbelt::set_test_now( self::NOW );
		Toolbelt::set_test_plugin( self::PLUGIN );
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		$GLOBALS['handl_aicac_test_options'] = array();
		self::$mails                         = array();
		Toolbelt::reset_for_tests();
		parent::tearDown();
	}

	public function test_defaults_off_and_noop_save_leaves_options_byte_identical(): void {
		$this->assertFalse( Toolbelt::is_enabled() );
		$before = $GLOBALS['handl_aicac_test_options'];
		$this->assertFalse( Toolbelt::save_settings( array( 'enabled' => false ) ) );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] );
		$this->assertFalse( (bool) get_option( Toolbelt::SETTINGS_OPTION, false ) );
		$this->assertFalse( (bool) get_option( Toolbelt::SEEN_OPTION, false ) );
	}

	public function test_feature_off_records_nothing_and_sends_nothing(): void {
		$before = $GLOBALS['handl_aicac_test_options'];
		$args   = $this->openai_args( array( 'search_posts' ) );
		$back   = Toolbelt::observe( $args, 'https://api.openai.com/v1/chat/completions' );
		$this->assertSame( $args, $back );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] );
		$this->assertSame( array(), self::$mails );
		$this->assertSame( array(), Toolbelt::get_seen() );
	}

	public function test_call_with_no_tool_list_records_nothing(): void {
		$this->enable();
		$args = array(
			'body' => wp_json_encode(
				array(
					'model'    => 'gpt-4o',
					'messages' => array(
						array(
							'role'    => 'user',
							'content' => self::SECRET,
						),
					),
				)
			),
		);
		Toolbelt::observe( $args, 'https://api.openai.com/v1/chat/completions' );
		$this->assertSame( array(), Toolbelt::get_seen() );
		$this->assertSame( array(), self::$mails );
		$this->assertStringNotContainsString( self::SECRET, (string) wp_json_encode( get_option( Toolbelt::SEEN_OPTION, array() ) ) );
	}

	public function test_first_tool_list_is_baseline_and_does_not_alert(): void {
		$this->enable();
		$args = $this->openai_args( array( 'update_order', 'search_posts' ) );
		$back = Toolbelt::observe( $args, 'https://api.openai.com/v1/chat/completions' );
		$this->assertSame( $args, $back );
		$seen = Toolbelt::get_seen();
		$this->assertArrayHasKey( self::PLUGIN, $seen );
		$this->assertSame( array( 'update_order', 'search_posts' ), $this->names_of( self::PLUGIN ) );
		$this->assertSame( self::NOW, $seen[ self::PLUGIN ]['search_posts']['first_seen'] );
		$this->assertSame( 'openai', $seen[ self::PLUGIN ]['search_posts']['provider'] );
		$this->assertSame( array(), self::$mails );
		$this->assertStringNotContainsString( self::SECRET, (string) wp_json_encode( $seen ) );
	}

	public function test_same_names_in_any_order_add_no_record_and_no_alert(): void {
		$this->enable();
		Toolbelt::observe( $this->openai_args( array( 'search_posts', 'update_order' ) ), 'https://api.openai.com/v1/chat/completions' );
		Toolbelt::set_test_now( self::NOW + 90 );
		Toolbelt::observe( $this->openai_args( array( 'update_order', 'search_posts' ) ), 'https://api.openai.com/v1/chat/completions' );
		$seen = Toolbelt::get_seen();
		$this->assertCount( 2, $seen[ self::PLUGIN ] );
		$this->assertSame( self::NOW, $seen[ self::PLUGIN ]['search_posts']['first_seen'] );
		$this->assertSame( self::NOW + 90, $seen[ self::PLUGIN ]['search_posts']['last_seen'] );
		$this->assertSame( array(), self::$mails );
	}

	public function test_one_added_name_records_and_alerts_once(): void {
		$this->enable();
		$this->set_alert_email();
		Toolbelt::observe( $this->openai_args( array( 'search_posts' ) ), 'https://api.openai.com/v1/chat/completions' );
		Toolbelt::set_test_now( self::NOW + 30 );
		Toolbelt::observe( $this->openai_args( array( 'search_posts', 'update_order' ) ), 'https://api.openai.com/v1/chat/completions' );
		$this->assertContains( 'update_order', $this->names_of( self::PLUGIN ) );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( self::PLUGIN, self::$mails[0]['subject'] );
		$this->assertStringContainsString( 'update_order', self::$mails[0]['subject'] );
		$this->assertStringContainsString( self::PLUGIN, self::$mails[0]['message'] );
		$this->assertStringContainsString( 'update_order', self::$mails[0]['message'] );
		$this->assertStringNotContainsString( 'search_posts', self::$mails[0]['subject'] );
		$this->assertStringNotContainsString( self::SECRET, self::$mails[0]['message'] );

		Toolbelt::observe( $this->openai_args( array( 'update_order' ) ), 'https://api.openai.com/v1/chat/completions' );
		$this->assertCount( 1, self::$mails );
	}

	public function test_provider_shapes_are_recognized_and_bad_json_is_skipped(): void {
		$this->enable();
		$this->set_alert_email();
		Toolbelt::observe( $this->openai_args( array( 'search_posts' ) ), 'https://api.openai.com/v1/chat/completions' );
		$this->assertSame( array( 'search_posts' ), $this->names_of( self::PLUGIN ) );

		Toolbelt::set_test_plugin( 'mail/mail.php' );
		Toolbelt::observe( $this->anthropic_args( array( 'send_email' ) ), 'https://api.anthropic.com/v1/messages' );
		$this->assertSame( array( 'send_email' ), $this->names_of( 'mail/mail.php' ) );
		$this->assertSame( 'anthropic', Toolbelt::get_seen()['mail/mail.php']['send_email']['provider'] );

		Toolbelt::set_test_plugin( 'shop/shop.php' );
		Toolbelt::observe( $this->gemini_args( array( 'refund_order' ) ), 'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent' );
		$this->assertSame( array( 'refund_order' ), $this->names_of( 'shop/shop.php' ) );
		$this->assertSame( 'google', Toolbelt::get_seen()['shop/shop.php']['refund_order']['provider'] );

		$before = get_option( Toolbelt::SEEN_OPTION );
		$args   = array( 'body' => '{not json ' . self::SECRET );
		$back   = Toolbelt::observe( $args, 'https://api.openai.com/v1/chat/completions' );
		$this->assertSame( $args, $back );
		$this->assertSame( $before, get_option( Toolbelt::SEEN_OPTION ) );
		$this->assertSame( array(), self::$mails );
	}

	public function test_stored_option_has_names_and_timestamps_only(): void {
		$this->enable();
		Toolbelt::observe( $this->openai_args( array( 'search_posts' ) ), 'https://api.openai.com/v1/chat/completions' );
		$stored = get_option( Toolbelt::SEEN_OPTION );
		$this->assertIsArray( $stored );
		$row = $stored[ self::PLUGIN ]['search_posts'];
		$this->assertSame( array( 'name', 'first_seen', 'last_seen', 'provider' ), array_keys( $row ) );
		$blob = (string) wp_json_encode( $stored );
		$this->assertStringNotContainsString( 'description', $blob );
		$this->assertStringNotContainsString( 'parameters', $blob );
		$this->assertStringNotContainsString( self::SECRET, $blob );
		$this->assertStringNotContainsString( 'input_schema', $blob );
	}

	public function test_non_provider_host_is_ignored(): void {
		$this->enable();
		Toolbelt::observe( $this->openai_args( array( 'search_posts' ) ), 'https://example.com/wp-json' );
		$this->assertSame( array(), Toolbelt::get_seen() );
		$this->assertSame( array(), self::$mails );
	}

	public function test_snooze_suppresses_the_alert_and_does_not_repeat(): void {
		$this->enable();
		$this->set_alert_email();
		Toolbelt::observe( $this->openai_args( array( 'search_posts' ) ), 'https://api.openai.com/v1/chat/completions' );
		Alert_Snooze::set( self::PLUGIN, '1h', self::NOW + 10 );
		Toolbelt::set_test_now( self::NOW + 20 );
		Toolbelt::observe( $this->openai_args( array( 'search_posts', 'delete_post' ) ), 'https://api.openai.com/v1/chat/completions' );
		$this->assertContains( 'delete_post', $this->names_of( self::PLUGIN ) );
		$this->assertSame( array(), self::$mails );
		Toolbelt::set_test_now( self::NOW + 40 );
		Toolbelt::observe( $this->openai_args( array( 'delete_post' ) ), 'https://api.openai.com/v1/chat/completions' );
		$this->assertSame( array(), self::$mails );
	}

	public function test_screen_flags_mutating_names_and_is_read_only(): void {
		$this->assertTrue( Toolbelt::changes_things( 'update_order' ) );
		$this->assertTrue( Toolbelt::changes_things( 'Send_Email' ) );
		$this->assertTrue( Toolbelt::changes_things( 'refund_order' ) );
		$this->assertFalse( Toolbelt::changes_things( 'search_posts' ) );
		$this->assertFalse( Toolbelt::changes_things( 'list_orders' ) );

		$this->enable();
		Toolbelt::observe( $this->openai_args( array( 'search_posts', 'update_order' ) ), 'https://api.openai.com/v1/chat/completions' );
		ob_start();
		Toolbelt::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Toolbelt', $html );
		$this->assertStringContainsString( 'does not allow or block', $html );
		$this->assertStringContainsString( 'search_posts', $html );
		$this->assertStringContainsString( 'update_order', $html );
		$this->assertStringContainsString( 'Changes things', $html );
		$this->assertStringContainsString( 'Watch tool lists', $html );
		$this->assertStringNotContainsString( self::SECRET, $html );
		$this->assertStringNotContainsString( 'name="tool"', $html );
	}

	public function test_readme_and_fence_files_untouched(): void {
		$root = dirname( __DIR__, 2 );
		$readme = (string) file_get_contents( $root . '/readme.txt' );
		$this->assertStringNotContainsString( 'Toolbelt', $readme );
		foreach ( array(
			'includes/class-handl-aicac-policy.php',
			'includes/class-handl-aicac-policy-simulator.php',
			'includes/class-handl-aicac-admin.php',
			'includes/class-handl-aicac-drift.php',
			'includes/class-handl-aicac-luggage.php',
			'includes/class-handl-aicac-mcp-gate.php',
		) as $rel ) {
			$this->assertStringNotContainsString( 'class-handl-aicac-toolbelt.php', (string) file_get_contents( $root . '/' . $rel ) );
		}
	}

	private function enable(): void {
		$this->assertTrue( Toolbelt::save_settings( array( 'enabled' => true ) ) );
		$this->assertTrue( Toolbelt::is_enabled() );
	}

	private function set_alert_email(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'alert_email' => 'admin@example.com',
				'default'     => 'allow',
				'plugins'     => array(),
			)
		);
	}

	/**
	 * @param list<string> $names
	 * @return array<string,mixed>
	 */
	private function openai_args( array $names ): array {
		$tools = array();
		foreach ( $names as $name ) {
			$tools[] = array(
				'type'     => 'function',
				'function' => array(
					'name'        => $name,
					'description' => self::SECRET,
					'parameters'  => array( 'type' => 'object', 'secret' => self::SECRET ),
				),
			);
		}

		return array(
			'timeout' => 5,
			'body'    => wp_json_encode(
				array(
					'model' => 'gpt-4o',
					'tools' => $tools,
				)
			),
		);
	}

	/**
	 * @param list<string> $names
	 * @return array<string,mixed>
	 */
	private function anthropic_args( array $names ): array {
		$tools = array();
		foreach ( $names as $name ) {
			$tools[] = array(
				'name'         => $name,
				'description'  => self::SECRET,
				'input_schema' => array( 'type' => 'object' ),
			);
		}

		return array(
			'body' => wp_json_encode( array( 'tools' => $tools ) ),
		);
	}

	/**
	 * @param list<string> $names
	 * @return array<string,mixed>
	 */
	private function gemini_args( array $names ): array {
		$decls = array();
		foreach ( $names as $name ) {
			$decls[] = array(
				'name'        => $name,
				'description' => self::SECRET,
				'parameters'  => array( 'type' => 'object' ),
			);
		}

		return array(
			'body' => wp_json_encode(
				array(
					'tools' => array(
						array( 'functionDeclarations' => $decls ),
					),
				)
			),
		);
	}

	/**
	 * @return list<string>
	 */
	private function names_of( string $plugin ): array {
		$seen = Toolbelt::get_seen();
		$this->assertArrayHasKey( $plugin, $seen );

		return array_keys( $seen[ $plugin ] );
	}
}
