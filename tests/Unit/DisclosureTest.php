<?php
/**
 * Unit tests for the public AI disclosure shortcode/block (AICAC-DISCLOSURE / #282).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Disclosure;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

final class DisclosureTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['handl_aicac_test_options']             = array();
		$GLOBALS['handl_aicac_test_added_actions']       = array();
		$GLOBALS['handl_aicac_test_added_filters']       = array();
		$GLOBALS['handl_aicac_test_shortcodes']          = array();
		$GLOBALS['handl_aicac_test_blocks']              = array();
		$GLOBALS['handl_aicac_test_privacy_guide']       = array();
		$GLOBALS['handl_aicac_test_is_privacy_policy']   = false;
		$_POST = array();
		Disclosure::reset_for_tests();
	}

	protected function tearDown(): void {
		$_POST = array();
		Disclosure::reset_for_tests();
		unset(
			$GLOBALS['handl_aicac_test_options'],
			$GLOBALS['handl_aicac_test_added_actions'],
			$GLOBALS['handl_aicac_test_added_filters'],
			$GLOBALS['handl_aicac_test_shortcodes'],
			$GLOBALS['handl_aicac_test_blocks'],
			$GLOBALS['handl_aicac_test_privacy_guide'],
			$GLOBALS['handl_aicac_test_is_privacy_policy']
		);
	}

	public function test_init_registers_hooks_without_option_io(): void {
		$before = $GLOBALS['handl_aicac_test_options'] ?? array();
		Disclosure::instance()->init();
		$actions = $GLOBALS['handl_aicac_test_added_actions'] ?? array();
		$filters = $GLOBALS['handl_aicac_test_added_filters'] ?? array();
		$this->assertContains( Disclosure::SHORTCODE, $GLOBALS['handl_aicac_test_shortcodes'] ?? array() );
		$this->assertContains( 'init', $actions );
		$this->assertContains( 'admin_init', $actions );
		$this->assertContains( 'handl_aicac_protections_settings', $actions );
		$this->assertContains( 'the_content', $filters );
		$this->assertContains( 'pre_update_option_' . Plugin::OPTION_KEY, $filters );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] ?? array() );
	}

	public function test_register_block_uses_render_callback(): void {
		Disclosure::instance()->register_block();
		$this->assertContains( Disclosure::BLOCK_NAME, $GLOBALS['handl_aicac_test_blocks'] ?? array() );
	}

	public function test_defaults_detail_on_privacy_off(): void {
		$this->assertTrue( Disclosure::is_detail_enabled( array() ) );
		$this->assertFalse( Disclosure::is_privacy_enabled( array() ) );
		$this->assertFalse( Disclosure::is_detail_enabled( array( Disclosure::POLICY_DETAIL_KEY => false ) ) );
		$this->assertTrue( Disclosure::is_privacy_enabled( array( Disclosure::POLICY_PRIVACY_KEY => true ) ) );
	}

	/**
	 * @return array<string,mixed>
	 */
	private function activeLog(): array {
		return array(
			array(
				'ts'                 => 1_700_000_000,
				'decision'           => 'allow',
				'plugin'             => 'acme/acme.php',
				'provider'           => 'openai',
				'capability_family'  => 'text',
			),
			array(
				'ts'                => 1_700_000_100,
				'decision'          => 'allow',
				'plugin'            => 'vision/vision.php',
				'provider'          => 'anthropic',
				'capability_family' => 'image',
			),
		);
	}

	public function test_active_policy_lists_providers_and_families(): void {
		$snap = Disclosure::build_snapshot( array(), $this->activeLog(), false, true );
		$this->assertSame( 'gated', $snap['mode'] );
		$this->assertFalse( $snap['paused'] );
		$this->assertFalse( $snap['empty'] );
		$this->assertSame( Disclosure::MODE_GATED, $snap['mode_text'] );
		$this->assertStringContainsString( 'OpenAI', $snap['providers_text'] );
		$this->assertStringContainsString( 'Anthropic', $snap['providers_text'] );
		$this->assertStringContainsString( 'Text', $snap['families_text'] );
		$this->assertStringContainsString( 'Image', $snap['families_text'] );

		$html = Disclosure::render_html( $snap );
		$this->assertStringContainsString( Disclosure::HEADING, $html );
		$this->assertStringContainsString( 'OpenAI: Text', $html );
		$this->assertStringContainsString( 'Anthropic: Image', $html );
		$this->assertStringNotContainsString( 'acme/acme.php', $html );
		$this->assertStringNotContainsString( 'vision/vision.php', $html );
	}

	public function test_observe_mode_copy(): void {
		$snap = Disclosure::build_snapshot( array( 'audit_only' => true ), $this->activeLog(), false, true );
		$this->assertSame( 'observe', $snap['mode'] );
		$this->assertSame( Disclosure::MODE_OBSERVE, $snap['mode_text'] );
		$html = Disclosure::render_html( $snap );
		$this->assertStringContainsString( $this->esc( Disclosure::MODE_OBSERVE ), $html );
		$this->assertStringNotContainsString( $this->esc( Disclosure::PAUSED ), $html );
	}

	public function test_freeze_paused_copy(): void {
		$snap = Disclosure::build_snapshot( array(), $this->activeLog(), true, true );
		$this->assertSame( 'paused', $snap['mode'] );
		$this->assertTrue( $snap['paused'] );
		$this->assertSame( '', $snap['mode_text'] );
		$html = Disclosure::render_html( $snap );
		$this->assertStringContainsString( $this->esc( Disclosure::PAUSED ), $html );
		$this->assertStringContainsString( 'OpenAI', $html );
		$this->assertStringNotContainsString( $this->esc( Disclosure::MODE_GATED ), $html );
	}

	public function test_kill_switch_paused_copy(): void {
		$snap = Disclosure::build_snapshot( array( 'kill_switch' => true, 'audit_only' => true ), $this->activeLog(), false, true );
		$this->assertSame( 'paused', $snap['mode'] );
		$this->assertTrue( $snap['paused'] );
		$this->assertSame( '', $snap['mode_text'] );
		$html = Disclosure::render_html( $snap );
		$this->assertStringContainsString( $this->esc( Disclosure::PAUSED ), $html );
		$this->assertStringNotContainsString( $this->esc( Disclosure::MODE_OBSERVE ), $html );
		$this->assertStringNotContainsString( $this->esc( Disclosure::MODE_GATED ), $html );
	}

	public function test_watch_plus_freeze_shows_only_paused(): void {
		$snap = Disclosure::build_snapshot( array( 'audit_only' => true ), $this->activeLog(), true, true );
		$this->assertTrue( $snap['paused'] );
		$this->assertSame( '', $snap['mode_text'] );
		$html = Disclosure::render_html( $snap );
		$this->assertStringContainsString( $this->esc( Disclosure::PAUSED ), $html );
		$this->assertStringNotContainsString( $this->esc( Disclosure::MODE_OBSERVE ), $html );
		$this->assertStringNotContainsString( 'without blocking', $html );
	}

	public function test_empty_state_when_no_activity(): void {
		$snap = Disclosure::build_snapshot( array(), array(), false, true );
		$this->assertTrue( $snap['empty'] );
		$this->assertSame( '', $snap['providers_text'] );
		$html = Disclosure::render_html( $snap );
		$this->assertStringContainsString( Disclosure::EMPTY, $html );
		$this->assertStringNotContainsString( Disclosure::PROVIDERS_PREFIX, $html );
		$this->assertStringNotContainsString( '<ul', $html );
	}

	public function test_detail_off_omits_per_provider_list(): void {
		$snap = Disclosure::build_snapshot( array(), $this->activeLog(), false, false );
		$this->assertFalse( $snap['detail'] );
		$html = Disclosure::render_html( $snap );
		$this->assertStringContainsString( Disclosure::PROVIDERS_PREFIX, $html );
		$this->assertStringContainsString( 'OpenAI', $html );
		$this->assertStringNotContainsString( '<ul', $html );
		$this->assertStringNotContainsString( 'OpenAI: Text', $html );
	}

	public function test_never_renders_pii_keys_paths_or_option_names(): void {
		$log = array(
			array(
				'ts'                => 1,
				'provider'          => 'openai',
				'capability_family' => 'text',
				'plugin'            => 'secret/secret.php',
				'user_email'        => 'ada@example.com',
				'api_key'           => 'sk-live-abcdef',
			),
			array(
				'ts'       => 2,
				'provider' => 'sk-live-abcdef',
				'plugin'   => 'handl_aicac_policy',
			),
			array(
				'ts'       => 3,
				'provider' => 'evil/plugin.php',
			),
			array(
				'ts'       => 4,
				'provider' => 'user@host.com',
			),
		);
		$html = Disclosure::render_html( Disclosure::build_snapshot( array(), $log, false, true ) );
		$this->assertStringContainsString( 'OpenAI', $html );
		$this->assertStringNotContainsString( 'secret/secret.php', $html );
		$this->assertStringNotContainsString( 'ada@example.com', $html );
		$this->assertStringNotContainsString( 'sk-live', $html );
		$this->assertStringNotContainsString( 'handl_aicac_policy', $html );
		$this->assertStringNotContainsString( 'evil/plugin.php', $html );
		$this->assertStringNotContainsString( 'user@host.com', $html );
	}

	public function test_skips_synthetic_and_share_channels(): void {
		$log = array(
			array(
				'ts'                => 1,
				'provider'          => 'openai',
				'capability_family' => 'text',
				'channel'           => 'share',
			),
			array(
				'ts'                => 2,
				'provider'          => 'anthropic',
				'capability_family' => 'image',
				'selftest'          => true,
			),
			array(
				'ts'                => 3,
				'provider'          => 'google',
				'capability_family' => 'text',
				'channel'           => 'selftest',
			),
		);
		$snap = Disclosure::build_snapshot( array(), $log, false, true );
		$this->assertTrue( $snap['empty'] );
	}

	public function test_forced_provider_and_operation_family(): void {
		$log = array(
			array(
				'ts'              => 1,
				'forced_provider' => 'mistral',
				'operation'       => 'generate_text',
			),
		);
		$snap = Disclosure::build_snapshot( array(), $log, false, true );
		$this->assertFalse( $snap['empty'] );
		$this->assertStringContainsString( 'Mistral', $snap['providers_text'] );
		$this->assertStringContainsString( 'Text', $snap['families_text'] );
	}

	public function test_shortcode_detail_off_attr(): void {
		$this->assertFalse( Disclosure::parse_detail_attr( 'off' ) );
		$this->assertFalse( Disclosure::parse_detail_attr( '0' ) );
		$this->assertFalse( Disclosure::parse_detail_attr( 'false' ) );
		$this->assertTrue( Disclosure::parse_detail_attr( 'on' ) );
		$html = Disclosure::render( Disclosure::parse_detail_attr( 'off' ), array(), $this->activeLog(), false );
		$this->assertStringContainsString( 'OpenAI', $html );
		$this->assertStringNotContainsString( '<ul', $html );
	}

	public function test_block_detail_false(): void {
		$html = Disclosure::render( false, array(), $this->activeLog(), false );
		$this->assertStringNotContainsString( 'OpenAI: Text', $html );
		$html_on = Disclosure::render( true, array(), $this->activeLog(), false );
		$this->assertStringContainsString( 'OpenAI: Text', $html_on );
	}

	public function test_privacy_append_only_on_privacy_page_when_enabled(): void {
		$disc = Disclosure::instance();
		update_option( Plugin::OPTION_KEY, array( Disclosure::POLICY_PRIVACY_KEY => true ) );
		$GLOBALS['handl_aicac_test_is_privacy_policy'] = false;
		$this->assertSame( 'body', $disc->append_privacy( 'body' ) );

		$GLOBALS['handl_aicac_test_is_privacy_policy'] = true;
		$out = $disc->append_privacy( 'body' );
		$this->assertStringStartsWith( 'body', $out );
		$this->assertStringContainsString( 'handl-aicac-disclosure', $out );

		$again = $disc->append_privacy( $out );
		$this->assertSame( $out, $again );
	}

	public function test_privacy_append_skips_when_disabled(): void {
		update_option( Plugin::OPTION_KEY, array( Disclosure::POLICY_PRIVACY_KEY => false ) );
		$GLOBALS['handl_aicac_test_is_privacy_policy'] = true;
		$this->assertSame( 'body', Disclosure::instance()->append_privacy( 'body' ) );
	}

	public function test_merge_policy_save_from_post(): void {
		$_POST = array(
			Disclosure::POST_PRESENT => '1',
			Disclosure::POST_PRIVACY => '1',
		);
		$out = Disclosure::merge_on_policy_save( array( 'default' => 'allow' ), array() );
		$this->assertTrue( $out[ Disclosure::POLICY_PRIVACY_KEY ] );
		$this->assertFalse( $out[ Disclosure::POLICY_DETAIL_KEY ] );
	}

	public function test_merge_policy_save_preserves_old_when_not_posted(): void {
		$_POST = array();
		$out   = Disclosure::merge_on_policy_save(
			array( 'default' => 'deny' ),
			array(
				Disclosure::POLICY_PRIVACY_KEY => true,
				Disclosure::POLICY_DETAIL_KEY  => false,
			)
		);
		$this->assertTrue( $out[ Disclosure::POLICY_PRIVACY_KEY ] );
		$this->assertFalse( $out[ Disclosure::POLICY_DETAIL_KEY ] );
	}

	public function test_settings_render_uses_copy_constants(): void {
		ob_start();
		Disclosure::instance()->render_settings( array() );
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( Disclosure::SETTINGS_TITLE, $html );
		$this->assertStringContainsString( Disclosure::SETTINGS_PRIVACY, $html );
		$this->assertStringContainsString( Disclosure::SETTINGS_DETAIL, $html );
		$this->assertStringContainsString( Disclosure::SETTINGS_HELP, $html );
		$this->assertStringContainsString( Disclosure::POST_PRESENT, $html );
	}

	private function esc( string $text ): string {
		return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
	}

	public function test_plugin_php_requires_and_inits_disclosure(): void {
		$src   = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$admin = strpos( $src, "require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php'" );
		$disc  = strpos( $src, "require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-disclosure.php'" );
		$this->assertNotFalse( $admin );
		$this->assertNotFalse( $disc );
		$this->assertGreaterThan( $admin, $disc );
		$this->assertNotFalse( strpos( $src, 'Disclosure::instance()->init()' ) );
	}
}
