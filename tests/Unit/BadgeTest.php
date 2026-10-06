<?php
/**
 * Unit tests for the public AI-transparency badge (AICAC-BADGE / #317).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Badge;
use HandL\AICAC\Disclosure;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

final class BadgeTest extends TestCase {

	protected function setUp(): void {
		$GLOBALS['handl_aicac_test_options']           = array();
		$GLOBALS['handl_aicac_test_added_actions']     = array();
		$GLOBALS['handl_aicac_test_shortcodes']        = array();
		$GLOBALS['handl_aicac_test_blocks']            = array();
		$GLOBALS['handl_aicac_test_privacy_url']       = 'https://example.test/privacy-policy/';
		$_POST = array();
		Badge::reset_for_tests();
		Disclosure::reset_for_tests();
	}

	protected function tearDown(): void {
		$_POST = array();
		Badge::reset_for_tests();
		Disclosure::reset_for_tests();
		unset(
			$GLOBALS['handl_aicac_test_options'],
			$GLOBALS['handl_aicac_test_added_actions'],
			$GLOBALS['handl_aicac_test_shortcodes'],
			$GLOBALS['handl_aicac_test_blocks'],
			$GLOBALS['handl_aicac_test_privacy_url']
		);
	}

	public function test_off_when_disclosure_is_off(): void {
		$html = Badge::render( array() );
		$this->assertSame( '', $html );
		ob_start();
		Badge::render_settings( array() );
		$settings = (string) ob_get_clean();
		$this->assertSame( '', $settings );
	}

	public function test_inline_svg_a11y_and_no_external_requests(): void {
		$policy = array( Disclosure::POLICY_PRIVACY_KEY => true );
		$html   = Badge::render( $policy );
		$this->assertStringContainsString( 'role="img"', $html );
		$this->assertStringContainsString( '<title', $html );
		$this->assertStringContainsString( Badge::LABEL, $html );
		$this->assertStringContainsString( 'https://example.test/privacy-policy/', $html );
		$this->assertStringNotContainsString( 'AI use disclosed', $html );
		$this->assertStringNotContainsString( '<img', $html );
		$this->assertStringNotContainsString( 'src=', $html );
		$this->assertStringNotContainsString( 'url(', $html );
		$this->assertMatchesRegularExpression( '/xmlns="http:\\/\\/www\\.w3\\.org\\/2000\\/svg"/', $html );
		$html_no_ns = str_replace( 'xmlns="http://www.w3.org/2000/svg"', '', $html );
		$this->assertStringNotContainsString( 'http://', $html_no_ns );
		$this->assertStringNotContainsString( '.php', $html );
		$this->assertStringNotContainsString( 'acme/', $html );
	}

	public function test_json_link_only_when_json_enabled(): void {
		$off = Badge::render( array( Disclosure::POLICY_PRIVACY_KEY => true ) );
		$this->assertStringNotContainsString( '/.well-known/ai.json', $off );
		$on = Badge::render(
			array(
				Disclosure::POLICY_PRIVACY_KEY => true,
				Disclosure::POLICY_JSON_KEY    => true,
			)
		);
		$this->assertStringContainsString( '/.well-known/ai.json', $on );
		$this->assertStringContainsString( Disclosure::FOOTER_JSON, $on );
	}

	public function test_snippet_matches_public_badge(): void {
		$policy = array(
			Disclosure::POLICY_PRIVACY_KEY => true,
			Disclosure::POLICY_JSON_KEY    => true,
		);
		$this->assertSame( Badge::render( $policy ), Badge::embed_snippet( $policy ) );
	}

	public function test_disabling_privacy_removes_badge_from_disclosure_html(): void {
		$log = array(
			array(
				'ts'                 => 1_700_000_000,
				'decision'           => 'allow',
				'plugin'             => 'acme/acme.php',
				'provider'           => 'openai',
				'capability_family'  => 'text',
			),
		);
		$off = Disclosure::render( true, array(), $log, false );
		$this->assertStringNotContainsString( 'handl-aicac-badge', $off );
		$on = Disclosure::render( true, array( Disclosure::POLICY_PRIVACY_KEY => true ), $log, false );
		$this->assertStringContainsString( 'handl-aicac-badge', $on );
		$this->assertStringNotContainsString( 'acme/acme.php', $on );
	}

	public function test_settings_snippet_when_privacy_on(): void {
		$policy = array( Disclosure::POLICY_PRIVACY_KEY => true );
		ob_start();
		Disclosure::instance()->render_settings( $policy );
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'handl-aicac-badge-embed', $html );
		$this->assertStringContainsString( 'Copy this HTML to link to this site', $html );
		$this->assertStringContainsString( 'Remove pasted badges if you turn the disclosure off', $html );
		$this->assertStringContainsString( htmlspecialchars( Badge::embed_snippet( $policy ), ENT_QUOTES, 'UTF-8' ), $html );
	}

	public function test_shortcode_and_block_register(): void {
		Badge::instance()->init();
		Badge::instance()->register_block();
		$this->assertContains( Badge::SHORTCODE, $GLOBALS['handl_aicac_test_shortcodes'] ?? array() );
		$this->assertContains( Badge::BLOCK_NAME, $GLOBALS['handl_aicac_test_blocks'] ?? array() );
		$this->assertSame( '', Badge::instance()->render_shortcode( array() ) );
	}

	public function test_plugin_php_requires_badge(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertNotFalse( strpos( $src, "require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-badge.php'" ) );
		$this->assertNotFalse( strpos( $src, 'Badge::instance()->init()' ) );
	}

	public function test_readme_unreleased_is_last_bullet(): void {
		$readme = (string) file_get_contents( HANDL_AICAC_DIR . '/readme.txt' );
		$unreleased = preg_split( '/\n= 1\./', $readme, 2 )[0] ?? '';
		$this->assertStringContainsString(
			'Public AI disclosure badge with a copyable HTML snippet. Inline SVG, no outside requests. Shortcode and block badges hide when disclosure is off; pasted HTML must be removed manually.',
			$unreleased
		);
		$pos_scan  = strrpos( $unreleased, 'Quick setup includes an optional scan' );
		$pos_badge = strrpos( $unreleased, 'Public AI disclosure badge' );
		$this->assertNotFalse( $pos_scan );
		$this->assertNotFalse( $pos_badge );
		$this->assertGreaterThan( $pos_scan, $pos_badge );
	}

	public function test_missing_privacy_page_links_to_public_disclosure(): void {
		$GLOBALS['handl_aicac_test_privacy_url'] = '';
		$html = Badge::render( array( Disclosure::POLICY_PRIVACY_KEY => true ) );
		$this->assertStringContainsString( 'https://example.test/ai-disclosure/', $html );
		$this->assertStringNotContainsString( 'href="https://example.test/"', $html );
	}

	public function test_public_disclosure_route_serves_heading_when_on(): void {
		$policy = array( Disclosure::POLICY_PRIVACY_KEY => true );
		$off    = Badge::respond( array() );
		$this->assertSame( 404, $off['status'] );
		$this->assertSame( '', $off['body'] );
		$on = Badge::respond( $policy );
		$this->assertSame( 200, $on['status'] );
		$this->assertStringContainsString( Disclosure::HEADING, $on['body'] );
		$this->assertStringContainsString( 'handl-aicac-disclosure', $on['body'] );
	}

	public function test_init_registers_public_route(): void {
		Badge::instance()->init();
		$actions = $GLOBALS['handl_aicac_test_added_actions'] ?? array();
		$this->assertContains( 'template_redirect', $actions );
	}
}
