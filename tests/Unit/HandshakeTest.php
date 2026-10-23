<?php
/**
 * AICAC-HANDSHAKE (#468).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Handshake;
use HandL\AICAC\Plugin;
use HandL\AICAC\Provider_Map;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class HandshakeTest extends TestCase {

	private const PLUGIN = 'connector/plugin.php';
	private const NOW    = 1791800000;
	private const AI_URL = 'https://api.openai.com/v1/chat/completions';

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_filters']          = array();
		$GLOBALS['handl_aicac_test_added_filters']    = array();
		Handshake::reset_for_tests();
		Handshake::set_test_now( self::NOW );
		Handshake::set_test_plugin( self::PLUGIN );
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_filters']       = array();
		$GLOBALS['handl_aicac_test_added_filters'] = array();
		Handshake::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * @return array<string,mixed>
	 */
	private function args( bool $ssl = true, float $timeout = 5.0, int $redir = 5 ): array {
		return array(
			'timeout'      => $timeout,
			'sslverify'    => $ssl,
			'redirection'  => $redir,
			'user-agent'   => 'WordPress',
			'_probe'       => 'keep-me',
		);
	}

	public function test_observe_returns_args_unchanged(): void {
		$args = $this->args();
		$copy = $args;
		$out  = Handshake::observe( $args, self::AI_URL );
		$this->assertSame( $copy, $out );
		$this->assertSame( $copy, $args );
		$this->assertSame( 'keep-me', $out['_probe'] );
	}

	public function test_non_provider_host_is_not_sampled(): void {
		Handshake::observe( $this->args( false, 60.0 ), 'https://wordpress.org/news/' );
		Handshake::observe( $this->args( false, 60.0 ), 'http://example.com/v1' );
		$snap = Handshake::snapshot();
		$this->assertSame( array(), $snap['rows'] );
	}

	public function test_https_sslverify_on_is_secure(): void {
		Handshake::observe( $this->args(), self::AI_URL );
		$snap = Handshake::snapshot();
		$this->assertCount( 1, $snap['rows'] );
		$row = $snap['rows'][0];
		$this->assertSame( Handshake::GRADE_SECURE, $row['grade'] );
		$this->assertSame( 'openai', $row['provider'] );
		$this->assertSame( self::PLUGIN, $row['plugin'] );
		$this->assertSame( 'https', $row['scheme'] );
		$this->assertTrue( $row['sslverify'] );
		$this->assertSame( 'HTTPS, sslverify on', $row['fact'] );
		$this->assertSame( '≤5s', $row['bucket'] );
	}

	public function test_sslverify_off_is_risky_with_fact(): void {
		Handshake::observe( $this->args( false ), self::AI_URL );
		$row = Handshake::snapshot()['rows'][0];
		$this->assertSame( Handshake::GRADE_RISKY, $row['grade'] );
		$this->assertSame( 'sslverify disabled', $row['fact'] );
		$this->assertFalse( $row['sslverify'] );
	}

	public function test_plain_http_is_risky_with_fact(): void {
		Handshake::observe( $this->args(), 'http://api.openai.com/v1/chat' );
		$row = Handshake::snapshot()['rows'][0];
		$this->assertSame( Handshake::GRADE_RISKY, $row['grade'] );
		$this->assertSame( 'plain HTTP', $row['fact'] );
		$this->assertSame( 'http', $row['scheme'] );
	}

	public function test_plain_http_and_sslverify_off_lists_both_facts(): void {
		Handshake::observe( $this->args( false ), 'http://api.openai.com/v1' );
		$row = Handshake::snapshot()['rows'][0];
		$this->assertSame( Handshake::GRADE_RISKY, $row['grade'] );
		$this->assertSame( 'plain HTTP; sslverify disabled', $row['fact'] );
	}

	public function test_timeout_over_30s_is_slowpoke(): void {
		Handshake::observe( $this->args( true, 60.0 ), self::AI_URL );
		$row = Handshake::snapshot()['rows'][0];
		$this->assertSame( Handshake::GRADE_SLOWPOKE, $row['grade'] );
		$this->assertSame( 'timeout 60s', $row['fact'] );
		$this->assertSame( '>30s', $row['bucket'] );
	}

	public function test_risky_outranks_slowpoke(): void {
		Handshake::observe( $this->args( false, 60.0 ), self::AI_URL );
		$row = Handshake::snapshot()['rows'][0];
		$this->assertSame( Handshake::GRADE_RISKY, $row['grade'] );
		$this->assertSame( 'sslverify disabled', $row['fact'] );
	}

	public function test_empty_state_copy(): void {
		ob_start();
		Handshake::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Transport hygiene', $html );
		$this->assertStringContainsString( 'No AI HTTP calls observed yet.', $html );
		$this->assertStringNotContainsString( '<tbody>', $html );
	}

	public function test_render_shows_discriminating_fact(): void {
		Handshake::observe( $this->args( false ), self::AI_URL );
		ob_start();
		Handshake::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'RISKY', $html );
		$this->assertStringContainsString( 'sslverify disabled', $html );
		$this->assertStringContainsString( self::PLUGIN, $html );
		$this->assertStringContainsString( 'OpenAI', $html );
		$this->assertStringContainsString( 'off', $html );
	}

	public function test_match_uses_provider_map_hosts_only(): void {
		$this->assertNotNull( Handshake::match_provider( self::AI_URL ) );
		$this->assertNull( Handshake::match_provider( 'https://status.openai.com/api/v2/status.json' ) );
		$hosts = array();
		foreach ( Provider_Map::endpoint_signatures() as $sig ) {
			foreach ( $sig['hosts'] as $host ) {
				$hosts[] = $host;
			}
		}
		$this->assertContains( 'api.openai.com', $hosts );
	}

	public function test_capped_storage_drops_oldest(): void {
		$GLOBALS['handl_aicac_test_filters']['handl_aicac_handshake_max_rows'] = static function () {
			return 2;
		};
		Handshake::set_test_now( self::NOW );
		Handshake::set_test_plugin( 'one/one.php' );
		Handshake::observe( $this->args(), self::AI_URL );
		Handshake::set_test_now( self::NOW + 10 );
		Handshake::set_test_plugin( 'two/two.php' );
		Handshake::observe( $this->args(), 'https://api.anthropic.com/v1/messages' );
		Handshake::set_test_now( self::NOW + 20 );
		Handshake::set_test_plugin( 'three/three.php' );
		Handshake::observe( $this->args(), 'https://api.groq.com/openai/v1/chat' );
		$plugins = array_column( Handshake::snapshot()['rows'], 'plugin' );
		$this->assertCount( 2, $plugins );
		$this->assertNotContains( 'one/one.php', $plugins );
		$this->assertContains( 'two/two.php', $plugins );
		$this->assertContains( 'three/three.php', $plugins );
	}

	public function test_init_registers_http_request_args_filter(): void {
		Handshake::init();
		$this->assertContains( 'http_request_args', $GLOBALS['handl_aicac_test_added_filters'] );
		$this->assertSame( Handshake::FRAMING, 'report_only_never_mutates_request_args' );
		$this->assertSame( 0, strpos( Handshake::OPTION_KEY, 'handl_aicac_' ) );
	}

	public function test_does_not_write_policy_option(): void {
		update_option( Plugin::OPTION_KEY, array( 'keep' => true ), false );
		$before = get_option( Plugin::OPTION_KEY, null );
		Handshake::observe( $this->args( false, 60.0 ), self::AI_URL );
		ob_start();
		Handshake::render_page();
		ob_end_clean();
		$this->assertSame( $before, get_option( Plugin::OPTION_KEY, null ) );
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-handshake.php' );
		$this->assertStringNotContainsString( 'admin_post_', $src );
		$this->assertStringNotContainsString( 'policy.php', $src );
	}

	public function test_classifier_insufficient_is_empty_snapshot_not_a_row(): void {
		$this->assertSame( Handshake::GRADE_SECURE, Handshake::classify( 'https', true, 5 )['grade'] );
		$this->assertSame( Handshake::GRADE_RISKY, Handshake::classify( 'http', true, 5 )['grade'] );
		$this->assertSame( Handshake::GRADE_SLOWPOKE, Handshake::classify( 'https', true, 30.1 )['grade'] );
		$this->assertSame( array(), Handshake::snapshot()['rows'] );
	}
}
