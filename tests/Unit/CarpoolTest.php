<?php
/**
 * AICAC-CARPOOL (#486).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Carpool;
use HandL\AICAC\Cost;
use HandL\AICAC\Dejavu;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class CarpoolTest extends TestCase {

	private const NOW = 1791800000;

	private const PLUGIN_A = 'echo/plugin.php';

	private const PLUGIN_B = 'other/plugin.php';

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_transients']       = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Carpool::reset_for_tests();
		Carpool::set_test_now( self::NOW );
		if ( class_exists( Dejavu::class, false ) ) {
			Dejavu::reset_for_tests();
		}
	}

	protected function tearDown(): void {
		Carpool::reset_for_tests();
		$GLOBALS['handl_aicac_test_options']    = array();
		$GLOBALS['handl_aicac_test_transients'] = array();
		parent::tearDown();
	}

	/**
	 * @return array<string,mixed>
	 */
	private function allow_event(
		string $plugin,
		string $prompt,
		string $model = 'gpt-4o-mini',
		string $provider = 'openai',
		string $op = 'generate_text'
	): array {
		$hash = hash( 'sha256', $prompt );

		return array(
			'ts'             => self::NOW,
			'decision'       => 'allow',
			'plugin'         => $plugin,
			'operation'      => $op,
			'provider'       => $provider,
			'model'          => $model,
			'prompt_preview' => $prompt,
			'prompt_hash'    => $hash,
			'log_key'        => 'aicac_test_' . substr( $hash, 0, 8 ),
		);
	}

	/**
	 * @return array{headers:array<string,string>,body:string,response:array{code:int,message:string},cookies:array,filename:null}
	 */
	private function http_ok( string $body = '{"ok":true}' ): array {
		return array(
			'headers'  => array( 'content-type' => 'application/json; charset=utf-8' ),
			'body'     => $body,
			'response' => array(
				'code'    => 200,
				'message' => 'OK',
			),
			'cookies'  => array(),
			'filename' => null,
		);
	}

	private function enable( string $plugin, int $ttl = 300 ): void {
		Carpool::save_settings(
			array(
				'connectors' => array( $plugin => true ),
				'ttl'        => $ttl,
			)
		);
	}

	public function test_off_by_default_and_per_connector(): void {
		$this->assertFalse( Carpool::is_enabled_for( self::PLUGIN_A ) );
		$this->enable( self::PLUGIN_A );
		$this->assertTrue( Carpool::is_enabled_for( self::PLUGIN_A ) );
		$this->assertFalse( Carpool::is_enabled_for( self::PLUGIN_B ) );
	}

	public function test_ask_key_includes_prompt_hash_via_dejavu(): void {
		$a = $this->allow_event( self::PLUGIN_A, 'hello world' );
		$b = $this->allow_event( self::PLUGIN_A, 'different' );
		$key_a = Carpool::ask_key( $a );
		$key_b = Carpool::ask_key( $b );
		$this->assertNotSame( $key_a, $key_b );
		$this->assertStringContainsString( $a['prompt_hash'], $key_a );
		$this->assertSame( $key_a, Dejavu::fingerprint( $a ) );
	}

	public function test_identical_ask_within_ttl_stubs_transport_and_tags_outcome(): void {
		$this->enable( self::PLUGIN_A, 300 );
		$event = $this->allow_event( self::PLUGIN_A, 'same ask' );
		$body  = '{"id":"cached-1","choices":[{"message":{"content":"hi"}}]}';

		// Miss → arm store, capture response.
		Carpool::maybe_arm_from_allow( false, $event, array( 'prompt_preview' => 'same ask' ), self::PLUGIN_A, 'generate_text' );
		$this->assertTrue( Carpool::is_armed() );
		$this->assertSame( 'store', Carpool::armed_state()['mode'] ?? '' );
		Carpool::instance()->maybe_capture( $this->http_ok( $body ), array(), 'https://api.openai.com/v1/chat/completions' );
		$this->assertFalse( Carpool::is_armed() );
		Carpool::attach_tokens_for_log_key( (string) $event['log_key'], 100, 20 );

		// Hit → stub; transport not invoked (pre_http_request returns body).
		$hit = $this->allow_event( self::PLUGIN_A, 'same ask' );
		$hit['log_key'] = 'aicac_test_hit2';
		Carpool::maybe_arm_from_allow( false, $hit, array( 'prompt_preview' => 'same ask' ), self::PLUGIN_A, 'generate_text' );
		$this->assertSame( Carpool::OUTCOME, $hit['outcome'] ?? '' );
		$this->assertSame( $event['log_key'], $hit['carpool_source'] ?? '' );
		$this->assertTrue( Carpool::is_armed() );

		$stub = Carpool::instance()->maybe_stub( false, array(), 'https://api.openai.com/v1/chat/completions' );
		$this->assertIsArray( $stub );
		$this->assertSame( $body, $stub['body'] ?? null );
		$this->assertFalse( Carpool::is_armed(), 'arm clears after one stub — transport never called' );

		$settings = Carpool::get_settings();
		$this->assertSame( 1, $settings['hits'] );
		$this->assertSame( 100, $settings['saved_input_tokens'] );
		$this->assertSame( 20, $settings['saved_output_tokens'] );
		$usd = Carpool::estimated_saved_usd( $settings );
		$this->assertNotNull( $usd );
		$this->assertGreaterThan( 0.0, (float) $usd );
		// Cost::estimate_usd is the only rate path (no hardcoded USD).
		$this->assertSame(
			Cost::estimate_usd( 100, 20 ),
			$usd
		);
	}

	public function test_different_prompt_model_or_connector_is_miss(): void {
		Carpool::save_settings(
			array(
				'connectors' => array(
					self::PLUGIN_A => true,
					self::PLUGIN_B => true,
				),
				'ttl'        => 300,
			)
		);
		$base = $this->allow_event( self::PLUGIN_A, 'ask' );
		Carpool::maybe_arm_from_allow( false, $base, array( 'prompt_preview' => 'ask' ), self::PLUGIN_A, 'generate_text' );
		Carpool::instance()->maybe_capture( $this->http_ok( '{"a":1}' ), array(), 'https://api.openai.com/v1/x' );
		Carpool::disarm();

		$diff_prompt = $this->allow_event( self::PLUGIN_A, 'other ask' );
		Carpool::maybe_arm_from_allow( false, $diff_prompt, array( 'prompt_preview' => 'other ask' ), self::PLUGIN_A, 'generate_text' );
		$this->assertSame( 'store', Carpool::armed_state()['mode'] ?? '' );
		$this->assertArrayNotHasKey( 'outcome', $diff_prompt );
		Carpool::disarm();

		$diff_model = $this->allow_event( self::PLUGIN_A, 'ask', 'gpt-4o' );
		Carpool::maybe_arm_from_allow( false, $diff_model, array( 'prompt_preview' => 'ask' ), self::PLUGIN_A, 'generate_text' );
		$this->assertSame( 'store', Carpool::armed_state()['mode'] ?? '' );
		Carpool::disarm();

		$diff_plugin = $this->allow_event( self::PLUGIN_B, 'ask' );
		Carpool::maybe_arm_from_allow( false, $diff_plugin, array( 'prompt_preview' => 'ask' ), self::PLUGIN_B, 'generate_text' );
		$this->assertSame( 'store', Carpool::armed_state()['mode'] ?? '' );
		Carpool::disarm();
	}

	public function test_ttl_expiry_forces_real_call(): void {
		$this->enable( self::PLUGIN_A, 300 );
		$event = $this->allow_event( self::PLUGIN_A, 'ttl ask' );
		Carpool::maybe_arm_from_allow( false, $event, array( 'prompt_preview' => 'ttl ask' ), self::PLUGIN_A, 'generate_text' );
		Carpool::instance()->maybe_capture( $this->http_ok( '{"ttl":1}' ), array(), 'https://api.openai.com/v1/x' );

		Carpool::set_test_now( self::NOW + 301 );
		$again = $this->allow_event( self::PLUGIN_A, 'ttl ask' );
		Carpool::maybe_arm_from_allow( false, $again, array( 'prompt_preview' => 'ttl ask' ), self::PLUGIN_A, 'generate_text' );
		$this->assertSame( 'store', Carpool::armed_state()['mode'] ?? '', 'expired entry must miss' );
		$this->assertArrayNotHasKey( 'outcome', $again );
		Carpool::disarm();
	}

	public function test_policy_change_flushes_store(): void {
		$this->enable( self::PLUGIN_A );
		$event = $this->allow_event( self::PLUGIN_A, 'flush me' );
		Carpool::maybe_arm_from_allow( false, $event, array( 'prompt_preview' => 'flush me' ), self::PLUGIN_A, 'generate_text' );
		Carpool::instance()->maybe_capture( $this->http_ok( '{"f":1}' ), array(), 'https://api.openai.com/v1/x' );
		$this->assertNotEmpty( Carpool::get_store() );

		$policy_key = class_exists( Plugin::class, false ) ? Plugin::OPTION_KEY : 'handl_aicac_policy';
		Carpool::on_updated_option( $policy_key, array(), array( 'default' => 'allow' ) );
		$this->assertSame( array(), Carpool::get_store() );
	}

	public function test_deny_and_disabled_connector_never_arm(): void {
		$this->enable( self::PLUGIN_A );
		$event = $this->allow_event( self::PLUGIN_A, 'nope' );
		Carpool::maybe_arm_from_allow( true, $event, array( 'prompt_preview' => 'nope' ), self::PLUGIN_A, 'generate_text' );
		$this->assertFalse( Carpool::is_armed() );

		Carpool::save_settings( array( 'connectors' => array() ) );
		$event2 = $this->allow_event( self::PLUGIN_A, 'nope' );
		Carpool::maybe_arm_from_allow( false, $event2, array( 'prompt_preview' => 'nope' ), self::PLUGIN_A, 'generate_text' );
		$this->assertFalse( Carpool::is_armed() );
	}

	public function test_plugin_and_bootstrap_require_carpool(): void {
		$plugin = file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$boot   = file_get_contents( HANDL_AICAC_DIR . '/tests/bootstrap.php' );
		$this->assertIsString( $plugin );
		$this->assertIsString( $boot );
		$this->assertStringContainsString( 'class-handl-aicac-carpool.php', (string) $plugin );
		$this->assertStringContainsString( 'Carpool::instance()->init()', (string) $plugin );
		$this->assertStringContainsString( 'class-handl-aicac-carpool.php', (string) $boot );
		$policy = file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy.php' );
		$this->assertStringContainsString( 'Carpool::maybe_arm_from_allow', (string) $policy );
		$dejavu = file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-dejavu.php' );
		$this->assertStringContainsString( 'Carpool::render_dejavu_panel', (string) $dejavu );
	}

	public function test_readme_free(): void {
		$readme = HANDL_AICAC_DIR . '/readme.txt';
		if ( ! is_readable( $readme ) ) {
			$this->assertTrue( true );
			return;
		}
		$before = 'placeholder';
		// No assertion on content — fence is no readme.txt changes in this PR.
		$this->assertFileExists( $readme );
		unset( $before );
	}
}
