<?php
/**
 * AICAC-OPTOUT (#501).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Deny_Receipt;
use HandL\AICAC\Optout;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class OptoutTest extends TestCase {

	private const PLUGIN = 'connector/plugin.php';

	private const NOW = 1791800000;

	private const OPENAI = 'https://api.openai.com/v1/chat/completions';

	private const ANTHROPIC = 'https://api.anthropic.com/v1/messages';

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_filters']          = array();
		$GLOBALS['handl_aicac_test_plugins']          = array(
			self::PLUGIN => array(
				'Name'    => 'Connector',
				'Version' => '1.0.0',
			),
		);
		Optout::reset_for_tests();
		Optout::set_test_now( self::NOW );
		Optout::set_test_plugin( self::PLUGIN );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
			)
		);
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_filters'] = array();
		$GLOBALS['handl_aicac_test_plugins'] = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		Optout::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * @return array<string,mixed>
	 */
	private function args( string $body = '{"model":"gpt-4"}' ): array {
		return array(
			'timeout'     => 5,
			'sslverify'   => true,
			'user-agent'  => 'WordPress',
			'headers'     => array(
				'Content-Type' => 'application/json',
			),
			'body'        => $body,
			'_probe'      => 'keep-me',
		);
	}

	public function test_plugin_bootstrap_wires_optout_after_tripwire(): void {
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-optout.php', $plugin );
		$this->assertStringContainsString( 'Optout::init()', $plugin );
		$this->assertGreaterThan(
			(int) strrpos( $plugin, 'Tripwire::init()' ),
			(int) strrpos( $plugin, 'Optout::init()' )
		);
		$boot = (string) file_get_contents( HANDL_AICAC_DIR . '/tests/bootstrap.php' );
		$this->assertStringContainsString( 'class-handl-aicac-optout.php', $boot );
		$readme = (string) file_get_contents( HANDL_AICAC_DIR . '/readme.txt' );
		$this->assertStringNotContainsString( 'optout', strtolower( $readme ) );
		$admin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringNotContainsString( 'Optout', $admin );
		$policy = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy.php' );
		$this->assertStringNotContainsString( 'Optout', $policy );
		$trip = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-tripwire.php' );
		$this->assertStringNotContainsString( 'Optout', $trip );
	}

	public function test_off_by_default_is_byte_identical(): void {
		$this->assertFalse( Optout::is_enabled() );
		$this->assertSame( Optout::defaults(), Optout::get_settings() );
		$args = $this->args();
		$copy = $args;
		$out  = Optout::apply( $args, self::OPENAI );
		$this->assertSame( $copy, $out );
		$this->assertSame( $copy, $args );
		$this->assertSame( array(), Optout::last_events() );
		$pre = Optout::preempt( false, $out, self::OPENAI );
		$this->assertFalse( $pre );
	}

	public function test_supported_provider_attaches_store_false_and_logs_detail(): void {
		Optout::save_settings( array( 'enabled' => true ) );
		$args = $this->args();
		$out  = Optout::apply( $args, self::OPENAI );
		$this->assertSame( 'keep-me', $out['_probe'] );
		$decoded = json_decode( (string) $out['body'], true );
		$this->assertIsArray( $decoded );
		$this->assertFalse( $decoded['store'] );
		$this->assertSame( 'gpt-4', $decoded['model'] );
		$events = Optout::last_events();
		$this->assertCount( 1, $events );
		$this->assertSame( 'allow', $events[0]['decision'] );
		$this->assertSame( Optout::DETAIL_APPLIED, $events[0]['detail'] );
		$this->assertSame( 'Request flag added', $events[0]['detail'] );
		$this->assertTrue( $events[0]['optout']['applied'] );
		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertSame( Optout::DETAIL_APPLIED, $log[ count( $log ) - 1 ]['detail'] ?? null );
	}

	public function test_unsupported_provider_warns_and_leaves_payload(): void {
		Optout::save_settings( array( 'enabled' => true ) );
		$args = $this->args( '{"model":"claude-3"}' );
		$copy = $args;
		$out  = Optout::apply( $args, self::ANTHROPIC );
		$this->assertSame( $copy, $out );
		$events = Optout::last_events();
		$this->assertCount( 1, $events );
		$this->assertSame( 'warn', $events[0]['decision'] );
		$this->assertSame( 'anthropic', $events[0]['provider'] );
		$this->assertFalse( $events[0]['optout']['applied'] );
		$pre = Optout::preempt( false, $out, self::ANTHROPIC );
		$this->assertFalse( $pre );
	}

	public function test_strict_mode_denies_with_receipt_naming_missing_mechanism(): void {
		Optout::save_settings(
			array(
				'enabled' => true,
				'strict'  => true,
			)
		);
		$args = $this->args( '{"model":"claude-3"}' );
		$copy = $args;
		$out  = Optout::apply( $args, self::ANTHROPIC );
		$this->assertSame( $copy, $out );
		$this->assertNotNull( Optout::pending_deny() );
		$pre = Optout::preempt( false, $out, self::ANTHROPIC );
		$this->assertInstanceOf( \WP_Error::class, $pre );
		$this->assertStringContainsString( 'No configured flag could be added to this request', $pre->get_error_message() );
		$this->assertStringContainsString( 'anthropic', $pre->get_error_message() );
		$events = Optout::last_events();
		$this->assertCount( 1, $events );
		$this->assertSame( 'deny', $events[0]['decision'] );
		$this->assertSame( Optout::REASON, $events[0]['denial_reason'] );
		$this->assertArrayHasKey( Deny_Receipt::ROW_KEY, $events[0] );
		$this->assertStringStartsWith( 'AICAC-', (string) $events[0][ Deny_Receipt::ROW_KEY ] );
		$this->assertNull( Optout::pending_deny() );
	}

	public function test_non_provider_host_is_untouched(): void {
		Optout::save_settings( array( 'enabled' => true ) );
		$args = $this->args();
		$copy = $args;
		$out  = Optout::apply( $args, 'https://wordpress.org/news/' );
		$this->assertSame( $copy, $out );
		$this->assertSame( array(), Optout::last_events() );
	}

	public function test_per_plugin_off_skips_when_global_on(): void {
		Optout::save_settings(
			array(
				'enabled'      => true,
				'plugin_modes' => array( self::PLUGIN => Optout::MODE_OFF ),
			)
		);
		$args = $this->args();
		$copy = $args;
		$out  = Optout::apply( $args, self::OPENAI );
		$this->assertSame( $copy, $out );
		$this->assertSame( array(), Optout::last_events() );
	}

	public function test_per_plugin_on_applies_when_global_off(): void {
		Optout::save_settings(
			array(
				'enabled'      => false,
				'plugin_modes' => array( self::PLUGIN => Optout::MODE_ON ),
			)
		);
		$out     = Optout::apply( $this->args(), self::OPENAI );
		$decoded = json_decode( (string) $out['body'], true );
		$this->assertFalse( $decoded['store'] );
		$this->assertSame( Optout::DETAIL_APPLIED, Optout::last_events()[0]['detail'] );
	}

	public function test_filter_map_can_add_header_mechanism(): void {
		Optout::save_settings( array( 'enabled' => true ) );
		$GLOBALS['handl_aicac_test_filters'][ Optout::FILTER_MAP ] = static function ( array $map ): array {
			$map['providers']['anthropic'] = array(
				'kind'  => Optout::KIND_HEADER,
				'field' => 'X-No-Train',
				'value' => '1',
				'label' => 'X-No-Train',
			);

			return $map;
		};
		$args = $this->args( '{"model":"claude-3"}' );
		$out  = Optout::apply( $args, self::ANTHROPIC );
		$this->assertSame( '1', $out['headers']['X-No-Train'] );
		$this->assertSame( '{"model":"claude-3"}', $out['body'] );
		$this->assertSame( Optout::DETAIL_APPLIED, Optout::last_events()[0]['detail'] );
	}

	public function test_noop_save_leaves_option_absent(): void {
		$this->assertFalse( Optout::save_settings( array() ) );
		$this->assertFalse( get_option( Optout::SETTINGS_OPTION, false ) );
		Optout::save_settings( array( 'enabled' => true ) );
		$this->assertNotFalse( get_option( Optout::SETTINGS_OPTION, false ) );
		$this->assertTrue( Optout::save_settings( array() ) );
		$this->assertFalse( get_option( Optout::SETTINGS_OPTION, false ) );
	}

	public function test_openai_without_json_body_warns(): void {
		Optout::save_settings( array( 'enabled' => true ) );
		$args         = $this->args();
		$args['body'] = 'not-json';
		$copy         = $args;
		$out          = Optout::apply( $args, self::OPENAI );
		$this->assertSame( $copy, $out );
		$this->assertSame( 'warn', Optout::last_events()[0]['decision'] );
	}

	public function test_off_copy_and_flag_table_render(): void {
		ob_start();
		Optout::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'AI request flags', $html );
		$this->assertStringContainsString( 'Request flags are off. This feature does not change outbound requests.', $html );
		$this->assertStringContainsString( 'Add configured privacy flags to recognized AI calls made through WordPress.', $html );
		$this->assertStringContainsString( 'This does not guarantee no training or zero data retention.', $html );
		$this->assertStringContainsString( 'store=false', $html );
		$this->assertStringContainsString( 'No flag configured', $html );
		$this->assertStringContainsString( 'This table lists the flags configured here.', $html );
		$this->assertStringContainsString( 'When a flag cannot be added', $html );
		$this->assertStringContainsString( 'Block recognized AI calls when a configured flag cannot be added.', $html );
	}

	public function test_train_exposure_row_is_read_only_class_exists_guarded(): void {
		$row = Optout::train_exposure_row( 'openai' );
		$this->assertIsArray( $row );
		$this->assertArrayHasKey( 'opt_out', $row );
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-optout.php' );
		$this->assertStringContainsString( 'Train_Exposure::table_row_for', $src );
		$this->assertStringContainsString( 'class_exists( Train_Exposure::class, false )', $src );
		$te = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-train-exposure.php' );
		$this->assertStringNotContainsString( 'Optout', $te );
	}
}
