<?php
/**
 * AICAC-SIEM (#235) unit tests.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Policy_Snapshots;
use HandL\AICAC\Siem;
use PHPUnit\Framework\TestCase;

final class SiemTest extends TestCase {

	/** @var list<string> */
	private array $syslog = array();

	/** @var string */
	private string $tmpdir = '';

	protected function setUp(): void {
		parent::setUp();
		$this->syslog = array();
		$GLOBALS['handl_aicac_syslog'] = function ( string $line ): void {
			$this->syslog[] = $line;
		};

		$this->tmpdir = sys_get_temp_dir() . '/handl-aicac-siem-test-' . bin2hex( random_bytes( 4 ) );
		mkdir( $this->tmpdir, 0755, true );
		$GLOBALS['handl_aicac_siem_dir'] = $this->tmpdir;

		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Siem::FILE_PATH_OPTION );
		delete_option( Policy_Snapshots::OPTION_KEY );
		delete_option( Policy_Snapshots::HISTORY_OPTION_KEY );
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_syslog'], $GLOBALS['handl_aicac_siem_dir'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Siem::FILE_PATH_OPTION );
		$this->rmtree( $this->tmpdir );
		parent::tearDown();
	}

	private function rmtree( string $dir ): void {
		if ( '' === $dir || ! is_dir( $dir ) ) {
			return;
		}
		foreach ( scandir( $dir ) ?: array() as $f ) {
			if ( '.' === $f || '..' === $f ) {
				continue;
			}
			$path = $dir . '/' . $f;
			if ( is_dir( $path ) ) {
				$this->rmtree( $path );
			} else {
				unlink( $path );
			}
		}
		rmdir( $dir );
	}

	public function test_off_by_default(): void {
		$st = Siem::status();
		$this->assertFalse( $st['enabled'] );
		$this->assertFalse( $st['syslog_enabled'] );
		$this->assertFalse( $st['file_enabled'] );
		$this->assertSame( Siem::FORMAT_CEF, $st['format'] );
	}

	public function test_classify_deny_and_shadow_and_tamper(): void {
		$this->assertSame(
			Siem::CLASS_DENY,
			Siem::classify(
				array(
					'decision' => 'deny',
					'plugin'   => 'acme/acme.php',
					'family'   => 'text',
				)
			)
		);
		$this->assertSame(
			Siem::CLASS_SHADOW_DENY,
			Siem::classify(
				array(
					'channel'  => 'direct_http',
					'decision' => 'deny',
					'host'     => 'api.openai.com',
				)
			)
		);
		$this->assertSame(
			Siem::CLASS_TAMPER,
			Siem::classify(
				array(
					'channel'  => 'tamper',
					'decision' => 'enforcement_stopped',
				)
			)
		);
		$this->assertNull(
			Siem::classify(
				array(
					'decision' => 'allow',
					'plugin'   => 'acme/acme.php',
				)
			)
		);
	}

	public function test_redact_strips_email_and_prompt(): void {
		$out = Siem::redact_payload(
			array(
				'plugin'         => 'acme/acme.php',
				'decision'       => 'deny',
				'family'         => 'text',
				'ts'             => 1_700_000_000,
				'alert_email'    => 'ops@example.test',
				'prompt_preview' => 'ssn 123-45-6789',
				'uri'            => '/wp-admin/?token=secret',
			)
		);
		$this->assertSame( 'acme/acme.php', $out['plugin'] );
		$this->assertArrayNotHasKey( 'alert_email', $out );
		$this->assertArrayNotHasKey( 'prompt_preview', $out );
		$this->assertArrayNotHasKey( 'uri', $out );
		$json = wp_json_encode( $out );
		$this->assertIsString( $json );
		$this->assertStringNotContainsString( 'ops@example.test', $json );
		$this->assertStringNotContainsString( '123-45-6789', $json );
	}

	public function test_cef_line_has_vendor_product_and_fields(): void {
		$line = Siem::format_cef(
			Siem::CLASS_DENY,
			array(
				'ts'       => 1_700_000_000,
				'plugin'   => 'acme/acme.php',
				'family'   => 'text',
				'decision' => 'deny',
			)
		);
		$this->assertStringStartsWith( 'CEF:0|HandL|AICAC|', $line );
		$this->assertStringContainsString( 'cs1=acme/acme.php', $line );
		$this->assertStringContainsString( 'cs2=text', $line );
		$this->assertStringContainsString( 'cs3=deny', $line );
		$this->assertStringContainsString( 'rt=1700000000000', $line );
	}

	public function test_observe_off_emits_nothing(): void {
		Siem::observe(
			array(
				'decision' => 'deny',
				'plugin'   => 'acme/acme.php',
				'family'   => 'text',
				'ts'       => 1_700_000_000,
			),
			Policy::get_policy()
		);
		$this->assertSame( array(), $this->syslog );
	}

	public function test_syslog_emit_on_deny_via_append_log_event(): void {
		Siem::apply_settings( array( 'syslog' => true, 'format' => 'cef' ) );
		Policy::save_policy(
			array_merge(
				get_option( Plugin::OPTION_KEY, array() ) ?: array(),
				array( 'log_enabled' => true )
			)
		);

		Policy::append_log_event(
			array(
				'ts'       => 1_700_000_000,
				'decision' => 'deny',
				'plugin'   => 'acme/acme.php',
				'family'   => 'text',
				'alert_email' => 'leak@example.test',
			)
		);

		$this->assertCount( 1, $this->syslog );
		$this->assertStringContainsString( 'CEF:0|HandL|AICAC|', $this->syslog[0] );
		$this->assertStringContainsString( 'cs1=acme/acme.php', $this->syslog[0] );
		$this->assertStringNotContainsString( 'leak@example.test', $this->syslog[0] );
	}

	public function test_siem_emits_even_when_activity_log_off(): void {
		Siem::apply_settings( array( 'syslog' => true ) );
		// log_enabled absent / false.
		Policy::append_log_event(
			array(
				'ts'       => 1_700_000_100,
				'decision' => 'deny',
				'plugin'   => 'other/other.php',
				'family'   => 'image',
			)
		);
		$this->assertCount( 1, $this->syslog );
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertSame( array(), $log );
	}

	public function test_disable_stops_emission(): void {
		Siem::apply_settings( array( 'syslog' => true ) );
		Policy::append_log_event(
			array(
				'ts'       => 1_700_000_200,
				'decision' => 'deny',
				'plugin'   => 'a/a.php',
				'family'   => 'text',
			)
		);
		$this->assertCount( 1, $this->syslog );

		Siem::apply_settings( array( 'syslog' => false ) );
		Policy::append_log_event(
			array(
				'ts'       => 1_700_000_300,
				'decision' => 'deny',
				'plugin'   => 'b/b.php',
				'family'   => 'text',
			)
		);
		$this->assertCount( 1, $this->syslog );
	}

	public function test_file_sink_and_test_round_trip(): void {
		Siem::apply_settings( array( 'file' => true, 'format' => 'json' ) );
		$path = Siem::ensure_file_path();
		$this->assertNotSame( '', $path );
		$this->assertStringContainsString( 'handl-aicac-siem-', $path );

		$result = Siem::emit_test();
		$this->assertTrue( $result['ok'] );
		$this->assertStringContainsString( '"class":"test"', $result['line'] );
		$this->assertStringNotContainsString( 'should-not-leak@example.test', $result['line'] );

		$contents = file_get_contents( $path );
		$this->assertIsString( $contents );
		$this->assertStringContainsString( '"class":"test"', $contents );
		$this->assertStringNotContainsString( 'should-not-leak@example.test', $contents );
	}

	public function test_budget_and_policy_channels_export(): void {
		Siem::apply_settings( array( 'syslog' => true, 'format' => 'cef' ) );
		$this->assertTrue(
			Siem::observe(
				array(
					'channel'  => 'budget',
					'decision' => 'budget_hit',
					'plugin'   => 'acme/acme.php',
					'ts'       => 1_700_000_400,
				),
				Policy::get_policy()
			)
		);
		$this->assertTrue(
			Siem::observe(
				array(
					'channel'  => 'policy_restore',
					'decision' => 'restored',
					'ts'       => 1_700_000_401,
				),
				Policy::get_policy()
			)
		);
		$this->assertCount( 2, $this->syslog );
		$this->assertStringContainsString( 'AICAC:budget', $this->syslog[0] );
		$this->assertStringContainsString( 'AICAC:policy', $this->syslog[1] );
	}
}
