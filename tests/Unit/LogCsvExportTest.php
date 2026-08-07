<?php
/**
 * Unit tests for Log_Csv (AICAC-101 audit log export).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Admin;
use HandL\AICAC\Log_Csv;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

final class LogCsvExportTest extends TestCase {

	public function test_document_starts_with_header_row(): void {
		$csv   = Log_Csv::document( array(), array() );
		$lines = preg_split( '/\r\n/', rtrim( $csv, "\r\n" ) ) ?: array();

		$this->assertNotEmpty( $lines );
		$this->assertSame( implode( ',', Log_Csv::headers() ), $lines[0] );
	}

	public function test_headers_cover_log_table_data_columns(): void {
		$headers = Log_Csv::headers();

		foreach (
			array(
				'Time',
				'Decision',
				'Operation',
				'Family',
				'Host',
				'Count',
				'Provider',
				'Model',
				'Input tokens',
				'Output tokens',
				'Est. $',
				'Plugin',
				'Prompt',
				'User',
				'URI',
			) as $required
		) {
			$this->assertContains( $required, $headers );
		}
	}

	public function test_rfc4180_escapes_comma_quote_and_newline(): void {
		$this->assertSame( 'plain', Log_Csv::escape_field( 'plain' ) );
		$this->assertSame( '"a,b"', Log_Csv::escape_field( 'a,b' ) );
		$this->assertSame( '"say ""hi"""', Log_Csv::escape_field( 'say "hi"' ) );
		$this->assertSame( "\"line1\nline2\"", Log_Csv::escape_field( "line1\nline2" ) );
		$this->assertSame( "\"a\r\nb\"", Log_Csv::escape_field( "a\r\nb" ) );
	}

	public function test_prompt_preview_with_comma_is_quoted_in_document(): void {
		$row = array(
			'ts'             => 1700000000,
			'decision'       => 'allow',
			'operation'      => 'generate_text',
			'provider'       => 'openai',
			'model'          => 'gpt-4o-mini',
			'plugin'         => 'demo/demo.php',
			'prompt_preview' => "Hello, world\n\"quoted\"",
			'input_tokens'   => 10,
			'output_tokens'  => 20,
			'user_id'        => 0,
			'uri'            => '/wp-admin/',
		);

		$csv = Log_Csv::document(
			array( $row ),
			array(),
			array(
				'demo/demo.php' => array( 'Name' => 'Demo Plugin' ),
			)
		);

		$this->assertStringContainsString( '"Hello, world' . "\n" . '""quoted"""', $csv );
		$this->assertStringContainsString( 'Demo Plugin (demo/demo.php)', $csv );
		$this->assertStringContainsString( 'generate_text', $csv );
		$this->assertStringContainsString( 'text', $csv ); // capability family
	}

	public function test_direct_http_collapsed_row_exports_host_uri_and_count(): void {
		$row = array(
			'ts'              => 1700000100,
			'decision'        => 'observe',
			'channel'         => 'direct_http',
			'host'            => 'api.openai.com',
			'uri'             => '/v1/chat/completions',
			'shadow_provider' => 'openai',
			'count'           => 7,
			'plugin'          => 'shadow/plugin.php',
			'file'            => '/var/www/wp-content/plugins/shadow/plugin.php',
			'user_id'         => 3,
		);

		$fields = Log_Csv::format_row(
			$row,
			array(),
			array(
				'shadow/plugin.php' => array( 'Name' => 'Shadow' ),
			),
			array( 3 => 'Alice' )
		);

		$headers = Log_Csv::headers();
		$mapped  = array_combine( $headers, $fields );
		$this->assertIsArray( $mapped );
		$this->assertSame( 'observe', $mapped['Decision'] );
		$this->assertSame( 'api.openai.com', $mapped['Host'] );
		$this->assertSame( '/v1/chat/completions', $mapped['URI'] );
		$this->assertSame( '7', $mapped['Count'] );
		$this->assertSame( 'openai', $mapped['Provider'] );
		$this->assertSame( 'Alice', $mapped['User'] );
		$this->assertSame( '', $mapped['Family'] );
		$this->assertSame( 'plugin.php', $mapped['Plugin file'] );
	}

	public function test_collapsed_row_stays_one_line_not_expanded(): void {
		$row = array(
			'ts'       => 1,
			'decision' => 'observe',
			'channel'  => 'direct_http',
			'host'     => 'api.anthropic.com',
			'count'    => 12,
			'uri'      => '/v1/messages',
		);

		$csv   = Log_Csv::document( array( $row ), array() );
		$lines = preg_split( '/\r\n/', rtrim( $csv, "\r\n" ) ) ?: array();

		$this->assertCount( 2, $lines ); // header + one data row
		$this->assertStringContainsString( ',12,', $lines[1] );
	}

	public function test_active_filters_limit_exported_rows(): void {
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php';

		$admin = Admin::instance();
		$match = new ReflectionMethod( Admin::class, 'log_row_matches_filters' );
		$match->setAccessible( true );

		$allow = array(
			'decision'  => 'allow',
			'operation' => 'generate_text',
			'provider'  => 'openai',
			'model'     => 'gpt-4o',
			'plugin'    => 'a/a.php',
		);
		$deny  = array(
			'decision'  => 'deny',
			'operation' => 'generate_text',
			'provider'  => 'openai',
			'model'     => 'gpt-4o',
			'plugin'    => 'b/b.php',
		);

		$filters = array(
			'decision'  => 'deny',
			'operation' => '',
			'provider'  => '',
			'model'     => '',
			'plugin'    => '',
		);

		$this->assertFalse( $match->invoke( $admin, $allow, $filters ) );
		$this->assertTrue( $match->invoke( $admin, $deny, $filters ) );

		$exported = array();
		foreach ( array( $allow, $deny ) as $row ) {
			if ( $match->invoke( $admin, $row, $filters ) ) {
				$exported[] = $row;
			}
		}

		$csv = Log_Csv::document( $exported, array() );
		$this->assertStringContainsString( 'deny', $csv );
		$this->assertStringNotContainsString( 'a/a.php', $csv );
		$this->assertStringContainsString( 'b/b.php', $csv );
	}

	public function test_handle_export_csv_uses_log_option_and_filters(): void {
		$admin_src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringContainsString( 'Plugin::LOG_OPTION_KEY', $admin_src );
		$this->assertMatchesRegularExpression(
			'/function\s+handle_export_csv[\s\S]*log_row_matches_filters/',
			$admin_src
		);
		$this->assertMatchesRegularExpression(
			'/function\s+handle_export_csv[\s\S]*Log_Csv::document/',
			$admin_src
		);
	}
}
