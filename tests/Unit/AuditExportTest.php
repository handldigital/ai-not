<?php
/**
 * Unit tests for Audit_Export CSV helpers (AICAC-26).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Audit_Export;
use PHPUnit\Framework\TestCase;

final class AuditExportTest extends TestCase {

	/**
	 * @return array{decision:string,operation:string,provider:string,model:string,plugin:string}
	 */
	private function empty_filters(): array {
		return array(
			'decision'  => '',
			'operation' => '',
			'provider'  => '',
			'model'     => '',
			'plugin'    => '',
		);
	}

	public function test_column_headers_match_admin_table_without_actions(): void {
		$headers = Audit_Export::column_headers();

		$this->assertSame(
			array(
				'Time',
				'Decision',
				'Operation / family',
				'Provider',
				'Model',
				'Input tokens',
				'Output tokens',
				'Est. $',
				'Plugin',
				'Prompt',
				'User',
				'URI',
				'Request context',
				'Returned error',
			),
			$headers
		);
		$this->assertNotContains( 'Actions', $headers );
	}

	public function test_filter_respects_observe_decision(): void {
		$log = array(
			array(
				'ts'       => 100,
				'decision' => 'allow',
				'plugin'   => 'a/a.php',
			),
			array(
				'ts'       => 200,
				'decision' => 'observe',
				'channel'  => 'direct_http',
				'plugin'   => 'b/b.php',
				'host'     => 'api.openai.com',
			),
			array(
				'ts'       => 300,
				'decision' => 'deny',
				'plugin'   => 'c/c.php',
			),
		);

		$filters             = $this->empty_filters();
		$filters['decision'] = 'observe';

		$rows = Audit_Export::filtered_rows( $log, $filters );

		$this->assertCount( 1, $rows );
		$this->assertSame( 'observe', $rows[0]['decision'] );
		$this->assertSame( 200, $rows[0]['ts'] );
	}

	public function test_empty_and_null_fields_become_empty_csv_cells(): void {
		$row = array(
			'ts'       => 0,
			'decision' => null,
			// no tokens, no uri, no plugin, no prompt
		);

		$cells = Audit_Export::format_row( $row, array(), array(), array() );

		$this->assertSame( '', $cells[0] ); // Time
		$this->assertSame( '', $cells[1] ); // Decision
		$this->assertSame( '', $cells[5] ); // Input tokens
		$this->assertSame( '', $cells[6] ); // Output tokens
		$this->assertSame( '', $cells[7] ); // Est. $
		$this->assertSame( '', $cells[8] ); // Plugin
		$this->assertSame( '', $cells[9] ); // Prompt
		$this->assertSame( '', $cells[10] ); // User
		$this->assertSame( '', $cells[11] ); // URI
		$this->assertSame( 'unknown', $cells[12] ); // Request context (legacy)
		$this->assertSame( '', $cells[13] ); // Returned error

		$csv = Audit_Export::build_csv( array( $row ), $this->empty_filters(), array(), array() );
		$this->assertStringNotContainsString( 'null', strtolower( $csv ) );
	}

	public function test_csv_escapes_commas_quotes_and_newlines(): void {
		$row = array(
			'ts'             => 1700000000,
			'decision'       => 'allow',
			'operation'      => 'generate_text',
			'provider'       => 'openai',
			'model'          => 'gpt-4o',
			'prompt_preview' => "Hello, \"world\"\nline2",
			'plugin'         => 'acme/plugin.php',
			'uri'            => '/wp-admin/edit.php?post=1,2',
			'user_id'        => 7,
			'input_tokens'   => 10,
			'output_tokens'  => 20,
		);

		$plugins = array(
			'acme/plugin.php' => array( 'Name' => 'Acme, Inc.' ),
		);
		$user_labels = array( 7 => 'Ada "Lovelace"' );

		$csv = Audit_Export::build_csv( array( $row ), $this->empty_filters(), $plugins, array(), $user_labels );

		$this->assertStringContainsString( '"Hello, ""world""' . "\n" . 'line2"', $csv );
		$this->assertStringContainsString( '"Acme, Inc. (acme/plugin.php)"', $csv );
		$this->assertStringContainsString( '"Ada ""Lovelace"""', $csv );
		$this->assertStringContainsString( '"/wp-admin/edit.php?post=1,2"', $csv );
	}

	public function test_build_csv_handles_1000_filtered_rows(): void {
		$log = array();
		for ( $i = 1; $i <= 1000; $i++ ) {
			$log[] = array(
				'ts'       => $i,
				'decision' => ( 0 === $i % 2 ) ? 'observe' : 'allow',
				'plugin'   => 'p/p.php',
				'uri'      => '/path/' . $i,
			);
		}

		$filters             = $this->empty_filters();
		$filters['decision'] = 'observe';

		$start = microtime( true );
		$csv   = Audit_Export::build_csv( $log, $filters, array(), array() );
		$elapsed = microtime( true ) - $start;

		$lines = preg_split( '/\R/', trim( $csv ) ) ?: array();
		$this->assertCount( 501, $lines ); // header + 500 observe rows
		$this->assertLessThan( 2.0, $elapsed, '1000-row filtered export should stay well under typical request limits' );
		$this->assertLessThan( 5 * 1024 * 1024, strlen( $csv ), 'CSV for ≤1000 rows should stay small' );
	}

	public function test_export_does_not_widen_beyond_table_columns(): void {
		$row = array(
			'ts'             => 100,
			'decision'       => 'allow',
			'operation'      => 'generate_text',
			'provider'       => 'openai',
			'model'          => 'gpt-4o',
			'prompt_preview' => 'hi',
			'plugin'         => 'a/a.php',
			'uri'            => '/wp-admin/?secret=token',
			'user_id'        => 1,
			'log_key'        => 'internal-key-must-not-export',
			'armed_tools'    => array( 'core/edit-post' ),
			'denial_reason'  => 'plugin',
			'file'           => '/var/www/wp-content/plugins/a/a.php',
		);

		$csv = Audit_Export::build_csv( array( $row ), $this->empty_filters(), array(), array(), array( 1 => 'Admin' ) );

		$this->assertStringNotContainsString( 'internal-key-must-not-export', $csv );
		$this->assertStringNotContainsString( 'armed_tools', $csv );
		$this->assertStringNotContainsString( 'denial_reason', $csv );
		$this->assertStringNotContainsString( '/var/www/', $csv );
		// URI is an on-screen column — may appear; secret query stays only because it is already in that column.
		$this->assertStringContainsString( '/wp-admin/?secret=token', $csv );
	}

	public function test_filtered_rows_newest_first(): void {
		$log = array(
			array( 'ts' => 1, 'decision' => 'allow' ),
			array( 'ts' => 2, 'decision' => 'allow' ),
			array( 'ts' => 3, 'decision' => 'allow' ),
		);

		$rows = Audit_Export::filtered_rows( $log, $this->empty_filters() );

		$this->assertSame( 3, $rows[0]['ts'] );
		$this->assertSame( 1, $rows[2]['ts'] );
	}
}
