<?php
/**
 * AICAC-DOM-TEST (#212): parsed DOM, not source text.
 *
 * The pre-#209 fixture is the 298fd4a..pre-#209 regression: a nested
 * <form> closes #handl-aicac-rules-save so Save is orphaned. The
 * post-#209 fixture is the fixed sibling + form= shape.
 *
 * On-demand against a live Rules tab:
 *   php tests/bin/check-rules-form-ownership.php --url URL --cookie …
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

require_once dirname( __DIR__ ) . '/Support/RulesFormOwnership.php';

use HandL\AICAC\Tests\Support\RulesFormOwnership;
use PHPUnit\Framework\TestCase;

final class RulesFormOwnershipDomTest extends TestCase {

	public function test_pre_209_nested_form_orphans_save(): void {
		$html = $this->fixture( 'rules-form-pre-209.html' );
		$rows = RulesFormOwnership::inspect( $html );
		$fail = RulesFormOwnership::format_failure( $rows );

		$this->assertNotSame( '', $fail, 'pre-#209 HTML must fail the DOM check' );
		$this->assertStringContainsString( 'owner=(none)', $fail );
		$this->assertStringContainsString( 'expected=handl-aicac-rules-save', $fail );
		$this->assertStringContainsString( 'value=save', $fail );

		$by_label = array();
		foreach ( $rows as $row ) {
			$by_label[ $row['element'] ] = $row;
		}
		$this->assertTrue( $by_label['input#handl-aicac-action']['ok'] );
		$this->assertTrue( $by_label['input[name=handl_aicac_nonce]']['ok'] );
	}

	public function test_post_209_save_nonce_action_share_rules_form(): void {
		$html = $this->fixture( 'rules-form-post-209.html' );
		$rows = RulesFormOwnership::inspect( $html );

		$this->assertSame(
			'',
			RulesFormOwnership::format_failure( $rows ),
			'post-#209 HTML must pass'
		);
		foreach ( $rows as $row ) {
			$this->assertTrue( $row['ok'], $row['element'] . ' owner=' . $row['owner'] );
			$this->assertSame( RulesFormOwnership::RULES_FORM_ID, $row['owner'] );
		}
	}

	public function test_cli_exits_nonzero_and_names_the_orphaned_save(): void {
		$script = HANDL_AICAC_DIR . '/tests/bin/check-rules-form-ownership.php';
		$pre    = HANDL_AICAC_DIR . '/tests/fixtures/rules-form-pre-209.html';
		$post   = HANDL_AICAC_DIR . '/tests/fixtures/rules-form-post-209.html';

		$pre_out = $this->run_cli( $script, $pre );
		$this->assertSame( 1, $pre_out['code'], $pre_out['stderr'] );
		$this->assertStringContainsString( 'owner=(none)', $pre_out['stderr'] );
		$this->assertStringContainsString( 'expected=handl-aicac-rules-save', $pre_out['stderr'] );

		$post_out = $this->run_cli( $script, $post );
		$this->assertSame( 0, $post_out['code'], $post_out['stderr'] );
		$this->assertStringContainsString( 'OK:', $post_out['stdout'] );
	}

	private function fixture( string $name ): string {
		$path = HANDL_AICAC_DIR . '/tests/fixtures/' . $name;
		$html = file_get_contents( $path );
		$this->assertNotFalse( $html, $path . ' must exist' );
		return (string) $html;
	}

	/**
	 * @return array{code:int,stdout:string,stderr:string}
	 */
	private function run_cli( string $script, string $html_file ): array {
		$cmd = escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $script ) . ' --html-file ' . escapeshellarg( $html_file );
		$spec = array(
			1 => array( 'pipe', 'w' ),
			2 => array( 'pipe', 'w' ),
		);
		$proc = proc_open( $cmd, $spec, $pipes );
		$this->assertIsResource( $proc );
		$stdout = stream_get_contents( $pipes[1] );
		$stderr = stream_get_contents( $pipes[2] );
		fclose( $pipes[1] );
		fclose( $pipes[2] );
		$code = proc_close( $proc );
		return array(
			'code'   => $code,
			'stdout' => (string) $stdout,
			'stderr' => (string) $stderr,
		);
	}
}
