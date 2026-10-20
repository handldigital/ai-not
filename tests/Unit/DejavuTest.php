<?php
/**
 * AICAC-DEJA-VU (#453).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Dejavu;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class DejavuTest extends TestCase {

	private const NOW = 1791800000;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_transients']       = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Dejavu::reset_for_tests();
		Dejavu::set_test_now( self::NOW );
		Dejavu::set_skip_cache( true );
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options']    = array();
		$GLOBALS['handl_aicac_test_transients'] = array();
		Dejavu::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * @return array<string,mixed>
	 */
	private function allow_row( string $plugin, string $op, int $ts, string $provider = 'openai', string $model = 'gpt-4' ): array {
		return array(
			'ts'        => $ts,
			'decision'  => 'allow',
			'plugin'    => $plugin,
			'operation' => $op,
			'provider'  => $provider,
			'model'     => $model,
			'user_id'   => 1,
		);
	}

	public function test_classifier_three_grades(): void {
		// 10 calls / 2 distinct → repeat 80% → ECHO
		$this->assertSame( Dejavu::GRADE_ECHO, Dejavu::classify( 10, 2 ) );
		// 10 / 5 → 50% → RERUN
		$this->assertSame( Dejavu::GRADE_RERUN, Dejavu::classify( 10, 5 ) );
		// 10 / 8 → 20% → VARIED
		$this->assertSame( Dejavu::GRADE_VARIED, Dejavu::classify( 10, 8 ) );
	}

	public function test_grade_connectors_all_three_and_top_fingerprint(): void {
		$now = self::NOW;
		$log = array();

		// echo/plugin: 10 allows, 2 fingerprints → 80% repeat
		for ( $i = 0; $i < 8; $i++ ) {
			$log[] = $this->allow_row( 'echo/plugin.php', 'complete', $now - $i );
		}
		$log[] = $this->allow_row( 'echo/plugin.php', 'embed', $now - 20 );
		$log[] = $this->allow_row( 'echo/plugin.php', 'embed', $now - 21 );

		// rerun/plugin: 10 allows, 5 fingerprints → 50%
		for ( $i = 0; $i < 5; $i++ ) {
			$log[] = $this->allow_row( 'rerun/plugin.php', 'op' . $i, $now - $i );
			$log[] = $this->allow_row( 'rerun/plugin.php', 'op' . $i, $now - 100 - $i );
		}

		// varied/plugin: 5 distinct, 5 calls → 0%
		for ( $i = 0; $i < 5; $i++ ) {
			$log[] = $this->allow_row( 'varied/plugin.php', 'v' . $i, $now - $i );
		}

		// Denies ignored.
		$log[] = array(
			'ts'       => $now - 1,
			'decision' => 'deny',
			'plugin'   => 'echo/plugin.php',
			'operation'=> 'complete',
		);

		Dejavu::set_test_log( $log );
		$rows = Dejavu::grade_connectors( $now );
		$by   = array();
		foreach ( $rows as $row ) {
			$by[ $row['connector'] ] = $row;
		}

		$this->assertSame( Dejavu::GRADE_ECHO, $by['echo/plugin.php']['grade'] );
		$this->assertSame( 10, (int) $by['echo/plugin.php']['calls'] );
		$this->assertSame( 2, (int) $by['echo/plugin.php']['distinct'] );
		$this->assertSame( 8, (int) $by['echo/plugin.php']['top_count'] );
		$this->assertStringContainsString( 'complete', $by['echo/plugin.php']['top_fingerprint'] );

		$this->assertSame( Dejavu::GRADE_RERUN, $by['rerun/plugin.php']['grade'] );
		$this->assertSame( Dejavu::GRADE_VARIED, $by['varied/plugin.php']['grade'] );
	}

	public function test_missing_history_empty_no_policy_writes(): void {
		Dejavu::set_test_log( null );
		$pack = Dejavu::read_activity_log();
		$this->assertFalse( $pack['available'] );
		$this->assertSame( array(), Dejavu::grade_connectors( self::NOW ) );

		$before = get_option( 'handl_aicac_policy', null );
		$snap   = Dejavu::snapshot( self::NOW );
		$this->assertSame( array(), $snap['rows'] );
		$this->assertSame( $before, get_option( 'handl_aicac_policy', null ) );
		$this->assertFalse( (bool) get_option( 'handl_aicac_recent_calls', false ) );
	}

	public function test_render_empty_and_escaped_table(): void {
		Dejavu::set_test_log( array() );
		ob_start();
		Dejavu::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'No repeated allowed calls', $html );
		$this->assertStringContainsString( 'ECHO-CHAMBER', $html );

		$now = self::NOW;
		Dejavu::set_test_log(
			array(
				$this->allow_row( 'evil<script>/x.php', 'complete', $now ),
				$this->allow_row( 'evil<script>/x.php', 'complete', $now - 1 ),
				$this->allow_row( 'evil<script>/x.php', 'complete', $now - 2 ),
				$this->allow_row( 'evil<script>/x.php', 'complete', $now - 3 ),
				$this->allow_row( 'evil<script>/x.php', 'other', $now - 4 ),
			)
		);
		ob_start();
		Dejavu::render_page();
		$html2 = (string) ob_get_clean();
		$this->assertStringNotContainsString( '<script>', $html2 );
		$this->assertStringContainsString( 'evil&lt;script&gt;/x.php', $html2 );
		$this->assertMatchesRegularExpression( '/\d+%/', $html2 );
	}
}
