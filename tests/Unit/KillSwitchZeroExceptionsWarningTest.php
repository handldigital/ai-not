<?php
/**
 * S-104: advisory warning when kill switch is on with zero exceptions.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Admin;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;

/**
 * Covers server-rendered warning state and the progressive-enhancement JS contract.
 */
final class KillSwitchZeroExceptionsWarningTest extends TestCase {

	/** @var ReflectionMethod */
	private static $render;

	/** @var Admin */
	private static $admin;

	public static function setUpBeforeClass(): void {
		require_once __DIR__ . '/../stubs/wp-admin-escape.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php';

		$ref          = new ReflectionClass( Admin::class );
		self::$admin  = $ref->newInstanceWithoutConstructor();
		self::$render = $ref->getMethod( 'render_kill_switch_settings_rows' );
		self::$render->setAccessible( true );
	}

	/**
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private function render_html( array $policy, array $plugins = array() ): string {
		if ( array() === $plugins ) {
			$plugins = array(
				'alpha/plugin.php' => array( 'Name' => 'Alpha' ),
				'beta/plugin.php'  => array( 'Name' => 'Beta' ),
			);
		}

		ob_start();
		self::$render->invoke( self::$admin, $policy, 'handl-aicac-rules-form', $plugins );
		$html = ob_get_clean();
		$this->assertIsString( $html );
		return $html;
	}

	/**
	 * AC: kill on + zero exceptions → distinct inline warning visible on load.
	 */
	public function test_kill_on_zero_exceptions_shows_warning(): void {
		$html = $this->render_html(
			array(
				'kill_switch'            => true,
				'kill_switch_exceptions' => array(),
			)
		);

		$this->assertStringContainsString( 'handl-aicac-kill-exceptions-zero-warn', $html );
		$this->assertStringContainsString(
			'ALL AI Client calls from every installed plugin will be blocked',
			$html
		);
		$this->assertDoesNotMatchRegularExpression(
			'/<p[^>]*id="handl-aicac-kill-exceptions-zero-warn"[^>]*\bhidden\b/',
			$html
		);
		$this->assertMatchesRegularExpression(
			'/aria-describedby="handl-aicac-kill-exceptions-zero-warn"/',
			$html
		);
		$this->assertMatchesRegularExpression(
			'/id="handl-aicac-kill-exceptions-zero-warn"[^>]*aria-live="polite"/',
			$html
		);
		$this->assertMatchesRegularExpression(
			'/<p[^>]*id="handl-aicac-kill-exceptions-state"[^>]*\bhidden\b/',
			$html
		);
	}

	/**
	 * AC / edge: pre-selected exceptions from prior save → no warning.
	 */
	public function test_kill_on_with_exception_hides_warning(): void {
		$html = $this->render_html(
			array(
				'kill_switch'            => true,
				'kill_switch_exceptions' => array( 'alpha/plugin.php' ),
			)
		);

		$this->assertMatchesRegularExpression(
			'/<p[^>]*id="handl-aicac-kill-exceptions-zero-warn"[^>]*\bhidden\b/',
			$html
		);
		$this->assertStringNotContainsString(
			'aria-describedby="handl-aicac-kill-exceptions-zero-warn"',
			$html
		);
		$this->assertStringContainsString( 'checked="checked"', $html );
	}

	/**
	 * AC: kill off → no zero-exceptions warning; existing Emergency-stop state messaging unchanged.
	 */
	public function test_kill_off_keeps_not_in_effect_and_hides_warning(): void {
		$html = $this->render_html(
			array(
				'kill_switch'            => false,
				'kill_switch_exceptions' => array(),
			)
		);

		$this->assertMatchesRegularExpression(
			'/<p[^>]*id="handl-aicac-kill-exceptions-zero-warn"[^>]*\bhidden\b/',
			$html
		);
		$this->assertDoesNotMatchRegularExpression(
			'/<p[^>]*id="handl-aicac-kill-exceptions-state"[^>]*\bhidden\b/',
			$html
		);
		$this->assertStringContainsString( 'Exceptions apply only while the Emergency stop is on.', $html );
		$this->assertMatchesRegularExpression(
			'/aria-describedby="handl-aicac-kill-exceptions-state"/',
			$html
		);
	}

	/**
	 * AC: live JS toggles warning on kill + exception checkbox changes (no reload).
	 */
	public function test_inline_js_updates_zero_warn_without_reload(): void {
		$html = $this->render_html(
			array(
				'kill_switch'            => false,
				'kill_switch_exceptions' => array(),
			)
		);

		$this->assertStringContainsString( 'handl-aicac-kill-exceptions-zero-warn', $html );
		$this->assertStringContainsString( 'aria-live="polite"', $html );
		$this->assertStringContainsString( 'anyEx()', $html );
		$this->assertStringContainsString( 'z.hidden=!zero', $html );
		$this->assertStringContainsString( 'handl_aicac_kill_exceptions[]', $html );
		$this->assertStringContainsString( 'addEventListener("change",s)', $html );
		$this->assertStringContainsString(
			'g.setAttribute("aria-describedby","handl-aicac-kill-exceptions-zero-warn")',
			$html
		);
		$this->assertStringContainsString(
			'g.setAttribute("aria-describedby","handl-aicac-kill-exceptions-state")',
			$html
		);
	}

	/**
	 * Guardrail: warning is advisory UI only — save path unchanged (no confirm/block).
	 */
	public function test_warning_does_not_alter_save_path(): void {
		$src = file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertNotFalse( $src );

		$fn_pos = strpos( $src, 'function apply_kill_switch_settings_from_post' );
		$this->assertNotFalse( $fn_pos );
		$next = strpos( $src, "\tprivate function ", $fn_pos + 1 );
		$body = false === $next ? substr( $src, $fn_pos ) : substr( $src, $fn_pos, $next - $fn_pos );

		$this->assertStringNotContainsString( 'zero-warn', $body );
		$this->assertStringNotContainsString( 'confirm(', $body );
		$this->assertStringContainsString( 'handl_aicac_kill_switch', $body );
		$this->assertStringContainsString( 'handl_aicac_kill_exceptions', $body );
	}
}
