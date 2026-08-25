<?php
/**
 * AICAC-A11Y (#162) Phase-2 markup contracts.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Admin;
use HandL\AICAC\Budget;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class AdminA11yTest extends TestCase {

	public function test_admin_source_covers_phase2_findings(): void {
		$path = HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php';
		$src  = file_get_contents( $path );
		$this->assertNotFalse( $src );

		// A11Y-002: budget bar names the adjacent progress text.
		$this->assertStringContainsString( 'aria-labelledby', $src );
		$this->assertStringContainsString( 'aria-valuetext', $src );
		$this->assertStringContainsString( 'handl-aicac-budget-progress-', $src );

		// A11Y-004: settings selects have label-for + stable ids.
		$this->assertStringContainsString( 'for="handl-aicac-default"', $src );
		$this->assertStringContainsString( 'id="handl-aicac-default"', $src );
		$this->assertStringContainsString( 'for="handl-aicac-unknown-operation"', $src );
		$this->assertStringContainsString( 'id="handl-aicac-unknown-operation"', $src );
		$this->assertStringContainsString( 'for="handl-aicac-model-force-unattributed"', $src );

		// A11Y-005: post-save notices are a focus target.
		$this->assertStringContainsString( 'id="handl-aicac-notices"', $src );
		$this->assertStringContainsString( 'n.focus()', $src );

		// A11Y-006: matrix note preview matches Activity aria-label.
		$this->assertMatchesRegularExpression(
			'/handl-aicac-rule-note-preview[^>]*aria-label=/',
			$src
		);

		// A11Y-007 / A11Y-008.
		$this->assertStringContainsString( '<th scope="col" id="cb"', $src );
		$this->assertStringContainsString( '<th scope="col"><span class="screen-reader-text">\' . esc_html__( \'Actions\'', $src );

		// A11Y-010: star is not title-only.
		$this->assertStringContainsString( 'handl-aicac-insights-rank-badge', $src );
		$this->assertStringContainsString( 'Highest value in this view', $src );
		$this->assertDoesNotMatchRegularExpression(
			'/handl-aicac-insights-rank-badge"[^>]*title=/',
			$src
		);
	}

	public function test_usage_trends_source_no_longer_hides_sparkline(): void {
		$path = HANDL_AICAC_DIR . '/includes/class-handl-aicac-usage-trends.php';
		$src  = file_get_contents( $path );
		$this->assertNotFalse( $src );
		$this->assertStringContainsString( 'role="img"', $src );
		$this->assertStringContainsString( 'aria-label=', $src );
		$this->assertStringNotContainsString( 'aria-hidden="true"', $src );
	}

	public function test_network_pagination_has_accessible_names(): void {
		$path = HANDL_AICAC_DIR . '/includes/class-handl-aicac-network-admin.php';
		$src  = file_get_contents( $path );
		$this->assertNotFalse( $src );
		$this->assertStringContainsString( 'Previous page', $src );
		$this->assertStringContainsString( 'Next page', $src );
		$this->assertStringContainsString( 'screen-reader-text', $src );
	}

	public function test_budget_progressbar_exposes_label(): void {
		require_once __DIR__ . '/../stubs/wp-admin-escape.php';
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php';

		$plugin = 'acme/acme.php';
		$policy = array(
			'plugin_budgets'      => array( $plugin => 10.0 ),
			'plugin_budget_modes' => array( $plugin => Budget::MODE_DENY ),
		);

		$ref    = new ReflectionClass( Admin::class );
		$admin  = $ref->newInstanceWithoutConstructor();
		$render = $ref->getMethod( 'render_plugin_budget_cell' );
		$render->setAccessible( true );

		ob_start();
		$render->invoke(
			$admin,
			$plugin,
			'Acme',
			$policy,
			array( $plugin => '10' ),
			array( $plugin => Budget::MODE_DENY ),
			'handl-aicac-rules-form'
		);
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'role="progressbar"', $html );
		$this->assertStringContainsString( 'aria-labelledby="handl-aicac-budget-progress-', $html );
		$this->assertStringContainsString( 'aria-valuetext=', $html );
		$this->assertStringContainsString( 'Estimated $', $html );
		$this->assertMatchesRegularExpression( '/id="handl-aicac-budget-progress-[a-f0-9]+"/', $html );
	}
}
