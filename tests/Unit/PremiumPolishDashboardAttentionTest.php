<?php
/**
 * #248 PREMIUM-POLISH: Needs attention all-clear vs alert delivery failures.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Admin;
use HandL\AICAC\Alert_Health;
use HandL\AICAC\Alerts;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class PremiumPolishDashboardAttentionTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		delete_option( Alert_Health::OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		update_option( 'admin_email', 'admin@example.com' );
	}

	protected function tearDown(): void {
		delete_option( Alert_Health::OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		parent::tearDown();
	}

	public function test_failed_alert_fixture_suppresses_healthy_all_clear(): void {
		$policy = array(
			'alert_on_deny' => true,
			'alert_email'   => 'ops@example.com',
		);
		update_option( Plugin::OPTION_KEY, $policy, false );

		Alert_Health::record_failure( Alert_Health::CHANNEL_EMAIL, 'wp_mail returned false' );
		Alert_Health::record_failure( Alert_Health::CHANNEL_EMAIL, 'wp_mail returned false' );
		Alert_Health::record_failure( Alert_Health::CHANNEL_EMAIL, 'wp_mail returned false' );

		$this->assertSame( 'ops@example.com', Alerts::resolve_email( $policy ) );
		$this->assertGreaterThanOrEqual(
			Alert_Health::FAILURE_THRESHOLD,
			(int) Alert_Health::get_state()[ Alert_Health::CHANNEL_EMAIL ]['consecutive_failures']
		);

		$html = $this->render_alert_delivery_line( $policy );
		$this->assertStringContainsString( 'handl-aicac-alert-delivery-failing', $html );
		$this->assertStringContainsString( 'Alert sending is failing repeatedly', $html );
		$this->assertStringContainsString( 'Alert email', $html );
		$this->assertStringNotContainsString(
			'Nothing needs your attention. AI access controls are operating normally.',
			$html
		);
	}

	public function test_healthy_alert_channel_emits_nothing(): void {
		$policy = array(
			'alert_on_deny' => true,
			'alert_email'   => 'ops@example.com',
		);
		$html = $this->render_alert_delivery_line( $policy );
		$this->assertSame( '', trim( $html ) );
	}

	public function test_rules_anchor_classes_and_sentence_case_advanced_label_css(): void {
		$admin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$css   = (string) file_get_contents( HANDL_AICAC_DIR . '/assets/admin.css' );

		$this->assertStringContainsString( 'handl-aicac-col-anchor handl-aicac-col-cb', $admin );
		$this->assertStringContainsString( 'handl-aicac-col-anchor handl-aicac-col-plugin', $admin );
		$this->assertStringContainsString( 'handl-aicac-col-anchor handl-aicac-col-status', $admin );
		$this->assertStringContainsString( 'handl-aicac-col-anchor handl-aicac-col-access', $admin );
		$this->assertStringContainsString( 'render_alert_delivery_dashboard_line', $admin );

		$this->assertStringContainsString( 'position: sticky', $css );
		$this->assertStringContainsString( '.handl-aicac-rules-matrix .handl-aicac-col-access', $css );
		$this->assertDoesNotMatchRegularExpression(
			'/\.handl-aicac-row-advanced__label\s*\{[^}]*text-transform:\s*uppercase/s',
			$css
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private function render_alert_delivery_line( array $policy ): string {
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php';

		$ref    = new ReflectionClass( Admin::class );
		$admin  = $ref->newInstanceWithoutConstructor();
		$method = $ref->getMethod( 'render_alert_delivery_dashboard_line' );
		$method->setAccessible( true );

		ob_start();
		$method->invoke( $admin, $policy );
		return (string) ob_get_clean();
	}
}
