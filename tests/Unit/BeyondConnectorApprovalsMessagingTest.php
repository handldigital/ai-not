<?php
/**
 * AICAC-11: lock in-product differentiator messaging vs Connector Approvals.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Differentiator_Messaging;
use PHPUnit\Framework\TestCase;

final class BeyondConnectorApprovalsMessagingTest extends TestCase {

	public function test_body_states_confirmed_caller_by_connector_granularity(): void {
		$body = Differentiator_Messaging::body();
		$this->assertStringContainsString( 'Connector Approvals', $body );
		$this->assertStringContainsString( 'connector credentials', $body );
		$this->assertStringContainsString( 'AI Client', $body );
		$this->assertStringContainsString( 'capability-family matrix', $body );
		$this->assertStringContainsString( 'direct connections outside the AI Client', $body );
	}

	public function test_copy_names_all_required_differentiators(): void {
		$combined = implode(
			' ',
			array(
				Differentiator_Messaging::headline(),
				Differentiator_Messaging::page_subtitle_addition(),
				Differentiator_Messaging::body(),
				Differentiator_Messaging::rules_note(),
			)
		);

		foreach ( Differentiator_Messaging::differentiator_phrases() as $phrase ) {
			$this->assertStringContainsString(
				$phrase,
				$combined,
				'Missing required differentiator phrase: ' . $phrase
			);
		}
	}

	public function test_coexistence_is_explicit(): void {
		$note = Differentiator_Messaging::coexistence();
		$this->assertStringContainsString( 'Both can run together', $note );
		$this->assertStringContainsString( 'different layers', $note );
	}

	public function test_admin_renders_dashboard_callout_and_rules_note(): void {
		$admin = file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertNotFalse( $admin );
		$this->assertStringContainsString( 'render_beyond_connector_approvals_callout', $admin );
		$this->assertStringContainsString( 'Differentiator_Messaging::headline', $admin );
		$this->assertStringContainsString( 'Differentiator_Messaging::body', $admin );
		$this->assertStringContainsString( 'Differentiator_Messaging::coexistence', $admin );
		$this->assertStringContainsString( 'Differentiator_Messaging::page_subtitle_addition', $admin );
		$this->assertStringContainsString( 'Differentiator_Messaging::rules_note', $admin );
		$this->assertStringContainsString( 'handl-aicac-beyond-ca', $admin );
	}

	public function test_readme_faq_documents_comparison(): void {
		$readme = file_get_contents( HANDL_AICAC_DIR . '/readme.txt' );
		$this->assertNotFalse( $readme );
		$this->assertStringContainsString( 'Connector Approvals', $readme );
		$this->assertStringContainsString( 'capability-family matrix', $readme );
		$this->assertStringContainsString( 'tool-arming denial', $readme );
		$this->assertStringContainsString( 'shadow-AI detection', $readme );
		$this->assertStringContainsString( 'spend / denial alerting', $readme );
		$this->assertStringContainsString( 'differs from Connector Approvals', $readme );
		$this->assertStringContainsString( '= 1.6.0 =', $readme );
	}

	public function test_plugin_version_stays_current_release(): void {
		$main = file_get_contents( HANDL_AICAC_DIR . '/handl-ai-connector-access-control.php' );
		$this->assertNotFalse( $main );
		// Release stamp must stay aligned across header + constant.
		$this->assertMatchesRegularExpression( "/define\(\s*'HANDL_AICAC_VERSION',\s*'1\.6\.0'\s*\)/", $main );
		$this->assertStringContainsString( 'Version: 1.6.0', $main );
	}
}
