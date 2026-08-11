<?php
/**
 * AICAC-GRADUATE unit tests: prefill mapping + duplicate coverage.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Graduate;
use HandL\AICAC\Operations;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class GraduateTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options'] = array();
	}

	public function test_proposal_from_log_row_maps_plugin_family_provider_model(): void {
		$row = array(
			'plugin'             => 'acme/ai-writer.php',
			'operation'          => 'generate_text',
			'capability_family'  => Operations::FAMILY_TEXT,
			'provider'           => 'openai',
			'model'              => 'gpt-4o-mini',
			'decision'           => 'allow',
		);

		$proposal = Graduate::proposal_from_log_row( $row );
		$this->assertNotNull( $proposal );
		$this->assertSame( 'acme/ai-writer.php', $proposal['plugin'] );
		$this->assertSame( Operations::FAMILY_TEXT, $proposal['family'] );
		$this->assertSame( 'openai', $proposal['provider'] );
		$this->assertSame( 'gpt-4o-mini', $proposal['model'] );
	}

	public function test_proposal_infers_family_from_operation_when_missing(): void {
		$row = array(
			'plugin'    => 'acme/img.php',
			'operation' => 'generate_image',
			'provider'  => 'openai',
			'model'     => 'dall-e-3',
		);

		$proposal = Graduate::proposal_from_log_row( $row );
		$this->assertNotNull( $proposal );
		$this->assertSame( Operations::FAMILY_IMAGE, $proposal['family'] );
	}

	public function test_proposal_rejects_direct_http_and_missing_plugin(): void {
		$this->assertNull(
			Graduate::proposal_from_log_row(
				array(
					'channel' => 'direct_http',
					'plugin'  => 'acme/bypass.php',
					'host'    => 'api.openai.com',
				)
			)
		);
		$this->assertNull(
			Graduate::proposal_from_log_row(
				array(
					'operation' => 'generate_text',
					'provider'  => 'openai',
				)
			)
		);
		$this->assertNull( Graduate::proposal_from_plugin( '' ) );
		$this->assertNull( Graduate::proposal_from_plugin( '../evil.php' ) );
	}

	public function test_coverage_detects_explicit_plugin_rule(): void {
		$policy = array(
			'plugins'    => array( 'acme/ai-writer.php' => 'deny' ),
			'operations' => array(),
		);

		$proposal = array(
			'plugin'   => 'acme/ai-writer.php',
			'family'   => Operations::FAMILY_TEXT,
			'provider' => 'openai',
			'model'    => 'gpt-4o',
		);

		$coverage = Graduate::coverage_for( $policy, $proposal );
		$this->assertNotNull( $coverage );
		$this->assertSame( 'plugin', $coverage['kind'] );
		$this->assertSame( 'deny', $coverage['rule'] );

		$label = Graduate::coverage_label(
			$coverage,
			array( 'acme/ai-writer.php' => array( 'Name' => 'Acme Writer' ) )
		);
		$this->assertStringContainsString( 'Deny', $label );
		$this->assertStringContainsString( 'Acme Writer', $label );
	}

	public function test_coverage_detects_family_rule_when_plugin_default(): void {
		$policy = array(
			'plugins'    => array(),
			'operations' => array(
				'acme/ai-writer.php' => array(
					Operations::FAMILY_TEXT => 'allow',
				),
			),
		);

		$proposal = array(
			'plugin' => 'acme/ai-writer.php',
			'family' => Operations::FAMILY_TEXT,
		);

		$coverage = Graduate::coverage_for( $policy, $proposal );
		$this->assertNotNull( $coverage );
		$this->assertSame( 'family', $coverage['kind'] );
		$this->assertSame( 'allow', $coverage['rule'] );
		$this->assertSame( Operations::FAMILY_TEXT, $coverage['family'] );
	}

	public function test_coverage_null_when_not_covered(): void {
		$policy   = array(
			'plugins'    => array(),
			'operations' => array(),
		);
		$proposal = array(
			'plugin' => 'acme/ai-writer.php',
			'family' => Operations::FAMILY_TEXT,
		);
		$this->assertNull( Graduate::coverage_for( $policy, $proposal ) );
	}

	public function test_rules_url_includes_prefill_query_args(): void {
		$url = Graduate::rules_url(
			array(
				'plugin'   => 'acme/ai-writer.php',
				'family'   => Operations::FAMILY_TEXT,
				'provider' => 'openai',
				'model'    => 'gpt-4o-mini',
			)
		);

		$this->assertStringContainsString( 'handl_aicac_tab=rules', $url );
		$this->assertStringContainsString( 'handl_aicac_graduate=1', $url );
		$this->assertStringContainsString( 'handl_aicac_focus_plugin=', $url );
		$this->assertStringContainsString( 'handl_aicac_graduate_family=text', $url );
		$this->assertStringContainsString( 'handl_aicac_graduate_provider=openai', $url );
		$this->assertStringContainsString( 'handl_aicac_graduate_model=gpt-4o-mini', $url );
		$this->assertStringContainsString( '#handl-aicac-rule-', $url );
	}

	public function test_proposal_from_request_reads_graduate_flags(): void {
		$_REQUEST = array(
			'handl_aicac_graduate'         => '1',
			'handl_aicac_focus_plugin'     => 'acme/ai-writer.php',
			'handl_aicac_graduate_family'  => 'text',
			'handl_aicac_graduate_provider'=> 'openai',
			'handl_aicac_graduate_model'   => 'gpt-4o-mini',
		);

		$proposal = Graduate::proposal_from_request();
		$this->assertNotNull( $proposal );
		$this->assertSame( 'acme/ai-writer.php', $proposal['plugin'] );
		$this->assertSame( 'text', $proposal['family'] );
		$this->assertSame( 'openai', $proposal['provider'] );
		$this->assertSame( 'gpt-4o-mini', $proposal['model'] );

		$_REQUEST = array();
		$this->assertNull( Graduate::proposal_from_request() );
	}

	public function test_set_plugin_rule_still_is_existing_save_path(): void {
		// Saving still goes through Policy::set_plugin_rule / save_policy (no new path).
		$ok = Policy::set_plugin_rule( 'acme/ai-writer.php', 'allow' );
		$this->assertTrue( $ok );
		$policy = Policy::get_policy();
		$this->assertSame( 'allow', $policy['plugins']['acme/ai-writer.php'] ?? null );
		// Covered after save.
		$this->assertNotNull(
			Graduate::coverage_for(
				$policy,
				array( 'plugin' => 'acme/ai-writer.php', 'family' => Operations::FAMILY_TEXT )
			)
		);
	}
}
