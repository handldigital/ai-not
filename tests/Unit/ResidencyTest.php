<?php
/**
 * AICAC-RESIDENCY (#229): region gate, map filter, unknown-provider mode.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alerts;
use HandL\AICAC\Residency;
use PHPUnit\Framework\TestCase;

final class ResidencyTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		delete_option( Residency::OPTION_KEY );
		unset( $GLOBALS['handl_aicac_test_filters'][ Residency::FILTER_MAP ] );
	}

	protected function tearDown(): void {
		delete_option( Residency::OPTION_KEY );
		unset( $GLOBALS['handl_aicac_test_filters'][ Residency::FILTER_MAP ] );
		parent::tearDown();
	}

	public function test_default_is_no_restriction(): void {
		$eval = Residency::evaluate( 'openai' );
		$this->assertFalse( $eval['active'] );
		$this->assertFalse( $eval['prevent'] );
		$this->assertSame( '', $eval['reason'] );
		$this->assertSame( Residency::REGION_NONE, Residency::get()['region'] );
	}

	public function test_eu_denies_us_provider_and_allows_mistral(): void {
		Residency::save( array( 'region' => Residency::REGION_EU ) );

		$openai = Residency::evaluate( 'openai' );
		$this->assertTrue( $openai['active'] );
		$this->assertTrue( $openai['prevent'] );
		$this->assertSame( Residency::REASON, $openai['reason'] );
		$this->assertSame( 'EU-only', $openai['rule'] );
		$this->assertSame( array( 'us' ), $openai['regions'] );

		$mistral = Residency::evaluate( 'Mistral' );
		$this->assertTrue( $mistral['active'] );
		$this->assertFalse( $mistral['prevent'] );
		$this->assertSame( array( 'eu' ), $mistral['regions'] );
	}

	public function test_us_denies_mistral_and_allows_openai(): void {
		Residency::save( array( 'region' => Residency::REGION_US ) );

		$this->assertTrue( Residency::evaluate( 'mistral' )['prevent'] );
		$this->assertFalse( Residency::evaluate( 'openai' )['prevent'] );
		$this->assertTrue( Residency::evaluate( 'deepseek' )['prevent'] );
	}

	public function test_unknown_provider_warns_by_default(): void {
		Residency::save( array( 'region' => Residency::REGION_EU ) );

		$eval = Residency::evaluate( 'not-a-real-provider' );
		$this->assertTrue( $eval['active'] );
		$this->assertTrue( $eval['unknown'] );
		$this->assertFalse( $eval['prevent'] );
		$this->assertSame( '', $eval['reason'] );
	}

	public function test_unknown_provider_fail_closed_when_strict(): void {
		Residency::save(
			array(
				'region'         => Residency::REGION_EU,
				'strict_unknown' => true,
			)
		);

		$eval = Residency::evaluate( '' );
		$this->assertTrue( $eval['unknown'] );
		$this->assertTrue( $eval['prevent'] );
		$this->assertSame( Residency::REASON, $eval['reason'] );
	}

	public function test_filter_extends_map_without_plugin_update(): void {
		Residency::save( array( 'region' => Residency::REGION_EU ) );
		$GLOBALS['handl_aicac_test_filters'][ Residency::FILTER_MAP ] = static function ( array $map ): array {
			$map['acme'] = array( 'eu' );
			return $map;
		};

		$eval = Residency::evaluate( 'acme' );
		$this->assertFalse( $eval['prevent'] );
		$this->assertFalse( $eval['unknown'] );
		$this->assertSame( array( 'eu' ), $eval['regions'] );
	}

	public function test_settings_override_can_remap_and_unmap(): void {
		Residency::save(
			array(
				'region' => Residency::REGION_EU,
				'map'    => array(
					'openai' => array( 'eu', 'us' ),
				),
			)
		);
		$this->assertFalse( Residency::evaluate( 'openai' )['prevent'] );

		Residency::save(
			array(
				'region' => Residency::REGION_EU,
				'map'    => Residency::parse_map_text( "openai=\nmistral=us" ),
			)
		);
		$openai = Residency::evaluate( 'openai' );
		$this->assertTrue( $openai['unknown'] );
		$this->assertFalse( $openai['prevent'] );

		$mistral = Residency::evaluate( 'mistral' );
		$this->assertTrue( $mistral['prevent'] );
		$this->assertSame( array( 'us' ), $mistral['regions'] );
	}

	public function test_apply_to_event_sets_reason_and_rule(): void {
		Residency::save( array( 'region' => Residency::REGION_EU ) );
		$event  = array(
			'plugin'   => 'acme/acme.php',
			'provider' => 'openai',
			'decision' => 'allow',
		);
		$result = Residency::apply_to_event( $event );

		$this->assertTrue( $result['prevent'] );
		$this->assertSame( 'EU-only', $event['residency_rule'] );
		$this->assertSame( 'eu', $event['residency_region'] );
		$this->assertSame( 'openai', $event['residency_provider'] );
		$this->assertArrayNotHasKey( 'residency_unknown', $event );
	}

	public function test_apply_to_event_tags_unknown_without_prevent(): void {
		Residency::save( array( 'region' => Residency::REGION_US ) );
		$event  = array( 'provider' => 'mystery-llm' );
		$result = Residency::apply_to_event( $event, null, 'mystery-llm' );

		$this->assertFalse( $result['prevent'] );
		$this->assertTrue( $result['unknown'] );
		$this->assertTrue( $event['residency_unknown'] );
		$this->assertSame( 'US-only', $event['residency_rule'] );
	}

	public function test_save_clears_option_when_back_to_defaults(): void {
		Residency::save( array( 'region' => Residency::REGION_EU, 'strict_unknown' => true ) );
		$this->assertNotFalse( get_option( Residency::OPTION_KEY, false ) );

		Residency::save( array( 'region' => Residency::REGION_NONE ) );
		$this->assertFalse( get_option( Residency::OPTION_KEY, false ) );
	}

	public function test_alert_summary_names_the_region_rule(): void {
		$summary = Alerts::summarize_event_public(
			array(
				'denial_reason'  => Residency::REASON,
				'residency_rule' => 'EU-only',
				'provider'       => 'openai',
			)
		);
		$this->assertSame( 'residency (EU-only)', $summary['denial_reason'] );
		$this->assertSame( 'openai', $summary['provider'] );
	}

	public function test_parse_map_text_ignores_comments_and_junk(): void {
		$map = Residency::parse_map_text(
			"# comment\nopenai=us\n\nbadline\nmistral = eu , us\n=eu\n"
		);
		$this->assertSame(
			array(
				'openai'  => array( 'us' ),
				'mistral' => array( 'eu', 'us' ),
			),
			$map
		);
	}
}
