<?php
/**
 * AICAC-RATES-FEED (#334).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Cost;
use HandL\AICAC\Plugin;
use HandL\AICAC\Rates_Feed;
use HandL\AICAC\Threat_Feed;
use PHPUnit\Framework\TestCase;

final class RatesFeedTest extends TestCase {

	/** Test-only Ed25519 secret key (hex). Production key is not this value. */
	private const TEST_SK = '2c2972afb959602dfcf714921c496c86655b725bce3286c6de4d55c429ffc1375e4ad62aa0895f60b9eab237b544845c7e13da9348d2b6b3808bdc12b4597470';

	private const TEST_PK = '5e4ad62aa0895f60b9eab237b544845c7e13da9348d2b6b3808bdc12b4597470';

	protected function setUp(): void {
		parent::setUp();
		Threat_Feed::reset_for_tests();
		Rates_Feed::reset_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Threat_Feed::OPTION_KEY );
		delete_option( Threat_Feed::SIGNATURE_OPTION_KEY );
		delete_option( Rates_Feed::OPTION_KEY );
		unset( $GLOBALS['handl_aicac_threat_feed_http'] );
		$GLOBALS['handl_aicac_test_filters'] = array(
			Threat_Feed::FILTER_PUBKEY => static function ( $pk ) {
				unset( $pk );
				return self::TEST_PK;
			},
		);
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
				'log_limit'   => 200,
				'default'     => 'observe',
			),
			false
		);
	}

	protected function tearDown(): void {
		Threat_Feed::reset_for_tests();
		Rates_Feed::reset_for_tests();
		unset(
			$GLOBALS['handl_aicac_threat_feed_http'],
			$GLOBALS['handl_aicac_test_filters']
		);
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Threat_Feed::OPTION_KEY );
		delete_option( Threat_Feed::SIGNATURE_OPTION_KEY );
		delete_option( Rates_Feed::OPTION_KEY );
		parent::tearDown();
	}

	/**
	 * @param array<string,mixed> $payload
	 */
	private function sign_envelope( array $payload ): string {
		$canonical = json_encode( $payload, Threat_Feed::SIGN_FLAGS );
		$sk        = hex2bin( self::TEST_SK );
		$this->assertIsString( $canonical );
		$this->assertIsString( $sk );
		$sig = sodium_crypto_sign_detached( $canonical, $sk );

		return (string) json_encode(
			array(
				'payload'   => $payload,
				'signature' => bin2hex( $sig ),
			),
			Threat_Feed::SIGN_FLAGS
		);
	}

	/**
	 * @param array<string,mixed> $extra
	 * @return array<string,mixed>
	 */
	private function base_payload( array $extra = array() ): array {
		return array_merge(
			array(
				'version'      => 1,
				'generated_at' => '2026-10-12T00:00:00Z',
				'advisories'   => array(),
			),
			$extra
		);
	}

	private function stub_http( int $code, string $body, string $etag = '"rates-v1"' ): void {
		$GLOBALS['handl_aicac_threat_feed_http'] = static function ( $url, $args ) use ( $code, $body, $etag ) {
			unset( $url, $args );
			return array(
				'response' => array( 'code' => $code ),
				'body'     => $body,
				'headers'  => array( 'etag' => $etag ),
			);
		};
	}

	/**
	 * @return array<string,mixed>
	 */
	private function rates_block( string $version = '2026-10-12', float $openai_in = 9.99 ): array {
		return array(
			'version'   => $version,
			'providers' => array(
				'openai' => array(
					'input_per_m'  => $openai_in,
					'output_per_m' => 19.99,
				),
			),
		);
	}

	private function fetch_rates( float $openai_in = 9.99, int $now = 1_700_100_000 ): void {
		$body = $this->sign_envelope(
			$this->base_payload(
				array(
					'rates' => $this->rates_block( '2026-10-12', $openai_in ),
				)
			)
		);
		$this->stub_http( 200, $body );
		$stat = Threat_Feed::run( $now );
		$this->assertSame( '', $stat['error'] );
		$this->assertTrue( $stat['fetched'] );
	}

	public function test_signed_rates_update_estimates_without_admin_override(): void {
		$policy = array(
			'est_usd_input_per_m'  => Cost::DEFAULT_INPUT_PER_M,
			'est_usd_output_per_m' => Cost::DEFAULT_OUTPUT_PER_M,
		);
		$before = Cost::rates_from_policy( $policy, 'openai' );
		$this->assertSame( Cost::DEFAULT_INPUT_PER_M, $before['input_per_m'] );

		$this->fetch_rates( 9.99 );
		$stored = Rates_Feed::stored_rates();
		$this->assertSame( '2026-10-12', $stored['version'] );
		$this->assertSame( 1_700_100_000, $stored['updated_at'] );
		$this->assertSame( 9.99, $stored['providers']['openai']['input_per_m'] );

		$after = Cost::rates_from_policy( $policy, 'openai' );
		$this->assertSame( 9.99, $after['input_per_m'] );
		$this->assertSame( 19.99, $after['output_per_m'] );

		$est = Cost::estimate_usd( 1_000_000, 0, $after );
		$this->assertEqualsWithDelta( 9.99, (float) $est, 0.0001 );
	}

	public function test_admin_override_wins_over_feed_rates(): void {
		$this->fetch_rates( 9.99 );
		$policy = array(
			'est_usd_input_per_m'    => 2.50,
			'est_usd_output_per_m'   => 10.00,
			'est_usd_provider_rates' => array(
				'openai' => array(
					'input_per_m'  => 1.11,
					'output_per_m' => 2.22,
				),
			),
		);
		$rates = Cost::rates_from_policy( $policy, 'openai' );
		$this->assertSame( 1.11, $rates['input_per_m'] );
		$this->assertSame( 2.22, $rates['output_per_m'] );
	}

	public function test_tampered_rates_payload_is_rejected(): void {
		$this->fetch_rates( 9.99 );
		$before = Rates_Feed::stored_rates();

		$payload = $this->base_payload(
			array(
				'rates' => $this->rates_block( 'evil', 0.01 ),
			)
		);
		$envelope              = json_decode( $this->sign_envelope( $payload ), true );
		$envelope['signature'] = str_repeat( 'ab', 64 );
		$this->stub_http( 200, (string) json_encode( $envelope, Threat_Feed::SIGN_FLAGS ) );

		$stat = Threat_Feed::run( 1_700_100_100 );
		$this->assertSame( 'invalid_signature', $stat['error'] );
		$this->assertSame( $before, Rates_Feed::stored_rates() );
		$this->assertSame( 9.99, Cost::rates_from_policy( array(), 'openai' )['input_per_m'] );
	}

	public function test_air_gap_skips_fetch_and_ignores_stored_rates(): void {
		$this->fetch_rates( 9.99 );
		$this->assertSame( 9.99, Rates_Feed::stored_rates()['providers']['openai']['input_per_m'] );

		$called = false;
		$GLOBALS['handl_aicac_threat_feed_http'] = static function () use ( &$called ) {
			$called = true;
			return array(
				'response' => array( 'code' => 200 ),
				'body'     => '{}',
			);
		};
		$GLOBALS['handl_aicac_test_filters'][ Threat_Feed::FILTER_DISABLED ] = static function () {
			return true;
		};

		$stat = Threat_Feed::run( 1_700_100_200 );
		$this->assertSame( 'disabled', $stat['error'] );
		$this->assertFalse( $called );
		$this->assertSame( array(), Rates_Feed::remote_rates()['providers'] );
		$this->assertSame( 9.99, Rates_Feed::stored_rates()['providers']['openai']['input_per_m'] );

		$rates = Cost::rates_from_policy( array(), 'openai' );
		$this->assertSame( Cost::DEFAULT_INPUT_PER_M, $rates['input_per_m'] );
	}

	public function test_omit_rates_key_keeps_stored_table(): void {
		$this->fetch_rates( 9.99 );
		$body = $this->sign_envelope( $this->base_payload() );
		$this->stub_http( 200, $body, '"adv-only"' );
		$stat = Threat_Feed::run( 1_700_100_300 );
		$this->assertSame( '', $stat['error'] );
		$this->assertSame( '2026-10-12', Rates_Feed::stored_rates()['version'] );
		$this->assertSame( 9.99, Rates_Feed::stored_rates()['providers']['openai']['input_per_m'] );
	}

	public function test_empty_providers_clears_stored_rates(): void {
		$this->fetch_rates( 9.99 );
		$body = $this->sign_envelope(
			$this->base_payload(
				array(
					'rates' => array(
						'version'   => 'cleared',
						'providers' => array(),
					),
				)
			)
		);
		$this->stub_http( 200, $body, '"rates-empty"' );
		$stat = Threat_Feed::run( 1_700_100_400 );
		$this->assertSame( '', $stat['error'] );
		$stored = Rates_Feed::stored_rates();
		$this->assertSame( 'cleared', $stored['version'] );
		$this->assertSame( array(), $stored['providers'] );
		$this->assertSame( Cost::DEFAULT_INPUT_PER_M, Cost::rates_from_policy( array(), 'openai' )['input_per_m'] );
	}

	public function test_rate_change_recomputes_estimate(): void {
		$policy = array();
		$this->fetch_rates( 1.00, 1_700_100_500 );
		$first = Cost::estimate_usd( 2_000_000, 0, Cost::rates_from_policy( $policy, 'openai' ) );
		$this->assertEqualsWithDelta( 2.0, (float) $first, 0.0001 );

		$this->fetch_rates( 5.00, 1_700_100_600 );
		$second = Cost::estimate_usd( 2_000_000, 0, Cost::rates_from_policy( $policy, 'openai' ) );
		$this->assertEqualsWithDelta( 10.0, (float) $second, 0.0001 );
		$this->assertSame( '2026-10-12', Rates_Feed::status()['version'] );
	}

	public function test_cli_status_mentions_rate_table(): void {
		$cli = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-cli-threat-feed.php' );
		$this->assertStringContainsString( 'Cost rate table:', $cli );
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-rates-feed.php', $plugin );
	}
}
