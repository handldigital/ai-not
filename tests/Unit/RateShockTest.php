<?php
/**
 * AICAC-RATE-SHOCK (#345).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Budget;
use HandL\AICAC\Plugin;
use HandL\AICAC\Rate_Shock;
use HandL\AICAC\Rates_Feed;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class RateShockTest extends TestCase {

	private const NOW = 1792165053;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		Rate_Shock::reset_for_tests();
		Rates_Feed::reset_for_tests();
		Rate_Shock::set_test_now( self::NOW );
		update_option( 'admin_email', 'haktan+aicac-rate-shock@handldigital.com' );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
				'log_limit'   => 200,
				'default'     => 'observe',
			),
			false
		);
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Budget::SPEND_OPTION_KEY );
	}

	protected function tearDown(): void {
		Rate_Shock::reset_for_tests();
		Rates_Feed::reset_for_tests();
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Budget::SPEND_OPTION_KEY );
		parent::tearDown();
	}

	/**
	 * @return array{version:string,updated_at:int,providers:array<string,array{input_per_m:float,output_per_m:float}>}
	 */
	private function state( string $version, float $openai_in, float $openai_out = 30.0 ): array {
		return array(
			'version'    => $version,
			'updated_at' => self::NOW,
			'providers'  => array(
				'openai' => array(
					'input_per_m'  => $openai_in,
					'output_per_m' => $openai_out,
				),
			),
		);
	}

	public function test_used_rate_change_fires_one_alert_with_delta(): void {
		// 1M input tokens @ $5 → $10 is +$5 (material vs $1 / 5%).
		Rate_Shock::set_test_log(
			array(
				array(
					'ts'            => self::NOW - 100,
					'plugin'        => 'demo/demo.php',
					'provider'      => 'openai',
					'input_tokens'  => 1_000_000,
					'output_tokens' => 0,
					'decision'      => 'allow',
				),
			)
		);

		$mails = array();
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) use ( &$mails ): bool {
			$mails[] = compact( 'to', 'subject', 'message' );
			return true;
		};

		Rate_Shock::on_rates_applied(
			$this->state( 'v1', 5.0 ),
			$this->state( 'v2', 10.0 ),
			self::NOW
		);

		$this->assertCount( 1, $mails );
		$this->assertSame( 'haktan+aicac-rate-shock@handldigital.com', $mails[0]['to'] );
		$this->assertStringContainsString( 'more for your recent AI use', $mails[0]['subject'] );
		$this->assertStringContainsString( '5.00', $mails[0]['message'] );
		$this->assertStringContainsString( '10.00', $mails[0]['message'] );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $log );
		$found = false;
		foreach ( $log as $row ) {
			if ( is_array( $row ) && 'rate_shock' === ( $row['channel'] ?? '' ) ) {
				$found = true;
				$this->assertSame( 1, (int) ( $row['material_count'] ?? 0 ) );
				$this->assertSame( 'v2', (string) ( $row['feed_version'] ?? '' ) );
			}
		}
		$this->assertTrue( $found );
		$notice = get_option( Rate_Shock::NOTICE_OPTION, null );
		$this->assertIsArray( $notice );
	}

	public function test_unused_and_subthreshold_audit_only_no_alert(): void {
		Rate_Shock::set_test_log(
			array(
				// Tiny usage: 1000 tokens @ $5→$5.10 = $0.0001 delta — below $1 and 5%.
				array(
					'ts'            => self::NOW - 50,
					'plugin'        => 'demo/demo.php',
					'provider'      => 'openai',
					'input_tokens'  => 1000,
					'output_tokens' => 0,
					'decision'      => 'allow',
				),
			)
		);
		$mails = array();
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) use ( &$mails ): bool {
			$mails[] = compact( 'to', 'subject', 'message' );
			return true;
		};

		// Unused anthropic change + sub-threshold openai change.
		$before = $this->state( 'v1', 5.0 );
		$after  = $this->state( 'v2', 5.10 );
		$after['providers']['anthropic'] = array(
			'input_per_m'  => 20.0,
			'output_per_m' => 40.0,
		);
		$before['providers']['anthropic'] = array(
			'input_per_m'  => 10.0,
			'output_per_m' => 20.0,
		);

		Rate_Shock::on_rates_applied( $before, $after, self::NOW );
		$this->assertSame( array(), $mails );

		$log   = get_option( Plugin::LOG_OPTION_KEY, array() );
		$found = false;
		foreach ( (array) $log as $row ) {
			if ( is_array( $row ) && 'rate_shock' === ( $row['channel'] ?? '' ) ) {
				$found = true;
				$this->assertSame( 0, (int) ( $row['material_count'] ?? -1 ) );
				$this->assertGreaterThanOrEqual( 1, (int) ( $row['change_count'] ?? 0 ) );
			}
		}
		$this->assertTrue( $found );
		$this->assertFalse( (bool) get_option( Rate_Shock::NOTICE_OPTION, false ) );
	}

	public function test_price_decrease_positive_framing(): void {
		Rate_Shock::set_test_log(
			array(
				array(
					'ts'            => self::NOW - 10,
					'plugin'        => 'demo/demo.php',
					'provider'      => 'openai',
					'input_tokens'  => 1_000_000,
					'output_tokens' => 0,
					'decision'      => 'allow',
				),
			)
		);
		$mails = array();
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) use ( &$mails ): bool {
			$mails[] = compact( 'to', 'subject', 'message' );
			return true;
		};

		Rate_Shock::on_rates_applied(
			$this->state( 'v1', 10.0 ),
			$this->state( 'v2', 5.0 ),
			self::NOW
		);

		$this->assertCount( 1, $mails );
		$this->assertStringContainsString( 'cheaper', $mails[0]['subject'] );
		$this->assertStringContainsString( 'Good news', $mails[0]['message'] );
	}

	public function test_budget_cap_warning_when_projection_crosses(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled'    => true,
				'log_limit'      => 200,
				'default'        => 'observe',
				'plugin_budgets' => array(
					'demo/demo.php' => 3.0,
				),
			),
			false
		);
		// Seed prior period spend under the cap.
		Budget::save_spend_map(
			array(
				Budget::period_id( self::NOW ) => array(
					'demo/demo.php' => 2.0,
				),
			)
		);

		Rate_Shock::set_test_log(
			array(
				array(
					'ts'            => self::NOW - 100,
					'plugin'        => 'demo/demo.php',
					'provider'      => 'openai',
					'input_tokens'  => 1_000_000,
					'output_tokens' => 0,
					'decision'      => 'allow',
				),
			)
		);
		$mails = array();
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) use ( &$mails ): bool {
			$mails[] = compact( 'to', 'subject', 'message' );
			return true;
		};

		// New rate $5 / 1M input → projected $5 > budget $3; prior spend was $2.
		Rate_Shock::on_rates_applied(
			$this->state( 'v1', 2.0 ),
			$this->state( 'v2', 5.0 ),
			self::NOW
		);

		$this->assertCount( 1, $mails );
		$this->assertStringContainsString( 'Budget early warning', $mails[0]['message'] );
		$this->assertStringContainsString( 'demo/demo.php', $mails[0]['message'] );
	}

	public function test_noop_save_leaves_settings_byte_identical(): void {
		$this->assertSame( Rate_Shock::defaults(), Rate_Shock::get_settings() );
		$this->assertFalse( (bool) get_option( Rate_Shock::SETTINGS_OPTION, false ) );

		Rate_Shock::save_settings(
			array(
				'threshold_usd' => 2.5,
				'threshold_pct' => 10.0,
			)
		);
		$stored = get_option( Rate_Shock::SETTINGS_OPTION, null );
		$this->assertIsArray( $stored );

		Rate_Shock::save_settings(
			array(
				'threshold_usd' => 2.5,
				'threshold_pct' => 10.0,
			)
		);
		$this->assertSame( $stored, get_option( Rate_Shock::SETTINGS_OPTION, null ) );

		Rate_Shock::save_settings( Rate_Shock::defaults() );
		$this->assertFalse( (bool) get_option( Rate_Shock::SETTINGS_OPTION, false ) );
	}

	public function test_rates_feed_apply_fires_action_constant(): void {
		$this->assertSame( 'handl_aicac_rates_feed_applied', Rates_Feed::ACTION_APPLIED );
		$seen = array();
		$GLOBALS['handl_aicac_test_do_actions'][ Rates_Feed::ACTION_APPLIED ] = static function ( $before, $after, $now ) use ( &$seen ): void {
			$seen[] = compact( 'before', 'after', 'now' );
		};
		Rates_Feed::apply_remote_rates(
			array(
				'version'   => 'hook-v',
				'providers' => array(
					'openai' => array(
						'input_per_m'  => 1.0,
						'output_per_m' => 2.0,
					),
				),
			),
			self::NOW
		);
		$this->assertCount( 1, $seen );
		$this->assertSame( 'hook-v', $seen[0]['after']['version'] );
		unset( $GLOBALS['handl_aicac_test_do_actions'] );
	}
}
