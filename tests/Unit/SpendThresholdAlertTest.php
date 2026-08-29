<?php
/**
 * S-103: estimated-spend threshold alerts.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Spend_Threshold;
use PHPUnit\Framework\TestCase;

final class SpendThresholdAlertTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Spend_Threshold::FIRED_OPTION_KEY );
		update_option( 'admin_email', 'admin@example.com' );

		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);
			return true;
		};
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Spend_Threshold::FIRED_OPTION_KEY );
		parent::tearDown();
	}

	public function test_empty_threshold_never_fires(): void {
		$this->seed_log_with_spend( 5.0 );
		$policy = $this->persist_policy(
			array(
				'spend_threshold_site' => null,
			)
		);
		Spend_Threshold::maybe_evaluate( $policy );
		$this->assertSame( array(), self::$mails );
	}

	public function test_site_threshold_fires_once_with_required_body(): void {
		$this->seed_log_with_spend( 12.5 );
		$policy = $this->persist_policy(
			array(
				'spend_threshold_site' => 10.0,
			)
		);
		// Avoid save_policy side-effect double-fire; evaluate explicitly.
		Spend_Threshold::maybe_evaluate( $policy );
		$this->assertCount( 1, self::$mails );
		$mail = self::$mails[0];
		$this->assertStringContainsString( 'estimated spend alert', strtolower( $mail['subject'] ) );
		$this->assertStringContainsString( 'site estimate crossed', strtolower( $mail['subject'] ) );
		$this->assertStringContainsString( 'Alert threshold:', $mail['message'] );
		$this->assertStringContainsString( 'Current estimated spend:', $mail['message'] );
		$this->assertStringContainsString( 'Saved activity period:', $mail['message'] );
		$this->assertStringContainsString( 'This estimate is based on logged token usage and configured rates. It is not a bill', $mail['message'] );
		$this->assertStringContainsString( 'page=handl-aicac-activity', $mail['message'] );

		// Second evaluate within 24h → no duplicate.
		Spend_Threshold::maybe_evaluate( $policy );
		$this->assertCount( 1, self::$mails );

		// Audit row present.
		$log   = get_option( Plugin::LOG_OPTION_KEY, array() );
		$found = false;
		foreach ( is_array( $log ) ? $log : array() as $row ) {
			if ( is_array( $row ) && ( $row['channel'] ?? '' ) === 'spend_threshold' ) {
				$found = true;
				$this->assertSame( 'spend_alert', $row['decision'] ?? '' );
				$this->assertSame( 'site', $row['scope'] ?? '' );
			}
		}
		$this->assertTrue( $found, 'Expected spend_threshold audit row' );
	}

	public function test_per_plugin_threshold_names_plugin(): void {
		$this->seed_log_with_spend( 3.0, 'acme/acme.php' );
		$this->seed_log_with_spend( 8.0, 'other/other.php' );
		$policy = $this->persist_policy(
			array(
				'spend_threshold_plugins' => array(
					'acme/acme.php' => 2.0,
				),
			)
		);
		Spend_Threshold::maybe_evaluate( $policy );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'acme/acme.php', self::$mails[0]['subject'] );
		$this->assertStringContainsString( 'Plugin:', self::$mails[0]['message'] );
	}

	public function test_logging_off_skips_evaluation(): void {
		$this->seed_log_with_spend( 50.0 );
		$policy = $this->persist_policy(
			array(
				'log_enabled'          => false,
				'audit_only'           => false,
				'spend_threshold_site' => 1.0,
			)
		);
		Spend_Threshold::maybe_evaluate( $policy );
		$this->assertSame( array(), self::$mails );
	}

	public function test_sanitize_empty_and_non_positive_are_off(): void {
		$this->assertNull( Spend_Threshold::sanitize_threshold( '' ) );
		$this->assertNull( Spend_Threshold::sanitize_threshold( null ) );
		$this->assertNull( Spend_Threshold::sanitize_threshold( 0 ) );
		$this->assertNull( Spend_Threshold::sanitize_threshold( -5 ) );
		$this->assertSame( 1.5, Spend_Threshold::sanitize_threshold( '1.5' ) );
		$this->assertSame( array(), Spend_Threshold::sanitize_plugin_thresholds( array( 'a/b.php' => '' ) ) );
		$this->assertSame(
			array( 'a/b.php' => 2.0 ),
			Spend_Threshold::sanitize_plugin_thresholds( array( 'a/b.php' => '2' ) )
		);
	}

	public function test_body_and_subject_helpers_include_estimate_disclaimer(): void {
		$body = Spend_Threshold::build_body( 'site', null, 10.0, 12.0, 'Aug 1 to Aug 10, 2026' );
		$this->assertStringContainsString( 'This estimate is based on logged token usage and configured rates. It is not a bill', $body );
		$this->assertStringContainsString( 'page=handl-aicac-activity', $body );
		$subject = Spend_Threshold::build_subject( 'site', null, 10.0, 12.0 );
		$this->assertStringContainsString( 'estimated spend alert', strtolower( $subject ) );
	}

	public function test_below_threshold_clears_fire_state_allowing_recross(): void {
		$policy = $this->persist_policy( array( 'spend_threshold_site' => 10.0 ) );

		// First cross.
		$this->seed_log_with_spend( 12.0 );
		Spend_Threshold::maybe_evaluate( $policy );
		$this->assertCount( 1, self::$mails );

		// Drop spend below threshold (replace log).
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
		$this->seed_log_with_spend( 1.0 );
		Spend_Threshold::maybe_evaluate( $policy );
		$this->assertCount( 1, self::$mails, 'Below threshold must not mail again' );

		// Cross again.
		$this->seed_log_with_spend( 20.0 );
		Spend_Threshold::maybe_evaluate( $policy );
		$this->assertCount( 2, self::$mails );
	}

	/**
	 * Persist a minimal policy so append_log_event audit rows see log_enabled.
	 *
	 * @param array<string,mixed> $extra
	 * @return array<string,mixed>
	 */
	private function persist_policy( array $extra ): array {
		$policy = array_merge(
			array(
				'log_enabled'             => true,
				'audit_only'              => false,
				'alert_email'             => 'ops@example.com',
				'est_usd_input_per_m'     => 2.50,
				'est_usd_output_per_m'    => 10.00,
				'est_usd_provider_rates'  => array(),
				'spend_threshold_site'    => null,
				'spend_threshold_plugins' => array(),
				'log_limit'               => 200,
			),
			$extra
		);
		// Direct option write — avoids save_policy evaluate side-effects during arrange.
		update_option( Plugin::OPTION_KEY, $policy, false );
		return $policy;
	}

	/**
	 * Seed retained log with one AI Client row whose tokens yield ~$usd at default rates.
	 *
	 * Default rates: $2.50 / 1M in + $10 / 1M out. Use output tokens only:
	 * usd = out / 1e6 * 10 → out = usd * 1e5.
	 */
	private function seed_log_with_spend( float $usd, string $plugin = 'demo/demo.php' ): void {
		$out_tokens = (int) round( $usd * 100000 );
		$log        = get_option( Plugin::LOG_OPTION_KEY, array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}
		$log[] = array(
			'ts'            => time(),
			'decision'      => 'allow',
			'plugin'        => $plugin,
			'provider'      => 'openai',
			'input_tokens'  => 0,
			'output_tokens' => $out_tokens,
		);
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
	}
}
