<?php
/**
 * AICAC-FORECAST: month-end estimated-spend projection.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Spend_Forecast;
use PHPUnit\Framework\TestCase;

final class SpendForecastTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Spend_Forecast::WARNED_OPTION_KEY );
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
		delete_option( Spend_Forecast::WARNED_OPTION_KEY );
		parent::tearDown();
	}

	public function test_zero_activity_returns_null(): void {
		$policy = $this->persist_policy( array() );
		$this->assertNull( Spend_Forecast::compute( array(), $policy, strtotime( '2026-08-15 12:00:00 UTC' ) ) );
	}

	public function test_fewer_than_three_active_days_hides_projection(): void {
		$now  = strtotime( '2026-08-15 12:00:00 UTC' );
		$log  = array(
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-01 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 1.0, strtotime( '2026-08-02 10:00:00 UTC' ) ),
		);
		$policy = $this->persist_policy( array() );
		$this->assertNull( Spend_Forecast::compute( $log, $policy, $now ) );
	}

	public function test_linear_run_rate_math_mid_month(): void {
		$now = strtotime( '2026-08-10 12:00:00 UTC' ); // day 10 of 31-day August
		// $10 over days 1,2,3 → MTD 10; daily rate 10/10; projected 10/10*31 = 31
		$log = array(
			$this->spend_row( 'a/a.php', 4.0, strtotime( '2026-08-01 10:00:00 UTC' ) ),
			$this->spend_row( 'b/b.php', 3.0, strtotime( '2026-08-02 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 3.0, strtotime( '2026-08-03 10:00:00 UTC' ) ),
		);
		$policy = $this->persist_policy( array() );
		$out    = Spend_Forecast::compute( $log, $policy, $now );
		$this->assertNotNull( $out );
		$this->assertSame( '2026-08', $out['period_ym'] );
		$this->assertSame( 10, $out['days_elapsed'] );
		$this->assertSame( 31, $out['days_in_month'] );
		$this->assertSame( 3, $out['active_days'] );
		$this->assertEqualsWithDelta( 10.0, $out['mtd_site'], 0.0001 );
		$this->assertEqualsWithDelta( 31.0, $out['projected_site'], 0.0001 );
		$this->assertArrayHasKey( 'a/a.php', $out['plugins'] );
		$this->assertEqualsWithDelta( 7.0, $out['plugins']['a/a.php']['mtd'], 0.0001 );
		$this->assertEqualsWithDelta( 21.7, $out['plugins']['a/a.php']['projected'], 0.0001 ); // 7/10*31
	}

	public function test_excludes_prior_month_and_non_token_rows(): void {
		$now = strtotime( '2026-08-10 12:00:00 UTC' );
		$log = array(
			$this->spend_row( 'a/a.php', 5.0, strtotime( '2026-07-28 10:00:00 UTC' ) ), // prior month
			array(
				'ts'       => strtotime( '2026-08-01 10:00:00 UTC' ),
				'plugin'   => 'a/a.php',
				'channel'  => 'direct_http',
				'decision' => 'observe',
			),
			$this->spend_row( 'a/a.php', 2.0, strtotime( '2026-08-01 11:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 2.0, strtotime( '2026-08-02 11:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 2.0, strtotime( '2026-08-03 11:00:00 UTC' ) ),
		);
		$policy = $this->persist_policy( array() );
		$out    = Spend_Forecast::compute( $log, $policy, $now );
		$this->assertNotNull( $out );
		$this->assertEqualsWithDelta( 6.0, $out['mtd_site'], 0.0001 );
		$this->assertEqualsWithDelta( 18.6, $out['projected_site'], 0.0001 ); // 6/10*31
	}

	public function test_month_boundary_february(): void {
		$now = strtotime( '2026-02-10 12:00:00 UTC' ); // non-leap Feb = 28 days
		$log = array(
			$this->spend_row( 'a/a.php', 10.0, strtotime( '2026-02-01 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 10.0, strtotime( '2026-02-02 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 10.0, strtotime( '2026-02-03 10:00:00 UTC' ) ),
		);
		$policy = $this->persist_policy( array() );
		$out    = Spend_Forecast::compute( $log, $policy, $now );
		$this->assertNotNull( $out );
		$this->assertSame( 28, $out['days_in_month'] );
		$this->assertEqualsWithDelta( 84.0, $out['projected_site'], 0.0001 ); // 30/10*28
	}

	public function test_projection_warning_fires_once_per_month(): void {
		$now = strtotime( '2026-08-10 12:00:00 UTC' );
		$log = array(
			$this->spend_row( 'a/a.php', 20.0, strtotime( '2026-08-01 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 20.0, strtotime( '2026-08-02 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 20.0, strtotime( '2026-08-03 10:00:00 UTC' ) ),
		);
		// MTD 60 / 10 * 31 = 186 → crosses $100 site threshold.
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
		$policy = $this->persist_policy(
			array(
				'spend_threshold_site' => 100.0,
			)
		);

		Spend_Forecast::maybe_evaluate( $policy, $now );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'estimated-spend forecast', strtolower( self::$mails[0]['subject'] ) );
		$this->assertStringContainsString( 'Estimated month-end (current pace):', self::$mails[0]['message'] );
		$this->assertStringContainsString( 'estimated-spend forecast warning', self::$mails[0]['message'] );
		$this->assertStringContainsString( 'page=handl-aicac', self::$mails[0]['message'] );

		Spend_Forecast::maybe_evaluate( $policy, $now );
		$this->assertCount( 1, self::$mails );

		// Next calendar month → new warning allowed.
		$next = strtotime( '2026-09-10 12:00:00 UTC' );
		$log2 = array(
			$this->spend_row( 'a/a.php', 20.0, strtotime( '2026-09-01 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 20.0, strtotime( '2026-09-02 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 20.0, strtotime( '2026-09-03 10:00:00 UTC' ) ),
		);
		update_option( Plugin::LOG_OPTION_KEY, $log2, false );
		Spend_Forecast::maybe_evaluate( $policy, $next );
		$this->assertCount( 2, self::$mails );
	}

	public function test_no_warning_without_threshold_or_email_path(): void {
		$now = strtotime( '2026-08-10 12:00:00 UTC' );
		$log = array(
			$this->spend_row( 'a/a.php', 20.0, strtotime( '2026-08-01 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 20.0, strtotime( '2026-08-02 10:00:00 UTC' ) ),
			$this->spend_row( 'a/a.php', 20.0, strtotime( '2026-08-03 10:00:00 UTC' ) ),
		);
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
		$policy = $this->persist_policy( array( 'spend_threshold_site' => null ) );
		Spend_Forecast::maybe_evaluate( $policy, $now );
		$this->assertSame( array(), self::$mails );
	}

	/**
	 * Persist a minimal policy so evaluate/audit paths see log_enabled.
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
		update_option( Plugin::OPTION_KEY, $policy, false );

		return $policy;
	}

	/**
	 * Seed a token row that Cost::estimate_usd can price with default rates.
	 *
	 * Default rates: $2.50 / 1M in + $10 / 1M out. Use output tokens only:
	 * usd = out / 1e6 * 10 → out = usd * 1e5.
	 *
	 * @return array<string,mixed>
	 */
	private function spend_row( string $plugin, float $usd, int $ts ): array {
		$out_tokens = (int) round( $usd * 100000 );

		return array(
			'ts'            => $ts,
			'plugin'        => $plugin,
			'decision'      => 'allow',
			'operation'     => 'generate_text',
			'provider'      => 'openai',
			'input_tokens'  => 0,
			'output_tokens' => $out_tokens,
		);
	}
}
