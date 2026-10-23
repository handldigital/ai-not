<?php
/**
 * AICAC-RECONCILE (#413).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Reconcile;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class ReconcileTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12 UTC.

	private const MONTH = '2026-10';

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Reconcile::reset_for_tests();
		update_option( 'admin_email', 'haktan+aicac-reconcile@handldigital.com' );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'              => 'allow',
				'log_enabled'          => true,
				'audit_only'           => false,
				'alert_email'          => 'haktan+aicac-reconcile@handldigital.com',
				'est_usd_input_per_m'  => 10.0,
				'est_usd_output_per_m' => 0.0,
			)
		);
		Reconcile::set_test_policy(
			array(
				'est_usd_input_per_m'  => 10.0,
				'est_usd_output_per_m' => 0.0,
			)
		);
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_test_filters'][ Reconcile::FILTER_THRESHOLD_PCT ] );
		$GLOBALS['handl_aicac_test_options'] = array();
		Reconcile::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * @param list<array<string,mixed>> $invoices Invoices.
	 */
	private function enable( float $threshold = 10.0, array $invoices = array() ): void {
		Reconcile::save_settings(
			array(
				'enabled'       => true,
				'threshold_pct' => $threshold,
				'invoices'      => $invoices,
			)
		);
	}

	/**
	 * One log row worth $10 per 1M input tokens.
	 *
	 * @return array<string,mixed>
	 */
	private function log_row( int $input_tokens, string $provider = 'openai', int $ts = self::NOW ): array {
		return array(
			'ts'            => $ts,
			'provider'      => $provider,
			'input_tokens'  => $input_tokens,
			'output_tokens' => 0,
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	private function invoice( float $amount, string $provider = 'openai', string $month = self::MONTH, string $note = '' ): array {
		return array(
			'provider' => $provider,
			'month'    => $month,
			'amount'   => $amount,
			'note'     => $note,
		);
	}

	public function test_defaults_off_save_defaults_deletes_and_noop_byte_identical(): void {
		$this->assertFalse( Reconcile::is_enabled() );
		$this->assertSame( Reconcile::defaults(), Reconcile::get_settings() );
		$this->assertSame( 10.0, Reconcile::defaults()['threshold_pct'] );
		$this->assertSame( array(), Reconcile::defaults()['invoices'] );

		$this->assertTrue( Reconcile::save_settings( array( 'enabled' => true, 'threshold_pct' => 10.0 ) ) );
		$this->assertTrue( Reconcile::is_enabled() );
		$before  = get_option( Reconcile::SETTINGS_OPTION );
		$changed = Reconcile::save_settings( array( 'enabled' => true, 'threshold_pct' => 10.0 ) );
		$this->assertFalse( $changed );
		$this->assertSame( $before, get_option( Reconcile::SETTINGS_OPTION ) );

		Reconcile::save_settings( Reconcile::defaults() );
		$this->assertFalse( (bool) get_option( Reconcile::SETTINGS_OPTION, false ) );
	}

	public function test_threshold_sanitize_and_filter(): void {
		$this->assertSame( 0.1, Reconcile::sanitize_threshold_pct( 0 ) );
		$this->assertSame( 0.1, Reconcile::sanitize_threshold_pct( -5 ) );
		$this->assertSame( 1000.0, Reconcile::sanitize_threshold_pct( 99999 ) );
		$this->assertSame( 10.0, Reconcile::sanitize_threshold_pct( 'nope' ) );
		$this->assertSame( 12.5, Reconcile::sanitize_threshold_pct( '12.5' ) );

		$this->enable( 25.0 );
		$this->assertSame( 25.0, Reconcile::threshold_pct() );
		$GLOBALS['handl_aicac_test_filters'][ Reconcile::FILTER_THRESHOLD_PCT ] = static function (): float {
			return 5.0;
		};
		$this->assertSame( 5.0, Reconcile::threshold_pct() );
	}

	public function test_invoice_sanitize_validates_and_caps(): void {
		$rows = Reconcile::sanitize_invoices(
			array(
				$this->invoice( 12.5, 'OpenAI ', '2026-10', 'ok' ),
				$this->invoice( -1.0 ),
				$this->invoice( 5.0, 'openai', '2026-13' ),
				$this->invoice( 5.0, 'openai', 'October' ),
				$this->invoice( 5.0, '', '2026-10' ),
				$this->invoice( 12.5, 'openai', '2026-10', 'ok' ), // Duplicate id.
				'junk',
			)
		);
		$this->assertCount( 1, $rows );
		$this->assertSame( 'openai', $rows[0]['provider'] );
		$this->assertSame( 12.5, $rows[0]['amount'] );
		$this->assertSame( 'ok', $rows[0]['note'] );
		$this->assertNotSame( '', $rows[0]['id'] );

		$many = array();
		for ( $i = 0; $i < 130; $i++ ) {
			$many[] = $this->invoice( (float) $i + 1, 'openai', self::MONTH, 'n' . $i );
		}
		$capped = Reconcile::sanitize_invoices( $many );
		$this->assertCount( Reconcile::INVOICE_CAP, $capped );
		$this->assertSame( 'n129', $capped[ Reconcile::INVOICE_CAP - 1 ]['note'] );
	}

	public function test_settings_from_form_adds_and_removes_invoices(): void {
		$this->enable( 10.0, array( $this->invoice( 40.0, 'anthropic', '2026-09' ) ) );
		$existing = Reconcile::get_invoices();
		$this->assertCount( 1, $existing );

		$next = Reconcile::settings_from_form(
			array(
				Reconcile::POST_ENABLED          => '1',
				Reconcile::POST_THRESHOLD_PCT    => '15',
				Reconcile::POST_NEW_PROVIDER     => 'OpenAI',
				Reconcile::POST_NEW_MONTH        => '2026-10',
				Reconcile::POST_NEW_AMOUNT       => '$1,200.50',
				Reconcile::POST_NEW_NOTE         => 'Oct invoice',
			),
			Reconcile::get_settings()
		);
		$this->assertTrue( $next['enabled'] );
		$this->assertSame( 15.0, $next['threshold_pct'] );
		$this->assertCount( 2, $next['invoices'] );
		$this->assertSame( 1200.5, $next['invoices'][1]['amount'] );

		Reconcile::save_settings( $next );
		$ids  = array( Reconcile::get_invoices()[0]['id'] );
		$next = Reconcile::settings_from_form(
			array(
				Reconcile::POST_ENABLED       => '1',
				Reconcile::POST_THRESHOLD_PCT => '15',
				Reconcile::POST_REMOVE        => $ids,
			),
			Reconcile::get_settings()
		);
		$this->assertCount( 1, $next['invoices'] );
		$this->assertSame( 'openai', $next['invoices'][0]['provider'] );
	}

	public function test_estimated_spend_filters_provider_and_calendar_month(): void {
		Reconcile::set_test_log(
			array(
				$this->log_row( 1_000_000, 'openai' ),
				$this->log_row( 500_000, 'openai' ),
				$this->log_row( 9_000_000, 'anthropic' ),
				$this->log_row( 9_000_000, 'openai', self::NOW - ( 40 * 86400 ) ), // September.
				array_merge( $this->log_row( 9_000_000, 'openai' ), array( 'channel' => 'budget' ) ), // Not activity.
			)
		);
		$this->assertSame( 15.0, Reconcile::estimated_spend( 'openai', self::MONTH ) );
		$this->assertSame( 90.0, Reconcile::estimated_spend( 'anthropic', self::MONTH ) );
		$this->assertSame( 0.0, Reconcile::estimated_spend( 'openai', 'bogus' ) );
	}

	public function test_variance_below_bill_flags_unmetered_usage(): void {
		$this->enable( 10.0, array( $this->invoice( 100.0 ) ) );
		Reconcile::set_test_log( array( $this->log_row( 5_000_000 ) ) ); // $50 estimated.

		$snap = Reconcile::snapshot( null, null, self::NOW );
		$this->assertSame( 1, $snap['over_count'] );
		$row = $snap['roster'][0];
		$this->assertSame( 50.0, $row['estimated'] );
		$this->assertSame( 100.0, $row['invoiced'] );
		$this->assertSame( -50.0, $row['delta_abs'] );
		$this->assertSame( -50.0, $row['delta_pct'] );
		$this->assertTrue( $row['over'] );
		$this->assertSame( Reconcile::DIRECTION_BELOW, $row['direction'] );
		$this->assertStringContainsString( 'unmetered', $row['direction_text'] );
		$this->assertSame( Reconcile::FRAMING, $snap['framing'] );
	}

	public function test_variance_above_bill_flags_stale_rates(): void {
		$this->enable( 10.0, array( $this->invoice( 100.0 ) ) );
		Reconcile::set_test_log( array( $this->log_row( 15_000_000 ) ) ); // $150 estimated.

		$snap = Reconcile::snapshot( null, null, self::NOW );
		$row  = $snap['roster'][0];
		$this->assertSame( 1, $snap['over_count'] );
		$this->assertSame( 50.0, $row['delta_pct'] );
		$this->assertSame( Reconcile::DIRECTION_ABOVE, $row['direction'] );
		$this->assertStringContainsString( 'stale rate', $row['direction_text'] );
	}

	public function test_variance_within_threshold_is_ok(): void {
		$this->enable( 10.0, array( $this->invoice( 100.0 ) ) );
		Reconcile::set_test_log( array( $this->log_row( 9_500_000 ) ) ); // $95, -5%.

		$snap = Reconcile::snapshot( null, null, self::NOW );
		$row  = $snap['roster'][0];
		$this->assertSame( 0, $snap['over_count'] );
		$this->assertFalse( $row['over'] );
		$this->assertSame( Reconcile::DIRECTION_WITHIN, $row['direction'] );
		$this->assertStringContainsString( 'within tolerance', $row['direction_text'] );
		$this->assertNull( $snap['worst'] );

		// Exactly at the threshold flags.
		Reconcile::set_test_log( array( $this->log_row( 9_000_000 ) ) ); // $90, -10%.
		$this->assertSame( 1, Reconcile::snapshot( null, null, self::NOW )['over_count'] );
	}

	public function test_zero_invoice_flags_only_when_estimate_positive(): void {
		$this->enable( 10.0, array( $this->invoice( 0.0 ) ) );

		Reconcile::set_test_log( array() );
		$snap = Reconcile::snapshot( null, null, self::NOW );
		$this->assertSame( 0, $snap['over_count'] );
		$this->assertNull( $snap['roster'][0]['delta_pct'] );

		Reconcile::set_test_log( array( $this->log_row( 1_000_000 ) ) );
		$snap = Reconcile::snapshot( null, null, self::NOW );
		$this->assertSame( 1, $snap['over_count'] );
		$this->assertSame( Reconcile::DIRECTION_ABOVE, $snap['roster'][0]['direction'] );
	}

	public function test_roster_orders_over_threshold_first_by_largest_gap(): void {
		$this->enable(
			10.0,
			array(
				$this->invoice( 100.0, 'anthropic' ),
				$this->invoice( 100.0, 'openai' ),
				$this->invoice( 100.0, 'google' ),
			)
		);
		Reconcile::set_test_log(
			array(
				$this->log_row( 10_000_000, 'anthropic' ), // $100 ok.
				$this->log_row( 5_000_000, 'openai' ),     // -$50.
				$this->log_row( 2_000_000, 'google' ),     // -$80 (worst).
			)
		);
		$roster = Reconcile::snapshot( null, null, self::NOW )['roster'];
		$this->assertSame( 'google', $roster[0]['provider'] );
		$this->assertSame( 'openai', $roster[1]['provider'] );
		$this->assertSame( 'anthropic', $roster[2]['provider'] );
	}

	public function test_alert_fires_once_and_rearms_when_cleared(): void {
		$this->enable( 10.0, array( $this->invoice( 100.0 ) ) );
		Reconcile::set_test_log( array( $this->log_row( 5_000_000 ) ) );

		$this->assertTrue( Reconcile::maybe_fire_alerts( self::NOW ) );
		$mails = Reconcile::test_mails();
		$this->assertNotEmpty( $mails );
		$this->assertStringContainsString( '[RECONCILE]', $mails[0]['subject'] );
		$this->assertStringContainsString( 'openai', $mails[0]['subject'] );
		$this->assertStringContainsString( self::MONTH, $mails[0]['body'] );
		$this->assertStringContainsString( 'unmetered', $mails[0]['body'] );
		$this->assertStringContainsString( 'never changes cost estimates', $mails[0]['body'] );
		$this->assertTrue( Reconcile::is_alerted() );
		$this->assertCount( 1, Reconcile::get_state()['history'] );

		$before = count( Reconcile::test_mails() );
		$this->assertFalse( Reconcile::maybe_fire_alerts( self::NOW ) );
		$this->assertCount( $before, Reconcile::test_mails() );

		// Clear variance -> re-arm.
		Reconcile::set_test_log( array( $this->log_row( 10_000_000 ) ) );
		$this->assertFalse( Reconcile::maybe_fire_alerts( self::NOW + 10 ) );
		$this->assertFalse( Reconcile::is_alerted() );

		// New variance can alert again.
		Reconcile::set_test_log( array( $this->log_row( 20_000_000 ) ) );
		$this->assertTrue( Reconcile::maybe_fire_alerts( self::NOW + 20 ) );
		$this->assertCount( $before + 1, Reconcile::test_mails() );
		$this->assertCount( 2, Reconcile::get_state()['history'] );
	}

	public function test_no_alert_when_under_threshold_or_disabled(): void {
		$this->enable( 10.0, array( $this->invoice( 100.0 ) ) );
		Reconcile::set_test_log( array( $this->log_row( 10_200_000 ) ) );
		$this->assertFalse( Reconcile::maybe_fire_alerts( self::NOW ) );
		$this->assertCount( 0, Reconcile::test_mails() );

		Reconcile::save_settings(
			array(
				'enabled'       => false,
				'threshold_pct' => 10.0,
				'invoices'      => array( $this->invoice( 100.0 ) ),
			)
		);
		Reconcile::set_test_log( array() );
		$this->assertFalse( Reconcile::maybe_fire_alerts( self::NOW ) );
		$this->assertCount( 0, Reconcile::test_mails() );
	}

	public function test_history_is_capped(): void {
		$history = array();
		for ( $i = 1; $i <= 60; $i++ ) {
			$history[] = array( 'ts' => self::NOW + $i, 'over_count' => 1 );
		}
		$state = Reconcile::sanitize_state( array( 'alerted' => true, 'history' => $history ) );
		$this->assertCount( Reconcile::HISTORY_CAP, $state['history'] );
		$this->assertSame( self::NOW + 60, $state['history'][ Reconcile::HISTORY_CAP - 1 ]['ts'] );
	}

	public function test_csv_contains_roster_and_framing(): void {
		$this->enable( 10.0, array( $this->invoice( 100.0, 'openai', self::MONTH, '=cmd' ) ) );
		Reconcile::set_test_log( array( $this->log_row( 5_000_000 ) ) );

		$csv = Reconcile::csv_for_snapshot( Reconcile::snapshot( null, null, self::NOW ) );
		$this->assertStringContainsString( 'section,id,provider,month,estimated_usd,invoiced_usd', $csv );
		$this->assertStringContainsString( 'summary', $csv );
		$this->assertStringContainsString( 'variance', $csv );
		$this->assertStringContainsString( 'openai', $csv );
		$this->assertStringContainsString( self::MONTH, $csv );
		$this->assertStringContainsString( '-50.0000', $csv );
		$this->assertStringContainsString( Reconcile::DIRECTION_BELOW, $csv );
		$this->assertStringContainsString( Reconcile::FRAMING, $csv );
		$this->assertStringContainsString( "'=cmd", $csv );
	}

	public function test_print_html_lists_roster(): void {
		$this->enable( 10.0, array( $this->invoice( 100.0 ) ) );
		Reconcile::set_test_log( array( $this->log_row( 5_000_000 ) ) );
		$html = Reconcile::build_print_html( Reconcile::snapshot( null, null, self::NOW ) );
		$this->assertStringContainsString( 'openai', $html );
		$this->assertStringContainsString( 'unmetered', $html );
	}

	public function test_writes_confined_to_own_options(): void {
		$this->enable( 10.0, array( $this->invoice( 100.0 ) ) );
		update_option( Plugin::LOG_OPTION_KEY, array( $this->log_row( 5_000_000 ) ), false );

		$before_log    = get_option( Plugin::LOG_OPTION_KEY );
		$before_policy = get_option( Plugin::OPTION_KEY );
		$before_keys   = array_keys( $GLOBALS['handl_aicac_test_options'] );

		Reconcile::set_test_policy( null );
		Reconcile::set_test_log( null );
		$snap = Reconcile::snapshot( null, null, self::NOW );
		$this->assertSame( 1, $snap['over_count'] );
		$this->assertTrue( Reconcile::maybe_fire_alerts( self::NOW ) );

		$this->assertSame( $before_log, get_option( Plugin::LOG_OPTION_KEY ) );
		$this->assertSame( $before_policy, get_option( Plugin::OPTION_KEY ) );
		$this->assertNotFalse( get_option( Reconcile::SETTINGS_OPTION, false ) );
		$this->assertNotFalse( get_option( Reconcile::STATE_OPTION, false ) );

		// Only our state option plus Alerts' own delivery-health bookkeeping (via safe_wp_mail).
		$new_keys = array_values( array_diff( array_keys( $GLOBALS['handl_aicac_test_options'] ), $before_keys ) );
		sort( $new_keys );
		$this->assertSame( array( 'handl_aicac_alert_health', Reconcile::STATE_OPTION ), $new_keys );
	}
}
