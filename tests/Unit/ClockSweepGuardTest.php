<?php
/**
 * Guard: fixed-date unit tests must stay green when wall clock is shifted.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class ClockSweepGuardTest extends TestCase {

	/** @var list<string> */
	private const FIXED_DATE_TESTS = array(
		'BudgetEnforcementTest',
		'BudgetPartCTest',
		'BudgetAccountingTest',
		'SpendForecastTest',
		'MonthlyReportTest',
		'UsageTrendsTest',
		'DailyTrendsTest',
		'QuietHoursTest',
		'PolicyBackupTest',
		'GovernanceDigestTest',
		'AnomalyAlertTest',
		'AlertHealthTest',
	);

	public function test_fixed_date_classes_pass_at_shifted_wall_clocks(): void {
		$root   = dirname( __DIR__, 2 );
		$php    = PHP_BINARY;
		$phpunit = $root . '/vendor/bin/phpunit';
		$filter  = implode( '|', self::FIXED_DATE_TESTS );
		$base    = time();

		foreach ( array( 0, 45, 400 ) as $days ) {
			$env = getenv();
			if ( ! is_array( $env ) ) {
				$env = array();
			}
			$env['HANDL_AICAC_TEST_NOW'] = (string) ( $base + ( $days * DAY_IN_SECONDS ) );

			$cmd = escapeshellarg( $php ) . ' -d memory_limit=512M '
				. escapeshellarg( $phpunit ) . ' --filter '
				. escapeshellarg( $filter ) . ' 2>&1';
			$descriptor = array(
				0 => array( 'pipe', 'r' ),
				1 => array( 'pipe', 'w' ),
				2 => array( 'pipe', 'w' ),
			);
			$proc = proc_open( $cmd, $descriptor, $pipes, $root, $env );
			$this->assertIsResource( $proc, 'proc_open failed for +' . $days . 'd' );
			fclose( $pipes[0] );
			$out = stream_get_contents( $pipes[1] );
			fclose( $pipes[1] );
			fclose( $pipes[2] );
			$code = proc_close( $proc );
			$this->assertSame(
				0,
				$code,
				'Fixed-date tests failed at wall clock +' . $days . "d:\n" . $out
			);
		}
	}
}
