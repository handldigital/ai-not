<?php
/**
 * AICAC-BLOCKED-UX Phase 1 — capture layer (context + returned error).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Audit_Export;
use HandL\AICAC\Plugin_Profile;
use HandL\AICAC\Policy;
use HandL\AICAC\Rest;
use PHPUnit\Framework\TestCase;

final class BlockedUxPhase1Test extends TestCase {

	public function test_detect_request_context_priority(): void {
		$this->assertSame( 'cron', Policy::detect_request_context( array( 'doing_cron' => true, 'rest' => true, 'is_admin' => true ) ) );
		$this->assertSame( 'rest', Policy::detect_request_context( array( 'doing_cron' => false, 'rest' => true, 'is_admin' => true ) ) );
		$this->assertSame( 'admin', Policy::detect_request_context( array( 'doing_cron' => false, 'rest' => false, 'is_admin' => true ) ) );
		$this->assertSame( 'frontend', Policy::detect_request_context( array( 'doing_cron' => false, 'rest' => false, 'is_admin' => false ) ) );
		$this->assertSame( 'unknown', Policy::detect_request_context( array( 'doing_cli' => true ) ) );
	}

	public function test_legacy_rows_read_unknown_never_frontend(): void {
		$this->assertSame( 'unknown', Policy::request_context_from_row( array( 'decision' => 'deny' ) ) );
		$this->assertSame( 'unknown', Policy::normalize_request_context( '' ) );
		$this->assertSame( 'unknown', Policy::normalize_request_context( 'bogus' ) );
		$this->assertSame( 'unknown', Policy::normalize_request_context( null ) );
		$this->assertNotSame( 'frontend', Policy::request_context_from_row( array() ) );
	}

	/**
	 * @return list<array{0:string,1:string}>
	 */
	public function contextProvider(): array {
		return array(
			array( 'frontend', 'Prompt execution was prevented by a filter.' ),
			array( 'admin', 'Prompt execution was prevented by a filter.' ),
			array( 'cron', 'Prompt execution was prevented by a filter.' ),
			array( 'rest', 'Prompt execution was prevented by a filter.' ),
		);
	}

	/**
	 * @dataProvider contextProvider
	 */
	public function test_csv_and_rest_expose_each_context_with_returned_error( string $context, string $error ): void {
		$row = array(
			'ts'              => 1_700_000_100,
			'decision'        => 'deny',
			'plugin'          => 'acme/acme.php',
			'operation'       => 'generate_text',
			'request_context' => $context,
			'returned_error'  => $error,
		);

		$cells = Audit_Export::format_row( $row, array(), array(), array() );
		$this->assertSame( $context, $cells[12] );
		$this->assertSame( $error, $cells[13] );

		$csv = Audit_Export::build_csv( array( $row ), array(
			'decision'  => '',
			'operation' => '',
			'provider'  => '',
			'model'     => '',
			'plugin'    => '',
		), array(), array() );
		$this->assertStringContainsString( 'Request context', $csv );
		$this->assertStringContainsString( 'Returned error', $csv );
		$this->assertStringContainsString( $context, $csv );
		$this->assertStringContainsString( 'Prompt execution was prevented by a filter.', $csv );

		$policy  = array( 'log_enabled' => true );
		$payload = Rest::build_activity_summary( $policy, array( $row ), 'all', 1_700_000_200 );
		$this->assertSame( 'ok', $payload['status'] );
		$this->assertSame( 1, $payload['denials_by_context'][ $context ] );
		$this->assertCount( 1, $payload['recent_denials'] );
		$this->assertSame( $context, $payload['recent_denials'][0]['request_context'] );
		$this->assertSame( $error, $payload['recent_denials'][0]['returned_error'] );
	}

	public function test_plugin_profile_what_they_saw_groups_by_context(): void {
		$plugin = 'acme/acme.php';
		$msg    = Policy::caller_deny_error_message();
		$log    = array(
			array(
				'ts'              => 100,
				'plugin'          => $plugin,
				'decision'        => 'deny',
				'operation'       => 'generate_text',
				'request_context' => 'frontend',
				'returned_error'  => $msg,
			),
			array(
				'ts'              => 200,
				'plugin'          => $plugin,
				'decision'        => 'deny',
				'operation'       => 'generate_text',
				'request_context' => 'admin',
				'returned_error'  => $msg,
			),
			array(
				'ts'              => 300,
				'plugin'          => $plugin,
				'decision'        => 'deny',
				'operation'       => 'generate_text',
				'request_context' => 'cron',
				'returned_error'  => $msg,
			),
			array(
				'ts'              => 400,
				'plugin'          => $plugin,
				'decision'        => 'deny',
				'operation'       => 'generate_text',
				'request_context' => 'rest',
				'returned_error'  => $msg,
			),
			// Legacy deny — must land in unknown, never frontend.
			array(
				'ts'       => 50,
				'plugin'   => $plugin,
				'decision' => 'deny',
				'operation'=> 'generate_text',
			),
			array(
				'ts'       => 500,
				'plugin'   => $plugin,
				'decision' => 'allow',
				'operation'=> 'generate_text',
			),
		);

		$profile = Plugin_Profile::build(
			$plugin,
			$log,
			array( 'log_enabled' => true, 'default' => 'allow', 'plugins' => array(), 'operations' => array() ),
			array(),
			array()
		);

		$this->assertArrayHasKey( 'what_they_saw', $profile );
		$saw = $profile['what_they_saw'];
		$this->assertSame( 5, $saw['denial_count'] );
		$this->assertCount( 1, $saw['by_context']['frontend'] );
		$this->assertCount( 1, $saw['by_context']['admin'] );
		$this->assertCount( 1, $saw['by_context']['cron'] );
		$this->assertCount( 1, $saw['by_context']['rest'] );
		$this->assertCount( 1, $saw['by_context']['unknown'] );
		$this->assertSame( $msg, $saw['by_context']['frontend'][0]['returned_error'] );
		$this->assertSame( 50, $saw['by_context']['unknown'][0]['ts'] );
	}

	public function test_rest_legacy_deny_counts_as_unknown_context(): void {
		$now = 1_700_000_000;
		$log = array(
			array(
				'ts'       => $now - 10,
				'decision' => 'deny',
				'plugin'   => 'acme/acme.php',
			),
		);
		$payload = Rest::build_activity_summary( array( 'log_enabled' => true ), $log, '7d', $now );
		$this->assertSame( 1, $payload['denials_by_context']['unknown'] );
		$this->assertSame( 0, $payload['denials_by_context']['frontend'] );
		$this->assertSame( 'unknown', $payload['recent_denials'][0]['request_context'] );
	}
}
