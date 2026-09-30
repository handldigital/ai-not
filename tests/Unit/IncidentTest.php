<?php
/**
 * AICAC-INCIDENT-TIMELINE (#276).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Incident;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

final class IncidentTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		unset( $GLOBALS['handl_aicac_test_filters'][ Incident::FILTER_EXPORT ] );
	}

	protected function tearDown(): void {
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		unset( $GLOBALS['handl_aicac_test_filters'][ Incident::FILTER_EXPORT ] );
		parent::tearDown();
	}

	public function test_empty_log_returns_no_incidents(): void {
		$this->assertSame( array(), Incident::group( array() ) );
		$this->assertSame( array(), Incident::list( array() ) );
	}

	public function test_storm_freeze_policy_save_group_into_one_incident(): void {
		$t   = 1_700_000_000;
		$log = array(
			$this->row( $t, 'acme/acme.php', 'allow' ),
			$this->row( $t + 30, 'acme/acme.php', 'deny', array( 'retry_storm' => true ) ),
			array(
				'ts'       => $t + 90,
				'decision' => 'freeze_started',
				'channel'  => 'freeze',
			),
			array(
				'ts'       => $t + 120,
				'decision' => 'policy_restored',
				'channel'  => 'policy_restore',
			),
			$this->row( $t + 150, 'acme/acme.php', 'deny' ),
			$this->row( $t + 40, 'other/other.php', 'deny' ),
		);

		$incidents = Incident::group( $log );
		$this->assertCount( 1, $incidents );
		$incident = $incidents[0];
		$this->assertSame( array( 'acme/acme.php' ), $incident['plugins'] );
		$this->assertSame( array( 'freeze_started', 'policy_save', 'retry_storm' ), $incident['reasons'] );
		$this->assertSame( $t, $incident['started_ts'] );
		$this->assertSame( $t + 150, $incident['ended_ts'] );
		$this->assertCount( 5, $incident['events'] );
		$plugins = array_map( array( Incident::class, 'row_plugin' ), $incident['events'] );
		$this->assertNotContains( 'other/other.php', $plugins );
		$types = array_column( $incident['events'], 'event_type' );
		$this->assertContains( 'retry_storm', $types );
		$this->assertContains( 'freeze_started', $types );
		$this->assertContains( 'policy_save', $types );
		$this->assertSame( $incident, Incident::get( $incident['id'], $log ) );
	}

	public function test_events_are_chronological_with_types_labeled(): void {
		$t   = 1_700_000_000;
		$log = array(
			$this->row( $t + 20, 'acme/acme.php', 'deny', array( 'retry_storm' => true ) ),
			$this->row( $t, 'acme/acme.php', 'allow' ),
		);
		$events = Incident::group( $log )[0]['events'];
		$this->assertSame( $t, $events[0]['ts'] );
		$this->assertSame( 'allow', $events[0]['event_type'] );
		$this->assertSame( $t + 20, $events[1]['ts'] );
		$this->assertSame( 'retry_storm', $events[1]['event_type'] );
		$this->assertStringContainsString( 'Retry storm', Incident::to_text( Incident::group( $log )[0] ) );
	}

	public function test_export_contains_every_row_and_detection_reason(): void {
		$t   = 1_700_000_000;
		$log = array(
			$this->row( $t, 'acme/acme.php', 'deny', array( 'retry_storm' => true ) ),
			array(
				'ts'       => $t + 10,
				'decision' => 'freeze_started',
				'channel'  => 'freeze',
			),
		);
		$incident = Incident::group( $log )[0];
		$json     = json_decode( Incident::export( $incident, 'json' ), true );
		$this->assertIsArray( $json );
		$this->assertSame( $incident['id'], $json['id'] );
		$this->assertCount( 2, $json['events'] );
		$this->assertContains( 'retry_storm', $json['reasons'] );
		$this->assertContains( 'freeze_started', $json['reasons'] );

		$text = Incident::export( $incident, 'text' );
		$this->assertStringContainsString( $incident['id'], $text );
		$this->assertStringContainsString( 'Retry storm', $text );
		$this->assertStringContainsString( 'Panic freeze started', $text );
		$this->assertStringContainsString( 'acme/acme.php', $text );
	}

	public function test_window_edges_are_inclusive_and_unrelated_plugins_stay_out(): void {
		$t      = 1_700_000_000;
		$window = 60;
		$policy = array( 'incident_window_seconds' => $window );
		$log    = array(
			$this->row( $t, 'acme/acme.php', 'deny', array( 'retry_storm' => true ) ),
			$this->row( $t + $window, 'acme/acme.php', 'allow' ),
			$this->row( $t + $window + 1, 'acme/acme.php', 'allow' ),
			$this->row( $t + 10, 'other/other.php', 'deny' ),
		);
		$incidents = Incident::group( $log, $policy );
		$this->assertCount( 1, $incidents );
		$ts = array_column( $incidents[0]['events'], 'ts' );
		$this->assertContains( $t, $ts );
		$this->assertContains( $t + $window, $ts );
		$this->assertNotContains( $t + $window + 1, $ts );
		$this->assertSame( array( 'acme/acme.php' ), $incidents[0]['plugins'] );
	}

	public function test_deny_burst_threshold_and_below_threshold_is_not_an_incident(): void {
		$t      = 1_700_000_000;
		$policy = array(
			'incident_window_seconds'         => 60,
			'incident_deny_burst_threshold'   => 3,
		);
		$below  = array(
			$this->row( $t, 'acme/acme.php', 'deny' ),
			$this->row( $t + 5, 'acme/acme.php', 'deny' ),
		);
		$this->assertSame( array(), Incident::group( $below, $policy ) );

		$burst = array(
			$this->row( $t, 'acme/acme.php', 'deny' ),
			$this->row( $t + 5, 'acme/acme.php', 'deny' ),
			$this->row( $t + 9, 'acme/acme.php', 'deny' ),
			$this->row( $t + 9, 'other/other.php', 'allow' ),
		);
		$incidents = Incident::group( $burst, $policy );
		$this->assertCount( 1, $incidents );
		$this->assertSame( array( 'deny_burst' ), $incidents[0]['reasons'] );
		$this->assertSame( array( 'acme/acme.php' ), $incidents[0]['plugins'] );
	}

	public function test_export_filter_hook_receives_payload(): void {
		$t        = 1_700_000_000;
		$incident = Incident::group(
			array( $this->row( $t, 'acme/acme.php', 'deny', array( 'retry_storm' => true ) ) )
		)[0];
		$seen = array();
		$GLOBALS['handl_aicac_test_filters'][ Incident::FILTER_EXPORT ] = static function ( $payload, $inc, $format ) use ( &$seen ) {
			$seen = array(
				'payload' => $payload,
				'id'      => $inc['id'] ?? '',
				'format'  => $format,
			);
			return 'HOOKED';
		};
		$this->assertSame( 'HOOKED', Incident::export( $incident, 'json' ) );
		$this->assertSame( 'json', $seen['format'] );
		$this->assertSame( $incident['id'], $seen['id'] );
	}

	public function test_list_reads_retained_log_option(): void {
		$t = 1_700_000_000;
		update_option(
			Plugin::LOG_OPTION_KEY,
			array( $this->row( $t, 'acme/acme.php', 'deny', array( 'retry_storm' => true ) ) ),
			false
		);
		$incidents = Incident::list();
		$this->assertCount( 1, $incidents );
		$this->assertSame( array( 'retry_storm' ), $incidents[0]['reasons'] );
	}

	/**
	 * @param array<string,mixed> $extra
	 * @return array<string,mixed>
	 */
	private function row( int $ts, string $plugin, string $decision, array $extra = array() ): array {
		return array_merge(
			array(
				'ts'       => $ts,
				'plugin'   => $plugin,
				'decision' => $decision,
			),
			$extra
		);
	}
}
