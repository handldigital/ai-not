<?php
/**
 * AICAC-NOTE (#125): per-rule why notes.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Audit_Export;
use HandL\AICAC\Audit_Evidence;
use HandL\AICAC\Policy;
use HandL\AICAC\Policy_Transfer;
use HandL\AICAC\Plugin;
use HandL\AICAC\Rule_Notes;
use HandL\AICAC\Temp_Allow;
use PHPUnit\Framework\TestCase;

final class RuleNotesTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
	}

	protected function tearDown(): void {
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		parent::tearDown();
	}

	public function test_sanitize_trims_and_caps_length(): void {
		$long = str_repeat( 'a', Rule_Notes::MAX_LENGTH + 40 );
		$out  = Rule_Notes::sanitize_plugin_notes(
			array(
				'a/a.php' => '  hello  ',
				'b/b.php' => $long,
				'c/c.php' => '   ',
				''        => 'x',
			)
		);
		$this->assertSame( 'hello', $out['a/a.php'] );
		$this->assertSame( Rule_Notes::MAX_LENGTH, strlen( $out['b/b.php'] ) );
		$this->assertArrayNotHasKey( 'c/c.php', $out );
	}

	public function test_normalize_drops_notes_without_explicit_rule(): void {
		$policy = array(
			'plugins'      => array( 'a/a.php' => 'allow' ),
			'plugin_notes' => array(
				'a/a.php' => 'keep me',
				'b/b.php' => 'orphan',
			),
		);
		$out = Rule_Notes::normalize_against_plugins( $policy );
		$this->assertSame( array( 'a/a.php' => 'keep me' ), $out['plugin_notes'] );
	}

	public function test_survives_rule_edit_clears_on_delete(): void {
		$policy = array(
			'plugins'        => array( 'a/a.php' => 'allow' ),
			'plugin_expires' => array(),
			'plugin_notes'   => array( 'a/a.php' => 'finance team request' ),
			'default'        => 'deny',
			'log_enabled'    => true,
		);
		Policy::save_policy( $policy );
		$saved = Policy::get_policy();
		$this->assertSame( 'finance team request', Rule_Notes::get( $saved, 'a/a.php' ) );

		// Edit allow → deny keeps note.
		$this->assertTrue( Policy::set_plugin_rule( 'a/a.php', 'deny' ) );
		$saved = Policy::get_policy();
		$this->assertSame( 'deny', $saved['plugins']['a/a.php'] );
		$this->assertSame( 'finance team request', Rule_Notes::get( $saved, 'a/a.php' ) );

		// Clear rule deletes note.
		$this->assertTrue( Policy::set_plugin_rule( 'a/a.php', '' ) );
		$saved = Policy::get_policy();
		$this->assertArrayNotHasKey( 'a/a.php', $saved['plugins'] ?? array() );
		$this->assertSame( '', Rule_Notes::get( $saved, 'a/a.php' ) );
	}

	public function test_temp_allow_expiry_clears_note(): void {
		$now    = time();
		$plugin = 'temp/t.php';
		$policy = array(
			'plugins'        => array( $plugin => 'allow' ),
			'plugin_expires' => array( $plugin => $now - 10 ),
			'plugin_notes'   => array( $plugin => 'temp vendor demo' ),
			'default'        => 'deny',
			'log_enabled'    => false,
			'alert_on_deny'  => false,
			'alert_on_shadow'=> false,
		);
		Policy::save_policy( $policy );
		$result = Temp_Allow::sweep_expired( Policy::get_policy(), $now );
		$this->assertContains( $plugin, $result['removed'] );
		$this->assertSame( '', Rule_Notes::get( $result['policy'], $plugin ) );
	}

	public function test_csv_includes_rule_note_from_row_not_live_policy(): void {
		$log = array(
			array(
				'ts'        => 100,
				'decision'  => 'deny',
				'plugin'    => 'a/a.php',
				'operation' => 'text-generation',
				'rule_note' => 'blocked for compliance',
			),
		);
		$filters = array(
			'decision'  => '',
			'operation' => '',
			'provider'  => '',
			'model'     => '',
			'plugin'    => '',
		);
		$empty = Audit_Export::build_csv( $log, $filters, array(), array( 'plugins' => array() ), array() );
		// Column appears because the row stores a note — even with empty live policy notes.
		$header = explode( "\n", $empty )[0];
		$this->assertStringContainsString( 'Rule note', $header );
		$this->assertStringContainsString( 'blocked for compliance', $empty );

		$no_stored = array(
			array(
				'ts'       => 100,
				'decision' => 'deny',
				'plugin'   => 'a/a.php',
			),
		);
		$policy = array(
			'plugins'      => array( 'a/a.php' => 'deny' ),
			'plugin_notes' => array( 'a/a.php' => 'live policy only' ),
		);
		$without = Audit_Export::build_csv( $no_stored, $filters, array(), $policy, array() );
		$this->assertStringNotContainsString( 'Rule note', explode( "\n", $without )[0] );
		$this->assertStringNotContainsString( 'live policy only', $without );
	}

	public function test_activity_note_survives_rule_edit_and_delete(): void {
		$policy = array(
			'plugins'      => array( 'a/a.php' => 'deny' ),
			'plugin_notes' => array( 'a/a.php' => 'note A' ),
			'default'      => 'allow',
			'log_enabled'  => true,
			'kill_switch'  => false,
		);
		$note_a = Rule_Notes::snapshot_for_event( $policy, 'a/a.php', 'plugin' );
		$this->assertSame( 'note A', $note_a );

		$row = array(
			'ts'           => 100,
			'decision'     => 'deny',
			'plugin'       => 'a/a.php',
			'denial_reason'=> 'plugin',
			'rule_note'    => $note_a,
		);

		// Edit live note to B — historical row stays A.
		$policy['plugin_notes']['a/a.php'] = 'note B';
		$this->assertSame( 'note A', Rule_Notes::from_activity_row( $row ) );
		$csv = Audit_Export::build_csv(
			array( $row ),
			array(
				'decision'  => '',
				'operation' => '',
				'provider'  => '',
				'model'     => '',
				'plugin'    => '',
			),
			array(),
			$policy,
			array()
		);
		$this->assertStringContainsString( 'note A', $csv );
		$this->assertStringNotContainsString( 'note B', $csv );

		// Remove rule — historical row stays A.
		unset( $policy['plugins']['a/a.php'], $policy['plugin_notes']['a/a.php'] );
		$this->assertSame( 'note A', Rule_Notes::from_activity_row( $row ) );
		$csv2 = Audit_Export::build_csv(
			array( $row ),
			array(
				'decision'  => '',
				'operation' => '',
				'provider'  => '',
				'model'     => '',
				'plugin'    => '',
			),
			array(),
			$policy,
			array()
		);
		$this->assertStringContainsString( 'note A', $csv2 );
	}

	public function test_higher_priority_decision_does_not_inherit_plugin_note(): void {
		$policy = array(
			'plugins'      => array( 'a/a.php' => 'allow' ),
			'plugin_notes' => array( 'a/a.php' => 'finance approved' ),
			'default'      => 'deny',
		);
		$this->assertSame( '', Rule_Notes::snapshot_for_event( $policy, 'a/a.php', 'kill_switch' ) );
		$this->assertSame( '', Rule_Notes::snapshot_for_event( $policy, 'a/a.php', 'budget' ) );
		$this->assertSame( '', Rule_Notes::snapshot_for_event( $policy, 'a/a.php', 'role' ) );
		$this->assertSame( '', Rule_Notes::snapshot_for_event( $policy, 'a/a.php', 'capability_family' ) );
		$this->assertSame( '', Rule_Notes::snapshot_for_event( $policy, 'a/a.php', 'tool_armed' ) );
		$this->assertSame( '', Rule_Notes::snapshot_for_event( $policy, 'a/a.php', 'quiet_hours' ) );

		// Explicit allow with empty reason snapshots the note.
		$this->assertSame( 'finance approved', Rule_Notes::snapshot_for_event( $policy, 'a/a.php', '' ) );

		$deny_policy = array(
			'plugins'      => array( 'a/a.php' => 'deny' ),
			'plugin_notes' => array( 'a/a.php' => 'blocked' ),
		);
		$this->assertSame( 'blocked', Rule_Notes::snapshot_for_event( $deny_policy, 'a/a.php', 'plugin' ) );
		$this->assertSame( '', Rule_Notes::snapshot_for_event( $deny_policy, 'a/a.php', 'budget' ) );
	}

	public function test_evidence_snapshot_includes_note_and_conditional_rule_note_column(): void {
		$policy = array(
			'plugins'        => array( 'a/a.php' => 'deny' ),
			'plugin_notes'   => array( 'a/a.php' => 'legal hold' ),
			'plugin_expires' => array(),
			'operations'     => array(),
		);
		$rows = Audit_Evidence::plugin_rules_snapshot( $policy, array( 'a/a.php' => array( 'Name' => 'A' ) ), time() );
		$this->assertSame( 'legal hold', $rows[0]['note'] );

		$html = Audit_Evidence::build_html(
			Audit_Evidence::build_report_data( $policy, array(), '7d', time(), array( 'a/a.php' => array( 'Name' => 'A' ) ) )
		);
		$this->assertStringContainsString( 'Rule note', $html );
		$this->assertStringContainsString( 'legal hold', $html );

		$empty_policy = array(
			'plugins'      => array( 'a/a.php' => 'allow' ),
			'plugin_notes' => array(),
			'operations'   => array(),
		);
		$html2 = Audit_Evidence::build_html(
			Audit_Evidence::build_report_data( $empty_policy, array(), '7d', time(), array( 'a/a.php' => array( 'Name' => 'A' ) ) )
		);
		$this->assertStringNotContainsString( '>Rule note<', $html2 );
	}

	public function test_export_import_round_trips_plugin_notes(): void {
		$this->assertContains( 'plugin_notes', Policy_Transfer::known_policy_keys() );
		$policy = array(
			'default'      => 'deny',
			'plugins'      => array( 'a/a.php' => 'allow' ),
			'plugin_notes' => array( 'a/a.php' => 'imported why' ),
		);
		$export = Policy_Transfer::build_export( $policy, '1.9.9', '2026-08-13T00:00:00Z' );
		$this->assertSame( 'imported why', $export['plugin_notes']['a/a.php'] );
		$json   = Policy_Transfer::encode_export( $export );
		$parsed = Policy_Transfer::parse_import( $json );
		$this->assertTrue( $parsed['ok'] );
		$for_save = Policy_Transfer::policy_for_save( $parsed['policy'] );
		$this->assertSame( 'imported why', $for_save['plugin_notes']['a/a.php'] );
	}

	public function test_truncate_for_display_empty_stays_empty(): void {
		$this->assertSame( '', Rule_Notes::truncate_for_display( '' ) );
		$this->assertSame( 'short', Rule_Notes::truncate_for_display( 'short' ) );
		$long = str_repeat( 'x', 80 );
		$out  = Rule_Notes::truncate_for_display( $long, 60 );
		$this->assertLessThan( 80, strlen( $out ) );
		$this->assertStringEndsWith( '…', $out );
	}
}
