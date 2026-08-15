<?php
/**
 * Unit tests for AICAC-CLI-APPLY (#195).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\CLI_Policy_Apply;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Policy_Snapshots;
use HandL\AICAC\Policy_Transfer;
use PHPUnit\Framework\TestCase;

final class CliPolicyApplyTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-cli-policy-apply.php';
		delete_option( Plugin::OPTION_KEY );
		delete_option( Policy_Snapshots::OPTION_KEY );
	}

	protected function tearDown(): void {
		delete_option( Plugin::OPTION_KEY );
		delete_option( Policy_Snapshots::OPTION_KEY );
		parent::tearDown();
	}

	/**
	 * @return array<string,mixed>
	 */
	private function seed_live( array $overrides = array() ): array {
		$base = array_merge(
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'kill_switch' => false,
				'plugins'     => array(
					'acme/a.php' => 'allow',
				),
			),
			$overrides
		);
		update_option( Plugin::OPTION_KEY, $base, false );
		return Policy::get_policy();
	}

	/**
	 * @param array<string,mixed> $policy Full or near-full policy (prefer get_policy shape).
	 */
	private function export_json( array $policy, string $site_url = 'https://example.test/' ): string {
		$export = Policy_Transfer::build_export( $policy, '1.5.0', '2026-08-13T00:00:00Z' );
		$export['site_url'] = $site_url;
		return Policy_Transfer::encode_export( $export );
	}

	public function test_prepare_rejects_malformed_json(): void {
		$result = CLI_Policy_Apply::prepare_apply( '{nope', 'https://example.test/', false );
		$this->assertFalse( $result['ok'] );
		$this->assertSame( 'invalid_json', $result['error'] );
	}

	public function test_prepare_rejects_foreign_export_missing_meta(): void {
		$result = CLI_Policy_Apply::prepare_apply( '{"default":"deny"}', 'https://example.test/', false );
		$this->assertFalse( $result['ok'] );
		$this->assertSame( 'missing_required_keys', $result['error'] );
	}

	public function test_prepare_rejects_site_mismatch_without_flag(): void {
		$live = $this->seed_live();
		$incoming = $live;
		$incoming['default'] = 'deny';
		$json = $this->export_json( $incoming, 'https://other.example/' );
		$result = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', false );
		$this->assertFalse( $result['ok'] );
		$this->assertSame( 'site_mismatch', $result['error'] );
	}

	public function test_prepare_allows_site_mismatch_with_flag(): void {
		$live = $this->seed_live();
		$incoming = $live;
		$incoming['default'] = 'deny';
		$json = $this->export_json( $incoming, 'https://other.example/' );
		$result = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', true );
		$this->assertTrue( $result['ok'] );
		$this->assertTrue( $result['has_changes'] );
	}

	public function test_dry_run_diff_matches_apply_result(): void {
		$live = $this->seed_live();
		$incoming = $live;
		$incoming['default']     = 'deny';
		$incoming['kill_switch'] = true;
		$json = $this->export_json( $incoming, 'https://example.test/' );

		$prepared = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', false );
		$this->assertTrue( $prepared['ok'] );
		$this->assertTrue( $prepared['has_changes'] );
		$joined = implode( "\n", $prepared['diff_lines'] );
		$this->assertStringContainsString( 'Default policy', $joined );
		$this->assertStringContainsString( 'Emergency stop', $joined );

		CLI_Policy_Apply::commit_apply( $prepared['policy'] );

		$live_after = Policy::get_policy();
		$this->assertSame( 'deny', $live_after['default'] );
		$this->assertTrue( ! empty( $live_after['kill_switch'] ) );

		$again = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', false );
		$this->assertTrue( $again['ok'] );
		$this->assertFalse( $again['has_changes'] );
	}

	public function test_parity_surfaces_policy_backup_email_enabled(): void {
		$live = $this->seed_live( array( 'policy_backup_email_enabled' => false ) );
		$incoming = $live;
		$incoming['policy_backup_email_enabled'] = true;
		$json = $this->export_json( $incoming );

		$prepared = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', false );
		$this->assertTrue( $prepared['ok'] );
		$this->assertTrue( $prepared['has_changes'] );
		$joined = implode( "\n", $prepared['diff_lines'] );
		$this->assertStringContainsString( 'Weekly rules backup email', $joined );

		$dry = CLI_Policy_Apply::execute( $json, 'https://example.test/', true, false, false );
		$this->assertSame( 1, $dry['exit_code'] );
		$this->assertFalse( $dry['wrote'] );

		$apply = CLI_Policy_Apply::execute( $json, 'https://example.test/', false, true, false );
		$this->assertSame( 0, $apply['exit_code'] );
		$this->assertTrue( $apply['wrote'] );
		$this->assertTrue( ! empty( Policy::get_policy()['policy_backup_email_enabled'] ) );
	}

	public function test_parity_surfaces_new_plugin_known_and_pending(): void {
		$live = $this->seed_live(
			array(
				'new_plugin_review_enabled' => true,
				'new_plugin_known'          => array( 'acme/a.php' ),
				'new_plugin_pending'        => array(),
			)
		);
		$incoming = $live;
		$incoming['new_plugin_known']   = array( 'acme/a.php', 'other/b.php' );
		$incoming['new_plugin_pending'] = array( 'fresh/c.php' => 1700000000 );
		$json = $this->export_json( $incoming );

		$prepared = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', false );
		$this->assertTrue( $prepared['ok'] );
		$this->assertTrue( $prepared['has_changes'] );
		$joined = implode( "\n", $prepared['diff_lines'] );
		$this->assertStringContainsString( 'Known plugins', $joined );
		$this->assertStringContainsString( 'Pending plugins', $joined );

		$apply = CLI_Policy_Apply::execute( $json, 'https://example.test/', false, true, false );
		$this->assertSame( 0, $apply['exit_code'] );
		$this->assertTrue( $apply['wrote'] );
		$after = Policy::get_policy();
		$this->assertContains( 'other/b.php', $after['new_plugin_known'] );
		$this->assertArrayHasKey( 'fresh/c.php', $after['new_plugin_pending'] );
	}

	public function test_parity_surfaces_plugin_notes_when_supported(): void {
		if ( ! class_exists( \HandL\AICAC\Rule_Notes::class ) ) {
			$this->markTestSkipped( 'Rule notes land after AICAC-NOTE (#125) merge.' );
		}
		if ( ! in_array( 'plugin_notes', Policy_Transfer::known_policy_keys(), true ) ) {
			$this->markTestSkipped( 'plugin_notes not yet a known transfer key.' );
		}

		$live = $this->seed_live();
		$incoming = $live;
		$incoming['plugin_notes'] = array(
			'acme/a.php' => 'Allow for checkout AI.',
		);
		$json = $this->export_json( $incoming );

		$prepared = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', false );
		$this->assertTrue( $prepared['ok'] );
		$this->assertTrue( $prepared['has_changes'] );
		$this->assertStringContainsString( 'Rule notes', implode( "\n", $prepared['diff_lines'] ) );
	}

	public function test_execute_identical_dry_run_exits_0_without_write(): void {
		$live = $this->seed_live();
		$json = $this->export_json( $live );

		$before = Policy::get_policy();
		$snaps  = count( Policy_Snapshots::all() );
		$result = CLI_Policy_Apply::execute( $json, 'https://example.test/', true, false, false );

		$this->assertSame( 0, $result['exit_code'] );
		$this->assertFalse( $result['wrote'] );
		$this->assertFalse( $result['has_changes'] );
		$this->assertSame( 'Dry run complete: the current policy matches this export.', $result['success'] ?? null );
		$this->assertContains( 'No policy differences found.', $result['logs'] );
		$this->assertSame( $before['default'], Policy::get_policy()['default'] );
		$this->assertSame( $snaps, count( Policy_Snapshots::all() ) );
	}

	public function test_secret_email_configured_to_configured_is_not_identical(): void {
		$live = $this->seed_live( array( 'alert_email' => 'ops@example.test' ) );
		$incoming = $live;
		$incoming['alert_email'] = 'security@example.test';
		$json = $this->export_json( $incoming );

		$prepared = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', false );
		$this->assertTrue( $prepared['ok'] );
		$this->assertTrue( $prepared['has_changes'] );
		$joined = implode( "\n", $prepared['diff_lines'] );
		$this->assertStringContainsString( 'Configured → Updated', $joined );
		$this->assertStringNotContainsString( 'ops@example.test', $joined );
		$this->assertStringNotContainsString( 'security@example.test', $joined );

		$dry = CLI_Policy_Apply::execute( $json, 'https://example.test/', true, false, false );
		$this->assertSame( 1, $dry['exit_code'] );
		$this->assertFalse( $dry['wrote'] );
		$this->assertSame( 'ops@example.test', Policy::get_policy()['alert_email'] );

		$apply = CLI_Policy_Apply::execute( $json, 'https://example.test/', false, true, false );
		$this->assertSame( 0, $apply['exit_code'] );
		$this->assertTrue( $apply['wrote'] );
		$this->assertSame( 'security@example.test', Policy::get_policy()['alert_email'] );
	}

	public function test_secret_webhook_configured_to_configured_is_not_identical(): void {
		$live = $this->seed_live(
			array(
				'alert_webhook_url' => 'https://hooks.example.test/old',
			)
		);
		$incoming = $live;
		$incoming['alert_webhook_url'] = 'https://hooks.example.test/new';
		$json = $this->export_json( $incoming );

		$prepared = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', false );
		$this->assertTrue( $prepared['ok'] );
		$this->assertTrue( $prepared['has_changes'] );
		$joined = implode( "\n", $prepared['diff_lines'] );
		$this->assertStringContainsString( 'Configured → Updated', $joined );
		$this->assertStringNotContainsString( 'hooks.example.test', $joined );

		$dry = CLI_Policy_Apply::execute( $json, 'https://example.test/', true, false, false );
		$this->assertSame( 1, $dry['exit_code'] );
		$this->assertFalse( $dry['wrote'] );

		$apply = CLI_Policy_Apply::execute( $json, 'https://example.test/', false, true, false );
		$this->assertSame( 0, $apply['exit_code'] );
		$this->assertTrue( $apply['wrote'] );
		$this->assertSame( 'https://hooks.example.test/new', Policy::get_policy()['alert_webhook_url'] );
	}

	public function test_same_count_known_plugins_uses_item_deltas(): void {
		$live = $this->seed_live(
			array(
				'new_plugin_review_enabled' => true,
				'new_plugin_known'          => array( 'acme/a.php', 'old/gone.php' ),
			)
		);
		$incoming = $live;
		$incoming['new_plugin_known'] = array( 'acme/a.php', 'new/here.php' );
		$json = $this->export_json( $incoming );

		$prepared = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', false );
		$this->assertTrue( $prepared['ok'] );
		$this->assertTrue( $prepared['has_changes'] );
		$joined = implode( "\n", $prepared['diff_lines'] );
		$this->assertStringContainsString( 'removed: old/gone.php', $joined );
		$this->assertStringContainsString( 'added: new/here.php', $joined );
		$this->assertStringNotContainsString( '2 known plugins → 2 known plugins', $joined );
	}

	public function test_same_count_plugin_notes_uses_updated_when_supported(): void {
		if ( ! class_exists( \HandL\AICAC\Rule_Notes::class ) ) {
			$this->markTestSkipped( 'Rule notes land after AICAC-NOTE (#125) merge.' );
		}
		if ( ! in_array( 'plugin_notes', Policy_Transfer::known_policy_keys(), true ) ) {
			$this->markTestSkipped( 'plugin_notes not yet a known transfer key.' );
		}

		$live = $this->seed_live();
		$incoming = $live;
		$incoming['plugin_notes'] = array(
			'acme/a.php' => 'Allow for checkout AI.',
		);
		update_option(
			Plugin::OPTION_KEY,
			array_merge(
				$live,
				array(
					'plugin_notes' => array(
						'acme/a.php' => 'Old note text.',
					),
				)
			),
			false
		);
		$live = Policy::get_policy();
		$incoming = $live;
		$incoming['plugin_notes'] = array(
			'acme/a.php' => 'Allow for checkout AI.',
		);
		$json = $this->export_json( $incoming );

		$prepared = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', false );
		$this->assertTrue( $prepared['ok'] );
		$this->assertTrue( $prepared['has_changes'] );
		$joined = implode( "\n", $prepared['diff_lines'] );
		$this->assertStringContainsString( 'Updated', $joined );
		$this->assertStringNotContainsString( 'Old note text', $joined );
		$this->assertStringNotContainsString( 'Allow for checkout AI', $joined );
	}

	public function test_execute_different_dry_run_exits_1_without_write(): void {
		$live = $this->seed_live();
		$incoming = $live;
		$incoming['default'] = 'deny';
		$json = $this->export_json( $incoming );

		$result = CLI_Policy_Apply::execute( $json, 'https://example.test/', true, true, false );
		$this->assertSame( 1, $result['exit_code'] );
		$this->assertFalse( $result['wrote'] );
		$this->assertTrue( $result['has_changes'] );
		$this->assertSame(
			'Dry run only: the policy would change. Run this command again without --dry-run and add --yes to apply it.',
			$result['warning'] ?? null
		);
		$this->assertSame( 'allow', Policy::get_policy()['default'] );
		$this->assertSame( array(), Policy_Snapshots::all() );
	}

	public function test_execute_apply_without_yes_exits_1_without_write(): void {
		$live = $this->seed_live();
		$incoming = $live;
		$incoming['default'] = 'deny';
		$json = $this->export_json( $incoming );

		$result = CLI_Policy_Apply::execute( $json, 'https://example.test/', false, false, false );
		$this->assertSame( 1, $result['exit_code'] );
		$this->assertFalse( $result['wrote'] );
		$this->assertSame(
			'Policy not applied. Use --dry-run to preview changes, or add --yes to confirm the update.',
			$result['error'] ?? null
		);
		$this->assertSame( 'allow', Policy::get_policy()['default'] );
		$this->assertSame( array(), Policy_Snapshots::all() );
	}

	public function test_execute_apply_with_yes_writes_and_snapshots(): void {
		$live = $this->seed_live();
		$incoming = $live;
		$incoming['default'] = 'deny';
		$json = $this->export_json( $incoming );

		$result = CLI_Policy_Apply::execute( $json, 'https://example.test/', false, true, false );
		$this->assertSame( 0, $result['exit_code'] );
		$this->assertTrue( $result['wrote'] );
		$this->assertSame(
			'Policy applied. A restore snapshot of the previous policy was saved.',
			$result['success'] ?? null
		);
		$this->assertSame( 'deny', Policy::get_policy()['default'] );
		$snaps = Policy_Snapshots::all();
		$this->assertNotEmpty( $snaps );
		$this->assertSame( 'allow', $snaps[0]['policy']['default'] ?? null );
	}

	public function test_execute_mismatched_site_exits_1_unless_allowed(): void {
		$live = $this->seed_live();
		$incoming = $live;
		$incoming['default'] = 'deny';
		$json = $this->export_json( $incoming, 'https://other.example/' );

		$blocked = CLI_Policy_Apply::execute( $json, 'https://example.test/', false, true, false );
		$this->assertSame( 1, $blocked['exit_code'] );
		$this->assertFalse( $blocked['wrote'] );
		$this->assertSame(
			'This export was created for a different site. If that is intentional, run the command again with --allow-mismatched-site.',
			$blocked['error'] ?? null
		);
		$this->assertSame( 'allow', Policy::get_policy()['default'] );

		$allowed = CLI_Policy_Apply::execute( $json, 'https://example.test/', false, true, true );
		$this->assertSame( 0, $allowed['exit_code'] );
		$this->assertTrue( $allowed['wrote'] );
		$this->assertSame( 'deny', Policy::get_policy()['default'] );
	}

	public function test_apply_creates_snapshot_via_save_policy(): void {
		$live = $this->seed_live();
		$incoming = $live;
		$incoming['default'] = 'deny';
		$json = $this->export_json( $incoming );
		$prepared = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', false );
		$this->assertTrue( $prepared['ok'] );

		CLI_Policy_Apply::commit_apply( $prepared['policy'] );

		$snaps = Policy_Snapshots::all();
		$this->assertNotEmpty( $snaps );
		$this->assertSame( 'allow', $snaps[0]['policy']['default'] ?? null );
	}

	public function test_malformed_never_partially_applies(): void {
		$this->seed_live();
		$before = Policy::get_policy();
		$result = CLI_Policy_Apply::prepare_apply( '{"plugin_version":"1.0","exported_at":"x"', 'https://example.test/', false );
		$this->assertFalse( $result['ok'] );
		$this->assertSame( 'allow', Policy::get_policy()['default'] );
		$this->assertSame( $before['default'], Policy::get_policy()['default'] );
		$this->assertSame( array(), Policy_Snapshots::all() );
	}

	public function test_site_url_normalization_ignores_trailing_slash(): void {
		$this->assertTrue(
			CLI_Policy_Apply::site_urls_match( 'https://Example.TEST/', 'https://example.test' )
		);
	}

	public function test_operator_copy_strings(): void {
		$this->assertSame(
			'This export was created for a different site. If that is intentional, run the command again with --allow-mismatched-site.',
			CLI_Policy_Apply::error_message( 'site_mismatch' )
		);
		$this->assertStringContainsString(
			'cannot be previewed safely: alert_email',
			CLI_Policy_Apply::error_message( 'non_comparable_applied', '', array( 'alert_email' ) )
		);
	}

	public function test_redacted_cli_export_json_has_no_email_url_or_note_text(): void {
		$note = 'cli-note-must-not-leak';
		$this->seed_live(
			array(
				'alert_email'       => 'qa-cli@handldigital.example',
				'alert_webhook_url' => 'https://hooks.example.test/cli-secret',
				'plugin_notes'      => array( 'acme/a.php' => $note ),
			)
		);

		$plain = CLI_Policy_Apply::export_current( false );
		$this->assertStringContainsString( 'qa-cli@handldigital.example', $plain['json'] );
		$this->assertArrayNotHasKey( 'redacted', $plain['export'] );

		$out = CLI_Policy_Apply::export_current( true );
		$this->assertTrue( $out['redacted'] );
		$this->assertTrue( $out['export']['redacted'] );
		$json = $out['json'];
		$this->assertDoesNotMatchRegularExpression(
			'/[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}/i',
			$json
		);
		$this->assertDoesNotMatchRegularExpression( '#https?://#i', $json );
		$this->assertStringNotContainsString( $note, $json );
		$this->assertStringContainsString( '"redacted": true', $json );
	}

	public function test_apply_redacted_export_skips_placeholders_and_keeps_live_secrets(): void {
		$live = $this->seed_live(
			array(
				'alert_email'       => 'keep-apply@handldigital.example',
				'alert_webhook_url' => 'https://hooks.live.test/keep-apply',
				'plugin_notes'      => array( 'acme/a.php' => 'live note stays' ),
			)
		);
		$incoming = $live;
		$incoming['default']           = 'deny';
		$incoming['alert_email']       = 'overwrite-me@handldigital.example';
		$incoming['alert_webhook_url'] = 'https://hooks.example.test/overwrite';
		$incoming['plugin_notes']      = array( 'acme/a.php' => 'imported note must not land' );
		$json = Policy_Transfer::encode_export(
			Policy_Transfer::build_export( $incoming, '1.5.0', '2026-08-15T00:00:00Z', true )
		);

		$prepared = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', true );
		$this->assertTrue( $prepared['ok'] );
		$this->assertSame( array( 'alert_email', 'alert_webhook_url', 'plugin_notes' ), $prepared['skipped'] );

		$result = CLI_Policy_Apply::execute( $json, 'https://example.test/', false, true, true );
		$this->assertSame( 0, $result['exit_code'] );
		$this->assertTrue( $result['wrote'] );
		$joined = implode( "\n", $result['logs'] );
		$this->assertStringContainsString( 'Skipped redacted fields:', $joined );

		$after = Policy::get_policy();
		$this->assertSame( 'deny', $after['default'] );
		$this->assertSame( 'keep-apply@handldigital.example', $after['alert_email'] );
		$this->assertSame( 'https://hooks.live.test/keep-apply', $after['alert_webhook_url'] );
		$this->assertSame( 'live note stays', $after['plugin_notes']['acme/a.php'] );
		$this->assertNotSame( Policy_Transfer::REDACT_PRESENT, $after['alert_email'] );
	}
}
