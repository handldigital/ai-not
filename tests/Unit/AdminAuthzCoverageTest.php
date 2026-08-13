<?php
/**
 * Static verification that admin state-mutating handlers keep nonce + capability coverage.
 *
 * AICAC-3 (#21 / #22) plus AICAC-102 transfer actions, AICAC-104 test webhook,
 * and AICAC-25 test email: locks the inventory of POST action dispatches in
 * class-handl-aicac-admin.php. Does not exercise WordPress runtime authz — it
 * fails if a new handl_aicac_action branch appears without updating the approved
 * inventory (and without a matching check_admin_referer), or if the shared
 * manage_options gate is removed.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class AdminAuthzCoverageTest extends TestCase {

	/**
	 * Approved POST handl_aicac_action dispatch inventory.
	 * Keep in sync with mutating_action_provider().
	 *
	 * @var list<string>
	 */
	private const APPROVED_DISPATCH_ACTIONS = array(
		'bulk_plugin_rules',
		'cancel_alert_snooze',
		'compare_latest_backup',
		'compare_rules_preview',
		'download_latest_backup',
		'export_audit_report',
		'export_log',
		'export_rules',
		'import_rules_confirm',
		'import_rules_preview',
		'keyscan_run',
		'onboard_dismiss',
		'onboard_reopen',
		'onboard_step',
		'onboard_test_email',
		'policy_backup_save',
		'policy_check_add',
		'policy_check_delete',
		'policy_checks_save_confirm',
		'policy_restore_confirm',
		'policy_restore_preview',
		'preset_apply_confirm',
		'preset_preview',
		'quick_rule',
		'renew_temp_allow',
		'save',
		'send_denial_digest',
		'send_test_email',
		'send_test_webhook',
		'simulate_policy',
		'snooze_alerts',
		'undo_quick_rule',
	);

	private string $source;

	/** @var list<string> */
	private array $lines;

	protected function setUp(): void {
		$path = HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php';
		$this->assertFileExists( $path );
		$raw = file_get_contents( $path );
		$this->assertNotFalse( $raw );
		$this->source = $raw;
		$this->lines  = preg_split( '/\R/', $raw ) ?: array();
	}

	/**
	 * Shared capability wrapper must precede POST mutation handling.
	 */
	public function test_shared_manage_options_gate_exists_before_post_dispatch(): void {
		$cap_line  = $this->first_line_matching( '/current_user_can\s*\(\s*[\'"]manage_options[\'"]\s*\)/' );
		$post_line = $this->first_line_matching( '/\$_POST\s*\[\s*[\'"]handl_aicac_action[\'"]\s*\]/' );

		$this->assertNotNull( $cap_line, 'Shared current_user_can( manage_options ) gate not found' );
		$this->assertNotNull( $post_line, 'POST handl_aicac_action dispatch not found' );
		$this->assertLessThan(
			$post_line,
			$cap_line,
			'Capability gate must run before POST action handling'
		);
	}

	/**
	 * Menu registration must also require manage_options (WordPress page gate).
	 */
	public function test_options_page_registered_with_manage_options(): void {
		$this->assertMatchesRegularExpression(
			'/add_options_page\s*\([\s\S]*?[\'"]manage_options[\'"]/',
			$this->source,
			'add_options_page must register manage_options capability'
		);
	}

	/**
	 * Settings API is not used — explicit "not found" outcome for AICAC-3.
	 */
	public function test_settings_api_not_used(): void {
		$this->assertDoesNotMatchRegularExpression(
			'/\bregister_setting\s*\(/',
			$this->source,
			'Unexpected register_setting — inventory assumed Settings API = not found'
		);
		$this->assertDoesNotMatchRegularExpression(
			'/\bsettings_fields\s*\(/',
			$this->source
		);
	}

	/**
	 * No alternate AJAX / admin-post entry points in the admin class.
	 */
	public function test_no_ajax_or_admin_post_hooks_in_admin_class(): void {
		$this->assertDoesNotMatchRegularExpression(
			'/[\'"]wp_ajax_/',
			$this->source
		);
		$this->assertDoesNotMatchRegularExpression(
			'/[\'"]admin_post_/',
			$this->source
		);
	}

	/**
	 * @return list<array{action:string,nonce_action:string}>
	 */
	public function mutating_action_provider(): array {
		return array(
			array(
				'action'       => 'bulk_plugin_rules',
				'nonce_action' => 'handl_aicac_save_policy',
			),
			array(
				'action'       => 'renew_temp_allow',
				'nonce_action' => 'handl_aicac_renew_temp_allow',
			),
			array(
				'action'       => 'snooze_alerts',
				'nonce_action' => 'handl_aicac_snooze_alerts',
			),
			array(
				'action'       => 'cancel_alert_snooze',
				'nonce_action' => 'handl_aicac_cancel_alert_snooze',
			),
			array(
				'action'       => 'quick_rule',
				'nonce_action' => 'handl_aicac_quick_rule',
			),
			array(
				'action'       => 'send_denial_digest',
				'nonce_action' => 'handl_aicac_send_digest',
			),
			array(
				'action'       => 'send_test_webhook',
				'nonce_action' => 'handl_aicac_send_test_webhook',
			),
			array(
				'action'       => 'send_test_email',
				'nonce_action' => 'handl_aicac_send_test_email',
			),
			array(
				'action'       => 'undo_quick_rule',
				'nonce_action' => 'handl_aicac_undo_quick_rule',
			),
			array(
				'action'       => 'save',
				'nonce_action' => 'handl_aicac_save_policy',
			),
			array(
				'action'       => 'export_rules',
				'nonce_action' => 'handl_aicac_export_rules',
			),
			array(
				'action'       => 'export_log',
				'nonce_action' => 'handl_aicac_export_log',
			),
			array(
				'action'       => 'export_audit_report',
				'nonce_action' => 'handl_aicac_export_audit_report',
			),
			array(
				'action'       => 'import_rules_preview',
				'nonce_action' => 'handl_aicac_import_rules',
			),
			array(
				'action'       => 'import_rules_confirm',
				'nonce_action' => 'handl_aicac_import_rules_confirm',
			),
			array(
				'action'       => 'compare_rules_preview',
				'nonce_action' => 'handl_aicac_compare_rules',
			),
			array(
				'action'       => 'compare_latest_backup',
				'nonce_action' => 'handl_aicac_compare_latest_backup',
			),
			array(
				'action'       => 'download_latest_backup',
				'nonce_action' => 'handl_aicac_download_latest_backup',
			),
			array(
				'action'       => 'policy_backup_save',
				'nonce_action' => 'handl_aicac_policy_backup_save',
			),
			array(
				'action'       => 'keyscan_run',
				'nonce_action' => 'handl_aicac_keyscan_run',
			),
			array(
				'action'       => 'simulate_policy',
				'nonce_action' => 'handl_aicac_save_policy',
			),
			array(
				'action'       => 'onboard_dismiss',
				'nonce_action' => 'handl_aicac_onboard',
			),
			array(
				'action'       => 'onboard_step',
				'nonce_action' => 'handl_aicac_onboard',
			),
			array(
				'action'       => 'onboard_test_email',
				'nonce_action' => 'handl_aicac_onboard',
			),
			array(
				'action'       => 'onboard_reopen',
				'nonce_action' => 'handl_aicac_onboard',
			),
			array(
				'action'       => 'preset_preview',
				'nonce_action' => 'handl_aicac_preset_preview',
			),
			array(
				'action'       => 'preset_apply_confirm',
				'nonce_action' => 'handl_aicac_preset_apply_confirm',
			),
			array(
				'action'       => 'policy_restore_preview',
				'nonce_action' => 'handl_aicac_policy_restore_preview',
			),
			array(
				'action'       => 'policy_restore_confirm',
				'nonce_action' => 'handl_aicac_policy_restore_confirm',
			),
			array(
				'action'       => 'policy_check_add',
				'nonce_action' => 'handl_aicac_policy_check_add',
			),
			array(
				'action'       => 'policy_check_delete',
				'nonce_action' => 'handl_aicac_policy_check_delete',
			),
			array(
				'action'       => 'policy_checks_save_confirm',
				'nonce_action' => 'handl_aicac_policy_checks_save_confirm',
			),
		);
	}

	/**
	 * Provider actions must match the approved dispatch inventory exactly.
	 */
	public function test_mutating_action_provider_matches_approved_inventory(): void {
		$from_provider = array();
		foreach ( $this->mutating_action_provider() as $row ) {
			$from_provider[] = $row['action'];
		}
		sort( $from_provider );
		$approved = self::APPROVED_DISPATCH_ACTIONS;
		$this->assertSame(
			$approved,
			$from_provider,
			'mutating_action_provider actions must equal APPROVED_DISPATCH_ACTIONS'
		);
	}

	/**
	 * Each known mutating POST action must check_admin_referer with its nonce action.
	 *
	 * @dataProvider mutating_action_provider
	 */
	public function test_each_mutating_action_has_matching_nonce_check( string $action, string $nonce_action ): void {
		$action_line = $this->first_line_matching(
			'/[\'"]' . preg_quote( $action, '/' ) . '[\'"]\s*===\s*\$posted_action|[\'"]' . preg_quote( $action, '/' ) . '[\'"]\s*===\s*\$_POST\s*\[\s*[\'"]handl_aicac_action[\'"]\s*\]|\$posted_action\s*===\s*[\'"]' . preg_quote( $action, '/' ) . '[\'"]/'
		);

		// save uses: 'save' === $_POST['handl_aicac_action']
		if ( null === $action_line && 'save' === $action ) {
			$action_line = $this->first_line_matching(
				'/[\'"]save[\'"]\s*===\s*\$_POST\s*\[\s*[\'"]handl_aicac_action[\'"]\s*\]/'
			);
		}

		$this->assertNotNull(
			$action_line,
			"Dispatch for action '{$action}' not found — update authz inventory if intentional"
		);

		$nonce_line = $this->first_line_matching_at_or_after(
			'/check_admin_referer\s*\(\s*[\'"]' . preg_quote( $nonce_action, '/' ) . '[\'"]/',
			$action_line
		);
		$this->assertNotNull(
			$nonce_line,
			"check_admin_referer( '{$nonce_action}' ) not found at/after action '{$action}'"
		);

		// Nonce check should be at or immediately after the action branch (within 5 lines).
		$this->assertLessThanOrEqual(
			5,
			$nonce_line - $action_line,
			"Nonce for '{$action}' is not adjacent to its action branch (lines {$action_line}→{$nonce_line})"
		);
	}

	/**
	 * Shared page gate + defense-in-depth helper each call current_user_can;
	 * dispatch keeps one check_admin_referer per mutating action; helper adds one more.
	 */
	public function test_combined_capability_and_nonce_verify_match_count(): void {
		preg_match_all( '/\bcurrent_user_can\s*\(/', $this->source, $cap );
		preg_match_all( '/\bcheck_admin_referer\s*\(/', $this->source, $nonce );
		preg_match_all( '/\bwp_verify_nonce\s*\(/', $this->source, $verify );

		$expected_dispatch_nonces = count( $this->mutating_action_provider() );
		// render_page shared gate + require_admin_mutation helper.
		$this->assertSame( 2, count( $cap[0] ), 'Expected shared gate + require_admin_mutation current_user_can' );
		// One referer per dispatch action + one inside require_admin_mutation.
		$this->assertSame(
			$expected_dispatch_nonces + 1,
			count( $nonce[0] ),
			'Expected dispatch nonces plus require_admin_mutation check_admin_referer'
		);
		$this->assertSame( 0, count( $verify[0] ), 'wp_verify_nonce should remain unused (check_admin_referer covers CSRF)' );
	}

	/**
	 * AICAC-22: require_admin_mutation must itself re-check capability + nonce.
	 */
	public function test_require_admin_mutation_rechecks_capability_and_nonce(): void {
		$body = $this->method_body( 'require_admin_mutation' );
		$this->assertNotNull( $body, 'require_admin_mutation() not found' );
		$this->assertMatchesRegularExpression(
			'/current_user_can\s*\(\s*[\'"]manage_options[\'"]\s*\)/',
			$body
		);
		$this->assertMatchesRegularExpression(
			'/check_admin_referer\s*\(\s*\$nonce_action\s*,\s*[\'"]handl_aicac_nonce[\'"]\s*\)/',
			$body
		);
	}

	/**
	 * AICAC-22: each private mutator must call require_admin_mutation with its action nonce.
	 *
	 * @dataProvider private_mutator_authz_provider
	 */
	public function test_private_mutator_rechecks_authz( string $method, string $nonce_action ): void {
		$body = $this->method_body( $method );
		$this->assertNotNull( $body, "Method {$method} not found" );

		$this->assertMatchesRegularExpression(
			'/\$this->require_admin_mutation\s*\(\s*[\'"]' . preg_quote( $nonce_action, '/' ) . '[\'"]\s*\)/',
			$body,
			"{$method} must call require_admin_mutation( '{$nonce_action}' ) before mutating"
		);

		// Re-check must precede Policy::save_policy / set_plugin_rule / option-affecting work.
		$recheck_pos = strpos( $body, 'require_admin_mutation' );
		$this->assertNotFalse( $recheck_pos );
		foreach ( array( 'Policy::save_policy', 'Policy::set_plugin_rule', 'Policy_Transfer::' ) as $write ) {
			$write_pos = strpos( $body, $write );
			if ( false === $write_pos ) {
				continue;
			}
			$this->assertLessThan(
				$write_pos,
				$recheck_pos,
				"{$method}: require_admin_mutation must run before {$write}"
			);
		}
	}

	/**
	 * @return list<array{method:string,nonce_action:string}>
	 */
	public function private_mutator_authz_provider(): array {
		return array(
			array( 'handle_save_rules', 'handl_aicac_save_policy' ),
			array( 'handle_save_log', 'handl_aicac_save_policy' ),
			array( 'handle_bulk_plugin_rules', 'handl_aicac_save_policy' ),
			array( 'handle_renew_temp_allow', 'handl_aicac_renew_temp_allow' ),
			array( 'handle_snooze_alerts', 'handl_aicac_snooze_alerts' ),
			array( 'handle_cancel_alert_snooze', 'handl_aicac_cancel_alert_snooze' ),
			array( 'handle_simulate_policy', 'handl_aicac_save_policy' ),
			array( 'handle_quick_rule_redirect', 'handl_aicac_quick_rule' ),
			array( 'handle_undo_quick_rule', 'handl_aicac_undo_quick_rule' ),
			array( 'apply_kill_switch_settings_from_post', 'handl_aicac_save_policy' ),
			array( 'apply_quiet_hours_settings_from_post', 'handl_aicac_save_policy' ),
			array( 'apply_model_force_settings_from_post', 'handl_aicac_save_policy' ),
			array( 'apply_role_gate_settings_from_post', 'handl_aicac_save_policy' ),
			array( 'apply_log_settings_from_post', 'handl_aicac_save_policy' ),
			array( 'handle_export_rules', 'handl_aicac_export_rules' ),
			array( 'handle_download_latest_backup', 'handl_aicac_download_latest_backup' ),
			array( 'handle_policy_backup_save', 'handl_aicac_policy_backup_save' ),
			array( 'handle_import_rules_preview', 'handl_aicac_import_rules' ),
			array( 'handle_import_rules_confirm', 'handl_aicac_import_rules_confirm' ),
			array( 'handle_compare_rules_preview', 'handl_aicac_compare_rules' ),
			array( 'handle_compare_latest_backup', 'handl_aicac_compare_latest_backup' ),
			array( 'handle_keyscan_run', 'handl_aicac_keyscan_run' ),
			array( 'handle_onboard_dismiss', 'handl_aicac_onboard' ),
			array( 'handle_onboard_step', 'handl_aicac_onboard' ),
			array( 'handle_onboard_test_email', 'handl_aicac_onboard' ),
			array( 'handle_onboard_reopen', 'handl_aicac_onboard' ),
			array( 'handle_policy_restore_preview', 'handl_aicac_policy_restore_preview' ),
			array( 'handle_policy_restore_confirm', 'handl_aicac_policy_restore_confirm' ),
			array( 'handle_policy_check_add', 'handl_aicac_policy_check_add' ),
			array( 'handle_policy_check_delete', 'handl_aicac_policy_check_delete' ),
			array( 'handle_policy_checks_save_confirm', 'handl_aicac_policy_checks_save_confirm' ),
		);
	}

	/**
	 * Private mutators must not become public without updating the authz inventory.
	 */
	public function test_core_mutators_remain_private(): void {
		foreach (
			array(
				'require_admin_mutation',
				'handle_save_rules',
				'handle_save_log',
				'handle_bulk_plugin_rules',
				'handle_simulate_policy',
				'handle_quick_rule_redirect',
				'handle_undo_quick_rule',
				'apply_kill_switch_settings_from_post',
				'apply_quiet_hours_settings_from_post',
				'apply_model_force_settings_from_post',
				'apply_role_gate_settings_from_post',
				'apply_log_settings_from_post',
				'handle_export_rules',
				'handle_download_latest_backup',
				'handle_policy_backup_save',
				'handle_export_log',
				'handle_import_rules_preview',
				'handle_import_rules_confirm',
				'handle_compare_rules_preview',
				'handle_compare_latest_backup',
				'handle_keyscan_run',
				'handle_onboard_dismiss',
				'handle_onboard_step',
				'handle_onboard_test_email',
				'handle_onboard_reopen',
				'handle_policy_restore_preview',
				'handle_policy_restore_confirm',
				'handle_policy_check_add',
				'handle_policy_check_delete',
				'handle_policy_checks_save_confirm',
			) as $method
		) {
			$this->assertMatchesRegularExpression(
				'/\bprivate\s+function\s+' . preg_quote( $method, '/' ) . '\s*\(/',
				$this->source,
				"Mutator {$method} must stay private (or update authz inventory if intentional)"
			);
		}
	}

	/**
	 * Inventory completeness: discovered dispatch literals must equal the approved set.
	 *
	 * Unlike a one-way “approved ⊆ found” check, set equality fails when a new
	 * branch (e.g. delete_all) appears without updating APPROVED_DISPATCH_ACTIONS.
	 */
	public function test_no_unknown_handl_aicac_action_string_literals_in_dispatch(): void {
		$discovered = $this->discover_dispatch_action_literals( $this->source );
		$approved   = self::APPROVED_DISPATCH_ACTIONS;

		$this->assertSame(
			$approved,
			$discovered,
			'Discovered handl_aicac_action dispatch literals must equal the approved inventory'
		);
	}

	/**
	 * Regression: discovery must surface unknown action branches so equality can fail.
	 */
	public function test_dispatch_literal_discovery_detects_unknown_action(): void {
		$fixture = <<<'PHP'
			if ( isset( $_POST['handl_aicac_action'] ) ) {
				$posted_action = sanitize_key( wp_unslash( (string) $_POST['handl_aicac_action'] ) );
				if ( 'quick_rule' === $posted_action ) {
					check_admin_referer( 'handl_aicac_quick_rule', 'handl_aicac_nonce' );
				}
				if ( 'delete_all' === $posted_action ) {
					// Hypothetical uninventoried branch — must be discovered.
				}
			}
			if ( isset( $_POST['handl_aicac_action'] ) && 'save' === $_POST['handl_aicac_action'] ) {
				check_admin_referer( 'handl_aicac_save_policy', 'handl_aicac_nonce' );
			}
		PHP;

		$discovered = $this->discover_dispatch_action_literals( $fixture );

		$this->assertContains(
			'delete_all',
			$discovered,
			'Discovery must include unknown dispatch literal delete_all'
		);
		$this->assertNotSame(
			self::APPROVED_DISPATCH_ACTIONS,
			$discovered,
			'Unknown action must make discovered set differ from approved inventory'
		);
	}

	/**
	 * File downloads must run on admin_init — render_page is after admin HTML is buffered,
	 * which produced HTML bodies with .csv filenames in QA (PR #72).
	 */
	public function test_file_downloads_hooked_on_admin_init_before_html(): void {
		$this->assertMatchesRegularExpression(
			"/add_action\s*\(\s*'admin_init'\s*,\s*array\s*\(\s*\\\$this\s*,\s*'maybe_handle_file_downloads'\s*\)/",
			$this->source,
			'CSV/JSON downloads must register on admin_init'
		);

		$maybe_pos  = strpos( $this->source, 'function maybe_handle_file_downloads' );
		$render_pos = strpos( $this->source, 'function render_page' );
		$this->assertNotFalse( $maybe_pos );
		$this->assertNotFalse( $render_pos );

		$maybe_body = substr( $this->source, $maybe_pos, $render_pos > $maybe_pos ? $render_pos - $maybe_pos : 2500 );
		$this->assertStringContainsString( 'handle_export_log', $maybe_body );
		$this->assertStringContainsString( 'handle_export_rules', $maybe_body );
		$this->assertStringContainsString( 'handle_download_latest_backup', $maybe_body );

		// Late dispatch in render_page must not call the stream handlers again.
		$render_end  = strpos( $this->source, 'function render_plugin_rules_filters', $render_pos );
		$render_body = substr(
			$this->source,
			$render_pos,
			false !== $render_end ? $render_end - $render_pos : 8000
		);
		$this->assertStringNotContainsString(
			'handle_export_log()',
			$render_body,
			'export_log must not stream from render_page (HTML already buffered)'
		);
		$this->assertStringNotContainsString(
			'handle_export_rules()',
			$render_body,
			'export_rules must not stream from render_page (HTML already buffered)'
		);
	}

	/**
	 * Import path must call Policy::save_policy (reuse sanitize path; no bypass).
	 */
	public function test_import_confirm_uses_policy_save_policy(): void {
		$preview_pos = strpos( $this->source, 'function handle_import_rules_preview' );
		$confirm_pos = strpos( $this->source, 'function handle_import_rules_confirm' );
		$this->assertNotFalse( $preview_pos );
		$this->assertNotFalse( $confirm_pos );
		$this->assertGreaterThan( $preview_pos, $confirm_pos );

		$preview_body = substr( $this->source, $preview_pos, $confirm_pos - $preview_pos );
		$confirm_body = substr( $this->source, $confirm_pos, 2500 );

		$this->assertStringNotContainsString(
			'Policy::save_policy(',
			$preview_body,
			'Preview must not write policy'
		);
		$this->assertStringContainsString(
			'Policy::save_policy(',
			$confirm_body,
			'Confirmed import must write through Policy::save_policy'
		);
	}

	/**
	 * Compare path is read-only: never calls Policy::save_policy.
	 */
	public function test_compare_preview_never_writes_policy(): void {
		$pos = strpos( $this->source, 'function handle_compare_rules_preview' );
		$this->assertNotFalse( $pos );
		$body = substr( $this->source, $pos, 2200 );
		$this->assertStringNotContainsString(
			'Policy::save_policy(',
			$body,
			'Compare must never write policy'
		);
		$this->assertStringContainsString( 'name="handl_aicac_compare_file"', $this->source );
		$this->assertStringContainsString( 'Compare with current', $this->source );
		$this->assertStringContainsString( 'render_confirm_diff_table', $this->source );

		$latest_pos = strpos( $this->source, 'function handle_compare_latest_backup' );
		$this->assertNotFalse( $latest_pos );
		$latest_body = substr( $this->source, $latest_pos, 1200 );
		$this->assertStringNotContainsString(
			'Policy::save_policy(',
			$latest_body,
			'Compare with latest backup must never write policy'
		);
	}

	/**
	 * Upload-only: no server path input field for import.
	 */
	public function test_import_uses_file_upload_not_path_input(): void {
		$this->assertStringContainsString( 'enctype="multipart/form-data"', $this->source );
		$this->assertStringContainsString( 'name="handl_aicac_import_file"', $this->source );
		$this->assertStringContainsString( 'type="file"', $this->source );
		$this->assertDoesNotMatchRegularExpression(
			'/name=[\'"]handl_aicac_import_(path|server_path|filepath)[\'"]/',
			$this->source
		);
	}

	/**
	 * Extract a method body from the admin source (best-effort brace match).
	 */
	private function method_body( string $method ): ?string {
		$pattern = '/\b(?:private|public|protected)\s+function\s+' . preg_quote( $method, '/' ) . '\s*\(/';
		if ( ! preg_match( $pattern, $this->source, $m, PREG_OFFSET_CAPTURE ) ) {
			return null;
		}
		$start = (int) $m[0][1];
		$open  = strpos( $this->source, '{', $start );
		if ( false === $open ) {
			return null;
		}
		$depth = 0;
		$len   = strlen( $this->source );
		for ( $i = $open; $i < $len; $i++ ) {
			$ch = $this->source[ $i ];
			if ( '{' === $ch ) {
				++$depth;
			} elseif ( '}' === $ch ) {
				--$depth;
				if ( 0 === $depth ) {
					return substr( $this->source, $open, $i - $open + 1 );
				}
			}
		}
		return null;
	}

	/**
	 * Discover action string literals compared in handl_aicac_action dispatch branches.
	 *
	 * @return list<string> Sorted unique action keys.
	 */
	private function discover_dispatch_action_literals( string $source ): array {
		$found    = array();
		$patterns = array(
			'/[\'"]([a-z0-9_]+)[\'"]\s*===\s*\$posted_action\b/',
			'/\$posted_action\s*===\s*[\'"]([a-z0-9_]+)[\'"]/',
			'/[\'"]([a-z0-9_]+)[\'"]\s*===\s*\$_POST\s*\[\s*[\'"]handl_aicac_action[\'"]\s*\]/',
			'/\$_POST\s*\[\s*[\'"]handl_aicac_action[\'"]\s*\]\s*===\s*[\'"]([a-z0-9_]+)[\'"]/',
		);

		foreach ( $patterns as $pattern ) {
			if ( preg_match_all( $pattern, $source, $matches ) ) {
				foreach ( $matches[1] as $token ) {
					$found[ $token ] = true;
				}
			}
		}

		$keys = array_keys( $found );
		sort( $keys );

		return $keys;
	}

	/**
	 * @return ?int 1-based line number
	 */
	private function first_line_matching( string $pattern ): ?int {
		foreach ( $this->lines as $idx => $line ) {
			if ( preg_match( $pattern, $line ) ) {
				return $idx + 1;
			}
		}
		return null;
	}

	/**
	 * @return ?int 1-based line number at or after $min_line
	 */
	private function first_line_matching_at_or_after( string $pattern, int $min_line ): ?int {
		foreach ( $this->lines as $idx => $line ) {
			$line_no = $idx + 1;
			if ( $line_no < $min_line ) {
				continue;
			}
			if ( preg_match( $pattern, $line ) ) {
				return $line_no;
			}
		}
		return null;
	}
}
