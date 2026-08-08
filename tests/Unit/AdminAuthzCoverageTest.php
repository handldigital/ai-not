<?php
/**
 * Static verification that admin state-mutating handlers keep nonce + capability coverage.
 *
 * AICAC-3 (#21 / #22) plus AICAC-102 transfer actions and AICAC-104 test webhook: locks the inventory of POST
 * action dispatches in class-handl-aicac-admin.php. Does not exercise WordPress
 * runtime authz — it fails if a new handl_aicac_action branch appears without
 * updating the approved inventory (and without a matching check_admin_referer),
 * or if the shared manage_options gate is removed.
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
		'export_log',
		'export_rules',
		'import_rules_confirm',
		'import_rules_preview',
		'quick_rule',
		'save',
		'send_denial_digest',
		'send_test_webhook',
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
				'action'       => 'import_rules_preview',
				'nonce_action' => 'handl_aicac_import_rules',
			),
			array(
				'action'       => 'import_rules_confirm',
				'nonce_action' => 'handl_aicac_import_rules_confirm',
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

		$nonce_line = $this->first_line_matching(
			'/check_admin_referer\s*\(\s*[\'"]' . preg_quote( $nonce_action, '/' ) . '[\'"]/'
		);
		$this->assertNotNull(
			$nonce_line,
			"check_admin_referer( '{$nonce_action}' ) not found for action '{$action}'"
		);

		// Nonce check should be at or immediately after the action branch (within 5 lines).
		$this->assertGreaterThanOrEqual(
			$action_line,
			$nonce_line,
			"Nonce for '{$action}' appears before its action branch"
		);
		$this->assertLessThanOrEqual(
			5,
			$nonce_line - $action_line,
			"Nonce for '{$action}' is not adjacent to its action branch (lines {$action_line}→{$nonce_line})"
		);
	}

	/**
	 * Combined match count: 1 shared capability + one check_admin_referer per mutating action.
	 */
	public function test_combined_capability_and_nonce_verify_match_count(): void {
		preg_match_all( '/\bcurrent_user_can\s*\(/', $this->source, $cap );
		preg_match_all( '/\bcheck_admin_referer\s*\(/', $this->source, $nonce );
		preg_match_all( '/\bwp_verify_nonce\s*\(/', $this->source, $verify );

		$expected_nonces = count( $this->mutating_action_provider() );
		$combined        = count( $cap[0] ) + count( $nonce[0] ) + count( $verify[0] );

		$this->assertSame( 1, count( $cap[0] ), 'Expected exactly one current_user_can in admin class' );
		$this->assertSame( $expected_nonces, count( $nonce[0] ), 'Expected one check_admin_referer per mutating action' );
		$this->assertSame( 0, count( $verify[0] ), 'wp_verify_nonce should remain unused (check_admin_referer covers CSRF)' );
		$this->assertSame( 1 + $expected_nonces, $combined, 'Shared-wrapper design: 1 capability + N action nonces' );
	}

	/**
	 * Private mutators must not become public without updating the authz inventory.
	 */
	public function test_core_mutators_remain_private(): void {
		foreach (
			array(
				'handle_save_rules',
				'handle_save_log',
				'handle_quick_rule_redirect',
				'handle_undo_quick_rule',
				'apply_kill_switch_settings_from_post',
				'apply_model_force_settings_from_post',
				'apply_log_settings_from_post',
				'handle_export_rules',
				'handle_export_log',
				'handle_import_rules_preview',
				'handle_import_rules_confirm',
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
}
