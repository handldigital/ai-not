<?php
/**
 * Static verification that admin state-mutating handlers keep nonce + capability coverage.
 *
 * AICAC-3 (#21): locks the inventory of POST action dispatches in
 * class-handl-aicac-admin.php. Does not exercise WordPress runtime authz —
 * it fails if a new handl_aicac_action branch appears without a matching
 * check_admin_referer, or if the shared manage_options gate is removed.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class AdminAuthzCoverageTest extends TestCase {

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
				'action'       => 'undo_quick_rule',
				'nonce_action' => 'handl_aicac_undo_quick_rule',
			),
			array(
				'action'       => 'save',
				'nonce_action' => 'handl_aicac_save_policy',
			),
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
			"Dispatch for action '{$action}' not found — update AICAC-3 inventory if intentional"
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
	 * Combined match count stays aligned with shared-wrapper design (1 cap + 4 nonces).
	 */
	public function test_combined_capability_and_nonce_verify_match_count(): void {
		preg_match_all( '/\bcurrent_user_can\s*\(/', $this->source, $cap );
		preg_match_all( '/\bcheck_admin_referer\s*\(/', $this->source, $nonce );
		preg_match_all( '/\bwp_verify_nonce\s*\(/', $this->source, $verify );

		$combined = count( $cap[0] ) + count( $nonce[0] ) + count( $verify[0] );

		$this->assertSame( 1, count( $cap[0] ), 'Expected exactly one current_user_can in admin class' );
		$this->assertSame( 4, count( $nonce[0] ), 'Expected exactly four check_admin_referer calls' );
		$this->assertSame( 0, count( $verify[0] ), 'wp_verify_nonce should remain unused (check_admin_referer covers CSRF)' );
		$this->assertSame( 5, $combined, 'AICAC-3 premise: five combined matches under shared-wrapper design' );
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
			) as $method
		) {
			$this->assertMatchesRegularExpression(
				'/\bprivate\s+function\s+' . preg_quote( $method, '/' ) . '\s*\(/',
				$this->source,
				"Mutator {$method} must stay private (or update AICAC-3 findings if intentional)"
			);
		}
	}

	/**
	 * Inventory completeness: every string compared as handl_aicac_action must be known.
	 */
	public function test_no_unknown_handl_aicac_action_string_literals_in_dispatch(): void {
		$known = array( 'quick_rule', 'send_denial_digest', 'undo_quick_rule', 'save' );
		$found = array();

		foreach ( $this->lines as $line ) {
			if ( ! preg_match( '/handl_aicac_action|posted_action/', $line ) ) {
				continue;
			}
			if ( preg_match_all( '/[\'"]([a-z0-9_]+)[\'"]/', $line, $m ) ) {
				foreach ( $m[1] as $token ) {
					if ( in_array( $token, $known, true ) ) {
						$found[ $token ] = true;
					} elseif ( in_array( $token, array( 'handl_aicac_action', 'handl_aicac_nonce' ), true ) ) {
						continue;
					} elseif ( preg_match( '/^(quick_rule|send_denial_digest|undo_quick_rule|save)$/', $token ) ) {
						$found[ $token ] = true;
					}
				}
			}
		}

		foreach ( $known as $action ) {
			$this->assertArrayHasKey(
				$action,
				$found,
				"Known action '{$action}' missing from source references"
			);
		}
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
