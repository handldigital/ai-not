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
	private function base_policy( string $default = 'allow' ): array {
		return array(
			'default'     => $default,
			'log_enabled' => true,
			'audit_only'  => false,
			'kill_switch' => false,
			'plugins'     => array(
				'acme/a.php' => 'allow',
			),
		);
	}

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
		update_option( Plugin::OPTION_KEY, $this->base_policy( 'allow' ), false );
		$json = $this->export_json( $this->base_policy( 'deny' ), 'https://other.example/' );
		$result = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', false );
		$this->assertFalse( $result['ok'] );
		$this->assertSame( 'site_mismatch', $result['error'] );
	}

	public function test_prepare_allows_site_mismatch_with_flag(): void {
		update_option( Plugin::OPTION_KEY, $this->base_policy( 'allow' ), false );
		$json = $this->export_json( $this->base_policy( 'deny' ), 'https://other.example/' );
		$result = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', true );
		$this->assertTrue( $result['ok'] );
		$this->assertTrue( $result['has_changes'] );
	}

	public function test_dry_run_diff_matches_apply_result(): void {
		update_option( Plugin::OPTION_KEY, $this->base_policy( 'allow' ), false );
		$incoming = $this->base_policy( 'deny' );
		$incoming['kill_switch'] = true;
		$json = $this->export_json( $incoming, 'https://example.test/' );

		$prepared = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', false );
		$this->assertTrue( $prepared['ok'] );
		$this->assertTrue( $prepared['has_changes'] );
		$joined = implode( "\n", $prepared['diff_lines'] );
		$this->assertStringContainsString( 'Default policy', $joined );
		$this->assertStringContainsString( 'Emergency stop', $joined );

		CLI_Policy_Apply::commit_apply( $prepared['policy'] );

		$live = Policy::get_policy();
		$this->assertSame( 'deny', $live['default'] );
		$this->assertTrue( ! empty( $live['kill_switch'] ) );

		// Same export vs post-apply live → no changes (dry-run exit 0 path).
		$again = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', false );
		$this->assertTrue( $again['ok'] );
		$this->assertFalse( $again['has_changes'] );
	}

	public function test_apply_creates_snapshot_via_save_policy(): void {
		update_option( Plugin::OPTION_KEY, $this->base_policy( 'allow' ), false );
		$json = $this->export_json( $this->base_policy( 'deny' ), 'https://example.test/' );
		$prepared = CLI_Policy_Apply::prepare_apply( $json, 'https://example.test/', false );
		$this->assertTrue( $prepared['ok'] );

		CLI_Policy_Apply::commit_apply( $prepared['policy'] );

		$snaps = Policy_Snapshots::all();
		$this->assertNotEmpty( $snaps );
		$this->assertSame( 'allow', $snaps[0]['policy']['default'] ?? null );
	}

	public function test_malformed_never_partially_applies(): void {
		update_option( Plugin::OPTION_KEY, $this->base_policy( 'allow' ), false );
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
}
