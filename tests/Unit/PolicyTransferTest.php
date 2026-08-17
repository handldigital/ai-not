<?php
/**
 * Unit tests for Policy_Transfer export / import / diff (AICAC-102).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Policy_Snapshots;
use HandL\AICAC\Policy_Transfer;
use PHPUnit\Framework\TestCase;

final class PolicyTransferTest extends TestCase {

	public function test_build_export_includes_policy_plus_metadata(): void {
		$policy = array(
			'default'      => 'deny',
			'plugins'      => array( 'acme/plugin.php' => 'allow' ),
			'operations'   => array(
				'acme/plugin.php' => array( 'text' => 'deny' ),
			),
			'kill_switch'  => true,
			'denied_tools' => array( 'core/edit-post' ),
			'model_force_plugins' => array(
				'acme/plugin.php' => array(
					'provider' => 'openai',
					'model'    => 'gpt-4o-mini',
				),
			),
		);

		$export = Policy_Transfer::build_export( $policy, '1.0.15', '2026-08-07T00:00:00+00:00' );

		$this->assertSame( '1.0.15', $export['plugin_version'] );
		$this->assertSame( '2026-08-07T00:00:00+00:00', $export['exported_at'] );
		$this->assertSame( 'https://example.test/', $export['site_url'] );
		$this->assertSame( 'deny', $export['default'] );
		$this->assertSame( array( 'acme/plugin.php' => 'allow' ), $export['plugins'] );
		$this->assertArrayNotHasKey( 'model_force_enabled', $export );
		$this->assertArrayNotHasKey( 'denied_abilities', $export );

		$json = Policy_Transfer::encode_export( $export );
		$this->assertStringContainsString( '"plugin_version"', $json );
		$this->assertStringContainsString( '"exported_at"', $json );
	}

	public function test_parse_import_rejects_invalid_json(): void {
		$result = Policy_Transfer::parse_import( '{not-json' );
		$this->assertFalse( $result['ok'] );
		$this->assertSame( 'invalid_json', $result['error'] );
	}

	public function test_parse_import_rejects_empty(): void {
		$result = Policy_Transfer::parse_import( "  \n  " );
		$this->assertFalse( $result['ok'] );
		$this->assertSame( 'empty', $result['error'] );
	}

	public function test_parse_import_rejects_missing_required_keys(): void {
		$result = Policy_Transfer::parse_import( '{"default":"allow"}' );
		$this->assertFalse( $result['ok'] );
		$this->assertSame( 'missing_required_keys', $result['error'] );
	}

	public function test_parse_import_accepts_empty_ruleset_with_metadata(): void {
		$json   = '{"plugin_version":"1.0.15","exported_at":"2026-08-07T00:00:00Z","default":"allow"}';
		$result = Policy_Transfer::parse_import( $json );
		$this->assertTrue( $result['ok'] );
		$this->assertSame( 'allow', $result['policy']['default'] );
		$this->assertSame( array(), $result['ignored'] );
	}

	public function test_parse_import_ignores_unknown_fields(): void {
		$json = wp_json_encode_compat(
			array(
				'plugin_version'   => '9.9.9',
				'exported_at'      => '2026-08-07T00:00:00Z',
				'default'          => 'allow',
				'future_feature_x' => array( 'a' => 1 ),
				'another_new_key'  => true,
			)
		);

		$result = Policy_Transfer::parse_import( $json );
		$this->assertTrue( $result['ok'] );
		$this->assertSame( array( 'another_new_key', 'future_feature_x' ), $result['ignored'] );
		$this->assertArrayNotHasKey( 'future_feature_x', $result['policy'] );
		$this->assertArrayNotHasKey( 'plugin_version', $result['policy'] );
	}

	public function test_diff_policies_reports_added_changed_removed_sections(): void {
		$current = array(
			'plugins' => array(
				'keep/plugin.php'   => 'allow',
				'change/plugin.php' => 'allow',
				'gone/plugin.php'   => 'deny',
			),
			'operations' => array(
				'keep/plugin.php' => array( 'text' => 'allow' ),
			),
			'kill_switch' => false,
			'kill_switch_exceptions' => array(),
			'denied_tools' => array( 'old-tool' ),
			'model_force_plugins' => array(
				'pin/plugin.php' => array( 'provider' => 'openai', 'model' => 'gpt-4o' ),
			),
			'model_force_unattributed' => 'none',
		);

		$incoming = array(
			'plugins' => array(
				'keep/plugin.php'   => 'allow',
				'change/plugin.php' => 'deny',
				'new/plugin.php'    => 'allow',
			),
			'operations' => array(
				'keep/plugin.php' => array( 'text' => 'deny' ),
				'new/plugin.php'  => array( 'image' => 'deny' ),
			),
			'kill_switch' => true,
			'kill_switch_exceptions' => array( 'keep/plugin.php' ),
			'denied_tools' => array( 'new-tool' ),
			'model_force_plugins' => array(
				'pin/plugin.php' => array( 'provider' => 'openai', 'model' => 'gpt-4o-mini' ),
			),
			'model_force_unattributed'          => 'force',
			'model_force_unattributed_provider' => 'openai',
			'model_force_unattributed_model'    => 'gpt-4o-mini',
		);

		$diff = Policy_Transfer::diff_policies( $current, $incoming );

		$this->assertSame( array( 'new/plugin.php' ), $diff['plugins']['added'] );
		$this->assertSame( array( 'change/plugin.php' ), $diff['plugins']['changed'] );
		$this->assertSame( array( 'gone/plugin.php' ), $diff['plugins']['removed'] );

		$this->assertContains( 'new/plugin.php', $diff['operations']['added'] );
		$this->assertContains( 'keep/plugin.php', $diff['operations']['changed'] );

		$this->assertTrue( $diff['kill_switch']['changed'] );
		$this->assertSame( array( 'new-tool' ), $diff['denied_tools']['added'] );
		$this->assertSame( array( 'old-tool' ), $diff['denied_tools']['removed'] );

		$this->assertSame( array( 'pin/plugin.php' ), $diff['model_force']['changed'] );
		$this->assertTrue( $diff['model_force']['unattributed_changed'] );

		$lines = Policy_Transfer::format_diff_lines( $diff );
		$this->assertNotEmpty( $lines );
		$this->assertStringContainsString( 'Per-plugin rules', implode( "\n", $lines ) );
	}

	public function test_policy_for_save_sets_weekly_write_intent(): void {
		$with = Policy_Transfer::policy_for_save( array( 'default' => 'allow', 'weekly_report_enabled' => true ) );
		$this->assertSame( 'set', $with['_weekly_report_write'] );

		$without = Policy_Transfer::policy_for_save( array( 'default' => 'deny' ) );
		$this->assertSame( 'omit', $without['_weekly_report_write'] );
	}

	public function test_export_contains_no_secret_field_names(): void {
		$keys = Policy_Transfer::known_policy_keys();
		foreach ( $keys as $key ) {
			$this->assertDoesNotMatchRegularExpression(
				'/api[_-]?key|secret|password|credential|auth_token|private_key/i',
				$key,
				"Policy key '{$key}' looks like a secret and must not be exported"
			);
		}
	}

	public function test_compare_diff_matches_import_policy_shape_and_lists_unknown_keys(): void {
		$current = array(
			'default'     => 'allow',
			'audit_only'  => false,
			'log_enabled' => true,
			'kill_switch' => false,
			'plugins'     => array( 'acme/plugin.php' => 'allow' ),
		);

		$json = wp_json_encode_compat(
			array(
				'plugin_version'   => '1.3.0',
				'exported_at'      => '2026-08-12T00:00:00Z',
				'default'          => 'deny',
				'audit_only'       => true,
				'log_enabled'      => true,
				'kill_switch'      => true,
				'plugins'          => array( 'acme/plugin.php' => 'deny' ),
				'future_feature_x' => array( 'a' => 1 ),
				'another_new_key'  => true,
			)
		);

		$parsed = Policy_Transfer::parse_import( $json );
		$this->assertTrue( $parsed['ok'] );

		// Same policy blob import confirm would hand to Policy::save_policy (minus write intent).
		$incoming = $parsed['policy'];
		$compare  = Policy_Transfer::compare_diff( $current, $incoming, $parsed['ignored'] );

		$this->assertSame( array( 'another_new_key', 'future_feature_x' ), $compare['not_comparable'] );
		$this->assertSame(
			Policy_Snapshots::diff_rows( $current, $incoming ),
			$compare['rows'],
			'Compare rows must match restore/import parity via Policy_Snapshots::diff_rows on the same parsed policy'
		);

		$keys = array_column( $compare['rows'], 'key' );
		$this->assertContains( 'default', $keys );
		$this->assertContains( 'audit_only', $keys );
		$this->assertContains( 'kill_switch', $keys );
		$this->assertContains( 'plugins', $keys );
		$this->assertNotContains( 'future_feature_x', $keys );
	}

	public function test_compare_rejects_malformed_json_without_policy_shape(): void {
		$bad = Policy_Transfer::parse_import( '{not-json' );
		$this->assertFalse( $bad['ok'] );
		$this->assertSame( 'invalid_json', $bad['error'] );

		$empty = Policy_Transfer::parse_import( '' );
		$this->assertFalse( $empty['ok'] );
		$this->assertSame( 'empty', $empty['error'] );
	}

	public function test_max_upload_bytes_is_one_megabyte(): void {
		$this->assertSame( 1048576, Policy_Transfer::MAX_UPLOAD_BYTES );
	}

	public function test_redacted_export_serialized_string_has_no_email_url_or_note_text(): void {
		$note = 'finance-team-do-not-share';
		$policy = array(
			'default'           => 'deny',
			'alert_email'       => 'ops@handldigital.example',
			'alert_webhook_url' => 'https://hooks.example.test/secret-token',
			'plugin_notes'      => array(
				'acme/plugin.php' => $note,
			),
			'plugins'           => array( 'acme/plugin.php' => 'allow' ),
		);

		$plain = Policy_Transfer::build_export( $policy, '1.5.0', '2026-08-15T00:00:00Z', false );
		$this->assertSame( 'ops@handldigital.example', $plain['alert_email'] );
		$this->assertSame( 'https://hooks.example.test/secret-token', $plain['alert_webhook_url'] );
		$this->assertSame( $note, $plain['plugin_notes']['acme/plugin.php'] );
		$this->assertArrayNotHasKey( 'redacted', $plain );

		$export = Policy_Transfer::build_export( $policy, '1.5.0', '2026-08-15T00:00:00Z', true );
		$this->assertTrue( $export['redacted'] );
		$this->assertSame( Policy_Transfer::REDACT_PRESENT, $export['alert_email'] );
		$this->assertSame( Policy_Transfer::REDACT_PRESENT, $export['alert_webhook_url'] );
		$this->assertSame( array(), $export['plugin_notes'] );
		$this->assertArrayNotHasKey( 'site_url', $export );

		$json = Policy_Transfer::encode_export( $export );
		$this->assertStringContainsString( '"redacted": true', $json );
		$this->assertDoesNotMatchRegularExpression(
			'/[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}/i',
			$json,
			'Redacted export JSON must contain zero email addresses'
		);
		$this->assertDoesNotMatchRegularExpression(
			'#https?://#i',
			$json,
			'Redacted export JSON must contain zero URLs'
		);
		$this->assertStringNotContainsString( $note, $json );
		$this->assertStringNotContainsString( 'finance-team', $json );
	}

	public function test_redacted_export_marks_empty_secrets_absent(): void {
		$export = Policy_Transfer::build_export(
			array(
				'default'           => 'allow',
				'alert_email'       => '',
				'alert_webhook_url' => '',
				'plugin_notes'      => array(),
			),
			'1.5.0',
			'2026-08-15T00:00:00Z',
			true
		);
		$this->assertSame( Policy_Transfer::REDACT_ABSENT, $export['alert_email'] );
		$this->assertSame( Policy_Transfer::REDACT_ABSENT, $export['alert_webhook_url'] );
	}

	public function test_parse_import_skips_redacted_fields_and_never_returns_placeholders(): void {
		$json = Policy_Transfer::encode_export(
			Policy_Transfer::build_export(
				array(
					'default'           => 'deny',
					'alert_email'       => 'ops@handldigital.example',
					'alert_webhook_url' => 'https://hooks.example.test/secret-token',
					'plugin_notes'      => array( 'acme/plugin.php' => 'finance-team-do-not-share' ),
					'plugins'           => array( 'acme/plugin.php' => 'allow' ),
				),
				'1.5.0',
				'2026-08-15T00:00:00Z',
				true
			)
		);

		$parsed = Policy_Transfer::parse_import( $json );
		$this->assertTrue( $parsed['ok'] );
		$this->assertTrue( $parsed['redacted'] );
		$this->assertSame(
			array( 'alert_email', 'alert_webhook_url', 'plugin_notes' ),
			$parsed['skipped']
		);
		$this->assertSame( 'deny', $parsed['policy']['default'] );
		$this->assertArrayNotHasKey( 'alert_email', $parsed['policy'] );
		$this->assertArrayNotHasKey( 'alert_webhook_url', $parsed['policy'] );
		$this->assertArrayNotHasKey( 'plugin_notes', $parsed['policy'] );
		$this->assertArrayNotHasKey( 'redacted', $parsed['policy'] );
	}

	public function test_restore_skipped_fields_keeps_live_secrets_not_placeholders(): void {
		$imported = array(
			'default' => 'deny',
			'plugins' => array( 'acme/plugin.php' => 'allow' ),
		);
		$current = array(
			'default'           => 'allow',
			'alert_email'       => 'keep-me@handldigital.example',
			'alert_webhook_url' => 'https://hooks.live.test/keep',
			'plugin_notes'      => array( 'acme/plugin.php' => 'live note stays' ),
		);
		$skipped = array( 'alert_email', 'alert_webhook_url', 'plugin_notes' );

		$merged = Policy_Transfer::restore_skipped_fields( $imported, $current, $skipped );
		$this->assertSame( 'deny', $merged['default'] );
		$this->assertSame( 'keep-me@handldigital.example', $merged['alert_email'] );
		$this->assertSame( 'https://hooks.live.test/keep', $merged['alert_webhook_url'] );
		$this->assertSame( array( 'acme/plugin.php' => 'live note stays' ), $merged['plugin_notes'] );
		$this->assertNotContains( Policy_Transfer::REDACT_PRESENT, $merged );
	}

	public function test_parse_import_skips_placeholders_even_without_redacted_flag(): void {
		$json = wp_json_encode_compat(
			array(
				'plugin_version'    => '1.5.0',
				'exported_at'       => '2026-08-15T00:00:00Z',
				'default'           => 'allow',
				'alert_email'       => Policy_Transfer::REDACT_PRESENT,
				'alert_webhook_url' => Policy_Transfer::REDACT_ABSENT,
			)
		);
		$parsed = Policy_Transfer::parse_import( $json );
		$this->assertTrue( $parsed['ok'] );
		$this->assertFalse( $parsed['redacted'] );
		$this->assertSame( array( 'alert_email', 'alert_webhook_url' ), $parsed['skipped'] );
		$this->assertArrayNotHasKey( 'alert_email', $parsed['policy'] );
		$this->assertArrayNotHasKey( 'alert_webhook_url', $parsed['policy'] );
	}
}

/**
 * Tiny helper so tests do not require WordPress wp_json_encode.
 *
 * @param mixed $data
 */
function wp_json_encode_compat( $data ): string {
	$json = json_encode( $data );
	return is_string( $json ) ? $json : '{}';
}
