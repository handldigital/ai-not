<?php
/**
 * Prove the save_policy incoming-key strip does not delete stored keys
 * for non-admin writers. Import / CLI apply are full-replace from a file
 * and get their own older-JSON case.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Break_Glass;
use HandL\AICAC\Budget;
use HandL\AICAC\CLI_Policy_Apply;
use HandL\AICAC\New_Plugin;
use HandL\AICAC\Onboarding;
use HandL\AICAC\Operations;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Policy_Packs;
use HandL\AICAC\Policy_Snapshots;
use HandL\AICAC\Policy_Transfer;
use HandL\AICAC\Presets;
use HandL\AICAC\Temp_Allow;
use PHPUnit\Framework\TestCase;

final class SavePolicyWriterContractTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_cron']    = array();
		unset( $GLOBALS['handl_aicac_test_filters'], $GLOBALS['handl_aicac_wp_mail'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Policy_Snapshots::OPTION_KEY );
		delete_option( Policy_Snapshots::HISTORY_OPTION_KEY );
		delete_option( Break_Glass::OPTION_KEY );
	}

	protected function tearDown(): void {
		delete_option( Plugin::OPTION_KEY );
		delete_option( Policy_Snapshots::OPTION_KEY );
		delete_option( Policy_Snapshots::HISTORY_OPTION_KEY );
		delete_option( Break_Glass::OPTION_KEY );
		unset( $GLOBALS['handl_aicac_wp_mail'], $GLOBALS['handl_aicac_test_filters'] );
		parent::tearDown();
	}

	public function test_new_plugin_activation_keeps_prior_store(): void {
		$prior = $this->seedRichStore(
			array(
				'new_plugin_review_enabled' => true,
				'new_plugin_known'          => array( 'ai/ai.php' ),
			)
		);

		New_Plugin::instance()->on_activated_plugin( 'brand-new/plugin.php' );

		$this->assertStoredKeepsPrior(
			$prior,
			$this->rawStore(),
			array( 'plugins', 'new_plugin_pending', 'new_plugin_known' )
		);
	}

	public function test_temp_allow_sweep_keeps_prior_store(): void {
		$now   = 1_800_000_000;
		$prior = $this->seedRichStore(
			array(
				'plugins'        => array(
					'ai/ai.php'   => 'allow',
					'temp/exp.php' => 'allow',
				),
				'plugin_expires' => array(
					'temp/exp.php' => $now - 10,
				),
				'plugin_notes'   => array(
					'ai/ai.php' => 'keep this note',
				),
			)
		);

		Temp_Allow::sweep_expired( Policy::get_policy(), $now );

		$this->assertStoredKeepsPrior(
			$prior,
			$this->rawStore(),
			array( 'plugins', 'plugin_expires', 'plugin_notes' )
		);
		$this->assertArrayNotHasKey( 'temp/exp.php', $this->rawStore()['plugins'] );
		$this->assertSame( 'allow', $this->rawStore()['plugins']['ai/ai.php'] );
	}

	public function test_preset_apply_keeps_prior_store(): void {
		$prior  = $this->seedRichStore();
		$result = Presets::apply( 'lockdown', Policy::get_policy() );
		$this->assertTrue( $result['ok'] );
		$this->assertSame( 'applied', $result['status'] );

		$this->assertStoredKeepsPrior(
			$prior,
			$this->rawStore(),
			array(
				'default',
				'audit_only',
				'log_enabled',
				'kill_switch',
				'shadow_block_enabled',
				'unknown_operation',
				'alert_on_deny',
				'alert_on_shadow',
				'alert_mode',
			)
		);
	}

	public function test_pack_apply_keeps_prior_store(): void {
		$prior  = $this->seedRichStore();
		$result = Policy_Packs::apply( 'observe_first', Policy::get_policy() );
		$this->assertTrue( $result['ok'] );
		$this->assertSame( 'applied', $result['status'] );

		$this->assertStoredKeepsPrior(
			$prior,
			$this->rawStore(),
			array(
				'default',
				'audit_only',
				'log_enabled',
				'kill_switch',
				'shadow_block_enabled',
				'unknown_operation',
				'alert_on_deny',
				'alert_on_shadow',
				'alert_mode',
				'new_plugin_review_enabled',
				'new_plugin_interim',
				'plugins',
				'operations',
			)
		);
	}

	public function test_snapshot_restore_keeps_prior_store(): void {
		$prior = $this->seedRichStore();
		$mutated = Policy::get_policy();
		$mutated['default'] = 'deny';
		Policy::save_policy( $mutated );
		$this->assertSame( 'deny', $this->rawStore()['default'] );

		$restored = Policy_Snapshots::restore_latest();
		$this->assertTrue( $restored['ok'] );

		$this->assertStoredKeepsPrior( $prior, $this->rawStore() );
	}

	public function test_break_glass_restore_keeps_prior_store(): void {
		$prior = $this->seedRichStore();
		$now   = 1_800_000_000;
		$start = Break_Glass::start( 15, 'contract proof', $now );
		$this->assertTrue( $start['ok'] );

		$mutated = Policy::get_policy();
		$mutated['default']     = 'deny';
		$mutated['kill_switch'] = true;
		Policy::save_policy( $mutated );

		$cancel = Break_Glass::cancel( $now + 10 );
		$this->assertTrue( $cancel['ok'] );

		$this->assertStoredKeepsPrior( $prior, $this->rawStore() );
	}

	public function test_onboarding_mode_write_keeps_prior_store(): void {
		$prior  = $this->seedRichStore();
		$policy = Onboarding::apply_mode_to_policy( Policy::get_policy(), Onboarding::MODE_OBSERVE, 10 );
		Policy::save_policy( $policy );

		$this->assertStoredKeepsPrior(
			$prior,
			$this->rawStore(),
			array( 'audit_only', 'log_enabled', 'log_max_age_days' )
		);
	}

	public function test_set_plugin_rule_keeps_prior_store(): void {
		$prior = $this->seedRichStore();
		$this->assertTrue( Policy::set_plugin_rule( 'ai/ai.php', 'deny' ) );

		$this->assertStoredKeepsPrior(
			$prior,
			$this->rawStore(),
			array( 'plugins', 'plugin_expires', 'plugin_notes', 'new_plugin_known', 'new_plugin_pending' )
		);
		$this->assertSame( 'deny', $this->rawStore()['plugins']['ai/ai.php'] );
	}

	public function test_set_family_rule_keeps_prior_store(): void {
		$prior = $this->seedRichStore();
		$this->assertTrue( Policy::set_family_rule( 'ai/ai.php', Operations::FAMILY_TEXT, 'deny' ) );

		$this->assertStoredKeepsPrior(
			$prior,
			$this->rawStore(),
			array( 'operations' )
		);
	}

	/**
	 * Older export missing newer keys: file keys land; keys only on the live
	 * store are gone from the raw option; get_policy() still returns defaults.
	 */
	public function test_policy_transfer_import_of_older_json_does_not_drop_file_keys(): void {
		$this->seedRichStore();
		$parsed = Policy_Transfer::parse_import( $this->olderExportJson() );
		$this->assertTrue( $parsed['ok'] );

		$incoming = $parsed['policy'];
		Policy::save_policy( Policy_Transfer::policy_for_save( $incoming ) );

		$after = $this->rawStore();
		foreach ( $incoming as $key => $value ) {
			$this->assertArrayHasKey( $key, $after, "import dropped file key {$key}" );
			$this->assertSame( $value, $after[ $key ], "import mutated file key {$key}" );
		}

		$this->assertArrayNotHasKey( 'governance_digest_enabled', $after );
		$this->assertArrayNotHasKey( 'governance_digest_always_send', $after );
		$this->assertArrayNotHasKey( 'policy_backup_email_enabled', $after );
		$this->assertArrayNotHasKey( 'plugin_notes', $after );
		$this->assertArrayNotHasKey( 'plugin_budget_modes', $after );
		$this->assertArrayNotHasKey( 'weekly_report_enabled', $after );

		$read = Policy::get_policy();
		$this->assertFalse( $read['governance_digest_enabled'] );
		$this->assertFalse( $read['policy_backup_email_enabled'] );
		$this->assertSame( array(), $read['plugin_notes'] );
		$this->assertSame( array(), $read['plugin_budget_modes'] );
	}

	public function test_cli_apply_of_older_json_does_not_drop_file_keys(): void {
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-cli-policy-apply.php';

		$this->seedRichStore();
		$prepared = CLI_Policy_Apply::prepare_apply( $this->olderExportJson(), 'https://example.test/', false );
		$this->assertTrue( $prepared['ok'] );

		CLI_Policy_Apply::commit_apply( $prepared['policy'] );

		$after    = $this->rawStore();
		$incoming = Policy_Transfer::parse_import( $this->olderExportJson() )['policy'];
		foreach ( $incoming as $key => $value ) {
			$this->assertArrayHasKey( $key, $after, "CLI apply dropped file key {$key}" );
			$this->assertSame( $value, $after[ $key ], "CLI apply mutated file key {$key}" );
		}

		$this->assertArrayNotHasKey( 'governance_digest_enabled', $after );
		$this->assertArrayNotHasKey( 'policy_backup_email_enabled', $after );
		$this->assertArrayNotHasKey( 'plugin_notes', $after );

		$read = Policy::get_policy();
		$this->assertFalse( $read['governance_digest_enabled'] );
		$this->assertFalse( $read['policy_backup_email_enabled'] );
		$this->assertSame( array(), $read['plugin_notes'] );
	}

	/**
	 * @return array<string,mixed>
	 */
	private function richFixture(): array {
		return array(
			'default'                          => 'allow',
			'plugins'                          => array(
				'ai/ai.php' => 'allow',
			),
			'plugin_notes'                     => array(
				'ai/ai.php' => 'keep this note',
			),
			'plugin_budget_modes'              => array(
				'ai/ai.php' => Budget::MODE_OBSERVE,
			),
			'log_enabled'                      => true,
			'audit_only'                       => false,
			'kill_switch'                      => false,
			'role_gate_enabled'                => false,
			'allowed_roles'                    => array(),
			'unknown_operation'                => 'inherit',
			'alert_on_deny'                    => false,
			'alert_on_shadow'                  => false,
			'shadow_block_enabled'             => false,
			'governance_digest_enabled'        => true,
			'governance_digest_always_send'    => true,
			'policy_backup_email_enabled'      => true,
			'weekly_report_enabled'            => true,
			'new_plugin_review_enabled'        => false,
			'new_plugin_interim'               => 'deny',
			'new_plugin_known'                 => array(),
			'new_plugin_pending'               => array(),
			'operations'                       => array(),
		);
	}

	/**
	 * @param array<string,mixed> $overrides
	 * @return array<string,mixed>
	 */
	private function seedRichStore( array $overrides = array() ): array {
		$stored = array_merge( $this->richFixture(), $overrides );
		update_option( Plugin::OPTION_KEY, $stored, false );
		return $stored;
	}

	/**
	 * @return array<string,mixed>
	 */
	private function rawStore(): array {
		$after = get_option( Plugin::OPTION_KEY );
		$this->assertIsArray( $after );
		return $after;
	}

	/**
	 * @param array<string,mixed> $prior
	 * @param array<string,mixed> $after
	 * @param list<string>        $changed_keys
	 */
	private function assertStoredKeepsPrior( array $prior, array $after, array $changed_keys = array() ): void {
		foreach ( $prior as $key => $value ) {
			$this->assertArrayHasKey( $key, $after, "writer dropped stored key {$key}" );
			if ( in_array( $key, $changed_keys, true ) ) {
				continue;
			}
			$this->assertSame( $value, $after[ $key ], "writer mutated stored key {$key}" );
		}
	}

	private function olderExportJson(): string {
		$json = wp_json_encode(
			array(
				'plugin_version' => '1.3.0',
				'exported_at'    => '2026-06-01T00:00:00Z',
				'default'        => 'deny',
				'plugins'        => array(
					'ai/ai.php' => 'allow',
				),
				'log_enabled'    => true,
				'kill_switch'    => false,
			)
		);
		$this->assertIsString( $json );
		return $json;
	}
}
