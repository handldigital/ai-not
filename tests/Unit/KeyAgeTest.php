<?php
/**
 * AICAC-KEY-AGE (#399).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Clock;
use HandL\AICAC\Key_Age;
use HandL\AICAC\Keyscan;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class KeyAgeTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12.

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Key_Age::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'haktan+aicac-key-age@handldigital.com',
			)
		);
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_filters'][ Key_Age::FILTER_MAX_DAYS ],
			$GLOBALS['handl_aicac_test_current_user_can']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		Key_Age::reset_for_tests();
		parent::tearDown();
	}

	private function enable(): void {
		Key_Age::save_settings(
			array(
				'enabled'      => true,
				'max_age_days' => 90,
			)
		);
	}

	private function seed_entry( string $provider, int $age_days, string $seed = '' ): void {
		Key_Age::put_ledger_entry(
			$provider,
			array(
				'fp'         => Key_Age::fingerprint_plaintext( 'sk-seed-' . $provider . $seed ),
				'rotated_at' => self::NOW - ( $age_days * 86400 ),
				'source'     => 'option',
				'slot'       => $provider . '_api_key',
			)
		);
	}

	/**
	 * @param array<string,array<string,mixed>> $rows Vault rows.
	 * @return array<string,mixed>
	 */
	private function vault_option( array $rows ): array {
		return array( 'keys' => $rows );
	}

	public function test_defaults_off_and_noop_save_byte_identical(): void {
		$this->assertFalse( Key_Age::is_enabled() );
		$this->assertSame( Key_Age::defaults(), Key_Age::get_settings() );
		$this->assertSame( 90, Key_Age::defaults()['max_age_days'] );
		$this->assertTrue( Key_Age::save_settings( array( 'enabled' => true, 'max_age_days' => 90 ) ) );
		$this->assertTrue( Key_Age::is_enabled() );
		$before  = get_option( Key_Age::SETTINGS_OPTION );
		$changed = Key_Age::save_settings( array( 'enabled' => true, 'max_age_days' => 90 ) );
		$this->assertFalse( $changed );
		$this->assertSame( $before, get_option( Key_Age::SETTINGS_OPTION ) );
		Key_Age::save_settings( Key_Age::defaults() );
		$this->assertFalse( (bool) get_option( Key_Age::SETTINGS_OPTION, false ) );
	}

	public function test_save_without_ledger_preserves_ledger(): void {
		$this->enable();
		$this->seed_entry( 'openai', 10 );
		$ledger = Key_Age::get_ledger();
		$this->assertArrayHasKey( 'openai', $ledger );
		Key_Age::save_settings(
			array(
				'enabled'      => false,
				'max_age_days' => 60,
			)
		);
		$this->assertSame( $ledger, Key_Age::get_ledger() );
		$this->assertSame( 60, Key_Age::get_settings()['max_age_days'] );
	}

	public function test_ledger_stores_hash_not_key_material(): void {
		$this->enable();
		$key = 'sk-proj-ABCDEFGHIJKLMNOP1234567890wxyz';
		Key_Age::observe_plugin_option( '', $key, 'openai_api_key' );

		$stored = get_option( Key_Age::SETTINGS_OPTION );
		$dump   = serialize( $stored ) . json_encode( $stored ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
		$this->assertStringNotContainsString( $key, $dump );
		$this->assertStringNotContainsString( 'sk-', $dump );
		$this->assertStringNotContainsString( 'wxyz', $dump );
		$entry = Key_Age::get_ledger()['openai'];
		$this->assertSame( Key_Age::fingerprint_plaintext( $key ), $entry['fp'] );
		$this->assertSame( 64, strlen( $entry['fp'] ) );
		$this->assertSame( hash_hmac( 'sha256', $key, wp_salt( 'auth' ) . '|handl_aicac_key_age_v1' ), $entry['fp'] );
		$this->assertSame( Key_Age::fingerprint_plaintext( $key ), Key_Age::fingerprint_plaintext( '  ' . $key . "\n" ) );
	}

	public function test_observe_plugin_option_updates_ledger(): void {
		$this->enable();
		Key_Age::observe_plugin_option( '', 'sk-first-key-0001', 'openai_api_key' );
		$first = Key_Age::get_ledger()['openai'];
		$this->assertSame( 'option', $first['source'] );
		$this->assertSame( 'openai_api_key', $first['slot'] );

		// Same value again: ledger untouched.
		Key_Age::observe_plugin_option( 'sk-first-key-0001', 'sk-first-key-0001', 'openai_api_key' );
		$this->assertSame( $first, Key_Age::get_ledger()['openai'] );

		Key_Age::observe_plugin_option( 'sk-first-key-0001', 'sk-second-key-0002', 'openai_api_key' );
		$second = Key_Age::get_ledger()['openai'];
		$this->assertNotSame( $first['fp'], $second['fp'] );
		$this->assertSame( Key_Age::fingerprint_plaintext( 'sk-second-key-0002' ), $second['fp'] );

		Key_Age::observe_plugin_option_added( 'anthropic_api_key', 'ant-key-aaaa' );
		$this->assertArrayHasKey( 'anthropic', Key_Age::get_ledger() );
		Key_Age::observe_plugin_option( '', 'g-key-bbbb', 'google_ai_api_key' );
		$this->assertArrayHasKey( 'google', Key_Age::get_ledger() );

		// Empty / unknown options ignored.
		Key_Age::observe_plugin_option( 'x', '', 'google_ai_api_key' );
		Key_Age::observe_plugin_option( '', 'zzz', 'not_a_key_option' );
		$this->assertCount( 3, Key_Age::get_ledger() );
	}

	public function test_observe_vault_update(): void {
		$this->enable();
		$row = array(
			'suffix'     => 'abcd',
			'revoked'    => false,
			'updated_at' => self::NOW - ( 5 * 86400 ),
			'n'          => 'bm9uY2U=',
			'c'          => 'Y2lwaGVy',
		);
		$vault = $this->vault_option(
			array(
				'openai'    => $row,
				'anthropic' => array_merge( $row, array( 'revoked' => true, 'n' => '', 'c' => '' ) ),
				'google'    => array_merge( $row, array( 'c' => '' ) ),
			)
		);
		update_option( Key_Age::VAULT_OPTION, $vault, false );
		Key_Age::observe_vault( array(), $vault, Key_Age::VAULT_OPTION );

		$ledger = Key_Age::get_ledger();
		$this->assertSame( array( 'openai' ), array_keys( $ledger ) );
		$this->assertSame( Key_Age::fingerprint_vault_row( $row ), $ledger['openai']['fp'] );
		$this->assertSame( 'vault', $ledger['openai']['source'] );
		$this->assertSame( (int) $row['updated_at'], $ledger['openai']['rotated_at'] );
		$this->assertSame( hash_hmac( 'sha256', 'bm9uY2U=|Y2lwaGVy', wp_salt( 'auth' ) . '|handl_aicac_key_age_v1' ), $ledger['openai']['fp'] );
		$this->assertSame( '', Key_Age::fingerprint_vault_row( array( 'revoked' => true, 'n' => 'a', 'c' => 'b' ) ) );

		$rotated            = $row;
		$rotated['c']       = 'bmV3Y2lwaGVy';
		$rotated['updated_at'] = self::NOW;
		$vault2             = $this->vault_option( array( 'openai' => $rotated ) );
		Key_Age::observe_vault_added( Key_Age::VAULT_OPTION, $vault2 );
		$this->assertSame( Key_Age::fingerprint_vault_row( $rotated ), Key_Age::get_ledger()['openai']['fp'] );
		$this->assertSame( self::NOW, Key_Age::get_ledger()['openai']['rotated_at'] );
	}

	public function test_age_tiers_ok_due_overdue(): void {
		$this->enable();
		$this->assertSame( 'ok', Key_Age::tier( 30, 90 ) );
		$this->assertSame( 'due', Key_Age::tier( 80, 90 ) );
		$this->assertSame( 'overdue', Key_Age::tier( 90, 90 ) );

		$this->seed_entry( 'openai', 30 );
		$this->seed_entry( 'anthropic', 80 );
		$this->seed_entry( 'google', 90 );
		$by = array();
		foreach ( Key_Age::roster( self::NOW ) as $row ) {
			$by[ $row['provider'] ] = $row;
		}
		$this->assertSame( 'ok', $by['openai']['tier'] );
		$this->assertSame( 30, $by['openai']['age_days'] );
		$this->assertSame( 'due', $by['anthropic']['tier'] );
		$this->assertSame( 'overdue', $by['google']['tier'] );
		$this->assertSame( 90, $by['google']['max_days'] );
		$this->assertSame( 90, Key_Age::age_days( Key_Age::get_ledger()['google'], self::NOW ) );
		$this->assertTrue( Key_Age::has_overdue_or_unmanaged( self::NOW ) );
	}

	public function test_per_provider_max_age_override(): void {
		Key_Age::save_settings(
			array(
				'enabled'           => true,
				'max_age_days'      => 90,
				'provider_max_days' => array( 'openai' => 30 ),
			)
		);
		$this->assertSame( 30, Key_Age::max_age_days( 'openai' ) );
		$this->assertSame( 90, Key_Age::max_age_days( 'anthropic' ) );
		$this->seed_entry( 'openai', 35 );
		$this->seed_entry( 'anthropic', 35 );
		$by = array();
		foreach ( Key_Age::roster( self::NOW ) as $row ) {
			$by[ $row['provider'] ] = $row;
		}
		$this->assertSame( 'overdue', $by['openai']['tier'] );
		$this->assertSame( 'ok', $by['anthropic']['tier'] );

		$GLOBALS['handl_aicac_test_filters'][ Key_Age::FILTER_MAX_DAYS ] = static function (): int {
			return 365;
		};
		$this->assertSame( 365, Key_Age::max_age_days( 'openai' ) );
	}

	public function test_alert_fires_once_and_rearms_on_rotation(): void {
		$this->enable();
		$this->seed_entry( 'openai', 120 );

		$first = Key_Age::maybe_fire_alerts( self::NOW );
		$this->assertSame( array( 'openai' ), $first );
		$mails = Key_Age::test_mails();
		$this->assertCount( 1, $mails );
		$this->assertStringContainsString( '[KEY-AGE]', $mails[0]['subject'] );
		$this->assertStringContainsString( 'haktan+aicac-key-age@handldigital.com', $mails[0]['to'] );
		$this->assertArrayHasKey( 'openai', Key_Age::get_alerted() );

		$this->assertSame( array(), Key_Age::maybe_fire_alerts( self::NOW ) );
		$this->assertCount( 1, Key_Age::test_mails() );

		// Observed rotation re-arms the alert.
		Key_Age::observe_plugin_option( 'old', 'sk-rotated-new-key', 'openai_api_key' );
		$this->assertSame( array(), Key_Age::get_alerted() );
		$this->assertSame( array(), Key_Age::maybe_fire_alerts( Clock::now() ) ); // Fresh key → ok.

		// Age past the limit again → second alert.
		$later = Clock::now() + ( 100 * 86400 );
		$this->assertSame( array( 'openai' ), Key_Age::maybe_fire_alerts( $later ) );
		$this->assertCount( 2, Key_Age::test_mails() );
	}

	public function test_unmanaged_keyscan_finding(): void {
		$this->enable();
		update_option( 'active_plugins', array( 'leaky/leaky.php' ), false );
		update_option(
			Keyscan::OPTION_KEY,
			array(
				'findings'  => array(
					array(
						'plugin'   => 'leaky/leaky.php',
						'provider' => 'openai',
						'source'   => 'file',
						'location' => 'config.php',
						'suffix'   => 'wxyz',
					),
					array(
						'plugin'   => 'inactive/inactive.php',
						'provider' => 'anthropic',
						'source'   => 'file',
						'location' => 'x.php',
						'suffix'   => 'aaaa',
					),
				),
				'last_scan' => self::NOW,
			),
			false
		);

		$rows = Key_Age::roster( self::NOW );
		$this->assertCount( 1, $rows );
		$this->assertSame( 'unmanaged', $rows[0]['tier'] );
		$this->assertSame( 'openai', $rows[0]['provider'] );
		$this->assertSame( array( 'leaky/leaky.php' ), $rows[0]['plugins'] );
		$this->assertTrue( Key_Age::has_overdue_or_unmanaged( self::NOW ) );

		// A custody vault entry makes it managed (seeded into the ledger, not unmanaged).
		update_option(
			Key_Age::VAULT_OPTION,
			$this->vault_option(
				array(
					'openai' => array(
						'revoked'    => false,
						'updated_at' => self::NOW - 86400,
						'n'          => 'bg==',
						'c'          => 'Yw==',
					),
				)
			),
			false
		);
		$rows = Key_Age::roster( self::NOW );
		$this->assertCount( 1, $rows );
		$this->assertSame( 'ok', $rows[0]['tier'] );
		$this->assertSame( 'vault_seed', $rows[0]['source'] );
		$this->assertFalse( Key_Age::has_overdue_or_unmanaged( self::NOW ) );
	}

	public function test_custody_deep_link_when_class_exists(): void {
		$this->assertStringContainsString( 'handl-aicac-key-age', Key_Age::admin_url() );
		if ( class_exists( 'HandL\\AICAC\\Key_Custody', false ) ) {
			$this->assertStringContainsString( 'handl-aicac-key-custody', Key_Age::custody_url() );
		} else {
			$this->assertSame( '', Key_Age::custody_url() );
		}
	}

	public function test_csv_export_columns(): void {
		$this->enable();
		$this->seed_entry( 'openai', 95 );
		$csv   = Key_Age::csv_for_roster( Key_Age::roster( self::NOW ) );
		$lines = explode( "\n", trim( $csv ) );
		$this->assertSame(
			'provider,tier,age_days,max_days,days_remaining,rotated_at,source,slot,custody,plugins,deep_link,framing',
			$lines[0]
		);
		$this->assertStringStartsWith( 'openai,overdue,95,90,-5,', $lines[1] );
		$this->assertStringContainsString( 'informational_never_blocks', $lines[1] );
		$this->assertStringNotContainsString( 'sk-', $csv );
		$this->assertStringContainsString( 'AI key age', Key_Age::build_print_html( Key_Age::roster( self::NOW ) ) );
	}

	public function test_disabled_page_and_readonly(): void {
		$this->assertFalse( Key_Age::is_enabled() );
		$this->assertSame( array(), Key_Age::roster( self::NOW ) );
		$this->assertSame( array(), Key_Age::maybe_fire_alerts( self::NOW ) );

		Key_Age::observe_plugin_option( '', 'sk-disabled-key', 'openai_api_key' );
		Key_Age::observe_vault(
			array(),
			$this->vault_option(
				array(
					'openai' => array(
						'revoked' => false,
						'n'       => 'bg==',
						'c'       => 'Yw==',
					),
				)
			),
			Key_Age::VAULT_OPTION
		);
		$this->assertFalse( get_option( Key_Age::SETTINGS_OPTION, false ) );

		$_GET['page'] = Key_Age::PAGE_SLUG;
		ob_start();
		Key_Age::render_page();
		$html = ob_get_clean();
		$this->assertStringContainsString( 'Key-age tracking is off', $html );
		$this->assertStringNotContainsString( 'Key roster', $html );
		unset( $_GET['page'] );

		// Enabled: observers write only our own options, never vault/keyscan.
		$this->enable();
		update_option( 'active_plugins', array( 'leaky/leaky.php' ), false );
		update_option( Keyscan::OPTION_KEY, array( 'findings' => array(), 'last_scan' => 1 ), false );
		$vault = $this->vault_option(
			array(
				'google' => array(
					'revoked'    => false,
					'updated_at' => self::NOW,
					'n'          => 'bg==',
					'c'          => 'Yw==',
				),
			)
		);
		update_option( Key_Age::VAULT_OPTION, $vault, false );
		$before = $GLOBALS['handl_aicac_test_options'];

		Key_Age::observe_plugin_option( '', 'sk-enabled-key', 'openai_api_key' );
		Key_Age::observe_vault( array(), $vault, Key_Age::VAULT_OPTION );
		Key_Age::roster( self::NOW );
		Key_Age::maybe_fire_alerts( self::NOW );

		$after = $GLOBALS['handl_aicac_test_options'];
		$this->assertSame( $before[ Key_Age::VAULT_OPTION ], $after[ Key_Age::VAULT_OPTION ] );
		$this->assertSame( $before[ Keyscan::OPTION_KEY ], $after[ Keyscan::OPTION_KEY ] );
		$this->assertSame( $before[ Plugin::OPTION_KEY ], $after[ Plugin::OPTION_KEY ] );
		$this->assertSame( $before['active_plugins'], $after['active_plugins'] );
		$this->assertArrayHasKey( 'openai', Key_Age::get_ledger() );
		$this->assertArrayHasKey( 'google', Key_Age::get_ledger() );
	}
}
