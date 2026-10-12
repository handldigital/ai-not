<?php
/**
 * AICAC-UNATTENDED (#403).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Caps;
use HandL\AICAC\Plugin;
use HandL\AICAC\Unattended;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class UnattendedTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12.

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Unattended::reset_for_tests();
		putenv( 'HANDL_AICAC_TEST_NOW=' . (string) self::NOW );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'haktan+aicac-unattended@handldigital.com',
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
		update_option( 'admin_email', 'admin@example.com' );
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_filters'][ Unattended::FILTER_DAYS ],
			$GLOBALS['handl_aicac_test_current_user_can'],
			$GLOBALS['handl_aicac_unattended_test_log'],
			$GLOBALS['handl_aicac_test_users']
		);
		putenv( 'HANDL_AICAC_TEST_NOW' );
		$GLOBALS['handl_aicac_test_options'] = array();
		Unattended::reset_for_tests();
		parent::tearDown();
	}

	private function set_now( int $ts ): void {
		putenv( 'HANDL_AICAC_TEST_NOW=' . (string) $ts );
	}

	/**
	 * @param array<string,mixed> $extra Extra settings.
	 */
	private function enable( int $days = 21, string $backup = 'backup@example.com', array $extra = array() ): void {
		Unattended::save_settings(
			array_merge(
				array(
					'enabled'      => true,
					'days'         => $days,
					'backup_email' => $backup,
				),
				$extra
			)
		);
	}

	/**
	 * @return object User-like object with has_cap.
	 */
	private function make_user( int $id, bool $can_manage ): object {
		return new class( $id, $can_manage ) {
			/** @var int */
			public $ID;
			/** @var bool */
			private $can_manage;

			public function __construct( int $id, bool $can_manage ) {
				$this->ID         = $id;
				$this->can_manage = $can_manage;
			}

			/**
			 * @param string $cap Capability.
			 */
			public function has_cap( $cap ): bool {
				return $this->can_manage && Caps::MANAGE === (string) $cap;
			}
		};
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private function activity_log( int $now, int $calls = 3 ): array {
		$rows = array();
		for ( $i = 0; $i < $calls; $i++ ) {
			$decision = 0 === $i % 3 ? 'deny' : ( 1 === $i % 3 ? 'allow' : 'observe' );
			$rows[]   = array(
				'ts'       => $now - ( $i * 3600 ),
				'decision' => $decision,
				'provider' => 0 === $i % 2 ? 'openai' : 'anthropic',
				'plugin'   => 'acme/acme.php',
				'count'    => 1,
			);
		}

		return $rows;
	}

	public function test_defaults_off_save_defaults_deletes_and_noop_byte_identical(): void {
		$this->assertFalse( Unattended::is_enabled() );
		$this->assertSame( Unattended::defaults(), Unattended::get_settings() );
		$this->assertSame( 21, Unattended::defaults()['days'] );

		$this->assertTrue(
			Unattended::save_settings(
				array(
					'enabled'      => true,
					'days'         => 21,
					'backup_email' => '',
				)
			)
		);
		$this->assertTrue( Unattended::is_enabled() );
		$before  = get_option( Unattended::SETTINGS_OPTION );
		$changed = Unattended::save_settings(
			array(
				'enabled'      => true,
				'days'         => 21,
				'backup_email' => '',
			)
		);
		$this->assertFalse( $changed );
		$this->assertSame( $before, get_option( Unattended::SETTINGS_OPTION ) );

		Unattended::save_settings( Unattended::defaults() );
		$this->assertFalse( (bool) get_option( Unattended::SETTINGS_OPTION, false ) );
	}

	public function test_days_sanitize_and_filter(): void {
		$this->assertSame( 1, Unattended::sanitize_days( 0 ) );
		$this->assertSame( 365, Unattended::sanitize_days( 9999 ) );
		$this->assertSame( 21, Unattended::sanitize_days( 'nope' ) );

		$this->enable( 30 );
		$this->assertSame( 30, Unattended::days() );
		$GLOBALS['handl_aicac_test_filters'][ Unattended::FILTER_DAYS ] = static function (): int {
			return 14;
		};
		$this->assertSame( 14, Unattended::days() );
	}

	public function test_wp_login_stamps_manage_user_only(): void {
		$this->enable( 21 );
		$manage = $this->make_user( 7, true );
		$guest  = $this->make_user( 8, false );

		Unattended::on_wp_login( 'guest', $guest );
		$this->assertSame( array(), Unattended::get_state()['ledger'] );

		$this->set_now( self::NOW );
		Unattended::on_wp_login( 'admin', $manage );
		$ledger = Unattended::get_state()['ledger'];
		$this->assertArrayHasKey( '7', $ledger );
		$this->assertSame( 7, $ledger['7']['user_id'] );
		$this->assertSame( self::NOW, $ledger['7']['ts'] );
		$this->assertArrayNotHasKey( '8', $ledger );
	}

	public function test_quiet_site_never_alerts(): void {
		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
		$this->set_now( self::NOW - ( 30 * $day ) );
		$this->enable( 21, 'backup@example.com' );
		$state                   = Unattended::get_state();
		$state['watching_since'] = self::NOW - ( 40 * $day );
		Unattended::put_state( $state );

		$GLOBALS['handl_aicac_unattended_test_log'] = array();
		$this->set_now( self::NOW );

		$this->assertFalse( Unattended::is_unattended( self::NOW ) );
		$this->assertFalse( Unattended::maybe_fire_alerts( null, self::NOW ) );
		$this->assertCount( 0, Unattended::test_mails() );
	}

	public function test_alert_fires_once_with_activity_and_absence(): void {
		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
		$this->set_now( self::NOW - ( 30 * $day ) );
		$this->enable( 21, 'backup@example.com' );
		$state                   = Unattended::get_state();
		$state['watching_since'] = self::NOW - ( 40 * $day );
		$state['ledger']         = array(
			'3' => array(
				'user_id' => 3,
				'ts'      => self::NOW - ( 40 * $day ),
			),
		);
		Unattended::put_state( $state );

		$GLOBALS['handl_aicac_unattended_test_log'] = $this->activity_log( self::NOW );
		$this->set_now( self::NOW );

		$this->assertTrue( Unattended::is_unattended( self::NOW ) );
		$this->assertTrue( Unattended::maybe_fire_alerts( null, self::NOW ) );
		$mails = Unattended::test_mails();
		$this->assertCount( 1, $mails );
		$this->assertSame( 'backup@example.com', $mails[0]['to'] );
		$this->assertStringContainsString( '[UNATTENDED]', $mails[0]['subject'] );
		$this->assertTrue( Unattended::is_alerted() );

		$this->assertFalse( Unattended::maybe_fire_alerts( null, self::NOW ) );
		$this->assertCount( 1, Unattended::test_mails() );
	}

	public function test_qualifying_login_rearms(): void {
		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
		$this->set_now( self::NOW - ( 30 * $day ) );
		$this->enable( 21, 'backup@example.com' );
		$state                   = Unattended::get_state();
		$state['watching_since'] = self::NOW - ( 40 * $day );
		$state['ledger']         = array(
			'3' => array(
				'user_id' => 3,
				'ts'      => self::NOW - ( 40 * $day ),
			),
		);
		Unattended::put_state( $state );
		$GLOBALS['handl_aicac_unattended_test_log'] = $this->activity_log( self::NOW );
		$this->set_now( self::NOW );

		$this->assertTrue( Unattended::maybe_fire_alerts( null, self::NOW ) );
		$this->assertTrue( Unattended::is_alerted() );

		$this->set_now( self::NOW + 60 );
		Unattended::on_wp_login( 'admin', $this->make_user( 9, true ) );
		$this->assertFalse( Unattended::is_alerted() );
		$this->assertArrayHasKey( '9', Unattended::get_state()['ledger'] );
		$this->assertSame( self::NOW + 60, Unattended::get_state()['ledger']['9']['ts'] );

		$this->assertFalse( Unattended::is_unattended( self::NOW + 60 ) );

		$later = self::NOW + 60 + ( 22 * $day );
		$GLOBALS['handl_aicac_unattended_test_log'] = $this->activity_log( $later );
		$this->assertTrue( Unattended::is_unattended( $later ) );
		$this->assertTrue( Unattended::maybe_fire_alerts( null, $later ) );
		$this->assertCount( 2, Unattended::test_mails() );
	}

	public function test_backup_email_falls_back_to_admin_email(): void {
		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
		$this->set_now( self::NOW - ( 30 * $day ) );
		$this->enable( 21, '' );
		$state                   = Unattended::get_state();
		$state['watching_since'] = self::NOW - ( 40 * $day );
		Unattended::put_state( $state );
		$GLOBALS['handl_aicac_unattended_test_log'] = $this->activity_log( self::NOW );
		$this->set_now( self::NOW );

		$this->assertSame( 'admin@example.com', Unattended::resolve_backup_email() );
		$this->assertTrue( Unattended::maybe_fire_alerts( null, self::NOW ) );
		$this->assertSame( 'admin@example.com', Unattended::test_mails()[0]['to'] );
	}

	public function test_csv_contains_roster_columns(): void {
		$this->enable( 21 );
		$this->set_now( self::NOW );
		Unattended::stamp_attention( 5, self::NOW - 100 );
		$GLOBALS['handl_aicac_test_users'] = array(
			5 => array(
				'user_login'   => 'ops',
				'display_name' => 'Ops Person',
			),
		);

		$csv = Unattended::csv_for_roster();
		$this->assertStringContainsString( 'user_id,login,last_seen_ts,last_seen_utc,source,framing', $csv );
		$this->assertStringContainsString( '5,ops,', $csv );
		$this->assertStringContainsString( 'login', $csv );
		$this->assertStringContainsString( Unattended::FRAMING, $csv );
		$this->assertNotSame( "user_id,login,last_seen_ts,last_seen_utc,source,framing\n", $csv );
	}

	public function test_cli_status_nonzero_via_is_unattended(): void {
		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
		$this->set_now( self::NOW - ( 30 * $day ) );
		$this->enable( 21 );
		$state                   = Unattended::get_state();
		$state['watching_since'] = self::NOW - ( 40 * $day );
		Unattended::put_state( $state );
		$GLOBALS['handl_aicac_unattended_test_log'] = $this->activity_log( self::NOW );
		$this->set_now( self::NOW );

		$this->assertTrue( Unattended::is_unattended( self::NOW ) );

		$GLOBALS['handl_aicac_unattended_test_log'] = array();
		$this->assertFalse( Unattended::is_unattended( self::NOW ) );
	}

	public function test_save_sets_watching_since_on_enable(): void {
		$this->set_now( self::NOW );
		$this->assertSame( 0, Unattended::get_state()['watching_since'] );
		$this->enable( 21 );
		$this->assertSame( self::NOW, Unattended::get_state()['watching_since'] );
	}

	public function test_attention_from_signals_helper(): void {
		$this->assertSame( 50, Unattended::attention_from_signals( 10, 50, 20 ) );
		$this->assertSame( 10, Unattended::attention_from_signals( 10, 0, 0 ) );
	}
}
