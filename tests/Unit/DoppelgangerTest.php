<?php
/**
 * AICAC-DOPPELGANGER (#423).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Doppelganger;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class DoppelgangerTest extends TestCase {

	private const NOW = 1791800000; // 2026-10-12 UTC.

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$GLOBALS['handl_aicac_test_cron']             = array();
		Doppelganger::reset_for_tests();
		update_option( 'admin_email', 'owner@prod.example.com' );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'alert_email' => 'alerts@prod.example.com',
			)
		);
		Doppelganger::set_test_now( self::NOW );
		Doppelganger::set_test_identity( $this->identity() );
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_cron']          = array();
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		Doppelganger::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * @param array<string,string> $over Overrides.
	 * @return array<string,string>
	 */
	private function identity( array $over = array() ): array {
		return array_merge(
			array(
				'site_url'     => 'https://www.example.com/',
				'home'         => 'https://www.example.com/',
				'table_prefix' => 'wp_',
				'environment'  => 'production',
				'db_hash'      => str_repeat( 'a', 64 ),
			),
			$over
		);
	}

	private function enable( bool $outbound = false ): void {
		Doppelganger::save_settings(
			array(
				'enabled'        => true,
				'outbound_alert' => $outbound,
			)
		);
	}

	/**
	 * @return list<string>
	 */
	private function codes(): array {
		$codes = array();
		foreach ( Doppelganger::snapshot( self::NOW )['findings'] as $row ) {
			$codes[] = $row['code'];
		}

		return $codes;
	}

	public function test_defaults_off_outbound_off_save_defaults_deletes_and_noop(): void {
		$this->assertFalse( Doppelganger::is_enabled() );
		$this->assertFalse( Doppelganger::is_outbound_enabled() );
		$this->assertSame(
			array(
				'enabled'        => false,
				'outbound_alert' => false,
			),
			Doppelganger::defaults()
		);
		$this->assertSame( Doppelganger::defaults(), Doppelganger::get_settings() );
		$this->assertSame( 'report_only_never_flips_outbound', Doppelganger::FRAMING );
		$this->assertSame( 'handl-aicac-doppelganger', Doppelganger::PAGE_SLUG );
		$this->assertSame( 'handl_aicac_doppelganger', Doppelganger::SETTINGS_OPTION );
		$this->assertSame( 'handl_aicac_doppelganger_state', Doppelganger::STATE_OPTION );

		$this->assertTrue( Doppelganger::save_settings( array( 'enabled' => true ) ) );
		$this->assertTrue( Doppelganger::is_enabled() );
		$this->assertFalse( Doppelganger::is_outbound_enabled(), 'enabling does not opt in to outbound' );
		$before = get_option( Doppelganger::SETTINGS_OPTION );
		$this->assertFalse( Doppelganger::save_settings( array( 'enabled' => true ) ) );
		$this->assertSame( $before, get_option( Doppelganger::SETTINGS_OPTION ) );

		$this->assertTrue( Doppelganger::save_settings( Doppelganger::defaults() ) );
		$this->assertFalse( (bool) get_option( Doppelganger::SETTINGS_OPTION, false ) );
		$this->assertFalse( Doppelganger::save_settings( Doppelganger::defaults() ) );
		$this->assertSame( Doppelganger::defaults(), Doppelganger::sanitize_settings( 'junk' ) );
	}

	public function test_disabled_does_nothing(): void {
		$this->assertFalse( Doppelganger::maybe_check( self::NOW, true ) );
		$this->assertFalse( Doppelganger::rebaseline( self::NOW ) );
		$this->assertFalse( Doppelganger::maybe_fire_alerts( self::NOW ) );
		$this->assertFalse( get_option( Doppelganger::STATE_OPTION, false ) );
	}

	public function test_first_enable_captures_fingerprint_without_finding_or_alert(): void {
		$this->enable();
		$state = Doppelganger::get_state();
		$this->assertSame( $this->identity(), $state['fingerprint'] );
		$this->assertSame( self::NOW, $state['baselined_ts'] );
		$this->assertFalse( $state['alerted'] );

		$snap = Doppelganger::snapshot( self::NOW );
		$this->assertFalse( $snap['baseline_pending'] );
		$this->assertSame( 0, $snap['unacknowledged_count'] );
		$this->assertSame( array(), $this->codes() );
		$this->assertFalse( Doppelganger::maybe_fire_alerts( self::NOW ) );
		$this->assertSame( array(), Doppelganger::test_mails() );
	}

	public function test_enabled_without_fingerprint_captures_silently_on_check(): void {
		update_option( Doppelganger::SETTINGS_OPTION, array( 'enabled' => true ) );
		Doppelganger::set_test_identity( $this->identity( array( 'environment' => 'staging' ) ) );

		$this->assertTrue( Doppelganger::maybe_check( self::NOW, true ) );
		$this->assertSame( 'staging', Doppelganger::get_state()['fingerprint']['environment'] );
		$this->assertSame( array(), $this->codes() );
		$this->assertFalse( Doppelganger::is_alerted() );
	}

	public function test_fingerprint_is_not_recaptured_by_later_enables_or_checks(): void {
		$this->enable();
		Doppelganger::set_test_identity( $this->identity( array( 'table_prefix' => 'dev_' ) ) );
		$this->assertFalse( Doppelganger::ensure_baseline( self::NOW + 5 ) );
		Doppelganger::save_settings( Doppelganger::defaults() );
		$this->enable();
		$this->assertSame( 'wp_', Doppelganger::get_state()['fingerprint']['table_prefix'] );
		$this->assertSame( array( 'prefix_changed' ), $this->codes() );
	}

	public function test_url_mismatch_is_a_finding_and_trailing_slash_is_not(): void {
		$this->enable();
		Doppelganger::set_test_identity( $this->identity( array( 'site_url' => 'https://WWW.example.com', 'home' => 'https://www.example.com' ) ) );
		$this->assertSame( array(), $this->codes(), 'case and trailing slash are not a change' );

		Doppelganger::set_test_identity( $this->identity( array( 'site_url' => 'https://staging.example.com/', 'home' => 'https://staging.example.com/' ) ) );
		$snap = Doppelganger::snapshot( self::NOW );
		$this->assertSame( array( 'url_changed' ), $this->codes() );
		$this->assertSame( 'high', $snap['findings'][0]['severity'] );
		$this->assertSame( 'site_url+home', $snap['findings'][0]['field'] );

		Doppelganger::set_test_identity( $this->identity( array( 'home' => 'https://www.example.com/blog/' ) ) );
		$this->assertSame( array( 'url_changed' ), $this->codes(), 'home path change counts' );
	}

	public function test_scheme_only_change_is_a_softer_url_finding(): void {
		$this->enable();
		Doppelganger::set_test_identity( $this->identity( array( 'site_url' => 'http://www.example.com/', 'home' => 'http://www.example.com/' ) ) );
		$snap = Doppelganger::snapshot( self::NOW );
		$this->assertSame( array( 'url_changed' ), $this->codes() );
		$this->assertSame( 'scheme_only', $snap['findings'][0]['severity'] );
	}

	public function test_environment_prefix_and_db_mismatch_are_findings(): void {
		$this->enable();

		Doppelganger::set_test_identity( $this->identity( array( 'environment' => 'staging' ) ) );
		$this->assertSame( array( 'environment_changed' ), $this->codes() );

		Doppelganger::set_test_identity( $this->identity( array( 'table_prefix' => 'wpx_' ) ) );
		$this->assertSame( array( 'prefix_changed' ), $this->codes() );

		Doppelganger::set_test_identity( $this->identity( array( 'db_hash' => str_repeat( 'b', 64 ) ) ) );
		$this->assertSame( array( 'db_changed' ), $this->codes() );

		Doppelganger::set_test_identity(
			$this->identity(
				array(
					'site_url'     => 'https://dev.local/',
					'home'         => 'https://dev.local/',
					'environment'  => 'development',
					'table_prefix' => 'dev_',
					'db_hash'      => str_repeat( 'c', 64 ),
				)
			)
		);
		$this->assertSame( array( 'url_changed', 'environment_changed', 'prefix_changed', 'db_changed' ), $this->codes() );
	}

	public function test_db_hash_is_salted_hmac_and_state_holds_no_raw_secret(): void {
		if ( ! defined( 'DB_NAME' ) ) {
			define( 'DB_NAME', 'handl_secret_dbname' );
		}
		if ( ! defined( 'DB_HOST' ) ) {
			define( 'DB_HOST', 'secret-db-host.internal' );
		}
		$hash = Doppelganger::compute_db_hash( 'handl_secret_dbname', 'db1', 'salt-one' );
		$this->assertMatchesRegularExpression( '/^[a-f0-9]{64}$/', $hash );
		$this->assertStringNotContainsString( 'handl_secret_dbname', $hash );
		$this->assertNotSame( $hash, Doppelganger::compute_db_hash( 'handl_secret_dbname', 'db2', 'salt-one' ) );
		$this->assertNotSame( $hash, Doppelganger::compute_db_hash( 'handl_secret_dbname', 'db1', 'salt-two' ) );
		$this->assertSame( '', Doppelganger::compute_db_hash( '', '', 'salt' ) );

		// Live (non-injected) identity path.
		Doppelganger::set_test_identity( null );
		$this->enable();
		$state = Doppelganger::get_state();
		$this->assertMatchesRegularExpression( '/^[a-f0-9]{64}$/', $state['fingerprint']['db_hash'] );
		$serialized = (string) serialize( get_option( Doppelganger::STATE_OPTION ) );
		$this->assertStringNotContainsString( (string) constant( 'DB_NAME' ), $serialized );
		$this->assertStringNotContainsString( (string) constant( 'DB_HOST' ), $serialized );
		$this->assertSame( array(), $this->codes(), 'live identity matches its own baseline' );
	}

	public function test_ammunition_inventory_reads_policy_without_writing(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'                   => 'allow',
				'alert_email'               => 'alerts@prod.example.com',
				'alert_webhook_url'         => 'https://hooks.example.com/services/T000/B000/SECRETTOKEN',
				'plugin_budgets'            => array( 'a/a.php' => 10, 'b/b.php' => 25 ),
				'log_enabled'               => true,
				'weekly_report_enabled'     => true,
				'monthly_report_enabled'    => true,
				'governance_digest_enabled' => false,
			)
		);
		$this->enable();
		$options_before = $GLOBALS['handl_aicac_test_options'];

		$ammo = Doppelganger::ammunition();
		$snap = Doppelganger::snapshot( self::NOW );

		$this->assertSame( $options_before, $GLOBALS['handl_aicac_test_options'], 'inventory writes no option' );
		$this->assertSame( 1, $ammo['email']['count'] );
		$this->assertSame( 'a***@prod.example.com', $ammo['email']['redacted'] );
		$this->assertSame( 'policy', $ammo['email']['source'] );
		$this->assertSame( 1, $ammo['webhook']['count'] );
		$this->assertSame( 'hooks.example.com', $ammo['webhook']['host'] );
		$this->assertStringNotContainsString( 'SECRETTOKEN', (string) wp_json_encode_for_test( $snap ) );
		$this->assertSame( 2, $ammo['budgets']['count'] );

		$live = array();
		foreach ( $ammo['schedules'] as $row ) {
			$live[ $row['key'] ] = $row['live'];
		}
		$this->assertTrue( $live['weekly_report'] );
		$this->assertTrue( $live['monthly_report'] );
		$this->assertFalse( $live['governance_digest'] );
		if ( ! class_exists( 'HandL\\AICAC\\Drill', false ) ) {
			$this->assertArrayNotHasKey( 'drill', $live, 'drill is skipped when its class is absent' );
		}
		$this->assertNotEmpty( $snap['checklist'] );

		$keys = array();
		foreach ( $snap['checklist'] as $item ) {
			$keys[] = $item['key'];
		}
		$this->assertContains( 'webhook', $keys );
		$this->assertContains( 'budgets', $keys );
	}

	public function test_ammunition_falls_back_to_admin_email(): void {
		update_option( Plugin::OPTION_KEY, array( 'default' => 'allow' ) );
		$ammo = Doppelganger::ammunition();
		$this->assertSame( 'admin_email', $ammo['email']['source'] );
		$this->assertSame( 0, $ammo['webhook']['count'] );
	}

	public function test_rebaseline_clears_findings_and_latch(): void {
		$this->enable();
		Doppelganger::set_test_identity( $this->identity( array( 'environment' => 'staging', 'table_prefix' => 'st_' ) ) );
		$this->assertTrue( Doppelganger::maybe_check( self::NOW + 400, true ) );
		$this->assertTrue( Doppelganger::is_alerted() );
		$this->assertCount( 2, Doppelganger::snapshot( self::NOW + 400 )['findings'] );

		$this->assertTrue( Doppelganger::rebaseline( self::NOW + 500 ) );
		$state = Doppelganger::get_state();
		$this->assertSame( 'staging', $state['fingerprint']['environment'] );
		$this->assertSame( self::NOW + 500, $state['rebaselined_ts'] );
		$this->assertFalse( $state['alerted'] );
		$this->assertSame( 0, $state['detected_ts'] );
		$this->assertSame( array(), $this->codes() );
	}

	public function test_alert_latch_fires_once_and_rearms(): void {
		$this->enable();
		Doppelganger::set_test_identity( $this->identity( array( 'environment' => 'staging' ) ) );

		$this->assertTrue( Doppelganger::maybe_check( self::NOW + 400, true ) );
		$state = Doppelganger::get_state();
		$this->assertTrue( $state['alerted'] );
		$this->assertSame( 'notice', $state['last_alert_channel'] );
		$this->assertSame( self::NOW + 400, $state['detected_ts'] );

		$this->assertTrue( Doppelganger::maybe_check( self::NOW + 800, true ) );
		$this->assertSame( self::NOW + 400, Doppelganger::get_state()['last_alert_ts'], 'second check does not re-alert' );
		$this->assertSame( self::NOW + 400, Doppelganger::get_state()['detected_ts'] );

		// Identity matches again: latch clears and re-arms.
		Doppelganger::set_test_identity( $this->identity() );
		$this->assertTrue( Doppelganger::maybe_check( self::NOW + 1200, true ) );
		$this->assertFalse( Doppelganger::is_alerted() );

		Doppelganger::set_test_identity( $this->identity( array( 'table_prefix' => 'zz_' ) ) );
		$this->assertTrue( Doppelganger::maybe_check( self::NOW + 1600, true ) );
		$this->assertSame( self::NOW + 1600, Doppelganger::get_state()['last_alert_ts'] );
	}

	public function test_check_is_throttled_unless_forced(): void {
		$this->enable();
		$this->assertTrue( Doppelganger::maybe_check( self::NOW + 400 ) );
		$this->assertFalse( Doppelganger::maybe_check( self::NOW + 500 ) );
		$this->assertTrue( Doppelganger::maybe_check( self::NOW + 400 + Doppelganger::CHECK_THROTTLE_SECONDS ) );
		$this->assertTrue( Doppelganger::maybe_check( self::NOW + 401, true ) );
	}

	public function test_admin_notice_path_renders_while_unacknowledged(): void {
		$this->enable();
		ob_start();
		Doppelganger::maybe_render_notice();
		$this->assertSame( '', (string) ob_get_clean(), 'no notice while the identity matches' );

		Doppelganger::set_test_identity( $this->identity( array( 'environment' => 'staging' ) ) );
		Doppelganger::maybe_check( self::NOW + 400, true );
		ob_start();
		Doppelganger::maybe_render_notice();
		$out = (string) ob_get_clean();
		$this->assertStringContainsString( 'Doppelganger', $out );
		$this->assertStringContainsString( 'notice-warning', $out );
		$this->assertCount( 1, Doppelganger::test_notices() );
		$this->assertSame( array(), Doppelganger::test_mails(), 'notice path sends nothing' );

		$GLOBALS['handl_aicac_test_current_user_can'] = false;
		ob_start();
		Doppelganger::maybe_render_notice();
		$this->assertSame( '', (string) ob_get_clean(), 'viewers only' );
		$GLOBALS['handl_aicac_test_current_user_can'] = true;

		Doppelganger::rebaseline( self::NOW + 500 );
		ob_start();
		Doppelganger::maybe_render_notice();
		$this->assertSame( '', (string) ob_get_clean(), 'cleared after re-baseline' );
	}

	public function test_outbound_off_never_mails_or_posts(): void {
		$mailed                           = 0;
		$GLOBALS['handl_aicac_wp_mail']   = static function () use ( &$mailed ) {
			++$mailed;

			return true;
		};
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'           => 'allow',
				'alert_email'       => 'alerts@prod.example.com',
				'alert_webhook_url' => 'https://hooks.example.com/x',
			)
		);
		$this->enable( false );
		Doppelganger::set_test_identity( $this->identity( array( 'environment' => 'staging', 'site_url' => 'https://copy.example.com/', 'home' => 'https://copy.example.com/' ) ) );

		$this->assertTrue( Doppelganger::maybe_check( self::NOW + 400, true ) );
		$this->assertTrue( Doppelganger::is_alerted() );
		$this->assertSame( array(), Doppelganger::test_mails() );
		$this->assertSame( 0, $mailed );
	}

	public function test_outbound_on_mails_through_guarded_path(): void {
		$sent                             = array();
		$GLOBALS['handl_aicac_wp_mail']   = static function ( $to, $subject ) use ( &$sent ) {
			$sent[] = array( $to, $subject );

			return true;
		};
		$this->enable( true );
		Doppelganger::set_test_identity( $this->identity( array( 'db_hash' => str_repeat( 'd', 64 ) ) ) );

		$this->assertTrue( Doppelganger::maybe_check( self::NOW + 400, true ) );
		$mails = Doppelganger::test_mails();
		$this->assertCount( 1, $mails );
		$this->assertSame( 'alerts@prod.example.com', $mails[0]['to'] );
		$this->assertStringContainsString( '[DOPPELGANGER]', $mails[0]['subject'] );
		$this->assertStringContainsString( 'db_changed', $mails[0]['subject'] );
		$this->assertCount( 1, $sent );
		$this->assertSame( 'notice+outbound', Doppelganger::get_state()['last_alert_channel'] );

		// Latched: no second mail.
		Doppelganger::maybe_check( self::NOW + 800, true );
		$this->assertCount( 1, Doppelganger::test_mails() );
	}

	public function test_outbound_failure_does_not_latch_so_it_retries(): void {
		$GLOBALS['handl_aicac_wp_mail'] = static function () {
			return false;
		};
		$this->enable( true );
		Doppelganger::set_test_identity( $this->identity( array( 'environment' => 'staging' ) ) );
		Doppelganger::maybe_check( self::NOW + 400, true );
		$this->assertFalse( Doppelganger::is_alerted() );
		$this->assertSame( array( 'environment_changed' ), $this->codes(), 'finding is still on the screen' );
	}

	public function test_never_schedules_cron_and_hooks_admin_init_only(): void {
		$this->enable( true );
		Doppelganger::set_test_identity( $this->identity( array( 'environment' => 'staging' ) ) );
		Doppelganger::maybe_check( self::NOW + 400, true );
		Doppelganger::rebaseline( self::NOW + 500 );
		Doppelganger::init();

		$this->assertSame( array(), $GLOBALS['handl_aicac_test_cron'] );
		$this->assertContains( 'admin_init', $GLOBALS['handl_aicac_test_added_actions'] );
		$this->assertContains( 'admin_notices', $GLOBALS['handl_aicac_test_added_actions'] );
		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-handl-aicac-doppelganger.php' );
		$this->assertStringNotContainsString( 'wp_schedule_event', str_replace( 'never wp_schedule_event', '', $source ) );
		$this->assertStringNotContainsString( 'wp_schedule_single_event', $source );
	}

	public function test_writes_are_confined_to_own_two_options(): void {
		update_option( 'alert_webhook_sentinel', 'keep' );
		$policy = get_option( Plugin::OPTION_KEY );
		// Outbound off: with it on, Alerts records its own delivery health, which is not ours.
		$this->enable( false );
		Doppelganger::set_test_identity( $this->identity( array( 'environment' => 'staging' ) ) );
		Doppelganger::maybe_check( self::NOW + 400, true );
		Doppelganger::ammunition();
		Doppelganger::rebaseline( self::NOW + 500 );
		Doppelganger::csv_for_snapshot();

		$keys = array_keys( $GLOBALS['handl_aicac_test_options'] );
		sort( $keys );
		$expected = array(
			'admin_email',
			'alert_webhook_sentinel',
			Plugin::OPTION_KEY,
			Doppelganger::SETTINGS_OPTION,
			Doppelganger::STATE_OPTION,
		);
		sort( $expected );
		$this->assertSame( $expected, $keys );
		$this->assertSame( $policy, get_option( Plugin::OPTION_KEY ) );
		$this->assertSame( 'owner@prod.example.com', get_option( 'admin_email' ) );
		$this->assertSame( 'keep', get_option( 'alert_webhook_sentinel' ) );
	}

	public function test_csv_contains_framing_and_mismatch_codes(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'           => 'allow',
				'alert_webhook_url' => 'https://hooks.example.com/services/SECRETTOKEN',
			)
		);
		$this->enable();
		Doppelganger::set_test_identity(
			$this->identity(
				array(
					'environment'  => 'staging',
					'table_prefix' => 'st_',
					'db_hash'      => str_repeat( 'e', 64 ),
					'site_url'     => 'https://copy.example.com/',
					'home'         => 'https://copy.example.com/',
				)
			)
		);
		$csv = Doppelganger::csv_for_snapshot();

		$this->assertStringStartsWith( 'section,code,field,baseline,current,detail,framing', $csv );
		$this->assertStringContainsString( 'report_only_never_flips_outbound', $csv );
		foreach ( array( 'url_changed', 'environment_changed', 'prefix_changed', 'db_changed' ) as $code ) {
			$this->assertStringContainsString( 'finding,' . $code . ',', $csv );
		}
		$this->assertStringContainsString( 'ammunition,webhook,host,,1,hooks.example.com', $csv );
		$this->assertStringNotContainsString( 'SECRETTOKEN', $csv );
		$this->assertStringContainsString( 'checklist,', $csv );
		$this->assertStringNotContainsString( str_repeat( 'e', 64 ), $csv, 'hashes stay out of exports' );
	}

	public function test_csv_neutralizes_formula_injection(): void {
		$this->assertSame( "'=cmd", Doppelganger::csv_line( array( '=cmd' ) ) );
		$this->assertSame( '"a,b"', Doppelganger::csv_line( array( 'a,b' ) ) );
	}

	public function test_print_html_is_report_only_and_escaped(): void {
		$this->enable();
		Doppelganger::set_test_identity( $this->identity( array( 'environment' => 'stag<script>' ) ) );
		$html = Doppelganger::build_print_html( Doppelganger::snapshot( self::NOW ) );
		$this->assertStringContainsString( 'Report only', $html );
		$this->assertStringNotContainsString( '<script>', $html );
	}

	public function test_plugin_wires_doppelganger_after_rescan_schedule(): void {
		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-handl-aicac-plugin.php' );
		$this->assertLessThan(
			strpos( $source, 'Doppelganger::init();' ),
			strpos( $source, 'Rescan_Schedule::init();' )
		);
		$this->assertLessThan(
			strpos( $source, "class-handl-aicac-doppelganger.php'" ),
			strpos( $source, "class-handl-aicac-rescan-schedule.php'" )
		);
	}
}

/**
 * Serialize helper for secret-leak assertions.
 *
 * @param mixed $value Value.
 */
function wp_json_encode_for_test( $value ): string {
	return (string) json_encode( $value );
}
