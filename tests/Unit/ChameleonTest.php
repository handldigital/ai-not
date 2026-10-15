<?php
/**
 * AICAC-CHAMELEON (#436).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Chameleon;
use HandL\AICAC\Plugin;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class ChameleonTest extends TestCase {

	private const NOW = 1800000000;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_users']            = array(
			12 => array(
				'ID'         => 12,
				'user_login' => 'jane',
				'roles'      => array( 'editor' ),
			),
		);
		unset( $GLOBALS['handl_aicac_test_is_multisite'] );
		Chameleon::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'                 => 'deny',
				'alert_email'             => 'alerts@example.com',
				'role_gate_enabled'       => true,
				'allowed_roles'           => array( 'administrator', 'editor' ),
				'user_quota_role_limits'  => array(
					'administrator' => 1000,
					'editor'        => 50,
					'subscriber'    => 10,
				),
			),
			false
		);
	}

	protected function tearDown(): void {
		Chameleon::reset_for_tests();
		$GLOBALS['handl_aicac_test_options'] = array();
		unset(
			$GLOBALS['handl_aicac_test_users'],
			$GLOBALS['handl_aicac_test_is_multisite'],
			$GLOBALS['handl_aicac_test_current_user_can']
		);
		parent::tearDown();
	}

	private function enable( bool $outbound = false ): void {
		Chameleon::save_settings(
			array(
				'enabled'        => true,
				'outbound_alert' => $outbound,
			)
		);
	}

	public function test_defaults_off_and_noop_save(): void {
		$this->assertFalse( Chameleon::is_enabled() );
		$before = $GLOBALS['handl_aicac_test_options'];
		$this->assertFalse( Chameleon::save_settings( Chameleon::defaults() ) );
		$this->assertSame( $before, $GLOBALS['handl_aicac_test_options'] );
		$this->assertFalse( (bool) get_option( Chameleon::SETTINGS_OPTION, false ) );
	}

	public function test_demotion_is_over_granted_with_quota_numbers(): void {
		$this->enable();
		$row = Chameleon::record_transition( 12, array( 'administrator' ), array( 'editor' ), self::NOW );
		$this->assertIsArray( $row );
		$this->assertSame( Chameleon::VERDICT_OVER, $row['verdict'] );
		$this->assertSame( 1000, $row['kept_quota'] );
		$this->assertSame( 50, $row['baseline_quota'] );
		$this->assertStringContainsString( '1000-call quota', $row['sentence'] );
		$this->assertStringContainsString( '50', $row['sentence'] );
		$this->assertCount( 1, Chameleon::unacked_over() );
	}

	public function test_promotion_is_under_granted(): void {
		$this->enable();
		$row = Chameleon::record_transition( 12, array( 'subscriber' ), array( 'administrator' ), self::NOW );
		$this->assertIsArray( $row );
		$this->assertSame( Chameleon::VERDICT_UNDER, $row['verdict'] );
		$this->assertSame( 10, $row['kept_quota'] );
		$this->assertSame( 1000, $row['baseline_quota'] );
		$this->assertSame( array(), Chameleon::unacked_over() );
	}

	public function test_role_gate_demotion_is_over_without_quota(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'           => 'deny',
				'role_gate_enabled' => true,
				'allowed_roles'     => array( 'administrator' ),
			),
			false
		);
		$this->enable();
		$row = Chameleon::record_transition( 12, array( 'administrator' ), array( 'subscriber' ), self::NOW );
		$this->assertSame( Chameleon::VERDICT_OVER, $row['verdict'] );
		$this->assertStringContainsString( 'would not allow AI access', $row['sentence'] );
	}

	public function test_ack_quiets_and_second_transition_rearms(): void {
		$this->enable();
		Chameleon::record_transition( 12, array( 'administrator' ), array( 'editor' ), self::NOW );
		$this->assertCount( 1, Chameleon::unacked_over() );
		$this->assertTrue( Chameleon::ack_user( 12, self::NOW + 10 ) );
		$this->assertSame( array(), Chameleon::unacked_over() );
		$findings = Chameleon::findings();
		$this->assertCount( 1, $findings );
		$this->assertTrue( Chameleon::is_acked( $findings[0] ) );

		$second = Chameleon::record_transition( 12, array( 'editor' ), array( 'subscriber' ), self::NOW + 20 );
		$this->assertIsArray( $second );
		$this->assertSame( Chameleon::VERDICT_OVER, $second['verdict'] );
		$this->assertCount( 1, Chameleon::unacked_over() );
		$this->assertFalse( Chameleon::is_acked( $second ) );
	}

	public function test_multisite_skips_cleanly(): void {
		$this->enable();
		$GLOBALS['handl_aicac_test_is_multisite'] = true;
		$this->assertNull( Chameleon::record_transition( 12, array( 'administrator' ), array( 'editor' ), self::NOW ) );
		$this->assertSame( array(), Chameleon::findings() );
	}

	public function test_cli_nonzero_on_unacked_over(): void {
		$this->enable();
		Chameleon::record_transition( 12, array( 'administrator' ), array( 'editor' ), self::NOW );
		$cli = Chameleon::cli_status();
		$this->assertSame( 1, $cli['code'] );
		Chameleon::ack_user( 12, self::NOW + 1 );
		$cli = Chameleon::cli_status();
		$this->assertSame( 0, $cli['code'] );
	}

	public function test_csv_census_headers(): void {
		$this->enable();
		Chameleon::record_transition( 12, array( 'administrator' ), array( 'editor' ), self::NOW );
		$csv = Chameleon::csv_census();
		$this->assertStringContainsString( 'user,old_role,new_role,posture_delta,ack_state', $csv );
		$this->assertStringContainsString( 'jane', $csv );
		$this->assertStringContainsString( 'OVER-GRANTED', $csv );
		$this->assertStringContainsString( 'open', $csv );
	}

	public function test_page_off_copy(): void {
		ob_start();
		Chameleon::render_page();
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Role-change review', $html );
		$this->assertStringContainsString( 'Watch role changes', $html );
		$this->assertStringContainsString( 'We do not change access.', $html );
		$this->assertStringContainsString( 'Role-change review is off.', $html );
	}

	public function test_on_set_user_role_classifies(): void {
		$this->enable();
		Chameleon::on_set_user_role( 12, 'editor', array( 'administrator' ) );
		$findings = Chameleon::findings();
		$this->assertCount( 1, $findings );
		$this->assertSame( Chameleon::VERDICT_OVER, $findings[0]['verdict'] );
	}

	public function test_disabled_is_noop(): void {
		$this->assertNull( Chameleon::record_transition( 12, array( 'administrator' ), array( 'editor' ), self::NOW ) );
		$this->assertSame( array(), Chameleon::findings() );
	}
}
