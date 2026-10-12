<?php
/**
 * AICAC-PROVISION (#355).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Inbox_Actions;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Provision;
use HandL\AICAC\Temp_Allow;
use PHPUnit\Framework\TestCase;

final class ProvisionTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']           = array();
		$GLOBALS['handl_aicac_test_user_id']           = 12;
		$GLOBALS['handl_aicac_test_user_login']        = 'alice';
		$GLOBALS['handl_aicac_test_current_user_can']  = true;
		$GLOBALS['handl_aicac_test_available_roles']   = array(
			'administrator' => 'Administrator',
			'editor'        => 'Editor',
			'author'        => 'Author',
			'subscriber'    => 'Subscriber',
		);
		$GLOBALS['handl_aicac_test_users']             = array(
			12 => array(
				'ID'         => 12,
				'user_login' => 'alice',
				'roles'      => array( 'editor' ),
			),
			13 => array(
				'ID'         => 13,
				'user_login' => 'bob',
				'roles'      => array( 'author' ),
			),
			1  => array(
				'ID'         => 1,
				'user_login' => 'admin',
				'roles'      => array( 'administrator' ),
			),
		);

		Provision::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'           => 'deny',
				'log_enabled'       => true,
				'audit_only'        => false,
				'role_gate_enabled' => true,
				'allowed_roles'     => array( 'administrator' ),
				'plugins'           => array(
					'blocked/plugin.php' => 'deny',
				),
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
		delete_option( Temp_Allow::WARNED_OPTION_KEY );
		Inbox_Actions::instance();
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_current_user_can'],
			$GLOBALS['handl_aicac_test_user_login'],
			$GLOBALS['handl_aicac_test_users'],
			$GLOBALS['handl_aicac_test_available_roles']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_user_id'] = 0;
		Provision::reset_for_tests();
		parent::tearDown();
	}

	public function test_save_untouched_templates_is_byte_identical(): void {
		$payload = array(
			'templates' => array(
				'editor' => array(
					'mode'    => Provision::MODE_ALLOW,
					'plugins' => array( 'openai/openai.php' ),
				),
			),
		);
		$this->assertTrue( Provision::save_settings( $payload ) );
		$before = get_option( Provision::OPTION_KEY );
		$this->assertIsArray( $before );

		$this->assertFalse( Provision::save_settings( $payload ) );
		$this->assertSame( $before, get_option( Provision::OPTION_KEY ) );

		// Request-only empty rows are not stored — saving them does not rewrite.
		$this->assertFalse(
			Provision::save_settings(
				array(
					'templates' => array(
						'editor' => array(
							'mode'    => Provision::MODE_ALLOW,
							'plugins' => array( 'openai/openai.php' ),
						),
						'author' => array(
							'mode'    => Provision::MODE_REQUEST,
							'plugins' => array(),
						),
					),
				)
			)
		);
		$this->assertSame( $before, get_option( Provision::OPTION_KEY ) );
	}

	public function test_no_templates_means_quiet_on_user_create(): void {
		$opts_before = $GLOBALS['handl_aicac_test_options'];
		$result      = Provision::provision_user( 12, 'editor', 'register', 1_700_000_000 );
		$this->assertFalse( $result['applied'] );
		$this->assertSame( array(), get_option( Plugin::LOG_OPTION_KEY, array() ) );
		$this->assertSame( $opts_before, $GLOBALS['handl_aicac_test_options'] );
	}

	public function test_allow_template_grants_temp_allow_role_gate_and_one_audit(): void {
		Provision::save_settings(
			array(
				'templates' => array(
					'editor' => array(
						'mode'    => Provision::MODE_ALLOW,
						'plugins' => array( 'blocked/plugin.php' ),
					),
				),
			)
		);

		$now    = 1_700_000_000;
		$result = Provision::provision_user( 12, 'editor', 'register', $now );
		$this->assertTrue( $result['applied'] );
		$this->assertContains( 'blocked/plugin.php', $result['plugins'] );
		$this->assertTrue( $result['role_added'] );
		$this->assertStringContainsString( 'alice', $result['summary'] );

		$policy = Policy::get_policy();
		$this->assertSame( 'allow', $policy['plugins']['blocked/plugin.php'] ?? '' );
		$this->assertNotNull( Temp_Allow::expires_at( $policy, 'blocked/plugin.php' ) );
		$this->assertContains( 'editor', Policy::sanitize_allowed_roles( $policy['allowed_roles'] ?? array() ) );

		// First AI call path: role gate open + plugin allow.
		$GLOBALS['handl_aicac_test_user_roles'] = array( 'editor' );
		$this->assertFalse( Policy::role_gate_should_prevent( $policy ) );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$prov = array_values(
			array_filter(
				$log,
				static function ( $row ) {
					return is_array( $row ) && ( $row['decision'] ?? '' ) === 'provision';
				}
			)
		);
		$this->assertCount( 1, $prov );
		$this->assertSame( 12, (int) $prov[0]['user_id'] );
		$this->assertSame( 'editor', $prov[0]['provision_role'] );
		$this->assertSame( 'register', $prov[0]['provision_via'] );
	}

	public function test_set_user_role_applies_template_untemplated_is_quiet(): void {
		Provision::save_settings(
			array(
				'templates' => array(
					'editor' => array(
						'mode'    => Provision::MODE_ALLOW,
						'plugins' => array( 'blocked/plugin.php' ),
					),
				),
			)
		);

		$quiet = Provision::provision_user( 13, 'subscriber', 'role', 1_700_000_000 );
		$this->assertFalse( $quiet['applied'] );
		$this->assertSame( array(), get_option( Plugin::LOG_OPTION_KEY, array() ) );

		$ok = Provision::provision_user( 12, 'editor', 'role', 1_700_000_100 );
		$this->assertTrue( $ok['applied'] );
		$this->assertContains( 'blocked/plugin.php', $ok['plugins'] );
	}

	public function test_request_only_template_grants_nothing(): void {
		Provision::save_settings(
			array(
				'templates' => array(
					'author' => array(
						'mode'    => Provision::MODE_ALLOW,
						'plugins' => array( 'blocked/plugin.php' ),
					),
				),
			)
		);
		// Force request-only storage shape (allow with plugins above, then overwrite).
		update_option(
			Provision::OPTION_KEY,
			array(
				'templates' => array(
					'author' => array(
						'mode'    => Provision::MODE_REQUEST,
						'plugins' => array( 'blocked/plugin.php' ),
					),
				),
			),
			false
		);

		$result = Provision::provision_user( 13, 'author', 'register', 1_700_000_000 );
		$this->assertFalse( $result['applied'] );
		$policy = Policy::get_policy();
		$this->assertSame( 'deny', $policy['plugins']['blocked/plugin.php'] ?? 'deny' );
		$this->assertSame( array(), get_option( Plugin::LOG_OPTION_KEY, array() ) );
	}

	public function test_hooks_delegate_to_provision(): void {
		Provision::save_settings(
			array(
				'templates' => array(
					'editor' => array(
						'mode'    => Provision::MODE_ALLOW,
						'plugins' => array( 'blocked/plugin.php' ),
					),
				),
			)
		);
		Provision::init();

		Provision::on_user_register( 12 );
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$prov = array_values(
			array_filter(
				$log,
				static function ( $row ) {
					return is_array( $row ) && ( $row['decision'] ?? '' ) === 'provision';
				}
			)
		);
		$this->assertNotEmpty( $prov );
		$this->assertSame( 'register', $prov[0]['provision_via'] );
	}
}
