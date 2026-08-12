<?php
/**
 * Unit tests for Policy_Checks (AICAC-RULE-TEST / #153).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Operations;
use HandL\AICAC\Policy;
use HandL\AICAC\Policy_Checks;
use HandL\AICAC\Policy_Simulator;
use PHPUnit\Framework\TestCase;

final class PolicyChecksTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		delete_option( Policy_Checks::OPTION_KEY );
		delete_option( Policy_Checks::FAILING_OPTION_KEY );
		$GLOBALS['handl_aicac_options'] = array();
	}

	protected function tearDown(): void {
		delete_option( Policy_Checks::OPTION_KEY );
		delete_option( Policy_Checks::FAILING_OPTION_KEY );
		unset( $GLOBALS['handl_aicac_options'], $GLOBALS['handl_aicac_test_user_id'], $GLOBALS['handl_aicac_test_user_roles'] );
		parent::tearDown();
	}

	public function test_zero_checks_is_noop(): void {
		$report = Policy_Checks::evaluate_all(
			array(
				'default' => 'allow',
				'plugins' => array(),
			)
		);
		$this->assertSame( 0, $report['total'] );
		$this->assertSame( array(), $report['failures'] );
	}

	public function test_evaluation_parity_with_simulator(): void {
		$plugin = 'demo/plugin.php';
		$policy = array(
			'default' => 'allow',
			'plugins' => array( $plugin => 'deny' ),
		);
		$check  = array(
			'id'       => 'pc_parity1',
			'label'    => '',
			'plugin'   => $plugin,
			'family'   => Operations::FAMILY_TEXT,
			'tool'     => '',
			'expected' => 'deny',
		);

		$row  = Policy_Checks::evaluate_one( $check, $policy );
		$eval = Policy_Simulator::evaluate_call(
			$policy,
			$plugin,
			Operations::canonical_operation_for_family( Operations::FAMILY_TEXT ),
			null,
			Operations::FAMILY_TEXT
		);

		$this->assertSame( $eval['prevent'], $row['eval']['prevent'] );
		$this->assertSame( $eval['reason'], $row['eval']['reason'] );
		$this->assertTrue( $row['pass'] );
		$this->assertSame( 'deny', $row['actual'] );
	}

	public function test_failing_check_detected(): void {
		$plugin = 'demo/plugin.php';
		$policy = array(
			'default' => 'allow',
			'plugins' => array( $plugin => 'allow' ),
		);
		Policy_Checks::save_all(
			array(
				array(
					'id'       => 'pc_fail1',
					'plugin'   => $plugin,
					'family'   => '',
					'tool'     => '',
					'expected' => 'deny',
					'label'    => 'Must block demo',
				),
			)
		);

		$report = Policy_Checks::evaluate_all( $policy );
		$this->assertSame( 1, $report['total'] );
		$this->assertCount( 1, $report['failures'] );
		$this->assertSame( 'allow', $report['failures'][0]['actual'] );
		$this->assertSame( 'deny', $report['failures'][0]['expected'] );
	}

	public function test_passing_check_for_allow(): void {
		$plugin = 'ok/plugin.php';
		$policy = array(
			'default' => 'deny',
			'plugins' => array( $plugin => 'allow' ),
		);
		$check  = array(
			'id'       => 'pc_ok1',
			'plugin'   => $plugin,
			'family'   => Operations::FAMILY_TEXT,
			'tool'     => '',
			'expected' => 'allow',
			'label'    => '',
		);
		$row = Policy_Checks::evaluate_one( $check, $policy );
		$this->assertTrue( $row['pass'] );
		$this->assertSame( 'allow', $row['actual'] );
	}

	public function test_tool_armed_check_uses_simulator_path(): void {
		$plugin = 'tools/plugin.php';
		$policy = array(
			'default'      => 'allow',
			'plugins'      => array( $plugin => 'allow' ),
			'denied_tools' => array( 'evil/tool' ),
		);
		$check  = array(
			'id'       => 'pc_tool1',
			'plugin'   => $plugin,
			'family'   => Operations::FAMILY_TEXT,
			'tool'     => 'evil/tool',
			'expected' => 'deny',
			'label'    => '',
		);
		$row = Policy_Checks::evaluate_one( $check, $policy );
		$eval = Policy_Simulator::evaluate_call(
			$policy,
			$plugin,
			'generate_text',
			array( 'evil/tool' ),
			Operations::FAMILY_TEXT
		);
		$this->assertSame( ! empty( $eval['prevent'] ), 'deny' === $row['actual'] );
		$this->assertTrue( $row['pass'] );
	}

	public function test_override_audit_and_dashboard_surface(): void {
		$plugin = 'demo/plugin.php';
		$policy = array(
			'default' => 'allow',
			'plugins' => array( $plugin => 'allow' ),
		);
		Policy_Checks::save_all(
			array(
				array(
					'id'       => 'pc_dash1',
					'plugin'   => $plugin,
					'family'   => '',
					'tool'     => '',
					'expected' => 'deny',
					'label'    => 'Dashboard fixture',
				),
			)
		);
		$report = Policy_Checks::evaluate_all( $policy );
		$this->assertNotEmpty( $report['failures'] );

		Policy_Checks::record_override_audit( $report['failures'], 'manual' );
		Policy_Checks::after_policy_saved( $policy, $report['failures'] );

		$open = Policy_Checks::get_failing_dashboard();
		$this->assertCount( 1, $open );
		$this->assertSame( 'pc_dash1', $open[0]['check']['id'] );

		// Clean save path clears when all pass.
		$deny_policy = array(
			'default' => 'allow',
			'plugins' => array( $plugin => 'deny' ),
		);
		Policy_Checks::after_policy_saved( $deny_policy, null );
		// refresh only clears when already open and now pass:
		Policy_Checks::set_failing_dashboard( $report['failures'] );
		Policy_Checks::refresh_failing_dashboard( $deny_policy );
		$this->assertSame( array(), Policy_Checks::get_failing_dashboard() );
	}

	public function test_sanitize_rejects_bad_plugin(): void {
		$this->assertNull(
			Policy_Checks::sanitize_check(
				array(
					'plugin'   => '../evil.php',
					'expected' => 'deny',
				)
			)
		);
		$this->assertNull(
			Policy_Checks::sanitize_check(
				array(
					'plugin'   => 'good/plugin.php',
					'expected' => 'maybe',
				)
			)
		);
	}

	public function test_save_all_round_trip(): void {
		Policy_Checks::save_all(
			array(
				array(
					'plugin'   => 'a/a.php',
					'family'   => Operations::FAMILY_IMAGE,
					'tool'     => '',
					'expected' => 'allow',
					'label'    => 'Images ok',
				),
			)
		);
		$all = Policy_Checks::get_all();
		$this->assertCount( 1, $all );
		$this->assertSame( 'a/a.php', $all[0]['plugin'] );
		$this->assertSame( Operations::FAMILY_IMAGE, $all[0]['family'] );
		$this->assertSame( 'allow', $all[0]['expected'] );
		$this->assertNotSame( '', $all[0]['id'] );
	}
}
