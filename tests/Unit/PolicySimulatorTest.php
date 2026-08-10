<?php
/**
 * Unit tests for Policy_Simulator (AICAC-SIM).
 *
 * Hard AC: simulator calls Policy::evaluate — parity on a fixture matrix.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Operations;
use HandL\AICAC\Policy;
use HandL\AICAC\Policy_Simulator;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

final class PolicySimulatorTest extends TestCase {

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_test_user_id'], $GLOBALS['handl_aicac_test_user_roles'] );
		parent::tearDown();
	}

	/**
	 * @return list<array{0:array<string,mixed>,1:?string,2:?string,3:?array,4:?string}>
	 */
	public function fixture_matrix_provider(): array {
		$plugin = 'demo/plugin.php';
		return array(
			array(
				array(
					'default' => 'allow',
					'plugins' => array( $plugin => 'deny' ),
				),
				$plugin,
				'generate_text',
				null,
				null,
			),
			array(
				array(
					'default'    => 'allow',
					'plugins'    => array( $plugin => 'allow' ),
					'operations' => array(
						$plugin => array( Operations::FAMILY_IMAGE => 'deny' ),
					),
				),
				$plugin,
				'generate_image',
				null,
				null,
			),
			array(
				array(
					'default'                => 'allow',
					'kill_switch'            => true,
					'kill_switch_exceptions' => array(),
				),
				$plugin,
				'generate_text',
				null,
				null,
			),
			array(
				array(
					'default'           => 'allow',
					'plugins'           => array( $plugin => 'allow' ),
					'unknown_operation' => 'deny',
				),
				$plugin,
				'is_supported_for_music_generation',
				null,
				null,
			),
			array(
				array(
					'default'      => 'allow',
					'plugins'      => array( $plugin => 'allow' ),
					'denied_tools' => array( 'evil/tool' ),
				),
				$plugin,
				'generate_text',
				array( 'evil/tool' ),
				null,
			),
			array(
				array(
					'default'           => 'allow',
					'role_gate_enabled' => true,
					'allowed_roles'     => array( 'administrator' ),
				),
				$plugin,
				'generate_text',
				null,
				null,
			),
		);
	}

	/**
	 * Simulator evaluate_call must equal Policy::evaluate on every fixture.
	 *
	 * @dataProvider fixture_matrix_provider
	 * @param array<string,mixed> $policy
	 * @param list<string>|null   $armed
	 */
	public function test_evaluate_call_matches_policy_evaluate(
		array $policy,
		?string $plugin,
		?string $operation,
		?array $armed,
		?string $family
	): void {
		if ( ! empty( $policy['role_gate_enabled'] ) ) {
			$GLOBALS['handl_aicac_test_user_id']    = 1;
			$GLOBALS['handl_aicac_test_user_roles'] = array( 'editor' );
		}

		$direct = Policy::evaluate( $policy, $plugin, $operation, $armed, $family );
		$via    = Policy_Simulator::evaluate_call( $policy, $plugin, $operation, $armed, $family );

		$this->assertSame( $direct, $via );
	}

	/**
	 * evaluate_call source must invoke Policy::evaluate (no parallel decision tree).
	 */
	public function test_evaluate_call_source_delegates_to_policy_evaluate(): void {
		$ref  = new ReflectionMethod( Policy_Simulator::class, 'evaluate_call' );
		$file = $ref->getFileName();
		$this->assertNotFalse( $file );
		$start = $ref->getStartLine();
		$end   = $ref->getEndLine();
		$lines = file( $file );
		$this->assertIsArray( $lines );
		$body = implode( '', array_slice( $lines, $start - 1, $end - $start + 1 ) );
		$this->assertMatchesRegularExpression(
			'/return\s+Policy::evaluate\s*\(/',
			$body,
			'Policy_Simulator::evaluate_call must return Policy::evaluate(...)'
		);
		$this->assertDoesNotMatchRegularExpression(
			'/decide_detailed|plugin_level_decision|kill_switch_exceptions/',
			$body,
			'Simulator must not reimplement enforcement branches'
		);
	}

	public function test_verdict_allowed_and_kill_switch_chip(): void {
		$allow = Policy_Simulator::verdict_from_eval(
			array(
				'prevent' => false,
				'reason'  => '',
			)
		);
		$this->assertTrue( $allow['allowed'] );
		$this->assertSame( 'Allowed', $allow['chip'] );

		$kill = Policy_Simulator::verdict_from_eval(
			array(
				'prevent' => true,
				'reason'  => 'kill_switch',
			)
		);
		$this->assertFalse( $kill['allowed'] );
		$this->assertSame( 'Blocked by Emergency stop', $kill['chip'] );

		$plugin = Policy_Simulator::verdict_from_eval(
			array(
				'prevent' => true,
				'reason'  => 'plugin',
			)
		);
		$this->assertStringContainsString( 'Plugin rule', $plugin['chip'] );
	}

	public function test_replay_diff_detects_newly_blocked_and_allowed(): void {
		$plugin = 'shop/plugin.php';
		$log    = array(
			array(
				'plugin'    => $plugin,
				'operation' => 'generate_text',
				'decision'  => 'allow',
			),
			array(
				'plugin'    => $plugin,
				'operation' => 'generate_image',
				'decision'  => 'deny',
				'denial_reason' => 'capability_family',
			),
			array(
				'plugin'    => 'other/x.php',
				'operation' => 'direct_http',
				'decision'  => 'observe',
			),
		);

		$saved = array(
			'default'    => 'allow',
			'plugins'    => array( $plugin => 'allow' ),
			'operations' => array(
				$plugin => array( Operations::FAMILY_IMAGE => 'deny' ),
			),
		);
		$draft = array(
			'default'    => 'allow',
			'plugins'    => array( $plugin => 'allow' ),
			'operations' => array(
				$plugin => array(
					Operations::FAMILY_TEXT  => 'deny',
					Operations::FAMILY_IMAGE => 'allow',
				),
			),
		);

		$diff = Policy_Simulator::replay_diff( $saved, $draft, $log, 50 );

		$this->assertSame( 2, $diff['scanned'] );
		$this->assertSame( 1, $diff['now_blocked_count'] );
		$this->assertSame( 1, $diff['now_allowed_count'] );
		$this->assertSame( 'generate_text', $diff['now_blocked'][0]['operation'] );
		$this->assertSame( 'generate_image', $diff['now_allowed'][0]['operation'] );
	}

	public function test_replay_empty_explains_logging_off(): void {
		$diff = Policy_Simulator::replay_diff(
			array( 'default' => 'allow' ),
			array( 'default' => 'deny' ),
			array(),
			20,
			array(
				'log_enabled' => false,
				'audit_only'  => false,
			)
		);

		$this->assertTrue( $diff['empty'] );
		$this->assertStringContainsString( 'Activity logging is off', $diff['empty_reason'] );
	}

	public function test_replay_empty_explains_ttl_window(): void {
		$diff = Policy_Simulator::replay_diff(
			array( 'default' => 'allow' ),
			array( 'default' => 'deny' ),
			array(),
			20,
			array(
				'log_enabled'      => true,
				'log_max_age_days' => 7,
			)
		);

		$this->assertTrue( $diff['empty'] );
		$this->assertStringContainsString( '7-day activity limit', $diff['empty_reason'] );
	}

	/**
	 * Rules save must not hide handl_aicac_action=save, and Run test must be an
	 * in-form submit (not form= external) so automation includes simulate_policy.
	 * Access filters must not open a nested <form> inside the Rules form.
	 */
	public function test_rules_form_action_is_submit_not_hidden_save(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );

		$this->assertTrue(
			(bool) preg_match(
				'/echo \'<form method="post" id="\' \. esc_attr\( \$rules_form_id \)[\s\S]*?render_policy_simulator_panel\([\s\S]*?echo \'<\/form>\';/',
				$src
			),
			'Rules form must wrap the policy simulator panel before closing'
		);

		$this->assertDoesNotMatchRegularExpression(
			'/\$rules_form_id = \'handl-aicac-rules-save\';[\s\S]{0,800}?handl_aicac_action" value="save"/',
			$src,
			'Rules form must not hard-code hidden save action near open'
		);

		$this->assertMatchesRegularExpression(
			'/<button type="submit" name="handl_aicac_action" value="save" class="button button-primary" data-aicac-action="save">/',
			$src,
			'Save changes must be an in-form submit with value=save'
		);
		$this->assertMatchesRegularExpression(
			'/<button type="submit" class="button button-secondary" name="handl_aicac_action" value="simulate_policy" id="handl-aicac-sim-run" data-aicac-action="simulate_policy">/',
			$src,
			'Run test must be an in-form submit with value=simulate_policy (no form=)'
		);
		$this->assertStringContainsString(
			'id="handl-aicac-action"',
			$src,
			'Early handl_aicac_action hidden must exist so Save survives max_input_vars truncation'
		);
		$this->assertTrue(
			strpos( $src, 'render_policy_simulator_panel' ) < strpos( $src, 'handl-aicac-rules-matrix' ),
			'Simulator panel must render before the plugin matrix (max_input_vars)'
		);
		$this->assertStringNotContainsString(
			'name="handl_aicac_action" value="simulate_policy" form="',
			$src,
			'Run test must not use external form= association'
		);

		$this->assertDoesNotMatchRegularExpression(
			'/echo \'<form method="post" id="\' \. esc_attr\( \$rules_form_id \) \. \'" class="handl-aicac-rules-save-form"/',
			$src,
			'Visible Rules form must not use handl-aicac-rules-save-form (CSS display:none)'
		);
		$this->assertMatchesRegularExpression(
			'/\$bulk_form_id[\s\S]{0,200}?class="handl-aicac-rules-save-form"/',
			$src,
			'Hidden bulk shell may keep handl-aicac-rules-save-form'
		);

		$this->assertTrue(
			(bool) preg_match(
				'/function render_plugin_rules_filters\(.*?\n\t\}/s',
				$src,
				$m
			),
			'render_plugin_rules_filters must exist'
		);
		$this->assertDoesNotMatchRegularExpression(
			'/echo\s+[\'"]<form\b/',
			$m[0],
			'Rules access filters must not echo a nested <form> inside the Rules POST form'
		);
	}
}
