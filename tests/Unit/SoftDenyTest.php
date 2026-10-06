<?php
/**
 * AICAC-SOFT-DENY (#279): configurable deny response mode.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Operations;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Retry_Storm;
use HandL\AICAC\Soft_Deny;
use PHPUnit\Framework\TestCase;

final class SoftDenyTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		Soft_Deny::reset_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
	}

	protected function tearDown(): void {
		Soft_Deny::reset_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		parent::tearDown();
	}

	public function test_default_mode_is_hard(): void {
		$plugin = 'acme/acme.php';
		$this->assertSame( Soft_Deny::MODE_HARD, Soft_Deny::mode_for_plugin( array(), $plugin ) );
		$this->assertFalse( Soft_Deny::is_soft( array( 'default' => 'deny' ), $plugin ) );
	}

	public function test_sanitize_omits_hard_default(): void {
		$clean = Soft_Deny::sanitize_plugin_modes(
			array(
				'a/a.php' => 'soft',
				'b/b.php' => 'hard',
				'c/c.php' => 'nope',
				''        => 'soft',
			)
		);
		$this->assertSame( array( 'a/a.php' => Soft_Deny::MODE_SOFT ), $clean );
	}

	public function test_merge_posted_modes_keeps_unposted_and_clears_hard(): void {
		$stored = array(
			'keep/soft.php' => Soft_Deny::MODE_SOFT,
			'flip/hard.php' => Soft_Deny::MODE_SOFT,
		);
		$merged = Soft_Deny::merge_posted_modes(
			$stored,
			array(
				'flip/hard.php' => Soft_Deny::MODE_HARD,
				'new/soft.php'  => Soft_Deny::MODE_SOFT,
			)
		);
		$this->assertSame(
			array(
				'keep/soft.php' => Soft_Deny::MODE_SOFT,
				'new/soft.php'  => Soft_Deny::MODE_SOFT,
			),
			$merged
		);
	}

	public function test_stub_body_shapes_per_family(): void {
		$text = json_decode( Soft_Deny::stub_body_for_family( Operations::FAMILY_TEXT, 'https://api.openai.com/v1/chat/completions' ), true );
		$this->assertIsArray( $text );
		$this->assertSame( '', $text['choices'][0]['message']['content'] ?? null );

		$anthropic = json_decode( Soft_Deny::stub_body_for_family( Operations::FAMILY_TEXT, 'https://api.anthropic.com/v1/messages' ), true );
		$this->assertIsArray( $anthropic );
		$this->assertSame( array(), $anthropic['content'] ?? null );

		$google = json_decode( Soft_Deny::stub_body_for_family( Operations::FAMILY_TEXT, 'https://generativelanguage.googleapis.com/v1/models/x:generateContent' ), true );
		$this->assertIsArray( $google );
		$this->assertSame( '', $google['candidates'][0]['content']['parts'][0]['text'] ?? null );

		$image = json_decode( Soft_Deny::stub_body_for_family( Operations::FAMILY_IMAGE ), true );
		$this->assertIsArray( $image );
		$this->assertSame( array(), $image['data'] ?? null );

		$speech = json_decode( Soft_Deny::stub_body_for_family( Operations::FAMILY_SPEECH ), true );
		$this->assertIsArray( $speech );
		$this->assertSame( '', $speech['text'] ?? null );

		$video = json_decode( Soft_Deny::stub_body_for_family( Operations::FAMILY_VIDEO ), true );
		$this->assertIsArray( $video );
		$this->assertSame( array(), $video['data'] ?? null );

		$http = Soft_Deny::stub_http_response( Operations::FAMILY_TEXT );
		$this->assertSame( 200, $http['response']['code'] );
		$this->assertStringContainsString( 'application/json', $http['headers']['content-type'] );
		$this->assertJson( $http['body'] );
	}

	public function test_maybe_arm_default_hard_does_not_arm(): void {
		$event  = array( 'decision' => 'deny' );
		$policy = array( 'plugins' => array( 'x/x.php' => 'deny' ) );
		$soft   = Soft_Deny::maybe_arm_from_deny( true, $event, $policy, 'x/x.php', 'generate_text', Operations::FAMILY_TEXT );
		$this->assertFalse( $soft );
		$this->assertFalse( Soft_Deny::is_armed() );
		$this->assertArrayNotHasKey( 'outcome', $event );
	}

	public function test_maybe_arm_soft_generating_labels_and_stubs(): void {
		$plugin = 'blocked/plugin.php';
		$event  = array(
			'decision' => 'deny',
			'plugin'   => $plugin,
		);
		$policy = array(
			Soft_Deny::POLICY_KEY => array( $plugin => Soft_Deny::MODE_SOFT ),
		);

		$soft = Soft_Deny::maybe_arm_from_deny(
			true,
			$event,
			$policy,
			$plugin,
			'generate_text',
			Operations::FAMILY_TEXT
		);
		$this->assertTrue( $soft );
		$this->assertSame( Soft_Deny::OUTCOME, $event['outcome'] ?? '' );
		$this->assertSame( 'deny', $event['decision'] );
		$this->assertTrue( Soft_Deny::is_armed() );

		$stub = Soft_Deny::instance()->maybe_stub( false, array(), 'https://api.openai.com/v1/chat/completions' );
		$this->assertIsArray( $stub );
		$this->assertSame( 200, $stub['response']['code'] );
		$body = json_decode( (string) $stub['body'], true );
		$this->assertSame( '', $body['choices'][0]['message']['content'] ?? null );
		$this->assertFalse( Soft_Deny::is_armed() );
	}

	public function test_maybe_arm_skips_support_checks_and_allow(): void {
		$plugin = 'blocked/plugin.php';
		$policy = array( Soft_Deny::POLICY_KEY => array( $plugin => Soft_Deny::MODE_SOFT ) );

		$event = array( 'decision' => 'deny' );
		$this->assertFalse(
			Soft_Deny::maybe_arm_from_deny( true, $event, $policy, $plugin, 'is_supported_for_text_generation', Operations::FAMILY_TEXT )
		);
		$this->assertFalse( Soft_Deny::is_armed() );

		$event = array( 'decision' => 'allow' );
		$this->assertFalse(
			Soft_Deny::maybe_arm_from_deny( false, $event, $policy, $plugin, 'generate_text', Operations::FAMILY_TEXT )
		);
		$this->assertFalse( Soft_Deny::is_armed() );
	}

	public function test_soft_deny_still_counts_as_deny_for_retry_storm(): void {
		$event = array(
			'decision' => 'deny',
			'outcome'  => Soft_Deny::OUTCOME,
			'plugin'   => 'x/x.php',
			'ts'       => time(),
		);
		$policy = array(
			'retry_storm_enabled'   => true,
			'retry_storm_window'    => 30,
			'retry_storm_threshold' => 5,
			'alert_on_deny'         => true,
		);
		$this->assertFalse( Retry_Storm::should_suppress_deny_alert( $event, $policy ) );

		$log = array();
		Retry_Storm::process_deny( $log, $event, $policy );
		$this->assertSame( 'deny', $event['decision'] );
	}

	public function test_save_policy_persists_soft_modes_without_materializing_hard(): void {
		$policy = array(
			'default'             => 'allow',
			'plugins'             => array(),
			Soft_Deny::POLICY_KEY => array(
				'soft/a.php' => Soft_Deny::MODE_SOFT,
				'hard/b.php' => Soft_Deny::MODE_HARD,
			),
		);
		Policy::save_policy( $policy );
		$stored = get_option( Plugin::OPTION_KEY );
		$this->assertIsArray( $stored );
		$this->assertSame(
			array( 'soft/a.php' => Soft_Deny::MODE_SOFT ),
			$stored[ Soft_Deny::POLICY_KEY ] ?? null
		);
	}

	public function test_noop_save_with_existing_soft_modes_stays_byte_identical(): void {
		$stored = array(
			'default'             => 'allow',
			'plugins'             => array( 'a/a.php' => 'deny' ),
			Soft_Deny::POLICY_KEY => array( 'a/a.php' => Soft_Deny::MODE_SOFT ),
		);
		update_option( Plugin::OPTION_KEY, $stored, false );
		Policy::save_policy( $stored );
		$this->assertSame( $stored, get_option( Plugin::OPTION_KEY ) );
	}

	public function test_policy_wires_soft_deny_after_blocked_ux_comment_not_in_evaluate(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy.php' );
		$pos = strpos( $src, 'Soft_Deny::maybe_arm_from_deny' );
		$this->assertNotFalse( $pos );
		$blocked = strpos( $src, 'AICAC-BLOCKED-UX Phase 1' );
		$this->assertNotFalse( $blocked );
		$this->assertLessThan( $blocked, $pos, 'Soft deny must run immediately before blocked-UX logging' );

		if ( ! preg_match( '/function decide_detailed\b.*?^(?:\t| {4})private function /ms', $src, $m ) ) {
			$this->fail( 'Could not isolate decide_detailed body' );
		}
		$this->assertStringNotContainsString(
			'Soft_Deny::',
			$m[0],
			'Soft_Deny must stay out of decide_detailed / evaluate (PR285 lane)'
		);
	}

	public function test_outcome_from_row(): void {
		$this->assertSame( Soft_Deny::OUTCOME, Soft_Deny::outcome_from_row( array( 'outcome' => 'soft-blocked' ) ) );
		$this->assertSame( '', Soft_Deny::outcome_from_row( array( 'outcome' => 'other' ) ) );
		$this->assertSame( '', Soft_Deny::outcome_from_row( array() ) );
	}
}
