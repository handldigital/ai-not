<?php
/**
 * AICAC-OUTCOME-REPLAY (#347).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Snooze;
use HandL\AICAC\Outcome_Replay;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class OutcomeReplayTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	/** @var list<string> */
	private static array $http = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		self::$http  = array();
		$GLOBALS['handl_aicac_outcome_replay_http'] = 0;

		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		Outcome_Replay::reset_for_tests();
		update_option( 'admin_email', 'admin@example.com' );

		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);
			return true;
		};

		$GLOBALS['handl_aicac_wp_remote_post'] = static function ( string $url, array $args ) {
			self::$http[] = $url;
			return array(
				'response' => array( 'code' => 200 ),
				'body'     => 'ok',
			);
		};

		// pre_http_request trap — any real HTTP during replay must be counted.
		$GLOBALS['handl_aicac_test_filters']['pre_http_request'] = static function ( $preempt, $args, $url ) {
			++$GLOBALS['handl_aicac_outcome_replay_http'];
			self::$http[] = (string) $url;
			return new \WP_Error( 'blocked', 'HTTP blocked in OutcomeReplayTest' );
		};
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_wp_mail'],
			$GLOBALS['handl_aicac_wp_remote_post'],
			$GLOBALS['handl_aicac_test_filters'],
			$GLOBALS['handl_aicac_outcome_replay_http'],
			$GLOBALS['handl_aicac_test_plugins']
		);
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		Outcome_Replay::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * @return array<string,mixed>
	 */
	private function allow_policy(): array {
		return array(
			'default'     => 'allow',
			'plugins'     => array( 'acme/acme.php' => 'allow' ),
			'log_enabled' => true,
			'alert_email' => 'admin@example.com',
		);
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private function sample_log(): array {
		return array(
			array(
				'ts'        => 1_700_000_000,
				'decision'  => 'allow',
				'plugin'    => 'acme/acme.php',
				'operation' => 'generate_text',
				'provider'  => 'openai',
				'model'     => 'gpt-4o-mini',
			),
			array(
				'ts'        => 1_700_000_100,
				'decision'  => 'allow',
				'plugin'    => 'other/other.php',
				'operation' => 'generate_text',
				'provider'  => 'openai',
			),
		);
	}

	public function test_noop_when_policy_unchanged(): void {
		$policy = $this->allow_policy();
		Policy::save_policy( $policy );
		update_option( Plugin::LOG_OPTION_KEY, $this->sample_log(), false );

		Outcome_Replay::on_upgrader_process_complete(
			null,
			array(
				'type'   => 'plugin',
				'action' => 'update',
				'plugin' => 'acme/acme.php',
			)
		);
		$stats = Outcome_Replay::run_pending();

		$this->assertSame( 0, $stats['flips'] );
		$this->assertFalse( $stats['alerted'] );
		$this->assertFalse( $stats['noticed'] );
		$this->assertSame( array(), self::$mails );
		$this->assertNull( get_option( Outcome_Replay::NOTICE_OPTION, null ) );
	}

	public function test_flip_allow_to_deny_alerts_once(): void {
		$policy = $this->allow_policy();
		Policy::save_policy( $policy );
		update_option( Plugin::LOG_OPTION_KEY, $this->sample_log(), false );

		// Tighten: deny acme.
		$policy['plugins']['acme/acme.php'] = 'deny';
		Policy::save_policy( $policy );

		Outcome_Replay::schedule_replay( 'plugins', array( 'acme/acme.php' ), 'plugin' );
		$stats = Outcome_Replay::run_pending( Policy::get_policy(), $this->sample_log(), 1_700_000_200 );

		$this->assertSame( 1, $stats['flips'] );
		$this->assertTrue( $stats['alerted'] );
		$this->assertTrue( $stats['noticed'] );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'acme/acme.php', self::$mails[0]['message'] );
		$this->assertStringContainsString( 'allow → deny', self::$mails[0]['message'] );

		$notice = get_option( Outcome_Replay::NOTICE_OPTION );
		$this->assertIsArray( $notice );
		$this->assertSame( 1, (int) $notice['count'] );
		$this->assertSame( 'allow', $notice['flips'][0]['old'] );
		$this->assertSame( 'deny', $notice['flips'][0]['new'] );
	}

	public function test_single_plugin_update_scopes_to_that_plugin(): void {
		$policy = $this->allow_policy();
		$policy['plugins']['other/other.php'] = 'deny';
		$policy['plugins']['acme/acme.php']   = 'deny';
		Policy::save_policy( $policy );

		// Both would flip, but scope is acme only.
		$result = Outcome_Replay::replay(
			Policy::get_policy(),
			$this->sample_log(),
			array( 'acme/acme.php' ),
			200,
			1_700_000_200
		);

		$this->assertSame( 1, $result['scanned'] );
		$this->assertCount( 1, $result['flips'] );
		$this->assertSame( 'acme/acme.php', $result['flips'][0]['plugin'] );
		$this->assertSame( 0, $result['http_calls'] );
	}

	public function test_core_and_aicac_scope_all_plugins(): void {
		$core = Outcome_Replay::parse_update_scope(
			array(
				'type'   => 'core',
				'action' => 'update',
			)
		);
		$this->assertSame( 'all', $core['scope'] );

		$aicac = Outcome_Replay::aicac_basename();
		$scope = Outcome_Replay::parse_update_scope(
			array(
				'type'   => 'plugin',
				'action' => 'update',
				'plugin' => $aicac,
			)
		);
		$this->assertSame( 'all', $scope['scope'] );
		$this->assertSame( 'aicac', $scope['trigger'] );

		$policy = $this->allow_policy();
		$policy['plugins']['acme/acme.php']   = 'deny';
		$policy['plugins']['other/other.php'] = 'deny';
		$result = Outcome_Replay::replay( $policy, $this->sample_log(), null );
		$this->assertCount( 2, $result['flips'] );
	}

	public function test_replay_issues_no_outbound_http(): void {
		$policy = $this->allow_policy();
		$policy['plugins']['acme/acme.php'] = 'deny';
		$result = Outcome_Replay::replay( $policy, $this->sample_log(), array( 'acme/acme.php' ) );

		$this->assertGreaterThan( 0, $result['scanned'] );
		$this->assertSame( 0, $result['http_calls'] );
		$this->assertSame( 0, (int) $GLOBALS['handl_aicac_outcome_replay_http'] );
		// wp_remote_post stub must not have been hit during pure replay.
		$this->assertSame( array(), self::$http );
	}

	public function test_snooze_suppresses_flip_rows(): void {
		$now = 1_700_000_200;
		Alert_Snooze::set( 'acme/acme.php', '24h', $now );

		$policy = $this->allow_policy();
		$policy['plugins']['acme/acme.php'] = 'deny';
		$result = Outcome_Replay::replay( $policy, $this->sample_log(), array( 'acme/acme.php' ), 200, $now );

		$this->assertSame( 1, $result['scanned'] );
		$this->assertSame( array(), $result['flips'] );
	}

	public function test_zero_flips_skips_notice_and_mail_after_run_pending(): void {
		Policy::save_policy( $this->allow_policy() );
		update_option( Plugin::LOG_OPTION_KEY, $this->sample_log(), false );
		Outcome_Replay::schedule_replay( 'all', array(), 'core' );
		$stats = Outcome_Replay::run_pending();
		$this->assertSame( 0, $stats['flips'] );
		$this->assertSame( array(), self::$mails );
		$this->assertNull( get_option( Outcome_Replay::NOTICE_OPTION, null ) );
	}

	public function test_gate_class_helpers(): void {
		$this->assertSame( 'budget', Outcome_Replay::gate_class( 'budget:hard' ) );
		$this->assertSame( 'rate_cap', Outcome_Replay::gate_class( 'rate_cap:hourly' ) );
		$this->assertSame( 'user_quota', Outcome_Replay::gate_class( 'user_quota' ) );
		$this->assertSame( '', Outcome_Replay::gate_class( 'rule:explicit-deny' ) );
	}
}
