<?php
/**
 * AICAC-DIGEST (#120): weekly governance digest.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Governance_Digest;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Rest;
use PHPUnit\Framework\TestCase;

final class GovernanceDigestTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		$GLOBALS['handl_aicac_test_cron'] = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Governance_Digest::SENT_OPTION_KEY );
		update_option( 'admin_email', 'admin@example.com' );
		update_option( 'blogname', 'Sandbox Site' );

		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message, $headers = '', $attachments = array() ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);
			unset( $headers, $attachments );
			return true;
		};
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'], $GLOBALS['handl_aicac_test_cron'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Governance_Digest::SENT_OPTION_KEY );
		parent::tearDown();
	}

	/**
	 * @param array<string,mixed> $extra
	 * @return array<string,mixed>
	 */
	private function persist_policy( array $extra ): array {
		$policy = array_merge(
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
			),
			$extra
		);
		Policy::save_policy( $policy );

		return Policy::get_policy();
	}

	/**
	 * @return array<string,mixed>
	 */
	private function client_row( string $plugin, string $decision, float $usd, int $ts ): array {
		// Rough token totals so Cost::estimate_usd yields ~$usd with defaults.
		$in = (int) max( 1, round( ( $usd / 2.0 ) * 1_000_000 / 0.15 ) );
		$out = (int) max( 1, round( ( $usd / 2.0 ) * 1_000_000 / 0.60 ) );

		return array(
			'ts'            => $ts,
			'plugin'        => $plugin,
			'decision'      => $decision,
			'provider'      => 'openai',
			'input_tokens'  => $in,
			'output_tokens' => $out,
		);
	}

	public function test_disabled_does_not_schedule_or_send(): void {
		$policy = $this->persist_policy( array( 'governance_digest_enabled' => false ) );
		Governance_Digest::maybe_schedule( $policy );
		$this->assertFalse( wp_next_scheduled( Governance_Digest::CRON_HOOK ) );

		$out = Governance_Digest::send_if_due( $policy, array(), time() );
		$this->assertFalse( $out['sent'] );
		$this->assertSame( 'inactive', $out['status'] );
		$this->assertSame( array(), self::$mails );
	}

	public function test_stats_match_activity_summary_and_body_uses_estimated(): void {
		$now = strtotime( '2026-08-12 15:00:00 UTC' );
		$log = array(
			$this->client_row( 'a/a.php', 'allow', 1.0, $now - 3600 ),
			$this->client_row( 'a/a.php', 'deny', 0.5, $now - 7200 ),
			array(
				'ts'       => $now - 1800,
				'channel'  => 'direct_http',
				'decision' => 'observe',
				'count'    => 3,
				'plugin'   => 'b/b.php',
				'host'     => 'api.openai.com',
			),
			array(
				'ts'       => $now - 900,
				'channel'  => 'anomaly',
				'decision' => 'anomaly_alert',
				'plugin'   => 'a/a.php',
			),
		);
		$policy  = $this->persist_policy( array( 'log_enabled' => true ) );
		$plugins = array( 'a/a.php' => array( 'Name' => 'Plugin A' ) );

		$stats   = Governance_Digest::build_stats( $policy, $log, $plugins, $now );
		$summary = Rest::build_activity_summary( $policy, $log, Governance_Digest::WINDOW, $now );

		$this->assertSame( (int) ( $summary['ai_client_call_count'] ?? 0 ), $stats['ai_client_calls'] );
		$this->assertSame( (int) ( $summary['calls_by_decision']['deny'] ?? 0 ), $stats['blocked_calls'] );
		$this->assertSame( (int) ( $summary['shadow_ai_observation_count'] ?? 0 ), $stats['shadow_count'] );
		$this->assertSame( 1, $stats['anomaly_count'] );
		$this->assertTrue( $stats['has_activity'] );

		$body = Governance_Digest::build_body( $stats );
		$this->assertStringContainsString( 'Estimated spend', $body );
		$this->assertStringContainsString( 'estimated', strtolower( $body ) );
		$this->assertStringContainsString( 'Turn off or change this digest:', $body );
		$this->assertStringNotContainsString( 'admin@example.com', $body );
	}

	public function test_zero_activity_skips_unless_always_send(): void {
		$now    = strtotime( '2026-08-12 15:00:00 UTC' );
		$policy = $this->persist_policy(
			array(
				'governance_digest_enabled'     => true,
				'governance_digest_always_send' => false,
				'log_enabled'                   => true,
				'alert_email'                   => 'ops@example.com',
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );

		$skip = Governance_Digest::send_if_due( $policy, array(), $now );
		$this->assertFalse( $skip['sent'] );
		$this->assertSame( 'no_activity', $skip['status'] );
		$this->assertSame( array(), self::$mails );

		$policy_always = $this->persist_policy(
			array(
				'governance_digest_enabled'     => true,
				'governance_digest_always_send' => true,
				'log_enabled'                   => true,
				'alert_email'                   => 'ops@example.com',
			)
		);
		$sent = Governance_Digest::send_if_due( $policy_always, array(), $now );
		$this->assertTrue( $sent['sent'] );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'governance digest', strtolower( self::$mails[0]['subject'] ) );
		$this->assertStringContainsString( 'No AI activity', self::$mails[0]['message'] );
	}

	public function test_one_email_per_week_and_disable_unschedules(): void {
		$now = strtotime( '2026-08-12 15:00:00 UTC' );
		$log = array( $this->client_row( 'a/a.php', 'allow', 1.0, $now - 100 ) );
		update_option( Plugin::LOG_OPTION_KEY, $log, false );

		$policy = $this->persist_policy(
			array(
				'governance_digest_enabled' => true,
				'log_enabled'               => true,
				'alert_email'               => 'ops@example.com',
			)
		);

		Governance_Digest::maybe_schedule( $policy );
		$this->assertNotFalse( wp_next_scheduled( Governance_Digest::CRON_HOOK ) );

		$first = Governance_Digest::send_if_due( $policy, array( 'a/a.php' => array( 'Name' => 'A' ) ), $now );
		$this->assertTrue( $first['sent'] );
		$this->assertCount( 1, self::$mails );

		$second = Governance_Digest::send_if_due( $policy, array(), $now + 3600 );
		$this->assertFalse( $second['sent'] );
		$this->assertSame( 'already_sent', $second['status'] );
		$this->assertCount( 1, self::$mails );

		$off = $this->persist_policy(
			array(
				'governance_digest_enabled' => false,
				'log_enabled'               => true,
			)
		);
		Governance_Digest::maybe_schedule( $off );
		$this->assertFalse( wp_next_scheduled( Governance_Digest::CRON_HOOK ) );
	}
}
