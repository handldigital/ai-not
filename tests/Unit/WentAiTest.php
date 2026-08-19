<?php
/**
 * AICAC-WENT-AI (#207): first AI Client call from a plugin that never used AI.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Snooze;
use HandL\AICAC\New_Plugin;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Quiet_Hours;
use HandL\AICAC\Went_AI;
use PHPUnit\Framework\TestCase;

final class WentAiTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Went_AI::STAMP_OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		update_option( 'admin_email', 'admin@example.com' );
		$GLOBALS['handl_aicac_test_plugins'] = array(
			'legacy/legacy.php' => array(
				'Name'    => 'Legacy Tool',
				'Version' => '3.2.1',
			),
			'fresh/fresh.php'   => array(
				'Name'    => 'Fresh Plugin',
				'Version' => '1.0.0',
			),
		);
		$GLOBALS['handl_aicac_wp_mail'] = static function ( $to, $subject, $message ) {
			self::$mails[] = array(
				'to'      => (string) $to,
				'subject' => (string) $subject,
				'message' => (string) $message,
			);
			return true;
		};
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_mail'], $GLOBALS['handl_aicac_test_plugins'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Went_AI::STAMP_OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		parent::tearDown();
	}

	public function test_first_ai_call_alerts_once_second_does_not(): void {
		$policy = $this->persist_policy();
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'             => 1_699_000_000,
					'plugin'         => 'legacy/legacy.php',
					'channel'        => 'direct_http',
					'plugin_version' => '3.1.0',
					'decision'       => 'observe',
				),
			),
			false
		);

		$first = $this->ai_event( 'legacy/legacy.php', 'openai', 'gpt-4o-mini', 1_700_000_000 );
		$hit   = Went_AI::observe( $first, $policy );
		$this->assertTrue( $hit['tagged'] );
		$this->assertTrue( $hit['alerted'] );
		$this->assertTrue( ! empty( $first['went_ai_first'] ) );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( '3.2.1', self::$mails[0]['message'] );
		$this->assertStringContainsString( '3.1.0', self::$mails[0]['message'] );

		$second = $this->ai_event( 'legacy/legacy.php', 'openai', 'gpt-4o-mini', 1_700_000_100 );
		$again  = Went_AI::observe( $second, $policy );
		$this->assertSame( 'known', $again['reason'] );
		$this->assertFalse( $again['alerted'] );
		$this->assertCount( 1, self::$mails );

		$stamps = Went_AI::get_stamps();
		$this->assertArrayHasKey( 'legacy/legacy.php', $stamps );
		$this->assertSame( 1_700_000_000, $stamps['legacy/legacy.php']['ts'] );
	}

	public function test_new_plugin_pending_does_not_double_alert(): void {
		$policy = $this->persist_policy(
			array(
				'new_plugin_review_enabled' => true,
				'new_plugin_pending'        => array( 'fresh/fresh.php' => 1_700_000_000 ),
				'new_plugin_known'          => array(),
			)
		);
		$event = $this->ai_event( 'fresh/fresh.php', 'openai', 'gpt-4o-mini' );
		$hit   = Went_AI::observe( $event, $policy );
		$this->assertTrue( $hit['tagged'] );
		$this->assertFalse( $hit['alerted'] );
		$this->assertSame( 'new_plugin', $hit['reason'] );
		$this->assertSame( array(), self::$mails );
		$this->assertTrue( New_Plugin::is_enabled( $policy ) );
		$this->assertContains( 'fresh/fresh.php', New_Plugin::pending_plugins( $policy ) );

		$again_event = $this->ai_event( 'fresh/fresh.php', 'openai', 'gpt-4o', 1_700_000_100 );
		$again       = Went_AI::observe( $again_event, $policy );
		$this->assertSame( 'known', $again['reason'] );
		$this->assertSame( array(), self::$mails );
	}

	public function test_provider_change_on_established_caller_is_not_went_ai(): void {
		$policy = $this->persist_policy();
		$base = $this->ai_event( 'legacy/legacy.php', 'openai', 'gpt-4o-mini' );
		Went_AI::observe( $base, $policy );
		self::$mails = array();

		$drift = $this->ai_event( 'legacy/legacy.php', 'anthropic', 'claude-3-5-sonnet', 1_700_000_200 );
		$hit   = Went_AI::observe( $drift, $policy );
		$this->assertSame( 'known', $hit['reason'] );
		$this->assertSame( array(), self::$mails );
	}

	public function test_snooze_suppresses_went_ai_alert(): void {
		$plugin = 'legacy/legacy.php';
		$now    = 1_700_000_000;
		Alert_Snooze::set( $plugin, '1h', $now );
		$policy = $this->persist_policy();
		$event  = $this->ai_event( $plugin, 'openai', 'gpt-4o-mini', $now );
		$hit    = Went_AI::observe( $event, $policy );
		$this->assertFalse( $hit['alerted'] );
		$this->assertSame( 'suppressed', $hit['reason'] );
		$this->assertSame( array(), self::$mails );
		$this->assertArrayHasKey( $plugin, Went_AI::get_stamps() );
	}

	public function test_quiet_hours_suppresses_went_ai_alert(): void {
		$now    = 1_704_067_200; // Monday 00:00 UTC 2023-12-04-ish; use window that always matches.
		$policy = $this->persist_policy(
			array(
				'quiet_hours' => array(
					array(
						'id'    => 'qa-window',
						'name'  => 'Always',
						'days'  => array( 0, 1, 2, 3, 4, 5, 6 ),
						'start' => '00:00',
						'end'   => '23:59',
						'mode'  => Quiet_Hours::MODE_OBSERVE,
					),
				),
			)
		);
		$event = $this->ai_event( 'legacy/legacy.php', 'openai', 'gpt-4o-mini', $now );
		$hit   = Went_AI::observe( $event, $policy );
		$this->assertFalse( $hit['alerted'] );
		$this->assertSame( 'quiet_hours', $hit['reason'] );
		$this->assertSame( array(), self::$mails );
	}

	public function test_site_health_lists_plugins_from_last_30_days(): void {
		$now = 1_700_000_000;
		Went_AI::save_stamps(
			array(
				'legacy/legacy.php' => array(
					'ts'       => $now - 1000,
					'version'  => '3.2.1',
					'provider' => 'openai',
					'model'    => 'gpt-4o-mini',
					'context'  => 'frontend',
				),
				'old/old.php'       => array(
					'ts'       => $now - ( Went_AI::WINDOW_SECONDS + 10 ),
					'version'  => '1.0',
					'provider' => 'openai',
					'model'    => 'gpt-4o',
					'context'  => 'frontend',
				),
			)
		);
		$recent = Went_AI::plugins_started_since( $now - Went_AI::WINDOW_SECONDS );
		$this->assertSame( array( 'legacy/legacy.php' ), $recent );
	}

	public function test_append_log_event_tags_and_alerts_once(): void {
		$this->persist_policy();
		Policy::append_log_event( $this->ai_event( 'legacy/legacy.php', 'openai', 'gpt-4o-mini', 1_700_000_000 ) );
		$this->assertCount( 1, self::$mails );

		Policy::append_log_event( $this->ai_event( 'legacy/legacy.php', 'openai', 'gpt-4o-mini', 1_700_000_100 ) );
		$this->assertCount( 1, self::$mails );

		$log    = get_option( Plugin::LOG_OPTION_KEY, array() );
		$tagged = false;
		foreach ( $log as $row ) {
			if ( is_array( $row ) && ! empty( $row['went_ai_first'] ) ) {
				$tagged = true;
			}
		}
		$this->assertTrue( $tagged, 'Expected went_ai_first on the first activity row' );
	}

	/**
	 * @param array<string,mixed> $overrides
	 * @return array<string,mixed>
	 */
	private function persist_policy( array $overrides = array() ): array {
		$policy = array_merge(
			array(
				'log_enabled' => true,
				'audit_only'  => false,
				'alert_email' => 'admin@example.com',
			),
			$overrides
		);
		Policy::save_policy( $policy );
		return Policy::get_policy();
	}

	/**
	 * @return array<string,mixed>
	 */
	private function ai_event( string $plugin, string $provider, string $model, int $ts = 1_700_000_000 ): array {
		return array(
			'ts'       => $ts,
			'plugin'   => $plugin,
			'provider' => $provider,
			'model'    => $model,
			'decision' => 'allow',
			'context'  => 'frontend',
		);
	}
}
