<?php
/**
 * AICAC-DRIFT (#157): provider/model change alerts.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Snooze;
use HandL\AICAC\Drift;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class DriftAlertTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Drift::SEEN_OPTION_KEY );
		delete_option( Drift::RECENT_OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		update_option( 'admin_email', 'admin@example.com' );

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
		unset( $GLOBALS['handl_aicac_wp_mail'] );
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Drift::SEEN_OPTION_KEY );
		delete_option( Drift::RECENT_OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		Drift::flush_deferred_alerts();
		parent::tearDown();
	}

	public function test_sanitize_mode_defaults_to_provider(): void {
		$this->assertSame( Drift::MODE_PROVIDER, Drift::sanitize_mode( '' ) );
		$this->assertSame( Drift::MODE_PROVIDER, Drift::sanitize_mode( 'nope' ) );
		$this->assertSame( Drift::MODE_MODEL, Drift::sanitize_mode( 'model' ) );
		$this->assertSame( Drift::MODE_OFF, Drift::sanitize_mode( 'off' ) );
	}

	public function test_baseline_first_activity_does_not_alert(): void {
		$policy = $this->persist_policy( array( 'drift_alert_mode' => Drift::MODE_MODEL ) );
		$event  = $this->ai_event( 'acme/acme.php', 'openai', 'gpt-4o-mini' );
		$result = Drift::observe( $event, $policy );

		$this->assertTrue( $result['baseline'] );
		$this->assertTrue( $result['tagged'] );
		$this->assertFalse( $result['alerted'] );
		$this->assertTrue( ! empty( $event['drift_first_seen'] ) );
		$this->assertSame( array(), self::$mails );
	}

	public function test_same_pair_never_realerts(): void {
		$policy = $this->persist_policy( array( 'drift_alert_mode' => Drift::MODE_MODEL ) );
		$first  = $this->ai_event( 'acme/acme.php', 'openai', 'gpt-4o-mini', 1_700_000_000 );
		Drift::observe( $first, $policy );

		$again  = $this->ai_event( 'acme/acme.php', 'openai', 'gpt-4o-mini', 1_700_000_100 );
		$result = Drift::observe( $again, $policy );
		$this->assertSame( 'known_pair', $result['reason'] );
		$this->assertFalse( $result['tagged'] );
		$this->assertSame( array(), self::$mails );

		// New model → alert once.
		$drift = $this->ai_event( 'acme/acme.php', 'openai', 'gpt-4o', 1_700_000_200 );
		$hit   = Drift::observe( $drift, $policy );
		$this->assertTrue( $hit['alerted'] );
		$this->assertCount( 1, self::$mails );

		$repeat = $this->ai_event( 'acme/acme.php', 'openai', 'gpt-4o', 1_700_000_300 );
		$again2 = Drift::observe( $repeat, $policy );
		$this->assertSame( 'known_pair', $again2['reason'] );
		$this->assertCount( 1, self::$mails );
	}

	public function test_provider_mode_skips_same_provider_new_model(): void {
		$policy = $this->persist_policy( array( 'drift_alert_mode' => Drift::MODE_PROVIDER ) );
		$base   = $this->ai_event( 'acme/acme.php', 'openai', 'gpt-4o-mini' );
		Drift::observe( $base, $policy );

		$same_provider = $this->ai_event( 'acme/acme.php', 'openai', 'gpt-4o' );
		$skip          = Drift::observe( $same_provider, $policy );
		$this->assertTrue( $skip['tagged'] );
		$this->assertFalse( $skip['alerted'] );
		$this->assertSame( 'mode_skip', $skip['reason'] );
		$this->assertSame( array(), self::$mails );

		$new_provider = $this->ai_event( 'acme/acme.php', 'anthropic', 'claude-3-5-sonnet' );
		$hit          = Drift::observe( $new_provider, $policy );
		$this->assertTrue( $hit['alerted'] );
		$this->assertCount( 1, self::$mails );
	}

	public function test_cost_multiple_only_when_both_provider_rates_exist(): void {
		$policy = array(
			'est_usd_provider_rates' => array(
				'openai'    => array( 'input_per_m' => 1.0, 'output_per_m' => 1.0 ),
				'anthropic' => array( 'input_per_m' => 3.0, 'output_per_m' => 3.0 ),
			),
		);
		$this->assertSame( 3.0, Drift::cost_multiple( 'openai', 'anthropic', $policy ) );
		$this->assertNull( Drift::cost_multiple( 'openai', 'openai', $policy ) );
		$this->assertNull( Drift::cost_multiple( 'openai', 'groq', $policy ) );

		$policy = $this->persist_policy(
			array(
				'drift_alert_mode'       => Drift::MODE_PROVIDER,
				'est_usd_provider_rates' => array(
					'openai'    => array( 'input_per_m' => 1.0, 'output_per_m' => 1.0 ),
					'anthropic' => array( 'input_per_m' => 5.0, 'output_per_m' => 5.0 ),
				),
			)
		);
		$base = $this->ai_event( 'acme/acme.php', 'openai', 'gpt-4o-mini' );
		$next = $this->ai_event( 'acme/acme.php', 'anthropic', 'claude-3-5-sonnet' );
		Drift::observe( $base, $policy );
		Drift::observe( $next, $policy );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( '5x', self::$mails[0]['message'] );
		$this->assertStringContainsString( 'Estimated spend is not billing', self::$mails[0]['message'] );
	}

	public function test_off_mode_tracks_without_alerting(): void {
		$policy = $this->persist_policy( array( 'drift_alert_mode' => Drift::MODE_OFF ) );
		$first  = $this->ai_event( 'acme/acme.php', 'openai', 'gpt-4o-mini' );
		$second_event = $this->ai_event( 'acme/acme.php', 'anthropic', 'claude-3-5-sonnet' );
		Drift::observe( $first, $policy );
		$second = Drift::observe( $second_event, $policy );
		$this->assertTrue( $second['tagged'] );
		$this->assertFalse( $second['alerted'] );
		$this->assertSame( 'disabled', $second['reason'] );
		$this->assertSame( array(), self::$mails );

		$map = Drift::get_seen_map();
		$this->assertArrayHasKey( 'acme/acme.php', $map );
		$this->assertCount( 2, $map['acme/acme.php'] );
	}

	public function test_append_log_event_tags_and_alerts_once(): void {
		$this->persist_policy( array( 'drift_alert_mode' => Drift::MODE_MODEL ) );

		Policy::append_log_event( $this->ai_event( 'acme/acme.php', 'openai', 'gpt-4o-mini', 1_700_000_000 ) );
		$this->assertCount( 1, self::$mails );
		$this->assertStringContainsString( 'started using AI', self::$mails[0]['subject'] );

		Policy::append_log_event( $this->ai_event( 'acme/acme.php', 'openai', 'gpt-4o', 1_700_000_100 ) );
		$this->assertCount( 2, self::$mails );
		$this->assertStringContainsString( 'gpt-4o', self::$mails[1]['subject'] );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $log );
		$tagged = false;
		$audit  = false;
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( ! empty( $row['drift_first_seen'] ) && ( $row['model'] ?? '' ) === 'gpt-4o' ) {
				$tagged = true;
			}
			if ( ( $row['channel'] ?? '' ) === 'drift' ) {
				$audit = true;
				$this->assertSame( 'drift_alert', $row['decision'] ?? '' );
			}
		}
		$this->assertTrue( $tagged, 'Expected drift_first_seen on activity row' );
		$this->assertTrue( $audit, 'Expected drift audit row' );
		$this->assertNotEmpty( Drift::get_recent() );
	}

	public function test_snooze_suppresses_drift_alert(): void {
		$plugin = 'acme/acme.php';
		$now    = 1_700_000_000;
		Alert_Snooze::set( $plugin, '1h', $now );
		$policy = $this->persist_policy( array( 'drift_alert_mode' => Drift::MODE_MODEL ) );

		$baseline = $this->ai_event( $plugin, 'openai', 'gpt-4o-mini', $now );
		$drift    = $this->ai_event( $plugin, 'openai', 'gpt-4o', $now + 10 );
		Drift::observe( $baseline, $policy );
		$hit = Drift::observe( $drift, $policy );
		$this->assertFalse( $hit['alerted'] );
		$this->assertSame( 'suppressed', $hit['reason'] );
		$this->assertSame( array(), self::$mails );
	}

	/**
	 * @param array<string,mixed> $overrides
	 * @return array<string,mixed>
	 */
	private function persist_policy( array $overrides ): array {
		$policy = array_merge(
			array(
				'log_enabled'      => true,
				'audit_only'       => false,
				'alert_email'      => 'admin@example.com',
				'drift_alert_mode' => Drift::MODE_PROVIDER,
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
		);
	}
}
