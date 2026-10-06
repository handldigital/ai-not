<?php
/**
 * AICAC-THREAT-FEED (#295).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Review_Due;
use HandL\AICAC\Threat_Feed;
use PHPUnit\Framework\TestCase;
use WP_Error;

final class ThreatFeedTest extends TestCase {

	/** Test-only Ed25519 secret key (hex). Production key is not this value. */
	private const TEST_SK = '2c2972afb959602dfcf714921c496c86655b725bce3286c6de4d55c429ffc1375e4ad62aa0895f60b9eab237b544845c7e13da9348d2b6b3808bdc12b4597470';

	private const TEST_PK = '5e4ad62aa0895f60b9eab237b544845c7e13da9348d2b6b3808bdc12b4597470';

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		Threat_Feed::reset_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Review_Due::OPTION_KEY );
		delete_option( Threat_Feed::OPTION_KEY );
		unset( $GLOBALS['handl_aicac_test_plugins'], $GLOBALS['handl_aicac_threat_feed_http'] );
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_filters']       = array(
			Threat_Feed::FILTER_PUBKEY => static function ( $pk ) {
				unset( $pk );
				return self::TEST_PK;
			},
		);
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
		Threat_Feed::reset_for_tests();
		unset(
			$GLOBALS['handl_aicac_wp_mail'],
			$GLOBALS['handl_aicac_test_plugins'],
			$GLOBALS['handl_aicac_threat_feed_http'],
			$GLOBALS['handl_aicac_test_filters']
		);
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Review_Due::OPTION_KEY );
		delete_option( Threat_Feed::OPTION_KEY );
		parent::tearDown();
	}

	/**
	 * @return array<string,array<string,mixed>>
	 */
	private function installed(): array {
		return array(
			'acme/acme.php' => array(
				'Name'    => 'Acme',
				'Version' => '1.0.0',
			),
		);
	}

	/**
	 * @param array<string,mixed> $payload
	 */
	private function sign_envelope( array $payload ): string {
		$canonical = json_encode( $payload, Threat_Feed::SIGN_FLAGS );
		$sk        = hex2bin( self::TEST_SK );
		$this->assertIsString( $canonical );
		$this->assertIsString( $sk );
		$sig = sodium_crypto_sign_detached( $canonical, $sk );

		return json_encode(
			array(
				'payload'   => $payload,
				'signature' => bin2hex( $sig ),
			),
			Threat_Feed::SIGN_FLAGS
		);
	}

	/**
	 * @param array<string,mixed> $advisory
	 */
	private function payload_with( array $advisory ): array {
		return array(
			'version'      => 1,
			'generated_at' => '2026-10-06T00:00:00Z',
			'advisories'   => array( $advisory ),
		);
	}

	private function stub_http( int $code, string $body, string $etag = '"v1"' ): void {
		$GLOBALS['handl_aicac_threat_feed_http'] = static function ( $url, $args ) use ( $code, $body, $etag ) {
			unset( $url, $args );
			return array(
				'response' => array( 'code' => $code ),
				'body'     => $body,
				'headers'  => array( 'etag' => $etag ),
			);
		};
	}

	private function save_allow_policy(): void {
		Policy::save_policy(
			array(
				'plugins'         => array( 'acme/acme.php' => 'allow' ),
				'review_due_days' => 90,
				'default'         => 'observe',
				'log_enabled'     => true,
				'alert_email'     => 'admin@example.com',
			)
		);
		$GLOBALS['handl_aicac_test_plugins'] = $this->installed();
	}

	public function test_init_registers_daily_cron_hook(): void {
		Threat_Feed::init();
		$actions = $GLOBALS['handl_aicac_test_added_actions'] ?? array();
		$this->assertContains( Threat_Feed::CRON_HOOK, $actions );
	}

	public function test_signature_reject_does_not_stamp_or_alert(): void {
		$this->save_allow_policy();
		Review_Due::put_stamps( array( 'acme/acme.php' => 1_700_000_000 ) );
		$payload = $this->payload_with(
			array(
				'id'      => 'adv-bad-sig',
				'plugins' => array( 'acme' ),
				'reason'  => 'known issue',
			)
		);
		$envelope = json_decode( $this->sign_envelope( $payload ), true );
		$envelope['signature'] = str_repeat( 'ab', 64 );
		$this->stub_http( 200, json_encode( $envelope, Threat_Feed::SIGN_FLAGS ) );

		$stat = Threat_Feed::run( 1_700_000_100 );
		$this->assertSame( 'invalid_signature', $stat['error'] );
		$this->assertSame( 0, $stat['applied'] );
		$this->assertSame( array(), self::$mails );
		$this->assertSame( 1_700_000_000, Review_Due::get_stamps()['acme/acme.php'] );
		$this->assertSame( 'allow', Policy::get_policy()['plugins']['acme/acme.php'] );
		$this->assertSame( 'invalid_signature', Threat_Feed::get_state()['last_error'] );
	}

	public function test_match_marks_review_due_and_sends_one_alert(): void {
		$this->save_allow_policy();
		Review_Due::put_stamps( array( 'acme/acme.php' => 1_700_000_000 ) );
		$body = $this->sign_envelope(
			$this->payload_with(
				array(
					'id'        => 'adv-2026-001',
					'plugins'   => array( 'acme' ),
					'endpoints' => array( 'api.evil.example' ),
					'models'    => array(),
					'reason'    => 'Public disclosure of leaked connector keys',
					'severity'  => 'high',
					'url'       => 'https://handldigital.com/advisories/adv-2026-001',
				)
			)
		);
		$this->stub_http( 200, $body );

		$now  = 1_700_000_100;
		$stat = Threat_Feed::run( $now );
		$this->assertSame( '', $stat['error'] );
		$this->assertTrue( $stat['fetched'] );
		$this->assertSame( 1, $stat['applied'] );
		$this->assertSame( 1, $stat['alerted'] );
		$this->assertCount( 1, self::$mails );
		$this->assertSame( Threat_Feed::DUE_STAMP, Review_Due::get_stamps()['acme/acme.php'] );

		$snap = Review_Due::snapshot( Policy::get_policy(), $this->installed(), $now );
		$this->assertSame( 1, $snap['due'] );
		$this->assertSame( 'allow', Policy::get_policy()['plugins']['acme/acme.php'] );

		$this->assertStringContainsString( 'Review an Allow rule', self::$mails[0]['subject'] );
		$this->assertStringContainsString( 'review your Allow rules', self::$mails[0]['message'] );
		$this->assertStringContainsString( 'Your access rules have not changed.', self::$mails[0]['message'] );
		$this->assertStringNotContainsString( 'advisory match', self::$mails[0]['message'] );
		$this->assertSame( $now, Threat_Feed::get_state()['applied_ids']['adv-2026-001'] );
		$this->assertSame( '', Threat_Feed::get_state()['last_error'] );
	}

	public function test_body_lists_all_matched_plugins_to_review(): void {
		$body = Threat_Feed::build_body(
			'acme/acme.php',
			array(
				'id'       => 'adv-multi',
				'reason'   => 'two allows',
				'severity' => 'high',
			),
			array( 'acme/acme.php', 'other/other.php' )
		);
		$this->assertStringContainsString( 'HandL AI Connector Access Control: review your Allow rules', $body );
		$this->assertStringContainsString( 'Plugin: acme/acme.php', $body );
		$this->assertStringContainsString( 'Plugins to review: acme/acme.php, other/other.php', $body );
		$this->assertStringNotContainsString( 'Also matched:', $body );
		$this->assertStringNotContainsString( 'advisory match', $body );
	}

	public function test_no_match_is_noop(): void {
		$this->save_allow_policy();
		Review_Due::put_stamps( array( 'acme/acme.php' => 1_700_000_000 ) );
		$body = $this->sign_envelope(
			$this->payload_with(
				array(
					'id'        => 'adv-other',
					'plugins'   => array( 'other-ai' ),
					'endpoints' => array( 'api.other.example' ),
					'models'    => array( 'other-model' ),
					'reason'    => 'unrelated',
					'severity'  => 'low',
				)
			)
		);
		$this->stub_http( 200, $body );

		$stat = Threat_Feed::run( 1_700_000_100 );
		$this->assertSame( '', $stat['error'] );
		$this->assertTrue( $stat['fetched'] );
		$this->assertSame( 0, $stat['applied'] );
		$this->assertSame( array(), self::$mails );
		$this->assertSame( 1_700_000_000, Review_Due::get_stamps()['acme/acme.php'] );
		$this->assertArrayNotHasKey( 'adv-other', Threat_Feed::get_state()['applied_ids'] );
		$this->assertSame( 'allow', Policy::get_policy()['plugins']['acme/acme.php'] );
	}

	public function test_unreachable_feed_is_noop(): void {
		$this->save_allow_policy();
		Review_Due::put_stamps( array( 'acme/acme.php' => 1_700_000_000 ) );
		$GLOBALS['handl_aicac_threat_feed_http'] = static function () {
			return new WP_Error( 'http_request_failed', 'Could not resolve host' );
		};

		$stat = Threat_Feed::run( 1_700_000_100 );
		$this->assertSame( 'unreachable', $stat['error'] );
		$this->assertFalse( $stat['fetched'] );
		$this->assertSame( 0, $stat['applied'] );
		$this->assertSame( array(), self::$mails );
		$this->assertSame( 1_700_000_000, Review_Due::get_stamps()['acme/acme.php'] );
		$this->assertSame( 'allow', Policy::get_policy()['plugins']['acme/acme.php'] );
		$this->assertSame( 'Could not resolve host', Threat_Feed::get_state()['last_error'] );
		$this->assertGreaterThan( 1_700_000_100, Threat_Feed::get_state()['backoff_until'] );
	}

	public function test_dedupe_per_advisory_id(): void {
		$this->save_allow_policy();
		Review_Due::put_stamps( array( 'acme/acme.php' => 1_700_000_000 ) );
		$body = $this->sign_envelope(
			$this->payload_with(
				array(
					'id'      => 'adv-once',
					'plugins' => array( 'acme/acme.php' ),
					'reason'  => 'repeat fetch',
					'severity'=> 'medium',
				)
			)
		);
		$this->stub_http( 200, $body );

		$first = Threat_Feed::run( 1_700_000_100 );
		$this->assertSame( 1, $first['applied'] );
		$this->assertCount( 1, self::$mails );

		$second = Threat_Feed::run( 1_700_000_200 );
		$this->assertSame( 0, $second['applied'] );
		$this->assertSame( 0, $second['alerted'] );
		$this->assertCount( 1, self::$mails );
		$this->assertSame( 'allow', Policy::get_policy()['plugins']['acme/acme.php'] );
	}

	public function test_observed_endpoint_marks_allow_rule(): void {
		Policy::save_policy(
			array(
				'plugins'         => array( 'acme/acme.php' => 'allow' ),
				'review_due_days' => 90,
				'default'         => 'observe',
				'log_enabled'     => true,
				'alert_email'     => 'admin@example.com',
			)
		);
		$GLOBALS['handl_aicac_test_plugins'] = $this->installed();
		Review_Due::put_stamps( array( 'acme/acme.php' => 1_700_000_000 ) );
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'plugin' => 'acme/acme.php',
					'host'   => 'api.evil.example',
					'model'  => 'evil-1',
				),
			),
			false
		);
		$body = $this->sign_envelope(
			$this->payload_with(
				array(
					'id'        => 'adv-host',
					'plugins'   => array(),
					'endpoints' => array( 'https://api.evil.example/v1' ),
					'models'    => array(),
					'reason'    => 'endpoint listed',
					'severity'  => 'high',
				)
			)
		);
		$this->stub_http( 200, $body );

		$stat = Threat_Feed::run( 1_700_000_100 );
		$this->assertSame( 1, $stat['applied'] );
		$this->assertSame( Threat_Feed::DUE_STAMP, Review_Due::get_stamps()['acme/acme.php'] );
		$this->assertSame( 'allow', Policy::get_policy()['plugins']['acme/acme.php'] );
	}

	public function test_deny_rule_is_not_stamped(): void {
		Policy::save_policy(
			array(
				'plugins'         => array( 'acme/acme.php' => 'deny' ),
				'review_due_days' => 90,
				'default'         => 'observe',
				'log_enabled'     => true,
				'alert_email'     => 'admin@example.com',
			)
		);
		$GLOBALS['handl_aicac_test_plugins'] = $this->installed();
		Review_Due::put_stamps( array( 'acme/acme.php' => 1_700_000_000 ) );
		$body = $this->sign_envelope(
			$this->payload_with(
				array(
					'id'      => 'adv-deny',
					'plugins' => array( 'acme' ),
					'reason'  => 'should not touch deny',
				)
			)
		);
		$this->stub_http( 200, $body );

		$stat = Threat_Feed::run( 1_700_000_100 );
		$this->assertSame( 0, $stat['applied'] );
		$this->assertSame( array(), self::$mails );
		$this->assertSame( 1_700_000_000, Review_Due::get_stamps()['acme/acme.php'] );
		$this->assertSame( 'deny', Policy::get_policy()['plugins']['acme/acme.php'] );
	}

	public function test_disabled_fetch_is_noop(): void {
		$this->save_allow_policy();
		Review_Due::put_stamps( array( 'acme/acme.php' => 1_700_000_000 ) );
		$called = false;
		$GLOBALS['handl_aicac_threat_feed_http'] = static function () use ( &$called ) {
			$called = true;
			return array(
				'response' => array( 'code' => 200 ),
				'body'     => '{}',
			);
		};
		$GLOBALS['handl_aicac_test_filters'][ Threat_Feed::FILTER_DISABLED ] = static function () {
			return true;
		};

		$stat = Threat_Feed::run( 1_700_000_100 );
		$this->assertSame( 'disabled', $stat['error'] );
		$this->assertFalse( $called );
		$this->assertSame( array(), self::$mails );
		$this->assertSame( 1_700_000_000, Review_Due::get_stamps()['acme/acme.php'] );
		$this->assertSame( 'disabled', Threat_Feed::get_state()['last_error'] );
	}
}
