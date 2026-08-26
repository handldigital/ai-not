<?php
/**
 * AICAC-PII-WARN (#230): payload PII screen — patterns, modes, no-leak.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Snooze;
use HandL\AICAC\Pii_Warn;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Quiet_Hours;
use PHPUnit\Framework\TestCase;

final class PiiWarnTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Alert_Snooze::OPTION_KEY );
		update_option( 'admin_email', 'admin@example.com' );
		$GLOBALS['handl_aicac_test_plugins'] = array(
			'acme/acme.php' => array(
				'Name'    => 'Acme AI',
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
		delete_option( Alert_Snooze::OPTION_KEY );
		parent::tearDown();
	}

	public function test_off_by_default_zero_overhead_shape(): void {
		$policy = array( 'plugins' => array( 'acme/acme.php' => 'allow' ) );
		$this->assertSame( Pii_Warn::MODE_OFF, Pii_Warn::mode_for_plugin( $policy, 'acme/acme.php' ) );
		$this->assertSame( Pii_Warn::MODE_OFF, Pii_Warn::mode_for_plugin( $policy, null ) );
	}

	public function test_screen_email_phone_card_national_id(): void {
		// Visa test PAN that passes Luhn.
		$text = "Contact user@example.com or +1 (415) 555-2671. Card 4111 1111 1111 1111 SSN 078-05-1120.";
		$hits = Pii_Warn::screen( $text );
		$this->assertSame( 1, $hits['email'] ?? 0 );
		$this->assertSame( 1, $hits['phone'] ?? 0 );
		$this->assertSame( 1, $hits['card'] ?? 0 );
		$this->assertSame( 1, $hits['national_id'] ?? 0 );
	}

	public function test_card_requires_luhn(): void {
		$bad = Pii_Warn::screen( 'Card 4111 1111 1111 1112 is invalid.' );
		$this->assertArrayNotHasKey( 'card', $bad );
		$this->assertTrue( Pii_Warn::luhn_ok( '4111111111111111' ) );
		$this->assertFalse( Pii_Warn::luhn_ok( '4111111111111112' ) );
	}

	public function test_pattern_filter_limits_types(): void {
		$text = 'user@example.com and 4111111111111111';
		$hits = Pii_Warn::screen( $text, array( Pii_Warn::PATTERN_EMAIL ) );
		$this->assertSame( array( 'email' => 1 ), $hits );
	}

	public function test_redact_never_leaves_matched_text(): void {
		$raw = 'Email user@example.com card 4111111111111111 phone 415-555-2671 ssn 078-05-1120';
		$out = Pii_Warn::redact( $raw );
		$this->assertStringNotContainsString( 'user@example.com', $out );
		$this->assertStringNotContainsString( '4111111111111111', $out );
		$this->assertStringNotContainsString( '415-555-2671', $out );
		$this->assertStringNotContainsString( '078-05-1120', $out );
		$this->assertStringContainsString( '[redacted-email]', $out );
		$this->assertStringContainsString( '[redacted-card]', $out );
	}

	public function test_apply_to_event_warn_allows_and_tags(): void {
		$policy = array(
			'pii_screen' => array( 'acme/acme.php' => 'warn' ),
		);
		$event  = array(
			'plugin'         => 'acme/acme.php',
			'decision'       => 'allow',
			'prompt_preview' => 'Send to user@example.com please',
		);
		$result = Pii_Warn::apply_to_event( $event, $policy, null );
		$this->assertTrue( $result['active'] );
		$this->assertFalse( $result['prevent'] );
		$this->assertSame( 'warn', $result['mode'] );
		$this->assertSame( 1, $result['matches']['email'] ?? 0 );
		$this->assertSame( 'allow', $event['decision'] );
		$this->assertSame( 'warn', $event['pii_match']['mode'] );
		$this->assertStringNotContainsString( 'user@example.com', (string) $event['prompt_preview'] );
	}

	public function test_apply_to_event_deny_sets_reason_pii(): void {
		$policy = array(
			'pii_screen' => array( 'acme/acme.php' => 'deny' ),
		);
		$event  = array(
			'plugin'         => 'acme/acme.php',
			'decision'       => 'allow',
			'prompt_preview' => 'SSN 078-05-1120',
		);
		$result = Pii_Warn::apply_to_event( $event, $policy, null );
		$this->assertTrue( $result['prevent'] );
		$this->assertSame( 'deny', $result['mode'] );
		$this->assertArrayHasKey( 'pii_match', $event );
		$this->assertSame( 'deny', $event['pii_match']['mode'] );
		$this->assertStringNotContainsString( '078-05-1120', (string) $event['prompt_preview'] );
		$json = wp_json_encode( $event );
		$this->assertIsString( $json );
		$this->assertStringNotContainsString( '078-05-1120', (string) $json );
	}

	public function test_warn_alert_respects_snooze_and_quiet_hours(): void {
		$policy = array(
			'alert_email'  => 'admin@example.com',
			'pii_screen'   => array( 'acme/acme.php' => 'warn' ),
			'quiet_hours'  => array(
				array(
					'id'    => 'night',
					'name'  => 'Night',
					'days'  => array( 0, 1, 2, 3, 4, 5, 6 ),
					'start' => '00:00',
					'end'   => '00:00',
					'mode'  => 'observe',
				),
			),
		);
		$event  = array(
			'ts'        => 1_700_000_000,
			'plugin'    => 'acme/acme.php',
			'decision'  => 'allow',
			'pii_match' => array(
				'mode'  => 'warn',
				'types' => array( 'email' => 1 ),
			),
		);

		$qh = Pii_Warn::maybe_alert( $event, $policy );
		$this->assertSame( 'quiet_hours', $qh['reason'] );
		$this->assertCount( 0, self::$mails );

		// Outside quiet hours + snoozed.
		$policy['quiet_hours'] = array();
		Alert_Snooze::set( 'acme/acme.php', '1h', 1_700_000_000 );
		$snoozed = Pii_Warn::maybe_alert( $event, $policy );
		$this->assertSame( 'suppressed', $snoozed['reason'] );
		$this->assertCount( 0, self::$mails );
	}

	public function test_warn_alert_body_has_types_not_matched_text(): void {
		$policy = array(
			'alert_email' => 'admin@example.com',
			'pii_screen'  => array( 'acme/acme.php' => 'warn' ),
		);
		$event  = array(
			'ts'             => 1_700_000_000,
			'plugin'         => 'acme/acme.php',
			'decision'       => 'allow',
			'prompt_preview' => '[redacted-email]',
			'pii_match'      => array(
				'mode'  => 'warn',
				'types' => array( 'email' => 2, 'card' => 1 ),
			),
		);
		$hit = Pii_Warn::maybe_alert( $event, $policy );
		$this->assertTrue( $hit['alerted'] );
		$this->assertCount( 1, self::$mails );
		$body    = self::$mails[0]['message'];
		$subject = self::$mails[0]['subject'];
		$this->assertStringContainsString( 'Possible personal information sent to AI by', $subject );
		$this->assertStringContainsString( 'found possible personal information in a request sent to an AI provider.', $body );
		$this->assertStringContainsString( 'Result: Allowed and logged', $body );
		$this->assertStringContainsString( 'Possible information found (counts only; HandL does not save or email the matching text):', $body );
		$this->assertStringContainsString( 'Email address: 2', $body );
		$this->assertStringContainsString( 'Payment card number: 1', $body );
		$this->assertStringContainsString( 'To block future requests like this, set this plugin’s personal information policy to Deny.', $body );
		$this->assertStringNotContainsString( 'Mode: warn', $body );
		$this->assertStringNotContainsString( 'national_id', $body );
		$this->assertStringNotContainsString( 'user@', $body );
		$this->assertStringNotContainsString( '4111', $body );
		$this->assertSame( 'Personal information detected', \HandL\AICAC\Policy_Simulator::reason_label( 'pii' ) );
	}

	public function test_append_log_event_fires_warn_alert_without_leaking(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
				'alert_email' => 'admin@example.com',
				'pii_screen'  => array( 'acme/acme.php' => 'warn' ),
			),
			false
		);

		$event = array(
			'ts'             => 1_700_000_000,
			'plugin'         => 'acme/acme.php',
			'decision'       => 'allow',
			'prompt_preview' => '[redacted-email]',
			'pii_match'      => array(
				'mode'  => 'warn',
				'types' => array( 'email' => 1 ),
			),
		);
		Policy::append_log_event( $event );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		$this->assertIsArray( $log );
		$this->assertNotEmpty( $log );
		$row = $log[ count( $log ) - 1 ];
		$this->assertSame( array( 'email' => 1 ), $row['pii_match']['types'] );
		$encoded = wp_json_encode( $log );
		$this->assertStringNotContainsString( 'user@example.com', (string) $encoded );
		$this->assertCount( 1, self::$mails );
	}

	public function test_sanitize_plugin_modes_drops_off(): void {
		$map = Pii_Warn::sanitize_plugin_modes(
			array(
				'acme/acme.php'   => 'warn',
				'other/other.php' => 'off',
				'bad'             => 'deny',
				''                => 'warn',
			)
		);
		$this->assertSame( array( 'acme/acme.php' => 'warn' ), $map );
	}
}
