<?php
/**
 * AICAC-NOTIFY-ROUTING (#194): shared recipient helper + upgrade parity.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alert_Routing;
use HandL\AICAC\Alerts;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class AlertRoutingTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		delete_option( Plugin::OPTION_KEY );
		update_option( 'admin_email', 'admin@example.com' );
	}

	public function test_upgrade_parity_empty_routing_matches_alerts_resolve(): void {
		$policy = array(
			'alert_email'   => 'ops@example.com',
			'alert_routing' => array(),
		);

		foreach ( Alert_Routing::TYPES as $type ) {
			$this->assertSame(
				Alerts::resolve_email( $policy ),
				Alert_Routing::resolve_email( $policy, $type ),
				'type=' . $type
			);
		}
	}

	public function test_upgrade_parity_missing_routing_falls_back_to_admin_email(): void {
		$policy = array( 'alert_email' => '' );
		$this->assertSame( 'admin@example.com', Alerts::resolve_email( $policy ) );
		$this->assertSame( 'admin@example.com', Alert_Routing::resolve_email( $policy, 'budget' ) );
	}

	public function test_typed_override_does_not_change_other_types(): void {
		$policy = array(
			'alert_email'   => 'ops@example.com',
			'alert_routing' => array(
				'budget' => 'billing@example.com',
				'drift'  => 'security@example.com, security+tag@example.com',
			),
		);

		$this->assertSame( 'billing@example.com', Alert_Routing::resolve_email( $policy, 'budget' ) );
		$this->assertSame(
			'security@example.com, security+tag@example.com',
			Alert_Routing::resolve_email( $policy, 'drift' )
		);
		$this->assertSame( 'ops@example.com', Alert_Routing::resolve_email( $policy, 'anomaly' ) );
		$this->assertSame( 'ops@example.com', Alerts::resolve_email( $policy ) );
	}

	public function test_sanitize_routing_drops_invalid_and_unknown_types(): void {
		$clean = Alert_Routing::sanitize_routing(
			array(
				'budget'   => 'ok@example.com, not-an-email, ok@example.com',
				'nope'     => 'x@example.com',
				'anomaly'  => '  ',
				'shadow'   => array( 'a@example.com', 'bad', 'a@example.com' ),
			)
		);

		$this->assertSame(
			array(
				'budget' => 'ok@example.com',
				'shadow' => 'a@example.com',
			),
			$clean
		);
	}

	public function test_validate_routing_input_rejects_invalid_with_plain_error(): void {
		$result = Alert_Routing::validate_routing_input(
			array(
				'budget' => 'billing@example.com, totally-broken',
			)
		);

		$this->assertFalse( $result['ok'] );
		$this->assertSame( array(), $result['routing'] );
		$this->assertStringContainsString( 'totally-broken', $result['error'] );
		$this->assertStringContainsString( 'not a valid email', $result['error'] );
	}

	public function test_validate_routing_input_accepts_plus_addressing(): void {
		$result = Alert_Routing::validate_routing_input(
			array(
				'expiry' => 'haktan+aicac-expiry@handldigital.com',
			)
		);

		$this->assertTrue( $result['ok'] );
		$this->assertSame(
			array( 'expiry' => 'haktan+aicac-expiry@handldigital.com' ),
			$result['routing']
		);
	}

	public function test_policy_get_sanitizes_alert_routing(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'alert_email'   => 'ops@example.com',
				'alert_routing' => array(
					'digest' => 'owner@example.com; junk',
					'bogus'  => 'x@example.com',
				),
			)
		);

		$policy = Policy::get_policy();
		$this->assertSame(
			array( 'digest' => 'owner@example.com' ),
			$policy['alert_routing']
		);
	}

	public function test_webhook_failure_alias_normalizes(): void {
		$policy = array(
			'alert_email'   => 'ops@example.com',
			'alert_routing' => array(
				'webhook_failure' => 'hooks@example.com',
			),
		);
		// Stored underscore form is accepted via sanitize_type alias on resolve path
		// only after sanitize_routing — underscore key is remapped.
		$policy['alert_routing'] = Alert_Routing::sanitize_routing( $policy['alert_routing'] );
		$this->assertSame( 'hooks@example.com', Alert_Routing::resolve_email( $policy, 'webhook-failure' ) );
	}
}
