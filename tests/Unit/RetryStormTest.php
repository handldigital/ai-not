<?php
/**
 * AICAC-RETRY-STORM (#240): collapse deny retry loops.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Alerts;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Retry_Storm;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';
require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php';

final class RetryStormTest extends TestCase {

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails = array();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		Retry_Storm::reset_state();
		$this->reset_alerts_deferred_state();
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
		Retry_Storm::reset_state();
		$this->reset_alerts_deferred_state();
		parent::tearDown();
	}

	private function reset_alerts_deferred_state(): void {
		$ref = new \ReflectionClass( Alerts::class );
		foreach ( array( 'deferred_immediate', 'deferred_digest_events' ) as $prop ) {
			$p = $ref->getProperty( $prop );
			$p->setAccessible( true );
			$p->setValue( null, array() );
		}
		$hooked = $ref->getProperty( 'flush_hooked' );
		$hooked->setAccessible( true );
		$hooked->setValue( null, false );
	}

	public function test_eight_denies_in_window_collapse_and_one_storm_alert(): void {
		$this->persist_policy(
			array(
				'alert_on_deny'              => true,
				'retry_storm_enabled'        => true,
				'retry_storm_window_seconds' => 30,
				'retry_storm_threshold'      => 5,
			)
		);

		$base = 1_700_000_000;
		for ( $i = 0; $i < 8; $i++ ) {
			$this->deny_and_notify( $base + $i, 'chatty/chatty.php', 'text_generation' );
		}

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $log );
		// 4 pass rows + 1 threshold/collapse row.
		$this->assertCount( 5, $log );

		$storm_rows = array_values(
			array_filter(
				$log,
				static function ( $row ) {
					return is_array( $row ) && ! empty( $row['retry_storm'] );
				}
			)
		);
		$this->assertCount( 1, $storm_rows );
		$this->assertSame( 4, (int) $storm_rows[0]['count'] ); // threshold + 3 collapses.

		$storm_mails = array_values(
			array_filter(
				self::$mails,
				static function ( array $m ) {
					return false !== strpos( $m['subject'], 'keeps retrying a blocked AI request' );
				}
			)
		);
		$this->assertCount( 1, $storm_mails );

		$deny_mails = array_values(
			array_filter(
				self::$mails,
				static function ( array $m ) {
					return false === strpos( $m['subject'], 'keeps retrying a blocked AI request' );
				}
			)
		);
		$this->assertCount( 4, $deny_mails );
	}

	public function test_window_expiry_starts_new_window(): void {
		$this->persist_policy(
			array(
				'alert_on_deny'              => true,
				'retry_storm_enabled'        => true,
				'retry_storm_window_seconds' => 10,
				'retry_storm_threshold'      => 5,
			)
		);

		$base = 1_700_000_000;
		for ( $i = 0; $i < 5; $i++ ) {
			$this->deny_and_notify( $base + $i, 'chatty/chatty.php', 'text_generation' );
		}
		$this->deny_and_notify( $base + 20, 'chatty/chatty.php', 'text_generation' );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $log );
		$this->assertCount( 6, $log );
		$last = $log[ count( $log ) - 1 ];
		$this->assertIsArray( $last );
		$this->assertArrayNotHasKey( 'retry_storm', $last );
	}

	public function test_off_switch_restores_per_deny_rows_and_alerts(): void {
		$this->persist_policy(
			array(
				'alert_on_deny'              => true,
				'retry_storm_enabled'        => false,
				'retry_storm_window_seconds' => 30,
				'retry_storm_threshold'      => 5,
			)
		);

		$base = 1_700_000_000;
		for ( $i = 0; $i < 8; $i++ ) {
			$this->deny_and_notify( $base + $i, 'chatty/chatty.php', 'text_generation' );
		}

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $log );
		$this->assertCount( 8, $log );
		$this->assertCount( 8, self::$mails );
		foreach ( $log as $row ) {
			$this->assertIsArray( $row );
			$this->assertArrayNotHasKey( 'retry_storm', $row );
		}
	}

	public function test_storm_alert_deduped_per_plugin_per_hour(): void {
		$this->persist_policy(
			array(
				'alert_on_deny'              => true,
				'retry_storm_enabled'        => true,
				'retry_storm_window_seconds' => 30,
				'retry_storm_threshold'      => 2,
			)
		);

		$base = 1_700_000_000;
		$this->deny_and_notify( $base, 'chatty/chatty.php', 'text_generation' );
		$this->deny_and_notify( $base + 1, 'chatty/chatty.php', 'text_generation' );
		$this->deny_and_notify( $base + 40, 'chatty/chatty.php', 'text_generation' );
		$this->deny_and_notify( $base + 41, 'chatty/chatty.php', 'text_generation' );

		$storm_mails = array_values(
			array_filter(
				self::$mails,
				static function ( array $m ) {
					return false !== strpos( $m['subject'], 'keeps retrying a blocked AI request' );
				}
			)
		);
		$this->assertCount( 1, $storm_mails );
	}

	/**
	 * @param array<string,mixed> $extra
	 * @return array<string,mixed>
	 */
	private function persist_policy( array $extra = array() ): array {
		$policy = array_merge(
			array(
				'default'       => 'deny',
				'log_enabled'   => true,
				'alert_on_deny' => true,
				'alert_email'   => 'admin@example.com',
				'alert_mode'    => 'immediate',
			),
			$extra
		);
		update_option( Plugin::OPTION_KEY, $policy, false );
		return Policy::get_policy();
	}

	private function deny_and_notify( int $ts, string $plugin, string $family ): void {
		$policy = Policy::get_policy();
		$event  = array(
			'ts'                => $ts,
			'plugin'            => $plugin,
			'decision'          => 'deny',
			'would_decision'    => 'deny',
			'capability_family' => $family,
			'operation'         => 'generate_text',
			'denial_reason'     => 'default',
		);
		Policy::append_log_event( $event );
		if ( ! Retry_Storm::should_suppress_deny_alert( $event, $policy ) ) {
			Alerts::maybe_notify_denial( $event, $policy );
		}
		Alerts::flush_deferred();
	}
}
