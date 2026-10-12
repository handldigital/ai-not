<?php
/**
 * AICAC-VISITOR (#373).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Cost;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Rate_Cap;
use HandL\AICAC\Visitor;
use PHPUnit\Framework\TestCase;

final class VisitorTest extends TestCase {

	private const TEST_IP = '203.0.113.77';

	private const TEST_UA = 'Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0';

	/** 2026-09-22 10:30:00 UTC. */
	private const NOW = 1_790_073_000;

	/** @var list<array{to:string,subject:string,message:string}> */
	private static array $mails = array();

	protected function setUp(): void {
		parent::setUp();
		self::$mails                                  = array();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_user_id']          = 0;
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		unset( $GLOBALS['handl_aicac_test_filters'] );
		Visitor::reset_for_tests();
		Visitor::set_test_identity( self::TEST_IP, self::TEST_UA );
		putenv( 'HANDL_AICAC_TEST_NOW=' . (string) self::NOW );
		update_option( 'admin_email', 'admin@example.com' );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
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
		putenv( 'HANDL_AICAC_TEST_NOW' );
		unset(
			$GLOBALS['handl_aicac_wp_mail'],
			$GLOBALS['handl_aicac_test_filters'],
			$GLOBALS['handl_aicac_test_current_user_can'],
			$_SERVER['HTTP_X_FORWARDED_FOR'],
			$_SERVER['HTTP_CF_CONNECTING_IP']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		$GLOBALS['handl_aicac_test_user_id'] = 0;
		Visitor::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * @param array<string,mixed> $extra Extra settings.
	 */
	private function enable( array $extra = array() ): void {
		Visitor::save_settings(
			array_merge(
				array(
					'enabled'         => true,
					'block_anonymous' => false,
					'cap_hour'        => null,
					'cap_day'         => null,
				),
				$extra
			)
		);
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private function log_rows(): array {
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );

		return is_array( $log ) ? array_values( $log ) : array();
	}

	public function test_defaults_are_off_and_save_defaults_deletes_option(): void {
		$this->assertSame(
			array(
				'enabled'         => false,
				'block_anonymous' => false,
				'cap_hour'        => null,
				'cap_day'         => null,
			),
			Visitor::get_settings()
		);
		$this->assertFalse( Visitor::is_enabled() );

		$this->enable( array( 'cap_hour' => 5 ) );
		$this->assertNotFalse( get_option( Visitor::SETTINGS_OPTION, false ) );
		$this->assertTrue( Visitor::is_enabled() );

		Visitor::save_settings( Visitor::defaults() );
		$this->assertFalse( get_option( Visitor::SETTINGS_OPTION, false ) );
		$this->assertFalse( Visitor::is_enabled() );
	}

	public function test_enabled_without_any_limit_is_inert(): void {
		$this->enable();
		$this->assertFalse( Visitor::is_enabled() );
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertSame( array(), Visitor::get_counts_map() );
	}

	public function test_sanitize_cap_empty_and_zero_are_unlimited(): void {
		$this->assertNull( Visitor::sanitize_cap( '' ) );
		$this->assertNull( Visitor::sanitize_cap( 0 ) );
		$this->assertNull( Visitor::sanitize_cap( '-3' ) );
		$this->assertNull( Visitor::sanitize_cap( 'abc' ) );
		$this->assertSame( 10, Visitor::sanitize_cap( '10' ) );
		$this->assertSame( Visitor::MAX_CAP, Visitor::sanitize_cap( Visitor::MAX_CAP + 5 ) );
	}

	public function test_disabled_never_prevents(): void {
		Visitor::save_settings(
			array(
				'enabled'         => false,
				'block_anonymous' => true,
				'cap_hour'        => 1,
			)
		);
		$this->assertFalse( Visitor::is_enabled() );
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertSame( array(), $this->log_rows() );
	}

	public function test_logged_in_user_is_exempt(): void {
		$this->enable(
			array(
				'block_anonymous' => true,
				'cap_hour'        => 1,
			)
		);
		$GLOBALS['handl_aicac_test_user_id'] = 12;

		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertSame( array(), Visitor::get_counts_map() );
		$this->assertSame( array(), $this->log_rows() );
	}

	public function test_block_all_denies_anonymous_without_counting(): void {
		$this->enable( array( 'block_anonymous' => true ) );
		$this->assertTrue( Visitor::is_enabled() );

		$this->assertTrue( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );

		$rows = $this->log_rows();
		$this->assertCount( 1, $rows );
		$last = $rows[0];
		$this->assertSame( 'deny', $last['decision'] ?? '' );
		$this->assertSame( Visitor::REASON_BLOCK_ALL, $last['denial_reason'] ?? '' );
		$this->assertSame( Visitor::REASON_BLOCK_ALL, $last['decision_source'] ?? '' );
		$this->assertSame( 0, $last['user_id'] ?? null );
		$this->assertTrue( $last['visitor'] ?? false );
		$this->assertTrue( $last['visitor_block_all'] ?? false );
		$this->assertSame( Visitor::CHANNEL, $last['channel'] ?? '' );
		$this->assertSame( Visitor::bucket_hash( self::NOW ), $last['visitor_bucket'] ?? '' );

		$this->assertSame( array(), Visitor::get_counts_map() );
		$stats = Visitor::get_stats_map();
		$this->assertSame( 1, $stats[ Visitor::bucket_hash( self::NOW ) ]['denies'] );
	}

	public function test_under_cap_allows_and_increments(): void {
		$this->enable(
			array(
				'cap_hour' => 3,
				'cap_day'  => 10,
			)
		);
		$bucket = Visitor::bucket_hash( self::NOW );
		$hour   = Rate_Cap::window_bounds( Rate_Cap::WINDOW_HOUR, self::NOW );
		$day    = Rate_Cap::window_bounds( Rate_Cap::WINDOW_DAY, self::NOW );

		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );

		$this->assertSame( 2, Visitor::get_window_count( $bucket, Visitor::WINDOW_HOUR, $hour['key'] ) );
		$this->assertSame( 2, Visitor::get_window_count( $bucket, Visitor::WINDOW_DAY, $day['key'] ) );
		$this->assertSame( 2, Visitor::get_stats_map()[ $bucket ]['calls'] );
		$this->assertSame( array(), $this->log_rows(), 'Allowed calls are logged elsewhere, not by the visitor gate.' );
	}

	public function test_at_cap_denies_visitor_limit_and_does_not_inflate_counter(): void {
		$this->enable( array( 'cap_hour' => 2 ) );
		$bucket = Visitor::bucket_hash( self::NOW );
		$hour   = Rate_Cap::window_bounds( Rate_Cap::WINDOW_HOUR, self::NOW );

		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertTrue( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertTrue( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );

		$this->assertSame( 2, Visitor::get_window_count( $bucket, Visitor::WINDOW_HOUR, $hour['key'] ) );

		$rows = $this->log_rows();
		$deny = array_values(
			array_filter(
				$rows,
				static function ( $r ): bool {
					return 'deny' === ( $r['decision'] ?? '' );
				}
			)
		);
		$this->assertNotEmpty( $deny );
		$last = $deny[ count( $deny ) - 1 ];
		$this->assertSame( Visitor::REASON, $last['denial_reason'] ?? '' );
		$this->assertSame( Visitor::REASON, $last['decision_source'] ?? '' );
		$this->assertFalse( $last['visitor_block_all'] ?? true );
		$this->assertSame( 'hour', $last['visitor_window'] ?? '' );
		$this->assertSame( 2, $last['visitor_limit'] ?? null );
		$this->assertSame( 2, $last['visitor_count'] ?? null );
		$this->assertSame( 2, $last['visitor_hour_limit'] ?? null );
		$this->assertSame( 2, $last['visitor_hour_count'] ?? null );
		$this->assertArrayHasKey( 'visitor_day_limit', $last );
		$this->assertNull( $last['visitor_day_limit'] );

		$stats = Visitor::get_stats_map()[ $bucket ];
		$this->assertSame( 2, $stats['calls'] );
		$this->assertSame( 2, $stats['denies'] );
	}

	public function test_day_cap_denies_even_when_hour_has_room(): void {
		$this->enable(
			array(
				'cap_hour' => 100,
				'cap_day'  => 1,
			)
		);
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertTrue( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );

		$rows = $this->log_rows();
		$this->assertSame( 'day', $rows[ count( $rows ) - 1 ]['visitor_window'] ?? '' );
	}

	public function test_counters_are_per_bucket(): void {
		$this->enable( array( 'cap_hour' => 1 ) );

		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertTrue( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );

		Visitor::set_test_identity( '198.51.100.5', self::TEST_UA );
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ), 'A different visitor has its own budget.' );
		$this->assertCount( 2, Visitor::roster() );
	}

	public function test_hour_window_rolls_over(): void {
		$this->enable( array( 'cap_hour' => 1 ) );
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertTrue( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );

		putenv( 'HANDL_AICAC_TEST_NOW=' . (string) ( self::NOW + 3600 ) );
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
	}

	public function test_prior_prevent_is_unchanged(): void {
		$this->enable( array( 'cap_hour' => 5 ) );
		$this->assertTrue( Visitor::maybe_prevent_prompt( true, new \stdClass() ) );
		$this->assertSame( array(), Visitor::get_counts_map(), 'A prior deny must not consume visitor budget.' );
		$this->assertSame( array(), $this->log_rows() );
	}

	public function test_audit_only_skips(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => true,
			)
		);
		$this->enable(
			array(
				'block_anonymous' => true,
				'cap_hour'        => 1,
			)
		);
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertSame( array(), Visitor::get_counts_map() );
	}

	public function test_deny_reclassifies_the_matching_allow_row(): void {
		$this->enable( array( 'block_anonymous' => true ) );
		$bucket = Visitor::bucket_hash( self::NOW );

		Policy::append_log_event(
			array(
				'ts'       => self::NOW,
				'decision' => 'allow',
				'user_id'  => 0,
			)
		);
		$this->assertCount( 1, $this->log_rows() );

		$this->assertTrue( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$rows = $this->log_rows();
		$this->assertCount( 1, $rows );
		$this->assertSame( 'deny', $rows[0]['decision'] ?? '' );

		// An allow row that belongs to another visitor bucket is left alone.
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
		Policy::append_log_event(
			array(
				'ts'             => self::NOW,
				'decision'       => 'allow',
				'user_id'        => 0,
				'visitor_bucket' => str_repeat( 'a', 16 ),
			)
		);
		$this->assertNotSame( str_repeat( 'a', 16 ), $bucket );
		$this->assertTrue( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$decisions = array_map(
			static function ( $r ) {
				return (string) ( $r['decision'] ?? '' );
			},
			$this->log_rows()
		);
		$this->assertSame( array( 'allow', 'deny' ), $decisions );
	}

	public function test_bucket_hash_is_stable_within_a_day(): void {
		$a = Visitor::bucket_hash( self::NOW );
		$b = Visitor::bucket_hash( self::NOW + 3 * 3600 );
		$this->assertSame( $a, $b );
		$this->assertMatchesRegularExpression( '/^[a-f0-9]{16}$/', $a );

		$other_ip = Visitor::bucket_hash( self::NOW, '198.51.100.9', self::TEST_UA );
		$this->assertNotSame( $a, $other_ip );

		$bot = Visitor::bucket_hash( self::NOW, self::TEST_IP, 'curl/8.0' );
		$this->assertNotSame( $a, $bot );
	}

	public function test_bucket_hash_changes_when_the_daily_salt_rotates(): void {
		$day_one = Visitor::bucket_hash();
		$salt_1  = get_option( Visitor::SALT_OPTION );
		$this->assertIsArray( $salt_1 );

		putenv( 'HANDL_AICAC_TEST_NOW=' . (string) ( self::NOW + 86400 ) );
		$day_two = Visitor::bucket_hash();
		$salt_2  = get_option( Visitor::SALT_OPTION );

		$this->assertNotSame( $salt_1['day_key'], $salt_2['day_key'] );
		$this->assertNotSame( $salt_1['salt'], $salt_2['salt'] );
		$this->assertNotSame( $day_one, $day_two );
		$this->assertSame( 64, strlen( (string) $salt_2['salt'] ) );
	}

	public function test_daily_salt_can_be_pinned_by_tests(): void {
		$GLOBALS['handl_aicac_test_visitor_salt'] = 'pinned-salt';
		$this->assertSame( 'pinned-salt', Visitor::daily_salt( self::NOW ) );
		$expected = substr( hash_hmac( 'sha256', self::TEST_IP . '|mozilla', 'pinned-salt' ), 0, 16 );
		$this->assertSame( $expected, Visitor::bucket_hash( self::NOW ) );
	}

	public function test_raw_ip_is_never_stored(): void {
		$this->enable(
			array(
				'cap_hour' => 2,
				'cap_day'  => 5,
			)
		);
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'       => 'allow',
				'log_enabled'   => true,
				'audit_only'    => false,
				'alert_on_deny' => true,
				'alert_email'   => 'ops@example.com',
			)
		);
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertTrue( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );

		$this->assertStringNotContainsString( self::TEST_IP, (string) wp_json_encode( $GLOBALS['handl_aicac_test_options'] ) );
		foreach ( array( Visitor::SETTINGS_OPTION, Visitor::SALT_OPTION, Visitor::COUNTS_OPTION, Visitor::STATS_OPTION, Visitor::WARNED_OPTION, Plugin::LOG_OPTION_KEY ) as $key ) {
			$this->assertStringNotContainsString( self::TEST_IP, (string) wp_json_encode( get_option( $key, array() ) ), $key );
		}
		$this->assertStringNotContainsString( self::TEST_IP, Visitor::csv_for_roster() );
		foreach ( self::$mails as $mail ) {
			$this->assertStringNotContainsString( self::TEST_IP, $mail['message'] );
		}
	}

	public function test_ip_header_is_filterable(): void {
		unset( $GLOBALS['handl_aicac_test_visitor_ip'], $GLOBALS['handl_aicac_test_visitor_ua'] );
		$_SERVER['REMOTE_ADDR']          = '10.0.0.1';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.9, 10.0.0.1';
		$_SERVER['HTTP_USER_AGENT']      = self::TEST_UA;

		$this->assertSame( '10.0.0.1', Visitor::resolve_client_ip() );

		$GLOBALS['handl_aicac_test_filters'][ Visitor::FILTER_IP_HEADER ] = static function ( $header ) {
			return 'HTTP_X_FORWARDED_FOR';
		};
		$this->assertSame( '203.0.113.9', Visitor::resolve_client_ip() );

		$via_header = Visitor::bucket_hash( self::NOW );
		$direct     = Visitor::bucket_hash( self::NOW, '203.0.113.9', self::TEST_UA );
		$this->assertSame( $direct, $via_header );

		// Missing / garbage header name falls back to REMOTE_ADDR.
		$GLOBALS['handl_aicac_test_filters'][ Visitor::FILTER_IP_HEADER ] = static function ( $header ) {
			return 'HTTP_NOT_SET';
		};
		$this->assertSame( '10.0.0.1', Visitor::resolve_client_ip() );

		unset( $_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT'] );
		unset( $GLOBALS['handl_aicac_test_filters'] );
		$this->assertSame( '0.0.0.0', Visitor::resolve_client_ip() );
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
	}

	public function test_ua_family(): void {
		$this->assertSame( 'mozilla', Visitor::ua_family( 'Mozilla/5.0 (Windows NT 10.0)' ) );
		$this->assertSame( 'bot', Visitor::ua_family( 'Googlebot/2.1 (+http://www.google.com/bot.html)' ) );
		$this->assertSame( 'bot', Visitor::ua_family( 'curl/8.4.0' ) );
		$this->assertSame( 'bot', Visitor::ua_family( 'python-requests/2.31' ) );
		$this->assertSame( 'bot', Visitor::ua_family( 'Wget/1.21' ) );
		$this->assertSame( 'unknown', Visitor::ua_family( '' ) );
		$this->assertSame( 'unknown', Visitor::ua_family( '   ' ) );
		$this->assertSame( 'okhttp', Visitor::ua_family( 'okhttp 4.9' ) );
	}

	public function test_soft_warn_fires_once_per_window(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'       => 'allow',
				'log_enabled'   => true,
				'audit_only'    => false,
				'alert_on_deny' => true,
				'alert_email'   => 'ops@example.com',
			)
		);
		$this->enable( array( 'cap_hour' => 10 ) );
		$bucket = Visitor::bucket_hash( self::NOW );
		$hour   = Rate_Cap::window_bounds( Rate_Cap::WINDOW_HOUR, self::NOW );
		// Soft threshold for 10 is 8; seed 6 so call 7 stays quiet and call 8 crosses 80%.
		Visitor::set_window_count( $bucket, Visitor::WINDOW_HOUR, $hour['key'], 6 );

		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertCount( 0, self::$mails );

		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertCount( 1, self::$mails );
		$this->assertSame( 'ops@example.com', self::$mails[0]['to'] );
		$this->assertStringContainsString( 'Usage: 8 of 10 calls', self::$mails[0]['message'] );
		$this->assertStringContainsString( $bucket, self::$mails[0]['message'] );

		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertCount( 1, self::$mails, 'Soft-warn is once per bucket + window.' );

		$warned = Visitor::get_warned_map();
		$this->assertArrayHasKey( $bucket . '|hour|' . $hour['key'], $warned );

		$warn_rows = array_values(
			array_filter(
				$this->log_rows(),
				static function ( $r ): bool {
					return Visitor::CHANNEL_WARN === ( $r['channel'] ?? '' );
				}
			)
		);
		$this->assertCount( 1, $warn_rows );
		$this->assertSame( 10, $warn_rows[0]['visitor_limit'] ?? null );
		$this->assertSame( 8, $warn_rows[0]['visitor_count'] ?? null );
	}

	public function test_soft_warn_without_alert_setting_sends_no_mail_but_still_audits(): void {
		$this->enable( array( 'cap_hour' => 5 ) );
		$bucket = Visitor::bucket_hash( self::NOW );
		$hour   = Rate_Cap::window_bounds( Rate_Cap::WINDOW_HOUR, self::NOW );
		Visitor::set_window_count( $bucket, Visitor::WINDOW_HOUR, $hour['key'], 3 );

		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertCount( 0, self::$mails );
		$this->assertCount( 1, Visitor::get_warned_map() );
	}

	public function test_roster_and_csv_headers(): void {
		$this->enable( array( 'cap_hour' => 2 ) );
		$bucket = Visitor::bucket_hash( self::NOW );

		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertTrue( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );

		Visitor::set_test_identity( '198.51.100.20', self::TEST_UA );
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );

		$rows = Visitor::roster();
		$this->assertCount( 2, $rows );
		$this->assertSame( $bucket, $rows[0]['bucket'], 'Busiest visitor sorts first.' );
		$this->assertSame( 2, $rows[0]['calls'] );
		$this->assertSame( 2, $rows[0]['hour_count'] );
		$this->assertSame( 2, $rows[0]['day_count'] );
		$this->assertSame( 2, $rows[0]['hour_limit'] );
		$this->assertNull( $rows[0]['day_limit'] );
		$this->assertSame( 1, $rows[0]['denies'] );
		$this->assertSame( self::NOW, $rows[0]['last_ts'] );
		$this->assertSame( 1, $rows[1]['calls'] );

		$this->assertCount( 2, Visitor::roster( Visitor::WINDOW_HOUR ) );

		$csv   = Visitor::csv_for_roster();
		$lines = explode( "\n", trim( $csv ) );
		$this->assertSame(
			'bucket,calls,hour_count,day_count,hour_limit,day_limit,denies,input_tokens,output_tokens,est_usd,last_ts,last_provider',
			$lines[0]
		);
		$this->assertCount( 3, $lines );
		$this->assertStringStartsWith( $bucket . ',2,2,2,2,,1,', $lines[1] );
	}

	public function test_roster_drops_buckets_outside_the_window(): void {
		$this->enable( array( 'cap_hour' => 5 ) );
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertCount( 1, Visitor::roster() );

		putenv( 'HANDL_AICAC_TEST_NOW=' . (string) ( self::NOW + 2 * 86400 ) );
		$this->assertSame( array(), Visitor::roster() );
	}

	public function test_estimated_cost_uses_cost_rates_for_seeded_tokens(): void {
		$this->enable( array( 'cap_hour' => 5 ) );
		$bucket = Visitor::bucket_hash( self::NOW );
		update_option(
			Visitor::STATS_OPTION,
			array(
				$bucket => array(
					'calls'         => 3,
					'denies'        => 0,
					'input_tokens'  => 2000000,
					'output_tokens' => 1000000,
					'est_usd'       => 0,
					'last_ts'       => self::NOW,
					'last_provider' => '',
				),
			),
			false
		);

		$policy   = Policy::get_policy();
		$expected = Cost::estimate_usd( 2000000, 1000000, Cost::rates_from_policy( $policy, null ) );
		$this->assertNotNull( $expected );
		$this->assertGreaterThan( 0.0, $expected );

		$rows = Visitor::roster();
		$this->assertCount( 1, $rows );
		$this->assertEqualsWithDelta( (float) $expected, $rows[0]['est_usd'], 0.000001 );
		$this->assertSame( 2000000, $rows[0]['input_tokens'] );

		$csv = Visitor::csv_for_roster();
		$this->assertStringContainsString( number_format( (float) $expected, 6, '.', '' ), $csv );
	}

	public function test_touch_stats_accumulates_tokens_and_cost(): void {
		$bucket = Visitor::bucket_hash( self::NOW );
		Visitor::touch_stats(
			$bucket,
			array(
				'provider'      => 'openai',
				'input_tokens'  => 1000000,
				'output_tokens' => 500000,
			),
			self::NOW
		);
		Visitor::touch_stats( $bucket, array( 'input_tokens' => 1000000 ), self::NOW + 1 );

		$row = Visitor::get_stats_map()[ $bucket ];
		$this->assertSame( 2, $row['calls'] );
		$this->assertSame( 2000000, $row['input_tokens'] );
		$this->assertSame( 500000, $row['output_tokens'] );
		$this->assertSame( 'openai', $row['last_provider'] );
		$this->assertSame( self::NOW + 1, $row['last_ts'] );

		$rates = Cost::rates_from_policy( Policy::get_policy(), 'openai' );
		$this->assertEqualsWithDelta(
			(float) Cost::estimate_usd( 1000000, 500000, $rates ) + (float) Cost::estimate_usd( 1000000, 0, $rates ),
			$row['est_usd'],
			0.000001
		);
	}

	public function test_reset_bucket_and_reset_all(): void {
		$this->enable( array( 'cap_hour' => 5 ) );
		$bucket = Visitor::bucket_hash( self::NOW );
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		Visitor::set_test_identity( '198.51.100.30', self::TEST_UA );
		$this->assertFalse( Visitor::maybe_prevent_prompt( false, new \stdClass() ) );
		$this->assertCount( 2, Visitor::roster() );

		$this->assertTrue( Visitor::reset_bucket( $bucket ) );
		$rows = Visitor::roster();
		$this->assertCount( 1, $rows );
		$this->assertNotSame( $bucket, $rows[0]['bucket'] );
		$this->assertFalse( Visitor::reset_bucket( 'not a bucket!' ) );

		Visitor::reset_all();
		$this->assertSame( array(), Visitor::roster() );
		$this->assertFalse( get_option( Visitor::COUNTS_OPTION, false ) );
		$this->assertFalse( get_option( Visitor::STATS_OPTION, false ) );
	}

	public function test_counts_map_prunes_stale_windows_when_large(): void {
		$bucket = Visitor::bucket_hash( self::NOW );
		$hour   = Rate_Cap::window_bounds( Rate_Cap::WINDOW_HOUR, self::NOW );
		$map    = array();
		for ( $i = 0; $i < 520; $i++ ) {
			$map[ sprintf( '%016x', $i ) . '|hour|2020010100' ] = 1;
		}
		$map[ Visitor::count_key( $bucket, Visitor::WINDOW_HOUR, $hour['key'] ) ] = 4;
		Visitor::save_counts_map( $map, self::NOW );

		$stored = Visitor::get_counts_map();
		$this->assertCount( 1, $stored );
		$this->assertSame( 4, Visitor::get_window_count( $bucket, Visitor::WINDOW_HOUR, $hour['key'] ) );
	}

	public function test_stats_map_is_capped_to_most_recent(): void {
		$map = array();
		for ( $i = 0; $i < Visitor::STATS_CAP + 20; $i++ ) {
			$map[ sprintf( '%016x', $i ) ] = array(
				'calls'   => 1,
				'last_ts' => 1000 + $i,
			);
		}
		Visitor::save_stats_map( $map );

		$stored = Visitor::get_stats_map();
		$this->assertCount( Visitor::STATS_CAP, $stored );
		$this->assertArrayHasKey( sprintf( '%016x', Visitor::STATS_CAP + 19 ), $stored );
		$this->assertArrayNotHasKey( sprintf( '%016x', 0 ), $stored );
	}
}
