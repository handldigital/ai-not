<?php
/**
 * Unit tests for AICAC-READONLY-SHARE (#268).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Share;
use PHPUnit\Framework\TestCase;

final class ShareTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		Share::reset_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		update_option( Plugin::OPTION_KEY, array( 'log_enabled' => true ), false );
	}

	protected function tearDown(): void {
		Share::reset_for_tests();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		parent::tearDown();
	}

	public function test_create_stores_hash_not_plaintext(): void {
		$made = Share::create( Share::TTL_7D, 1_700_000_000 );
		$this->assertTrue( $made['ok'] );
		$this->assertStringContainsString( 'handl_aicac_share=', $made['url'] );
		$stored = get_option( Share::OPTION_KEY, array() );
		$this->assertIsArray( $stored );
		$this->assertArrayHasKey( $made['hash'], $stored );
		$this->assertStringNotContainsString( $made['hash'], $made['url'] );
		foreach ( $stored as $hash => $row ) {
			$this->assertSame( 64, strlen( (string) $hash ) );
			$this->assertArrayNotHasKey( 'token', $row );
			$this->assertArrayNotHasKey( 'plain', $row );
		}
	}

	public function test_lookup_accepts_plaintext_and_rejects_hash(): void {
		$made  = Share::create( Share::TTL_24H, 1_700_000_000 );
		$query = parse_url( $made['url'], PHP_URL_QUERY );
		parse_str( (string) $query, $params );
		$plain = (string) ( $params[ Share::QUERY_VAR ] ?? '' );
		$this->assertSame( 32, strlen( $plain ) );

		$hit = Share::lookup( $plain, 1_700_000_000 );
		$this->assertNotNull( $hit );
		$this->assertSame( $made['hash'], $hit['hash'] );

		$this->assertNull( Share::lookup( $made['hash'], 1_700_000_000 ) );
		$this->assertTrue( Share::hash_is_not_a_token( $made['hash'] ) );
	}

	public function test_expired_and_revoked_are_gone(): void {
		$made  = Share::create( Share::TTL_24H, 1_700_000_000 );
		$query = parse_url( $made['url'], PHP_URL_QUERY );
		parse_str( (string) $query, $params );
		$plain = (string) $params[ Share::QUERY_VAR ];

		$this->assertNull( Share::lookup( $plain, 1_700_000_000 + DAY_IN_SECONDS + 1 ) );

		$made2 = Share::create( Share::TTL_7D, 1_700_000_000 );
		parse_str( (string) parse_url( $made2['url'], PHP_URL_QUERY ), $p2 );
		$plain2 = (string) $p2[ Share::QUERY_VAR ];
		$this->assertTrue( Share::revoke( $made2['hash'], 1_700_000_001 ) );
		$this->assertNull( Share::lookup( $plain2, 1_700_000_002 ) );
	}

	public function test_views_rate_limit_one_log_row_per_hour(): void {
		$made  = Share::create( Share::TTL_7D, 1_700_000_000 );
		$query = parse_url( $made['url'], PHP_URL_QUERY );
		parse_str( (string) $query, $params );
		$plain = (string) $params[ Share::QUERY_VAR ];
		$row   = Share::lookup( $plain, 1_700_000_000 );
		$this->assertNotNull( $row );

		Share::record_view( $row['hash'], 1_700_000_010 );
		Share::record_view( $row['hash'], 1_700_000_020 );
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$views = 0;
		foreach ( is_array( $log ) ? $log : array() as $event ) {
			if ( is_array( $event ) && 'view' === ( $event['share_action'] ?? '' ) ) {
				++$views;
			}
		}
		$this->assertSame( 1, $views );

		Share::record_view( $row['hash'], 1_700_000_010 + HOUR_IN_SECONDS );
		$log2 = get_option( Plugin::LOG_OPTION_KEY, array() );
		$views2 = 0;
		foreach ( is_array( $log2 ) ? $log2 : array() as $event ) {
			if ( is_array( $event ) && 'view' === ( $event['share_action'] ?? '' ) ) {
				++$views2;
			}
		}
		$this->assertSame( 2, $views2 );
	}

	public function test_create_and_revoke_write_activity_rows(): void {
		$made = Share::create( Share::TTL_7D, 1_700_000_000 );
		Share::revoke( $made['hash'], 1_700_000_001 );
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$actions = array();
		foreach ( is_array( $log ) ? $log : array() as $event ) {
			if ( is_array( $event ) && isset( $event['share_action'] ) ) {
				$actions[] = (string) $event['share_action'];
			}
		}
		$this->assertContains( 'create', $actions );
		$this->assertContains( 'revoke', $actions );
	}

	public function test_summary_is_counts_only_without_plugin_basenames(): void {
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
				'plugins'     => array(
					'acme/acme.php'   => 'allow',
					'blocked/b.php'   => 'deny',
					'skip/skip.php'   => 'inherit',
				),
			),
			false
		);
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'       => 1_700_000_000,
					'plugin'   => 'acme/acme.php',
					'decision' => 'allow',
					'provider' => 'openai',
				),
				array(
					'ts'       => 1_700_000_000,
					'plugin'   => 'blocked/b.php',
					'decision' => 'deny',
					'provider' => 'openai',
				),
			),
			false
		);

		$sum = Share::summary( 1_700_000_000 );
		$this->assertSame( 1, $sum['allowed'] );
		$this->assertSame( 1, $sum['denied'] );
		$this->assertSame( 2, $sum['calls_7d'] );
		$this->assertSame( 1, $sum['denies_7d'] );
		$html = Share::page_html( $sum );
		$this->assertStringNotContainsString( 'acme/acme.php', $html );
		$this->assertStringNotContainsString( 'blocked/b.php', $html );
		$this->assertStringContainsString( 'noindex', $html );
		$this->assertArrayHasKey( 'X-Robots-Tag', Share::page_headers() );
	}

	public function test_plugin_php_requires_share(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-share.php', $src );
		$this->assertStringContainsString( 'Share::instance()->init()', $src );
	}
}
