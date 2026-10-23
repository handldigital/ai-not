<?php
/**
 * AICAC-DIVIDEND (#442).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Dividend;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class DividendTest extends TestCase {

	private const NOW = 1792165053;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		unset(
			$GLOBALS['handl_aicac_test_dividend_ua'],
			$GLOBALS['handl_aicac_test_dividend_referrer'],
			$GLOBALS['handl_aicac_test_dividend_utm'],
			$GLOBALS['handl_aicac_test_dividend_path']
		);
		Dividend::reset_for_tests();
		Dividend::set_test_now( self::NOW );
		Dividend::set_test_frontend( true );
	}

	protected function tearDown(): void {
		unset(
			$GLOBALS['handl_aicac_test_dividend_ua'],
			$GLOBALS['handl_aicac_test_dividend_referrer'],
			$GLOBALS['handl_aicac_test_dividend_utm'],
			$GLOBALS['handl_aicac_test_dividend_path']
		);
		$GLOBALS['handl_aicac_test_options'] = array();
		Dividend::reset_for_tests();
		parent::tearDown();
	}

	public function test_perplexity_referrer_increments_unrelated_byte_identical(): void {
		$GLOBALS['handl_aicac_test_dividend_ua']       = 'Mozilla/5.0 (Macintosh; Intel Mac OS X)';
		$GLOBALS['handl_aicac_test_dividend_referrer'] = 'https://www.perplexity.ai/search?q=test';
		$GLOBALS['handl_aicac_test_dividend_path']     = '/pricing';
		Dividend::maybe_observe();

		$ledger = Dividend::get_ledger();
		$this->assertArrayHasKey( 'perplexity', $ledger['sources'] );
		$this->assertSame( 1, (int) $ledger['sources']['perplexity']['hits'] );
		$week = Dividend::week_key( self::NOW );
		$this->assertSame( 1, (int) $ledger['weeks'][ $week ]['perplexity'] );

		$serialized = get_option( Dividend::LEDGER_OPTION, null );

		$GLOBALS['handl_aicac_test_dividend_referrer'] = 'https://example.com/page';
		$GLOBALS['handl_aicac_test_dividend_path']     = '/other';
		Dividend::maybe_observe();
		$this->assertSame( $serialized, get_option( Dividend::LEDGER_OPTION, null ) );
	}

	public function test_landing_and_ledger_caps(): void {
		$src = array(
			'id'    => 'chatgpt',
			'label' => 'ChatGPT',
			'hosts' => array( 'chatgpt.com' ),
			'utm'   => array(),
		);
		for ( $i = 0; $i < 40; $i++ ) {
			Dividend::record_hit( $src, '/land/' . $i, self::NOW + $i );
		}
		$row = Dividend::get_ledger()['sources']['chatgpt'];
		$this->assertLessThanOrEqual( Dividend::MAX_LANDINGS_PER_SOURCE, count( $row['landings'] ) );
		$this->assertSame( 40, (int) $row['hits'] );
		$this->assertSame( Dividend::MAX_SOURCES, 40 );
		$this->assertSame( Dividend::MAX_WEEK_BUCKETS, 26 );
	}

	public function test_give_vs_get_soft_read_and_absent(): void {
		$this->assertNull( Dividend::give_vs_get() );

		update_option(
			Dividend::BOTWATCH_LEDGER_OPTION,
			array(
				'bots' => array(
					'gptbot' => array(
						'hits' => 12,
					),
				),
			),
			false
		);

		$src = array(
			'id'    => 'claude',
			'label' => 'Claude',
			'hosts' => array( 'claude.ai' ),
			'utm'   => array(),
		);
		Dividend::record_hit( $src, '/', self::NOW );
		$gvg = Dividend::give_vs_get();
		$this->assertIsArray( $gvg );
		$this->assertSame( 12, (int) $gvg['crawl_hits'] );
		$this->assertSame( 1, (int) $gvg['referral_hits'] );

		$snap = Dividend::snapshot();
		$this->assertNotNull( $snap['give_vs_get'] );

		delete_option( Dividend::BOTWATCH_LEDGER_OPTION );
		$this->assertNull( Dividend::give_vs_get() );
	}

	public function test_noop_save_and_crawler_ua_excluded(): void {
		$this->assertTrue( Dividend::is_enabled() );
		$this->assertFalse( (bool) get_option( Dividend::SETTINGS_OPTION, false ) );

		Dividend::save_settings( array( 'enabled' => false ) );
		$stored = get_option( Dividend::SETTINGS_OPTION, null );
		Dividend::save_settings( array( 'enabled' => false ) );
		$this->assertSame( $stored, get_option( Dividend::SETTINGS_OPTION, null ) );

		Dividend::save_settings( Dividend::defaults() );
		$this->assertFalse( (bool) get_option( Dividend::SETTINGS_OPTION, false ) );

		Dividend::save_settings( array( 'enabled' => true ) ); // still defaults → delete
		$this->assertTrue( Dividend::is_enabled() );

		$GLOBALS['handl_aicac_test_dividend_ua']       = 'Mozilla/5.0 (compatible; GPTBot/1.0)';
		$GLOBALS['handl_aicac_test_dividend_referrer'] = 'https://www.perplexity.ai/';
		$GLOBALS['handl_aicac_test_dividend_path']     = '/';
		Dividend::maybe_observe();
		$this->assertFalse( (bool) get_option( Dividend::LEDGER_OPTION, false ) );
	}
}
