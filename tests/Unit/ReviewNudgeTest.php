<?php
/**
 * AICAC-REVIEW-NUDGE (#325): value-anchored WP.org review ask.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Demo_Mode;
use HandL\AICAC\Plugin;
use HandL\AICAC\Review_Nudge;
use PHPUnit\Framework\TestCase;

final class ReviewNudgeTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		Review_Nudge::reset_for_tests();
		Demo_Mode::reset_for_tests();
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Review_Nudge::OPTION_KEY );
		delete_option( Demo_Mode::OPTION_KEY );
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$_GET['page'] = 'handl-aicac';
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_test_current_user_can'], $_GET['page'] );
		Review_Nudge::reset_for_tests();
		Demo_Mode::reset_for_tests();
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Review_Nudge::OPTION_KEY );
		delete_option( Demo_Mode::OPTION_KEY );
		parent::tearDown();
	}

	/**
	 * @param int $calls
	 * @param int $denies
	 * @return list<array<string,mixed>>
	 */
	private function seed_log( int $calls, int $denies ): array {
		$log = array();
		$ts  = 1_700_000_000;
		for ( $i = 0; $i < $calls; $i++ ) {
			$log[] = array(
				'ts'        => $ts + $i,
				'decision'  => 'allow',
				'plugin'    => 'seo/seo.php',
				'provider'  => 'openai',
				'operation' => 'text_generation',
			);
		}
		for ( $i = 0; $i < $denies; $i++ ) {
			$log[] = array(
				'ts'        => $ts + $calls + $i,
				'decision'  => 'deny',
				'plugin'    => 'seo/seo.php',
				'provider'  => 'openai',
				'operation' => 'text_generation',
			);
		}
		update_option( Plugin::LOG_OPTION_KEY, $log, false );

		return $log;
	}

	private function age_state( int $days_ago, ?int $now = null ): void {
		$now = null === $now ? 1_800_000_000 : $now;
		Review_Nudge::save_state(
			array(
				'activated_at' => $now - ( $days_ago * DAY_IN_SECONDS ),
			)
		);
	}

	public function test_value_counts_from_log_excluding_demo_and_selftest(): void {
		$log = $this->seed_log( 10, 5 );
		$log[] = array(
			'ts'       => 1_700_000_500,
			'decision' => 'deny',
			'plugin'   => 'demo-seo-writer/demo-seo-writer.php',
			'demo'     => true,
		);
		$log[] = array(
			'ts'        => 1_700_000_501,
			'decision'  => 'deny',
			'plugin'    => 'seo/seo.php',
			'channel'   => 'selftest',
			'selftest'  => true,
		);
		$log[] = array(
			'ts'       => 1_700_000_502,
			'decision' => 'deny',
			'plugin'   => 'seo/seo.php',
			'count'    => 3,
		);
		update_option( Plugin::LOG_OPTION_KEY, $log, false );

		$counts = Review_Nudge::value_counts();
		// 10 allow + 5 deny + 1 collapsed row (demo/selftest excluded).
		$this->assertSame( 16, $counts['calls'] );
		$this->assertSame( 8, $counts['denies'] ); // 5 + 3 collapsed
	}

	public function test_eligibility_requires_age_and_value(): void {
		$now = 1_800_000_000;
		$this->age_state( 10, $now );
		$this->seed_log( 600, 0 );
		$young = Review_Nudge::eligibility( $now );
		$this->assertFalse( $young['eligible'] );
		$this->assertSame( 'too_young', $young['reason'] );

		$this->age_state( 31, $now );
		$this->seed_log( 10, 5 );
		$low = Review_Nudge::eligibility( $now );
		$this->assertFalse( $low['eligible'] );
		$this->assertSame( 'low_value', $low['reason'] );

		$this->seed_log( 500, 0 );
		$ok_calls = Review_Nudge::eligibility( $now );
		$this->assertTrue( $ok_calls['eligible'] );
		$this->assertSame( 500, $ok_calls['calls'] );

		$this->seed_log( 10, 25 );
		$ok_denies = Review_Nudge::eligibility( $now );
		$this->assertTrue( $ok_denies['eligible'] );
		$this->assertSame( 25, $ok_denies['denies'] );
	}

	public function test_demo_mode_blocks_eligibility(): void {
		$now = 1_800_000_000;
		$this->age_state( 40, $now );
		$this->seed_log( 600, 0 );
		update_option(
			Demo_Mode::OPTION_KEY,
			array(
				'seeded_at' => $now,
			),
			false
		);
		$elig = Review_Nudge::eligibility( $now );
		$this->assertFalse( $elig['eligible'] );
		$this->assertSame( 'demo', $elig['reason'] );
	}

	public function test_hard_cap_two_asks_and_forever(): void {
		$now = 1_800_000_000;
		$this->age_state( 40, $now );
		$this->seed_log( 600, 0 );

		$first = Review_Nudge::mark_shown( $now );
		$this->assertTrue( $first['opened'] );
		$this->assertSame( 1, Review_Nudge::get_state()['ask_count'] );
		$this->assertTrue( Review_Nudge::get_state()['pending'] );

		Review_Nudge::snooze( $now );
		$this->assertFalse( Review_Nudge::get_state()['pending'] );
		$this->assertGreaterThan( $now, Review_Nudge::get_state()['snooze_until'] );

		$snoozed = Review_Nudge::eligibility( $now );
		$this->assertFalse( $snoozed['eligible'] );
		$this->assertSame( 'snoozed', $snoozed['reason'] );

		$after = $now + ( 31 * DAY_IN_SECONDS );
		$second = Review_Nudge::mark_shown( $after );
		$this->assertTrue( $second['opened'] );
		$this->assertSame( 2, Review_Nudge::get_state()['ask_count'] );

		Review_Nudge::snooze( $after );
		$capped = Review_Nudge::eligibility( $after + ( 31 * DAY_IN_SECONDS ) );
		$this->assertFalse( $capped['eligible'] );
		$this->assertSame( 'max_asks', $capped['reason'] );

		Review_Nudge::save_state(
			array_merge(
				Review_Nudge::get_state(),
				array(
					'ask_count'    => 0,
					'forever'      => false,
					'snooze_until' => 0,
					'pending'      => false,
				)
			)
		);
		Review_Nudge::forever();
		$done = Review_Nudge::eligibility( $after );
		$this->assertFalse( $done['eligible'] );
		$this->assertSame( 'forever', $done['reason'] );
	}

	public function test_render_outputs_value_line_and_actions(): void {
		$now = 1_800_000_000;
		$this->age_state( 40, $now );
		$this->seed_log( 512, 30 );

		// Freeze Clock-like now via pending eligibility path using mark + render.
		Review_Nudge::mark_shown( $now );

		ob_start();
		// should_render uses Clock::now(); seed state already pending + eligible thresholds in log.
		// Force eligibility by ensuring activated_at is old relative to real Clock::now().
		$state = Review_Nudge::get_state();
		$state['activated_at'] = time() - ( 40 * DAY_IN_SECONDS );
		$state['pending']      = true;
		$state['ask_count']    = 1;
		Review_Nudge::save_state( $state );

		Review_Nudge::instance()->maybe_render_notice();
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'handl-aicac-review-nudge', $html );
		$this->assertStringContainsString( 'Your saved Activity log shows', $html );
		$this->assertStringContainsString( 'calls blocked by AI Not', $html );
		$this->assertStringContainsString( 'Leave a review', $html );
		$this->assertStringContainsString( 'Maybe later', $html );
		$this->assertStringContainsString( 'Don&#039;t ask again', $html );
		$this->assertStringContainsString( Review_Nudge::REVIEW_URL, $html );
		$this->assertStringContainsString( Review_Nudge::ACTION_SNOOZE, $html );
		$this->assertStringContainsString( Review_Nudge::ACTION_FOREVER, $html );
	}

	public function test_should_not_render_off_aicac_screens(): void {
		$state = array(
			'activated_at' => time() - ( 40 * DAY_IN_SECONDS ),
			'ask_count'    => 0,
			'pending'      => false,
		);
		Review_Nudge::save_state( $state );
		$this->seed_log( 600, 0 );
		unset( $_GET['page'] );
		$this->assertFalse( Review_Nudge::should_render() );
	}
}
