<?php
/**
 * AICAC-DEAD-RULES (#290).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Dead_Rules;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Policy_Snapshots;
use HandL\AICAC\Review_Due;
use PHPUnit\Framework\TestCase;

final class DeadRulesTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Dead_Rules::MATCHED_OPTION_KEY );
		delete_option( Dead_Rules::ALLOW_SINCE_OPTION_KEY );
		delete_option( Review_Due::OPTION_KEY );
		delete_option( Policy_Snapshots::OPTION_KEY );
		delete_option( Policy_Snapshots::HISTORY_OPTION_KEY );
		delete_option( Dead_Rules::SCAN_TRANSIENT_KEY );
	}

	protected function tearDown(): void {
		delete_option( Plugin::OPTION_KEY );
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Dead_Rules::MATCHED_OPTION_KEY );
		delete_option( Dead_Rules::ALLOW_SINCE_OPTION_KEY );
		delete_option( Review_Due::OPTION_KEY );
		delete_option( Policy_Snapshots::OPTION_KEY );
		delete_option( Policy_Snapshots::HISTORY_OPTION_KEY );
		delete_option( Dead_Rules::SCAN_TRANSIENT_KEY );
		parent::tearDown();
	}

	public function test_observe_stamps_matched_allow_only(): void {
		$policy = array(
			'plugins'     => array(
				'live/live.php' => 'allow',
				'deny/deny.php' => 'deny',
			),
			'default'     => 'observe',
			'log_enabled' => true,
		);
		Policy::save_policy( $policy );
		$saved = Policy::get_policy();

		$now = 1_700_000_000;
		$r1  = Dead_Rules::observe(
			array(
				'ts'       => $now,
				'plugin'   => 'live/live.php',
				'decision' => 'allow',
			),
			$saved
		);
		$this->assertTrue( $r1['stamped'] );
		$this->assertSame( $now, Dead_Rules::get_matched()['live/live.php'] );

		$r2 = Dead_Rules::observe(
			array(
				'ts'       => $now + 10,
				'plugin'   => 'deny/deny.php',
				'decision' => 'deny',
			),
			$saved
		);
		$this->assertFalse( $r2['stamped'] );
		$this->assertArrayNotHasKey( 'deny/deny.php', Dead_Rules::get_matched() );

		$r3 = Dead_Rules::observe(
			array(
				'ts'       => $now + 20,
				'plugin'   => 'other/other.php',
				'decision' => 'allow',
			),
			$saved
		);
		$this->assertFalse( $r3['stamped'] );
		$this->assertSame( 'no_allow_rule', $r3['reason'] );
	}

	public function test_absent_stamp_older_than_window_is_flagged_deny_never(): void {
		$now = 1_700_000_000;
		$old = $now - ( 90 * DAY_IN_SECONDS );
		$policy = array(
			'plugins'         => array(
				'old/old.php'   => 'allow',
				'deny/deny.php' => 'deny',
				'new/new.php'   => 'allow',
			),
			'dead_rules_days' => 60,
			'default'         => 'observe',
			'log_enabled'     => true,
		);
		Policy::save_policy( $policy );

		Dead_Rules::put_allow_since(
			array(
				'old/old.php' => $old,
				'new/new.php' => $now - ( 10 * DAY_IN_SECONDS ),
			)
		);
		Dead_Rules::put_matched( array() );

		$snap = Dead_Rules::snapshot( Policy::get_policy(), $now );
		$this->assertSame( 2, $snap['total'] );
		$this->assertSame( 1, $snap['flagged'] );
		$this->assertSame( 'old/old.php', $snap['rows'][0]['basename'] );
		$this->assertSame( 0, $snap['rows'][0]['last_matched'] );
		$this->assertFalse( Dead_Rules::is_flagged( 'deny/deny.php', Policy::get_policy(), $now ) );
		$this->assertFalse( Dead_Rules::is_flagged( 'new/new.php', Policy::get_policy(), $now ) );
	}

	public function test_stale_last_matched_is_flagged_fresh_is_not(): void {
		$now = 1_700_000_000;
		$policy = array(
			'plugins'         => array(
				'stale/s.php' => 'allow',
				'fresh/f.php' => 'allow',
			),
			'dead_rules_days' => 60,
			'default'         => 'observe',
			'log_enabled'     => true,
		);
		Policy::save_policy( $policy );
		Dead_Rules::put_allow_since(
			array(
				'stale/s.php' => $now - ( 200 * DAY_IN_SECONDS ),
				'fresh/f.php' => $now - ( 200 * DAY_IN_SECONDS ),
			)
		);
		Dead_Rules::put_matched(
			array(
				'stale/s.php' => $now - ( 70 * DAY_IN_SECONDS ),
				'fresh/f.php' => $now - ( 5 * DAY_IN_SECONDS ),
			)
		);

		$flagged = Dead_Rules::flagged_basenames( Policy::get_policy(), $now );
		$this->assertSame( array( 'stale/s.php' ), $flagged );
	}

	public function test_window_off_flags_nothing(): void {
		$now = 1_700_000_000;
		$policy = array(
			'plugins'         => array( 'a/a.php' => 'allow' ),
			'dead_rules_days' => 0,
			'default'         => 'observe',
			'log_enabled'     => true,
		);
		Policy::save_policy( $policy );
		Dead_Rules::put_allow_since( array( 'a/a.php' => $now - ( 400 * DAY_IN_SECONDS ) ) );
		$snap = Dead_Rules::snapshot( Policy::get_policy(), $now );
		$this->assertSame( 0, $snap['flagged'] );
		$this->assertSame( 0, $snap['days'] );
	}

	public function test_retire_snapshots_and_undo_restores_byte_identical_allow(): void {
		$policy = array(
			'plugins'     => array(
				'keep/keep.php' => 'allow',
				'die/die.php'   => 'allow',
			),
			'default'     => 'observe',
			'log_enabled' => true,
		);
		Policy::save_policy( $policy );
		$before = Policy::get_policy();
		$this->assertSame( 'allow', $before['plugins']['die/die.php'] );

		Dead_Rules::put_matched( array( 'die/die.php' => 1_600_000_000 ) );
		Dead_Rules::put_allow_since( array( 'die/die.php' => 1_500_000_000 ) );

		$result = Dead_Rules::retire( 'die/die.php' );
		$this->assertTrue( $result['ok'] );
		$this->assertSame( 'retired', $result['status'] );

		$after = Policy::get_policy();
		$this->assertArrayNotHasKey( 'die/die.php', $after['plugins'] );
		$this->assertSame( 'allow', $after['plugins']['keep/keep.php'] );
		$this->assertArrayNotHasKey( 'die/die.php', Dead_Rules::get_matched() );

		$undo = Dead_Rules::undo_retire();
		$this->assertTrue( $undo['ok'] );
		$this->assertSame( 'restored', $undo['status'] );

		$restored = Policy::get_policy();
		$this->assertSame( 'allow', $restored['plugins']['die/die.php'] );
		$this->assertSame( 'allow', $restored['plugins']['keep/keep.php'] );
		// Rule map restored; stamps may reseed via stamp_on_rule_changes on restore write.
		$this->assertSame( $before['plugins']['die/die.php'], $restored['plugins']['die/die.php'] );
	}

	public function test_retire_rejects_deny_and_missing(): void {
		Policy::save_policy(
			array(
				'plugins'     => array( 'deny/deny.php' => 'deny' ),
				'default'     => 'observe',
				'log_enabled' => true,
			)
		);
		$r1 = Dead_Rules::retire( 'deny/deny.php' );
		$this->assertFalse( $r1['ok'] );
		$this->assertSame( 'not_allow', $r1['error'] );

		$r2 = Dead_Rules::retire( 'gone/gone.php' );
		$this->assertFalse( $r2['ok'] );
		$this->assertSame( 'not_allow', $r2['error'] );
	}

	public function test_no_auto_retire_from_snapshot_or_scan(): void {
		$now = 1_700_000_000;
		Policy::save_policy(
			array(
				'plugins'         => array( 'old/old.php' => 'allow' ),
				'dead_rules_days' => 60,
				'default'         => 'observe',
				'log_enabled'     => true,
			)
		);
		Dead_Rules::put_allow_since( array( 'old/old.php' => $now - ( 120 * DAY_IN_SECONDS ) ) );

		Dead_Rules::snapshot( Policy::get_policy(), $now );
		Dead_Rules::scan_activity(
			array(
				array(
					'ts'       => $now - ( 200 * DAY_IN_SECONDS ),
					'plugin'   => 'old/old.php',
					'decision' => 'allow',
				),
			),
			Policy::get_policy(),
			$now
		);

		$policy = Policy::get_policy();
		$this->assertSame( 'allow', $policy['plugins']['old/old.php'] );
	}

	public function test_scan_activity_seeds_last_matched(): void {
		Policy::save_policy(
			array(
				'plugins'     => array( 'a/a.php' => 'allow' ),
				'default'     => 'observe',
				'log_enabled' => true,
			)
		);
		$stat = Dead_Rules::scan_activity(
			array(
				array(
					'ts'       => 1_700_000_100,
					'plugin'   => 'a/a.php',
					'decision' => 'allow',
				),
				array(
					'ts'       => 1_700_000_050,
					'plugin'   => 'a/a.php',
					'decision' => 'allow',
				),
			),
			Policy::get_policy()
		);
		$this->assertSame( 1, $stat['updated'] );
		$this->assertSame( 1_700_000_100, Dead_Rules::get_matched()['a/a.php'] );
	}

	public function test_stamp_on_rule_changes_sets_allow_since_clears_on_deny(): void {
		$now = 1_700_000_000;
		Dead_Rules::stamp_on_rule_changes(
			array( 'plugins' => array( 'a/a.php' => 'allow' ) ),
			array( 'plugins' => array() ),
			$now
		);
		$this->assertSame( $now, Dead_Rules::get_allow_since()['a/a.php'] );

		Dead_Rules::put_matched( array( 'a/a.php' => $now - 10 ) );
		Dead_Rules::stamp_on_rule_changes(
			array( 'plugins' => array( 'a/a.php' => 'deny' ) ),
			array( 'plugins' => array( 'a/a.php' => 'allow' ) ),
			$now + 5
		);
		$this->assertArrayNotHasKey( 'a/a.php', Dead_Rules::get_allow_since() );
		$this->assertArrayNotHasKey( 'a/a.php', Dead_Rules::get_matched() );
	}

	public function test_status_for_chip_label(): void {
		$now = 1_700_000_000;
		$policy = array(
			'plugins'         => array( 'a/a.php' => 'allow' ),
			'dead_rules_days' => 60,
		);
		Dead_Rules::put_allow_since( array( 'a/a.php' => $now - ( 90 * DAY_IN_SECONDS ) ) );
		$status = Dead_Rules::status_for( 'a/a.php', $policy, $now );
		$this->assertTrue( $status['flagged'] );
		$this->assertSame( 'No recorded matches in 60 days', $status['label'] );
	}

	public function test_retire_history_uses_removed_allow_copy(): void {
		Policy::save_policy(
			array(
				'plugins'     => array( 'die/die.php' => 'allow' ),
				'default'     => 'observe',
				'log_enabled' => true,
			)
		);
		Dead_Rules::retire( 'die/die.php' );
		$history = Policy_Snapshots::history();
		$found   = false;
		foreach ( $history as $row ) {
			if ( 'Removed Allow rule (die/die.php)' === (string) ( $row['summary'] ?? '' ) ) {
				$found = true;
				$this->assertSame( array( 'Removed Allow rule (die/die.php)' ), $row['changes'] );
			}
		}
		$this->assertTrue( $found );
	}

	public function test_cmd_list_notices_avoid_false_all_clear(): void {
		$this->assertSame( 'Unused-rule checks are off.', Dead_Rules::cmd_list_empty_notice( 0 ) );
		$this->assertSame( 'No Allow rules flagged for review.', Dead_Rules::cmd_list_empty_notice( 60 ) );
		$this->assertSame( 'not recorded', Dead_Rules::cmd_list_last_matched_label( 0 ) );
		$this->assertSame( '1700000000', Dead_Rules::cmd_list_last_matched_label( 1_700_000_000 ) );
	}

	public function test_list_rows_shape_for_cli(): void {
		$now = 1_700_000_000;
		Policy::save_policy(
			array(
				'plugins'         => array( 'a/a.php' => 'allow' ),
				'dead_rules_days' => 60,
				'default'         => 'observe',
				'log_enabled'     => true,
			)
		);
		Dead_Rules::put_allow_since( array( 'a/a.php' => $now - ( 90 * DAY_IN_SECONDS ) ) );
		$snap = Dead_Rules::snapshot( Policy::get_policy(), $now );
		$this->assertSame( 1, Dead_Rules::inbox_count( $snap ) );
		$this->assertSame( 'a/a.php', $snap['rows'][0]['basename'] );
	}
}
