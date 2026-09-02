<?php
/**
 * AICAC-REVIEW-DUE (#203).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Audit_Evidence;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Policy_Snapshots;
use HandL\AICAC\Review_Due;
use PHPUnit\Framework\TestCase;

final class ReviewDueTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		delete_option( Plugin::OPTION_KEY );
		delete_option( Review_Due::OPTION_KEY );
		delete_option( Policy_Snapshots::OPTION_KEY );
		delete_option( Policy_Snapshots::HISTORY_OPTION_KEY );
	}

	protected function tearDown(): void {
		delete_option( Plugin::OPTION_KEY );
		delete_option( Review_Due::OPTION_KEY );
		delete_option( Policy_Snapshots::OPTION_KEY );
		delete_option( Policy_Snapshots::HISTORY_OPTION_KEY );
		parent::tearDown();
	}

	public function test_fresh_install_shows_zero_due(): void {
		$snap = Review_Due::snapshot( array(), array(), 1_700_000_000 );
		$this->assertSame( 0, $snap['total'] );
		$this->assertSame( 0, $snap['due'] );
		$this->assertSame( 0, $snap['orphaned'] );
		$this->assertSame( array(), $snap['rows'] );
	}

	public function test_stamped_back_fixture_appears_and_confirm_clears_without_policy_change(): void {
		$now = 1_700_000_000;
		$old = $now - ( 120 * DAY_IN_SECONDS );
		$policy = array(
			'plugins'         => array( 'a/a.php' => 'deny' ),
			'review_due_days' => 90,
			'default'         => 'allow',
			'log_enabled'     => true,
		);
		Policy::save_policy( $policy );
		Review_Due::put_stamps( array( 'a/a.php' => $old ) );
		$saved = Policy::get_policy();
		$this->assertSame( 'deny', $saved['plugins']['a/a.php'] );

		$installed = array( 'a/a.php' => array( 'Name' => 'A' ) );
		$snap      = Review_Due::snapshot( $saved, $installed, $now );
		$this->assertSame( 1, $snap['due'] );
		$this->assertSame( 'a/a.php', $snap['rows'][0]['basename'] );
		$this->assertFalse( $snap['rows'][0]['orphaned'] );

		Review_Due::confirm( $saved, array( 'a/a.php' ), $now );

		$after = Policy::get_policy();
		$this->assertSame( 'deny', $after['plugins']['a/a.php'] );
		$snap2 = Review_Due::snapshot( $after, $installed, $now );
		$this->assertSame( 0, $snap2['due'] );
		$this->assertSame( 1, $snap2['confirmed'] );

		$history = Policy_Snapshots::history();
		$this->assertNotEmpty( $history );
		$joined = implode( ' ', $history[0]['changes'] ?? array() );
		$this->assertStringContainsString( 'a/a.php', $joined );
	}

	public function test_uninstalled_plugin_is_orphaned(): void {
		$policy = array(
			'plugins'         => array( 'gone/gone.php' => 'allow' ),
			'review_due_days' => 90,
		);
		Review_Due::put_stamps( array( 'gone/gone.php' => 1_700_000_000 ) );
		$snap = Review_Due::snapshot( $policy, array(), 1_700_000_000 );
		$this->assertSame( 1, $snap['orphaned'] );
		$this->assertTrue( $snap['rows'][0]['orphaned'] );
	}

	public function test_window_off_hides_stale_keeps_orphans(): void {
		$now = 1_700_000_000;
		$policy = array(
			'plugins' => array(
				'a/a.php'    => 'allow',
				'gone/g.php' => 'deny',
			),
			'review_due_days' => 0,
		);
		$installed = array( 'a/a.php' => array( 'Name' => 'A' ) );
		$snap      = Review_Due::snapshot( $policy, $installed, $now );
		$this->assertSame( 0, $snap['due'] );
		$this->assertSame( 1, $snap['orphaned'] );
		$this->assertSame( 'gone/g.php', $snap['rows'][0]['basename'] );
	}

	public function test_stamp_on_create_and_change(): void {
		$t1 = 1_700_000_000;
		$incoming = array(
			'plugins' => array( 'a/a.php' => 'allow' ),
		);
		Review_Due::stamp_on_rule_changes( $incoming, array(), $t1 );
		$this->assertSame( $t1, Review_Due::get_stamps()['a/a.php'] );

		$t2 = $t1 + 10;
		Review_Due::stamp_on_rule_changes(
			array( 'plugins' => array( 'a/a.php' => 'deny' ) ),
			array( 'plugins' => array( 'a/a.php' => 'allow' ) ),
			$t2
		);
		$this->assertSame( $t2, Review_Due::get_stamps()['a/a.php'] );

		$t3 = $t2 + 10;
		Review_Due::stamp_on_rule_changes(
			array( 'plugins' => array( 'a/a.php' => 'deny' ) ),
			array( 'plugins' => array( 'a/a.php' => 'deny' ) ),
			$t3
		);
		$this->assertSame( $t2, Review_Due::get_stamps()['a/a.php'] );
	}

	public function test_evidence_line_matches_snapshot_counts(): void {
		$now = 1_700_000_000;
		$policy = array(
			'plugins' => array(
				'a/a.php' => 'allow',
				'b/b.php' => 'deny',
			),
			'review_due_days' => 90,
		);
		Review_Due::put_stamps(
			array(
				'a/a.php' => $now,
				'b/b.php' => $now - ( 5 * DAY_IN_SECONDS ),
			)
		);
		$installed = array(
			'a/a.php' => array( 'Name' => 'A' ),
			'b/b.php' => array( 'Name' => 'B' ),
		);
		$snap = Review_Due::snapshot( $policy, $installed, $now );
		$this->assertSame( 2, $snap['confirmed'] );
		$line = Review_Due::evidence_line( $snap );
		$this->assertSame( '2 of 2 rules confirmed within 90 days.', $line );

		$data = Audit_Evidence::build_report_data( $policy, array(), '7d', $now, $installed );
		$this->assertSame( $line, $data['review_due_line'] ?? null );
	}

	public function test_confirm_does_not_touch_unselected_rule(): void {
		$now = 1_700_000_000;
		$policy = array(
			'plugins' => array(
				'a/a.php' => 'allow',
				'b/b.php' => 'deny',
			),
		);
		Review_Due::put_stamps(
			array(
				'a/a.php' => $now - ( 200 * DAY_IN_SECONDS ),
				'b/b.php' => $now - ( 200 * DAY_IN_SECONDS ),
			)
		);
		Review_Due::confirm( $policy, array( 'a/a.php' ), $now );
		$stamps = Review_Due::get_stamps();
		$this->assertSame( $now, $stamps['a/a.php'] );
		$this->assertSame( $now - ( 200 * DAY_IN_SECONDS ), $stamps['b/b.php'] );
		$this->assertSame( 'allow', $policy['plugins']['a/a.php'] );
		$this->assertSame( 'deny', $policy['plugins']['b/b.php'] );
	}
}
