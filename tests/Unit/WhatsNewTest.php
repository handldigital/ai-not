<?php
/**
 * AICAC-WHATS-NEW: version bump notice + highlights.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Whats_New;
use PHPUnit\Framework\TestCase;

final class WhatsNewTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']  = array();
		$GLOBALS['handl_aicac_test_user_meta'] = array();
		$GLOBALS['handl_aicac_test_user_id']   = 7;
		delete_option( Whats_New::OPTION_KEY );
		delete_option( Whats_New::ANNOUNCE_OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
	}

	protected function tearDown(): void {
		delete_option( Whats_New::OPTION_KEY );
		delete_option( Whats_New::ANNOUNCE_OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		$GLOBALS['handl_aicac_test_user_meta'] = array();
		unset( $GLOBALS['handl_aicac_test_user_id'] );
		parent::tearDown();
	}

	public function test_fresh_install_seeds_without_announcement(): void {
		// No policy option → fresh.
		$announce = Whats_New::detect_version_bump( '1.6.0', true );
		$this->assertSame( '', $announce );
		$this->assertSame( '1.6.0', get_option( Whats_New::OPTION_KEY ) );
		$this->assertSame( '', Whats_New::get_announce_version() );
		$this->assertFalse( Whats_New::should_show_notice_for_user( 7 ) );
	}

	public function test_upgrade_to_new_version_announces_once_per_user(): void {
		update_option( Plugin::OPTION_KEY, array( 'log_enabled' => true ), false );
		update_option( Whats_New::OPTION_KEY, '1.5.0', false );

		$announce = Whats_New::detect_version_bump( '1.6.0', false );
		$this->assertSame( '1.6.0', $announce );
		$this->assertSame( '1.6.0', get_option( Whats_New::OPTION_KEY ) );
		$this->assertTrue( Whats_New::should_show_notice_for_user( 7 ) );

		Whats_New::dismiss_for_user( 7, '1.6.0' );
		$this->assertFalse( Whats_New::should_show_notice_for_user( 7 ) );

		// Another admin still sees it.
		$this->assertTrue( Whats_New::should_show_notice_for_user( 8 ) );
	}

	public function test_existing_site_first_meeting_feature_announces_current(): void {
		update_option( Plugin::OPTION_KEY, array( 'log_enabled' => true ), false );
		// No seen-version option yet.
		$announce = Whats_New::detect_version_bump( '1.6.0', false );
		$this->assertSame( '1.6.0', $announce );
		$this->assertTrue( Whats_New::should_show_notice_for_user( 7 ) );
	}

	public function test_same_version_does_not_reannounce(): void {
		update_option( Whats_New::OPTION_KEY, '1.6.0', false );
		update_option( Whats_New::ANNOUNCE_OPTION_KEY, '1.6.0', false );
		Whats_New::dismiss_for_user( 7, '1.6.0' );

		$announce = Whats_New::detect_version_bump( '1.6.0', false );
		$this->assertSame( '1.6.0', $announce );
		$this->assertFalse( Whats_New::should_show_notice_for_user( 7 ) );
	}

	public function test_highlights_fallback_empty_for_unknown_version(): void {
		$this->assertSame( array(), Whats_New::highlights_for_version( '9.9.9' ) );
		$this->assertNotEmpty( Whats_New::highlights_for_version( '1.6.0' ) );
		$this->assertLessThanOrEqual( 5, count( Whats_New::highlights_for_version( '1.6.0' ) ) );
		$this->assertNotEmpty( Whats_New::highlights_for_version( '1.5.0' ) );
		$this->assertLessThanOrEqual( 5, count( Whats_New::highlights_for_version( '1.5.0' ) ) );
	}

	public function test_opening_panel_dismisses_for_user(): void {
		update_option( Whats_New::OPTION_KEY, '1.5.0', false );
		Whats_New::detect_version_bump( '1.6.0', false );
		$this->assertTrue( Whats_New::should_show_notice_for_user( 7 ) );
		Whats_New::dismiss_for_user( 7, '1.6.0' );
		$this->assertSame( '1.6.0', Whats_New::get_user_dismissed_version( 7 ) );
		$this->assertFalse( Whats_New::should_show_notice_for_user( 7 ) );
	}
}
