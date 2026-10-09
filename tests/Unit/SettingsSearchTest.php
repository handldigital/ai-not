<?php
/**
 * Unit tests for AICAC-FIND (#198) settings search index.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Admin;
use HandL\AICAC\Settings_Search;
use PHPUnit\Framework\TestCase;

final class SettingsSearchTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		Settings_Search::reset_for_tests();
	}

	protected function tearDown(): void {
		Settings_Search::reset_for_tests();
		parent::tearDown();
	}

	public function test_index_covers_every_registered_entry(): void {
		$registered = Settings_Search::registered();
		$this->assertNotEmpty( $registered );

		$index = Settings_Search::build_index();
		$keys  = array();
		foreach ( $index as $row ) {
			$this->assertArrayHasKey( 'key', $row );
			$this->assertArrayHasKey( 'label', $row );
			$this->assertArrayHasKey( 'screen', $row );
			$this->assertArrayHasKey( 'url', $row );
			$this->assertArrayHasKey( 'selector', $row );
			$this->assertArrayHasKey( 'haystack', $row );
			$this->assertNotSame( '', (string) $row['key'] );
			$this->assertNotSame( '', (string) $row['label'] );
			$this->assertNotSame( '', (string) $row['haystack'] );
			$keys[ (string) $row['key'] ] = true;
		}

		foreach ( $registered as $key => $entry ) {
			$this->assertArrayHasKey(
				$key,
				$keys,
				'Registered field must appear in the search index: ' . $key
			);
			$this->assertSame( $entry['label'], $this->label_for( $index, $key ) );
		}
		$this->assertCount( count( $registered ), $index );
	}

	public function test_mute_synonym_finds_snooze_entry(): void {
		$hits = Settings_Search::match( 'mute' );
		$this->assertNotEmpty( $hits );
		$keys = array_column( $hits, 'key' );
		$this->assertContains( 'alert-snooze', $keys );

		$snooze = Settings_Search::match( 'snooze' );
		$skeys  = array_column( $snooze, 'key' );
		$this->assertContains( 'alert-snooze', $skeys );
	}

	public function test_webhook_query_reaches_webhook_url(): void {
		$hits = Settings_Search::match( 'webhook' );
		$keys = array_column( $hits, 'key' );
		$this->assertContains( 'alert-webhook', $keys );

		$exact = Settings_Search::match( 'webhook url' );
		$this->assertNotEmpty( $exact );
		$this->assertSame( 'alert-webhook', $exact[0]['key'] );
		$this->assertSame( '#handl-aicac-alert-webhook', $exact[0]['selector'] );
		$this->assertSame( 'alerts', $exact[0]['screen'] );
	}

	public function test_render_box_exposes_combobox_and_aria_live(): void {
		ob_start();
		Settings_Search::render_box();
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'id="handl-aicac-settings-search-input"', $html );
		$this->assertStringContainsString( 'role="combobox"', $html );
		$this->assertStringContainsString( 'aria-controls="handl-aicac-settings-search-list"', $html );
		$this->assertStringContainsString( 'id="handl-aicac-settings-search-status"', $html );
		$this->assertStringContainsString( 'aria-live="polite"', $html );
		$this->assertStringContainsString( 'Find a setting', $html );
		$this->assertStringNotContainsString( 'snooze', strtolower( $html ) );
	}

	public function test_admin_wires_enqueue_and_header_render(): void {
		$admin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringContainsString( 'Settings_Search::enqueue', $admin );
		$this->assertStringContainsString( 'Settings_Search::render_box', $admin );

		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-settings-search.php', $plugin );

		$this->assertFileExists( HANDL_AICAC_DIR . '/assets/settings-search.js' );
		$js = (string) file_get_contents( HANDL_AICAC_DIR . '/assets/settings-search.js' );
		$this->assertStringContainsString( 'aria-activedescendant', $js );
		$this->assertStringContainsString( 'ArrowDown', $js );
		$this->assertStringContainsString( 'handl-aicac-settings-search-target', $js );
	}

	public function test_index_urls_use_focused_screen_slugs(): void {
		$index = Settings_Search::build_index();
		foreach ( $index as $row ) {
			if ( 'alerts' === $row['screen'] ) {
				$this->assertStringContainsString( Admin::SCREEN_SLUGS['alerts'], $row['url'] );
			}
			if ( 'protections' === $row['screen'] ) {
				$this->assertStringContainsString( Admin::SCREEN_SLUGS['protections'], $row['url'] );
			}
		}
	}

	/**
	 * @param list<array<string,string>> $index
	 */
	private function label_for( array $index, string $key ): string {
		foreach ( $index as $row ) {
			if ( ( $row['key'] ?? '' ) === $key ) {
				return (string) ( $row['label'] ?? '' );
			}
		}
		return '';
	}
}
