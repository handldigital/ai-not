<?php
/**
 * AICAC-PRIVACY-HOOKS (#294).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Privacy_Hooks;
use PHPUnit\Framework\TestCase;

final class PrivacyHooksTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		Privacy_Hooks::reset_for_tests();
		$GLOBALS['handl_aicac_test_added_filters'] = array();
		$GLOBALS['handl_aicac_test_users']         = array(
			7 => array(
				'ID'         => 7,
				'user_email' => 'ada@example.com',
				'user_login' => 'ada',
			),
			9 => array(
				'ID'         => 9,
				'user_email' => 'other@example.com',
				'user_login' => 'other',
			),
		);
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		update_option( Plugin::OPTION_KEY, array( 'log_enabled' => true, 'log_limit' => 200 ), false );
	}

	protected function tearDown(): void {
		Privacy_Hooks::reset_for_tests();
		delete_option( Plugin::LOG_OPTION_KEY );
		delete_option( Plugin::OPTION_KEY );
		unset( $GLOBALS['handl_aicac_test_users'] );
		parent::tearDown();
	}

	public function test_init_registers_exporter_and_eraser_filters(): void {
		Privacy_Hooks::init();
		$filters = $GLOBALS['handl_aicac_test_added_filters'] ?? array();
		$this->assertContains( 'wp_privacy_personal_data_exporters', $filters );
		$this->assertContains( 'wp_privacy_personal_data_erasers', $filters );

		$exporters = Privacy_Hooks::register_exporter( array() );
		$this->assertSame( Privacy_Hooks::FRIENDLY_NAME, $exporters[ Privacy_Hooks::EXPORTER_ID ]['exporter_friendly_name'] );
		$this->assertSame( array( Privacy_Hooks::class, 'export' ), $exporters[ Privacy_Hooks::EXPORTER_ID ]['callback'] );

		$erasers = Privacy_Hooks::register_eraser( array() );
		$this->assertSame( Privacy_Hooks::FRIENDLY_NAME, $erasers[ Privacy_Hooks::ERASER_ID ]['eraser_friendly_name'] );
		$this->assertSame( array( Privacy_Hooks::class, 'erase' ), $erasers[ Privacy_Hooks::ERASER_ID ]['callback'] );
	}

	public function test_exporter_returns_matching_rows_paged(): void {
		$t   = 1_700_000_000;
		$log = array();
		for ( $i = 0; $i < Privacy_Hooks::PAGE_SIZE + 2; $i++ ) {
			$log[] = $this->row( $t + $i, 7, '' );
		}
		$log[] = $this->row( $t + 900, 9, 'other prompt' );
		update_option( Plugin::LOG_OPTION_KEY, $log, false );

		$page1 = Privacy_Hooks::export( 'ada@example.com', 1 );
		$this->assertFalse( $page1['done'] );
		$this->assertCount( Privacy_Hooks::PAGE_SIZE, $page1['data'] );
		$this->assertSame( Privacy_Hooks::GROUP_ACTIVITY, $page1['data'][0]['group_id'] );
		$this->assertSame( Privacy_Hooks::GROUP_LABEL_ACTIVITY, $page1['data'][0]['group_label'] );

		$page2 = Privacy_Hooks::export( 'ada@example.com', 2 );
		$this->assertTrue( $page2['done'] );
		$this->assertCount( 2, $page2['data'] );

		$ids = array();
		foreach ( array_merge( $page1['data'], $page2['data'] ) as $item ) {
			$ids[] = $item['item_id'];
			$blob  = wp_json_encode( $item );
			$this->assertStringNotContainsString( 'other@example.com', (string) $blob );
			$this->assertStringNotContainsString( 'other prompt', (string) $blob );
		}
		$this->assertContains( 'handl-aicac-activity-0', $ids );
		$this->assertContains( 'handl-aicac-activity-51', $ids );
	}

	public function test_exporter_matches_email_inside_prompt_snapshot(): void {
		$t = 1_700_000_000;
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				$this->row( $t, 0, 'Contact ada@example.com please' ),
				$this->row( $t + 1, 9, 'no match' ),
			),
			false
		);
		$result = Privacy_Hooks::export( 'ada@example.com', 1 );
		$this->assertTrue( $result['done'] );
		$groups = array_column( $result['data'], 'group_id' );
		$this->assertContains( Privacy_Hooks::GROUP_ACTIVITY, $groups );
		$this->assertContains( Privacy_Hooks::GROUP_PROMPT, $groups );
		$blob = wp_json_encode( $result['data'] );
		$this->assertStringContainsString( 'Contact ada@example.com please', (string) $blob );
		$this->assertStringNotContainsString( 'no match', (string) $blob );
	}

	public function test_eraser_clears_identifying_fields_and_preserves_counters(): void {
		$t = 1_700_000_000;
		update_option(
			Plugin::LOG_OPTION_KEY,
			array(
				array(
					'ts'             => $t,
					'plugin'         => 'acme/acme.php',
					'decision'       => 'deny',
					'provider'       => 'openai',
					'user_id'        => 7,
					'user_role'      => 'editor',
					'prompt_preview' => 'secret from ada@example.com',
					'uri'            => '/wp-admin/?user=ada',
					'count'          => 4,
					'channel'        => '',
				),
				array(
					'ts'             => $t + 1,
					'plugin'         => 'other/other.php',
					'decision'       => 'allow',
					'user_id'        => 9,
					'user_role'      => 'author',
					'prompt_preview' => 'keep me',
					'uri'            => '/other',
					'count'          => 2,
				),
			),
			false
		);

		$result = Privacy_Hooks::erase( 'ada@example.com', 1 );
		$this->assertTrue( $result['items_removed'] );
		$this->assertFalse( $result['items_retained'] );
		$this->assertTrue( $result['done'] );
		$this->assertNotEmpty( $result['messages'] );
		$this->assertStringContainsString( 'Removed personal details from 1 AI activity record', $result['messages'][0] );

		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $log );
		$subject = $log[0];
		$this->assertSame( 0, $subject['user_id'] );
		$this->assertSame( '', $subject['user_role'] );
		$this->assertSame( '', $subject['prompt_preview'] );
		$this->assertSame( '', $subject['uri'] );
		$this->assertSame( 4, $subject['count'] );
		$this->assertSame( 'deny', $subject['decision'] );
		$this->assertSame( 'acme/acme.php', $subject['plugin'] );
		$this->assertSame( $t, $subject['ts'] );

		$other = $log[1];
		$this->assertSame( 9, $other['user_id'] );
		$this->assertSame( 'keep me', $other['prompt_preview'] );
		$this->assertSame( '/other', $other['uri'] );
		$this->assertSame( 2, $other['count'] );

		$evidence = $log[2];
		$this->assertSame( Privacy_Hooks::CHANNEL, $evidence['channel'] );
		$this->assertSame( 'erased', $evidence['decision'] );
		$this->assertSame( 1, $evidence['erased_count'] );
		$this->assertSame( 0, $evidence['user_id'] );
		$this->assertSame( '', $evidence['prompt_preview'] );
		$this->assertSame( sha1( 'ada@example.com' ), $evidence['email_sha1'] );
		$this->assertStringNotContainsString( 'ada@example.com', (string) wp_json_encode( $evidence ) );
	}

	public function test_eraser_drains_remaining_matches_across_pages(): void {
		$t   = 1_700_000_000;
		$log = array();
		for ( $i = 0; $i < 100; $i++ ) {
			$log[] = $this->row( $t + $i, 7, 'prompt ' . $i );
		}
		$log[] = $this->row( $t + 500, 9, 'keep other' );
		update_option( Plugin::OPTION_KEY, array( 'log_enabled' => true, 'log_limit' => 1000 ), false );
		update_option( Plugin::LOG_OPTION_KEY, $log, false );

		$page1 = Privacy_Hooks::erase( 'ada@example.com', 1 );
		$this->assertTrue( $page1['items_removed'] );
		$this->assertFalse( $page1['done'] );

		$page2 = Privacy_Hooks::erase( 'ada@example.com', 2 );
		$this->assertTrue( $page2['items_removed'] );
		$this->assertTrue( $page2['done'] );

		$stored = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $stored );
		$still_personal = 0;
		$other_ok       = false;
		foreach ( $stored as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( Privacy_Hooks::CHANNEL === ( $row['channel'] ?? '' ) ) {
				continue;
			}
			if ( 9 === (int) ( $row['user_id'] ?? 0 ) ) {
				$other_ok = ( 'keep other' === ( $row['prompt_preview'] ?? '' ) );
				continue;
			}
			if ( Privacy_Hooks::row_has_personal_data( $row ) ) {
				++$still_personal;
			}
			$this->assertSame( 0, (int) ( $row['user_id'] ?? -1 ) );
			$this->assertSame( '', (string) ( $row['prompt_preview'] ?? 'x' ) );
			$this->assertSame( 1, (int) ( $row['count'] ?? 0 ) );
			$this->assertSame( 'allow', (string) ( $row['decision'] ?? '' ) );
		}
		$this->assertSame( 0, $still_personal );
		$this->assertTrue( $other_ok );
	}

	public function test_eraser_does_not_touch_non_matching_users(): void {
		$t = 1_700_000_000;
		$original = array(
			$this->row( $t, 9, 'other prompt' ),
		);
		update_option( Plugin::LOG_OPTION_KEY, $original, false );
		$result = Privacy_Hooks::erase( 'ada@example.com', 1 );
		$this->assertFalse( $result['items_removed'] );
		$this->assertTrue( $result['done'] );
		$this->assertSame( $original, get_option( Plugin::LOG_OPTION_KEY ) );
	}

	public function test_empty_email_exports_nothing(): void {
		update_option( Plugin::LOG_OPTION_KEY, array( $this->row( 1_700_000_000, 7, 'x' ) ), false );
		$result = Privacy_Hooks::export( '', 1 );
		$this->assertSame( array(), $result['data'] );
		$this->assertTrue( $result['done'] );
	}

	/**
	 * @return array<string,mixed>
	 */
	private function row( int $ts, int $user_id, string $preview ): array {
		return array(
			'ts'             => $ts,
			'plugin'         => 'acme/acme.php',
			'decision'       => 'allow',
			'provider'       => 'openai',
			'model'          => 'gpt-4o',
			'user_id'        => $user_id,
			'user_role'      => $user_id > 0 ? 'editor' : '',
			'prompt_preview' => $preview,
			'uri'            => '/wp-admin/',
			'count'          => 1,
		);
	}
}
