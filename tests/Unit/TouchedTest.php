<?php
/**
 * AICAC-TOUCHED (#367).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Plugin;
use HandL\AICAC\Touched;
use PHPUnit\Framework\TestCase;

final class TouchedTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']   = array();
		$GLOBALS['handl_aicac_test_post_meta'] = array();
		$GLOBALS['handl_aicac_test_user_id']   = 12;
		$GLOBALS['handl_aicac_test_caps']      = array(
			'read'             => true,
			'handl_aicac_view' => true,
		);
		unset( $GLOBALS['handl_aicac_test_current_user_can'] );
		Touched::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
			),
			false
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
	}

	protected function tearDown(): void {
		Touched::reset_for_tests();
		$GLOBALS['handl_aicac_test_options']   = array();
		$GLOBALS['handl_aicac_test_post_meta'] = array();
		$GLOBALS['handl_aicac_test_user_id']   = 0;
		unset(
			$GLOBALS['handl_aicac_test_caps'],
			$GLOBALS['handl_aicac_test_current_user_can'],
			$GLOBALS['handl_aicac_test_shortcodes'],
			$GLOBALS['handl_aicac_test_filters'],
			$_POST['post_ID'],
			$_REQUEST['post_ID']
		);
		parent::tearDown();
	}

	public function test_init_registers_hooks_and_shortcode(): void {
		Touched::init();
		$this->assertContains( Touched::SHORTCODE, $GLOBALS['handl_aicac_test_shortcodes'] ?? array() );
		$actions = $GLOBALS['handl_aicac_test_added_actions'] ?? array();
		$this->assertContains( 'wp_ai_client_after_generate_result', $actions );
		$this->assertContains( 'add_meta_boxes', $actions );
		$this->assertContains( 'admin_menu', $actions );
	}

	public function test_badge_off_by_default_renders_empty(): void {
		Touched::record_touch(
			42,
			array(
				'ts'       => 1_700_000_000,
				'provider' => 'openai',
				'user_id'  => 12,
				'outcome'  => 'success',
			)
		);
		$html = Touched::render_shortcode( array( 'post_id' => 42 ) );
		$this->assertSame( '', $html );
	}

	public function test_badge_on_renders_provider_family(): void {
		Touched::save_settings( array( 'badge_enabled' => true ) );
		Touched::record_touch(
			42,
			array(
				'ts'       => 1_700_000_000,
				'provider' => 'openai',
				'user_id'  => 12,
				'outcome'  => 'success',
			)
		);
		$html = Touched::render_shortcode( array( 'post_id' => 42 ) );
		$this->assertStringContainsString( 'AI-assisted', $html );
		$this->assertStringContainsString( 'OpenAI', $html );
	}

	public function test_record_touch_writes_history_summary_and_index(): void {
		$ok = Touched::record_touch(
			7,
			array(
				'ts'         => 100,
				'provider'   => 'anthropic',
				'model'      => 'claude-3',
				'capability' => 'text-generation',
				'user_id'    => 12,
				'outcome'    => 'success',
			)
		);
		$this->assertTrue( $ok );
		$history = Touched::history_for_post( 7 );
		$this->assertCount( 1, $history );
		$this->assertSame( 'anthropic', $history[0]['provider'] );
		$summary = Touched::summary_for_post( 7 );
		$this->assertNotNull( $summary );
		$this->assertSame( 1, $summary['count'] );
		$this->assertSame( 'anthropic', $summary['last_provider'] );
		$list = Touched::list_touched();
		$this->assertCount( 1, $list );
		$this->assertSame( 7, $list[0]['post_id'] );
	}

	public function test_unlinkable_context_records_nothing(): void {
		Touched::set_test_post_id( false );
		$event = new class() {
			public function getResult() {
				return new class() {
					public function getTokenUsage() {
						return null;
					}
				};
			}
			public function getProviderId(): string {
				return 'openai';
			}
		};
		Touched::maybe_record_outcome( $event );
		$this->assertSame( array(), Touched::list_touched() );
		$this->assertSame( array(), Touched::index_ids() );
	}

	public function test_editing_context_records_from_outcome_hook(): void {
		Touched::set_test_post_id( 55 );
		$event = new class() {
			public function getResult() {
				return new class() {
					public function getTokenUsage() {
						return null;
					}
				};
			}
			public function getProviderId(): string {
				return 'google';
			}
			public function getCapability(): string {
				return 'text-generation';
			}
		};
		Touched::maybe_record_outcome( $event );
		$summary = Touched::summary_for_post( 55 );
		$this->assertNotNull( $summary );
		$this->assertSame( 'google', $summary['last_provider'] );
		$this->assertSame( 1, $summary['count'] );
	}

	public function test_resolve_post_context_from_post_body(): void {
		Touched::set_test_post_id( null );
		$_POST['post_ID'] = '88';
		$this->assertSame( 88, Touched::resolve_post_context() );
	}

	public function test_posts_column_and_csv(): void {
		Touched::record_touch(
			3,
			array(
				'ts'       => 200,
				'provider' => 'openai',
				'user_id'  => 12,
			)
		);
		$cols = Touched::posts_column( array( 'title' => 'Title' ) );
		$this->assertArrayHasKey( 'handl_aicac_touched', $cols );

		ob_start();
		Touched::posts_column_content( 'handl_aicac_touched', 3 );
		$cell = (string) ob_get_clean();
		$this->assertStringContainsString( 'OpenAI', $cell );

		$csv = Touched::csv_for_list();
		$this->assertStringContainsString( 'post_id,call_count', $csv );
		$this->assertStringContainsString( '3,1,200,openai', $csv );
	}

	public function test_activity_log_row_appended(): void {
		Touched::record_touch(
			9,
			array(
				'ts'       => 300,
				'provider' => 'openai',
				'user_id'  => 12,
				'outcome'  => 'success',
			)
		);
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$this->assertIsArray( $log );
		$touched = array_values(
			array_filter(
				$log,
				static function ( $row ) {
					return is_array( $row ) && ( $row['channel'] ?? '' ) === Touched::CHANNEL;
				}
			)
		);
		$this->assertCount( 1, $touched );
		$this->assertSame( 9, (int) ( $touched[0]['post_id'] ?? 0 ) );
	}

	public function test_history_cap_trims_oldest(): void {
		for ( $i = 1; $i <= Touched::HISTORY_CAP + 5; $i++ ) {
			Touched::record_touch(
				11,
				array(
					'ts'       => $i,
					'provider' => 'openai',
					'user_id'  => 12,
				)
			);
		}
		$history = Touched::history_for_post( 11 );
		$this->assertCount( Touched::HISTORY_CAP, $history );
		$this->assertSame( 6, (int) $history[0]['ts'] );
	}
}
