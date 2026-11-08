<?php
/**
 * AICAC-UNDERSTUDY (#493).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Budget;
use HandL\AICAC\Model_Force;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use HandL\AICAC\Understudy;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../stubs/wp-admin-escape.php';

final class UnderstudyTest extends TestCase {

	private const PLUGIN = 'alpha/alpha.php';
	private const NOW    = 1791800000;

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		$GLOBALS['handl_aicac_test_filters']          = array();
		$GLOBALS['handl_aicac_test_added_actions']    = array();
		$GLOBALS['handl_aicac_test_added_filters']    = array();
		$GLOBALS['handl_aicac_test_cron']             = array();
		$GLOBALS['handl_aicac_test_plugins']          = array(
			self::PLUGIN => array( 'Name' => 'Alpha' ),
		);
		Understudy::reset_for_tests();
		Understudy::set_test_now( self::NOW );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'plugins'     => array( self::PLUGIN => 'allow' ),
			),
			false
		);
	}

	protected function tearDown(): void {
		$GLOBALS['handl_aicac_test_options']       = array();
		$GLOBALS['handl_aicac_test_filters']       = array();
		$GLOBALS['handl_aicac_test_added_actions'] = array();
		$GLOBALS['handl_aicac_test_added_filters'] = array();
		$GLOBALS['handl_aicac_test_cron']          = array();
		Understudy::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private function allowed_rows( int $n, string $prompt = 'Summarize this post about cats and dogs' ): array {
		$rows = array();
		for ( $i = 0; $i < $n; $i++ ) {
			$rows[] = array(
				'ts'             => self::NOW - ( $i * 60 ),
				'decision'       => 'allow',
				'plugin'         => self::PLUGIN,
				'provider'       => 'openai',
				'model'          => 'gpt-4o',
				'operation'      => 'generate_text',
				'prompt_preview' => $prompt . ' ' . $i,
				'input_tokens'   => 1000,
				'output_tokens'  => 400,
			);
		}

		return $rows;
	}

	public function test_init_registers_menu_cron_and_save_once(): void {
		Understudy::init();
		Understudy::init();
		$hooks = $GLOBALS['handl_aicac_test_added_actions'];
		$this->assertSame(
			array(
				'admin_menu',
				'admin_notices',
				'admin_post_' . Understudy::ACTION_SAVE,
				'admin_post_' . Understudy::ACTION_APPLY,
				'admin_post_' . Understudy::ACTION_REVERT,
				Understudy::CRON_HOOK,
			),
			$hooks
		);
		$this->assertSame( Understudy::FRAMING, 'cron_async_never_on_live_request_path' );
		$this->assertSame( 0, strpos( Understudy::SETTINGS_OPTION, 'handl_aicac_understudy' ) );
	}

	public function test_plugin_bootstrap_wires_understudy_at_bottom(): void {
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-understudy.php', $plugin );
		$this->assertStringContainsString( 'Understudy::init()', $plugin );
		$this->assertGreaterThan(
			(int) strrpos( $plugin, 'Neighbors::init()' ),
			(int) strrpos( $plugin, 'Understudy::init()' )
		);
		$boot = (string) file_get_contents( HANDL_AICAC_DIR . '/tests/bootstrap.php' );
		$this->assertStringContainsString( 'class-handl-aicac-understudy.php', $boot );
		$readme = (string) file_get_contents( HANDL_AICAC_DIR . '/readme.txt' );
		$this->assertStringNotContainsString( 'understudy', strtolower( $readme ) );
		$policy = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-policy.php' );
		$this->assertStringNotContainsString( 'Understudy', $policy );
		$admin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringNotContainsString( 'Understudy', $admin );
	}

	public function test_live_request_path_is_untouched(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-understudy.php' );
		$this->assertStringNotContainsString( 'wp_ai_client', $src );
		$this->assertStringNotContainsString( 'prevent_prompt', $src );
		$this->assertStringNotContainsString( 'http_request_args', $src );
		$this->assertStringNotContainsString( 'wp_remote_', $src );
		Understudy::init();
		$hooks = $GLOBALS['handl_aicac_test_added_actions'];
		$this->assertNotContains( 'wp_ai_client_prevent_prompt', $hooks );
		$this->assertNotContains( 'wp_ai_client_before_generate_result', $hooks );
		$this->assertContains( Understudy::CRON_HOOK, $hooks );
	}

	public function test_off_by_default_and_enable_is_per_plugin(): void {
		$this->assertFalse( Understudy::is_enabled() );
		$this->assertFalse( Understudy::is_enabled_for( self::PLUGIN ) );
		ob_start();
		Understudy::render_page();
		$off = (string) ob_get_clean();
		$this->assertStringContainsString( 'Model audition is off.', $off );
		$this->assertStringContainsString( 'Model audition', $off );
		$this->assertStringContainsString( 'Try another model on a sample of allowed calls.', $off );
		$this->assertStringContainsString( 'Test another model for this plugin', $off );
		$this->assertStringContainsString( 'Model to test', $off );
		$this->assertStringContainsString( 'Test calls may incur provider charges. To stop testing, clear this checkbox and save.', $off );
		$this->assertStringNotContainsString( 'OFF', $off );
		$this->assertStringNotContainsString( 'cheaper', strtolower( $off ) );

		$this->assertTrue(
			Understudy::enable_for(
				self::PLUGIN,
				array(
					'provider' => 'openai',
					'model'    => 'gpt-4o-mini',
				)
			)
		);
		$this->assertTrue( Understudy::is_enabled() );
		$this->assertTrue( Understudy::is_enabled_for( self::PLUGIN ) );
		$this->assertFalse( Understudy::is_enabled_for( 'beta/beta.php' ) );
	}

	public function test_similarity_is_deterministic_and_length_normalized(): void {
		$a = 'The cat sat on the mat';
		$b = 'The cat sat on the mat';
		$this->assertSame( 1.0, Understudy::similarity( $a, $b ) );
		$this->assertSame( Understudy::similarity( $a, $b ), Understudy::similarity( $a, $b ) );
		$this->assertSame( 0.0, Understudy::similarity( 'alpha beta', 'gamma delta' ) );
		$partial = Understudy::similarity( 'the cat sat on the mat', 'the cat sat on a rug' );
		$this->assertGreaterThan( 0.5, $partial );
		$this->assertLessThan( 1.0, $partial );
		$this->assertSame( Understudy::VERDICT_CLOSE, Understudy::verdict_for_score( 0.9 ) );
		$this->assertSame( Understudy::VERDICT_DRIFT, Understudy::verdict_for_score( 0.2 ) );
	}

	public function test_cron_samples_allowed_calls_through_policy_gate_tagged_shadow(): void {
		Understudy::enable_for(
			self::PLUGIN,
			array(
				'provider'   => 'openai',
				'model'      => 'gpt-4o-mini',
				'sample_pct' => 100,
				'daily_cap'  => 10,
			)
		);
		Understudy::set_test_force_sample( true );
		Understudy::set_test_shadow_text( 'Summarize this post about cats and dogs 0' );
		Understudy::set_test_log( $this->allowed_rows( 3 ) );
		Understudy::cron_run();

		$samples = Understudy::samples();
		$this->assertNotEmpty( $samples );
		$this->assertSame( self::PLUGIN, $samples[0]['plugin'] );
		$this->assertArrayHasKey( 'score', $samples[0] );
		$this->assertArrayHasKey( 'verdict', $samples[0] );
		$this->assertArrayNotHasKey( 'live_text', $samples[0] );
		$this->assertArrayNotHasKey( 'shadow_text', $samples[0] );

		$log    = get_option( Plugin::LOG_OPTION_KEY, array() );
		$shadow = array();
		foreach ( is_array( $log ) ? $log : array() as $row ) {
			if ( is_array( $row ) && Understudy::is_shadow_row( $row ) ) {
				$shadow[] = $row;
			}
		}
		$this->assertNotEmpty( $shadow );
		$this->assertSame( Understudy::CHANNEL_SHADOW, $shadow[0]['channel'] );
		$this->assertSame( Understudy::CHANNEL_SHADOW, $shadow[0]['tag'] );
		$this->assertSame( 'allow', $shadow[0]['decision'] );
		$this->assertFalse( Understudy::is_headline_row( $shadow[0] ) );
		$this->assertTrue( Understudy::is_headline_row( $this->allowed_rows( 1 )[0] ) );
	}

	public function test_daily_cap_and_stop_halts_shadow_calls(): void {
		Understudy::enable_for(
			self::PLUGIN,
			array(
				'provider'   => 'openai',
				'model'      => 'gpt-4o-mini',
				'sample_pct' => 100,
				'daily_cap'  => 1,
			)
		);
		Understudy::set_test_force_sample( true );
		Understudy::set_test_shadow_text( 'same text for overlap' );
		Understudy::set_test_log( $this->allowed_rows( 5, 'same text for overlap' ) );
		Understudy::cron_run();
		$this->assertCount( 1, Understudy::samples() );

		Understudy::disable_for( self::PLUGIN );
		$this->assertFalse( Understudy::is_enabled_for( self::PLUGIN ) );
		Understudy::cron_run();
		$this->assertCount( 1, Understudy::samples() );
		$this->assertSame( array(), get_option( Understudy::QUEUE_OPTION, array() ) ?: array() );
	}

	public function test_denied_plugin_still_hits_policy_gate(): void {
		Policy::save_policy(
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'plugins'     => array( self::PLUGIN => 'deny' ),
			)
		);
		Understudy::enable_for(
			self::PLUGIN,
			array(
				'provider'   => 'openai',
				'model'      => 'gpt-4o-mini',
				'sample_pct' => 100,
				'daily_cap'  => 5,
			)
		);
		Understudy::set_test_force_sample( true );
		Understudy::set_test_shadow_text( 'should not score' );
		Understudy::set_test_log( $this->allowed_rows( 1 ) );
		Understudy::cron_run();
		$this->assertSame( array(), Understudy::samples() );
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		$hit = false;
		foreach ( is_array( $log ) ? $log : array() as $row ) {
			if ( is_array( $row ) && Understudy::is_shadow_row( $row ) && 'deny' === ( $row['decision'] ?? '' ) ) {
				$hit = true;
			}
		}
		$this->assertTrue( $hit );
	}

	public function test_apply_sets_model_force_and_is_reversible(): void {
		Understudy::enable_for(
			self::PLUGIN,
			array(
				'provider' => 'openai',
				'model'    => 'gpt-4o-mini',
			)
		);
		$this->assertTrue( Understudy::apply_force( self::PLUGIN ) );
		$map = Model_Force::force_map( Policy::get_policy() );
		$this->assertSame( 'openai', $map[ self::PLUGIN ]['provider'] );
		$this->assertSame( 'gpt-4o-mini', $map[ self::PLUGIN ]['model'] );
		$this->assertTrue( Understudy::is_applied( self::PLUGIN ) );

		$this->assertTrue( Understudy::revert_force( self::PLUGIN ) );
		$map = Model_Force::force_map( Policy::get_policy() );
		$this->assertArrayNotHasKey( self::PLUGIN, $map );
		$this->assertFalse( Understudy::is_applied( self::PLUGIN ) );
	}

	public function test_verdict_card_and_savings_use_rates_feed_prices(): void {
		Understudy::enable_for(
			self::PLUGIN,
			array(
				'provider'   => 'openai',
				'model'      => 'gpt-4o-mini',
				'sample_pct' => 100,
				'daily_cap'  => 20,
			)
		);
		Understudy::set_test_force_sample( true );
		Understudy::set_test_shadow_text( 'Summarize this post about cats and dogs 0' );
		Understudy::set_test_log( $this->allowed_rows( 4 ) );
		Understudy::cron_run();
		$card = Understudy::verdict( self::PLUGIN );
		$this->assertGreaterThan( 0, $card['sample_count'] );
		$this->assertNotNull( $card['monthly_savings'] );
		$this->assertGreaterThan( 0.0, (float) $card['monthly_savings'] );

		ob_start();
		Understudy::render_plugin_card( self::PLUGIN );
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Similar wording in', $html );
		$this->assertStringContainsString( 'Compares shared words only. Similar wording does not confirm accuracy or quality. Review the results before switching models.', $html );
		$this->assertStringContainsString( 'Use this model for this plugin', $html );
		$this->assertStringContainsString( 'Estimated savings on priced calls in the last 30 days:', $html );
		$this->assertStringContainsString( 'Uses recorded token counts and available rates. Excludes unpriced calls and test-call costs. Actual savings may differ.', $html );
		$this->assertStringNotContainsString( 'Based on sampled calls. This is an estimate.', $html );
		$this->assertStringNotContainsString( 'CLOSE-MATCH', $html );
		$this->assertStringNotContainsString( 'INSUFFICIENT', $html );
		$this->assertStringNotContainsString( 'cheaper', strtolower( $html ) );
	}

	public function test_applied_state_and_restore_stay_visible_when_testing_is_off(): void {
		Understudy::enable_for(
			self::PLUGIN,
			array(
				'provider' => 'openai',
				'model'    => 'gpt-4o-mini',
			)
		);
		$this->assertTrue( Understudy::apply_force( self::PLUGIN ) );
		Understudy::disable_for( self::PLUGIN );
		$this->assertFalse( Understudy::is_enabled_for( self::PLUGIN ) );
		$this->assertTrue( Understudy::is_applied( self::PLUGIN ) );

		ob_start();
		Understudy::render_plugin_card( self::PLUGIN );
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Model audition is off.', $html );
		$this->assertStringContainsString( 'This model is applied to future AI calls from this plugin. Stopping the audition does not restore the previous model setting.', $html );
		$this->assertStringContainsString( 'Restore previous model setting', $html );
		$this->assertStringNotContainsString( 'Use this model for this plugin', $html );
	}

	public function test_applied_state_and_restore_stay_visible_when_samples_expire(): void {
		Understudy::enable_for(
			self::PLUGIN,
			array(
				'provider' => 'openai',
				'model'    => 'gpt-4o-mini',
			)
		);
		$this->assertTrue( Understudy::apply_force( self::PLUGIN ) );
		$this->assertTrue( Understudy::is_enabled_for( self::PLUGIN ) );
		$this->assertTrue( Understudy::is_applied( self::PLUGIN ) );
		$this->assertSame( 0, Understudy::verdict( self::PLUGIN )['sample_count'] );

		ob_start();
		Understudy::render_plugin_card( self::PLUGIN );
		$html = (string) ob_get_clean();
		$this->assertStringContainsString( 'Not enough samples yet.', $html );
		$this->assertStringContainsString( 'This model is applied to future AI calls from this plugin. Stopping the audition does not restore the previous model setting.', $html );
		$this->assertStringContainsString( 'Restore previous model setting', $html );
		$this->assertStringNotContainsString( 'Use this model for this plugin', $html );
	}

	public function test_spend_lands_on_distinct_understudy_ledger_line(): void {
		Understudy::enable_for(
			self::PLUGIN,
			array(
				'provider'   => 'openai',
				'model'      => 'gpt-4o-mini',
				'sample_pct' => 100,
				'daily_cap'  => 5,
			)
		);
		Understudy::set_test_force_sample( true );
		Understudy::set_test_shadow_text( 'Summarize this post about cats and dogs 0' );
		Understudy::set_test_log( $this->allowed_rows( 2 ) );
		Understudy::cron_run();
		$spend = Budget::current_period_spend( Understudy::LEDGER_PLUGIN, self::NOW );
		$this->assertGreaterThan( 0.0, $spend );
		$this->assertSame( 0.0, Budget::current_period_spend( self::PLUGIN, self::NOW ) );
	}

	public function test_uninstall_cleans_understudy_options(): void {
		if ( ! defined( 'HANDL_AICAC_UNINSTALL_HELPERS' ) ) {
			define( 'HANDL_AICAC_UNINSTALL_HELPERS', true );
		}
		require_once HANDL_AICAC_DIR . '/uninstall.php';

		Understudy::enable_for( self::PLUGIN, array( 'provider' => 'openai', 'model' => 'gpt-4o-mini' ) );
		update_option( Understudy::SAMPLES_OPTION, array( array( 'plugin' => self::PLUGIN ) ), false );
		update_option( Understudy::QUEUE_OPTION, array( array( 'plugin' => self::PLUGIN ) ), false );
		update_option( 'handl_aicac_uninstall_policy', 'purge', false );
		\handl_aicac_uninstall_purge();

		$this->assertFalse( get_option( Understudy::SETTINGS_OPTION, false ) );
		$this->assertFalse( get_option( Understudy::SAMPLES_OPTION, false ) );
	}

	public function test_render_does_not_mutate_policy(): void {
		Understudy::enable_for( self::PLUGIN, array( 'provider' => 'openai', 'model' => 'gpt-4o-mini' ) );
		$before = get_option( Plugin::OPTION_KEY, null );
		ob_start();
		Understudy::render_page();
		ob_end_clean();
		$this->assertSame( $before, get_option( Plugin::OPTION_KEY, null ) );
	}
}
