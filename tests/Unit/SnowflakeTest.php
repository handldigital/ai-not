<?php
/**
 * AICAC-SNOWFLAKE (#459).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Snowflake;
use PHPUnit\Framework\TestCase;

final class SnowflakeTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		Snowflake::reset_for_tests();
		Snowflake::set_skip_cache( true );
	}

	protected function tearDown(): void {
		Snowflake::reset_for_tests();
		parent::tearDown();
	}

	public function test_classify_default_customized_unknown_and_missing(): void {
		$map = array(
			'handl_aicac_policy.default' => 'allow',
			'handl_aicac_policy.log_enabled' => false,
		);

		$this->assertSame( Snowflake::STATUS_DEFAULT, Snowflake::classify( 'handl_aicac_policy.default', null, $map ) );
		$this->assertSame( Snowflake::STATUS_DEFAULT, Snowflake::classify( 'handl_aicac_policy.default', 'allow', $map ) );
		$this->assertSame( Snowflake::STATUS_CUSTOMIZED, Snowflake::classify( 'handl_aicac_policy.default', 'deny', $map ) );
		$this->assertSame( Snowflake::STATUS_DEFAULT, Snowflake::classify( 'handl_aicac_policy.log_enabled', false, $map ) );
		$this->assertSame( Snowflake::STATUS_CUSTOMIZED, Snowflake::classify( 'handl_aicac_policy.log_enabled', true, $map ) );
		$this->assertSame( Snowflake::STATUS_UNKNOWN, Snowflake::classify( 'handl_aicac_not_in_map', 'x', $map ) );
	}

	public function test_secret_like_redaction(): void {
		$this->assertTrue( Snowflake::is_secret_like( 'handl_aicac_policy.alert_webhook_url' ) );
		$this->assertTrue( Snowflake::is_secret_like( 'handl_aicac_chat_notify.slack_url' ) );
		$this->assertTrue( Snowflake::is_secret_like( 'api_token' ) );
		$this->assertTrue( Snowflake::is_secret_like( 'client_secret' ) );
		$this->assertFalse( Snowflake::is_secret_like( 'handl_aicac_policy.default' ) );

		$this->assertSame( Snowflake::REDACT_NOT_SET, Snowflake::display_value( 'handl_aicac_policy.alert_webhook_url', '' ) );
		$this->assertSame( Snowflake::REDACT_SET, Snowflake::display_value( 'handl_aicac_policy.alert_webhook_url', 'https://hooks.example/x' ) );
		$this->assertSame( 'deny', Snowflake::display_value( 'handl_aicac_policy.default', 'deny' ) );
	}

	public function test_census_all_defaults_and_support_block(): void {
		Snowflake::set_test_defaults(
			array(
				'handl_aicac_policy.default' => 'allow',
				'handl_aicac_policy.log_enabled' => false,
			)
		);
		Snowflake::set_test_stored( array() );

		$snap = Snowflake::census( 1000 );
		$this->assertSame( 2, $snap['tracked'] );
		$this->assertSame( 0, $snap['customized'] );
		$this->assertTrue( $snap['all_defaults'] );
		$this->assertStringContainsString( 'all tracked settings match defaults', Snowflake::support_block( $snap ) );
	}

	public function test_census_customized_table_and_support_paths(): void {
		Snowflake::set_test_defaults(
			array(
				'handl_aicac_policy.default' => 'allow',
				'handl_aicac_policy.alert_webhook_url' => '',
				'handl_aicac_chat_notify.slack_url' => '',
			)
		);
		Snowflake::set_test_stored(
			array(
				'handl_aicac_policy.default' => 'deny',
				'handl_aicac_policy.alert_webhook_url' => 'https://hooks.example/secret',
				'handl_aicac_chat_notify.slack_url' => '',
			)
		);

		$snap = Snowflake::census( 2000 );
		$this->assertSame( 3, $snap['tracked'] );
		$this->assertSame( 2, $snap['customized'] );
		$this->assertFalse( $snap['all_defaults'] );
		$this->assertSame(
			array( 'handl_aicac_policy.default', 'handl_aicac_policy.alert_webhook_url' ),
			$snap['customized_paths']
		);

		$custom_rows = array_values(
			array_filter(
				$snap['rows'],
				static function ( array $row ): bool {
					return Snowflake::STATUS_CUSTOMIZED === $row['status'];
				}
			)
		);
		$this->assertCount( 2, $custom_rows );
		$by_path = array();
		foreach ( $custom_rows as $row ) {
			$by_path[ $row['path'] ] = $row;
		}
		$this->assertSame( 'deny', $by_path['handl_aicac_policy.default']['current_display'] );
		$this->assertSame( Snowflake::REDACT_SET, $by_path['handl_aicac_policy.alert_webhook_url']['current_display'] );
		$this->assertSame( Snowflake::REDACT_NOT_SET, $by_path['handl_aicac_policy.alert_webhook_url']['default_display'] );

		$block = Snowflake::support_block( $snap );
		$this->assertStringContainsString( 'handl_aicac_policy.default', $block );
		$this->assertStringContainsString( 'handl_aicac_policy.alert_webhook_url', $block );
		$this->assertStringNotContainsString( 'hooks.example', $block );
	}

	public function test_render_writes_only_snowflake_options(): void {
		Snowflake::set_test_defaults(
			array(
				'handl_aicac_policy.default' => 'allow',
			)
		);
		Snowflake::set_test_stored(
			array(
				'handl_aicac_policy.default' => 'deny',
			)
		);
		Snowflake::set_skip_cache( false );
		$GLOBALS['handl_aicac_test_current_user_can'] = true;

		$foreign = 'handl_aicac_policy';
		$before  = array( 'default' => 'deny', 'marker' => 'keep-me' );
		update_option( $foreign, $before, false );

		ob_start();
		Snowflake::render_page();
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( 'Snowflake', $html );
		$this->assertStringContainsString( '1 customized of 1 tracked', $html );
		$this->assertStringContainsString( 'handl_aicac_policy.default', $html );
		$this->assertSame( $before, get_option( $foreign, null ) );

		$census = get_option( Snowflake::CENSUS_OPTION, null );
		$this->assertIsArray( $census );
		$this->assertNotFalse( get_option( Snowflake::GENERATED_OPTION, false ) );
		unset( $GLOBALS['handl_aicac_test_current_user_can'] );
	}

	public function test_plugin_bootstrap_wires_snowflake_at_bottom(): void {
		$plugin = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringContainsString( 'class-handl-aicac-snowflake.php', $plugin );
		$this->assertStringContainsString( 'Snowflake::init()', $plugin );
		$this->assertGreaterThan(
			strrpos( $plugin, 'Rescan_Schedule::init()' ),
			strrpos( $plugin, 'Snowflake::init()' )
		);
	}

	public function test_curated_defaults_filterable_and_count(): void {
		$map = Snowflake::curated_defaults();
		$this->assertGreaterThanOrEqual( 20, count( $map ) );
		$this->assertArrayHasKey( 'handl_aicac_policy.default', $map );
		$this->assertSame( 'allow', $map['handl_aicac_policy.default'] );

		$GLOBALS['handl_aicac_test_filters'][ Snowflake::FILTER_DEFAULTS ] = static function ( array $defaults ): array {
			$defaults['handl_aicac_policy.default'] = 'deny';

			return $defaults;
		};
		$filtered = Snowflake::curated_defaults();
		$this->assertSame( 'deny', $filtered['handl_aicac_policy.default'] );
		unset( $GLOBALS['handl_aicac_test_filters'][ Snowflake::FILTER_DEFAULTS ] );
	}

	public function test_plugin_does_not_touch_foreign_option_keys_in_source(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-snowflake.php' );
		$this->assertStringNotContainsString( 'handl_aicac_weather', $src );
		$this->assertStringNotContainsString( 'handl_aicac_coldcase', $src );
		$this->assertStringNotContainsString( 'handl_aicac_rush_hour', $src );
		$this->assertStringNotContainsString( 'handl_aicac_stowaway', $src );
		$this->assertStringNotContainsString( 'handl_aicac_deja', $src );
		$this->assertStringNotContainsString( 'handl_aicac_fineprint', $src );
	}
}
