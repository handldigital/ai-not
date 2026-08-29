<?php
/**
 * AICAC-IA (#242): focused-screen URLs and legacy Settings redirects.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Admin;
use PHPUnit\Framework\TestCase;

final class AdminScreenUrlTest extends TestCase {

	public function test_seven_screen_slugs_are_registered(): void {
		$this->assertSame(
			array(
				'dashboard',
				'rules',
				'protections',
				'activity',
				'insights',
				'policy-tools',
				'alerts',
			),
			array_keys( Admin::SCREEN_SLUGS )
		);
		$this->assertSame( 'handl-aicac', Admin::MENU_SLUG );
		$this->assertSame( 'handl-ai-connector-access-control', Admin::LEGACY_PAGE_SLUG );
	}

	/**
	 * @return array<string, array{0:string,1:string}>
	 */
	public function screenSlugProvider(): array {
		return array(
			'dashboard'    => array( 'dashboard', 'handl-aicac' ),
			'rules'        => array( 'rules', 'handl-aicac-rules' ),
			'protections'  => array( 'protections', 'handl-aicac-protections' ),
			'activity'     => array( 'activity', 'handl-aicac-activity' ),
			'insights'     => array( 'insights', 'handl-aicac-insights' ),
			'policy-tools' => array( 'policy-tools', 'handl-aicac-policy-tools' ),
			'alerts'       => array( 'alerts', 'handl-aicac-alerts' ),
		);
	}

	/**
	 * @dataProvider screenSlugProvider
	 */
	public function test_screen_url_uses_admin_php_and_new_slug( string $screen, string $slug ): void {
		$url = Admin::screen_url( $screen );
		$this->assertStringContainsString( 'admin.php', $url );
		$this->assertStringContainsString( 'page=' . $slug, $url );
		$this->assertStringNotContainsString( 'options-general.php', $url );
		$this->assertStringNotContainsString( 'handl_aicac_tab=', $url );
	}

	public function test_log_alias_and_profile_overlay(): void {
		$this->assertSame( 'activity', Admin::normalize_screen( 'log' ) );
		$this->assertSame( 'activity', Admin::normalize_screen( 'profile' ) );
		$this->assertSame( 'dashboard', Admin::normalize_screen( 'whats-new' ) );

		$profile = Admin::screen_url( 'profile', array( 'handl_aicac_plugin' => 'ai/ai.php' ) );
		$this->assertStringContainsString( 'page=handl-aicac-activity', $profile );
		$this->assertStringContainsString( 'handl_aicac_tab=profile', $profile );
		$this->assertStringContainsString( 'handl_aicac_plugin=ai%2Fai.php', $profile );
	}

	/**
	 * @return array<string, array{0:array<string,string>,1:string}>
	 */
	public function legacyRedirectProvider(): array {
		return array(
			'dashboard default' => array(
				array( 'page' => 'handl-ai-connector-access-control' ),
				'page=handl-aicac',
			),
			'rules'             => array(
				array(
					'page'            => 'handl-ai-connector-access-control',
					'handl_aicac_tab' => 'rules',
				),
				'page=handl-aicac-rules',
			),
			'activity'          => array(
				array(
					'page'            => 'handl-ai-connector-access-control',
					'handl_aicac_tab' => 'activity',
				),
				'page=handl-aicac-activity',
			),
			'log alias'         => array(
				array(
					'page'            => 'handl-ai-connector-access-control',
					'handl_aicac_tab' => 'log',
				),
				'page=handl-aicac-activity',
			),
			'insights'          => array(
				array(
					'page'            => 'handl-ai-connector-access-control',
					'handl_aicac_tab' => 'insights',
				),
				'page=handl-aicac-insights',
			),
			'profile overlay'   => array(
				array(
					'page'               => 'handl-ai-connector-access-control',
					'handl_aicac_tab'    => 'profile',
					'handl_aicac_plugin' => 'foo/bar.php',
				),
				'page=handl-aicac-activity',
			),
		);
	}

	/**
	 * @dataProvider legacyRedirectProvider
	 * @param array<string,string> $get
	 */
	public function test_legacy_redirect_matrix( array $get, string $needle ): void {
		$url = Admin::legacy_redirect_url( $get );
		$this->assertStringContainsString( 'admin.php', $url );
		$this->assertStringContainsString( $needle, $url );
		$this->assertStringNotContainsString( 'options-general.php', $url );
		if ( isset( $get['handl_aicac_tab'] ) && 'profile' === $get['handl_aicac_tab'] ) {
			$this->assertStringContainsString( 'handl_aicac_tab=profile', $url );
			$this->assertStringContainsString( 'handl_aicac_plugin=', $url );
		}
	}

	public function test_menu_registration_uses_top_level_menu(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringContainsString( 'add_menu_page(', $src );
		$this->assertStringContainsString( 'dashicons-shield-alt', $src );
		$this->assertStringContainsString( "\$cap      = 'manage_options';", $src );
		foreach ( array( 'Protections', 'Policy Tools', 'Alerts & Settings' ) as $label ) {
			$this->assertStringContainsString( $label, $src );
		}
		$this->assertStringContainsString( 'maybe_redirect_legacy_settings_url', $src );
	}
}
