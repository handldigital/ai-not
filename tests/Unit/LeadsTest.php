<?php
/**
 * Unit tests for AICAC-LEADS opt-in registration.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Leads;
use HandL\AICAC\Onboarding;
use PHPUnit\Framework\TestCase;

final class LeadsTest extends TestCase {

	/** @var list<array{url:string,args:array}> */
	private static array $posts = array();

	protected function setUp(): void {
		self::$posts                        = array();
		$GLOBALS['handl_aicac_test_options'] = array();
		unset( $GLOBALS['handl_aicac_test_filters'] );
		$GLOBALS['handl_aicac_wp_remote_post'] = static function ( string $url, array $args ) {
			self::$posts[] = array(
				'url'  => $url,
				'args' => $args,
			);
			return array(
				'response' => array( 'code' => 200 ),
				'body'     => '{"ok":true}',
			);
		};
		parent::setUp();
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_wp_remote_post'], $GLOBALS['handl_aicac_test_filters'] );
		$GLOBALS['handl_aicac_test_options'] = array();
		parent::tearDown();
	}

	public function test_no_consent_performs_zero_http_calls(): void {
		$ok = Leads::maybe_register( 'haktan+aicac-leads@handldigital.com', false );
		$this->assertFalse( $ok );
		$this->assertSame( array(), self::$posts, 'No-consent path must not call wp_remote_post' );
	}

	public function test_consent_posts_payload_once(): void {
		$ok = Leads::maybe_register( 'haktan+aicac-leads@handldigital.com', true );
		$this->assertTrue( $ok );
		$this->assertCount( 1, self::$posts );

		$post = self::$posts[0];
		$this->assertSame( Leads::DEFAULT_ENDPOINT, $post['url'] );
		$this->assertSame(
			Leads::DEFAULT_TOKEN,
			$post['args']['headers']['X-HandL-AICAC-Token'] ?? null
		);

		$body = json_decode( (string) ( $post['args']['body'] ?? '' ), true );
		$this->assertIsArray( $body );
		$this->assertSame( 'haktan+aicac-leads@handldigital.com', $body['email'] );
		$this->assertArrayHasKey( 'site_url', $body );
		$this->assertArrayHasKey( 'plugin_version', $body );
		$this->assertArrayHasKey( 'consented_at', $body );
		$this->assertNotSame( '', $body['consented_at'] );
	}

	public function test_invalid_email_skips_http(): void {
		$ok = Leads::maybe_register( 'not-an-email', true );
		$this->assertFalse( $ok );
		$this->assertSame( array(), self::$posts );
	}

	public function test_build_payload_shape(): void {
		$payload = Leads::build_payload( 'haktan+leads@handldigital.com', 1700000000 );
		$this->assertIsArray( $payload );
		$this->assertSame( 'haktan+leads@handldigital.com', $payload['email'] );
		$this->assertSame( '2023-11-14T22:13:20+00:00', $payload['consented_at'] );
		$this->assertSame( HANDL_AICAC_VERSION, $payload['plugin_version'] );
	}

	public function test_onboard_state_defaults_leads_consent_false(): void {
		$state = Onboarding::sanitize_state( array() );
		$this->assertFalse( $state['leads_consent'] );
	}

	public function test_wizard_has_unchecked_consent_checkbox(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringContainsString( 'handl_aicac_onboard_leads_consent', $src );
		// Must not be pre-checked in the markup.
		$this->assertDoesNotMatchRegularExpression(
			'/name="handl_aicac_onboard_leads_consent"[^>]*checked/',
			$src
		);
		// Finish path calls Leads only when consent stored.
		$this->assertStringContainsString( 'Leads::maybe_register', $src );
	}

	public function test_privacy_discloses_opt_in_transmission(): void {
		$readme = (string) file_get_contents( HANDL_AICAC_DIR . '/readme.txt' );
		$this->assertStringContainsString( 'product news and related offers', $readme );
		$this->assertStringContainsString( 'off by default', $readme );
		$this->assertStringContainsString( 'support@handldigital.com', $readme );
	}

	public function test_release_and_deploy_exclude_server(): void {
		$release = (string) file_get_contents( HANDL_AICAC_DIR . '/.github/workflows/release.yml' );
		$this->assertStringContainsString( '--exclude "server/"', $release );

		$deploy = (string) file_get_contents( HANDL_AICAC_DIR . '/deploy.sh' );
		$this->assertStringContainsString( 'server', $deploy );
		$this->assertMatchesRegularExpression( '/exclude.*server|server\/\*\*/', $deploy );

		// Server intake must exist in-repo for deploy, but not load in the plugin bootstrap.
		$this->assertFileExists( HANDL_AICAC_DIR . '/server/leads/public/index.php' );
		$main = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-plugin.php' );
		$this->assertStringNotContainsString( 'server/leads', $main );
	}

	public function test_dry_run_release_rsync_drops_server(): void {
		$tmp = sys_get_temp_dir() . '/aicac-leads-pack-' . getmypid();
		if ( is_dir( $tmp ) ) {
			$this->rm_tree( $tmp );
		}
		mkdir( $tmp . '/out', 0755, true );

		$cmd = sprintf(
			'rsync -a --exclude ".git/" --exclude ".github/" --exclude "dist/" --exclude ".DS_Store" --exclude "wordpress-org/" --exclude "server/" --exclude "vendor/" --exclude "tests/" --exclude "composer.json" --exclude "composer.lock" --exclude "phpunit.xml.dist" --exclude ".gitignore" --exclude "deploy.sh" --exclude "*.md" %s/ %s/out/',
			escapeshellarg( HANDL_AICAC_DIR ),
			escapeshellarg( $tmp )
		);
		// escapeshellarg already quoted paths; rebuild without double-quoting.
		$cmd = 'rsync -a'
			. ' --exclude ".git/"'
			. ' --exclude ".github/"'
			. ' --exclude "dist/"'
			. ' --exclude ".DS_Store"'
			. ' --exclude "wordpress-org/"'
			. ' --exclude "server/"'
			. ' --exclude "vendor/"'
			. ' --exclude "tests/"'
			. ' --exclude "composer.json"'
			. ' --exclude "composer.lock"'
			. ' --exclude "phpunit.xml.dist"'
			. ' --exclude ".gitignore"'
			. ' --exclude "deploy.sh"'
			. ' --exclude "*.md"'
			. ' ' . escapeshellarg( HANDL_AICAC_DIR . '/' )
			. ' ' . escapeshellarg( $tmp . '/out/' );

		exec( $cmd, $out, $code );
		$this->assertSame( 0, $code, 'rsync dry packaging failed: ' . implode( "\n", $out ) );
		$this->assertDirectoryDoesNotExist( $tmp . '/out/server' );
		$this->assertFileExists( $tmp . '/out/handl-ai-connector-access-control.php' );
		$this->assertFileExists( $tmp . '/out/includes/class-handl-aicac-leads.php' );

		$this->rm_tree( $tmp );
	}

	private function rm_tree( string $dir ): void {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$it = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ( $it as $file ) {
			$path = $file->getPathname();
			if ( $file->isDir() ) {
				rmdir( $path );
			} else {
				unlink( $path );
			}
		}
		rmdir( $dir );
	}
}
