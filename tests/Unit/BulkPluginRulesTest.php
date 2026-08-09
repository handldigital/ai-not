<?php
/**
 * Unit tests for AICAC-BULK plugin-level bulk allow/deny.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class BulkPluginRulesTest extends TestCase {

	/**
	 * Bulk deny updates only the selected installed plugins.
	 */
	public function test_bulk_deny_updates_only_selected(): void {
		$policy = array(
			'plugins' => array(
				'alpha/alpha.php' => 'allow',
				'beta/beta.php'   => 'allow',
				'gamma/gamma.php' => 'deny',
			),
			'operations' => array(
				'alpha/alpha.php' => array( 'text' => 'deny' ),
			),
			'model_force_plugins' => array(
				'alpha/alpha.php' => array( 'provider' => 'openai', 'model' => 'gpt-4o' ),
			),
		);
		$installed = array(
			'alpha/alpha.php' => array( 'Name' => 'Alpha' ),
			'beta/beta.php'   => array( 'Name' => 'Beta' ),
			'gamma/gamma.php' => array( 'Name' => 'Gamma' ),
		);

		$result = Policy::apply_bulk_plugin_rules(
			$policy,
			array( 'alpha/alpha.php', 'beta/beta.php' ),
			'deny',
			$installed
		);

		$this->assertIsArray( $result );
		$this->assertSame( 2, $result['updated'] );
		$this->assertSame( 'deny', $result['policy']['plugins']['alpha/alpha.php'] );
		$this->assertSame( 'deny', $result['policy']['plugins']['beta/beta.php'] );
		$this->assertSame( 'deny', $result['policy']['plugins']['gamma/gamma.php'] );
		// Family + force maps untouched.
		$this->assertSame(
			array( 'text' => 'deny' ),
			$result['policy']['operations']['alpha/alpha.php']
		);
		$this->assertSame(
			array( 'provider' => 'openai', 'model' => 'gpt-4o' ),
			$result['policy']['model_force_plugins']['alpha/alpha.php']
		);
	}

	/**
	 * Empty selection is a no-op (updated=0); policy plugins map unchanged.
	 */
	public function test_empty_selection_is_noop(): void {
		$policy = array(
			'plugins' => array(
				'alpha/alpha.php' => 'allow',
			),
		);
		$installed = array(
			'alpha/alpha.php' => array( 'Name' => 'Alpha' ),
		);

		$result = Policy::apply_bulk_plugin_rules( $policy, array(), 'deny', $installed );
		$this->assertIsArray( $result );
		$this->assertSame( 0, $result['updated'] );
		$this->assertSame( array( 'alpha/alpha.php' => 'allow' ), $result['policy']['plugins'] );
	}

	/**
	 * Posted basenames not in the installed list are skipped (no trust of arbitrary POST).
	 */
	public function test_rejects_unknown_basenames(): void {
		$policy = array(
			'plugins' => array(
				'alpha/alpha.php' => 'allow',
			),
		);
		$installed = array(
			'alpha/alpha.php' => array( 'Name' => 'Alpha' ),
		);

		$result = Policy::apply_bulk_plugin_rules(
			$policy,
			array( 'evil/evil.php', 'alpha/alpha.php' ),
			'deny',
			$installed
		);

		$this->assertIsArray( $result );
		$this->assertSame( 1, $result['updated'] );
		$this->assertSame( 1, $result['skipped'] );
		$this->assertArrayNotHasKey( 'evil/evil.php', $result['policy']['plugins'] );
		$this->assertSame( 'deny', $result['policy']['plugins']['alpha/alpha.php'] );
	}

	/**
	 * Invalid bulk action string fails closed.
	 */
	public function test_invalid_rule_returns_false(): void {
		$this->assertFalse(
			Policy::apply_bulk_plugin_rules(
				array( 'plugins' => array() ),
				array( 'alpha/alpha.php' ),
				'maybe',
				array( 'alpha/alpha.php' => array( 'Name' => 'Alpha' ) )
			)
		);
	}

	/**
	 * Authz inventory: bulk action reuses save_policy nonce (static source check).
	 */
	public function test_admin_bulk_action_reuses_save_policy_nonce(): void {
		$source = file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertNotFalse( $source );
		$this->assertMatchesRegularExpression(
			"/'bulk_plugin_rules'\\s*===\\s*\\\$posted_action[\\s\\S]{0,200}check_admin_referer\\s*\\(\\s*'handl_aicac_save_policy'/",
			$source
		);
		$this->assertMatchesRegularExpression(
			'/private\\s+function\\s+handle_bulk_plugin_rules\\s*\\(/',
			$source
		);
	}
}
