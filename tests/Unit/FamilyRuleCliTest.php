<?php
/**
 * Unit tests for family-rule apply/list helpers and CLI validation (AICAC-103).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\CLI;
use HandL\AICAC\Operations;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class FamilyRuleCliTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		require_once HANDL_AICAC_DIR . '/includes/class-handl-aicac-cli.php';
	}

	/**
	 * AC2: deny writes through sanitize_operations shape.
	 */
	public function test_apply_family_rule_sets_deny(): void {
		$policy = array(
			'default'    => 'allow',
			'plugins'    => array(),
			'operations' => array(),
		);

		$updated = Policy::apply_family_rule_to_policy(
			$policy,
			'acme-plugin/acme-plugin.php',
			Operations::FAMILY_TEXT,
			'deny'
		);

		$this->assertIsArray( $updated );
		$this->assertSame(
			array(
				'acme-plugin/acme-plugin.php' => array(
					Operations::FAMILY_TEXT => 'deny',
				),
			),
			$updated['operations']
		);
	}

	/**
	 * Inherit clears a family field and drops empty plugin rows.
	 */
	public function test_apply_family_rule_inherit_clears(): void {
		$plugin = 'acme-plugin/acme-plugin.php';
		$policy = array(
			'operations' => array(
				$plugin => array(
					Operations::FAMILY_TEXT  => 'deny',
					Operations::FAMILY_IMAGE => 'allow',
				),
			),
		);

		$updated = Policy::apply_family_rule_to_policy( $policy, $plugin, Operations::FAMILY_TEXT, 'inherit' );
		$this->assertIsArray( $updated );
		$this->assertSame(
			array( Operations::FAMILY_IMAGE => 'allow' ),
			$updated['operations'][ $plugin ]
		);

		$cleared = Policy::apply_family_rule_to_policy( $updated, $plugin, Operations::FAMILY_IMAGE, 'inherit' );
		$this->assertIsArray( $cleared );
		$this->assertSame( array(), $cleared['operations'] );
	}

	/**
	 * AC3: unrecognized family does not mutate operations.
	 */
	public function test_apply_family_rule_rejects_unknown_family(): void {
		$policy = array(
			'operations' => array(
				'acme-plugin/acme-plugin.php' => array(
					Operations::FAMILY_TEXT => 'allow',
				),
			),
		);
		$before = $policy['operations'];

		$result = Policy::apply_family_rule_to_policy(
			$policy,
			'acme-plugin/acme-plugin.php',
			'music',
			'deny'
		);

		$this->assertFalse( $result );
		$this->assertSame( $before, $policy['operations'] );
	}

	/**
	 * Invalid rule value is rejected (no write semantics).
	 */
	public function test_apply_family_rule_rejects_invalid_rule(): void {
		$result = Policy::apply_family_rule_to_policy(
			array( 'operations' => array() ),
			'acme-plugin/acme-plugin.php',
			Operations::FAMILY_TEXT,
			'block'
		);
		$this->assertFalse( $result );
	}

	/**
	 * Invalid families are stripped by sanitize_operations (shared write path).
	 */
	public function test_sanitize_operations_drops_unknown_family_keys(): void {
		$sanitized = Policy::sanitize_operations(
			array(
				'acme-plugin/acme-plugin.php' => array(
					'text'  => 'deny',
					'music' => 'deny',
					'bogus' => 'allow',
				),
			)
		);

		$this->assertSame(
			array(
				'acme-plugin/acme-plugin.php' => array(
					'text' => 'deny',
				),
			),
			$sanitized
		);
	}

	/**
	 * AC1: list rows cover every installed plugin with family-level state.
	 */
	public function test_family_rule_rows_include_inactive_and_inherit(): void {
		$plugins = array(
			'active-plugin/plugin.php'   => array( 'Name' => 'Active Plugin' ),
			'inactive-plugin/plugin.php' => array( 'Name' => 'Inactive Plugin' ),
		);
		$policy  = array(
			'operations' => array(
				'inactive-plugin/plugin.php' => array(
					Operations::FAMILY_IMAGE => 'deny',
				),
			),
		);
		$active = array( 'active-plugin/plugin.php' => true );

		$rows = Policy::family_rule_rows_for_plugins( $plugins, $policy, $active );

		$this->assertCount( 2, $rows );
		$this->assertSame( 'active-plugin/plugin.php', $rows[0]['plugin'] );
		$this->assertSame( 'active', $rows[0]['status'] );
		$this->assertSame( 'inherit', $rows[0]['text'] );
		$this->assertSame( 'inactive-plugin/plugin.php', $rows[1]['plugin'] );
		$this->assertSame( 'inactive', $rows[1]['status'] );
		$this->assertSame( 'deny', $rows[1]['image'] );
		$this->assertSame( 'inherit', $rows[1]['text'] );
	}

	/**
	 * AC1 empty install → empty list, not an error shape.
	 */
	public function test_family_rule_rows_empty_plugins(): void {
		$this->assertSame( array(), Policy::family_rule_rows_for_plugins( array(), array() ) );
	}

	/**
	 * AC3: CLI validation rejects unknown plugin before write.
	 */
	public function test_cli_validate_rejects_unknown_plugin(): void {
		$error = CLI::validate_set_args(
			'missing/plugin.php',
			'text',
			'deny',
			array( 'acme-plugin/acme-plugin.php' )
		);
		$this->assertNotNull( $error );
		$this->assertStringContainsString( 'Unrecognized plugin basename', $error );
	}

	/**
	 * AC3: CLI validation rejects unknown family.
	 */
	public function test_cli_validate_rejects_unknown_family(): void {
		$error = CLI::validate_set_args(
			'acme-plugin/acme-plugin.php',
			'unknown',
			'deny',
			array( 'acme-plugin/acme-plugin.php' )
		);
		$this->assertNotNull( $error );
		$this->assertStringContainsString( 'Unrecognized capability family', $error );
	}

	/**
	 * Inactive-but-installed plugins are accepted (Rules-tab parity).
	 */
	public function test_cli_validate_accepts_inactive_installed_plugin(): void {
		$error = CLI::validate_set_args(
			'inactive-plugin/plugin.php',
			'tts',
			'allow',
			array( 'inactive-plugin/plugin.php' )
		);
		$this->assertNull( $error );
	}

	/**
	 * AC2 confirmation message for deny and inherit.
	 */
	public function test_cli_confirmation_messages(): void {
		$this->assertSame(
			'Set text family rule for acme-plugin/acme-plugin.php to deny.',
			CLI::set_confirmation_message( 'acme-plugin/acme-plugin.php', 'text', 'deny' )
		);
		$this->assertSame(
			'Cleared text family rule for acme-plugin/acme-plugin.php (inherit).',
			CLI::set_confirmation_message( 'acme-plugin/acme-plugin.php', 'text', 'inherit' )
		);
	}

	/**
	 * AC5: CLI command class exposes list_/set only as public subcommand methods.
	 */
	public function test_cli_public_subcommands_are_list_and_set_only(): void {
		$methods = array();
		foreach ( ( new \ReflectionClass( CLI::class ) )->getMethods( \ReflectionMethod::IS_PUBLIC ) as $method ) {
			if ( $method->class !== CLI::class ) {
				continue;
			}
			if ( $method->isStatic() ) {
				continue;
			}
			$methods[] = $method->name;
		}
		sort( $methods );
		$this->assertSame( array( 'list_', 'set' ), $methods );
	}
}
