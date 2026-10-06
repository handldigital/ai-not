<?php
/**
 * AICAC-WHY-FILTER (#314).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Admin;
use HandL\AICAC\Audit_Export;
use HandL\AICAC\Pager;
use HandL\AICAC\Plugin;
use HandL\AICAC\Why;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class WhyFilterTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options'] = array();
		unset( $_REQUEST['handl_aicac_log_source'], $_GET['handl_aicac_log_source'] );
		delete_option( Plugin::OPTION_KEY );
		update_option(
			Plugin::OPTION_KEY,
			array(
				'log_enabled' => true,
				'log_limit'   => 200,
			),
			false
		);
	}

	protected function tearDown(): void {
		unset( $_REQUEST['handl_aicac_log_source'], $_GET['handl_aicac_log_source'] );
		parent::tearDown();
	}

	/**
	 * @return array{decision:string,operation:string,provider:string,model:string,plugin:string,source:string}
	 */
	private function filters( string $source = '', string $provider = '' ): array {
		return array(
			'decision'  => '',
			'operation' => '',
			'provider'  => $provider,
			'model'     => '',
			'plugin'    => '',
			'source'    => $source,
		);
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	private function fixture_log(): array {
		return array(
			array(
				'ts'              => 10,
				'decision'        => 'deny',
				'plugin'          => 'budget/budget.php',
				'provider'        => 'openai',
				'decision_source' => 'budget:hard',
			),
			array(
				'ts'              => 20,
				'decision'        => 'allow',
				'plugin'          => 'budget/budget.php',
				'provider'        => 'anthropic',
				'decision_source' => 'budget:observe',
			),
			array(
				'ts'              => 30,
				'decision'        => 'deny',
				'plugin'          => 'cap/cap.php',
				'provider'        => 'openai',
				'decision_source' => 'rate_cap:hourly',
			),
			array(
				'ts'              => 40,
				'decision'        => 'deny',
				'plugin'          => 'ice/ice.php',
				'provider'        => 'openai',
				'decision_source' => 'freeze',
			),
			array(
				'ts'              => 50,
				'decision'        => 'deny',
				'plugin'          => 'rule/rule.php',
				'provider'        => 'openai',
				'decision_source' => 'rule:explicit-deny',
			),
			array(
				'ts'       => 60,
				'decision' => 'allow',
				'plugin'   => 'legacy/legacy.php',
				'provider' => 'openai',
			),
		);
	}

	public function test_buckets_group_stamps_and_legacy(): void {
		$this->assertSame( 'budget', Why::bucket_for_row( array( 'decision_source' => 'budget:hard' ) ) );
		$this->assertSame( 'budget', Why::bucket_for_row( array( 'decision_source' => 'budget:observe' ) ) );
		$this->assertSame( 'rate_cap', Why::bucket_for_row( array( 'decision_source' => 'rate_cap:daily' ) ) );
		$this->assertSame( 'rule', Why::bucket_for_row( array( 'decision_source' => 'rule:explicit-allow' ) ) );
		$this->assertSame( 'default', Why::bucket_for_row( array( 'decision_source' => 'default:deny' ) ) );
		$this->assertSame( Why::FILTER_NONE, Why::bucket_for_row( array( 'decision' => 'allow' ) ) );
		$this->assertSame( Why::FILTER_NONE, Why::bucket_for_row( array( 'decision_source' => '' ) ) );
		$this->assertSame( '', Why::sanitize_filter( 'not-a-bucket' ) );
		$this->assertSame( 'budget', Why::sanitize_filter( 'budget' ) );
	}

	public function test_budget_filter_shows_only_budget_rows(): void {
		$rows = Audit_Export::filtered_rows( $this->fixture_log(), $this->filters( 'budget' ) );
		$this->assertCount( 2, $rows );
		$this->assertSame( array( 'budget:observe', 'budget:hard' ), array_column( $rows, 'decision_source' ) );
	}

	public function test_legacy_bucket_is_only_unstamped_rows(): void {
		$rows = Audit_Export::filtered_rows( $this->fixture_log(), $this->filters( Why::FILTER_NONE ) );
		$this->assertCount( 1, $rows );
		$this->assertSame( 'legacy/legacy.php', $rows[0]['plugin'] );
		$this->assertArrayNotHasKey( 'decision_source', $rows[0] );
	}

	public function test_source_and_provider_compose_and(): void {
		$rows = Audit_Export::filtered_rows( $this->fixture_log(), $this->filters( 'budget', 'openai' ) );
		$this->assertCount( 1, $rows );
		$this->assertSame( 'budget:hard', $rows[0]['decision_source'] );
	}

	public function test_export_contains_exactly_filtered_rows(): void {
		$csv = Audit_Export::build_csv( $this->fixture_log(), $this->filters( 'budget' ), array(), array() );
		$this->assertSame( 2, substr_count( $csv, 'budget/budget.php' ) );
		$this->assertStringNotContainsString( 'cap/cap.php', $csv );
		$this->assertStringNotContainsString( 'legacy/legacy.php', $csv );
		$this->assertStringNotContainsString( 'ice/ice.php', $csv );
		$lines = array_values( array_filter( explode( "\n", trim( $csv ) ) ) );
		$this->assertCount( 3, $lines );
	}

	public function test_pagination_counts_at_25_50_100(): void {
		$log = array();
		for ( $i = 0; $i < 80; $i++ ) {
			$log[] = array(
				'ts'              => 1_700_000_000 + $i,
				'decision'        => 'deny',
				'plugin'          => 'budget/budget.php',
				'provider'        => 'openai',
				'decision_source' => 0 === $i % 2 ? 'budget:hard' : 'budget:observe',
			);
		}
		for ( $i = 0; $i < 10; $i++ ) {
			$log[] = array(
				'ts'              => 1_800_000_000 + $i,
				'decision'        => 'deny',
				'plugin'          => 'cap/cap.php',
				'decision_source' => 'rate_cap:hourly',
			);
		}
		$log[] = array(
			'ts'       => 1_900_000_000,
			'decision' => 'allow',
			'plugin'   => 'legacy/legacy.php',
		);

		$ref     = new ReflectionClass( Admin::class );
		$admin   = $ref->newInstanceWithoutConstructor();
		$collect = $ref->getMethod( 'collect_filtered_log_rows' );
		$collect->setAccessible( true );
		$rows = $collect->invoke( $admin, $log, $this->filters( 'budget' ) );
		$this->assertCount( 80, $rows );

		$this->assertCount( 25, Pager::slice( $rows, 1, 25 ) );
		$this->assertCount( 5, Pager::slice( $rows, 4, 25 ) );
		$this->assertSame( 4, Pager::total_pages( 80, 25 ) );
		$this->assertCount( 50, Pager::slice( $rows, 1, 50 ) );
		$this->assertCount( 30, Pager::slice( $rows, 2, 50 ) );
		$this->assertSame( 2, Pager::total_pages( 80, 50 ) );
		$this->assertCount( 80, Pager::slice( $rows, 1, 100 ) );
		$this->assertSame( 1, Pager::total_pages( 80, 100 ) );
	}

	public function test_parse_source_query_arg_does_not_write_options(): void {
		$before = get_option( Plugin::OPTION_KEY );
		$_REQUEST['handl_aicac_log_source'] = 'budget';
		$ref    = new ReflectionClass( Admin::class );
		$admin  = $ref->newInstanceWithoutConstructor();
		$parse  = $ref->getMethod( 'parse_log_filters' );
		$parse->setAccessible( true );
		$out = $parse->invoke( $admin );
		$this->assertSame( 'budget', $out['source'] );
		$this->assertSame( $before, get_option( Plugin::OPTION_KEY ) );
	}

	public function test_admin_dropdown_uses_issue_copy(): void {
		$src = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-admin.php' );
		$this->assertStringContainsString( 'handl_aicac_log_source', $src );
		$this->assertStringContainsString( 'handl-aicac-log-source-filter', $src );
		$this->assertStringContainsString( 'Why::filter_choices()', $src );
		$this->assertStringContainsString( 'All explanations', $src );
		$why = (string) file_get_contents( HANDL_AICAC_DIR . '/includes/class-handl-aicac-why.php' );
		foreach ( array( 'Explicit rule', 'Role', 'Rate cap', 'Budget' ) as $label ) {
			$this->assertStringContainsString( $label, $why );
		}
		$this->assertStringContainsString( 'Emergency stop', $why );
		$this->assertStringContainsString( 'Newcomer hold', $why );
		$this->assertStringContainsString( 'Quiet hours', $why );
		$this->assertStringContainsString( 'Temporary Allow', $why );
		$this->assertStringContainsString( 'Site default', $why );
		$this->assertStringContainsString( 'No explanation recorded', $why );
	}
}
