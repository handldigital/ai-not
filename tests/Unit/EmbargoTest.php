<?php
/**
 * AICAC-EMBARGO (#371).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Embargo;
use HandL\AICAC\Plugin;
use HandL\AICAC\Policy;
use PHPUnit\Framework\TestCase;

final class EmbargoTest extends TestCase {

	private const DRAFT_BODY = 'Confidential earnings draft for Q4 shows revenue up twenty percent and board memo private.';

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['handl_aicac_test_options']          = array();
		$GLOBALS['handl_aicac_test_user_id']          = 12;
		$GLOBALS['handl_aicac_test_post_meta']        = array();
		$GLOBALS['handl_aicac_test_current_user_can'] = true;
		Embargo::reset_for_tests();
		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => false,
			)
		);
		update_option( Plugin::LOG_OPTION_KEY, array(), false );
	}

	protected function tearDown(): void {
		unset( $GLOBALS['handl_aicac_test_current_user_can'] );
		$GLOBALS['handl_aicac_test_options']   = array();
		$GLOBALS['handl_aicac_test_user_id']   = 0;
		$GLOBALS['handl_aicac_test_post_meta'] = array();
		Embargo::reset_for_tests();
		parent::tearDown();
	}

	/**
	 * @return array<string,mixed>
	 */
	private function draft_post( int $id = 77, string $status = 'draft' ): array {
		return array(
			'ID'            => $id,
			'post_status'   => $status,
			'post_title'    => 'Earnings draft',
			'post_content'  => self::DRAFT_BODY,
			'post_password' => '',
			'post_type'     => 'post',
		);
	}

	private function enable( string $mode = Embargo::MODE_WARN ): void {
		Embargo::save_settings(
			array(
				'enabled' => true,
				'mode'    => $mode,
			)
		);
		Embargo::rebuild_index( array( $this->draft_post() ) );
	}

	private function payload_builder( string $text ): object {
		$builder = new \stdClass();
		$builder->handl_aicac_test_payload = $text;

		return $builder;
	}

	public function test_disabled_never_prevents_or_annotates(): void {
		Embargo::save_settings(
			array(
				'enabled' => false,
				'mode'    => Embargo::MODE_ENFORCE,
			)
		);
		Embargo::rebuild_index( array( $this->draft_post() ) );
		$this->assertFalse( Embargo::is_enabled() );
		$this->assertFalse( Embargo::maybe_prevent_prompt( false, $this->payload_builder( self::DRAFT_BODY ) ) );
		$this->assertSame( array(), get_option( Plugin::LOG_OPTION_KEY, array() ) );
		$this->assertSame( array(), Embargo::hits() );
	}

	public function test_detects_draft_chunk_in_warn_mode(): void {
		$this->enable( Embargo::MODE_WARN );
		$hit = Embargo::match_payload( 'Please rewrite: ' . self::DRAFT_BODY );
		$this->assertNotNull( $hit );
		$this->assertSame( 77, (int) $hit['post_id'] );

		$prevent = Embargo::maybe_prevent_prompt( false, $this->payload_builder( 'Please rewrite: ' . self::DRAFT_BODY ) );
		$this->assertFalse( $prevent );

		$log  = get_option( Plugin::LOG_OPTION_KEY, array() );
		$last = $log[ count( $log ) - 1 ];
		$this->assertSame( 'allow', $last['decision'] ?? '' );
		$this->assertSame( 'deny', $last['would_decision'] ?? '' );
		$this->assertSame( 'embargo_warn', $last['decision_source'] ?? '' );
		$this->assertSame( Embargo::MODE_WARN, $last['embargo'] ?? '' );
		$this->assertSame( 77, (int) ( $last['embargo_hit'] ?? 0 ) );
		$this->assertCount( 1, Embargo::hits() );
	}

	public function test_enforce_denies_with_embargoed_content(): void {
		$this->enable( Embargo::MODE_ENFORCE );

		Policy::append_log_event(
			array(
				'ts'       => 1_700_000_001,
				'decision' => 'allow',
				'user_id'  => 12,
			)
		);

		$prevent = Embargo::maybe_prevent_prompt( false, $this->payload_builder( self::DRAFT_BODY ) );
		$this->assertTrue( $prevent );

		$log  = get_option( Plugin::LOG_OPTION_KEY, array() );
		$last = $log[ count( $log ) - 1 ];
		$this->assertSame( 'deny', $last['decision'] ?? '' );
		$this->assertSame( Embargo::REASON, $last['denial_reason'] ?? '' );
		$this->assertSame( Embargo::REASON, $last['decision_source'] ?? '' );
		$this->assertSame( 77, (int) ( $last['embargo_hit'] ?? 0 ) );
	}

	public function test_publish_transition_drops_from_index(): void {
		$post = $this->draft_post();
		Embargo::rebuild_index( array( $post ) );
		$this->assertArrayHasKey( '77', Embargo::get_index()['posts'] );

		$published               = $post;
		$published['post_status'] = 'publish';
		Embargo::on_transition_status( 'publish', 'draft', $published );

		$this->assertArrayNotHasKey( '77', Embargo::get_index()['posts'] );
		$this->assertNull( Embargo::match_payload( self::DRAFT_BODY ) );
	}

	public function test_per_post_override_bypasses_guard(): void {
		$this->enable( Embargo::MODE_ENFORCE );
		Embargo::set_override( 77, true );
		$this->assertTrue( Embargo::is_override_allowed( 77 ) );
		$this->assertNull( Embargo::match_payload( self::DRAFT_BODY ) );
		$this->assertFalse( Embargo::maybe_prevent_prompt( false, $this->payload_builder( self::DRAFT_BODY ) ) );
	}

	public function test_index_never_stores_plaintext(): void {
		Embargo::rebuild_index( array( $this->draft_post() ) );
		$raw = get_option( Embargo::INDEX_OPTION, array() );
		$json = wp_json_encode( $raw );
		$this->assertIsString( $json );
		$this->assertStringNotContainsString( 'Confidential earnings', (string) $json );
		$this->assertStringNotContainsString( 'twenty percent', (string) $json );
		foreach ( Embargo::get_index()['posts'] as $row ) {
			foreach ( $row['hashes'] as $h ) {
				$this->assertMatchesRegularExpression( '/^[a-f0-9]{64}$/', $h );
			}
		}
	}

	public function test_password_protected_is_non_public(): void {
		$post = $this->draft_post( 88, 'publish' );
		$post['post_password'] = 'secret';
		$this->assertTrue( Embargo::is_non_public( $post ) );
		Embargo::rebuild_index( array( $post ) );
		$this->assertArrayHasKey( '88', Embargo::get_index()['posts'] );
	}

	public function test_prior_prevent_unchanged_and_audit_only_skips(): void {
		$this->enable( Embargo::MODE_ENFORCE );
		$this->assertTrue( Embargo::maybe_prevent_prompt( true, $this->payload_builder( self::DRAFT_BODY ) ) );

		update_option(
			Plugin::OPTION_KEY,
			array(
				'default'     => 'allow',
				'log_enabled' => true,
				'audit_only'  => true,
			)
		);
		$this->assertFalse( Embargo::maybe_prevent_prompt( false, $this->payload_builder( self::DRAFT_BODY ) ) );
	}

	public function test_csv_and_roster(): void {
		$this->enable( Embargo::MODE_WARN );
		Embargo::maybe_prevent_prompt( false, $this->payload_builder( self::DRAFT_BODY ) );
		$csv = Embargo::csv_for_hits();
		$this->assertStringContainsString( 'post_id', $csv );
		$this->assertStringContainsString( '77', $csv );
		$roster = Embargo::indexed_roster();
		$this->assertNotEmpty( $roster );
		$this->assertSame( 77, (int) $roster[0]['id'] );
	}
}
