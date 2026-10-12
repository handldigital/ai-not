<?php
/**
 * AICAC-EXIT-INTERVIEW (#328): payload builder + local option write.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Exit_Interview;
use PHPUnit\Framework\TestCase;

final class ExitInterviewTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		Exit_Interview::reset_for_tests();
	}

	protected function tearDown(): void {
		Exit_Interview::reset_for_tests();
		parent::tearDown();
	}

	public function test_build_payload_rejects_unknown_reason(): void {
		$this->assertNull( Exit_Interview::build_payload( 'nope' ) );
	}

	public function test_build_payload_requires_other_text_for_other(): void {
		$this->assertNull( Exit_Interview::build_payload( 'other', '' ) );
		$this->assertNull( Exit_Interview::build_payload( 'other', '   ' ) );
	}

	public function test_build_payload_accepts_known_reasons(): void {
		$payload = Exit_Interview::build_payload(
			'testing',
			'',
			array(
				'user_login' => 'qa-admin',
				'site_url'   => 'https://example.test/',
				'now'        => 1_700_000_000,
			)
		);
		$this->assertIsArray( $payload );
		$this->assertSame( 'testing', $payload['reason'] );
		$this->assertSame( '', $payload['other'] );
		$this->assertSame( 'qa-admin', $payload['user'] );
		$this->assertSame( 'https://example.test/', $payload['site'] );
		$this->assertSame( 1_700_000_000, $payload['ts'] );
	}

	public function test_build_payload_truncates_other_text(): void {
		$long    = str_repeat( 'a', Exit_Interview::OTHER_MAX + 40 );
		$payload = Exit_Interview::build_payload( 'other', $long, array( 'now' => 10 ) );
		$this->assertIsArray( $payload );
		$this->assertSame( Exit_Interview::OTHER_MAX, strlen( $payload['other'] ) );
	}

	public function test_store_submission_writes_option(): void {
		$payload = Exit_Interview::build_payload(
			'complex',
			'',
			array(
				'user_login' => 'alice',
				'site_url'   => 'https://example.test/',
				'now'        => 1_700_000_100,
			)
		);
		$this->assertIsArray( $payload );

		$rows = Exit_Interview::store_submission( $payload );
		$this->assertCount( 1, $rows );
		$this->assertSame( 'complex', $rows[0]['reason'] );

		$stored = get_option( Exit_Interview::OPTION_KEY );
		$this->assertIsArray( $stored );
		$this->assertSame( 'complex', $stored['last']['reason'] );
		$this->assertSame( 'alice', $stored['last']['user'] );
	}

	public function test_store_submission_caps_history(): void {
		for ( $i = 0; $i < Exit_Interview::HISTORY_MAX + 5; $i++ ) {
			$payload = Exit_Interview::build_payload(
				'testing',
				'',
				array(
					'user_login' => 'u' . $i,
					'site_url'   => 'https://example.test/',
					'now'        => 1_700_000_000 + $i,
				)
			);
			Exit_Interview::store_submission( $payload );
		}
		$stored = get_option( Exit_Interview::OPTION_KEY );
		$this->assertCount( Exit_Interview::HISTORY_MAX, $stored['submissions'] );
		$this->assertSame( 'u' . ( Exit_Interview::HISTORY_MAX + 4 ), $stored['last']['user'] );
	}
}
