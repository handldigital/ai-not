<?php
/**
 * Unit tests for Operations capability-family mapping.
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use HandL\AICAC\Operations;
use PHPUnit\Framework\TestCase;

final class OperationsFamilyTest extends TestCase {

	/**
	 * Known generate_* methods map to their families.
	 *
	 * @dataProvider known_operation_provider
	 */
	public function test_known_operations_map_to_family( string $operation, string $family ): void {
		$this->assertSame( $family, Operations::family_from_operation( $operation ) );
	}

	/**
	 * @return array<string,array{0:string,1:string}>
	 */
	public function known_operation_provider(): array {
		return array(
			'text'   => array( 'generate_text', Operations::FAMILY_TEXT ),
			'image'  => array( 'generate_image', Operations::FAMILY_IMAGE ),
			'speech' => array( 'generate_speech', Operations::FAMILY_SPEECH ),
			'tts'    => array( 'convert_text_to_speech', Operations::FAMILY_TTS ),
			'video'  => array( 'generate_video', Operations::FAMILY_VIDEO ),
		);
	}

	/**
	 * TTS prefix must win over Text so unmapped TTS names are not misclassified.
	 */
	public function test_tts_prefix_wins_over_text_prefix(): void {
		$this->assertSame(
			Operations::FAMILY_TTS,
			Operations::family_from_operation( 'is_supported_for_text_to_speech_custom' )
		);
	}

	/**
	 * Empty / unknown operations stay unknown (unknown_operation fallback applies).
	 */
	public function test_empty_and_unmapped_are_unknown(): void {
		$this->assertSame( Operations::FAMILY_UNKNOWN, Operations::family_from_operation( '' ) );
		$this->assertSame(
			Operations::FAMILY_UNKNOWN,
			Operations::family_from_operation( 'is_supported_for_music_generation' )
		);
	}

	/**
	 * Generic generate_result uses inferred capability when provided.
	 */
	public function test_generate_result_uses_inferred_capability(): void {
		$this->assertSame(
			Operations::FAMILY_IMAGE,
			Operations::family_from_operation( 'generate_result', 'image_generation' )
		);
		$this->assertSame(
			Operations::FAMILY_UNKNOWN,
			Operations::family_from_operation( 'generate_result', null )
		);
	}

	/**
	 * Capability enum-style strings normalize to families.
	 */
	public function test_family_from_capability_normalizes(): void {
		$this->assertSame( Operations::FAMILY_TEXT, Operations::family_from_capability( 'textGeneration' ) );
		$this->assertSame( Operations::FAMILY_TTS, Operations::family_from_capability( 'text-to-speech-conversion' ) );
		$this->assertSame( Operations::FAMILY_UNKNOWN, Operations::family_from_capability( null ) );
	}
}
