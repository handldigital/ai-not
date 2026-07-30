<?php
/**
 * Capability-family mapping for AI Client operations.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Maps WP AI Client method names onto capability families.
 *
 * is_supported_for_* and matching generate_* share the same family so a
 * support check cannot pass while generation is denied (or vice versa).
 */
final class Operations {
	public const FAMILY_TEXT    = 'text';
	public const FAMILY_IMAGE   = 'image';
	public const FAMILY_SPEECH  = 'speech';
	public const FAMILY_TTS     = 'tts';
	public const FAMILY_VIDEO   = 'video';
	public const FAMILY_UNKNOWN = 'unknown';

	/**
	 * Ordered families shown in the admin matrix (excludes unknown).
	 *
	 * @return list<string>
	 */
	public static function families(): array {
		return array(
			self::FAMILY_TEXT,
			self::FAMILY_IMAGE,
			self::FAMILY_SPEECH,
			self::FAMILY_TTS,
			self::FAMILY_VIDEO,
		);
	}

	/**
	 * @return array<string,string> family_id => label
	 */
	public static function family_labels(): array {
		return array(
			self::FAMILY_TEXT   => __( 'Text', 'handl-ai-connector-access-control' ),
			self::FAMILY_IMAGE  => __( 'Image', 'handl-ai-connector-access-control' ),
			self::FAMILY_SPEECH => __( 'Speech', 'handl-ai-connector-access-control' ),
			self::FAMILY_TTS    => __( 'TTS', 'handl-ai-connector-access-control' ),
			self::FAMILY_VIDEO  => __( 'Video', 'handl-ai-connector-access-control' ),
		);
	}

	/**
	 * Resolve a capability family from an AI Client method name.
	 *
	 * Unknown or empty operations return FAMILY_UNKNOWN so callers can apply
	 * an explicit fallback (never an implicit random path).
	 */
	public static function family_from_operation( string $operation ): string {
		$operation = trim( $operation );
		if ( '' === $operation ) {
			return self::FAMILY_UNKNOWN;
		}

		$map = self::operation_map();
		if ( isset( $map[ $operation ] ) ) {
			return $map[ $operation ];
		}

		// Prefix heuristics for forward-compatible method names.
		if ( 0 === strpos( $operation, 'is_supported_for_text' ) || 0 === strpos( $operation, 'generate_text' ) ) {
			return self::FAMILY_TEXT;
		}
		if ( 0 === strpos( $operation, 'is_supported_for_image' ) || 0 === strpos( $operation, 'generate_image' ) ) {
			return self::FAMILY_IMAGE;
		}
		if ( 0 === strpos( $operation, 'is_supported_for_speech' ) || 0 === strpos( $operation, 'generate_speech' ) ) {
			return self::FAMILY_SPEECH;
		}
		if (
			0 === strpos( $operation, 'is_supported_for_text_to_speech' )
			|| 0 === strpos( $operation, 'convert_text_to_speech' )
		) {
			return self::FAMILY_TTS;
		}
		if ( 0 === strpos( $operation, 'is_supported_for_video' ) || 0 === strpos( $operation, 'generate_video' ) ) {
			return self::FAMILY_VIDEO;
		}

		// Generic is_supported / generate_result without a family suffix.
		return self::FAMILY_UNKNOWN;
	}

	/**
	 * @return array<string,string> operation => family
	 */
	private static function operation_map(): array {
		return array(
			// Text.
			'generate_text'                    => self::FAMILY_TEXT,
			'generate_texts'                   => self::FAMILY_TEXT,
			'generate_text_result'             => self::FAMILY_TEXT,
			'is_supported_for_text_generation' => self::FAMILY_TEXT,

			// Image.
			'generate_image'                    => self::FAMILY_IMAGE,
			'generate_images'                   => self::FAMILY_IMAGE,
			'generate_image_result'             => self::FAMILY_IMAGE,
			'is_supported_for_image_generation' => self::FAMILY_IMAGE,

			// Speech (audio generation).
			'generate_speech'                    => self::FAMILY_SPEECH,
			'generate_speeches'                  => self::FAMILY_SPEECH,
			'generate_speech_result'             => self::FAMILY_SPEECH,
			'is_supported_for_speech_generation' => self::FAMILY_SPEECH,

			// Text-to-speech conversion.
			'convert_text_to_speech'                    => self::FAMILY_TTS,
			'convert_text_to_speeches'                  => self::FAMILY_TTS,
			'convert_text_to_speech_result'             => self::FAMILY_TTS,
			'is_supported_for_text_to_speech_conversion' => self::FAMILY_TTS,

			// Video.
			'generate_video'                    => self::FAMILY_VIDEO,
			'generate_videos'                   => self::FAMILY_VIDEO,
			'generate_video_result'             => self::FAMILY_VIDEO,
			'is_supported_for_video_generation' => self::FAMILY_VIDEO,

			// Known but not in the admin matrix — treated as unknown so the
			// configured unknown-operation fallback applies explicitly.
			'is_supported_for_music_generation'     => self::FAMILY_UNKNOWN,
			'is_supported_for_embedding_generation' => self::FAMILY_UNKNOWN,
			'is_supported'                          => self::FAMILY_UNKNOWN,
			'generate_result'                       => self::FAMILY_UNKNOWN,
		);
	}
}
