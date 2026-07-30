<?php
/**
 * Best-effort extraction of prompt builder context for logging.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Prompt_Snapshot {
	private const PROMPT_PREVIEW_MAX = 240;

	/**
	 * @param mixed $builder WP_AI_Client_Prompt_Builder clone (read-only).
	 * @return array<string,mixed>
	 */
	public static function from_builder( $builder ): array {
		if ( ! is_object( $builder ) || ! class_exists( 'WP_AI_Client_Prompt_Builder', false ) ) {
			return array();
		}
		if ( ! $builder instanceof \WP_AI_Client_Prompt_Builder ) {
			return array();
		}

		try {
			$inner = self::get_inner_builder( $builder );
			if ( null === $inner ) {
				return array();
			}

			$operation = self::operation_from_backtrace();
			$op_name   = isset( $operation['operation'] ) ? (string) $operation['operation'] : '';

			// Resolve capability once; reuse for provider/model inference and family mapping.
			// Generic is_supported / generate_result only get a real family when inference works.
			$capability = self::capability_from_operation( $inner, $op_name );
			$family     = Operations::family_from_operation( $op_name, $capability );

			return array_merge(
				$operation,
				self::extract_provider_model( $inner, $op_name, $capability ),
				self::extract_config( $inner ),
				array(
					'prompt_preview'    => self::extract_prompt_preview( $inner ),
					'capability_family' => $family,
				)
			);
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			return array();
		}
	}

	/**
	 * @return array{operation?:string}
	 */
	private static function operation_from_backtrace(): array {
		$trace = ( new \Exception() )->getTrace();
		foreach ( $trace as $frame ) {
			if ( ( $frame['class'] ?? '' ) !== 'WP_AI_Client_Prompt_Builder' ) {
				continue;
			}
			if ( ( $frame['function'] ?? '' ) !== '__call' ) {
				continue;
			}
			$name = $frame['args'][0] ?? null;
			if ( is_string( $name ) && '' !== $name ) {
				return array( 'operation' => $name );
			}
		}
		return array();
	}

	/**
	 * @param object     $inner PromptBuilder instance.
	 * @param string     $operation AI Client method that triggered the filter.
	 * @param mixed|null $capability Pre-resolved CapabilityEnum (avoids double work).
	 * @return array<string,mixed>
	 */
	private static function extract_provider_model( object $inner, string $operation, $capability = null ): array {
		$ref = new \ReflectionClass( $inner );

		$provider    = self::read_property( $ref, $inner, 'providerIdOrClassName' );
		$preferences = self::read_property( $ref, $inner, 'modelPreferenceKeys' );
		$model       = self::read_property( $ref, $inner, 'model' );

		$out = array(
			'provider'          => is_string( $provider ) && '' !== $provider ? $provider : null,
			'model'             => null,
			'model_preferences' => null,
			'model_inferred'    => false,
		);

		if ( is_array( $preferences ) && ! empty( $preferences ) ) {
			$out['model_preferences'] = array_values(
				array_map(
					static function ( $key ): string {
						return is_string( $key ) ? $key : '';
					},
					$preferences
				)
			);
		}

		if ( is_object( $model ) && method_exists( $model, 'metadata' ) && method_exists( $model, 'providerMetadata' ) ) {
			try {
				$meta = $model->metadata();
				$prov = $model->providerMetadata();
				if ( is_object( $meta ) && method_exists( $meta, 'getId' ) ) {
					$out['model'] = (string) $meta->getId();
				}
				if ( is_object( $prov ) && method_exists( $prov, 'getId' ) ) {
					$out['provider'] = (string) $prov->getId();
				}
			} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
				// Best-effort only.
			}
		}

		if ( null === $out['model'] || null === $out['provider'] ) {
			$inferred = self::resolve_inferred_provider_model(
				$inner,
				$operation,
				is_array( $preferences ) ? $preferences : array(),
				$capability
			);
			if ( null !== $inferred['provider'] && null === $out['provider'] ) {
				$out['provider'] = $inferred['provider'];
			}
			if ( null !== $inferred['model'] && null === $out['model'] ) {
				$out['model'] = $inferred['model'];
			}
			if ( ! empty( $inferred['model_inferred'] ) ) {
				$out['model_inferred'] = true;
			}
		}

		if ( is_string( $out['provider'] ) && '' !== $out['provider'] ) {
			$out['provider'] = self::normalize_provider_id( $inner, $out['provider'] );
		}

		return $out;
	}

	/**
	 * Resolve the provider/model WordPress AI Client would pick for this prompt.
	 *
	 * @param object              $inner PromptBuilder instance.
	 * @param string              $operation AI Client method name.
	 * @param array<int,string>   $preferences Model preference keys from the builder.
	 * @param mixed|null          $capability Pre-resolved CapabilityEnum or null.
	 * @return array{provider:?string,model:?string,model_inferred:bool}
	 */
	private static function resolve_inferred_provider_model( object $inner, string $operation, array $preferences, $capability = null ): array {
		$empty = array(
			'provider'       => null,
			'model'          => null,
			'model_inferred' => false,
		);

		if ( ! class_exists( 'WordPress\\AiClient\\Providers\\Models\\DTO\\ModelRequirements' ) ) {
			return $empty;
		}

		$ref         = new \ReflectionClass( $inner );
		$messages    = self::read_property( $ref, $inner, 'messages' );
		$model_config = self::read_property( $ref, $inner, 'modelConfig' );
		if ( ! is_array( $messages ) || ! is_object( $model_config ) ) {
			return $empty;
		}

		if ( null === $capability ) {
			$capability = self::capability_from_operation( $inner, $operation );
		}
		if ( null === $capability ) {
			return $empty;
		}

		try {
			$requirements = \WordPress\AiClient\Providers\Models\DTO\ModelRequirements::fromPromptData(
				$capability,
				$messages,
				$model_config
			);
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			return $empty;
		}

		try {
			$method = $ref->getMethod( 'getCandidateModelsMap' );
			$method->setAccessible( true );
			$candidate_map = $method->invoke( $inner, $requirements );
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			return $empty;
		}

		if ( ! is_array( $candidate_map ) || empty( $candidate_map ) ) {
			return $empty;
		}

		$provider_id = null;
		$model_id    = null;

		if ( ! empty( $preferences ) ) {
			$matching = array_intersect_key( array_flip( $preferences ), $candidate_map );
			if ( ! empty( $matching ) ) {
				$first_key = array_key_first( $matching );
				if ( is_string( $first_key ) && isset( $candidate_map[ $first_key ] ) ) {
					$tuple = $candidate_map[ $first_key ];
					if ( is_array( $tuple ) && count( $tuple ) >= 2 ) {
						$provider_id = (string) $tuple[0];
						$model_id    = (string) $tuple[1];
					}
				}
			}
		}

		if ( null === $provider_id || null === $model_id ) {
			$first = reset( $candidate_map );
			if ( ! is_array( $first ) || count( $first ) < 2 ) {
				return $empty;
			}
			$provider_id = (string) $first[0];
			$model_id    = (string) $first[1];
		}

		return array(
			'provider'       => $provider_id,
			'model'          => $model_id,
			'model_inferred' => true,
		);
	}

	/**
	 * @param object $inner PromptBuilder instance.
	 * @return \WordPress\AiClient\Providers\Models\Enums\CapabilityEnum|null
	 */
	private static function capability_from_operation( object $inner, string $operation ) {
		if ( ! class_exists( 'WordPress\\AiClient\\Providers\\Models\\Enums\\CapabilityEnum' ) ) {
			return null;
		}

		$enum = 'WordPress\\AiClient\\Providers\\Models\\Enums\\CapabilityEnum';

		$map = array(
			'generate_text'                          => 'textGeneration',
			'generate_texts'                         => 'textGeneration',
			'generate_text_result'                   => 'textGeneration',
			'is_supported_for_text_generation'       => 'textGeneration',
			'generate_image'                         => 'imageGeneration',
			'generate_images'                        => 'imageGeneration',
			'generate_image_result'                  => 'imageGeneration',
			'is_supported_for_image_generation'      => 'imageGeneration',
			'generate_video'                         => 'videoGeneration',
			'generate_videos'                        => 'videoGeneration',
			'generate_video_result'                  => 'videoGeneration',
			'is_supported_for_video_generation'      => 'videoGeneration',
			'generate_speech'                        => 'speechGeneration',
			'generate_speeches'                      => 'speechGeneration',
			'generate_speech_result'                 => 'speechGeneration',
			'is_supported_for_speech_generation'     => 'speechGeneration',
			'convert_text_to_speech'                 => 'textToSpeechConversion',
			'convert_text_to_speeches'               => 'textToSpeechConversion',
			'convert_text_to_speech_result'          => 'textToSpeechConversion',
			'is_supported_for_text_to_speech_conversion' => 'textToSpeechConversion',
			'is_supported_for_music_generation'      => 'musicGeneration',
			'is_supported_for_embedding_generation'  => 'embeddingGeneration',
		);

		if ( isset( $map[ $operation ] ) ) {
			return $enum::{$map[ $operation ]}();
		}

		if ( 'is_supported' === $operation || 'generate_result' === $operation ) {
			try {
				$method = ( new \ReflectionClass( $inner ) )->getMethod( 'inferCapabilityFromOutputModalities' );
				$method->setAccessible( true );
				return $method->invoke( $inner );
			} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
				// Inference failed — null so family stays unknown (not Text).
				// Guessing textGeneration here would fail-open past unknown_operation=deny.
				return null;
			}
		}

		// Provider/model inference only: a wrong guess is a slightly wrong log
		// row. Enforcement must not treat this as a real family — family_from_operation
		// ignores inferred capability except for is_supported / generate_result.
		if ( 0 === strpos( $operation, 'generate_' ) || 0 === strpos( $operation, 'convert_text_to_speech' ) ) {
			return $enum::textGeneration();
		}

		return $enum::textGeneration();
	}

	/**
	 * @param object $inner PromptBuilder instance.
	 */
	private static function normalize_provider_id( object $inner, string $provider ): string {
		if ( ! class_exists( 'WordPress\\AiClient\\Providers\\ProviderRegistry' ) ) {
			return $provider;
		}

		$registry = self::read_property( new \ReflectionClass( $inner ), $inner, 'registry' );
		if ( ! is_object( $registry ) || ! method_exists( $registry, 'getProviderId' ) ) {
			return $provider;
		}

		try {
			return (string) $registry->getProviderId( $provider );
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			return $provider;
		}
	}

	/**
	 * @param object $inner PromptBuilder instance.
	 * @return array<string,mixed>
	 */
	private static function extract_config( object $inner ): array {
		$config = self::read_property( new \ReflectionClass( $inner ), $inner, 'modelConfig' );
		if ( ! is_object( $config ) || ! method_exists( $config, 'toArray' ) ) {
			return array();
		}

		try {
			$arr = $config->toArray();
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			return array();
		}

		if ( ! is_array( $arr ) ) {
			return array();
		}

		$pick = array();
		foreach ( array( 'maxTokens', 'temperature', 'topP', 'topK', 'candidateCount' ) as $key ) {
			if ( array_key_exists( $key, $arr ) && null !== $arr[ $key ] ) {
				$pick[ $key ] = $arr[ $key ];
			}
		}

		if ( ! empty( $arr['systemInstruction'] ) && is_string( $arr['systemInstruction'] ) ) {
			$pick['systemInstruction'] = self::truncate( $arr['systemInstruction'], 120 );
		}

		return empty( $pick ) ? array() : array( 'config' => $pick );
	}

	/**
	 * @param object $inner PromptBuilder instance.
	 */
	private static function extract_prompt_preview( object $inner ): ?string {
		$messages = self::read_property( new \ReflectionClass( $inner ), $inner, 'messages' );
		if ( ! is_array( $messages ) ) {
			return null;
		}

		$chunks = array();
		foreach ( $messages as $message ) {
			if ( ! is_object( $message ) || ! method_exists( $message, 'getParts' ) ) {
				continue;
			}
			$parts = $message->getParts();
			if ( ! is_array( $parts ) ) {
				continue;
			}
			foreach ( $parts as $part ) {
				if ( ! is_object( $part ) || ! method_exists( $part, 'getText' ) ) {
					continue;
				}
				$text = $part->getText();
				if ( is_string( $text ) && '' !== trim( $text ) ) {
					$chunks[] = trim( $text );
				}
			}
		}

		if ( empty( $chunks ) ) {
			return null;
		}

		return self::truncate( implode( "\n", $chunks ), self::PROMPT_PREVIEW_MAX );
	}

	/**
	 * @param \WP_AI_Client_Prompt_Builder $builder
	 * @return object|null
	 */
	private static function get_inner_builder( $builder ): ?object {
		$ref = new \ReflectionClass( $builder );
		if ( ! $ref->hasProperty( 'builder' ) ) {
			return null;
		}
		$prop = $ref->getProperty( 'builder' );
		$prop->setAccessible( true );
		$inner = $prop->getValue( $builder );
		return is_object( $inner ) ? $inner : null;
	}

	/**
	 * @param \ReflectionClass<object> $ref
	 * @return mixed
	 */
	private static function read_property( \ReflectionClass $ref, object $object, string $name ) {
		if ( ! $ref->hasProperty( $name ) ) {
			return null;
		}
		$prop = $ref->getProperty( $name );
		$prop->setAccessible( true );
		return $prop->getValue( $object );
	}

	private static function truncate( string $text, int $max ): string {
		if ( strlen( $text ) <= $max ) {
			return $text;
		}
		return substr( $text, 0, $max - 1 ) . '…';
	}
}
