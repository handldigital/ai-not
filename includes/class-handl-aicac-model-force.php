<?php
/**
 * Experimental model force / downgrade (F4).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Pins AI Client generation to an admin-configured provider/model pair.
 *
 * EXPERIMENTAL. Relies on a WordPress AI Client implementation detail: the
 * prevent-prompt filter receives a shallow clone of WP_AI_Client_Prompt_Builder
 * that currently shares the private inner PromptBuilder. Core documents that
 * clone as read-only. If core adds a deep __clone(), overrides stop taking
 * effect — clone-compat detection + final-route verification exist so that
 * failure is loud, never silent.
 *
 * This class never changes allow/deny. It only mutates route preference and
 * fail-closes generation when the final selected model does not match.
 */
final class Model_Force {
	public const HEALTH_OPTION_KEY = 'handl_aicac_model_force_health';

	/** @var array{provider:string,model:string}|null */
	private static ?array $pending_expected = null;

	/** @var bool|null Cached clone-sharing probe for this request. */
	private static ?bool $clone_compatible = null;

	/** @var string|null */
	private static ?string $clone_reason = null;

	private static ?Model_Force $instance = null;

	public static function instance(): Model_Force {
		if ( null === self::$instance ) {
			self::$instance = new Model_Force();
		}
		return self::$instance;
	}

	public function init(): void {
		// Final-route verification: before the provider call, after model selection.
		add_action( 'wp_ai_client_before_generate_result', array( $this, 'verify_final_route' ), 1, 1 );
		add_action( 'admin_notices', array( $this, 'maybe_admin_health_notice' ) );
	}

	/**
	 * Whether the experimental force is fully configured and on.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function is_enabled( array $policy ): bool {
		if ( empty( $policy['model_force_enabled'] ) ) {
			return false;
		}
		$provider = self::sanitize_id( $policy['model_force_provider'] ?? '' );
		$model    = self::sanitize_id( $policy['model_force_model'] ?? '' );
		return '' !== $provider && '' !== $model;
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_id( $raw ): string {
		$raw = sanitize_text_field( (string) $raw );
		// Provider/model ids: letters, digits, . _ - / :
		$raw = (string) preg_replace( '/[^a-zA-Z0-9._\\-\\/:]+/', '', $raw );
		return substr( $raw, 0, 191 );
	}

	/**
	 * Called from Policy after allow decision: apply preference on the clone
	 * and arm final-route verification for this request.
	 *
	 * @param mixed               $builder WP_AI_Client_Prompt_Builder clone.
	 * @param array<string,mixed> $policy
	 * @return array{applied:bool,reason:string,provider?:string,model?:string}
	 */
	public static function maybe_apply( $builder, array $policy ): array {
		if ( ! self::is_enabled( $policy ) ) {
			return array( 'applied' => false, 'reason' => 'disabled' );
		}

		$provider = self::sanitize_id( $policy['model_force_provider'] ?? '' );
		$model    = self::sanitize_id( $policy['model_force_model'] ?? '' );
		if ( '' === $provider || '' === $model ) {
			return array( 'applied' => false, 'reason' => 'incomplete' );
		}

		if ( ! self::is_clone_compatible() ) {
			self::record_health(
				array(
					'clone_compatible' => false,
					'clone_reason'     => self::$clone_reason ?? 'incompatible',
					'status'           => 'clone_incompatible',
				)
			);
			return array( 'applied' => false, 'reason' => 'clone_incompatible' );
		}

		if ( ! is_object( $builder ) || ! class_exists( 'WP_AI_Client_Prompt_Builder', false ) ) {
			return array( 'applied' => false, 'reason' => 'no_builder' );
		}
		if ( ! $builder instanceof \WP_AI_Client_Prompt_Builder ) {
			return array( 'applied' => false, 'reason' => 'wrong_builder' );
		}

		try {
			// Public fluent API on the wrapper (maps to inner PromptBuilder).
			// using_provider + using_model_preference pins selection order.
			if ( is_callable( array( $builder, 'using_provider' ) ) ) {
				$builder->using_provider( $provider );
			} elseif ( is_callable( array( $builder, 'usingProvider' ) ) ) {
				// @phpstan-ignore-next-line camelCase fallback for unexpected surfaces.
				$builder->usingProvider( $provider );
			}

			// Preference as [providerId, modelId] — supported by usingModelPreference.
			if ( is_callable( array( $builder, 'using_model_preference' ) ) ) {
				$builder->using_model_preference( array( $provider, $model ) );
			} elseif ( is_callable( array( $builder, 'usingModelPreference' ) ) ) {
				// @phpstan-ignore-next-line camelCase fallback.
				$builder->usingModelPreference( array( $provider, $model ) );
			} else {
				return array( 'applied' => false, 'reason' => 'no_preference_api' );
			}
		} catch ( \Throwable $e ) {
			self::record_health(
				array(
					'status'       => 'apply_failed',
					'last_error'   => substr( $e->getMessage(), 0, 200 ),
					'last_error_at'=> time(),
				)
			);
			return array( 'applied' => false, 'reason' => 'apply_threw' );
		}

		// Arm verification only when we believe the override landed on a shared inner.
		self::$pending_expected = array(
			'provider' => strtolower( $provider ),
			'model'    => strtolower( $model ),
		);

		self::record_health(
			array(
				'clone_compatible' => true,
				'clone_reason'     => self::$clone_reason ?? 'shallow_wrapper_clone',
				'status'           => 'armed',
				'last_armed_at'    => time(),
			)
		);

		return array(
			'applied'  => true,
			'reason'   => 'ok',
			'provider' => $provider,
			'model'    => $model,
		);
	}

	/**
	 * Final-route verification (guardrail 2 + 3).
	 *
	 * @param mixed $event BeforeGenerateResultEvent.
	 */
	public function verify_final_route( $event ): void {
		$expected = self::$pending_expected;
		self::$pending_expected = null;

		if ( null === $expected ) {
			return;
		}

		if ( ! is_object( $event ) || ! method_exists( $event, 'getModel' ) ) {
			self::fail_closed_mismatch( $expected, '(unreadable event)', '(unreadable event)' );
		}

		try {
			$model_obj = $event->getModel();
			$actual_model    = '';
			$actual_provider = '';

			if ( is_object( $model_obj ) && method_exists( $model_obj, 'metadata' ) ) {
				$meta = $model_obj->metadata();
				if ( is_object( $meta ) && method_exists( $meta, 'getId' ) ) {
					$actual_model = (string) $meta->getId();
				}
			}
			if ( is_object( $model_obj ) && method_exists( $model_obj, 'providerMetadata' ) ) {
				$pmeta = $model_obj->providerMetadata();
				if ( is_object( $pmeta ) && method_exists( $pmeta, 'getId' ) ) {
					$actual_provider = (string) $pmeta->getId();
				}
			}
		} catch ( \Throwable $e ) {
			self::fail_closed_mismatch( $expected, '(error)', '(error)' );
			return; // unreachable — fail_closed throws.
		}

		if ( ! self::route_matches( $expected, $actual_provider, $actual_model ) ) {
			self::fail_closed_mismatch( $expected, $actual_provider, $actual_model );
		}

		// Success: clear mismatch health if any.
		self::record_health(
			array(
				'status'            => 'verified_ok',
				'last_verified_at'  => time(),
				'last_mismatch_at'  => null,
				'last_mismatch'     => null,
			)
		);
	}

	/**
	 * @param array{provider:string,model:string} $expected
	 */
	private static function route_matches( array $expected, string $provider, string $model ): bool {
		$p = strtolower( trim( $provider ) );
		$m = strtolower( trim( $model ) );
		if ( '' === $p || '' === $m ) {
			return false;
		}
		// Exact match preferred; also accept model id alone if provider matches class-style id.
		if ( $p === $expected['provider'] && $m === $expected['model'] ) {
			return true;
		}
		// Some registries return model as "provider/model".
		if ( $m === $expected['provider'] . '/' . $expected['model'] ) {
			return true;
		}
		// Provider id may be a class name containing the short id.
		if ( $m === $expected['model'] && ( $p === $expected['provider'] || false !== stripos( $p, $expected['provider'] ) ) ) {
			return true;
		}
		return false;
	}

	/**
	 * @param array{provider:string,model:string} $expected
	 * @return never
	 */
	private static function fail_closed_mismatch( array $expected, string $actual_provider, string $actual_model ): void {
		self::record_health(
			array(
				'status'           => 'route_mismatch',
				'last_mismatch_at' => time(),
				'last_mismatch'    => array(
					'expected_provider' => $expected['provider'],
					'expected_model'    => $expected['model'],
					'actual_provider'   => $actual_provider,
					'actual_model'      => $actual_model,
				),
			)
		);

		$message = sprintf(
			/* translators: 1: expected provider, 2: expected model, 3: actual provider, 4: actual model */
			__( 'HandL AICAC experimental model force: final route mismatch (expected %1$s / %2$s, got %3$s / %4$s). Generation blocked before the provider call. Disable the experimental force or fix the provider/model ids under Settings → HandL AI Connector Access Control.', 'handl-ai-connector-access-control' ),
			$expected['provider'],
			$expected['model'],
			$actual_provider,
			$actual_model
		);

		// Unsanctioned control flow: action is not stoppable, but the WordPress
		// wrapper catches Throwable and returns WP_Error before executeModelGeneration.
		throw new \RuntimeException( $message );
	}

	/**
	 * Guardrail 1: detect whether the prevent-prompt clone shares the inner builder.
	 *
	 * Current WP 7.0.x: wrapper has no __clone → PHP shallow-clones the object and
	 * the private PromptBuilder property is shared (Frink live probe: same_inner true).
	 * If core later adds a deep __clone on the wrapper, we refuse to force.
	 */
	public static function is_clone_compatible(): bool {
		if ( null !== self::$clone_compatible ) {
			return self::$clone_compatible;
		}

		if ( ! class_exists( 'WP_AI_Client_Prompt_Builder', false ) ) {
			self::$clone_compatible = false;
			self::$clone_reason     = 'no_builder_class';
			return false;
		}

		try {
			$ref = new \ReflectionClass( 'WP_AI_Client_Prompt_Builder' );
			if ( $ref->hasMethod( '__clone' ) ) {
				$decl = $ref->getMethod( '__clone' )->getDeclaringClass()->getName();
				// Any real __clone on the wrapper means we cannot assume shared inner.
				if ( 'WP_AI_Client_Prompt_Builder' === $decl ) {
					self::$clone_compatible = false;
					self::$clone_reason     = 'wrapper_defines_clone';
					return false;
				}
			}

			if ( ! $ref->hasProperty( 'builder' ) ) {
				self::$clone_compatible = false;
				self::$clone_reason     = 'no_inner_property';
				return false;
			}

			self::$clone_compatible = true;
			self::$clone_reason     = 'shallow_wrapper_clone';
			return true;
		} catch ( \Throwable $e ) {
			self::$clone_compatible = false;
			self::$clone_reason     = 'probe_threw';
			return false;
		}
	}

	/**
	 * @return array{compatible:bool,reason:string}
	 */
	public static function clone_compat_status(): array {
		$ok = self::is_clone_compatible();
		return array(
			'compatible' => $ok,
			'reason'     => (string) ( self::$clone_reason ?? ( $ok ? 'ok' : 'unknown' ) ),
		);
	}

	/**
	 * @param array<string,mixed> $patch
	 */
	public static function record_health( array $patch ): void {
		$current = get_option( self::HEALTH_OPTION_KEY, array() );
		if ( ! is_array( $current ) ) {
			$current = array();
		}
		foreach ( $patch as $k => $v ) {
			if ( null === $v ) {
				unset( $current[ $k ] );
			} else {
				$current[ $k ] = $v;
			}
		}
		$current['updated_at'] = time();
		update_option( self::HEALTH_OPTION_KEY, $current, false );
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function get_health(): array {
		$h = get_option( self::HEALTH_OPTION_KEY, array() );
		return is_array( $h ) ? $h : array();
	}

	/**
	 * Whether a persistent admin warning should show.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function needs_health_warning( array $policy ): bool {
		if ( ! self::is_enabled( $policy ) ) {
			return false;
		}
		if ( ! self::is_clone_compatible() ) {
			return true;
		}
		$health = self::get_health();
		$status = isset( $health['status'] ) ? (string) $health['status'] : '';
		return in_array( $status, array( 'route_mismatch', 'clone_incompatible', 'apply_failed' ), true );
	}

	/**
	 * Guardrail 4: loud persistent health warning.
	 */
	public function maybe_admin_health_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$policy = Policy::get_policy();
		if ( ! self::is_enabled( $policy ) ) {
			return;
		}

		$compat = self::clone_compat_status();
		$health = self::get_health();
		$status = isset( $health['status'] ) ? (string) $health['status'] : '';

		if ( $compat['compatible'] && ! in_array( $status, array( 'route_mismatch', 'clone_incompatible', 'apply_failed' ), true ) ) {
			// Still surface a quiet experimental banner on our own settings screen only.
			$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
			$on_our_page = $screen && isset( $screen->id ) && false !== strpos( (string) $screen->id, 'handl-ai-connector-access-control' );
			if ( ! $on_our_page ) {
				return;
			}
			echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'EXPERIMENTAL: Model force is enabled.', 'handl-ai-connector-access-control' ) . '</strong> ';
			echo esc_html__( 'This feature relies on unsupported AI Client clone behaviour. Prefer it only for controlled testing. An upstream routing filter is the supported exit ramp.', 'handl-ai-connector-access-control' );
			echo ' <a href="' . esc_url( admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=rules' ) ) . '">' . esc_html__( 'Review settings', 'handl-ai-connector-access-control' ) . '</a></p></div>';
			return;
		}

		echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'EXPERIMENTAL model force is not healthy.', 'handl-ai-connector-access-control' ) . '</strong> ';

		if ( ! $compat['compatible'] ) {
			echo esc_html(
				sprintf(
					/* translators: %s: technical reason code */
					__( 'Clone-sharing compatibility check failed (%s). The forced provider/model will not be applied — WordPress may have fixed the shallow clone. Disable this experimental feature or wait for an official routing filter.', 'handl-ai-connector-access-control' ),
					$compat['reason']
				)
			);
		} elseif ( 'route_mismatch' === $status ) {
			$detail = isset( $health['last_mismatch'] ) && is_array( $health['last_mismatch'] ) ? $health['last_mismatch'] : array();
			echo esc_html__( 'A generation was blocked because the final selected model did not match the forced route. Check provider/model ids and installed AI providers.', 'handl-ai-connector-access-control' );
			if ( ! empty( $detail['expected_model'] ) ) {
				echo ' ' . esc_html(
					sprintf(
						/* translators: 1: expected, 2: actual */
						__( 'Expected %1$s / %2$s; got %3$s / %4$s.', 'handl-ai-connector-access-control' ),
						(string) ( $detail['expected_provider'] ?? '' ),
						(string) ( $detail['expected_model'] ?? '' ),
						(string) ( $detail['actual_provider'] ?? '' ),
						(string) ( $detail['actual_model'] ?? '' )
					)
				);
			}
		} else {
			echo esc_html__( 'The experimental override failed to apply. Generation continues on the caller’s chosen model until you fix or disable the force.', 'handl-ai-connector-access-control' );
		}

		echo ' <a href="' . esc_url( admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=rules' ) ) . '">' . esc_html__( 'Open settings', 'handl-ai-connector-access-control' ) . '</a></p></div>';
	}
}
