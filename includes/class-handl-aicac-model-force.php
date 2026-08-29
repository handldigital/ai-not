<?php
/**
 * Experimental per-plugin model force / downgrade (F4).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Pins AI Client generation to an admin-configured provider/model pair per detected caller.
 *
 * EXPERIMENTAL. Relies on a WordPress AI Client implementation detail: the
 * prevent-prompt filter receives a shallow clone of WP_AI_Client_Prompt_Builder
 * that currently shares the private inner PromptBuilder. Core documents that
 * clone as read-only. If core deep-clones or otherwise stops sharing the inner
 * builder, overrides stop taking effect.
 *
 * Guardrail 1 (is_clone_compatible) is a cheap pre-check only: it detects one
 * failure mode (wrapper defining __clone). It does not prove the mutation will
 * land. Guardrail 2 (verify_final_route / route_matches) is the real safety —
 * exact provider+model match after selection, fail-closed on mismatch. Do not
 * relax guardrail 2 because guardrail 1 said "compatible".
 *
 * Force applies only when a caller is attributed (a plugin frame resolved from
 * the backtrace, best-effort, nearest-frame) and that plugin has a force row —
 * or, when the admin explicitly opts in, for unattributed calls via the
 * Unattributed-calls control. Unattributed with default "don't force" ⇒ route
 * untouched, logged unforced, counted.
 *
 * Attribution answers "whose file is nearest," not "who initiated" — a pin
 * follows the detected caller and is not a spend guarantee. Misattribution can
 * select the wrong pin without tripping fail-closed (existence ≠ correctness).
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
	 * Whether any experimental force rule is configured (per-plugin or unattributed opt-in).
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function has_any_force_rules( array $policy ): bool {
		$map = self::force_map( $policy );
		if ( ! empty( $map ) ) {
			return true;
		}
		return null !== self::unattributed_route( $policy );
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array<string,array{provider:string,model:string}>
	 */
	public static function force_map( array $policy ): array {
		$raw = $policy['model_force_plugins'] ?? array();
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $basename => $row ) {
			$basename = sanitize_text_field( (string) $basename );
			if ( '' === $basename || ! is_array( $row ) ) {
				continue;
			}
			$provider = self::sanitize_id( $row['provider'] ?? '' );
			$model    = self::sanitize_id( $row['model'] ?? '' );
			if ( '' === $provider || '' === $model ) {
				continue;
			}
			$out[ $basename ] = array(
				'provider' => $provider,
				'model'    => $model,
			);
		}
		return $out;
	}

	/**
	 * @param mixed $raw
	 * @return array<string,array{provider:string,model:string}>
	 */
	public static function sanitize_force_map( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		return self::force_map( array( 'model_force_plugins' => $raw ) );
	}

	/**
	 * Unattributed-calls mode: none (default) | force.
	 *
	 * @param mixed $raw
	 * @return 'none'|'force'
	 */
	public static function sanitize_unattributed_mode( $raw ): string {
		$raw = sanitize_text_field( (string) $raw );
		return 'force' === $raw ? 'force' : 'none';
	}

	/**
	 * Explicit unattributed force target, or null when mode is none / incomplete.
	 *
	 * @param array<string,mixed> $policy
	 * @return array{provider:string,model:string}|null
	 */
	public static function unattributed_route( array $policy ): ?array {
		if ( 'force' !== self::sanitize_unattributed_mode( $policy['model_force_unattributed'] ?? 'none' ) ) {
			return null;
		}
		$provider = self::sanitize_id( $policy['model_force_unattributed_provider'] ?? '' );
		$model    = self::sanitize_id( $policy['model_force_unattributed_model'] ?? '' );
		if ( '' === $provider || '' === $model ) {
			return null;
		}
		return array(
			'provider' => $provider,
			'model'    => $model,
		);
	}

	/**
	 * Resolve the force target for a detected caller (or unattributed).
	 *
	 * Force applies only when a caller is attributed (plugin frame from the
	 * backtrace, best-effort, nearest-frame) and that plugin has a force row.
	 * Unattributed ⇒ no force unless the admin's Unattributed-calls control is
	 * set to force with an explicit provider/model (not a resurrected site-wide pin).
	 *
	 * @param array<string,mixed> $policy
	 * @return array{apply:bool,reason:string,provider?:string,model?:string,source?:string}
	 */
	public static function resolve_route( array $policy, ?string $plugin_basename ): array {
		$plugin_basename = is_string( $plugin_basename ) ? sanitize_text_field( $plugin_basename ) : '';

		if ( '' === $plugin_basename ) {
			$ua = self::unattributed_route( $policy );
			if ( null === $ua ) {
				// Countable gap only when someone configured at least one pin.
				if ( ! empty( self::force_map( $policy ) ) ) {
					return array( 'apply' => false, 'reason' => 'unattributed' );
				}
				return array( 'apply' => false, 'reason' => 'no_rule' );
			}
			return array(
				'apply'    => true,
				'reason'   => 'ok',
				'provider' => $ua['provider'],
				'model'    => $ua['model'],
				'source'   => 'unattributed',
			);
		}

		$map = self::force_map( $policy );
		if ( ! isset( $map[ $plugin_basename ] ) ) {
			return array( 'apply' => false, 'reason' => 'no_rule' );
		}

		return array(
			'apply'    => true,
			'reason'   => 'ok',
			'provider' => $map[ $plugin_basename ]['provider'],
			'model'    => $map[ $plugin_basename ]['model'],
			'source'   => 'plugin',
		);
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
	 * Called from Policy after allow decision on a *generating* operation only:
	 * apply preference on the clone and arm final-route verification for this call.
	 *
	 * Pending expectation is a single request-scoped static slot. Clear it at every
	 * entry before deciding (overwrite-or-clear, never carry). Consume-on-verify
	 * still runs in verify_final_route. That way an armed call that never reaches
	 * wp_ai_client_before_generate_result (denied later, provider throws pre-hook,
	 * support-check path that must not arm, etc.) cannot poison the next call.
	 *
	 * @param mixed               $builder WP_AI_Client_Prompt_Builder clone.
	 * @param array<string,mixed> $policy
	 * @param string|null         $plugin_basename Detected caller (nearest plugin frame) or null.
	 * @return array{applied:bool,reason:string,provider?:string,model?:string,source?:string}
	 */
	public static function maybe_apply( $builder, array $policy, ?string $plugin_basename ): array {
		// Self-cleaning slot: staleness cannot outlive one call regardless of exit path.
		self::$pending_expected = null;

		$resolved = self::resolve_route( $policy, $plugin_basename );
		if ( empty( $resolved['apply'] ) ) {
			return array(
				'applied' => false,
				'reason'  => (string) ( $resolved['reason'] ?? 'no_rule' ),
			);
		}

		$provider = self::sanitize_id( $resolved['provider'] ?? '' );
		$model    = self::sanitize_id( $resolved['model'] ?? '' );
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
					'status'        => 'apply_failed',
					'last_error'    => substr( $e->getMessage(), 0, 200 ),
					'last_error_at' => time(),
				)
			);
			return array( 'applied' => false, 'reason' => 'apply_threw' );
		}

		// Arm verification only when we believe the override landed on a shared inner.
		// No health write on the allow path here — "armed" is not diagnostic value;
		// guardrail 2 writes verified_ok / route_mismatch once status actually changes.
		self::$pending_expected = array(
			'provider' => strtolower( $provider ),
			'model'    => strtolower( $model ),
		);

		return array(
			'applied'  => true,
			'reason'   => 'ok',
			'provider' => $provider,
			'model'    => $model,
			'source'   => (string) ( $resolved['source'] ?? 'plugin' ),
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
			return; // fail_closed throws; return keeps call sites safe if that ever changes.
		}

		try {
			$model_obj       = $event->getModel();
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
			return; // fail_closed throws.
		}

		if ( ! self::route_matches( $expected, $actual_provider, $actual_model ) ) {
			self::fail_closed_mismatch( $expected, $actual_provider, $actual_model );
			return; // fail_closed throws.
		}

		// Success: write health only on transition (record_health no-ops if already verified_ok).
		self::record_health(
			array(
				'clone_compatible' => true,
				'clone_reason'     => self::$clone_reason ?? 'shallow_wrapper_clone',
				'status'           => 'verified_ok',
				'last_verified_at' => time(),
				'last_mismatch_at' => null,
				'last_mismatch'    => null,
			)
		);
	}

	/**
	 * Exact provider + model match only (guardrail 2 safety).
	 *
	 * No substring / "near match" on provider ids: azure-openai must not pass
	 * for expected openai. Registries that return model as "provider/model"
	 * are accepted only when the provider id itself still matches exactly.
	 *
	 * @param array{provider:string,model:string} $expected
	 */
	private static function route_matches( array $expected, string $provider, string $model ): bool {
		$p = strtolower( trim( $provider ) );
		$m = strtolower( trim( $model ) );
		if ( '' === $p || '' === $m ) {
			return false;
		}
		// Exact provider + exact model.
		if ( $p === $expected['provider'] && $m === $expected['model'] ) {
			return true;
		}
		// Some registries return model as "provider/model" while provider is still exact.
		if ( $p === $expected['provider'] && $m === $expected['provider'] . '/' . $expected['model'] ) {
			return true;
		}
		return false;
	}

	/**
	 * Throws unconditionally — generation becomes WP_Error before the provider call.
	 *
	 * Signature stays :void for PHP 7.4 (never is 8.1+). Call sites must return
	 * after invoking so a future early-return inside this method cannot fall through.
	 *
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
			__( 'HandL AI Access blocked the generation because the final model route did not match. Expected %1$s / %2$s; received %3$s / %4$s. The generation was blocked before the provider call. Update or disable model routing under Settings → HandL AI Access.', 'handl-ai-connector-access-control' ),
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
	 * Guardrail 1 — cheap pre-check only, not the safety gate.
	 *
	 * Detects one failure mode: WP_AI_Client_Prompt_Builder declaring __clone
	 * (which would break the shallow-clone shared-inner assumption on WP 7.0.2).
	 * Does NOT detect: fresh wrapper around a cloned inner, explicit inner clone
	 * before apply_filters, or immutable fluent methods. Those still look
	 * "compatible" here; only guardrail 2 (final-route verification) proves
	 * the force landed. Never relax route_matches because this returned true.
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
	 * Persist health only when status or other non-timestamp fields change.
	 *
	 * On the allow path every generation used to write twice (armed + verified_ok)
	 * because updated_at always differed. Skip no-op updates so hot-path AI calls
	 * do not hit the options table.
	 *
	 * @param array<string,mixed> $patch
	 */
	public static function record_health( array $patch ): void {
		$current = get_option( self::HEALTH_OPTION_KEY, array() );
		if ( ! is_array( $current ) ) {
			$current = array();
		}

		$next = $current;
		foreach ( $patch as $k => $v ) {
			if ( null === $v ) {
				unset( $next[ $k ] );
			} else {
				$next[ $k ] = $v;
			}
		}

		// Compare without timestamps that always churn on the hot path.
		$ignore   = array( 'updated_at', 'last_armed_at', 'last_verified_at', 'last_error_at', 'last_mismatch_at' );
		$curr_cmp = $current;
		$next_cmp = $next;
		foreach ( $ignore as $key ) {
			unset( $curr_cmp[ $key ], $next_cmp[ $key ] );
		}
		if ( $curr_cmp === $next_cmp ) {
			return;
		}

		$next['updated_at'] = time();
		update_option( self::HEALTH_OPTION_KEY, $next, false );
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function get_health(): array {
		$h = get_option( self::HEALTH_OPTION_KEY, array() );
		return is_array( $h ) ? $h : array();
	}

	/**
	 * Count retained audit rows that ran unforced because the caller was unattributed.
	 *
	 * F2 inert-entry pattern applied to routing: surface the attribution gap
	 * instead of letting the admin infer it from a bill.
	 *
	 * @param array<int,mixed> $log
	 */
	public static function count_unforced_unattributed( array $log ): int {
		// model_force_unforced is set whenever skip === unattributed (policy.php);
		// the redundant model_force_skipped === unattributed branch is gone (F5 cleanup #1).
		$n = 0;
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( ! empty( $row['model_force_unforced'] ) ) {
				++$n;
			}
		}
		return $n;
	}

	/**
	 * Pin-hold stats over attempted forces only (Δ2).
	 *
	 * Y = model_forced + technical skips (clone_incompatible, apply_threw,
	 * no_preference_api, incomplete). X = model_forced. Unattributed-unforced
	 * and operation_unresolved stay out of this ratio.
	 *
	 * @param array<int,mixed> $log
	 * @return array{held:int,attempted:int,by_skip:array<string,int>}
	 */
	public static function pin_hold_stats( array $log ): array {
		$held      = 0;
		$attempted = 0;
		$by_skip   = array();
		$technical = array( 'clone_incompatible', 'apply_threw', 'no_preference_api', 'incomplete' );

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( ! empty( $row['model_forced'] ) ) {
				++$held;
				++$attempted;
				continue;
			}
			$skip = isset( $row['model_force_skipped'] ) ? (string) $row['model_force_skipped'] : '';
			if ( in_array( $skip, $technical, true ) ) {
				++$attempted;
				if ( ! isset( $by_skip[ $skip ] ) ) {
					$by_skip[ $skip ] = 0;
				}
				++$by_skip[ $skip ];
			}
		}

		return array(
			'held'      => $held,
			'attempted' => $attempted,
			'by_skip'   => $by_skip,
		);
	}

	/**
	 * How many retained rows were forced for a given plugin basename.
	 *
	 * @param array<int,mixed> $log
	 */
	public static function count_forced_for_plugin( array $log, string $plugin_basename ): int {
		$plugin_basename = sanitize_text_field( $plugin_basename );
		if ( '' === $plugin_basename ) {
			return 0;
		}
		$n = 0;
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( empty( $row['model_forced'] ) ) {
				continue;
			}
			$p = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			if ( $p === $plugin_basename ) {
				++$n;
			}
		}
		return $n;
	}

	/**
	 * Whether a persistent admin warning should show.
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function needs_health_warning( array $policy ): bool {
		if ( ! self::has_any_force_rules( $policy ) ) {
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
		if ( ! self::has_any_force_rules( $policy ) ) {
			return;
		}

		$compat = self::clone_compat_status();
		$health = self::get_health();
		$status = isset( $health['status'] ) ? (string) $health['status'] : '';

		if ( $compat['compatible'] && ! in_array( $status, array( 'route_mismatch', 'clone_incompatible', 'apply_failed' ), true ) ) {
			// Still surface a quiet experimental banner on our own settings screen only.
			$screen     = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
			$on_our_page = $screen && isset( $screen->id ) && false !== strpos( (string) $screen->id, 'handl-aicac' );
			if ( ! $on_our_page ) {
				return;
			}
			echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Model routing by plugin is configured (experimental).', 'handl-ai-connector-access-control' ) . '</strong> ';
			echo esc_html__( 'Routes follow the detected plugin. Detection is best-effort, and model routing is not a spend guarantee. This experimental feature relies on unsupported AI Client behavior.', 'handl-ai-connector-access-control' );
			echo ' <a href="' . esc_url( Admin::screen_url( 'protections' ) ) . '">' . esc_html__( 'Review model routing', 'handl-ai-connector-access-control' ) . '</a></p></div>';
			return;
		}

		echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'Experimental model routing is not working.', 'handl-ai-connector-access-control' ) . '</strong> ';

		if ( ! $compat['compatible'] ) {
			echo esc_html(
				sprintf(
					/* translators: %s: technical reason code */
					__( 'Compatibility check failed: %s. Model routing will not be applied. Disable this experimental feature or wait for an official WordPress routing option.', 'handl-ai-connector-access-control' ),
					$compat['reason']
				)
			);
		} elseif ( 'route_mismatch' === $status ) {
			$detail = isset( $health['last_mismatch'] ) && is_array( $health['last_mismatch'] ) ? $health['last_mismatch'] : array();
			echo esc_html__( 'A generation was blocked because the selected provider or model did not match the configured route. Check the saved IDs and installed AI providers.', 'handl-ai-connector-access-control' );
			if ( ! empty( $detail['expected_model'] ) ) {
				echo ' ' . esc_html(
					sprintf(
						/* translators: 1: expected provider, 2: expected model, 3: actual provider, 4: actual model */
						__( 'Expected: %1$s / %2$s. Received: %3$s / %4$s.', 'handl-ai-connector-access-control' ),
						(string) ( $detail['expected_provider'] ?? '' ),
						(string) ( $detail['expected_model'] ?? '' ),
						(string) ( $detail['actual_provider'] ?? '' ),
						(string) ( $detail['actual_model'] ?? '' )
					)
				);
			}
		} else {
			echo esc_html__( 'The experimental route could not be applied. Calls will continue using the model chosen by the calling plugin until you fix or remove the routing settings.', 'handl-ai-connector-access-control' );
		}

		echo ' <a href="' . esc_url( Admin::screen_url( 'protections' ) ) . '">' . esc_html__( 'Open settings', 'handl-ai-connector-access-control' ) . '</a></p></div>';
	}
}
