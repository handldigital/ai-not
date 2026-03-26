<?php
/**
 * Enforcement + logging.
 *
 * @package AINot
 */

namespace AINot;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Policy {
	private static ?Policy $instance = null;

	public static function instance(): Policy {
		if ( null === self::$instance ) {
			self::$instance = new Policy();
		}
		return self::$instance;
	}

	public function init(): void {
		add_filter( 'wp_ai_client_prevent_prompt', array( $this, 'maybe_prevent_prompt' ), 1, 2 );
	}

	/**
	 * @param bool $prevent
	 * @param mixed $builder WP_AI_Client_Prompt_Builder clone (read-only)
	 */
	public function maybe_prevent_prompt( bool $prevent, $builder ): bool {
		if ( $prevent ) {
			return true;
		}

		$policy = self::get_policy();

		$attrib = Attribution::resolve_from_backtrace();
		$plugin = is_string( $attrib['plugin'] ?? null ) ? (string) $attrib['plugin'] : null;

		$decision = $this->decide( $policy, $plugin );

		$this->log_event(
			array(
				'ts'        => time(),
				'plugin'    => $plugin,
				'file'      => $attrib['file'] ?? null,
				'method'    => $attrib['method'] ?? null,
				'decision'  => $decision ? 'deny' : 'allow',
				'user_id'   => get_current_user_id(),
				'uri'       => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) ) : null,
			)
		);

		return $decision;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private function decide( array $policy, ?string $plugin_basename ): bool {
		$default = ( $policy['default'] ?? 'allow' ) === 'deny' ? 'deny' : 'allow';
		$rules   = is_array( $policy['plugins'] ?? null ) ? (array) $policy['plugins'] : array();

		if ( $plugin_basename && isset( $rules[ $plugin_basename ] ) ) {
			return 'deny' === $rules[ $plugin_basename ];
		}

		return 'deny' === $default;
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function get_policy(): array {
		$policy = get_option( Plugin::OPTION_KEY );
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}

		$policy['default'] = ( $policy['default'] ?? 'allow' ) === 'deny' ? 'deny' : 'allow';
		$policy['plugins'] = is_array( $policy['plugins'] ?? null ) ? (array) $policy['plugins'] : array();
		// Opt-in: logging stores local request metadata (e.g. user id / URI).
		$policy['log_enabled'] = (bool) ( $policy['log_enabled'] ?? false );
		$policy['log_limit'] = (int) ( $policy['log_limit'] ?? 200 );
		if ( $policy['log_limit'] < 20 ) {
			$policy['log_limit'] = 20;
		}
		if ( $policy['log_limit'] > 1000 ) {
			$policy['log_limit'] = 1000;
		}

		return $policy;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function save_policy( array $policy ): void {
		update_option( Plugin::OPTION_KEY, $policy, false );
	}

	/**
	 * @param array<string,mixed> $event
	 */
	private function log_event( array $event ): void {
		$policy = self::get_policy();
		if ( empty( $policy['log_enabled'] ) ) {
			return;
		}

		$limit = (int) ( $policy['log_limit'] ?? 200 );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) ) {
			$log = array();
		}

		$log[] = $event;
		$count = count( $log );
		if ( $count > $limit ) {
			$log = array_slice( $log, $count - $limit );
		}

		update_option( Plugin::LOG_OPTION_KEY, $log, false );
	}
}

