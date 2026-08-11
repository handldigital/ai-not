<?php
/**
 * AICAC-GRADUATE: map observed Activity rows into Rules-tab prefill proposals.
 *
 * Prefill only — rule creation still goes through Admin::handle_save_rules /
 * Policy::save_policy (nonce + capability). No separate persistence path.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Graduate {

	/**
	 * Build a graduate proposal from one retained log row.
	 *
	 * Returns null when the row cannot be graduated (no plugin, direct HTTP,
	 * or empty/invalid plugin basename).
	 *
	 * @param array<string,mixed> $row
	 * @return array{plugin:string,family:string,provider:string,model:string}|null
	 */
	public static function proposal_from_log_row( array $row ): ?array {
		if ( isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'] ) {
			return null;
		}

		$plugin = Plugin_Profile::sanitize_plugin( $row['plugin'] ?? '' );
		if ( '' === $plugin ) {
			return null;
		}

		$family = isset( $row['capability_family'] ) ? sanitize_key( (string) $row['capability_family'] ) : '';
		if ( '' === $family || ! in_array( $family, Operations::families(), true ) ) {
			$operation = isset( $row['operation'] ) ? (string) $row['operation'] : '';
			$family    = Operations::family_from_operation( $operation );
			if ( Operations::FAMILY_UNKNOWN === $family || ! in_array( $family, Operations::families(), true ) ) {
				$family = '';
			}
		}

		$provider = Model_Force::sanitize_id( $row['provider'] ?? '' );
		$model    = Model_Force::sanitize_id( Audit_Export::row_model( $row ) );

		return array(
			'plugin'   => $plugin,
			'family'   => $family,
			'provider' => $provider,
			'model'    => $model,
		);
	}

	/**
	 * Plugin-only proposal (Dashboard top-caller / suggested-rules rows).
	 *
	 * @return array{plugin:string,family:string,provider:string,model:string}|null
	 */
	public static function proposal_from_plugin( string $plugin_basename ): ?array {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin_basename );
		if ( '' === $plugin ) {
			return null;
		}

		return array(
			'plugin'   => $plugin,
			'family'   => '',
			'provider' => '',
			'model'    => '',
		);
	}

	/**
	 * Whether an identical explicit rule already covers this proposal.
	 *
	 * Coverage order:
	 * 1. Explicit plugin Allow/Deny (covers all families for that plugin).
	 * 2. Explicit capability-family Allow/Deny for the proposed family.
	 *
	 * @param array<string,mixed>                                              $policy
	 * @param array{plugin:string,family?:string,provider?:string,model?:string} $proposal
	 * @return array{kind:string,rule:string,plugin:string,family:string}|null Null when not covered.
	 */
	public static function coverage_for( array $policy, array $proposal ): ?array {
		$plugin = Plugin_Profile::sanitize_plugin( $proposal['plugin'] ?? '' );
		if ( '' === $plugin ) {
			return null;
		}

		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] ) ? $policy['plugins'] : array();
		$explicit = isset( $plugins[ $plugin ] ) ? sanitize_text_field( (string) $plugins[ $plugin ] ) : '';
		if ( 'allow' === $explicit || 'deny' === $explicit ) {
			return array(
				'kind'   => 'plugin',
				'rule'   => $explicit,
				'plugin' => $plugin,
				'family' => '',
			);
		}

		$family = isset( $proposal['family'] ) ? sanitize_key( (string) $proposal['family'] ) : '';
		if ( '' === $family || ! in_array( $family, Operations::families(), true ) ) {
			return null;
		}

		$operations = isset( $policy['operations'] ) && is_array( $policy['operations'] ) ? $policy['operations'] : array();
		$row        = isset( $operations[ $plugin ] ) && is_array( $operations[ $plugin ] ) ? $operations[ $plugin ] : array();
		$fam_rule   = isset( $row[ $family ] ) ? sanitize_text_field( (string) $row[ $family ] ) : '';
		if ( 'allow' === $fam_rule || 'deny' === $fam_rule ) {
			return array(
				'kind'   => 'family',
				'rule'   => $fam_rule,
				'plugin' => $plugin,
				'family' => $family,
			);
		}

		return null;
	}

	/**
	 * Human status for a covered proposal (Activity / Dashboard action cell).
	 *
	 * @param array{kind:string,rule:string,plugin:string,family:string} $coverage
	 * @param array<string,array<string,mixed>>                          $plugins Installed plugins map.
	 */
	public static function coverage_label( array $coverage, array $plugins = array() ): string {
		$plugin = (string) ( $coverage['plugin'] ?? '' );
		$label  = $plugin;
		if ( '' !== $plugin && isset( $plugins[ $plugin ]['Name'] ) ) {
			$label = (string) $plugins[ $plugin ]['Name'];
		}

		$rule_word = 'deny' === ( $coverage['rule'] ?? '' )
			? __( 'Deny', 'handl-ai-connector-access-control' )
			: __( 'Allow', 'handl-ai-connector-access-control' );

		if ( 'family' === ( $coverage['kind'] ?? '' ) ) {
			$family_labels = Operations::family_labels();
			$family_key    = (string) ( $coverage['family'] ?? '' );
			$family_label  = $family_labels[ $family_key ] ?? $family_key;

			return sprintf(
				/* translators: 1: Allow|Deny, 2: AI type label, 3: plugin name */
				__( 'Already covered by %1$s rule for %2$s on %3$s', 'handl-ai-connector-access-control' ),
				$rule_word,
				$family_label,
				$label
			);
		}

		return sprintf(
			/* translators: 1: Allow|Deny, 2: plugin name */
			__( 'Already covered by %1$s rule for %2$s', 'handl-ai-connector-access-control' ),
			$rule_word,
			$label
		);
	}

	/**
	 * Rules-tab URL with graduate prefill query args + focus fragment.
	 *
	 * @param array{plugin:string,family?:string,provider?:string,model?:string} $proposal
	 */
	public static function rules_url( array $proposal ): string {
		$plugin = Plugin_Profile::sanitize_plugin( $proposal['plugin'] ?? '' );
		if ( '' === $plugin ) {
			return Plugin_Profile::rules_url( '' );
		}

		$args = array(
			'page'                     => 'handl-ai-connector-access-control',
			'handl_aicac_tab'          => 'rules',
			'handl_aicac_focus_plugin' => $plugin,
			'handl_aicac_graduate'     => '1',
		);

		$family = isset( $proposal['family'] ) ? sanitize_key( (string) $proposal['family'] ) : '';
		if ( '' !== $family && in_array( $family, Operations::families(), true ) ) {
			$args['handl_aicac_graduate_family'] = $family;
		}

		$provider = Model_Force::sanitize_id( $proposal['provider'] ?? '' );
		if ( '' !== $provider ) {
			$args['handl_aicac_graduate_provider'] = $provider;
		}

		$model = Model_Force::sanitize_id( $proposal['model'] ?? '' );
		if ( '' !== $model ) {
			$args['handl_aicac_graduate_model'] = $model;
		}

		return add_query_arg( $args, admin_url( 'options-general.php' ) )
			. '#handl-aicac-rule-' . rawurlencode( md5( $plugin ) );
	}

	/**
	 * Parse graduate prefill from the current request (Rules tab only).
	 *
	 * @return array{plugin:string,family:string,provider:string,model:string}|null
	 */
	public static function proposal_from_request(): ?array {
		if ( ! isset( $_REQUEST['handl_aicac_graduate'] ) || '1' !== (string) $_REQUEST['handl_aicac_graduate'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return null;
		}

		$plugin = Plugin_Profile::sanitize_plugin(
			isset( $_REQUEST['handl_aicac_focus_plugin'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				? self::unslash_string( (string) $_REQUEST['handl_aicac_focus_plugin'] )
				: ''
		);
		if ( '' === $plugin ) {
			return null;
		}

		$family = isset( $_REQUEST['handl_aicac_graduate_family'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			? sanitize_key( self::unslash_string( (string) $_REQUEST['handl_aicac_graduate_family'] ) )
			: '';
		if ( '' !== $family && ! in_array( $family, Operations::families(), true ) ) {
			$family = '';
		}

		$provider = isset( $_REQUEST['handl_aicac_graduate_provider'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			? Model_Force::sanitize_id( self::unslash_string( (string) $_REQUEST['handl_aicac_graduate_provider'] ) )
			: '';
		$model = isset( $_REQUEST['handl_aicac_graduate_model'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			? Model_Force::sanitize_id( self::unslash_string( (string) $_REQUEST['handl_aicac_graduate_model'] ) )
			: '';

		return array(
			'plugin'   => $plugin,
			'family'   => $family,
			'provider' => $provider,
			'model'    => $model,
		);
	}

	/**
	 * @param string $value Raw request value.
	 */
	private static function unslash_string( string $value ): string {
		if ( function_exists( 'wp_unslash' ) ) {
			return (string) wp_unslash( $value );
		}
		return $value;
	}
}
