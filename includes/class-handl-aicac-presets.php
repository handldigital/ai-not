<?php
/**
 * Curated policy presets (AICAC-PRESET / #106).
 *
 * Definitions are code data (filterable). Apply merges a patch into the current
 * policy and persists only via Policy::save_policy() — no new option keys.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One-click starting templates for Settings.
 */
final class Presets {

	/** Transient TTL for confirm-before-apply (seconds). */
	public const PREVIEW_TTL = 900;

	/**
	 * Keys each built-in preset may write. Used for fingerprints + diffs.
	 *
	 * @var list<string>
	 */
	public const TRACKED_KEYS = array(
		'default',
		'audit_only',
		'log_enabled',
		'kill_switch',
		'shadow_block_enabled',
		'unknown_operation',
		'alert_on_deny',
		'alert_on_shadow',
		'alert_mode',
		'spend_threshold_site',
		'est_usd_input_per_m',
		'est_usd_output_per_m',
		'est_usd_provider_rates',
		'plugins',
		'operations',
	);

	/**
	 * Filterable catalog. Each entry: id, label, description, patch (partial policy).
	 *
	 * @return array<string,array{id:string,label:string,description:string,patch:array<string,mixed>}>
	 */
	public static function definitions(): array {
		$defs = array(
			'observe'   => array(
				'id'          => 'observe',
				'label'       => __( 'Observe everything', 'handl-ai-connector-access-control' ),
				'description' => __( 'Watch AI activity with alerts on. Nothing is blocked.', 'handl-ai-connector-access-control' ),
				'patch'       => array(
					'default'              => 'allow',
					'audit_only'           => true,
					'log_enabled'          => true,
					'kill_switch'          => false,
					'shadow_block_enabled' => false,
					'unknown_operation'    => 'inherit',
					'alert_on_deny'        => true,
					'alert_on_shadow'      => true,
					'alert_mode'           => 'immediate',
					'spend_threshold_site' => null,
				),
			),
			'cost_guard' => array(
				'id'          => 'cost_guard',
				'label'       => __( 'Cost guard', 'handl-ai-connector-access-control' ),
				'description' => __( 'Sets a $25 estimated-spend alert and restores default rate tables. Existing block rules stay in place.', 'handl-ai-connector-access-control' ),
				'patch'       => array(
					'default'                 => 'allow',
					'audit_only'              => false,
					'log_enabled'             => true,
					'kill_switch'             => false,
					'shadow_block_enabled'    => false,
					'unknown_operation'       => 'inherit',
					'alert_on_deny'           => true,
					'alert_mode'              => 'immediate',
					'spend_threshold_site'    => 25.0,
					'est_usd_input_per_m'     => Cost::DEFAULT_INPUT_PER_M,
					'est_usd_output_per_m'    => Cost::DEFAULT_OUTPUT_PER_M,
					'est_usd_provider_rates'  => array(),
				),
			),
			'lockdown'  => array(
				'id'          => 'lockdown',
				'label'       => __( 'Strict lockdown', 'handl-ai-connector-access-control' ),
				'description' => __( 'Deny by default, block direct AI connections, and arm Emergency stop.', 'handl-ai-connector-access-control' ),
				'patch'       => array(
					'default'              => 'deny',
					'audit_only'           => false,
					'log_enabled'          => true,
					'kill_switch'          => true,
					'shadow_block_enabled' => true,
					'unknown_operation'    => 'deny',
					'alert_on_deny'        => true,
					'alert_on_shadow'      => true,
					'alert_mode'           => 'immediate',
				),
			),
			'privacy'   => array(
				'id'          => 'privacy',
				'label'       => __( 'Privacy first', 'handl-ai-connector-access-control' ),
				'description' => __( 'Deny embeddings and other unknown AI types. Block direct provider calls. Send blocked-call alerts right away.', 'handl-ai-connector-access-control' ),
				'patch'       => array(
					'default'              => 'allow',
					'audit_only'           => false,
					'log_enabled'          => true,
					'kill_switch'          => false,
					'shadow_block_enabled' => true,
					'unknown_operation'    => 'deny',
					'alert_on_deny'        => true,
					'alert_on_shadow'      => true,
					'alert_mode'           => 'immediate',
				),
			),
		);

		/**
		 * Filter the curated preset catalog.
		 *
		 * @param array<string,array<string,mixed>> $defs Preset id => definition.
		 */
		$filtered = apply_filters( 'handl_aicac_presets', $defs );
		if ( ! is_array( $filtered ) ) {
			return $defs;
		}

		$out = array();
		foreach ( $filtered as $id => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$sid = sanitize_key( (string) ( $row['id'] ?? $id ) );
			if ( '' === $sid ) {
				continue;
			}
			$patch = isset( $row['patch'] ) && is_array( $row['patch'] ) ? $row['patch'] : array();
			$out[ $sid ] = array(
				'id'          => $sid,
				'label'       => (string) ( $row['label'] ?? $sid ),
				'description' => (string) ( $row['description'] ?? '' ),
				'patch'       => $patch,
			);
		}

		return $out;
	}

	/**
	 * @return array{id:string,label:string,description:string,patch:array<string,mixed>}|null
	 */
	public static function get( string $id ): ?array {
		$id    = sanitize_key( $id );
		$defs  = self::definitions();
		return $defs[ $id ] ?? null;
	}

	/**
	 * Build the policy that would result after applying a preset (no save).
	 *
	 * @param array<string,mixed> $current Normalized current policy.
	 * @return array<string,mixed>|null
	 */
	public static function build_target( string $id, array $current ): ?array {
		$def = self::get( $id );
		if ( null === $def ) {
			return null;
		}
		$target = $current;
		foreach ( $def['patch'] as $key => $value ) {
			$target[ (string) $key ] = $value;
		}
		// Observe / audit_only always forces logging on (save_policy does too).
		if ( ! empty( $target['audit_only'] ) ) {
			$target['log_enabled'] = true;
		}
		if ( array_key_exists( 'est_usd_provider_rates', $def['patch'] ) ) {
			$target['est_usd_provider_rates'] = Cost::sanitize_provider_rates( $target['est_usd_provider_rates'] ?? array() );
		}
		if ( array_key_exists( 'spend_threshold_site', $def['patch'] ) ) {
			$target['spend_threshold_site'] = Spend_Threshold::sanitize_threshold( $target['spend_threshold_site'] ?? null );
		}

		return $target;
	}

	/**
	 * True when current policy already matches the preset's tracked patch.
	 *
	 * @param array<string,mixed> $current
	 */
	public static function is_active( string $id, array $current ): bool {
		$target = self::build_target( $id, $current );
		if ( null === $target ) {
			return false;
		}
		$def = self::get( $id );
		if ( null === $def ) {
			return false;
		}
		$keys = array_keys( $def['patch'] );
		return self::fingerprint( $current, $keys ) === self::fingerprint( $target, $keys );
	}

	/**
	 * Human-readable current → new rows for the confirmation screen.
	 *
	 * @param array<string,mixed> $current
	 * @return array{ok:bool,error?:string,active?:bool,rows?:list<array{key:string,label:string,current:string,new:string,overwrite:bool}>,overwrites?:bool}
	 */
	public static function diff( string $id, array $current ): array {
		$def = self::get( $id );
		if ( null === $def ) {
			return array(
				'ok'    => false,
				'error' => 'unknown_preset',
			);
		}
		if ( self::is_active( $id, $current ) ) {
			return array(
				'ok'     => true,
				'active' => true,
				'rows'   => array(),
				'overwrites' => false,
			);
		}

		$target = self::build_target( $id, $current );
		if ( null === $target ) {
			return array(
				'ok'    => false,
				'error' => 'unknown_preset',
			);
		}

		$rows       = array();
		$overwrites = false;
		foreach ( $def['patch'] as $key => $_ignored ) {
			$key = (string) $key;
			$cur_val = $current[ $key ] ?? null;
			$new_val = $target[ $key ] ?? null;
			if ( self::values_equal( $key, $cur_val, $new_val ) ) {
				continue;
			}
			$overwrite = self::is_overwrite( $key, $cur_val, $new_val );
			if ( $overwrite ) {
				$overwrites = true;
			}
			$rows[] = array(
				'key'       => $key,
				'label'     => self::field_label( $key ),
				'current'   => self::format_value( $key, $cur_val ),
				'new'       => self::format_value( $key, $new_val ),
				'overwrite' => $overwrite,
			);
		}

		return array(
			'ok'         => true,
			'active'     => false,
			'rows'       => $rows,
			'overwrites' => $overwrites,
		);
	}

	/**
	 * Apply preset via Policy::save_policy. Idempotent no-op when already active.
	 *
	 * @param array<string,mixed> $current
	 * @return array{ok:bool,status:string,error?:string}
	 */
	public static function apply( string $id, array $current ): array {
		$def = self::get( $id );
		if ( null === $def ) {
			return array(
				'ok'     => false,
				'status' => 'error',
				'error'  => 'unknown_preset',
			);
		}
		if ( self::is_active( $id, $current ) ) {
			return array(
				'ok'     => true,
				'status' => 'noop',
			);
		}
		$target = self::build_target( $id, $current );
		if ( null === $target ) {
			return array(
				'ok'     => false,
				'status' => 'error',
				'error'  => 'unknown_preset',
			);
		}
		Policy::save_policy( $target );

		return array(
			'ok'     => true,
			'status' => 'applied',
		);
	}

	public static function preview_transient_key( int $user_id ): string {
		return 'handl_aicac_preset_' . $user_id;
	}

	/**
	 * @param list<string>        $keys
	 * @param array<string,mixed> $policy
	 */
	public static function fingerprint( array $policy, array $keys ): string {
		$slice = array();
		foreach ( $keys as $key ) {
			$key = (string) $key;
			$slice[ $key ] = self::normalize_for_compare( $key, $policy[ $key ] ?? null );
		}
		ksort( $slice, SORT_STRING );
		$json = wp_json_encode( $slice );
		return is_string( $json ) ? md5( $json ) : '';
	}

	/**
	 * @param mixed $raw
	 * @return mixed
	 */
	private static function normalize_for_compare( string $key, $raw ) {
		switch ( $key ) {
			case 'default':
				return ( 'deny' === $raw ) ? 'deny' : 'allow';
			case 'audit_only':
			case 'log_enabled':
			case 'kill_switch':
			case 'shadow_block_enabled':
			case 'alert_on_deny':
			case 'alert_on_shadow':
				return (bool) $raw;
			case 'unknown_operation':
				$v = (string) $raw;
				return in_array( $v, array( 'inherit', 'allow', 'deny' ), true ) ? $v : 'inherit';
			case 'alert_mode':
				return Alerts::sanitize_mode( $raw ?? 'immediate' );
			case 'spend_threshold_site':
				return Spend_Threshold::sanitize_threshold( $raw );
			case 'est_usd_input_per_m':
				return Cost::sanitize_rate( $raw ?? Cost::DEFAULT_INPUT_PER_M, Cost::DEFAULT_INPUT_PER_M );
			case 'est_usd_output_per_m':
				return Cost::sanitize_rate( $raw ?? Cost::DEFAULT_OUTPUT_PER_M, Cost::DEFAULT_OUTPUT_PER_M );
			case 'est_usd_provider_rates':
				return Cost::sanitize_provider_rates( is_array( $raw ) ? $raw : array() );
			case 'plugins':
				if ( ! is_array( $raw ) ) {
					return array();
				}
				$out = array();
				foreach ( $raw as $basename => $rule ) {
					$basename = (string) $basename;
					$rule     = (string) $rule;
					if ( '' !== $basename && ( 'allow' === $rule || 'deny' === $rule ) ) {
						$out[ $basename ] = $rule;
					}
				}
				ksort( $out, SORT_STRING );
				return $out;
			case 'operations':
				return is_array( $raw ) ? Policy::sanitize_operations( $raw ) : array();
			default:
				return $raw;
		}
	}

	/**
	 * @param mixed $a
	 * @param mixed $b
	 */
	private static function values_equal( string $key, $a, $b ): bool {
		return self::normalize_for_compare( $key, $a ) === self::normalize_for_compare( $key, $b );
	}

	/**
	 * @param mixed $cur
	 * @param mixed $new
	 */
	private static function is_overwrite( string $key, $cur, $new ): bool {
		if ( 'plugins' !== $key && 'operations' !== $key ) {
			return false;
		}
		$cur_n = self::normalize_for_compare( $key, $cur );
		$new_n = self::normalize_for_compare( $key, $new );
		if ( ! is_array( $cur_n ) || empty( $cur_n ) ) {
			return false;
		}
		// Changing or clearing existing custom rules is an overwrite.
		return $cur_n !== $new_n;
	}

	private static function field_label( string $key ): string {
		$labels = array(
			'default'                 => __( 'Default policy', 'handl-ai-connector-access-control' ),
			'audit_only'              => __( 'Learn mode (observe only)', 'handl-ai-connector-access-control' ),
			'log_enabled'             => __( 'Activity logging', 'handl-ai-connector-access-control' ),
			'kill_switch'             => __( 'Emergency stop', 'handl-ai-connector-access-control' ),
			'shadow_block_enabled'    => __( 'Block direct AI connections', 'handl-ai-connector-access-control' ),
			'unknown_operation'       => __( 'Unknown AI operations', 'handl-ai-connector-access-control' ),
			'alert_on_deny'           => __( 'Blocked-call email alerts', 'handl-ai-connector-access-control' ),
			'alert_on_shadow'         => __( 'Direct-connection email alerts', 'handl-ai-connector-access-control' ),
			'alert_mode'              => __( 'Alert timing', 'handl-ai-connector-access-control' ),
			'spend_threshold_site'    => __( 'Site estimated-spend alert', 'handl-ai-connector-access-control' ),
			'est_usd_input_per_m'     => __( 'Default input rate ($ / 1M tokens)', 'handl-ai-connector-access-control' ),
			'est_usd_output_per_m'    => __( 'Default output rate ($ / 1M tokens)', 'handl-ai-connector-access-control' ),
			'est_usd_provider_rates'  => __( 'Provider rate table', 'handl-ai-connector-access-control' ),
			'plugins'                 => __( 'Per-plugin rules', 'handl-ai-connector-access-control' ),
			'operations'              => __( 'Capability-family rules', 'handl-ai-connector-access-control' ),
		);

		return $labels[ $key ] ?? $key;
	}

	/**
	 * @param mixed $value
	 */
	private static function format_value( string $key, $value ): string {
		$value = self::normalize_for_compare( $key, $value );
		switch ( $key ) {
			case 'audit_only':
			case 'log_enabled':
			case 'kill_switch':
			case 'shadow_block_enabled':
			case 'alert_on_deny':
			case 'alert_on_shadow':
				return $value ? __( 'On', 'handl-ai-connector-access-control' ) : __( 'Off', 'handl-ai-connector-access-control' );
			case 'default':
				return 'deny' === $value
					? __( 'Deny', 'handl-ai-connector-access-control' )
					: __( 'Allow', 'handl-ai-connector-access-control' );
			case 'unknown_operation':
				if ( 'deny' === $value ) {
					return __( 'Deny', 'handl-ai-connector-access-control' );
				}
				if ( 'allow' === $value ) {
					return __( 'Allow', 'handl-ai-connector-access-control' );
				}
				return __( 'Follow plugin rule', 'handl-ai-connector-access-control' );
			case 'alert_mode':
				return 'digest' === $value
					? __( 'Hourly summary', 'handl-ai-connector-access-control' )
					: __( 'Immediate', 'handl-ai-connector-access-control' );
			case 'spend_threshold_site':
				if ( null === $value ) {
					return __( 'Off', 'handl-ai-connector-access-control' );
				}
				return '$' . rtrim( rtrim( number_format( (float) $value, 2, '.', '' ), '0' ), '.' );
			case 'est_usd_input_per_m':
			case 'est_usd_output_per_m':
				return (string) $value;
			case 'est_usd_provider_rates':
				if ( ! is_array( $value ) || empty( $value ) ) {
					return __( 'Default rates', 'handl-ai-connector-access-control' );
				}
				return sprintf(
					/* translators: %d: number of provider rate rows */
					_n( '%d provider rate', '%d provider rates', count( $value ), 'handl-ai-connector-access-control' ),
					count( $value )
				);
			case 'plugins':
			case 'operations':
				if ( ! is_array( $value ) || empty( $value ) ) {
					return __( 'None', 'handl-ai-connector-access-control' );
				}
				return sprintf(
					/* translators: %d: number of custom rules */
					_n( '%d custom rule', '%d custom rules', count( $value ), 'handl-ai-connector-access-control' ),
					count( $value )
				);
			default:
				if ( is_scalar( $value ) || null === $value ) {
					return null === $value ? '—' : (string) $value;
				}
				$json = wp_json_encode( $value );
				return is_string( $json ) ? $json : '—';
		}
	}
}
