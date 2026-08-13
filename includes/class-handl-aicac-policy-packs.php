<?php
/**
 * Starter policy packs (AICAC-TEMPLATES / #173).
 *
 * Pack definitions live in includes/data/policy-packs.php. Apply is additive for
 * per-plugin / AI-type rules (conflicts keep the user's rule and are listed in
 * the preview). Diff rows reuse Policy_Snapshots::diff_rows.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Policy_Packs {

	/** Transient TTL for confirm-before-apply (seconds). */
	public const PREVIEW_TTL = 900;

	/**
	 * Scalar / map keys a pack may write (for active fingerprint).
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
		'new_plugin_review_enabled',
		'new_plugin_interim',
		'plugins',
		'operations',
	);

	/**
	 * Filterable catalog from data file.
	 *
	 * @return array<string,array{
	 *   id:string,
	 *   label:string,
	 *   description:string,
	 *   patch:array<string,mixed>,
	 *   plugins?:array<string,string>,
	 *   operations?:array<string,mixed>,
	 *   seed_active_plugins_allow?:bool
	 * }>
	 */
	public static function definitions(): array {
		$path = HANDL_AICAC_DIR . '/includes/data/policy-packs.php';
		$raw  = is_readable( $path ) ? include $path : array();
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}

		$defs = array();
		foreach ( $raw as $id => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$sid = sanitize_key( (string) ( $row['id'] ?? $id ) );
			if ( '' === $sid ) {
				continue;
			}
			$patch = isset( $row['patch'] ) && is_array( $row['patch'] ) ? $row['patch'] : array();
			$entry = array(
				'id'                        => $sid,
				'label'                     => (string) ( $row['label'] ?? $sid ),
				'description'               => (string) ( $row['description'] ?? '' ),
				'patch'                     => $patch,
				'seed_active_plugins_allow' => ! empty( $row['seed_active_plugins_allow'] ),
			);
			if ( isset( $row['plugins'] ) && is_array( $row['plugins'] ) ) {
				$entry['plugins'] = $row['plugins'];
			}
			if ( isset( $row['operations'] ) && is_array( $row['operations'] ) ) {
				$entry['operations'] = $row['operations'];
			}
			$defs[ $sid ] = $entry;
		}

		/**
		 * Filter the starter policy pack catalog.
		 *
		 * @param array<string,array<string,mixed>> $defs Pack id => definition.
		 */
		$filtered = apply_filters( 'handl_aicac_policy_packs', $defs );
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
			$entry = array(
				'id'                        => $sid,
				'label'                     => (string) ( $row['label'] ?? $sid ),
				'description'               => (string) ( $row['description'] ?? '' ),
				'patch'                     => $patch,
				'seed_active_plugins_allow' => ! empty( $row['seed_active_plugins_allow'] ),
			);
			if ( isset( $row['plugins'] ) && is_array( $row['plugins'] ) ) {
				$entry['plugins'] = $row['plugins'];
			}
			if ( isset( $row['operations'] ) && is_array( $row['operations'] ) ) {
				$entry['operations'] = $row['operations'];
			}
			$out[ $sid ] = $entry;
		}

		return $out;
	}

	/**
	 * @return array<string,mixed>|null
	 */
	public static function get( string $id ): ?array {
		$id   = sanitize_key( $id );
		$defs = self::definitions();
		return $defs[ $id ] ?? null;
	}

	/**
	 * Build the policy that would result after applying a pack (no save).
	 *
	 * Scalar patch keys overwrite. plugins/operations merge additively — existing
	 * user rules win on conflict. Optional seed_active_plugins_allow adds Allow
	 * for active plugins that have no rule yet (Strict pack).
	 *
	 * @param array<string,mixed> $current Normalized current policy.
	 * @param list<string>|null   $active_basenames Injectable active plugins for tests.
	 * @return array{target:array<string,mixed>,conflicts:list<array{scope:string,key:string,current:string,pack:string}>}|null
	 */
	public static function build_merge( string $id, array $current, ?array $active_basenames = null ): ?array {
		$def = self::get( $id );
		if ( null === $def ) {
			return null;
		}

		$target    = $current;
		$conflicts = array();

		foreach ( $def['patch'] as $key => $value ) {
			$target[ (string) $key ] = $value;
		}

		if ( ! empty( $target['audit_only'] ) ) {
			$target['log_enabled'] = true;
		}

		$pack_plugins = isset( $def['plugins'] ) && is_array( $def['plugins'] ) ? $def['plugins'] : array();
		if ( ! empty( $def['seed_active_plugins_allow'] ) ) {
			foreach ( self::active_plugin_basenames( $active_basenames ) as $basename ) {
				if ( ! isset( $pack_plugins[ $basename ] ) ) {
					$pack_plugins[ $basename ] = 'allow';
				}
			}
		}

		$cur_plugins = isset( $current['plugins'] ) && is_array( $current['plugins'] ) ? $current['plugins'] : array();
		$merged_plugins = $cur_plugins;
		foreach ( $pack_plugins as $basename => $rule ) {
			$basename = (string) $basename;
			$rule     = (string) $rule;
			if ( '' === $basename || ( 'allow' !== $rule && 'deny' !== $rule ) ) {
				continue;
			}
			if ( ! isset( $merged_plugins[ $basename ] ) ) {
				$merged_plugins[ $basename ] = $rule;
				continue;
			}
			$existing = (string) $merged_plugins[ $basename ];
			if ( $existing !== $rule ) {
				$conflicts[] = array(
					'scope'   => 'plugins',
					'key'     => $basename,
					'current' => $existing,
					'pack'    => $rule,
				);
			}
		}
		$target['plugins'] = $merged_plugins;

		$pack_ops = isset( $def['operations'] ) && is_array( $def['operations'] ) ? $def['operations'] : array();
		$cur_ops  = isset( $current['operations'] ) && is_array( $current['operations'] ) ? $current['operations'] : array();
		$merged_ops = $cur_ops;
		foreach ( $pack_ops as $basename => $families ) {
			$basename = (string) $basename;
			if ( '' === $basename || ! is_array( $families ) ) {
				continue;
			}
			if ( ! isset( $merged_ops[ $basename ] ) || ! is_array( $merged_ops[ $basename ] ) ) {
				$merged_ops[ $basename ] = $families;
				continue;
			}
			foreach ( $families as $family => $rule ) {
				$family = (string) $family;
				$rule   = (string) $rule;
				if ( 'allow' !== $rule && 'deny' !== $rule ) {
					continue;
				}
				if ( ! isset( $merged_ops[ $basename ][ $family ] ) ) {
					$merged_ops[ $basename ][ $family ] = $rule;
					continue;
				}
				$existing = (string) $merged_ops[ $basename ][ $family ];
				if ( $existing !== $rule ) {
					$conflicts[] = array(
						'scope'   => 'operations',
						'key'     => $basename . ':' . $family,
						'current' => $existing,
						'pack'    => $rule,
					);
				}
			}
		}
		$target['operations'] = $merged_ops;

		return array(
			'target'    => $target,
			'conflicts' => $conflicts,
		);
	}

	/**
	 * @param array<string,mixed> $current
	 * @param list<string>|null   $active_basenames
	 * @return array<string,mixed>|null
	 */
	public static function build_target( string $id, array $current, ?array $active_basenames = null ): ?array {
		$merge = self::build_merge( $id, $current, $active_basenames );
		return null === $merge ? null : $merge['target'];
	}

	/**
	 * @param array<string,mixed> $current
	 * @param list<string>|null   $active_basenames
	 */
	public static function is_active( string $id, array $current, ?array $active_basenames = null ): bool {
		$merge = self::build_merge( $id, $current, $active_basenames );
		if ( null === $merge ) {
			return false;
		}
		$def = self::get( $id );
		if ( null === $def ) {
			return false;
		}
		$keys = array_keys( $def['patch'] );
		// Include plugins when the pack seeds or ships plugin rules.
		if ( ! empty( $def['seed_active_plugins_allow'] ) || ! empty( $def['plugins'] ) ) {
			$keys[] = 'plugins';
		}
		if ( ! empty( $def['operations'] ) ) {
			$keys[] = 'operations';
		}
		$keys = array_values( array_unique( $keys ) );
		return self::fingerprint( $current, $keys ) === self::fingerprint( $merge['target'], $keys );
	}

	/**
	 * Preview payload for the Rules confirm UI.
	 *
	 * @param array<string,mixed> $current
	 * @param list<string>|null   $active_basenames
	 * @return array{
	 *   ok:bool,
	 *   error?:string,
	 *   active?:bool,
	 *   rows?:list<array{key:string,label:string,current:string,new:string}>,
	 *   conflicts?:list<array{scope:string,key:string,current:string,pack:string}>
	 * }
	 */
	public static function preview( string $id, array $current, ?array $active_basenames = null ): array {
		$merge = self::build_merge( $id, $current, $active_basenames );
		if ( null === $merge ) {
			return array(
				'ok'    => false,
				'error' => 'unknown_pack',
			);
		}
		if ( self::is_active( $id, $current, $active_basenames ) ) {
			return array(
				'ok'        => true,
				'active'    => true,
				'rows'      => array(),
				'conflicts' => array(),
			);
		}

		return array(
			'ok'        => true,
			'active'    => false,
			'rows'      => Policy_Snapshots::diff_rows( $current, $merge['target'] ),
			'conflicts' => $merge['conflicts'],
		);
	}

	/**
	 * Apply pack via Policy::save_policy. Runs New_Plugin grandfathering on enable.
	 *
	 * @param array<string,mixed> $current
	 * @param list<string>|null   $active_basenames
	 * @return array{ok:bool,status:string,error?:string,conflicts?:list<array<string,string>>}
	 */
	public static function apply( string $id, array $current, ?array $active_basenames = null ): array {
		$merge = self::build_merge( $id, $current, $active_basenames );
		if ( null === $merge ) {
			return array(
				'ok'     => false,
				'status' => 'error',
				'error'  => 'unknown_pack',
			);
		}
		if ( self::is_active( $id, $current, $active_basenames ) ) {
			return array(
				'ok'     => true,
				'status' => 'noop',
			);
		}

		$target = New_Plugin::apply_settings_transition( $merge['target'], $current, $active_basenames );
		Policy::save_policy( $target );

		return array(
			'ok'        => true,
			'status'    => 'applied',
			'conflicts' => $merge['conflicts'],
		);
	}

	public static function preview_transient_key( int $user_id ): string {
		return 'handl_aicac_pack_' . $user_id;
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
	 * @param list<string>|null $active_basenames
	 * @return list<string>
	 */
	private static function active_plugin_basenames( ?array $active_basenames ): array {
		if ( null !== $active_basenames ) {
			$out = array();
			foreach ( $active_basenames as $bn ) {
				$bn = Plugin_Profile::sanitize_plugin( $bn );
				if ( '' !== $bn ) {
					$out[] = $bn;
				}
			}
			return array_values( array_unique( $out ) );
		}
		if ( ! function_exists( 'get_option' ) ) {
			return array();
		}
		$raw = get_option( 'active_plugins', array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $bn ) {
			$bn = Plugin_Profile::sanitize_plugin( $bn );
			if ( '' !== $bn ) {
				$out[] = $bn;
			}
		}
		return array_values( array_unique( $out ) );
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
			case 'new_plugin_review_enabled':
				return (bool) $raw;
			case 'new_plugin_interim':
				return New_Plugin::sanitize_interim( $raw );
			case 'unknown_operation':
				$v = (string) $raw;
				return in_array( $v, array( 'inherit', 'allow', 'deny' ), true ) ? $v : 'inherit';
			case 'alert_mode':
				return Alerts::sanitize_mode( $raw ?? 'immediate' );
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
}
