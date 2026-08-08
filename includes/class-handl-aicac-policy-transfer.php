<?php
/**
 * Policy JSON export / import helpers (AICAC-102).
 *
 * Pure validate/diff/build logic for Rules-tab transfer. Writes go through
 * Policy::save_policy() — never a parallel option writer.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Policy_Transfer {
	/** Soft cap for uploaded JSON (~1MB). Policy option is small. */
	public const MAX_UPLOAD_BYTES = 1048576;

	/** Transient TTL for pending import preview (seconds). */
	public const PREVIEW_TTL = 900;

	/**
	 * Top-level metadata keys on the export file (not stored in OPTION_KEY).
	 *
	 * @var list<string>
	 */
	public const META_KEYS = array( 'plugin_version', 'exported_at' );

	/**
	 * Known policy option keys this plugin version understands.
	 *
	 * @return list<string>
	 */
	public static function known_policy_keys(): array {
		return array(
			'default',
			'plugins',
			'log_enabled',
			'audit_only',
			'kill_switch',
			'kill_switch_exceptions',
			'log_limit',
			'operations',
			'unknown_operation',
			'denied_tools',
			'denied_abilities', // legacy; save_policy migrates away
			'alert_on_deny',
			'alert_on_shadow',
			'alert_mode',
			'alert_email',
			'est_usd_input_per_m',
			'est_usd_output_per_m',
			'weekly_report_enabled',
			'model_force_plugins',
			'model_force_unattributed',
			'model_force_unattributed_provider',
			'model_force_unattributed_model',
			// Legacy site-wide force keys — accepted then dropped by save_policy.
			'model_force_enabled',
			'model_force_provider',
			'model_force_model',
		);
	}

	/**
	 * Build export array: full policy option plus forward-compat metadata.
	 *
	 * @param array<string,mixed> $policy Normalized policy (e.g. from Policy::get_policy()).
	 * @return array<string,mixed>
	 */
	public static function build_export( array $policy, string $plugin_version, string $exported_at ): array {
		$out = array(
			'plugin_version' => $plugin_version,
			'exported_at'    => $exported_at,
		);

		foreach ( self::known_policy_keys() as $key ) {
			if ( array_key_exists( $key, $policy ) ) {
				$out[ $key ] = $policy[ $key ];
			}
		}

		// Never export superseded site-wide force keys.
		unset( $out['model_force_enabled'], $out['model_force_provider'], $out['model_force_model'], $out['denied_abilities'] );

		return $out;
	}

	/**
	 * @param array<string,mixed> $export
	 */
	public static function encode_export( array $export ): string {
		if ( function_exists( 'wp_json_encode' ) ) {
			$json = wp_json_encode( $export, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
		} else {
			$json = json_encode( $export, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
		}
		return is_string( $json ) ? $json : '{}';
	}

	/**
	 * Parse and validate an uploaded export JSON string.
	 *
	 * Required top-level keys: plugin_version, exported_at (AC4).
	 * Unknown keys beyond meta + known policy keys are listed in ignored (AC5).
	 *
	 * @return array{
	 *   ok:true,
	 *   policy:array<string,mixed>,
	 *   ignored:list<string>,
	 *   plugin_version:string,
	 *   exported_at:string
	 * }|array{ok:false,error:string}
	 */
	public static function parse_import( string $json ) {
		$json = trim( $json );
		if ( '' === $json ) {
			return array(
				'ok'    => false,
				'error' => 'empty',
			);
		}

		$data = json_decode( $json, true );
		if ( JSON_ERROR_NONE !== json_last_error() || ! is_array( $data ) ) {
			return array(
				'ok'    => false,
				'error' => 'invalid_json',
			);
		}

		if ( ! array_key_exists( 'plugin_version', $data ) || ! array_key_exists( 'exported_at', $data ) ) {
			return array(
				'ok'    => false,
				'error' => 'missing_required_keys',
			);
		}

		$plugin_version = is_scalar( $data['plugin_version'] ) ? (string) $data['plugin_version'] : '';
		$exported_at    = is_scalar( $data['exported_at'] ) ? (string) $data['exported_at'] : '';
		if ( '' === $plugin_version || '' === $exported_at ) {
			return array(
				'ok'    => false,
				'error' => 'missing_required_keys',
			);
		}

		$known   = array_flip( array_merge( self::META_KEYS, self::known_policy_keys() ) );
		$ignored = array();
		$policy  = array();

		foreach ( $data as $key => $value ) {
			$key = (string) $key;
			if ( in_array( $key, self::META_KEYS, true ) ) {
				continue;
			}
			if ( ! isset( $known[ $key ] ) ) {
				$ignored[] = $key;
				continue;
			}
			$policy[ $key ] = $value;
		}

		sort( $ignored, SORT_STRING );

		return array(
			'ok'             => true,
			'policy'         => $policy,
			'ignored'        => $ignored,
			'plugin_version' => $plugin_version,
			'exported_at'    => $exported_at,
		);
	}

	/**
	 * Prepare imported policy for Policy::save_policy (full replace of option contents).
	 *
	 * Marks weekly_report_enabled write intent so a full replace does not
	 * accidentally preserve the target site's prior weekly key semantics.
	 *
	 * @param array<string,mixed> $imported
	 * @return array<string,mixed>
	 */
	public static function policy_for_save( array $imported ): array {
		$policy = $imported;

		if ( array_key_exists( 'weekly_report_enabled', $policy ) ) {
			$policy['_weekly_report_write'] = 'set';
		} else {
			$policy['_weekly_report_write'] = 'omit';
		}

		return $policy;
	}

	/**
	 * Diff focused governance sections for the import preview (AC2).
	 *
	 * @param array<string,mixed> $current
	 * @param array<string,mixed> $incoming
	 * @return array{
	 *   plugins:array{added:list<string>,changed:list<string>,removed:list<string>},
	 *   operations:array{added:list<string>,changed:list<string>,removed:list<string>},
	 *   kill_switch:array{changed:bool,detail:string},
	 *   denied_tools:array{added:list<string>,removed:list<string>},
	 *   model_force:array{added:list<string>,changed:list<string>,removed:list<string>,unattributed_changed:bool}
	 * }
	 */
	public static function diff_policies( array $current, array $incoming ): array {
		$cur_plugins = self::normalize_plugin_map( $current['plugins'] ?? array() );
		$in_plugins  = self::normalize_plugin_map( $incoming['plugins'] ?? array() );

		$cur_ops = is_array( $current['operations'] ?? null ) ? (array) $current['operations'] : array();
		$in_ops  = is_array( $incoming['operations'] ?? null ) ? (array) $incoming['operations'] : array();
		// Sanitize shape for stable compare without requiring full WP bootstrap beyond stubs.
		$cur_ops = self::normalize_operations_map( $cur_ops );
		$in_ops  = self::normalize_operations_map( $in_ops );

		$cur_tools = self::normalize_string_list( $current['denied_tools'] ?? $current['denied_abilities'] ?? array() );
		$in_tools  = self::normalize_string_list( $incoming['denied_tools'] ?? $incoming['denied_abilities'] ?? array() );

		$cur_force = self::normalize_force_map( $current['model_force_plugins'] ?? array() );
		$in_force  = self::normalize_force_map( $incoming['model_force_plugins'] ?? array() );

		$cur_kill = ! empty( $current['kill_switch'] );
		$in_kill  = ! empty( $incoming['kill_switch'] );
		$cur_exc  = self::normalize_string_list( $current['kill_switch_exceptions'] ?? array() );
		$in_exc   = self::normalize_string_list( $incoming['kill_switch_exceptions'] ?? array() );

		$kill_changed = ( $cur_kill !== $in_kill ) || ( $cur_exc !== $in_exc );
		$kill_detail  = '';
		if ( $kill_changed ) {
			$parts = array();
			if ( $cur_kill !== $in_kill ) {
				$parts[] = sprintf(
					'kill_switch: %s → %s',
					$cur_kill ? 'on' : 'off',
					$in_kill ? 'on' : 'off'
				);
			}
			if ( $cur_exc !== $in_exc ) {
				$parts[] = sprintf(
					'exceptions: [%s] → [%s]',
					implode( ', ', $cur_exc ),
					implode( ', ', $in_exc )
				);
			}
			$kill_detail = implode( '; ', $parts );
		}

		$cur_ua = array(
			'mode'     => (string) ( $current['model_force_unattributed'] ?? 'none' ),
			'provider' => (string) ( $current['model_force_unattributed_provider'] ?? '' ),
			'model'    => (string) ( $current['model_force_unattributed_model'] ?? '' ),
		);
		$in_ua = array(
			'mode'     => (string) ( $incoming['model_force_unattributed'] ?? 'none' ),
			'provider' => (string) ( $incoming['model_force_unattributed_provider'] ?? '' ),
			'model'    => (string) ( $incoming['model_force_unattributed_model'] ?? '' ),
		);

		return array(
			'plugins'      => self::map_diff( $cur_plugins, $in_plugins ),
			'operations'   => self::map_diff( $cur_ops, $in_ops ),
			'kill_switch'  => array(
				'changed' => $kill_changed,
				'detail'  => $kill_detail,
			),
			'denied_tools' => array(
				'added'   => array_values( array_diff( $in_tools, $cur_tools ) ),
				'removed' => array_values( array_diff( $cur_tools, $in_tools ) ),
			),
			'model_force'  => array_merge(
				self::map_diff( $cur_force, $in_force ),
				array( 'unattributed_changed' => $cur_ua !== $in_ua )
			),
		);
	}

	/**
	 * Human-readable summary lines for admin preview.
	 *
	 * @param array<string,mixed> $diff From diff_policies().
	 * @return list<string>
	 */
	public static function format_diff_lines( array $diff ): array {
		$lines = array();

		foreach ( array(
			'plugins'    => 'Per-plugin rules',
			'operations' => 'Capability-family settings',
			'model_force'=> 'Model-force pins',
		) as $section => $label ) {
			$row = is_array( $diff[ $section ] ?? null ) ? $diff[ $section ] : array();
			$added   = isset( $row['added'] ) && is_array( $row['added'] ) ? $row['added'] : array();
			$changed = isset( $row['changed'] ) && is_array( $row['changed'] ) ? $row['changed'] : array();
			$removed = isset( $row['removed'] ) && is_array( $row['removed'] ) ? $row['removed'] : array();
			if ( empty( $added ) && empty( $changed ) && empty( $removed ) ) {
				if ( 'model_force' === $section && ! empty( $row['unattributed_changed'] ) ) {
					$lines[] = $label . ': unattributed force settings will change.';
				}
				continue;
			}
			$bits = array();
			if ( ! empty( $added ) ) {
				$bits[] = 'added ' . implode( ', ', $added );
			}
			if ( ! empty( $changed ) ) {
				$bits[] = 'changed ' . implode( ', ', $changed );
			}
			if ( ! empty( $removed ) ) {
				$bits[] = 'removed ' . implode( ', ', $removed );
			}
			$lines[] = $label . ': ' . implode( '; ', $bits ) . '.';
			if ( 'model_force' === $section && ! empty( $row['unattributed_changed'] ) ) {
				$lines[] = $label . ': unattributed force settings will change.';
			}
		}

		$ks = is_array( $diff['kill_switch'] ?? null ) ? $diff['kill_switch'] : array();
		if ( ! empty( $ks['changed'] ) ) {
			$detail  = isset( $ks['detail'] ) ? (string) $ks['detail'] : '';
			$lines[] = 'Kill switch: ' . ( '' !== $detail ? $detail : 'will change.' );
		}

		$tools = is_array( $diff['denied_tools'] ?? null ) ? $diff['denied_tools'] : array();
		$t_add = isset( $tools['added'] ) && is_array( $tools['added'] ) ? $tools['added'] : array();
		$t_rem = isset( $tools['removed'] ) && is_array( $tools['removed'] ) ? $tools['removed'] : array();
		if ( ! empty( $t_add ) || ! empty( $t_rem ) ) {
			$bits = array();
			if ( ! empty( $t_add ) ) {
				$bits[] = 'added ' . implode( ', ', $t_add );
			}
			if ( ! empty( $t_rem ) ) {
				$bits[] = 'removed ' . implode( ', ', $t_rem );
			}
			$lines[] = 'Denied tools: ' . implode( '; ', $bits ) . '.';
		}

		if ( empty( $lines ) ) {
			$lines[] = 'No differences in per-plugin rules, capability-family settings, kill switch, denied tools, or model-force pins (other option fields may still change on full replace).';
		}

		return $lines;
	}

	/**
	 * @param mixed $raw
	 * @return array<string,string>
	 */
	private static function normalize_plugin_map( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $basename => $rule ) {
			$basename = (string) $basename;
			$rule     = (string) $rule;
			if ( '' === $basename ) {
				continue;
			}
			if ( 'allow' === $rule || 'deny' === $rule ) {
				$out[ $basename ] = $rule;
			}
		}
		ksort( $out, SORT_STRING );
		return $out;
	}

	/**
	 * @param array<string,mixed> $raw
	 * @return array<string,array<string,string>>
	 */
	private static function normalize_operations_map( array $raw ): array {
		$families = array( 'text', 'image', 'speech', 'tts', 'video' );
		if ( class_exists( Operations::class ) && method_exists( Operations::class, 'families' ) ) {
			$families = Operations::families();
		}
		$out = array();
		foreach ( $raw as $basename => $family_rules ) {
			$basename = (string) $basename;
			if ( '' === $basename || ! is_array( $family_rules ) ) {
				continue;
			}
			$row = array();
			foreach ( $families as $family ) {
				$rule = isset( $family_rules[ $family ] ) ? (string) $family_rules[ $family ] : '';
				if ( 'allow' === $rule || 'deny' === $rule ) {
					$row[ $family ] = $rule;
				}
			}
			if ( ! empty( $row ) ) {
				ksort( $row, SORT_STRING );
				$out[ $basename ] = $row;
			}
		}
		ksort( $out, SORT_STRING );
		return $out;
	}

	/**
	 * @param mixed $raw
	 * @return list<string>
	 */
	private static function normalize_string_list( $raw ): array {
		if ( is_string( $raw ) ) {
			$parts = preg_split( '/[\s,]+/', $raw ) ?: array();
			$raw   = $parts;
		}
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $item ) {
			$item = trim( (string) $item );
			if ( '' !== $item ) {
				$out[] = $item;
			}
		}
		$out = array_values( array_unique( $out ) );
		sort( $out, SORT_STRING );
		return $out;
	}

	/**
	 * @param mixed $raw
	 * @return array<string,array{provider:string,model:string}>
	 */
	private static function normalize_force_map( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $basename => $row ) {
			$basename = (string) $basename;
			if ( '' === $basename || ! is_array( $row ) ) {
				continue;
			}
			$provider = trim( (string) ( $row['provider'] ?? '' ) );
			$model    = trim( (string) ( $row['model'] ?? '' ) );
			if ( '' === $provider && '' === $model ) {
				continue;
			}
			$out[ $basename ] = array(
				'provider' => $provider,
				'model'    => $model,
			);
		}
		ksort( $out, SORT_STRING );
		return $out;
	}

	/**
	 * @param array<string,mixed> $current
	 * @param array<string,mixed> $incoming
	 * @return array{added:list<string>,changed:list<string>,removed:list<string>}
	 */
	private static function map_diff( array $current, array $incoming ): array {
		$added   = array();
		$changed = array();
		$removed = array();

		foreach ( $incoming as $key => $value ) {
			$key = (string) $key;
			if ( ! array_key_exists( $key, $current ) ) {
				$added[] = $key;
			} elseif ( $current[ $key ] !== $value ) {
				$changed[] = $key;
			}
		}
		foreach ( $current as $key => $_value ) {
			$key = (string) $key;
			if ( ! array_key_exists( $key, $incoming ) ) {
				$removed[] = $key;
			}
		}

		sort( $added, SORT_STRING );
		sort( $changed, SORT_STRING );
		sort( $removed, SORT_STRING );

		return array(
			'added'   => $added,
			'changed' => $changed,
			'removed' => $removed,
		);
	}

	/**
	 * Transient key for the current user's pending import preview.
	 */
	public static function preview_transient_key( int $user_id ): string {
		return 'handl_aicac_import_' . $user_id;
	}
}
