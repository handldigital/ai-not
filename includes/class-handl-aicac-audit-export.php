<?php
/**
 * Audit log CSV export helpers (AICAC-26).
 *
 * Pure filter / format / encode logic for Activity-tab CSV download.
 * Streams at most the retained ring buffer (≤1000 rows). Column set matches
 * the on-screen admin table (excluding the Actions column).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Audit_Export {
	/** Sentinel used by Activity filters for empty/unknown field values. */
	public const FILTER_UNKNOWN = '__unknown__';

	/**
	 * CSV column headers — same fields as the admin table (no Actions).
	 *
	 * @return list<string>
	 */
	public static function column_headers( bool $include_rule_note = false ): array {
		$headers = array(
			'Time',
			'Decision',
			'Operation / family',
			'Provider',
			'Model',
			'Input tokens',
			'Output tokens',
			'Est. $',
			'Plugin',
			'Prompt',
			'User',
			'URI',
			'Request context',
			'Returned error',
		);
		if ( $include_rule_note ) {
			$headers[] = 'Rule note';
		}

		return $headers;
	}

	/**
	 * Resolve the model string the same way the admin table / filters do.
	 *
	 * @param array<string,mixed> $row
	 */
	public static function row_model( array $row ): string {
		$model = isset( $row['model'] ) ? (string) $row['model'] : '';
		if ( '' === $model && ! empty( $row['model_preferences'] ) && is_array( $row['model_preferences'] ) ) {
			$model = implode( ', ', array_map( 'strval', $row['model_preferences'] ) );
		}

		return $model;
	}

	/**
	 * @param array<string,mixed> $row
	 */
	public static function row_field( array $row, string $field ): string {
		if ( 'model' === $field ) {
			return self::row_model( $row );
		}

		return isset( $row[ $field ] ) ? (string) $row[ $field ] : '';
	}

	/**
	 * Whether a retained log row matches the active Activity filters.
	 *
	 * @param array<string,mixed>                                                         $row
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $filters
	 */
	public static function row_matches_filters( array $row, array $filters ): bool {
		foreach ( array( 'decision', 'operation', 'provider', 'model', 'plugin' ) as $field ) {
			if ( ! isset( $filters[ $field ] ) || '' === $filters[ $field ] ) {
				continue;
			}

			$value = self::row_field( $row, $field );
			if ( self::FILTER_UNKNOWN === $filters[ $field ] ) {
				if ( '' !== $value ) {
					return false;
				}
				continue;
			}

			if ( $filters[ $field ] !== $value ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Filtered rows, newest first (same order as the Activity table).
	 * Includes every matching retained entry (not capped at the on-screen 50).
	 *
	 * @param array<int,mixed>                                                            $log
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $filters
	 * @return list<array<string,mixed>>
	 */
	public static function filtered_rows( array $log, array $filters ): array {
		$out = array();
		foreach ( array_reverse( $log ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( ! self::row_matches_filters( $row, $filters ) ) {
				continue;
			}
			$out[] = $row;
		}

		return $out;
	}

	/**
	 * Format one log row as CSV cell values (empty string for null/missing).
	 *
	 * @param array<string,mixed>               $row
	 * @param array<string,array<string,mixed>> $plugins Plugin file => data (Name).
	 * @param array<string,mixed>               $policy
	 * @param array<int,string>                 $user_labels user_id => display label.
	 * @return list<string>
	 */
	public static function format_row( array $row, array $plugins, array $policy, array $user_labels = array() ): array {
		$ts        = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		$decision  = isset( $row['decision'] ) ? (string) $row['decision'] : '';
		$operation = isset( $row['operation'] ) ? (string) $row['operation'] : '';
		$provider  = isset( $row['provider'] ) ? (string) $row['provider'] : '';
		$plugin    = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
		$uri       = isset( $row['uri'] ) ? (string) $row['uri'] : '';
		$prompt    = isset( $row['prompt_preview'] ) ? (string) $row['prompt_preview'] : '';
		$user_id   = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
		$is_direct = isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'];

		if ( $is_direct && '' === $provider && ! empty( $row['shadow_provider'] ) ) {
			$provider = (string) $row['shadow_provider'];
		}

		$model = self::row_model( $row );

		$family = isset( $row['capability_family'] ) ? (string) $row['capability_family'] : '';
		if ( '' === $family && '' !== $operation && ! $is_direct ) {
			$family = Operations::family_from_operation( $operation );
		}
		$family_labels = Operations::family_labels();
		$family_label  = '';
		if ( '' !== $family ) {
			if ( isset( $family_labels[ $family ] ) ) {
				$family_label = (string) $family_labels[ $family ];
			} elseif ( Operations::FAMILY_UNKNOWN === $family ) {
				$family_label = __( 'Unknown', 'handl-ai-connector-access-control' );
			} else {
				$family_label = $family;
			}
		}

		$operation_cell = $operation;
		if ( $is_direct && ! empty( $row['host'] ) ) {
			$host = (string) $row['host'];
			$operation_cell = '' !== $operation ? $operation . ' / ' . $host : $host;
		} elseif ( '' !== $family_label ) {
			$operation_cell = '' !== $operation ? $operation . ' / ' . $family_label : $family_label;
		}

		$input_tokens  = array_key_exists( 'input_tokens', $row ) ? (string) (int) $row['input_tokens'] : '';
		$output_tokens = array_key_exists( 'output_tokens', $row ) ? (string) (int) $row['output_tokens'] : '';

		$est = '';
		$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
		$out = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
		$usd = Cost::estimate_usd( $in, $out, Cost::rates_from_policy( $policy ) );
		if ( null !== $usd ) {
			$est = Cost::format_usd( $usd );
		}

		$plugin_cell = '';
		if ( '' !== $plugin ) {
			if ( isset( $plugins[ $plugin ]['Name'] ) && '' !== (string) $plugins[ $plugin ]['Name'] ) {
				$plugin_cell = (string) $plugins[ $plugin ]['Name'] . ' (' . $plugin . ')';
			} else {
				$plugin_cell = $plugin;
			}
		}

		$user_cell = '';
		if ( $user_id > 0 ) {
			$user_cell = isset( $user_labels[ $user_id ] ) && '' !== $user_labels[ $user_id ]
				? (string) $user_labels[ $user_id ]
				: '#' . $user_id;
		}

		return array(
			$ts > 0 ? wp_date( 'Y-m-d H:i:s', $ts ) : '',
			$decision,
			$operation_cell,
			$provider,
			$model,
			$input_tokens,
			$output_tokens,
			$est,
			$plugin_cell,
			$prompt,
			$user_cell,
			$uri,
			Policy::request_context_from_row( $row ),
			Policy::returned_error_from_row( $row ),
		);
	}

	/**
	 * Build a complete CSV document (header + filtered rows).
	 *
	 * Uses PHP's fputcsv so commas/newlines/quotes are RFC-style escaped.
	 *
	 * @param array<int,mixed>                                                            $log
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $filters
	 * @param array<string,array<string,mixed>>                                           $plugins
	 * @param array<string,mixed>                                                         $policy
	 * @param array<int,string>                                                           $user_labels
	 */
	public static function build_csv( array $log, array $filters, array $plugins, array $policy, array $user_labels = array() ): string {
		$fh = fopen( 'php://temp', 'r+' );
		if ( false === $fh ) {
			return '';
		}

		$filtered         = self::filtered_rows( $log, $filters );
		$include_rule_note = false;
		foreach ( $filtered as $probe ) {
			if ( '' !== Rule_Notes::from_activity_row( $probe ) ) {
				$include_rule_note = true;
				break;
			}
		}
		fputcsv( $fh, self::column_headers( $include_rule_note ) );

		foreach ( $filtered as $row ) {
			$cells = self::format_row( $row, $plugins, $policy, $user_labels );
			if ( $include_rule_note ) {
				$cells[] = Rule_Notes::from_activity_row( $row );
			}
			fputcsv( $fh, $cells );
		}

		rewind( $fh );
		$csv = stream_get_contents( $fh );
		fclose( $fh );

		return is_string( $csv ) ? $csv : '';
	}
}
