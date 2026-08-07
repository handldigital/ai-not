<?php
/**
 * RFC 4180 CSV builder for the retained audit log export.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Formats retained audit-log rows for Activity-tab CSV download.
 *
 * Column set mirrors the on-screen log table data surface (not the Actions UI).
 * Does not expand chatty-host collapsed rows; exports aggregate `count` as stored.
 */
final class Log_Csv {

	/**
	 * Header labels matching Activity log table columns (plus host/count for shadow rows).
	 *
	 * @return list<string>
	 */
	public static function headers(): array {
		return array(
			'Time',
			'Decision',
			'Operation',
			'Family',
			'Host',
			'Count',
			'Provider',
			'Model',
			'Input tokens',
			'Output tokens',
			'Thought tokens',
			'Est. $',
			'Plugin',
			'Plugin file',
			'Prompt',
			'User',
			'URI',
		);
	}

	/**
	 * RFC 4180 field escape: quote when the value contains comma, quote, CR, or LF.
	 */
	public static function escape_field( string $value ): string {
		if ( false !== strpbrk( $value, ",\"\r\n" ) ) {
			return '"' . str_replace( '"', '""', $value ) . '"';
		}

		return $value;
	}

	/**
	 * @param list<string> $fields
	 */
	public static function format_line( array $fields ): string {
		$escaped = array();
		foreach ( $fields as $field ) {
			$escaped[] = self::escape_field( (string) $field );
		}

		return implode( ',', $escaped ) . "\r\n";
	}

	/**
	 * Build a full CSV document (header + data rows). Newest-first order expected from caller.
	 *
	 * @param list<array<string,mixed>>         $rows
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $plugins
	 * @param array<int,string>                 $user_labels user_id => display label
	 */
	public static function document( array $rows, array $policy, array $plugins = array(), array $user_labels = array() ): string {
		$out = self::format_line( self::headers() );
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$out .= self::format_line( self::format_row( $row, $policy, $plugins, $user_labels ) );
		}

		return $out;
	}

	/**
	 * @param array<string,mixed>               $row
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $plugins
	 * @param array<int,string>                 $user_labels
	 * @return list<string>
	 */
	public static function format_row( array $row, array $policy, array $plugins = array(), array $user_labels = array() ): array {
		$ts             = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		$decision       = isset( $row['decision'] ) ? (string) $row['decision'] : '';
		$operation      = isset( $row['operation'] ) ? (string) $row['operation'] : '';
		$provider       = isset( $row['provider'] ) ? (string) $row['provider'] : '';
		$plugin         = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
		$file           = isset( $row['file'] ) ? (string) $row['file'] : '';
		$user_id        = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
		$uri            = isset( $row['uri'] ) ? (string) $row['uri'] : '';
		$prompt         = isset( $row['prompt_preview'] ) ? (string) $row['prompt_preview'] : '';
		$input_tokens   = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
		$output_tokens  = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
		$thought_tokens = array_key_exists( 'thought_tokens', $row ) ? (int) $row['thought_tokens'] : null;
		$is_direct_http = isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'];
		$host           = isset( $row['host'] ) ? (string) $row['host'] : '';

		if ( $is_direct_http && '' === $provider && ! empty( $row['shadow_provider'] ) ) {
			$provider = (string) $row['shadow_provider'];
		}

		$model = isset( $row['model'] ) ? (string) $row['model'] : '';
		if ( '' === $model && ! empty( $row['model_preferences'] ) && is_array( $row['model_preferences'] ) ) {
			$model = implode( ', ', array_map( 'strval', $row['model_preferences'] ) );
		}

		$family = isset( $row['capability_family'] ) ? (string) $row['capability_family'] : '';
		if ( '' === $family && '' !== $operation && ! $is_direct_http ) {
			$family = Operations::family_from_operation( $operation );
		}
		if ( $is_direct_http ) {
			$family = '';
		}

		$plugin_label = $plugin;
		if ( $plugin && isset( $plugins[ $plugin ]['Name'] ) ) {
			$plugin_label = (string) $plugins[ $plugin ]['Name'] . ' (' . $plugin . ')';
		}

		$count = '';
		if ( $is_direct_http ) {
			$cluster = isset( $row['count'] ) ? (int) $row['count'] : 1;
			$count   = (string) ( $cluster > 0 ? $cluster : 1 );
		}

		$est = '';
		if ( null !== $input_tokens || null !== $output_tokens ) {
			$usd = Cost::estimate_usd( $input_tokens, $output_tokens, Cost::rates_from_policy( $policy ) );
			if ( null !== $usd ) {
				$est = Cost::format_usd( $usd );
			}
		}

		$user_label = '';
		if ( $user_id > 0 ) {
			$user_label = isset( $user_labels[ $user_id ] )
				? $user_labels[ $user_id ]
				: (string) $user_id;
		}

		$file_base = '';
		if ( '' !== $file ) {
			$file_base = function_exists( 'wp_basename' ) ? wp_basename( $file ) : basename( $file );
		}

		return array(
			self::format_timestamp( $ts ),
			$decision,
			$operation,
			$family,
			$is_direct_http ? $host : '',
			$count,
			$provider,
			$model,
			null === $input_tokens ? '' : (string) $input_tokens,
			null === $output_tokens ? '' : (string) $output_tokens,
			( null === $thought_tokens || $thought_tokens <= 0 ) ? '' : (string) $thought_tokens,
			$est,
			$plugin_label !== '' ? $plugin_label : '',
			$file_base,
			$prompt,
			$user_label,
			$uri,
		);
	}

	private static function format_timestamp( int $ts ): string {
		if ( $ts <= 0 ) {
			return '';
		}

		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( 'Y-m-d H:i:s', $ts );
		}

		return gmdate( 'Y-m-d H:i:s', $ts );
	}
}
