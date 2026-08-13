<?php
/**
 * AICAC-NOTE (#125): optional per-plugin-rule "why" notes.
 *
 * Plain text, length-capped, local-only. Survives Allow/Deny edits; clears when
 * the explicit rule is removed (Default / deleted / expired temp allow).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Rule_Notes {

	/** Max stored characters (plain text). */
	public const MAX_LENGTH = 500;

	/** Truncation length for Rules table / Activity display. */
	public const DISPLAY_LENGTH = 60;

	/**
	 * Sanitize basename => note map. Empty notes dropped.
	 *
	 * @param mixed $raw
	 * @return array<string,string>
	 */
	public static function sanitize_plugin_notes( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $basename => $note ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
			if ( '' === $basename ) {
				continue;
			}
			$clean = self::sanitize_note( $note );
			if ( '' === $clean ) {
				continue;
			}
			$out[ $basename ] = $clean;
		}

		return $out;
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_note( $raw ): string {
		if ( ! is_scalar( $raw ) ) {
			return '';
		}
		$note = sanitize_textarea_field( (string) $raw );
		$note = trim( $note );
		if ( '' === $note ) {
			return '';
		}
		if ( function_exists( 'mb_substr' ) ) {
			$note = mb_substr( $note, 0, self::MAX_LENGTH );
		} elseif ( strlen( $note ) > self::MAX_LENGTH ) {
			$note = substr( $note, 0, self::MAX_LENGTH );
		}

		return trim( $note );
	}

	/**
	 * Keep notes only for plugins with an explicit Allow/Deny rule.
	 *
	 * @param array<string,mixed> $policy
	 * @return array<string,mixed>
	 */
	public static function normalize_against_plugins( array $policy ): array {
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();
		$notes = self::sanitize_plugin_notes( $policy['plugin_notes'] ?? array() );
		$kept  = array();
		foreach ( $notes as $basename => $note ) {
			$rule = isset( $plugins[ $basename ] ) ? (string) $plugins[ $basename ] : '';
			if ( 'allow' !== $rule && 'deny' !== $rule ) {
				continue;
			}
			$kept[ $basename ] = $note;
		}
		$policy['plugin_notes'] = $kept;

		return $policy;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function get( array $policy, string $plugin_basename ): string {
		$plugin_basename = Plugin_Profile::sanitize_plugin( $plugin_basename );
		if ( '' === $plugin_basename ) {
			return '';
		}
		$notes = self::sanitize_plugin_notes( $policy['plugin_notes'] ?? array() );

		return $notes[ $plugin_basename ] ?? '';
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function any( array $policy ): bool {
		$notes = self::sanitize_plugin_notes( $policy['plugin_notes'] ?? array() );

		return ! empty( $notes );
	}

	/**
	 * Truncate for table display; empty in → empty out.
	 */
	public static function truncate_for_display( string $note, int $max = self::DISPLAY_LENGTH ): string {
		$note = trim( $note );
		if ( '' === $note ) {
			return '';
		}
		$len = function_exists( 'mb_strlen' ) ? mb_strlen( $note ) : strlen( $note );
		if ( $len <= $max ) {
			return $note;
		}
		$cut = function_exists( 'mb_substr' ) ? mb_substr( $note, 0, $max - 1 ) : substr( $note, 0, $max - 1 );

		return rtrim( $cut ) . '…';
	}

	/**
	 * Drop note for one basename (rule deleted / expired).
	 *
	 * @param array<string,mixed> $policy
	 * @return array<string,mixed>
	 */
	public static function clear_for_plugin( array $policy, string $plugin_basename ): array {
		$plugin_basename = Plugin_Profile::sanitize_plugin( $plugin_basename );
		if ( '' === $plugin_basename ) {
			return $policy;
		}
		$notes = self::sanitize_plugin_notes( $policy['plugin_notes'] ?? array() );
		unset( $notes[ $plugin_basename ] );
		$policy['plugin_notes'] = $notes;

		return $policy;
	}

	/**
	 * Set or clear a note for a plugin that already has an explicit rule.
	 *
	 * @param array<string,mixed> $policy
	 * @return array<string,mixed>
	 */
	public static function set_for_plugin( array $policy, string $plugin_basename, string $note ): array {
		$plugin_basename = Plugin_Profile::sanitize_plugin( $plugin_basename );
		if ( '' === $plugin_basename ) {
			return $policy;
		}
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] )
			? $policy['plugins']
			: array();
		$rule = isset( $plugins[ $plugin_basename ] ) ? (string) $plugins[ $plugin_basename ] : '';
		if ( 'allow' !== $rule && 'deny' !== $rule ) {
			return self::clear_for_plugin( $policy, $plugin_basename );
		}
		$notes = self::sanitize_plugin_notes( $policy['plugin_notes'] ?? array() );
		$clean = self::sanitize_note( $note );
		if ( '' === $clean ) {
			unset( $notes[ $plugin_basename ] );
		} else {
			$notes[ $plugin_basename ] = $clean;
		}
		$policy['plugin_notes'] = $notes;

		return $policy;
	}
}
