<?php
/**
 * AICAC-NOTIFY-ROUTING: per-alert-type email recipients (#194).
 *
 * Shared resolve path for budget, drift, anomaly, shadow, expiry, digest,
 * and webhook-failure mail. Empty / missing routing falls back to the single
 * alert_email (or admin_email) so upgrades change nothing.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Typed recipient resolution + routing-table sanitize/validate.
 */
final class Alert_Routing {

	/**
	 * Alert types that may carry a dedicated recipient list.
	 *
	 * @var list<string>
	 */
	public const TYPES = array(
		'budget',
		'drift',
		'anomaly',
		'shadow',
		'expiry',
		'digest',
		'webhook-failure',
	);

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_type( $raw ): string {
		$type = sanitize_key( (string) $raw );
		// sanitize_key keeps hyphens; map underscore form to canonical.
		if ( 'webhook_failure' === $type ) {
			$type = 'webhook-failure';
		}
		return in_array( $type, self::TYPES, true ) ? $type : '';
	}

	/**
	 * Parse a comma-separated recipient field into unique valid emails.
	 * Plus-addressing is preserved via Alerts::sanitize_email().
	 *
	 * @param mixed $raw
	 * @return list<string>
	 */
	public static function sanitize_recipient_list( $raw ): array {
		if ( is_array( $raw ) ) {
			$parts = $raw;
		} else {
			$parts = preg_split( '/[\s,;]+/', (string) $raw ) ?: array();
		}

		$out = array();
		$seen = array();
		foreach ( $parts as $part ) {
			$email = Alerts::sanitize_email( $part );
			if ( '' === $email ) {
				continue;
			}
			$key = strtolower( $email );
			if ( isset( $seen[ $key ] ) ) {
				continue;
			}
			$seen[ $key ] = true;
			$out[]        = $email;
		}

		return $out;
	}

	/**
	 * Policy key `alert_routing`: type => comma-separated recipients (storage)
	 * or list of emails. Empty type lists are omitted.
	 *
	 * @param mixed $raw
	 * @return array<string,string> type => comma-separated emails
	 */
	public static function sanitize_routing( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}

		$out = array();
		foreach ( $raw as $type => $recipients ) {
			$type = self::sanitize_type( $type );
			if ( '' === $type ) {
				continue;
			}
			$list = self::sanitize_recipient_list( $recipients );
			if ( empty( $list ) ) {
				continue;
			}
			$out[ $type ] = implode( ', ', $list );
		}

		return $out;
	}

	/**
	 * Validate admin routing input before save.
	 *
	 * Empty / whitespace-only per type is allowed (clears that type).
	 * Any non-empty token that is not a valid email → reject with a plain error.
	 *
	 * @param mixed $raw
	 * @return array{ok:bool,routing:array<string,string>,error:string}
	 */
	public static function validate_routing_input( $raw ): array {
		if ( null === $raw || '' === $raw ) {
			return array(
				'ok'      => true,
				'routing' => array(),
				'error'   => '',
			);
		}
		if ( ! is_array( $raw ) ) {
			return array(
				'ok'      => false,
				'routing' => array(),
				'error'   => __( 'Alert routing must be a list of recipients per alert type.', 'handl-ai-connector-access-control' ),
			);
		}

		$out = array();
		foreach ( $raw as $type => $recipients ) {
			$type = self::sanitize_type( $type );
			if ( '' === $type ) {
				continue;
			}

			if ( is_array( $recipients ) ) {
				$tokens = $recipients;
			} else {
				$trimmed = trim( (string) $recipients );
				if ( '' === $trimmed ) {
					continue;
				}
				$tokens = preg_split( '/[\s,;]+/', $trimmed ) ?: array();
			}

			$list = array();
			$seen = array();
			foreach ( $tokens as $token ) {
				$token = trim( (string) $token );
				if ( '' === $token ) {
					continue;
				}
				$email = Alerts::sanitize_email( $token );
				if ( '' === $email ) {
					return array(
						'ok'      => false,
						'routing' => array(),
						'error'   => sprintf(
							/* translators: %s: invalid email address as typed */
							__( '“%s” is not a valid email address. Fix or remove it, then save again.', 'handl-ai-connector-access-control' ),
							$token
						),
					);
				}
				$key = strtolower( $email );
				if ( isset( $seen[ $key ] ) ) {
					continue;
				}
				$seen[ $key ] = true;
				$list[]       = $email;
			}

			if ( ! empty( $list ) ) {
				$out[ $type ] = implode( ', ', $list );
			}
		}

		return array(
			'ok'      => true,
			'routing' => $out,
			'error'   => '',
		);
	}

	/**
	 * Recipients for an alert type as a wp_mail-ready string.
	 *
	 * When the type has no dedicated list (or is unknown), returns the same
	 * single-address fallback as Alerts::resolve_email().
	 *
	 * @param array<string,mixed> $policy
	 */
	public static function resolve_email( array $policy, string $type ): string {
		$type = self::sanitize_type( $type );
		if ( '' !== $type ) {
			$routing = self::sanitize_routing( $policy['alert_routing'] ?? array() );
			if ( isset( $routing[ $type ] ) && '' !== $routing[ $type ] ) {
				return $routing[ $type ];
			}
		}

		return Alerts::resolve_email( $policy );
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return list<string>
	 */
	public static function resolve_recipients( array $policy, string $type ): array {
		return self::sanitize_recipient_list( self::resolve_email( $policy, $type ) );
	}
}
