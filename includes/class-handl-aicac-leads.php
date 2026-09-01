<?php
/**
 * Opt-in onboarding lead registration (AICAC-LEADS).
 *
 * POSTs consented admin email + site metadata to HandL's lead endpoint.
 * Never runs without explicit consent. Failures are silent and never block onboarding.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Leads {
	/**
	 * Production lead intake URL on the HandL server.
	 * Overridable via HANDL_AICAC_LEADS_URL or the handl_aicac_leads_endpoint filter.
	 */
	public const DEFAULT_ENDPOINT = 'https://www.handldigital.com/aicac/leads/';

	/**
	 * Shared write token. Not a high-security secret (ships in the plugin);
	 * raises the bar above an open write + pairs with server rate limits.
	 * Overridable via HANDL_AICAC_LEADS_TOKEN constant (wp-config).
	 */
	public const DEFAULT_TOKEN = 'aicac-leads-v1-handl-optin';

	/**
	 * Whether the admin checked the opt-in box (unchecked by default).
	 *
	 * @param mixed $raw Raw POST/state value.
	 */
	public static function sanitize_consent( $raw ): bool {
		if ( is_bool( $raw ) ) {
			return $raw;
		}
		if ( is_int( $raw ) || is_float( $raw ) ) {
			return (int) $raw === 1;
		}
		$s = strtolower( trim( (string) $raw ) );
		return in_array( $s, array( '1', 'true', 'yes', 'on' ), true );
	}

	/**
	 * Endpoint URL used for the opt-in POST.
	 */
	public static function endpoint_url(): string {
		if ( defined( 'HANDL_AICAC_LEADS_URL' ) && is_string( HANDL_AICAC_LEADS_URL ) && '' !== HANDL_AICAC_LEADS_URL ) {
			$url = HANDL_AICAC_LEADS_URL;
		} else {
			$url = self::DEFAULT_ENDPOINT;
		}

		/**
		 * Filter the lead registration endpoint URL.
		 *
		 * @param string $url Endpoint URL.
		 */
		$url = (string) apply_filters( 'handl_aicac_leads_endpoint', $url );
		$url = esc_url_raw( $url );
		return is_string( $url ) ? $url : '';
	}

	/**
	 * Shared write token presented to the endpoint.
	 */
	public static function write_token(): string {
		if ( defined( 'HANDL_AICAC_LEADS_TOKEN' ) && is_string( HANDL_AICAC_LEADS_TOKEN ) && '' !== HANDL_AICAC_LEADS_TOKEN ) {
			return HANDL_AICAC_LEADS_TOKEN;
		}
		return self::DEFAULT_TOKEN;
	}

	/**
	 * Build the JSON body for a consented registration.
	 *
	 * @return array{email:string,site_url:string,plugin_version:string,consented_at:string}|null
	 */
	public static function build_payload( string $email, ?int $consented_at = null ): ?array {
		$email = Alerts::sanitize_email( $email );
		if ( '' === $email ) {
			return null;
		}

		$site = home_url( '/' );
		if ( ! is_string( $site ) || '' === $site ) {
			return null;
		}
		$site = rtrim( $site, '/' );
		if ( '' === $site ) {
			return null;
		}

		$ts = null === $consented_at ? Clock::now() : max( 0, $consented_at );

		return array(
			'email'          => $email,
			'site_url'       => $site,
			'plugin_version' => defined( 'HANDL_AICAC_VERSION' ) ? (string) HANDL_AICAC_VERSION : '',
			'consented_at'   => gmdate( 'c', $ts ),
		);
	}

	/**
	 * Register a lead only when consent is true. Zero HTTP when consent is false.
	 *
	 * Failures never throw and never block the wizard.
	 *
	 * @return bool True when a 2xx response was received.
	 */
	public static function maybe_register( string $email, bool $consented ): bool {
		if ( ! $consented ) {
			return false;
		}

		$payload = self::build_payload( $email );
		if ( null === $payload ) {
			return false;
		}

		return self::post_payload( $payload );
	}

	/**
	 * Contained POST. Never throws; non-2xx / network error → false.
	 *
	 * @param array{email:string,site_url:string,plugin_version:string,consented_at:string} $payload
	 */
	public static function post_payload( array $payload ): bool {
		$url = self::endpoint_url();
		if ( '' === $url ) {
			return false;
		}

		$body = wp_json_encode( $payload );
		if ( ! is_string( $body ) || '' === $body ) {
			return false;
		}

		try {
			$response = wp_remote_post(
				$url,
				array(
					'timeout'     => 5,
					'redirection' => 0,
					'blocking'    => true,
					'headers'     => array(
						'Content-Type'           => 'application/json; charset=utf-8',
						'X-HandL-AICAC-Token'    => self::write_token(),
						'Accept'                 => 'application/json',
					),
					'body'        => $body,
				)
			);
		} catch ( \Throwable $e ) {
			return false;
		}

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		return $code >= 200 && $code < 300;
	}
}
