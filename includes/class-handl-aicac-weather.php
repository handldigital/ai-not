<?php
/**
 * AICAC-WEATHER (#447): provider status-page watchdog.
 *
 * Hourly fetch of public statuspage JSON. Tells admins "it's the provider,
 * not you" on ok → degraded/major. Fetch failures are silent. README-FREE.
 * Own option only. Own admin screen. No admin.php / policy.php / alerts.php.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Public-status watchdog for configured AI providers.
 */
final class Weather {

	public const OPTION_KEY = 'handl_aicac_weather';

	public const CRON_HOOK = 'handl_aicac_weather_hourly';

	public const PAGE_SLUG = 'handl-aicac-weather';

	public const ACTION_SAVE = 'handl_aicac_weather_save';

	public const POST_PRESENT = 'handl_aicac_weather_present';

	public const POST_ENABLED = 'handl_aicac_weather_enabled';

	public const QUERY_DISMISS = 'handl_aicac_weather_dismiss';

	public const HTTP_TIMEOUT = 5;

	public const INDICATOR_OK = 'ok';

	public const INDICATOR_DEGRADED = 'degraded';

	public const INDICATOR_MAJOR = 'major';

	/** @var bool */
	private static $registered = false;

	/** @var int|null */
	private static $test_now = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( self::CRON_HOOK, array( self::class, 'cron_run' ) );
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_init', array( self::class, 'maybe_handle_dismiss' ), 5 );
		add_action( 'admin_notices', array( self::class, 'maybe_render_notice' ) );
		self::maybe_schedule();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$test_now   = null;
		delete_option( self::OPTION_KEY );
		unset( $GLOBALS['handl_aicac_weather_http'] );
		if ( isset( $GLOBALS['handl_aicac_test_cron'] ) && is_array( $GLOBALS['handl_aicac_test_cron'] ) ) {
			unset( $GLOBALS['handl_aicac_test_cron'][ self::CRON_HOOK ] );
		}
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	public static function now(): int {
		if ( null !== self::$test_now ) {
			return self::$test_now;
		}
		$env = getenv( 'HANDL_AICAC_TEST_NOW' );
		if ( false !== $env && '' !== $env && is_numeric( $env ) ) {
			return (int) $env;
		}

		return time();
	}

	/**
	 * Default roster. Statuspage.io /v2/status.json endpoints.
	 *
	 * @return array<string,array{id:string,label:string,url:string}>
	 */
	public static function roster(): array {
		$roster = array(
			'openai'    => array(
				'id'    => 'openai',
				'label' => 'OpenAI',
				'url'   => 'https://status.openai.com/api/v2/status.json',
			),
			'anthropic' => array(
				'id'    => 'anthropic',
				'label' => 'Anthropic',
				'url'   => 'https://status.anthropic.com/api/v2/status.json',
			),
		);

		/**
		 * Filter the provider status-page roster.
		 *
		 * @param array<string,array{id:string,label:string,url:string}> $roster Roster.
		 */
		$filtered = apply_filters( 'handl_aicac_weather_providers', $roster );

		return is_array( $filtered ) ? $filtered : $roster;
	}

	/**
	 * @return array{enabled:bool,providers:array<string,array<string,mixed>>}
	 */
	public static function defaults(): array {
		return array(
			'enabled'   => false,
			'providers' => array(),
		);
	}

	/**
	 * @return array{enabled:bool,providers:array<string,array<string,mixed>>}
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::OPTION_KEY, array() ) );
	}

	/**
	 * @param mixed $raw Raw option.
	 * @return array{enabled:bool,providers:array<string,array<string,mixed>>}
	 */
	public static function sanitize_state( $raw ): array {
		$out = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$out['enabled'] = ! empty( $raw['enabled'] );
		$providers      = array();
		$src            = isset( $raw['providers'] ) && is_array( $raw['providers'] ) ? $raw['providers'] : array();
		foreach ( $src as $id => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$key = sanitize_key( (string) $id );
			if ( '' === $key ) {
				continue;
			}
			$providers[ $key ] = self::sanitize_provider_row( $key, $row );
		}
		$out['providers'] = $providers;

		return $out;
	}

	/**
	 * @param array<string,mixed> $row Raw row.
	 * @return array{id:string,indicator:string,description:string,changed_at:int,fetched_at:int,notice:bool,dismissed:bool}
	 */
	public static function sanitize_provider_row( string $id, array $row ): array {
		$indicator = self::normalize_indicator( (string) ( $row['indicator'] ?? self::INDICATOR_OK ) );

		return array(
			'id'          => $id,
			'indicator'   => $indicator,
			'description' => sanitize_text_field( (string) ( $row['description'] ?? '' ) ),
			'changed_at'  => max( 0, (int) ( $row['changed_at'] ?? 0 ) ),
			'fetched_at'  => max( 0, (int) ( $row['fetched_at'] ?? 0 ) ),
			'notice'      => ! empty( $row['notice'] ),
			'dismissed'   => ! empty( $row['dismissed'] ),
		);
	}

	/**
	 * Map statuspage indicators onto ok / degraded / major.
	 */
	public static function normalize_indicator( string $raw ): string {
		$raw = strtolower( trim( $raw ) );
		if ( in_array( $raw, array( 'none', 'ok', 'operational', '' ), true ) ) {
			return self::INDICATOR_OK;
		}
		if ( in_array( $raw, array( 'minor', 'degraded', 'degraded_performance' ), true ) ) {
			return self::INDICATOR_DEGRADED;
		}

		return self::INDICATOR_MAJOR;
	}

	public static function is_incident( string $indicator ): bool {
		return self::INDICATOR_OK !== $indicator;
	}

	/**
	 * @param array{enabled:bool,providers:array<string,array<string,mixed>>} $state State.
	 */
	public static function put_state( array $state ): bool {
		$clean = self::sanitize_state( $state );
		if ( $clean === self::defaults() ) {
			$had = get_option( self::OPTION_KEY, false );
			if ( false === $had || array() === $had ) {
				return false;
			}
			delete_option( self::OPTION_KEY );

			return true;
		}
		$before = self::get_state();
		if ( $clean === $before ) {
			return false;
		}
		update_option( self::OPTION_KEY, $clean, false );

		return true;
	}

	/**
	 * @param array<string,mixed> $settings Settings (enabled only from the form).
	 */
	public static function save_settings( array $settings ): bool {
		$state             = self::get_state();
		$state['enabled']  = ! empty( $settings['enabled'] );
		$changed           = self::put_state( $state );
		if ( $state['enabled'] ) {
			self::maybe_schedule();
		} else {
			self::clear_schedule();
		}

		return $changed;
	}

	public static function is_enabled(): bool {
		return ! empty( self::get_state()['enabled'] );
	}

	public static function maybe_schedule(): void {
		if ( ! self::is_enabled() ) {
			self::clear_schedule();

			return;
		}
		if ( ! function_exists( 'wp_next_scheduled' ) || ! function_exists( 'wp_schedule_event' ) ) {
			return;
		}
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			$hourly = defined( 'HOUR_IN_SECONDS' ) ? HOUR_IN_SECONDS : 3600;
			wp_schedule_event( time() + $hourly, 'hourly', self::CRON_HOOK );
		}
	}

	public static function clear_schedule(): void {
		if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
			wp_clear_scheduled_hook( self::CRON_HOOK );
		}
	}

	public static function cron_run(): void {
		self::poll();
	}

	/**
	 * Fetch every roster URL. Fetch failures leave that provider's stored
	 * row untouched. If every fetch fails, the option is not written.
	 *
	 * @return array{polled:int,updated:int,failed:int,notices:int}
	 */
	public static function poll( ?int $now = null ): array {
		$now = null !== $now && $now > 0 ? $now : self::now();
		$out = array(
			'polled'  => 0,
			'updated' => 0,
			'failed'  => 0,
			'notices' => 0,
		);
		if ( ! self::is_enabled() ) {
			return $out;
		}

		$state   = self::get_state();
		$changed = false;
		foreach ( self::roster() as $id => $meta ) {
			if ( ! is_array( $meta ) ) {
				continue;
			}
			++$out['polled'];
			$url  = isset( $meta['url'] ) ? (string) $meta['url'] : '';
			$http = self::http_get( $url );
			if ( ! $http['ok'] ) {
				++$out['failed'];
				continue;
			}
			$parsed = self::parse_status_payload( $http['body'] );
			if ( null === $parsed ) {
				++$out['failed'];
				continue;
			}
			$before_row = $state['providers'][ $id ] ?? null;
			$applied    = self::apply_observation( $id, $parsed['indicator'], $parsed['description'], $now, is_array( $before_row ) ? $before_row : null );
			$state['providers'][ $id ] = $applied['row'];
			++$out['updated'];
			if ( $applied['notice_opened'] ) {
				++$out['notices'];
			}
			$changed = true;
		}

		if ( $changed ) {
			self::put_state( $state );
		}

		return $out;
	}

	/**
	 * Apply one successful observation to a stored row.
	 *
	 * @param array<string,mixed>|null $before Previous row or null.
	 * @return array{row:array<string,mixed>,notice_opened:bool}
	 */
	public static function apply_observation( string $id, string $indicator, string $description, int $now, $before ): array {
		$indicator   = self::normalize_indicator( $indicator );
		$description = sanitize_text_field( $description );
		$prev        = is_array( $before ) ? self::sanitize_provider_row( $id, $before ) : null;
		$prev_ind    = $prev ? (string) $prev['indicator'] : self::INDICATOR_OK;
		$row         = $prev ? $prev : self::sanitize_provider_row(
			$id,
			array(
				'indicator'  => self::INDICATOR_OK,
				'changed_at' => 0,
			)
		);
		$row['fetched_at']  = $now;
		$row['description'] = $description;

		$notice_opened = false;
		if ( $indicator !== $prev_ind ) {
			$row['changed_at'] = $now;
			$row['indicator']  = $indicator;
			if ( self::is_incident( $indicator ) && ! self::is_incident( $prev_ind ) ) {
				$row['notice']    = true;
				$row['dismissed'] = false;
				$notice_opened    = true;
			} elseif ( self::is_incident( $indicator ) && self::is_incident( $prev_ind ) && $indicator !== $prev_ind ) {
				// Level change (degraded ↔ major) is a new incident.
				$row['notice']    = true;
				$row['dismissed'] = false;
				$notice_opened    = true;
			} elseif ( ! self::is_incident( $indicator ) ) {
				$row['notice']    = false;
				$row['dismissed'] = false;
			}
		} else {
			$row['indicator'] = $indicator;
		}

		return array(
			'row'           => self::sanitize_provider_row( $id, $row ),
			'notice_opened' => $notice_opened,
		);
	}

	/**
	 * @return array{indicator:string,description:string}|null
	 */
	public static function parse_status_payload( string $body ): ?array {
		$body = trim( $body );
		if ( '' === $body ) {
			return null;
		}
		$data = json_decode( $body, true );
		if ( ! is_array( $data ) ) {
			return null;
		}
		$status = isset( $data['status'] ) && is_array( $data['status'] ) ? $data['status'] : array();
		$raw    = isset( $status['indicator'] ) ? (string) $status['indicator'] : '';
		if ( '' === $raw && isset( $data['indicator'] ) ) {
			$raw = (string) $data['indicator'];
		}
		if ( '' === $raw ) {
			return null;
		}
		$desc = '';
		if ( isset( $status['description'] ) ) {
			$desc = (string) $status['description'];
		} elseif ( isset( $data['description'] ) ) {
			$desc = (string) $data['description'];
		}

		return array(
			'indicator'   => self::normalize_indicator( $raw ),
			'description' => sanitize_text_field( $desc ),
		);
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function active_notices(): array {
		if ( ! self::is_enabled() ) {
			return array();
		}
		$out    = array();
		$roster = self::roster();
		foreach ( self::get_state()['providers'] as $id => $row ) {
			if ( empty( $row['notice'] ) || ! empty( $row['dismissed'] ) ) {
				continue;
			}
			if ( ! self::is_incident( (string) $row['indicator'] ) ) {
				continue;
			}
			$label = isset( $roster[ $id ]['label'] ) ? (string) $roster[ $id ]['label'] : $id;
			$out[] = array(
				'id'        => $id,
				'label'     => $label,
				'indicator' => (string) $row['indicator'],
			);
		}

		return $out;
	}

	public static function dismiss( string $id ): bool {
		$id    = sanitize_key( $id );
		$state = self::get_state();
		if ( ! isset( $state['providers'][ $id ] ) ) {
			return false;
		}
		if ( ! empty( $state['providers'][ $id ]['dismissed'] ) ) {
			return false;
		}
		$state['providers'][ $id ]['dismissed'] = true;
		self::put_state( $state );

		return true;
	}

	public static function maybe_handle_dismiss(): void {
		if ( empty( $_GET[ self::QUERY_DISMISS ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		if ( ! self::user_can_view() ) {
			return;
		}
		$id = sanitize_key( wp_unslash( (string) $_GET[ self::QUERY_DISMISS ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( '' === $id ) {
			return;
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['_wpnonce'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( function_exists( 'wp_verify_nonce' ) && ! wp_verify_nonce( $nonce, self::QUERY_DISMISS . '_' . $id ) ) {
			return;
		}
		self::dismiss( $id );
	}

	public static function maybe_render_notice(): void {
		if ( ! self::user_can_view() ) {
			return;
		}
		foreach ( self::active_notices() as $notice ) {
			$level = (string) $notice['indicator'];
			$class = self::INDICATOR_MAJOR === $level ? 'notice-error' : 'notice-warning';
			$msg   = sprintf(
				/* translators: 1: provider name, 2: incident level */
				__( '%1$s is at %2$s. This is the provider, not this site.', 'handl-ai-connector-access-control' ),
				(string) $notice['label'],
				$level
			);
			$dismiss = self::dismiss_url( (string) $notice['id'] );
			echo '<div class="notice ' . esc_attr( $class ) . '">';
			echo '<p>' . esc_html( $msg );
			if ( '' !== $dismiss ) {
				echo ' <a href="' . esc_url( $dismiss ) . '">' . esc_html__( 'Dismiss', 'handl-ai-connector-access-control' ) . '</a>';
			}
			echo '</p></div>';
		}
	}

	public static function dismiss_url( string $id ): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}
		$url = add_query_arg(
			array(
				'page'               => self::PAGE_SLUG,
				self::QUERY_DISMISS  => $id,
			),
			admin_url( 'admin.php' )
		);
		if ( function_exists( 'wp_nonce_url' ) ) {
			return wp_nonce_url( $url, self::QUERY_DISMISS . '_' . $id );
		}
		if ( function_exists( 'wp_create_nonce' ) ) {
			return add_query_arg( '_wpnonce', wp_create_nonce( self::QUERY_DISMISS . '_' . $id ), $url );
		}

		return $url;
	}

	public static function register_menu(): void {
		if ( ! self::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) || ! class_exists( Admin::class, false ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Provider weather', 'handl-ai-connector-access-control' ),
			__( 'Provider weather', 'handl-ai-connector-access-control' ),
			class_exists( Caps::class, false ) ? Caps::VIEW : 'manage_options',
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function handle_save(): void {
		if ( ! self::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save provider weather.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Invalid form', 'handl-ai-connector-access-control' ) );
		}
		self::save_settings(
			array(
				'enabled' => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
			)
		);
		self::redirect_to_page();
	}

	public static function redirect_to_page(): void {
		$url = admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $url );
			exit;
		}
	}

	/**
	 * @return list<array{id:string,label:string,indicator:string,changed_at:int,fetched_at:int}>
	 */
	public static function screen_rows(): array {
		$state  = self::get_state();
		$roster = self::roster();
		$out    = array();
		foreach ( $roster as $id => $meta ) {
			if ( ! is_array( $meta ) ) {
				continue;
			}
			$row = $state['providers'][ $id ] ?? array();
			$out[] = array(
				'id'         => (string) $id,
				'label'      => (string) ( $meta['label'] ?? $id ),
				'indicator'  => isset( $row['indicator'] ) ? (string) $row['indicator'] : '',
				'changed_at' => isset( $row['changed_at'] ) ? (int) $row['changed_at'] : 0,
				'fetched_at' => isset( $row['fetched_at'] ) ? (int) $row['fetched_at'] : 0,
			);
		}

		return $out;
	}

	public static function render_page(): void {
		if ( ! self::user_can_view() ) {
			return;
		}
		$enabled    = self::is_enabled();
		$can_manage = self::user_can_manage();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Provider weather', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p>' . esc_html__( 'Public status pages for the AI providers this site uses. A down provider is not a problem with this plugin.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Watch', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1"' . checked( $enabled, true, false ) . ' /> ';
			echo esc_html__( 'Watch provider status pages', 'handl-ai-connector-access-control' ) . '</label>';
			echo '</td></tr></tbody></table>';
			if ( function_exists( 'submit_button' ) ) {
				submit_button( __( 'Save changes', 'handl-ai-connector-access-control' ) );
			} else {
				echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Save changes', 'handl-ai-connector-access-control' ) . '</button></p>';
			}
			echo '</form>';
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Provider weather is off.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<h2>' . esc_html__( 'Current weather', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Status', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Last change', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( self::screen_rows() as $row ) {
			$indicator = (string) $row['indicator'];
			$status    = '' === $indicator ? __( 'Not checked yet', 'handl-ai-connector-access-control' ) : $indicator;
			echo '<tr>';
			echo '<td>' . esc_html( (string) $row['label'] ) . '</td>';
			echo '<td>' . esc_html( $status ) . '</td>';
			echo '<td>' . esc_html( self::format_ts( (int) $row['changed_at'] ) ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
		echo '</div>';
	}

	private static function format_ts( int $ts ): string {
		if ( $ts <= 0 ) {
			return '—';
		}
		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( 'Y-m-d H:i', $ts );
		}

		return gmdate( 'Y-m-d H:i', $ts );
	}

	private static function user_can_view(): bool {
		return class_exists( Caps::class, false ) && Caps::user_can_view();
	}

	private static function user_can_manage(): bool {
		return class_exists( Caps::class, false ) && Caps::user_can_manage();
	}

	/**
	 * @return array{ok:bool,code:int,body:string,error:string}
	 */
	private static function http_get( string $url ): array {
		$fail = array(
			'ok'    => false,
			'code'  => 0,
			'body'  => '',
			'error' => 'unreachable',
		);
		if ( '' === $url ) {
			$fail['error'] = 'invalid_url';

			return $fail;
		}
		if ( isset( $GLOBALS['handl_aicac_weather_http'] ) && is_callable( $GLOBALS['handl_aicac_weather_http'] ) ) {
			$res = call_user_func( $GLOBALS['handl_aicac_weather_http'], $url );
		} elseif ( function_exists( 'wp_remote_get' ) ) {
			$res = wp_remote_get(
				$url,
				array(
					'timeout'     => self::HTTP_TIMEOUT,
					'redirection' => 0,
					'user-agent'  => 'HandL-AICAC/' . ( defined( 'HANDL_AICAC_VERSION' ) ? HANDL_AICAC_VERSION : '1' ),
				)
			);
		} else {
			$fail['error'] = 'http_unavailable';

			return $fail;
		}

		if ( is_wp_error( $res ) ) {
			return $fail;
		}
		if ( ! is_array( $res ) ) {
			return $fail;
		}
		$code = isset( $res['response']['code'] ) ? (int) $res['response']['code'] : 0;
		$body = isset( $res['body'] ) && is_string( $res['body'] ) ? $res['body'] : '';
		if ( $code < 200 || $code >= 300 ) {
			$fail['code'] = $code;

			return $fail;
		}

		return array(
			'ok'    => true,
			'code'  => $code,
			'body'  => $body,
			'error' => '',
		);
	}
}
