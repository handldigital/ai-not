<?php
/**
 * AICAC-FINEPRINT (#455): provider terms-change watchdog.
 *
 * OFF by default. Hash-watches terms/usage-policy pages (hashes + short
 * excerpt only). Fetch failures are UNREACHABLE, never changes. Own cron,
 * own options, own admin screen. README-FREE. Hard fence vs WEATHER.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Terms-page change watchdog for configured AI providers.
 */
final class Fineprint {

	public const SETTINGS_OPTION = 'handl_aicac_fineprint';

	public const STATE_OPTION = 'handl_aicac_fineprint_state';

	public const CRON_HOOK = 'handl_aicac_fineprint_hourly';

	public const PAGE_SLUG = 'handl-aicac-fineprint';

	public const ACTION_SAVE = 'handl_aicac_fineprint_save';

	public const POST_PRESENT = 'handl_aicac_fineprint_present';

	public const POST_ENABLED = 'handl_aicac_fineprint_enabled';

	public const POST_URL_PREFIX = 'handl_aicac_fineprint_url_';

	public const QUERY_DISMISS = 'handl_aicac_fineprint_dismiss';

	public const HTTP_TIMEOUT = 8;

	public const EXCERPT_LEN = 120;

	public const LEDGER_MAX = 50;

	public const VERDICT_CHANGED = 'CHANGED';

	public const VERDICT_UNCHANGED = 'UNCHANGED';

	public const VERDICT_UNREACHABLE = 'UNREACHABLE';

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
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATE_OPTION );
		unset( $GLOBALS['handl_aicac_fineprint_http'] );
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
	 * Bundled terms/usage-policy URLs. Separate from Weather status registry.
	 *
	 * @return array<string,array{id:string,label:string,url:string}>
	 */
	public static function registry(): array {
		$roster = array(
			'openai'    => array(
				'id'    => 'openai',
				'label' => 'OpenAI',
				'url'   => 'https://openai.com/policies/terms-of-use/',
			),
			'anthropic' => array(
				'id'    => 'anthropic',
				'label' => 'Anthropic',
				'url'   => 'https://www.anthropic.com/legal/consumer-terms',
			),
		);

		/**
		 * Filter the provider terms-page registry (FINEPRINT — not Weather).
		 *
		 * @param array<string,array{id:string,label:string,url:string}> $roster Roster.
		 */
		$filtered = apply_filters( 'handl_aicac_fineprint_providers', $roster );

		return is_array( $filtered ) ? $filtered : $roster;
	}

	/**
	 * @return array{enabled:bool,urls:array<string,string>}
	 */
	public static function settings_defaults(): array {
		return array(
			'enabled' => false,
			'urls'    => array(),
		);
	}

	/**
	 * @return array{providers:array<string,array<string,mixed>>,ledger:list<array<string,mixed>>,notices:array<string,array<string,mixed>>}
	 */
	public static function state_defaults(): array {
		return array(
			'providers' => array(),
			'ledger'    => array(),
			'notices'   => array(),
		);
	}

	/**
	 * @return array{enabled:bool,urls:array<string,string>}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw.
	 * @return array{enabled:bool,urls:array<string,string>}
	 */
	public static function sanitize_settings( $raw ): array {
		$out = self::settings_defaults();
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$out['enabled'] = ! empty( $raw['enabled'] );
		$urls           = array();
		$src            = isset( $raw['urls'] ) && is_array( $raw['urls'] ) ? $raw['urls'] : array();
		foreach ( $src as $id => $url ) {
			$key = sanitize_key( (string) $id );
			$u   = esc_url_raw( trim( (string) $url ) );
			if ( '' === $key || '' === $u ) {
				continue;
			}
			$urls[ $key ] = $u;
		}
		$out['urls'] = $urls;

		return $out;
	}

	/**
	 * @return array{providers:array<string,array<string,mixed>>,ledger:list<array<string,mixed>>,notices:array<string,array<string,mixed>>}
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw.
	 * @return array{providers:array<string,array<string,mixed>>,ledger:list<array<string,mixed>>,notices:array<string,array<string,mixed>>}
	 */
	public static function sanitize_state( $raw ): array {
		$out = self::state_defaults();
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$providers = array();
		$src       = isset( $raw['providers'] ) && is_array( $raw['providers'] ) ? $raw['providers'] : array();
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

		$ledger = array();
		$lsrc   = isset( $raw['ledger'] ) && is_array( $raw['ledger'] ) ? $raw['ledger'] : array();
		foreach ( $lsrc as $entry ) {
			if ( ! is_array( $entry ) ) {
				continue;
			}
			$clean = self::sanitize_ledger_entry( $entry );
			if ( '' !== $clean['change_id'] ) {
				$ledger[] = $clean;
			}
			if ( count( $ledger ) >= self::LEDGER_MAX ) {
				break;
			}
		}
		$out['ledger'] = $ledger;

		$notices = array();
		$nsrc    = isset( $raw['notices'] ) && is_array( $raw['notices'] ) ? $raw['notices'] : array();
		foreach ( $nsrc as $cid => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$change_id = sanitize_key( (string) $cid );
			if ( '' === $change_id ) {
				continue;
			}
			$notices[ $change_id ] = array(
				'change_id' => $change_id,
				'provider'  => sanitize_key( (string) ( $row['provider'] ?? '' ) ),
				'label'     => sanitize_text_field( (string) ( $row['label'] ?? '' ) ),
				'date'      => max( 0, (int) ( $row['date'] ?? 0 ) ),
				'dismissed' => ! empty( $row['dismissed'] ),
			);
		}
		$out['notices'] = $notices;

		return $out;
	}

	/**
	 * @param array<string,mixed> $row Raw.
	 * @return array{id:string,hash:string,fetched_at:int,status:string,excerpt:string}
	 */
	public static function sanitize_provider_row( string $id, array $row ): array {
		$status = strtoupper( sanitize_key( (string) ( $row['status'] ?? 'ok' ) ) );
		if ( ! in_array( $status, array( 'ok', 'unreachable', self::VERDICT_UNREACHABLE ), true ) ) {
			$status = 'ok';
		}
		if ( self::VERDICT_UNREACHABLE === $status ) {
			$status = 'unreachable';
		}

		return array(
			'id'         => $id,
			'hash'       => preg_replace( '/[^a-f0-9]/', '', strtolower( (string) ( $row['hash'] ?? '' ) ) ) ?: '',
			'fetched_at' => max( 0, (int) ( $row['fetched_at'] ?? 0 ) ),
			'status'     => $status,
			'excerpt'    => sanitize_text_field( (string) ( $row['excerpt'] ?? '' ) ),
		);
	}

	/**
	 * @param array<string,mixed> $entry Raw.
	 * @return array{change_id:string,provider:string,label:string,date:int,previous_hash:string,current_hash:string}
	 */
	public static function sanitize_ledger_entry( array $entry ): array {
		$prev = preg_replace( '/[^a-f0-9]/', '', strtolower( (string) ( $entry['previous_hash'] ?? '' ) ) ) ?: '';
		$curr = preg_replace( '/[^a-f0-9]/', '', strtolower( (string) ( $entry['current_hash'] ?? '' ) ) ) ?: '';
		$cid  = sanitize_key( (string) ( $entry['change_id'] ?? '' ) );
		if ( '' === $cid && '' !== $curr ) {
			$cid = sanitize_key( (string) ( $entry['provider'] ?? 'x' ) . '_' . substr( $curr, 0, 12 ) );
		}

		return array(
			'change_id'     => $cid,
			'provider'      => sanitize_key( (string) ( $entry['provider'] ?? '' ) ),
			'label'         => sanitize_text_field( (string) ( $entry['label'] ?? '' ) ),
			'date'          => max( 0, (int) ( $entry['date'] ?? 0 ) ),
			'previous_hash' => $prev,
			'current_hash'  => $curr,
		);
	}

	/**
	 * Effective URL for a registry provider (settings override wins).
	 */
	public static function url_for( string $id ): string {
		$id       = sanitize_key( $id );
		$settings = self::get_settings();
		if ( isset( $settings['urls'][ $id ] ) && '' !== $settings['urls'][ $id ] ) {
			return (string) $settings['urls'][ $id ];
		}
		$reg = self::registry();

		return isset( $reg[ $id ]['url'] ) ? (string) $reg[ $id ]['url'] : '';
	}

	/**
	 * Strip volatile markup before hashing.
	 */
	public static function normalize_body( string $body ): string {
		$body = preg_replace( '#<script\b[^>]*>.*?</script>#is', ' ', $body ) ?? $body;
		$body = preg_replace( '#<style\b[^>]*>.*?</style>#is', ' ', $body ) ?? $body;
		$body = preg_replace( '#<!--.*?-->#s', ' ', $body ) ?? $body;
		$body = function_exists( 'wp_strip_all_tags' ) ? wp_strip_all_tags( $body ) : strip_tags( $body );
		$body = html_entity_decode( $body, ENT_QUOTES | ENT_HTML5, 'UTF-8' );
		$body = preg_replace( '/\s+/u', ' ', $body ) ?? $body;

		return trim( strtolower( $body ) );
	}

	public static function hash_body( string $body ): string {
		$norm = self::normalize_body( $body );

		return hash( 'sha256', $norm );
	}

	public static function excerpt_from( string $body ): string {
		$norm = self::normalize_body( $body );
		if ( function_exists( 'mb_substr' ) ) {
			return mb_substr( $norm, 0, self::EXCERPT_LEN );
		}

		return substr( $norm, 0, self::EXCERPT_LEN );
	}

	/**
	 * Pure change detector. No network.
	 *
	 * @param string|null $previous_hash Prior hash or null/empty for first fetch.
	 * @param bool        $fetch_ok      Whether the HTTP fetch succeeded.
	 * @param string      $body          Response body (ignored when unreachable).
	 */
	public static function detect( $previous_hash, bool $fetch_ok, string $body ): string {
		if ( ! $fetch_ok ) {
			return self::VERDICT_UNREACHABLE;
		}
		$prev = is_string( $previous_hash ) ? preg_replace( '/[^a-f0-9]/', '', strtolower( $previous_hash ) ) : '';
		$curr = self::hash_body( $body );
		if ( '' === $prev ) {
			// First successful fetch seeds the hash — not a change notice.
			return self::VERDICT_UNCHANGED;
		}
		if ( $prev === $curr ) {
			return self::VERDICT_UNCHANGED;
		}

		return self::VERDICT_CHANGED;
	}

	/**
	 * @param array{enabled:bool,urls:array<string,string>} $settings Settings.
	 */
	public static function put_settings( array $settings ): bool {
		$clean = self::sanitize_settings( $settings );
		if ( $clean === self::settings_defaults() ) {
			$had = get_option( self::SETTINGS_OPTION, false );
			if ( false === $had || array() === $had ) {
				return false;
			}
			delete_option( self::SETTINGS_OPTION );

			return true;
		}
		$before = self::get_settings();
		if ( $clean === $before ) {
			return false;
		}
		update_option( self::SETTINGS_OPTION, $clean, false );

		return true;
	}

	/**
	 * @param array{providers:array<string,array<string,mixed>>,ledger:list<array<string,mixed>>,notices:array<string,array<string,mixed>>} $state State.
	 */
	public static function put_state( array $state ): bool {
		$clean = self::sanitize_state( $state );
		if ( $clean === self::state_defaults() ) {
			$had = get_option( self::STATE_OPTION, false );
			if ( false === $had || array() === $had ) {
				return false;
			}
			delete_option( self::STATE_OPTION );

			return true;
		}
		$before = self::get_state();
		if ( $clean === $before ) {
			return false;
		}
		update_option( self::STATE_OPTION, $clean, false );

		return true;
	}

	/**
	 * @param array<string,mixed> $settings Form payload.
	 */
	public static function save_settings( array $settings ): bool {
		$next = self::get_settings();
		$next['enabled'] = ! empty( $settings['enabled'] );
		if ( isset( $settings['urls'] ) && is_array( $settings['urls'] ) ) {
			$urls = array();
			foreach ( $settings['urls'] as $id => $url ) {
				$key = sanitize_key( (string) $id );
				$u   = esc_url_raw( trim( (string) $url ) );
				if ( '' === $key || '' === $u ) {
					continue;
				}
				$urls[ $key ] = $u;
			}
			$next['urls'] = $urls;
		}
		$changed = self::put_settings( $next );
		if ( $next['enabled'] ) {
			self::maybe_schedule();
		} else {
			self::clear_schedule();
		}

		return $changed;
	}

	public static function is_enabled(): bool {
		return ! empty( self::get_settings()['enabled'] );
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
	 * @return array{polled:int,changed:int,unchanged:int,unreachable:int}
	 */
	public static function poll( ?int $now = null ): array {
		$now = null !== $now && $now > 0 ? $now : self::now();
		$out = array(
			'polled'      => 0,
			'changed'     => 0,
			'unchanged'   => 0,
			'unreachable' => 0,
		);
		if ( ! self::is_enabled() ) {
			return $out;
		}

		$state   = self::get_state();
		$changed = false;
		foreach ( self::registry() as $id => $meta ) {
			if ( ! is_array( $meta ) ) {
				continue;
			}
			++$out['polled'];
			$url  = self::url_for( (string) $id );
			$http = self::http_get( $url );
			$prev = isset( $state['providers'][ $id ]['hash'] ) ? (string) $state['providers'][ $id ]['hash'] : '';
			$verdict = self::detect( $prev, $http['ok'], $http['body'] );

			if ( self::VERDICT_UNREACHABLE === $verdict ) {
				++$out['unreachable'];
				$row               = $state['providers'][ $id ] ?? array();
				$row['id']         = $id;
				$row['status']     = 'unreachable';
				$row['fetched_at'] = $now;
				// Keep prior hash/excerpt — never invent a change from a failure.
				$state['providers'][ $id ] = self::sanitize_provider_row( (string) $id, $row );
				$changed                   = true;
				continue;
			}

			$hash    = self::hash_body( $http['body'] );
			$excerpt = self::excerpt_from( $http['body'] );
			$label   = (string) ( $meta['label'] ?? $id );

			if ( self::VERDICT_CHANGED === $verdict ) {
				++$out['changed'];
				$change_id = sanitize_key( $id . '_' . substr( $hash, 0, 12 ) . '_' . $now );
				$entry     = self::sanitize_ledger_entry(
					array(
						'change_id'     => $change_id,
						'provider'      => $id,
						'label'         => $label,
						'date'          => $now,
						'previous_hash' => $prev,
						'current_hash'  => $hash,
					)
				);
				array_unshift( $state['ledger'], $entry );
				if ( count( $state['ledger'] ) > self::LEDGER_MAX ) {
					$state['ledger'] = array_slice( $state['ledger'], 0, self::LEDGER_MAX );
				}
				$state['notices'][ $change_id ] = array(
					'change_id' => $change_id,
					'provider'  => $id,
					'label'     => $label,
					'date'      => $now,
					'dismissed' => false,
				);
			} else {
				++$out['unchanged'];
			}

			$state['providers'][ $id ] = self::sanitize_provider_row(
				(string) $id,
				array(
					'hash'       => $hash,
					'fetched_at' => $now,
					'status'     => 'ok',
					'excerpt'    => $excerpt,
				)
			);
			$changed = true;
		}

		if ( $changed ) {
			self::put_state( $state );
		}

		return $out;
	}

	/**
	 * @return list<array{change_id:string,provider:string,label:string,date:int}>
	 */
	public static function active_notices(): array {
		if ( ! self::is_enabled() ) {
			return array();
		}
		$out = array();
		foreach ( self::get_state()['notices'] as $row ) {
			if ( ! empty( $row['dismissed'] ) ) {
				continue;
			}
			$out[] = array(
				'change_id' => (string) $row['change_id'],
				'provider'  => (string) $row['provider'],
				'label'     => (string) $row['label'],
				'date'      => (int) $row['date'],
			);
		}

		return $out;
	}

	public static function dismiss( string $change_id ): bool {
		$change_id = sanitize_key( $change_id );
		$state     = self::get_state();
		if ( ! isset( $state['notices'][ $change_id ] ) ) {
			return false;
		}
		if ( ! empty( $state['notices'][ $change_id ]['dismissed'] ) ) {
			return false;
		}
		$state['notices'][ $change_id ]['dismissed'] = true;
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
			$when = self::format_date( (int) $notice['date'] );
			$msg  = sprintf(
				/* translators: 1: provider name, 2: Y-m-d date */
				__( '%1$s terms page changed on %2$s — review.', 'handl-ai-connector-access-control' ),
				(string) $notice['label'],
				$when
			);
			$dismiss = self::dismiss_url( (string) $notice['change_id'] );
			echo '<div class="notice notice-warning">';
			echo '<p>' . esc_html( $msg );
			if ( '' !== $dismiss ) {
				echo ' <a href="' . esc_url( $dismiss ) . '">' . esc_html__( 'Dismiss', 'handl-ai-connector-access-control' ) . '</a>';
			}
			echo '</p></div>';
		}
	}

	public static function dismiss_url( string $change_id ): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}
		$url = add_query_arg(
			array(
				'page'              => self::PAGE_SLUG,
				self::QUERY_DISMISS => $change_id,
			),
			admin_url( 'admin.php' )
		);
		if ( function_exists( 'wp_nonce_url' ) ) {
			return wp_nonce_url( $url, self::QUERY_DISMISS . '_' . $change_id );
		}
		if ( function_exists( 'wp_create_nonce' ) ) {
			return add_query_arg( '_wpnonce', wp_create_nonce( self::QUERY_DISMISS . '_' . $change_id ), $url );
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
			__( 'Fine print', 'handl-ai-connector-access-control' ),
			__( 'Fine print', 'handl-ai-connector-access-control' ),
			class_exists( Caps::class, false ) ? Caps::VIEW : 'manage_options',
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function handle_save(): void {
		if ( ! self::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save fine print settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );
		}
		$urls = array();
		foreach ( self::registry() as $id => $_meta ) {
			$key = self::POST_URL_PREFIX . $id;
			if ( isset( $_POST[ $key ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
				$urls[ $id ] = (string) wp_unslash( $_POST[ $key ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			}
		}
		self::save_settings(
			array(
				'enabled' => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'urls'    => $urls,
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

	public static function render_page(): void {
		if ( ! self::user_can_view() ) {
			return;
		}
		$settings   = self::get_settings();
		$enabled    = ! empty( $settings['enabled'] );
		$can_manage = self::user_can_manage();
		$state      = self::get_state();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Fine print', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Watch AI provider terms pages for quiet rewrites. Stores hashes only — never full page bodies. Read-only notices; does not change allow/deny rules.', 'handl-ai-connector-access-control' ) . '</p>';

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
			echo esc_html__( 'Watch provider terms pages', 'handl-ai-connector-access-control' ) . '</label>';
			echo '</td></tr>';
			foreach ( self::registry() as $id => $meta ) {
				if ( ! is_array( $meta ) ) {
					continue;
				}
				$label = (string) ( $meta['label'] ?? $id );
				$url   = self::url_for( (string) $id );
				echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td>';
				echo '<input type="url" class="regular-text" name="' . esc_attr( self::POST_URL_PREFIX . $id ) . '" value="' . esc_attr( $url ) . '" />';
				echo '</td></tr>';
			}
			echo '</tbody></table>';
			if ( function_exists( 'submit_button' ) ) {
				submit_button( __( 'Save changes', 'handl-ai-connector-access-control' ) );
			} else {
				echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Save changes', 'handl-ai-connector-access-control' ) . '</button></p>';
			}
			echo '</form>';
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Fine print watch is off. Turn it on to hash-check terms pages on an hourly schedule.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<h2>' . esc_html__( 'Providers', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Status', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Last checked', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Hash', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( self::registry() as $id => $meta ) {
			$row    = $state['providers'][ $id ] ?? array();
			$status = isset( $row['status'] ) ? (string) $row['status'] : '';
			$status = '' === $status ? __( 'Not checked yet', 'handl-ai-connector-access-control' ) : $status;
			$hash   = isset( $row['hash'] ) ? (string) $row['hash'] : '';
			$hash_s = '' === $hash ? '—' : substr( $hash, 0, 12 ) . '…';
			echo '<tr>';
			echo '<td>' . esc_html( (string) ( $meta['label'] ?? $id ) ) . '</td>';
			echo '<td>' . esc_html( $status ) . '</td>';
			echo '<td>' . esc_html( self::format_ts( (int) ( $row['fetched_at'] ?? 0 ) ) ) . '</td>';
			echo '<td><code>' . esc_html( $hash_s ) . '</code></td>';
			echo '</tr>';
		}
		echo '</tbody></table>';

		echo '<h2>' . esc_html__( 'Change ledger', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( array() === $state['ledger'] ) {
			echo '<p>' . esc_html__( 'No terms-page changes recorded yet. A first successful fetch seeds the hash without opening a notice.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Date', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Previous', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Current', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $state['ledger'] as $entry ) {
				echo '<tr>';
				echo '<td>' . esc_html( (string) ( $entry['label'] !== '' ? $entry['label'] : $entry['provider'] ) ) . '</td>';
				echo '<td>' . esc_html( self::format_date( (int) $entry['date'] ) ) . '</td>';
				echo '<td><code>' . esc_html( substr( (string) $entry['previous_hash'], 0, 12 ) . '…' ) . '</code></td>';
				echo '<td><code>' . esc_html( substr( (string) $entry['current_hash'], 0, 12 ) . '…' ) . '</code></td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}
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

	private static function format_date( int $ts ): string {
		if ( $ts <= 0 ) {
			return '—';
		}
		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( 'Y-m-d', $ts );
		}

		return gmdate( 'Y-m-d', $ts );
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
		if ( isset( $GLOBALS['handl_aicac_fineprint_http'] ) && is_callable( $GLOBALS['handl_aicac_fineprint_http'] ) ) {
			$res = call_user_func( $GLOBALS['handl_aicac_fineprint_http'], $url );
		} elseif ( function_exists( 'wp_remote_get' ) ) {
			$res = wp_remote_get(
				$url,
				array(
					'timeout'     => self::HTTP_TIMEOUT,
					'redirection' => 2,
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
