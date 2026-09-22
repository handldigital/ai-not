<?php
/**
 * AICAC-READONLY-SHARE (#268): expiring hashed status links for outside consultants.
 *
 * Tokens are 128-bit random values stored as HMAC-SHA256 hashes. A leaked
 * option row cannot reconstruct a working URL. Expiry and revoke are enforced
 * server-side. Views log at most one Activity row per token per hour.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Share {

	public const OPTION_KEY = 'handl_aicac_share_links';

	public const QUERY_VAR = 'handl_aicac_share';

	public const CREATE_HOOK = 'handl_aicac_share_create';

	public const REVOKE_HOOK = 'handl_aicac_share_revoke';

	public const CHANNEL = 'share';

	public const TTL_24H = '24h';
	public const TTL_7D  = '7d';
	public const TTL_30D = '30d';

	private static ?Share $instance = null;

	public static function instance(): Share {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public static function reset_for_tests(): void {
		self::$instance = null;
		delete_option( self::OPTION_KEY );
	}

	public function init(): void {
		add_filter( 'query_vars', array( $this, 'filter_query_vars' ) );
		add_action( 'template_redirect', array( $this, 'maybe_render' ), 0 );
		add_action( 'admin_post_' . self::CREATE_HOOK, array( $this, 'handle_create' ) );
		add_action( 'admin_post_' . self::REVOKE_HOOK, array( $this, 'handle_revoke' ) );
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			CLI_Share::register();
		}
	}

	/**
	 * @param list<string> $vars
	 * @return list<string>
	 */
	public function filter_query_vars( $vars ): array {
		$vars   = is_array( $vars ) ? $vars : array();
		$vars[] = self::QUERY_VAR;
		return $vars;
	}

	public function maybe_render(): void {
		$token = self::request_token();
		if ( '' === $token ) {
			return;
		}

		$row = self::lookup( $token, time() );
		if ( null === $row ) {
			self::send_gone();
			return;
		}

		$now     = time();
		$summary = self::summary( $now );
		self::record_view( $row['hash'], $now );
		self::send_page( $summary );
	}

	public function handle_create(): void {
		if ( ! class_exists( Caps::class ) || ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You cannot create a status link.', 'handl-ai-connector-access-control' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::CREATE_HOOK, 'handl_aicac_nonce' );
		$ttl    = self::sanitize_ttl( isset( $_POST['handl_aicac_share_ttl'] ) ? wp_unslash( (string) $_POST['handl_aicac_share_ttl'] ) : self::TTL_7D );
		$result = self::create( $ttl, time() );
		if ( ! empty( $result['url'] ) ) {
			self::set_flash( (string) $result['url'] );
		}
		wp_safe_redirect( Admin::screen_url( 'alerts' ) );
		exit;
	}

	public function handle_revoke(): void {
		if ( ! class_exists( Caps::class ) || ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You cannot revoke a status link.', 'handl-ai-connector-access-control' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::REVOKE_HOOK, 'handl_aicac_nonce' );
		$hash = isset( $_POST['handl_aicac_share_hash'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['handl_aicac_share_hash'] ) ) : '';
		self::revoke( $hash, time() );
		wp_safe_redirect( Admin::screen_url( 'alerts' ) );
		exit;
	}

	/**
	 * @return '24h'|'7d'|'30d'
	 */
	public static function sanitize_ttl( $raw ): string {
		$ttl = sanitize_key( (string) $raw );
		if ( self::TTL_24H === $ttl || self::TTL_30D === $ttl ) {
			return $ttl;
		}

		return self::TTL_7D;
	}

	public static function ttl_seconds( string $ttl ): int {
		$ttl = self::sanitize_ttl( $ttl );
		if ( self::TTL_24H === $ttl ) {
			return DAY_IN_SECONDS;
		}
		if ( self::TTL_30D === $ttl ) {
			return 30 * DAY_IN_SECONDS;
		}

		return 7 * DAY_IN_SECONDS;
	}

	/**
	 * @return array{ok:bool,url:string,hash:string,exp:int,ttl:string}
	 */
	public static function create( string $ttl = self::TTL_7D, ?int $now = null ): array {
		$now  = null !== $now && $now > 0 ? $now : time();
		$ttl  = self::sanitize_ttl( $ttl );
		$exp  = $now + self::ttl_seconds( $ttl );
		$plain = self::new_token();
		$hash  = self::hash_token( $plain );

		$map          = self::get_map();
		$map          = self::purge_expired( $map, $now );
		$map[ $hash ] = array(
			'exp'       => $exp,
			'created'   => $now,
			'ttl'       => $ttl,
			'last_view' => 0,
			'revoked'   => false,
		);
		self::save_map( $map );
		self::log_event(
			array(
				'ts'           => $now,
				'decision'     => 'allow',
				'channel'      => self::CHANNEL,
				'share_action' => 'create',
				'share_ttl'    => $ttl,
			)
		);

		return array(
			'ok'   => true,
			'url'  => self::public_url( $plain ),
			'hash' => $hash,
			'exp'  => $exp,
			'ttl'  => $ttl,
		);
	}

	public static function revoke( string $hash, ?int $now = null ): bool {
		$hash = self::sanitize_hash( $hash );
		$now  = null !== $now && $now > 0 ? $now : time();
		if ( '' === $hash ) {
			return false;
		}
		$map = self::get_map();
		if ( ! isset( $map[ $hash ] ) ) {
			return false;
		}
		unset( $map[ $hash ] );
		self::save_map( $map );
		self::log_event(
			array(
				'ts'           => $now,
				'decision'     => 'allow',
				'channel'      => self::CHANNEL,
				'share_action' => 'revoke',
			)
		);

		return true;
	}

	/**
	 * @return array{hash:string,exp:int,created:int,ttl:string,last_view:int}|null
	 */
	public static function lookup( string $plain, ?int $now = null ): ?array {
		$plain = self::sanitize_token( $plain );
		$now   = null !== $now && $now > 0 ? $now : time();
		if ( '' === $plain ) {
			return null;
		}
		$hash = self::hash_token( $plain );
		$map  = self::get_map();
		$found = null;
		foreach ( $map as $stored_hash => $row ) {
			if ( ! is_string( $stored_hash ) || ! is_array( $row ) ) {
				continue;
			}
			if ( ! hash_equals( $stored_hash, $hash ) ) {
				continue;
			}
			$found = $row;
			$found['hash'] = $stored_hash;
			break;
		}
		if ( ! is_array( $found ) ) {
			return null;
		}
		if ( ! empty( $found['revoked'] ) ) {
			return null;
		}
		if ( (int) ( $found['exp'] ?? 0 ) <= $now ) {
			return null;
		}

		return array(
			'hash'      => (string) $found['hash'],
			'exp'       => (int) $found['exp'],
			'created'   => (int) ( $found['created'] ?? 0 ),
			'ttl'       => self::sanitize_ttl( $found['ttl'] ?? self::TTL_7D ),
			'last_view' => (int) ( $found['last_view'] ?? 0 ),
		);
	}

	/**
	 * True when the presented value is a stored hash, not a live token.
	 */
	public static function hash_is_not_a_token( string $hash ): bool {
		$hash = self::sanitize_hash( $hash );
		if ( '' === $hash ) {
			return true;
		}

		return null === self::lookup( $hash, time() );
	}

	/**
	 * @return list<array{hash:string,exp:int,created:int,ttl:string,id:string}>
	 */
	public static function list_active( ?int $now = null ): array {
		$now = null !== $now && $now > 0 ? $now : time();
		$map = self::purge_expired( self::get_map(), $now );
		$out = array();
		foreach ( $map as $hash => $row ) {
			if ( ! is_string( $hash ) || ! is_array( $row ) ) {
				continue;
			}
			if ( ! empty( $row['revoked'] ) || (int) ( $row['exp'] ?? 0 ) <= $now ) {
				continue;
			}
			$out[] = array(
				'hash'    => $hash,
				'id'      => substr( $hash, 0, 8 ),
				'exp'     => (int) $row['exp'],
				'created' => (int) ( $row['created'] ?? 0 ),
				'ttl'     => self::sanitize_ttl( $row['ttl'] ?? self::TTL_7D ),
			);
		}

		return $out;
	}

	/**
	 * Coarse public summary — counts only, no plugin rule list.
	 *
	 * @return array{score:int,allowed:int,denied:int,calls_7d:int,denies_7d:int,providers:list<array{name:string,calls:int}>,policy_changed:int}
	 */
	public static function summary( ?int $now = null ): array {
		$now    = null !== $now && $now > 0 ? $now : time();
		$policy = class_exists( Policy::class ) ? Policy::get_policy() : array();
		$log    = class_exists( Policy::class ) ? Policy::get_retained_log( $now ) : array();
		$score  = 0;
		if ( class_exists( Governance_Coverage::class ) ) {
			$cov   = Governance_Coverage::compute( is_array( $policy ) ? $policy : array(), is_array( $log ) ? $log : array() );
			$score = (int) ( $cov['score'] ?? 0 );
		}

		$allowed = 0;
		$denied  = 0;
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] ) ? $policy['plugins'] : array();
		foreach ( $plugins as $rule ) {
			if ( 'allow' === $rule ) {
				++$allowed;
			} elseif ( 'deny' === $rule ) {
				++$denied;
			}
		}

		$since     = $now - ( 7 * DAY_IN_SECONDS );
		$calls_7d  = 0;
		$denies_7d = 0;
		$providers = array();
		foreach ( is_array( $log ) ? $log : array() as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts < $since ) {
				continue;
			}
			if ( ! self::is_counted_attempt( $row ) ) {
				continue;
			}
			$n = self::attempt_count( $row );
			$calls_7d += $n;
			if ( 'deny' === (string) ( $row['decision'] ?? '' ) ) {
				$denies_7d += $n;
			}
			$name = '';
			if ( ! empty( $row['provider'] ) && is_string( $row['provider'] ) ) {
				$name = sanitize_key( $row['provider'] );
			} elseif ( ! empty( $row['forced_provider'] ) && is_string( $row['forced_provider'] ) ) {
				$name = sanitize_key( $row['forced_provider'] );
			}
			if ( '' === $name ) {
				continue;
			}
			if ( ! isset( $providers[ $name ] ) ) {
				$providers[ $name ] = 0;
			}
			$providers[ $name ] += $n;
		}
		arsort( $providers );
		$list = array();
		foreach ( array_slice( $providers, 0, 5, true ) as $name => $calls ) {
			$list[] = array(
				'name'  => (string) $name,
				'calls' => (int) $calls,
			);
		}

		$changed = 0;
		if ( class_exists( Policy_Snapshots::class ) ) {
			$latest = Policy_Snapshots::latest();
			if ( is_array( $latest ) ) {
				$changed = (int) ( $latest['ts'] ?? 0 );
			}
			if ( $changed <= 0 ) {
				$hist = Policy_Snapshots::history();
				if ( isset( $hist[0]['ts'] ) ) {
					$changed = (int) $hist[0]['ts'];
				}
			}
		}

		return array(
			'score'          => $score,
			'allowed'        => $allowed,
			'denied'         => $denied,
			'calls_7d'       => $calls_7d,
			'denies_7d'      => $denies_7d,
			'providers'      => $list,
			'policy_changed' => $changed,
		);
	}

	public static function page_headers(): array {
		return array(
			'X-Robots-Tag' => 'noindex, nofollow',
			'Cache-Control' => 'no-store, no-cache, must-revalidate',
		);
	}

	public static function public_url( string $plain ): string {
		$plain = self::sanitize_token( $plain );
		return add_query_arg( self::QUERY_VAR, $plain, home_url( '/' ) );
	}

	public static function hash_token( string $plain ): string {
		return hash_hmac( 'sha256', self::sanitize_token( $plain ), self::secret() );
	}

	public static function render_settings(): void {
		if ( ! class_exists( Caps::class ) || ! Caps::user_can_view() ) {
			return;
		}

		$can    = Caps::user_can_manage();
		$links  = self::list_active( time() );
		$flash  = self::take_flash();

		echo '<div class="handl-aicac-share" style="margin-top:2em;max-width:40em;">';
		echo '<h2>' . esc_html__( 'Share status', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Anyone with this link can view your setup score, rule totals, recorded activity totals, provider names, and last settings change. They cannot change settings. The link expires, and you can revoke it at any time.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( '' !== $flash ) {
			echo '<div class="notice notice-success inline"><p>';
			echo esc_html__( 'Copy this link now. It will not be shown again.', 'handl-ai-connector-access-control' );
			echo '</p><p><code style="word-break:break-all;">' . esc_html( $flash ) . '</code></p></div>';
		}

		if ( $can ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="margin:12px 0;">';
			wp_nonce_field( self::CREATE_HOOK, 'handl_aicac_nonce' );
			echo '<input type="hidden" name="action" value="' . esc_attr( self::CREATE_HOOK ) . '" />';
			echo '<label for="handl-aicac-share-ttl">' . esc_html__( 'Link lasts', 'handl-ai-connector-access-control' ) . '</label> ';
			echo '<select id="handl-aicac-share-ttl" name="handl_aicac_share_ttl">';
			$opts = array(
				self::TTL_24H => __( '24 hours', 'handl-ai-connector-access-control' ),
				self::TTL_7D  => __( '7 days', 'handl-ai-connector-access-control' ),
				self::TTL_30D => __( '30 days', 'handl-ai-connector-access-control' ),
			);
			foreach ( $opts as $value => $label ) {
				echo '<option value="' . esc_attr( $value ) . '"' . selected( $value, self::TTL_7D, false ) . '>' . esc_html( $label ) . '</option>';
			}
			echo '</select> ';
			echo '<button type="submit" class="button">' . esc_html__( 'Create link', 'handl-ai-connector-access-control' ) . '</button>';
			echo '</form>';
		}

		if ( empty( $links ) ) {
			echo '<p class="description">' . esc_html__( 'No active status links.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';
			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Link ID', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Expires', 'handl-ai-connector-access-control' ) . '</th>';
		if ( $can ) {
			echo '<th></th>';
		}
		echo '</tr></thead><tbody>';
		foreach ( $links as $link ) {
			$when = function_exists( 'wp_date' ) ? wp_date( 'Y-m-d H:i', (int) $link['exp'] ) : gmdate( 'Y-m-d H:i', (int) $link['exp'] );
			echo '<tr>';
			echo '<td><code>' . esc_html( (string) $link['id'] ) . '</code></td>';
			echo '<td>' . esc_html( $when ) . '</td>';
			if ( $can ) {
				echo '<td><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="margin:0;">';
				wp_nonce_field( self::REVOKE_HOOK, 'handl_aicac_nonce' );
				echo '<input type="hidden" name="action" value="' . esc_attr( self::REVOKE_HOOK ) . '" />';
				echo '<input type="hidden" name="handl_aicac_share_hash" value="' . esc_attr( (string) $link['hash'] ) . '" />';
				echo '<button type="submit" class="button-link">' . esc_html__( 'Revoke', 'handl-ai-connector-access-control' ) . '</button>';
				echo '</form></td>';
			}
			echo '</tr>';
		}
		echo '</tbody></table>';
		echo '</div>';
	}

	public static function record_view( string $hash, int $now ): void {
		$hash = self::sanitize_hash( $hash );
		if ( '' === $hash ) {
			return;
		}
		$map = self::get_map();
		if ( ! isset( $map[ $hash ] ) || ! is_array( $map[ $hash ] ) ) {
			return;
		}
		$last = (int) ( $map[ $hash ]['last_view'] ?? 0 );
		if ( $last > 0 && ( $now - $last ) < HOUR_IN_SECONDS ) {
			return;
		}
		$map[ $hash ]['last_view'] = $now;
		self::save_map( $map );
		$ip = '';
		if ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = sanitize_text_field( wp_unslash( (string) $_SERVER['REMOTE_ADDR'] ) );
		}
		self::log_event(
			array(
				'ts'           => $now,
				'decision'     => 'allow',
				'channel'      => self::CHANNEL,
				'share_action' => 'view',
				'share_ip'     => $ip,
			)
		);
	}

	/**
	 * @param array<string,mixed> $summary
	 */
	public static function page_html( array $summary ): string {
		$changed = (int) ( $summary['policy_changed'] ?? 0 );
		$changed_label = $changed > 0
			? ( function_exists( 'wp_date' ) ? wp_date( 'Y-m-d', $changed ) : gmdate( 'Y-m-d', $changed ) )
			: __( 'Not recorded', 'handl-ai-connector-access-control' );

		ob_start();
		echo '<!DOCTYPE html><html><head><meta charset="utf-8" />';
		echo '<meta name="robots" content="noindex, nofollow" />';
		echo '<meta name="viewport" content="width=device-width, initial-scale=1" />';
		echo '<title>' . esc_html__( 'AI status', 'handl-ai-connector-access-control' ) . '</title>';
		echo '<style>body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;max-width:40em;margin:2em auto;padding:0 1em;color:#1d2327;}h1{font-size:1.4em;}dl{display:grid;grid-template-columns:12em 1fr;gap:.4em 1em;}dt{font-weight:600;}code{font-size:13px;}</style>';
		echo '</head><body>';
		echo '<h1>' . esc_html__( 'AI status', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p>' . esc_html__( 'Read-only summary. Plugin rules are not listed.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<dl>';
		echo '<dt>' . esc_html__( 'Setup score', 'handl-ai-connector-access-control' ) . '</dt>';
		echo '<dd>' . esc_html( (string) (int) ( $summary['score'] ?? 0 ) ) . '</dd>';
		echo '<dt>' . esc_html__( 'Plugins with an Allow rule', 'handl-ai-connector-access-control' ) . '</dt>';
		echo '<dd>' . esc_html( (string) (int) ( $summary['allowed'] ?? 0 ) ) . '</dd>';
		echo '<dt>' . esc_html__( 'Plugins with a Deny rule', 'handl-ai-connector-access-control' ) . '</dt>';
		echo '<dd>' . esc_html( (string) (int) ( $summary['denied'] ?? 0 ) ) . '</dd>';
		echo '<dt>' . esc_html__( 'Recorded AI calls, last 7 days', 'handl-ai-connector-access-control' ) . '</dt>';
		echo '<dd>' . esc_html( (string) (int) ( $summary['calls_7d'] ?? 0 ) ) . '</dd>';
		echo '<dt>' . esc_html__( 'Recorded blocked calls, last 7 days', 'handl-ai-connector-access-control' ) . '</dt>';
		echo '<dd>' . esc_html( (string) (int) ( $summary['denies_7d'] ?? 0 ) ) . '</dd>';
		echo '<dt>' . esc_html__( 'Settings last changed', 'handl-ai-connector-access-control' ) . '</dt>';
		echo '<dd>' . esc_html( $changed_label ) . '</dd>';
		echo '</dl>';
		echo '<p>' . esc_html__( 'Based on saved Activity. Older or unrecorded activity is not included.', 'handl-ai-connector-access-control' ) . '</p>';
		$providers = isset( $summary['providers'] ) && is_array( $summary['providers'] ) ? $summary['providers'] : array();
		if ( ! empty( $providers ) ) {
			echo '<h2>' . esc_html__( 'Providers, last 7 days', 'handl-ai-connector-access-control' ) . '</h2><ul>';
			foreach ( $providers as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				echo '<li><code>' . esc_html( (string) ( $row['name'] ?? '' ) ) . '</code> — ' . esc_html( (string) (int) ( $row['calls'] ?? 0 ) ) . '</li>';
			}
			echo '</ul>';
		}
		echo '</body></html>';

		return (string) ob_get_clean();
	}

	private static function request_token(): string {
		if ( isset( $_GET[ self::QUERY_VAR ] ) ) {
			return self::sanitize_token( wp_unslash( (string) $_GET[ self::QUERY_VAR ] ) );
		}
		if ( function_exists( 'get_query_var' ) ) {
			return self::sanitize_token( (string) get_query_var( self::QUERY_VAR, '' ) );
		}

		return '';
	}

	private static function send_gone(): void {
		if ( function_exists( 'status_header' ) ) {
			status_header( 404 );
		}
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		header( 'X-Robots-Tag: noindex, nofollow' );
		echo '<!DOCTYPE html><html><head><meta charset="utf-8" /><meta name="robots" content="noindex, nofollow" /><title>404</title></head><body><p>';
		echo esc_html__( 'This status link has expired or been revoked.', 'handl-ai-connector-access-control' );
		echo '</p></body></html>';
		exit;
	}

	/**
	 * @param array<string,mixed> $summary
	 */
	private static function send_page( array $summary ): void {
		if ( function_exists( 'status_header' ) ) {
			status_header( 200 );
		}
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		foreach ( self::page_headers() as $name => $value ) {
			header( $name . ': ' . $value );
		}
		echo self::page_html( $summary ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- page_html escapes.
		exit;
	}

	private static function new_token(): string {
		return bin2hex( random_bytes( 16 ) );
	}

	private static function secret(): string {
		if ( function_exists( 'wp_salt' ) ) {
			return (string) wp_salt( 'auth' );
		}

		return 'handl-aicac-share';
	}

	private static function sanitize_token( string $raw ): string {
		$raw = strtolower( trim( $raw ) );
		$raw = preg_replace( '/[^a-f0-9]/', '', $raw ) ?? '';
		return 32 === strlen( $raw ) ? $raw : '';
	}

	private static function sanitize_hash( string $raw ): string {
		$raw = strtolower( trim( $raw ) );
		$raw = preg_replace( '/[^a-f0-9]/', '', $raw ) ?? '';
		return 64 === strlen( $raw ) ? $raw : '';
	}

	/**
	 * @return array<string,array<string,mixed>>
	 */
	private static function get_map(): array {
		$raw = get_option( self::OPTION_KEY, array() );
		return is_array( $raw ) ? $raw : array();
	}

	/**
	 * @param array<string,array<string,mixed>> $map
	 */
	private static function save_map( array $map ): void {
		update_option( self::OPTION_KEY, $map, false );
	}

	/**
	 * @param array<string,array<string,mixed>> $map
	 * @return array<string,array<string,mixed>>
	 */
	private static function purge_expired( array $map, int $now ): array {
		$out = array();
		foreach ( $map as $hash => $row ) {
			if ( ! is_string( $hash ) || ! is_array( $row ) ) {
				continue;
			}
			if ( (int) ( $row['exp'] ?? 0 ) <= $now ) {
				continue;
			}
			$out[ $hash ] = $row;
		}

		return $out;
	}

	/**
	 * AI Client attempts that belong on the public totals (not admin/test rows).
	 *
	 * @param array<string,mixed> $row
	 */
	private static function is_counted_attempt( array $row ): bool {
		if ( class_exists( Selftest::class ) && Selftest::is_synthetic_row( $row ) ) {
			return false;
		}
		$channel = isset( $row['channel'] ) ? (string) $row['channel'] : '';
		if ( self::CHANNEL === $channel || ! empty( $row['share_action'] ) ) {
			return false;
		}
		if ( class_exists( Usage_Trends::class ) ) {
			return Usage_Trends::is_activity_row( $row );
		}

		return true;
	}

	/**
	 * Grouped deny / shadow clusters store the attempt total in `count`.
	 *
	 * @param array<string,mixed> $row
	 */
	private static function attempt_count( array $row ): int {
		$n = isset( $row['count'] ) ? (int) $row['count'] : 1;

		return $n > 0 ? $n : 1;
	}

	/**
	 * @param array<string,mixed> $event
	 */
	private static function log_event( array $event ): void {
		if ( class_exists( Policy::class ) ) {
			Policy::append_log_event( $event );
		}
	}

	private static function flash_key(): string {
		$uid = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
		return 'handl_aicac_share_flash_' . $uid;
	}

	private static function set_flash( string $url ): void {
		if ( function_exists( 'set_transient' ) ) {
			set_transient( self::flash_key(), $url, 120 );
		}
	}

	private static function take_flash(): string {
		if ( ! function_exists( 'get_transient' ) ) {
			return '';
		}
		$key = self::flash_key();
		$raw = get_transient( $key );
		if ( function_exists( 'delete_transient' ) ) {
			delete_transient( $key );
		}

		return is_string( $raw ) ? $raw : '';
	}
}

/**
 * WP-CLI stub: wp handl-aicac share create|list|revoke.
 *
 * @when after_wp_load
 */
final class CLI_Share {

	public static function register(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac share', self::class );
	}

	/**
	 * Create a read-only status link.
	 *
	 * ## OPTIONS
	 *
	 * [--ttl=<ttl>]
	 * : 24h, 7d, or 30d.
	 * ---
	 * default: 7d
	 * options:
	 *   - 24h
	 *   - 7d
	 *   - 30d
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp handl-aicac share create --ttl=7d
	 *
	 * @subcommand create
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function create( $args, $assoc_args ): void {
		unset( $args );
		$ttl    = Share::sanitize_ttl( isset( $assoc_args['ttl'] ) ? (string) $assoc_args['ttl'] : Share::TTL_7D );
		$result = Share::create( $ttl, time() );
		\WP_CLI::success( sprintf( 'Status link created. Copy it now: %s', $result['url'] ) );
	}

	/**
	 * List active status links (ids only; URLs are not stored).
	 *
	 * @subcommand list
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function list_( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$rows   = Share::list_active( time() );
		if ( 'json' === $format ) {
			$safe = array();
			foreach ( $rows as $row ) {
				$safe[] = array(
					'id'  => $row['id'],
					'ttl' => $row['ttl'],
					'exp' => $row['exp'],
				);
			}
			\WP_CLI::print_value( $safe, array( 'format' => 'json' ) );
			return;
		}
		if ( empty( $rows ) ) {
			\WP_CLI::log( 'No active status links.' );
			return;
		}
		$out = array();
		foreach ( $rows as $row ) {
			$out[] = array(
				'id'  => $row['id'],
				'ttl' => $row['ttl'],
				'exp' => gmdate( 'c', (int) $row['exp'] ),
			);
		}
		\WP_CLI\Utils\format_items( 'table', $out, array( 'id', 'ttl', 'exp' ) );
	}

	/**
	 * Revoke a status link by the 8-character id from `share list`.
	 *
	 * ## OPTIONS
	 *
	 * <id>
	 * : Short id from share list.
	 *
	 * @subcommand revoke
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public function revoke( $args, $assoc_args ): void {
		unset( $assoc_args );
		$id = isset( $args[0] ) ? strtolower( preg_replace( '/[^a-f0-9]/', '', (string) $args[0] ) ?? '' ) : '';
		if ( strlen( $id ) < 8 ) {
			\WP_CLI::error( 'Need the 8-character id from wp handl-aicac share list.' );
		}
		$hit = '';
		foreach ( Share::list_active( time() ) as $row ) {
			if ( 0 === strpos( (string) $row['hash'], $id ) ) {
				$hit = (string) $row['hash'];
				break;
			}
		}
		if ( '' === $hit || ! Share::revoke( $hit, time() ) ) {
			\WP_CLI::error( 'No active link matches that id.' );
		}
		\WP_CLI::success( 'Status link revoked.' );
	}
}
