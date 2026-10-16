<?php
/**
 * AICAC-DIVIDEND (#442): AI referral dividend — traffic AI tools send back.
 *
 * Frontend census of human visits arriving from known AI-tool referrers
 * (ChatGPT, Perplexity, Gemini, Copilot, Claude, …). Bounded ledger of
 * per-source counts, week buckets, and landing-path samples. Soft-reads the
 * BOTWATCH ledger option when present for a give-vs-get headline — never a
 * hard dependency. README-FREE; options confined to handl_aicac_dividend*.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * AI referral dividend report.
 */
final class Dividend {

	public const SETTINGS_OPTION = 'handl_aicac_dividend';

	public const LEDGER_OPTION = 'handl_aicac_dividend_ledger';

	/** Soft-read only — owned by BOTWATCH (#441). */
	public const BOTWATCH_LEDGER_OPTION = 'handl_aicac_botwatch_ledger';

	public const PAGE_SLUG = 'handl-aicac-dividend';

	public const ACTION_SAVE = 'handl_aicac_dividend_save';

	public const POST_PRESENT = 'handl_aicac_dividend_present';

	public const POST_ENABLED = 'handl_aicac_dividend_enabled';

	public const MAX_SOURCES = 40;

	public const MAX_LANDINGS_PER_SOURCE = 25;

	public const MAX_WEEK_BUCKETS = 26;

	/** @var bool */
	private static $registered = false;

	/** @var int|null */
	private static $test_now = null;

	/** @var bool|null */
	private static $test_frontend = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'template_redirect', array( self::class, 'maybe_observe' ), 2 );
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
	}

	public static function reset_for_tests(): void {
		self::$registered    = false;
		self::$test_now      = null;
		self::$test_frontend = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::LEDGER_OPTION );
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	public static function set_test_frontend( ?bool $frontend ): void {
		self::$test_frontend = $frontend;
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

	/* ---------------------------------------------------------------------
	 * Rosters
	 * ------------------------------------------------------------------ */

	/**
	 * AI-tool referrer hosts (lowercase). Match is exact host or subdomain.
	 *
	 * @return list<array{id:string,label:string,hosts:list<string>,utm:list<string>}>
	 */
	public static function referrer_roster(): array {
		return array(
			array(
				'id'    => 'chatgpt',
				'label' => 'ChatGPT',
				'hosts' => array( 'chatgpt.com', 'chat.openai.com' ),
				'utm'   => array( 'chatgpt.com' ),
			),
			array(
				'id'    => 'perplexity',
				'label' => 'Perplexity',
				'hosts' => array( 'perplexity.ai', 'www.perplexity.ai' ),
				'utm'   => array( 'perplexity' ),
			),
			array(
				'id'    => 'gemini',
				'label' => 'Gemini',
				'hosts' => array( 'gemini.google.com' ),
				'utm'   => array( 'gemini' ),
			),
			array(
				'id'    => 'copilot',
				'label' => 'Microsoft Copilot',
				'hosts' => array( 'copilot.microsoft.com', 'www.bing.com' ),
				'utm'   => array( 'copilot' ),
			),
			array(
				'id'    => 'claude',
				'label' => 'Claude',
				'hosts' => array( 'claude.ai' ),
				'utm'   => array( 'claude.ai' ),
			),
			array(
				'id'    => 'you',
				'label' => 'You.com',
				'hosts' => array( 'you.com' ),
				'utm'   => array( 'you.com' ),
			),
		);
	}

	/**
	 * UA substrings that identify AI crawlers (mirrors BOTWATCH roster; no class dependency).
	 *
	 * @return list<string>
	 */
	public static function crawler_ua_tokens(): array {
		if ( class_exists( Botwatch::class, false ) && method_exists( Botwatch::class, 'crawler_ua_tokens' ) ) {
			return Botwatch::crawler_ua_tokens();
		}

		return array(
			'gptbot',
			'chatgpt-user',
			'claudebot',
			'anthropic-ai',
			'ccbot',
			'perplexitybot',
			'google-extended',
			'bytespider',
			'amazonbot',
			'cohere-ai',
			'diffbot',
			'omgilibot',
		);
	}

	/**
	 * @return array{id:string,label:string,hosts:list<string>,utm:list<string>}|null
	 */
	public static function match_referrer( string $referrer_url, string $utm_source = '' ): ?array {
		$host = self::host_from_url( $referrer_url );
		$utm  = strtolower( trim( $utm_source ) );
		foreach ( self::referrer_roster() as $src ) {
			if ( '' !== $host ) {
				foreach ( $src['hosts'] as $allowed ) {
					$allowed = strtolower( $allowed );
					if ( $host === $allowed || ( strlen( $host ) > strlen( $allowed ) && substr( $host, -strlen( $allowed ) - 1 ) === '.' . $allowed ) ) {
						return $src;
					}
				}
			}
			if ( '' !== $utm ) {
				foreach ( $src['utm'] as $token ) {
					if ( $utm === strtolower( $token ) ) {
						return $src;
					}
				}
			}
		}

		return null;
	}

	public static function host_from_url( string $url ): string {
		$url = trim( $url );
		if ( '' === $url ) {
			return '';
		}
		$parsed = wp_parse_url( $url );
		if ( ! is_array( $parsed ) || empty( $parsed['host'] ) ) {
			return '';
		}

		return strtolower( (string) $parsed['host'] );
	}

	public static function is_crawler_ua( string $ua ): bool {
		$lower = strtolower( $ua );
		if ( '' === $lower ) {
			return false;
		}
		foreach ( self::crawler_ua_tokens() as $token ) {
			if ( false !== strpos( $lower, $token ) ) {
				return true;
			}
		}

		return false;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * Observation is on when enabled (default true). Toggle only gates recording.
	 *
	 * @return array{enabled:bool}
	 */
	public static function defaults(): array {
		return array(
			'enabled' => true,
		);
	}

	/**
	 * @return array{enabled:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw.
	 * @return array{enabled:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}
		// Absent key → default true (observation on). Explicit false disables.
		if ( ! array_key_exists( 'enabled', $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled' => ! empty( $raw['enabled'] ),
		);
	}

	/**
	 * @param array<string,mixed> $settings Settings.
	 */
	public static function save_settings( array $settings ): bool {
		$clean  = self::sanitize_settings( $settings );
		$before = self::get_settings();
		if ( $clean === $before ) {
			return true;
		}
		if ( $clean === self::defaults() ) {
			delete_option( self::SETTINGS_OPTION );
		} else {
			update_option( self::SETTINGS_OPTION, $clean, false );
		}

		return true;
	}

	public static function is_enabled(): bool {
		return ! empty( self::get_settings()['enabled'] );
	}

	/* ---------------------------------------------------------------------
	 * Ledger
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{sources:array<string,array<string,mixed>>,weeks:array<string,array<string,int>>}
	 */
	public static function empty_ledger(): array {
		return array(
			'sources' => array(),
			'weeks'   => array(),
		);
	}

	/**
	 * @return array{sources:array<string,array<string,mixed>>,weeks:array<string,array<string,int>>}
	 */
	public static function get_ledger(): array {
		return self::sanitize_ledger( get_option( self::LEDGER_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw.
	 * @return array{sources:array<string,array<string,mixed>>,weeks:array<string,array<string,int>>}
	 */
	public static function sanitize_ledger( $raw ): array {
		$empty = self::empty_ledger();
		if ( ! is_array( $raw ) ) {
			return $empty;
		}

		$sources = array();
		if ( isset( $raw['sources'] ) && is_array( $raw['sources'] ) ) {
			foreach ( $raw['sources'] as $id => $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$clean_id = sanitize_key( (string) $id );
				if ( '' === $clean_id ) {
					continue;
				}
				$sources[ $clean_id ] = self::sanitize_source_row( $clean_id, $row );
				if ( count( $sources ) >= self::MAX_SOURCES ) {
					break;
				}
			}
		}

		$weeks = array();
		if ( isset( $raw['weeks'] ) && is_array( $raw['weeks'] ) ) {
			foreach ( $raw['weeks'] as $week => $counts ) {
				$wk = sanitize_text_field( (string) $week );
				if ( '' === $wk || ! is_array( $counts ) ) {
					continue;
				}
				$clean_counts = array();
				foreach ( $counts as $sid => $n ) {
					$sid = sanitize_key( (string) $sid );
					if ( '' !== $sid ) {
						$clean_counts[ $sid ] = max( 0, (int) $n );
					}
				}
				$weeks[ $wk ] = $clean_counts;
			}
			krsort( $weeks );
			$weeks = array_slice( $weeks, 0, self::MAX_WEEK_BUCKETS, true );
		}

		return array(
			'sources' => $sources,
			'weeks'   => $weeks,
		);
	}

	/**
	 * @param array<string,mixed> $row Raw.
	 * @return array{id:string,label:string,hits:int,first_seen:int,last_seen:int,landings:list<string>}
	 */
	public static function sanitize_source_row( string $id, array $row ): array {
		$landings = array();
		if ( isset( $row['landings'] ) && is_array( $row['landings'] ) ) {
			foreach ( $row['landings'] as $p ) {
				$path = self::sanitize_path( (string) $p );
				if ( '' !== $path && ! in_array( $path, $landings, true ) ) {
					$landings[] = $path;
				}
				if ( count( $landings ) >= self::MAX_LANDINGS_PER_SOURCE ) {
					break;
				}
			}
		}

		return array(
			'id'         => $id,
			'label'      => sanitize_text_field( (string) ( $row['label'] ?? $id ) ),
			'hits'       => max( 0, (int) ( $row['hits'] ?? 0 ) ),
			'first_seen' => max( 0, (int) ( $row['first_seen'] ?? 0 ) ),
			'last_seen'  => max( 0, (int) ( $row['last_seen'] ?? 0 ) ),
			'landings'   => $landings,
		);
	}

	public static function sanitize_path( string $path ): string {
		$path = trim( $path );
		if ( '' === $path ) {
			return '';
		}
		if ( false !== strpos( $path, '://' ) ) {
			$parsed = wp_parse_url( $path );
			$path   = is_array( $parsed ) && isset( $parsed['path'] ) ? (string) $parsed['path'] : '/';
		}
		$path = strtok( $path, '?#' );
		$path = is_string( $path ) ? $path : '/';
		if ( '' === $path || '/' !== $path[0] ) {
			$path = '/' . ltrim( $path, '/' );
		}
		$path = sanitize_text_field( $path );
		if ( strlen( $path ) > 250 ) {
			$path = substr( $path, 0, 250 );
		}

		return $path;
	}

	/**
	 * @param array{sources:array<string,array<string,mixed>>,weeks:array<string,array<string,int>>} $ledger Ledger.
	 */
	public static function save_ledger( array $ledger ): void {
		$clean = self::sanitize_ledger( $ledger );
		if ( array() === $clean['sources'] && array() === $clean['weeks'] ) {
			delete_option( self::LEDGER_OPTION );

			return;
		}
		update_option( self::LEDGER_OPTION, $clean, false );
	}

	public static function week_key( ?int $now = null ): string {
		$now = null !== $now ? $now : self::now();

		return gmdate( 'o-\WW', $now );
	}

	/* ---------------------------------------------------------------------
	 * Observation
	 * ------------------------------------------------------------------ */

	public static function is_frontend_request(): bool {
		if ( null !== self::$test_frontend ) {
			return self::$test_frontend;
		}
		if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
			return false;
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return false;
		}
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			return false;
		}
		if ( function_exists( 'is_admin' ) && is_admin() ) {
			return false;
		}

		return true;
	}

	public static function resolve_ua(): string {
		if ( isset( $GLOBALS['handl_aicac_test_dividend_ua'] ) ) {
			return (string) $GLOBALS['handl_aicac_test_dividend_ua'];
		}
		if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			return (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		}

		return '';
	}

	public static function resolve_referrer(): string {
		if ( isset( $GLOBALS['handl_aicac_test_dividend_referrer'] ) ) {
			return (string) $GLOBALS['handl_aicac_test_dividend_referrer'];
		}
		if ( isset( $_SERVER['HTTP_REFERER'] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			return (string) wp_unslash( $_SERVER['HTTP_REFERER'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		}

		return '';
	}

	public static function resolve_utm_source(): string {
		if ( isset( $GLOBALS['handl_aicac_test_dividend_utm'] ) ) {
			return (string) $GLOBALS['handl_aicac_test_dividend_utm'];
		}
		if ( isset( $_GET['utm_source'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return sanitize_text_field( (string) wp_unslash( $_GET['utm_source'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}

		return '';
	}

	public static function resolve_path(): string {
		if ( isset( $GLOBALS['handl_aicac_test_dividend_path'] ) ) {
			return self::sanitize_path( (string) $GLOBALS['handl_aicac_test_dividend_path'] );
		}
		$uri = '';
		if ( isset( $_SERVER['REQUEST_URI'] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			$uri = (string) wp_unslash( $_SERVER['REQUEST_URI'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		}
		$path = self::sanitize_path( $uri );

		return '' !== $path ? $path : '/';
	}

	public static function maybe_observe(): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		if ( ! self::is_frontend_request() ) {
			return;
		}
		$ua = self::resolve_ua();
		if ( self::is_crawler_ua( $ua ) ) {
			return;
		}
		$src = self::match_referrer( self::resolve_referrer(), self::resolve_utm_source() );
		if ( null === $src ) {
			return;
		}
		self::record_hit( $src, self::resolve_path(), self::now() );
	}

	/**
	 * @param array{id:string,label:string,hosts:list<string>,utm:list<string>} $src Source.
	 * @return array{ledger:array<string,mixed>}
	 */
	public static function record_hit( array $src, string $path, ?int $now = null ): array {
		$now  = null !== $now ? $now : self::now();
		$path = self::sanitize_path( $path );
		if ( '' === $path ) {
			$path = '/';
		}
		$id     = sanitize_key( (string) $src['id'] );
		$ledger = self::get_ledger();

		if ( ! isset( $ledger['sources'][ $id ] ) ) {
			if ( count( $ledger['sources'] ) >= self::MAX_SOURCES ) {
				uasort(
					$ledger['sources'],
					static function ( array $a, array $b ): int {
						return ( (int) ( $a['last_seen'] ?? 0 ) ) <=> ( (int) ( $b['last_seen'] ?? 0 ) );
					}
				);
				array_shift( $ledger['sources'] );
			}
			$ledger['sources'][ $id ] = array(
				'id'         => $id,
				'label'      => (string) $src['label'],
				'hits'       => 0,
				'first_seen' => $now,
				'last_seen'  => $now,
				'landings'   => array(),
			);
		}

		$row               = $ledger['sources'][ $id ];
		$row['hits']       = (int) $row['hits'] + 1;
		$row['last_seen']  = $now;
		if ( 0 === (int) $row['first_seen'] ) {
			$row['first_seen'] = $now;
		}
		if ( ! in_array( $path, $row['landings'], true ) ) {
			$row['landings'][] = $path;
			if ( count( $row['landings'] ) > self::MAX_LANDINGS_PER_SOURCE ) {
				$row['landings'] = array_slice( $row['landings'], -self::MAX_LANDINGS_PER_SOURCE );
			}
		}
		$ledger['sources'][ $id ] = $row;

		$week = self::week_key( $now );
		if ( ! isset( $ledger['weeks'][ $week ] ) ) {
			$ledger['weeks'][ $week ] = array();
		}
		$ledger['weeks'][ $week ][ $id ] = (int) ( $ledger['weeks'][ $week ][ $id ] ?? 0 ) + 1;
		krsort( $ledger['weeks'] );
		$ledger['weeks'] = array_slice( $ledger['weeks'], 0, self::MAX_WEEK_BUCKETS, true );

		self::save_ledger( $ledger );

		return array( 'ledger' => self::get_ledger() );
	}

	/* ---------------------------------------------------------------------
	 * Soft-read BOTWATCH give-vs-get
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{crawl_hits:int,referral_hits:int,available:bool}|null
	 */
	public static function give_vs_get(): ?array {
		$raw = get_option( self::BOTWATCH_LEDGER_OPTION, null );
		if ( ! is_array( $raw ) || ! isset( $raw['bots'] ) || ! is_array( $raw['bots'] ) ) {
			return null;
		}
		$crawl = 0;
		foreach ( $raw['bots'] as $bot ) {
			if ( is_array( $bot ) ) {
				$crawl += max( 0, (int) ( $bot['hits'] ?? 0 ) );
			}
		}
		$referral = 0;
		foreach ( self::get_ledger()['sources'] as $src ) {
			$referral += max( 0, (int) ( $src['hits'] ?? 0 ) );
		}

		return array(
			'crawl_hits'    => $crawl,
			'referral_hits' => $referral,
			'available'     => true,
		);
	}

	/* ---------------------------------------------------------------------
	 * Admin
	 * ------------------------------------------------------------------ */

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) || ! class_exists( Admin::class, false ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'AI referrals', 'handl-ai-connector-access-control' ),
			__( 'AI referrals', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save dividend settings.', 'handl-ai-connector-access-control' ) );
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
	 * @return array{sources:list<array<string,mixed>>,weeks:array<string,array<string,int>>,give_vs_get:?array{crawl_hits:int,referral_hits:int,available:bool},settings:array{enabled:bool}}
	 */
	public static function snapshot(): array {
		$ledger = self::get_ledger();
		$sources = array_values( $ledger['sources'] );
		usort(
			$sources,
			static function ( array $a, array $b ): int {
				return ( (int) $b['hits'] ) <=> ( (int) $a['hits'] );
			}
		);

		return array(
			'sources'     => $sources,
			'weeks'       => $ledger['weeks'],
			'give_vs_get' => self::give_vs_get(),
			'settings'    => self::get_settings(),
		);
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$snap       = self::snapshot();
		$can_manage = Caps::user_can_manage();
		$settings   = $snap['settings'];

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'AI referral dividend', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p>' . esc_html__( 'Human visits that arrive from AI tools after they crawl or cite this site. Referrer host and landing path only — no cookies, no PII, no per-visitor tracking.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			wp_nonce_field( self::ACTION_SAVE );
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Recording', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1"' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Record AI-tool referral visits', 'handl-ai-connector-access-control' ) . '</label>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save changes', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		$gvg = $snap['give_vs_get'];
		if ( is_array( $gvg ) ) {
			echo '<h2>' . esc_html__( 'Give vs get', 'handl-ai-connector-access-control' ) . '</h2>';
			echo '<p>';
			echo esc_html(
				sprintf(
					/* translators: 1: crawl hits, 2: referral hits */
					__( 'AI crawlers recorded %1$d hits; AI tools sent back %2$d human referral visits.', 'handl-ai-connector-access-control' ),
					(int) $gvg['crawl_hits'],
					(int) $gvg['referral_hits']
				)
			);
			echo '</p>';
		}

		echo '<h2>' . esc_html__( 'Sources', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( array() === $snap['sources'] ) {
			echo '<p>' . esc_html__( 'No AI-tool referrals recorded yet.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Source', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Visits', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Last seen', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Sample landings', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $snap['sources'] as $src ) {
				$landings = implode( ', ', array_map( 'strval', $src['landings'] ) );
				echo '<tr>';
				echo '<td>' . esc_html( (string) $src['label'] ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $src['hits'] ) . '</td>';
				echo '<td>' . esc_html( self::format_ts( (int) $src['last_seen'] ) ) . '</td>';
				echo '<td><code>' . esc_html( $landings ) . '</code></td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '<h2>' . esc_html__( 'Weekly trend', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( array() === $snap['weeks'] ) {
			echo '<p>' . esc_html__( 'No week buckets yet.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Week', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Visits', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $snap['weeks'] as $week => $counts ) {
				$total = array_sum( array_map( 'intval', $counts ) );
				echo '<tr>';
				echo '<td>' . esc_html( (string) $week ) . '</td>';
				echo '<td>' . esc_html( (string) $total ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '<p class="description">' . esc_html(
			sprintf(
				/* translators: 1: max sources, 2: max landings, 3: max weeks */
				__( 'Caps: at most %1$d sources, %2$d landing samples per source, %3$d week buckets.', 'handl-ai-connector-access-control' ),
				self::MAX_SOURCES,
				self::MAX_LANDINGS_PER_SOURCE,
				self::MAX_WEEK_BUCKETS
			)
		) . '</p>';
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
}
