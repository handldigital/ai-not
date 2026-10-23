<?php
/**
 * AICAC-BOTWATCH (#441): AI crawler census + robots-compliance watch.
 *
 * Inbound observation only — records known AI crawler user-agents on frontend
 * requests, keeps a bounded ledger (first/last seen, hits, path samples), and
 * flags NON-COMPLIANT fetches against robots.txt. Optional wp_mail alerts are
 * OFF by default. Zero Alerts-class edits. No policy/gate involvement.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * AI crawler census + robots.txt compliance findings.
 */
final class Botwatch {

	public const SETTINGS_OPTION = 'handl_aicac_botwatch';

	public const LEDGER_OPTION = 'handl_aicac_botwatch_ledger';

	public const PAGE_SLUG = 'handl-aicac-botwatch';

	public const ACTION_SAVE = 'handl_aicac_botwatch_save';

	public const POST_PRESENT = 'handl_aicac_botwatch_present';

	public const POST_ALERT_FIRST = 'handl_aicac_botwatch_alert_first';

	public const POST_ALERT_NONCOMPLIANT = 'handl_aicac_botwatch_alert_noncompliant';

	/** Max distinct bots retained in the ledger. */
	public const MAX_BOTS = 40;

	/** Max path samples retained per bot. */
	public const MAX_PATHS_PER_BOT = 25;

	/** Max NON-COMPLIANT findings retained per bot. */
	public const MAX_FINDINGS_PER_BOT = 25;

	/** Max findings across the whole ledger. */
	public const MAX_FINDINGS_TOTAL = 200;

	/** @var bool */
	private static $registered = false;

	/** @var int|null */
	private static $test_now = null;

	/** @var string|null Injected robots.txt body for tests. */
	private static $test_robots = null;

	/** @var bool|null Force frontend / non-frontend in tests. */
	private static $test_frontend = null;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'template_redirect', array( self::class, 'maybe_observe' ), 1 );
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
	}

	public static function reset_for_tests(): void {
		self::$registered    = false;
		self::$test_now      = null;
		self::$test_robots   = null;
		self::$test_frontend = null;
		self::$test_mails    = array();
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::LEDGER_OPTION );
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	public static function set_test_robots( ?string $body ): void {
		self::$test_robots = $body;
	}

	public static function set_test_frontend( ?bool $frontend ): void {
		self::$test_frontend = $frontend;
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
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
	 * Roster
	 * ------------------------------------------------------------------ */

	/**
	 * Known AI crawler user-agents. Match is case-insensitive substring.
	 *
	 * @return list<array{id:string,label:string,ua:string}>
	 */
	public static function roster(): array {
		return array(
			array(
				'id'    => 'gptbot',
				'label' => 'GPTBot',
				'ua'    => 'GPTBot',
			),
			array(
				'id'    => 'chatgpt-user',
				'label' => 'ChatGPT-User',
				'ua'    => 'ChatGPT-User',
			),
			array(
				'id'    => 'claudebot',
				'label' => 'ClaudeBot',
				'ua'    => 'ClaudeBot',
			),
			array(
				'id'    => 'anthropic-ai',
				'label' => 'anthropic-ai',
				'ua'    => 'anthropic-ai',
			),
			array(
				'id'    => 'ccbot',
				'label' => 'CCBot',
				'ua'    => 'CCBot',
			),
			array(
				'id'    => 'perplexitybot',
				'label' => 'PerplexityBot',
				'ua'    => 'PerplexityBot',
			),
			array(
				'id'    => 'google-extended',
				'label' => 'Google-Extended',
				'ua'    => 'Google-Extended',
			),
			array(
				'id'    => 'bytespider',
				'label' => 'Bytespider',
				'ua'    => 'Bytespider',
			),
			array(
				'id'    => 'amazonbot',
				'label' => 'Amazonbot',
				'ua'    => 'Amazonbot',
			),
			array(
				'id'    => 'cohere-ai',
				'label' => 'cohere-ai',
				'ua'    => 'cohere-ai',
			),
			array(
				'id'    => 'diffbot',
				'label' => 'Diffbot',
				'ua'    => 'Diffbot',
			),
			array(
				'id'    => 'omgili',
				'label' => 'Omgilibot',
				'ua'    => 'Omgilibot',
			),
		);
	}

	/**
	 * @return array{id:string,label:string,ua:string}|null
	 */
	public static function match_ua( string $ua ): ?array {
		$ua = trim( $ua );
		if ( '' === $ua ) {
			return null;
		}
		$lower = strtolower( $ua );
		foreach ( self::roster() as $bot ) {
			if ( false !== strpos( $lower, strtolower( $bot['ua'] ) ) ) {
				return $bot;
			}
		}

		return null;
	}

	/**
	 * UA tokens used by Dividend to exclude crawlers from human-referral census.
	 *
	 * @return list<string>
	 */
	public static function crawler_ua_tokens(): array {
		$out = array();
		foreach ( self::roster() as $bot ) {
			$out[] = strtolower( $bot['ua'] );
		}

		return $out;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{alert_first:bool,alert_noncompliant:bool}
	 */
	public static function defaults(): array {
		return array(
			'alert_first'         => false,
			'alert_noncompliant'  => false,
		);
	}

	/**
	 * @return array{alert_first:bool,alert_noncompliant:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{alert_first:bool,alert_noncompliant:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'alert_first'        => ! empty( $raw['alert_first'] ),
			'alert_noncompliant' => ! empty( $raw['alert_noncompliant'] ),
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

	/* ---------------------------------------------------------------------
	 * Ledger
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{bots:array<string,array<string,mixed>>,alerted_first:array<string,int>,alerted_noncompliant:array<string,int>}
	 */
	public static function empty_ledger(): array {
		return array(
			'bots'                 => array(),
			'alerted_first'        => array(),
			'alerted_noncompliant' => array(),
		);
	}

	/**
	 * @return array{bots:array<string,array<string,mixed>>,alerted_first:array<string,int>,alerted_noncompliant:array<string,int>}
	 */
	public static function get_ledger(): array {
		return self::sanitize_ledger( get_option( self::LEDGER_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw ledger.
	 * @return array{bots:array<string,array<string,mixed>>,alerted_first:array<string,int>,alerted_noncompliant:array<string,int>}
	 */
	public static function sanitize_ledger( $raw ): array {
		$empty = self::empty_ledger();
		if ( ! is_array( $raw ) ) {
			return $empty;
		}

		$bots = array();
		if ( isset( $raw['bots'] ) && is_array( $raw['bots'] ) ) {
			foreach ( $raw['bots'] as $id => $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$clean_id = sanitize_key( (string) $id );
				if ( '' === $clean_id ) {
					continue;
				}
				$bots[ $clean_id ] = self::sanitize_bot_row( $clean_id, $row );
				if ( count( $bots ) >= self::MAX_BOTS ) {
					break;
				}
			}
		}

		$alerted_first = array();
		if ( isset( $raw['alerted_first'] ) && is_array( $raw['alerted_first'] ) ) {
			foreach ( $raw['alerted_first'] as $id => $ts ) {
				$key = sanitize_key( (string) $id );
				if ( '' !== $key ) {
					$alerted_first[ $key ] = max( 0, (int) $ts );
				}
			}
		}

		$alerted_nc = array();
		if ( isset( $raw['alerted_noncompliant'] ) && is_array( $raw['alerted_noncompliant'] ) ) {
			foreach ( $raw['alerted_noncompliant'] as $key => $ts ) {
				$k = sanitize_text_field( (string) $key );
				if ( '' !== $k ) {
					$alerted_nc[ $k ] = max( 0, (int) $ts );
				}
			}
		}

		return array(
			'bots'                 => $bots,
			'alerted_first'        => $alerted_first,
			'alerted_noncompliant' => $alerted_nc,
		);
	}

	/**
	 * @param array<string,mixed> $row Raw bot row.
	 * @return array{id:string,label:string,ua:string,first_seen:int,last_seen:int,hits:int,paths:list<string>,findings:list<array{path:string,ts:int}>}
	 */
	public static function sanitize_bot_row( string $id, array $row ): array {
		$paths = array();
		if ( isset( $row['paths'] ) && is_array( $row['paths'] ) ) {
			foreach ( $row['paths'] as $p ) {
				$path = self::sanitize_path( (string) $p );
				if ( '' !== $path && ! in_array( $path, $paths, true ) ) {
					$paths[] = $path;
				}
				if ( count( $paths ) >= self::MAX_PATHS_PER_BOT ) {
					break;
				}
			}
		}

		$findings = array();
		if ( isset( $row['findings'] ) && is_array( $row['findings'] ) ) {
			foreach ( $row['findings'] as $f ) {
				if ( ! is_array( $f ) ) {
					continue;
				}
				$path = self::sanitize_path( (string) ( $f['path'] ?? '' ) );
				if ( '' === $path ) {
					continue;
				}
				$findings[] = array(
					'path' => $path,
					'ts'   => max( 0, (int) ( $f['ts'] ?? 0 ) ),
				);
				if ( count( $findings ) >= self::MAX_FINDINGS_PER_BOT ) {
					break;
				}
			}
		}

		return array(
			'id'         => $id,
			'label'      => sanitize_text_field( (string) ( $row['label'] ?? $id ) ),
			'ua'         => sanitize_text_field( (string) ( $row['ua'] ?? $id ) ),
			'first_seen' => max( 0, (int) ( $row['first_seen'] ?? 0 ) ),
			'last_seen'  => max( 0, (int) ( $row['last_seen'] ?? 0 ) ),
			'hits'       => max( 0, (int) ( $row['hits'] ?? 0 ) ),
			'paths'      => $paths,
			'findings'   => $findings,
		);
	}

	public static function sanitize_path( string $path ): string {
		$path = trim( $path );
		if ( '' === $path ) {
			return '';
		}
		// Keep path only — strip query/fragment and host if a full URL slipped in.
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
	 * @param array{bots:array<string,array<string,mixed>>,alerted_first:array<string,int>,alerted_noncompliant:array<string,int>} $ledger Ledger.
	 */
	public static function save_ledger( array $ledger ): void {
		$clean = self::sanitize_ledger( $ledger );
		if ( array() === $clean['bots'] && array() === $clean['alerted_first'] && array() === $clean['alerted_noncompliant'] ) {
			delete_option( self::LEDGER_OPTION );

			return;
		}
		update_option( self::LEDGER_OPTION, $clean, false );
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
		if ( isset( $GLOBALS['handl_aicac_test_botwatch_ua'] ) ) {
			return (string) $GLOBALS['handl_aicac_test_botwatch_ua'];
		}
		if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			return (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		}

		return '';
	}

	public static function resolve_path(): string {
		if ( isset( $GLOBALS['handl_aicac_test_botwatch_path'] ) ) {
			return self::sanitize_path( (string) $GLOBALS['handl_aicac_test_botwatch_path'] );
		}
		$uri = '';
		if ( isset( $_SERVER['REQUEST_URI'] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			$uri = (string) wp_unslash( $_SERVER['REQUEST_URI'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		}
		$path = self::sanitize_path( $uri );

		return '' !== $path ? $path : '/';
	}

	/**
	 * Hook: observe matching AI crawler requests on the frontend.
	 */
	public static function maybe_observe(): void {
		if ( ! self::is_frontend_request() ) {
			return;
		}
		$ua  = self::resolve_ua();
		$bot = self::match_ua( $ua );
		if ( null === $bot ) {
			return;
		}
		self::record_hit( $bot, self::resolve_path(), self::now() );
	}

	/**
	 * Record a crawl hit. Public for tests.
	 *
	 * @param array{id:string,label:string,ua:string} $bot Bot.
	 * @return array{first:bool,noncompliant:bool,ledger:array<string,mixed>}
	 */
	public static function record_hit( array $bot, string $path, ?int $now = null ): array {
		$now  = null !== $now ? $now : self::now();
		$path = self::sanitize_path( $path );
		if ( '' === $path ) {
			$path = '/';
		}
		$id     = sanitize_key( (string) $bot['id'] );
		$ledger = self::get_ledger();
		$first  = ! isset( $ledger['bots'][ $id ] );

		if ( $first ) {
			if ( count( $ledger['bots'] ) >= self::MAX_BOTS && ! isset( $ledger['bots'][ $id ] ) ) {
				// Drop oldest by last_seen to make room.
				uasort(
					$ledger['bots'],
					static function ( array $a, array $b ): int {
						return ( (int) ( $a['last_seen'] ?? 0 ) ) <=> ( (int) ( $b['last_seen'] ?? 0 ) );
					}
				);
				array_shift( $ledger['bots'] );
			}
			$ledger['bots'][ $id ] = array(
				'id'         => $id,
				'label'      => (string) $bot['label'],
				'ua'         => (string) $bot['ua'],
				'first_seen' => $now,
				'last_seen'  => $now,
				'hits'       => 0,
				'paths'      => array(),
				'findings'   => array(),
			);
		}

		$row               = $ledger['bots'][ $id ];
		$row['last_seen']  = $now;
		$row['hits']       = (int) $row['hits'] + 1;
		if ( $first || 0 === (int) $row['first_seen'] ) {
			$row['first_seen'] = $now;
		}
		if ( ! in_array( $path, $row['paths'], true ) ) {
			$row['paths'][] = $path;
			if ( count( $row['paths'] ) > self::MAX_PATHS_PER_BOT ) {
				$row['paths'] = array_slice( $row['paths'], -self::MAX_PATHS_PER_BOT );
			}
		}

		$noncompliant = false;
		if ( self::path_disallowed_for_ua( $path, (string) $bot['ua'] ) ) {
			$noncompliant = true;
			$dup          = false;
			foreach ( $row['findings'] as $f ) {
				if ( (string) ( $f['path'] ?? '' ) === $path ) {
					$dup = true;
					break;
				}
			}
			if ( ! $dup ) {
				$row['findings'][] = array(
					'path' => $path,
					'ts'   => $now,
				);
				if ( count( $row['findings'] ) > self::MAX_FINDINGS_PER_BOT ) {
					$row['findings'] = array_slice( $row['findings'], -self::MAX_FINDINGS_PER_BOT );
				}
			}
		}

		$ledger['bots'][ $id ] = $row;
		self::trim_findings_total( $ledger );
		self::save_ledger( $ledger );

		$settings = self::get_settings();
		if ( $first && ! empty( $settings['alert_first'] ) ) {
			self::maybe_alert_first( $id, $row, $ledger, $now );
		}
		if ( $noncompliant && ! empty( $settings['alert_noncompliant'] ) ) {
			self::maybe_alert_noncompliant( $id, $row, $path, $ledger, $now );
		}

		return array(
			'first'         => $first,
			'noncompliant'  => $noncompliant,
			'ledger'        => self::get_ledger(),
		);
	}

	/**
	 * @param array{bots:array<string,array<string,mixed>>,alerted_first:array<string,int>,alerted_noncompliant:array<string,int>} $ledger Ledger by ref.
	 */
	private static function trim_findings_total( array &$ledger ): void {
		$total = 0;
		foreach ( $ledger['bots'] as $row ) {
			$total += count( $row['findings'] ?? array() );
		}
		if ( $total <= self::MAX_FINDINGS_TOTAL ) {
			return;
		}
		// Drop oldest findings across bots until under cap.
		$flat = array();
		foreach ( $ledger['bots'] as $bid => $row ) {
			foreach ( $row['findings'] as $idx => $f ) {
				$flat[] = array(
					'bot' => $bid,
					'idx' => $idx,
					'ts'  => (int) ( $f['ts'] ?? 0 ),
				);
			}
		}
		usort(
			$flat,
			static function ( array $a, array $b ): int {
				return $a['ts'] <=> $b['ts'];
			}
		);
		$drop = $total - self::MAX_FINDINGS_TOTAL;
		for ( $i = 0; $i < $drop; $i++ ) {
			$bid = $flat[ $i ]['bot'];
			$idx = $flat[ $i ]['idx'];
			unset( $ledger['bots'][ $bid ]['findings'][ $idx ] );
		}
		foreach ( $ledger['bots'] as $bid => $row ) {
			$ledger['bots'][ $bid ]['findings'] = array_values( $row['findings'] );
		}
	}

	/* ---------------------------------------------------------------------
	 * robots.txt
	 * ------------------------------------------------------------------ */

	public static function robots_body(): string {
		if ( null !== self::$test_robots ) {
			return self::$test_robots;
		}
		$url  = home_url( '/robots.txt' );
		$resp = function_exists( 'wp_remote_get' )
			? wp_remote_get( $url, array( 'timeout' => 2, 'redirection' => 2 ) )
			: null;
		if ( is_array( $resp ) && ! is_wp_error( $resp ) ) {
			$code = (int) wp_remote_retrieve_response_code( $resp );
			$body = (string) wp_remote_retrieve_body( $resp );
			if ( $code >= 200 && $code < 300 && '' !== $body ) {
				return $body;
			}
		}

		/**
		 * Filter the robots.txt body used for BOTWATCH compliance checks.
		 *
		 * @param string $body Body or empty.
		 */
		return (string) apply_filters( 'handl_aicac_botwatch_robots_body', '' );
	}

	/**
	 * @return list<string> Disallow prefixes applicable to $ua (including *).
	 */
	public static function disallow_prefixes_for_ua( string $ua ): array {
		$body = self::robots_body();
		if ( '' === trim( $body ) ) {
			return array();
		}

		$blocks   = array();
		$current  = array();
		$ua_lower = strtolower( trim( $ua ) );
		$lines    = preg_split( '/\r\n|\r|\n/', $body );
		if ( ! is_array( $lines ) ) {
			return array();
		}

		$flush = static function () use ( &$blocks, &$current ): void {
			if ( array() !== $current ) {
				$blocks[] = $current;
				$current  = array();
			}
		};

		foreach ( $lines as $line ) {
			$line = trim( (string) $line );
			if ( '' === $line || '#' === $line[0] ) {
				continue;
			}
			if ( preg_match( '/^user-agent\s*:\s*(.+)$/i', $line, $m ) ) {
				// New UA line: if we already have disallows, start a new block group for chained UAs.
				if ( isset( $current['disallow'] ) && array() !== $current['disallow'] && isset( $current['agents'] ) ) {
					$flush();
				}
				if ( ! isset( $current['agents'] ) ) {
					$current['agents']   = array();
					$current['disallow'] = array();
				}
				$current['agents'][] = strtolower( trim( $m[1] ) );
				continue;
			}
			if ( preg_match( '/^disallow\s*:\s*(.*)$/i', $line, $m ) ) {
				if ( ! isset( $current['agents'] ) ) {
					$current['agents']   = array( '*' );
					$current['disallow'] = array();
				}
				$rule = trim( $m[1] );
				if ( '' !== $rule ) {
					$current['disallow'][] = $rule;
				}
				continue;
			}
			if ( preg_match( '/^allow\s*:/i', $line ) ) {
				continue;
			}
			// Other directives end the current block.
			$flush();
		}
		$flush();

		$prefixes = array();
		foreach ( $blocks as $block ) {
			$agents = $block['agents'] ?? array();
			$match  = false;
			foreach ( $agents as $agent ) {
				if ( '*' === $agent || $agent === $ua_lower || false !== strpos( $ua_lower, $agent ) || false !== strpos( $agent, $ua_lower ) ) {
					$match = true;
					break;
				}
			}
			if ( ! $match ) {
				continue;
			}
			foreach ( $block['disallow'] as $rule ) {
				$prefixes[] = $rule;
			}
		}

		return array_values( array_unique( $prefixes ) );
	}

	public static function path_disallowed_for_ua( string $path, string $ua ): bool {
		$path     = self::sanitize_path( $path );
		$prefixes = self::disallow_prefixes_for_ua( $ua );
		foreach ( $prefixes as $prefix ) {
			if ( '/' === $prefix ) {
				return true;
			}
			if ( 0 === strpos( $path, $prefix ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Compliance verdict for a bot row.
	 *
	 * @param array<string,mixed> $row Bot row.
	 */
	public static function compliance_verdict( array $row ): string {
		$findings = $row['findings'] ?? array();
		if ( is_array( $findings ) && array() !== $findings ) {
			return 'non_compliant';
		}
		$body = self::robots_body();
		if ( '' === trim( $body ) ) {
			return 'unknown';
		}

		return 'ok';
	}

	/* ---------------------------------------------------------------------
	 * Alerts (own wp_mail)
	 * ------------------------------------------------------------------ */

	/**
	 * @param array<string,mixed>                                                                                                                                   $row Bot row.
	 * @param array{bots:array<string,array<string,mixed>>,alerted_first:array<string,int>,alerted_noncompliant:array<string,int>} $ledger Ledger.
	 */
	private static function maybe_alert_first( string $id, array $row, array &$ledger, int $now ): void {
		if ( isset( $ledger['alerted_first'][ $id ] ) ) {
			return;
		}
		$label = (string) ( $row['label'] ?? $id );
		$ok    = self::send_mail(
			sprintf(
				/* translators: %s: crawler label */
				__( '[AI Not] New AI crawler seen: %s', 'handl-ai-connector-access-control' ),
				$label
			),
			sprintf(
				/* translators: 1: crawler label, 2: path */
				__( "AI Not recorded the first visit from %1\$s.\n\nThis is an inbound crawl observation only — no policy changed.\n", 'handl-ai-connector-access-control' ),
				$label
			)
		);
		if ( $ok ) {
			$ledger['alerted_first'][ $id ] = $now;
			self::save_ledger( $ledger );
		}
	}

	/**
	 * @param array<string,mixed>                                                                                                                                   $row Bot row.
	 * @param array{bots:array<string,array<string,mixed>>,alerted_first:array<string,int>,alerted_noncompliant:array<string,int>} $ledger Ledger.
	 */
	private static function maybe_alert_noncompliant( string $id, array $row, string $path, array &$ledger, int $now ): void {
		$key = $id . '|' . $path;
		if ( isset( $ledger['alerted_noncompliant'][ $key ] ) ) {
			return;
		}
		$label = (string) ( $row['label'] ?? $id );
		$ok    = self::send_mail(
			sprintf(
				/* translators: %s: crawler label */
				__( '[AI Not] AI crawler non-compliant: %s', 'handl-ai-connector-access-control' ),
				$label
			),
			sprintf(
				/* translators: 1: crawler label, 2: path */
				__( "AI Not saw %1\$s fetch a robots.txt-disallowed path:\n\n%2\$s\n\nDeclared blocked, crawled anyway.\n", 'handl-ai-connector-access-control' ),
				$label,
				$path
			)
		);
		if ( $ok ) {
			$ledger['alerted_noncompliant'][ $key ] = $now;
			self::save_ledger( $ledger );
		}
	}

	private static function send_mail( string $subject, string $body ): bool {
		$to = (string) get_option( 'admin_email', '' );
		if ( '' === $to || ! is_email( $to ) ) {
			return false;
		}
		$mail = array(
			'to'      => $to,
			'subject' => $subject,
			'body'    => $body,
		);
		self::$test_mails[] = $mail;
		if ( ! function_exists( 'wp_mail' ) ) {
			return false;
		}

		return (bool) wp_mail( $to, $subject, $body );
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
			__( 'Botwatch', 'handl-ai-connector-access-control' ),
			__( 'Botwatch', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save botwatch settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );
		}
		self::save_settings(
			array(
				'alert_first'        => ! empty( $_POST[ self::POST_ALERT_FIRST ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'alert_noncompliant' => ! empty( $_POST[ self::POST_ALERT_NONCOMPLIANT ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
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
	 * @return array{bots:list<array<string,mixed>>,findings:list<array<string,mixed>>,settings:array{alert_first:bool,alert_noncompliant:bool}}
	 */
	public static function snapshot(): array {
		$ledger   = self::get_ledger();
		$settings = self::get_settings();
		$bots     = array();
		$findings = array();
		foreach ( $ledger['bots'] as $row ) {
			$row['compliance'] = self::compliance_verdict( $row );
			$bots[]            = $row;
			foreach ( $row['findings'] as $f ) {
				$findings[] = array(
					'bot_id' => (string) $row['id'],
					'label'  => (string) $row['label'],
					'path'   => (string) $f['path'],
					'ts'     => (int) $f['ts'],
				);
			}
		}
		usort(
			$bots,
			static function ( array $a, array $b ): int {
				return ( (int) $b['last_seen'] ) <=> ( (int) $a['last_seen'] );
			}
		);
		usort(
			$findings,
			static function ( array $a, array $b ): int {
				return ( (int) $b['ts'] ) <=> ( (int) $a['ts'] );
			}
		);

		return array(
			'bots'     => $bots,
			'findings' => $findings,
			'settings' => $settings,
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
		echo '<h1>' . esc_html__( 'AI crawler census', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p>' . esc_html__( 'Inbound observation only: who crawls this site, how often, and whether they honored robots.txt. This does not change allow/deny policy.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			wp_nonce_field( self::ACTION_SAVE );
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Email alerts', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ALERT_FIRST ) . '" value="1"' . checked( ! empty( $settings['alert_first'] ), true, false ) . ' /> ';
			echo esc_html__( 'Alert on first-seen AI crawler', 'handl-ai-connector-access-control' ) . '</label><br />';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ALERT_NONCOMPLIANT ) . '" value="1"' . checked( ! empty( $settings['alert_noncompliant'] ), true, false ) . ' /> ';
			echo esc_html__( 'Alert when a listed bot fetches a robots-disallowed path', 'handl-ai-connector-access-control' ) . '</label>';
			echo '<p class="description">' . esc_html__( 'Alerts are off by default and use wp_mail to the site admin email.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save changes', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		echo '<h2>' . esc_html__( 'Roster', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( array() === $snap['bots'] ) {
			echo '<p>' . esc_html__( 'No listed AI crawlers recorded yet.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Bot', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'First seen', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Last seen', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Hits', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Compliance', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $snap['bots'] as $bot ) {
				$verdict = (string) $bot['compliance'];
				$label   = 'ok' === $verdict
					? __( 'OK', 'handl-ai-connector-access-control' )
					: ( 'non_compliant' === $verdict
						? __( 'NON-COMPLIANT', 'handl-ai-connector-access-control' )
						: __( 'Unknown', 'handl-ai-connector-access-control' ) );
				echo '<tr>';
				echo '<td>' . esc_html( (string) $bot['label'] ) . '</td>';
				echo '<td>' . esc_html( self::format_ts( (int) $bot['first_seen'] ) ) . '</td>';
				echo '<td>' . esc_html( self::format_ts( (int) $bot['last_seen'] ) ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $bot['hits'] ) . '</td>';
				echo '<td>' . esc_html( $label ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '<h2>' . esc_html__( 'NON-COMPLIANT findings', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( array() === $snap['findings'] ) {
			echo '<p>' . esc_html__( 'No robots-disallowed fetches recorded.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Bot', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Path', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'When', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $snap['findings'] as $f ) {
				echo '<tr>';
				echo '<td>' . esc_html( (string) $f['label'] ) . '</td>';
				echo '<td><code>' . esc_html( (string) $f['path'] ) . '</code></td>';
				echo '<td>' . esc_html( self::format_ts( (int) $f['ts'] ) ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '<p class="description">' . esc_html(
			sprintf(
				/* translators: 1: max bots, 2: max paths, 3: max findings */
				__( 'Caps: at most %1$d bots, %2$d path samples per bot, %3$d findings total.', 'handl-ai-connector-access-control' ),
				self::MAX_BOTS,
				self::MAX_PATHS_PER_BOT,
				self::MAX_FINDINGS_TOTAL
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
