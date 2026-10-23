<?php
/**
 * AICAC-HANDSHAKE (#468): outbound transport-hygiene census.
 *
 * Observes AI-destined HTTP via http_request_args. Hosts come from
 * Provider_Map::endpoint_signatures() only. Never mutates request args.
 * README-FREE. Own option only. Own admin screen.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Read-only transport-hygiene census.
 */
final class Handshake {

	public const PAGE_SLUG = 'handl-aicac-handshake';

	public const OPTION_KEY = 'handl_aicac_handshake';

	public const GRADE_SECURE       = 'SECURE';
	public const GRADE_RISKY        = 'RISKY';
	public const GRADE_SLOWPOKE     = 'SLOWPOKE';
	public const GRADE_INSUFFICIENT = 'INSUFFICIENT-DATA';

	public const FRAMING = 'report_only_never_mutates_request_args';

	public const MAX_ROWS = 50;

	public const SLOW_TIMEOUT = 30;

	/** @var bool */
	private static $registered = false;

	/** @var int|null */
	private static $test_now = null;

	/** @var string|null */
	private static $test_plugin = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_filter( 'http_request_args', array( self::class, 'observe' ), 10, 2 );
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
	}

	public static function reset_for_tests(): void {
		self::$registered  = false;
		self::$test_now    = null;
		self::$test_plugin = null;
		delete_option( self::OPTION_KEY );
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	public static function set_test_plugin( ?string $plugin ): void {
		self::$test_plugin = ( is_string( $plugin ) && '' !== $plugin ) ? $plugin : null;
	}

	public static function now(): int {
		if ( null !== self::$test_now ) {
			return (int) self::$test_now;
		}
		if ( class_exists( Clock::class, false ) && method_exists( Clock::class, 'now' ) ) {
			return (int) Clock::now();
		}

		return time();
	}

	/**
	 * @param mixed $args WP HTTP args.
	 * @param mixed $url  Request URL.
	 * @return mixed Unchanged args.
	 */
	public static function observe( $args, $url ) {
		if ( is_array( $args ) ) {
			self::sample( $args, is_string( $url ) ? $url : '' );
		}

		return $args;
	}

	/**
	 * Read-only sample. Never writes into $args.
	 *
	 * @param array<string,mixed> $args Request args.
	 */
	public static function sample( array $args, string $url ): void {
		$match = self::match_provider( $url );
		if ( null === $match ) {
			return;
		}

		$scheme = strtolower( (string) ( function_exists( 'wp_parse_url' ) ? wp_parse_url( $url, PHP_URL_SCHEME ) : parse_url( $url, PHP_URL_SCHEME ) ) );
		$ssl    = true;
		if ( array_key_exists( 'sslverify', $args ) ) {
			$ssl = (bool) $args['sslverify'];
		}
		$timeout = isset( $args['timeout'] ) && is_numeric( $args['timeout'] ) ? (float) $args['timeout'] : 5.0;
		$redir   = isset( $args['redirection'] ) && is_numeric( $args['redirection'] ) ? (int) $args['redirection'] : 5;

		self::persist_row(
			array(
				'plugin'      => self::caller_plugin(),
				'provider'    => $match['id'],
				'label'       => $match['label'],
				'host'        => $match['host'],
				'scheme'      => '' !== $scheme ? $scheme : 'https',
				'sslverify'   => $ssl,
				'timeout'     => $timeout,
				'redirection' => $redir,
				'last_seen'   => self::now(),
			)
		);
	}

	/**
	 * Host match against Provider_Map::endpoint_signatures() hosts only.
	 *
	 * @return array{id:string,label:string,host:string}|null
	 */
	public static function match_provider( string $url ): ?array {
		if ( '' === $url ) {
			return null;
		}
		$host = strtolower( (string) ( function_exists( 'wp_parse_url' ) ? wp_parse_url( $url, PHP_URL_HOST ) : parse_url( $url, PHP_URL_HOST ) ) );
		if ( '' === $host ) {
			return null;
		}
		if ( ! class_exists( Provider_Map::class, false ) || ! method_exists( Provider_Map::class, 'endpoint_signatures' ) ) {
			return null;
		}
		foreach ( Provider_Map::endpoint_signatures() as $id => $sig ) {
			if ( ! is_array( $sig ) ) {
				continue;
			}
			$hosts = isset( $sig['hosts'] ) && is_array( $sig['hosts'] ) ? $sig['hosts'] : array();
			foreach ( $hosts as $sig_host ) {
				$sig_host = strtolower( trim( (string) $sig_host ) );
				if ( '' === $sig_host ) {
					continue;
				}
				$suffix = '.' . $sig_host;
				if ( $host === $sig_host || ( strlen( $host ) > strlen( $suffix ) && substr( $host, -strlen( $suffix ) ) === $suffix ) ) {
					$label = isset( $sig['label'] ) && '' !== (string) $sig['label'] ? (string) $sig['label'] : (string) $id;

					return array(
						'id'    => (string) $id,
						'label' => $label,
						'host'  => $host,
					);
				}
			}
		}

		return null;
	}

	/**
	 * @return array{grade:string,fact:string,bucket:string}
	 */
	public static function classify( string $scheme, bool $sslverify, float $timeout ): array {
		$scheme = strtolower( $scheme );
		$bucket = self::timeout_bucket( $timeout );
		$risky  = array();
		if ( 'http' === $scheme ) {
			$risky[] = 'plain HTTP';
		}
		if ( ! $sslverify ) {
			$risky[] = 'sslverify disabled';
		}
		if ( array() !== $risky ) {
			return array(
				'grade'  => self::GRADE_RISKY,
				'fact'   => implode( '; ', $risky ),
				'bucket' => $bucket,
			);
		}
		if ( $timeout > self::SLOW_TIMEOUT ) {
			return array(
				'grade'  => self::GRADE_SLOWPOKE,
				'fact'   => sprintf(
					/* translators: %s: timeout seconds */
					__( 'timeout %ss', 'handl-ai-connector-access-control' ),
					self::format_timeout( $timeout )
				),
				'bucket' => $bucket,
			);
		}

		return array(
			'grade'  => self::GRADE_SECURE,
			'fact'   => __( 'HTTPS, sslverify on', 'handl-ai-connector-access-control' ),
			'bucket' => $bucket,
		);
	}

	public static function timeout_bucket( float $timeout ): string {
		if ( $timeout > self::SLOW_TIMEOUT ) {
			return '>30s';
		}
		if ( $timeout > 5 ) {
			return '6–30s';
		}

		return '≤5s';
	}

	public static function max_rows(): int {
		$n = self::MAX_ROWS;
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( 'handl_aicac_handshake_max_rows', $n );
			if ( is_numeric( $filtered ) ) {
				$n = (int) $filtered;
			}
		}

		return $n < 1 ? 1 : $n;
	}

	/**
	 * @return array{as_of:int,rows:list<array<string,mixed>>}
	 */
	public static function snapshot(): array {
		$state = self::get_state();
		$rows  = array();
		foreach ( $state['rows'] as $row ) {
			$rows[] = self::decorate( $row );
		}
		usort(
			$rows,
			static function ( $a, $b ) {
				$rank = array(
					self::GRADE_RISKY    => 0,
					self::GRADE_SLOWPOKE => 1,
					self::GRADE_SECURE   => 2,
				);
				$ra = $rank[ (string) ( $a['grade'] ?? '' ) ] ?? 9;
				$rb = $rank[ (string) ( $b['grade'] ?? '' ) ] ?? 9;
				if ( $ra !== $rb ) {
					return $ra <=> $rb;
				}

				return ( (int) ( $b['last_seen'] ?? 0 ) ) <=> ( (int) ( $a['last_seen'] ?? 0 ) );
			}
		);

		return array(
			'as_of' => (int) $state['as_of'],
			'rows'  => $rows,
		);
	}

	public static function register_menu(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) || ! class_exists( Admin::class, false ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Transport hygiene', 'handl-ai-connector-access-control' ),
			__( 'Transport hygiene', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		$snap = self::snapshot();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Transport hygiene', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'How AI HTTP calls actually travel: TLS, scheme, timeout. Report only — this screen never changes request arguments.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<ul class="ul-disc">';
		echo '<li><strong>' . esc_html__( 'SECURE', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'HTTPS with SSL verification on.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'RISKY', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'sslverify disabled or plain HTTP. The discriminating fact is shown per row.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'SLOWPOKE', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Timeout over 30 seconds.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '</ul>';

		if ( empty( $snap['rows'] ) ) {
			echo '<p>' . esc_html__( 'No AI HTTP calls observed yet.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Scheme', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'SSL verify', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Timeout', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Redirection', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Last seen', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Grade', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Fact', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $snap['rows'] as $row ) {
			echo '<tr>';
			echo '<td>' . esc_html( (string) $row['plugin'] ) . '</td>';
			echo '<td>' . esc_html( (string) $row['label'] ) . '</td>';
			echo '<td>' . esc_html( (string) $row['scheme'] ) . '</td>';
			echo '<td>' . esc_html( ! empty( $row['sslverify'] ) ? 'on' : 'off' ) . '</td>';
			echo '<td>' . esc_html( self::format_timeout( (float) $row['timeout'] ) . 's (' . (string) $row['bucket'] . ')' ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $row['redirection'] ) . '</td>';
			echo '<td>' . esc_html( self::format_seen( (int) $row['last_seen'] ) ) . '</td>';
			echo '<td>' . esc_html( (string) $row['grade'] ) . '</td>';
			echo '<td>' . esc_html( (string) $row['fact'] ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
		echo '</div>';
	}

	/**
	 * @param array<string,mixed> $args Request args.
	 */
	private static function persist_row( array $incoming ): void {
		$state  = self::get_state();
		$plugin = (string) $incoming['plugin'];
		$prov   = (string) $incoming['provider'];
		$key    = self::row_key( $plugin, $prov );
		$now    = (int) $incoming['last_seen'];
		$calls  = 1;
		if ( isset( $state['rows'][ $key ] ) && is_array( $state['rows'][ $key ] ) ) {
			$calls = (int) ( $state['rows'][ $key ]['calls'] ?? 0 ) + 1;
		} elseif ( count( $state['rows'] ) >= self::max_rows() ) {
			$oldest_key = null;
			$oldest_ts  = PHP_INT_MAX;
			foreach ( $state['rows'] as $rk => $row ) {
				$ts = (int) ( $row['last_seen'] ?? 0 );
				if ( $ts < $oldest_ts ) {
					$oldest_ts  = $ts;
					$oldest_key = $rk;
				}
			}
			if ( null !== $oldest_key ) {
				unset( $state['rows'][ $oldest_key ] );
			}
		}

		$state['rows'][ $key ] = array(
			'plugin'      => $plugin,
			'provider'    => $prov,
			'label'       => (string) $incoming['label'],
			'host'        => (string) $incoming['host'],
			'scheme'      => (string) $incoming['scheme'],
			'sslverify'   => ! empty( $incoming['sslverify'] ),
			'timeout'     => (float) $incoming['timeout'],
			'redirection' => (int) $incoming['redirection'],
			'last_seen'   => $now,
			'calls'       => $calls,
		);
		$state['as_of'] = $now;
		update_option( self::OPTION_KEY, $state, false );
	}

	/**
	 * @return array{as_of:int,rows:array<string,array<string,mixed>>}
	 */
	private static function get_state(): array {
		$raw = get_option( self::OPTION_KEY, array() );
		$out = array(
			'as_of' => 0,
			'rows'  => array(),
		);
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$out['as_of'] = isset( $raw['as_of'] ) ? (int) $raw['as_of'] : 0;
		$src          = isset( $raw['rows'] ) && is_array( $raw['rows'] ) ? $raw['rows'] : array();
		foreach ( $src as $key => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			$prov   = isset( $row['provider'] ) ? (string) $row['provider'] : '';
			if ( '' === $plugin || '' === $prov ) {
				continue;
			}
			$out['rows'][ (string) $key ] = array(
				'plugin'      => $plugin,
				'provider'    => $prov,
				'label'       => isset( $row['label'] ) ? (string) $row['label'] : $prov,
				'host'        => isset( $row['host'] ) ? (string) $row['host'] : '',
				'scheme'      => isset( $row['scheme'] ) ? (string) $row['scheme'] : 'https',
				'sslverify'   => ! empty( $row['sslverify'] ),
				'timeout'     => isset( $row['timeout'] ) ? (float) $row['timeout'] : 5.0,
				'redirection' => isset( $row['redirection'] ) ? (int) $row['redirection'] : 5,
				'last_seen'   => isset( $row['last_seen'] ) ? (int) $row['last_seen'] : 0,
				'calls'       => isset( $row['calls'] ) ? (int) $row['calls'] : 1,
			);
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $row Stored row.
	 * @return array<string,mixed>
	 */
	private static function decorate( array $row ): array {
		$graded = self::classify( (string) $row['scheme'], ! empty( $row['sslverify'] ), (float) $row['timeout'] );
		$row['grade']  = $graded['grade'];
		$row['fact']   = $graded['fact'];
		$row['bucket'] = $graded['bucket'];

		return $row;
	}

	private static function row_key( string $plugin, string $provider ): string {
		return $plugin . "\t" . $provider;
	}

	private static function caller_plugin(): string {
		if ( null !== self::$test_plugin ) {
			return self::$test_plugin;
		}
		if ( class_exists( Attribution::class, false ) ) {
			$resolved = Attribution::resolve_from_backtrace();
			if ( is_array( $resolved ) && ! empty( $resolved['plugin'] ) && is_string( $resolved['plugin'] ) ) {
				return $resolved['plugin'];
			}
		}

		return 'unknown';
	}

	private static function format_timeout( float $timeout ): string {
		if ( abs( $timeout - (int) $timeout ) < 0.001 ) {
			return (string) (int) $timeout;
		}

		return rtrim( rtrim( sprintf( '%.2f', $timeout ), '0' ), '.' );
	}

	private static function format_seen( int $ts ): string {
		if ( $ts <= 0 ) {
			return '—';
		}

		return gmdate( 'Y-m-d H:i:s', $ts ) . ' UTC';
	}
}
