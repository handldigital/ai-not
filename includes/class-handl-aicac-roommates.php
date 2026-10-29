<?php
/**
 * AICAC-ROOMMATES (#474): shared API-key census.
 *
 * Report-only blast-radius grade per credential. Keyscan owns discovery
 * patterns; this page consumes them behind class_exists and never edits
 * keyscan.php. Store salted fingerprints only — never persist or render
 * a raw key.
 *
 * README-FREE. Own options only (handl_aicac_roommates*). Own admin screen.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Read-only shared-credential census.
 */
final class Roommates {

	public const PAGE_SLUG = 'handl-aicac-roommates';

	public const CENSUS_OPTION = 'handl_aicac_roommates';

	public const GENERATED_OPTION = 'handl_aicac_roommates_generated_at';

	public const GRADE_SOLO         = 'SOLO-KEY';
	public const GRADE_SHARED       = 'SHARED';
	public const GRADE_SKELETON     = 'SKELETON-KEY';
	public const GRADE_INSUFFICIENT = 'INSUFFICIENT-DATA';

	public const FRAMING = 'report_only_never_mutates_policy';

	public const SHORT_LEN = 12;

	public const MIN_CALLS_DEFAULT = 5;

	/** @var bool */
	private static $registered = false;

	/** @var bool */
	private static $skip_cache = false;

	/** @var list<array<string,mixed>>|null */
	private static $test_hits = null;

	/** @var list<array<string,mixed>>|null */
	private static $test_log = null;

	/** @var int|null */
	private static $test_now = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
	}

	public static function reset_for_tests(): void {
		self::$registered  = false;
		self::$skip_cache  = false;
		self::$test_hits   = null;
		self::$test_log    = null;
		self::$test_now    = null;
		delete_option( self::CENSUS_OPTION );
		delete_option( self::GENERATED_OPTION );
	}

	public static function set_skip_cache( bool $skip ): void {
		self::$skip_cache = $skip;
	}

	/**
	 * Injected raw hits. Each row: plugin, provider, key. Dropped after fingerprint.
	 *
	 * @param list<array<string,mixed>>|null $hits Hits.
	 */
	public static function set_test_hits( ?array $hits ): void {
		self::$test_hits = $hits;
	}

	/**
	 * @param list<array<string,mixed>>|null $log Injected activity rows.
	 */
	public static function set_test_log( ?array $log ): void {
		self::$test_log = $log;
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
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
	 * Salted fingerprint. Never returns the raw key.
	 */
	public static function fingerprint( string $raw_key ): string {
		$raw_key = trim( $raw_key );
		if ( '' === $raw_key ) {
			return '';
		}
		$salt = function_exists( 'wp_salt' ) ? (string) wp_salt( 'auth' ) : 'handl-aicac-roommates';

		return hash_hmac( 'sha256', $raw_key, $salt );
	}

	public static function short_fingerprint( string $fingerprint ): string {
		if ( strlen( $fingerprint ) <= self::SHORT_LEN ) {
			return $fingerprint;
		}

		return substr( $fingerprint, 0, self::SHORT_LEN );
	}

	public static function grade_for_plugin_count( int $count ): string {
		if ( $count >= 3 ) {
			return self::GRADE_SKELETON;
		}
		if ( 2 === $count ) {
			return self::GRADE_SHARED;
		}
		if ( 1 === $count ) {
			return self::GRADE_SOLO;
		}

		return self::GRADE_INSUFFICIENT;
	}

	public static function min_calls(): int {
		$default = self::MIN_CALLS_DEFAULT;
		$filtered = apply_filters( 'handl_aicac_roommates_min_calls', $default );
		$min      = is_numeric( $filtered ) ? (int) $filtered : $default;

		return $min < 1 ? 1 : $min;
	}

	/**
	 * Guarded soft-read of the activity log. Never writes it.
	 *
	 * @return array{rows:list<array<string,mixed>>,available:bool}
	 */
	public static function read_activity_log(): array {
		if ( null !== self::$test_log ) {
			return array(
				'rows'      => array_values( self::$test_log ),
				'available' => true,
			);
		}
		$key = class_exists( Plugin::class, false ) ? Plugin::LOG_OPTION_KEY : 'handl_aicac_recent_calls';
		$raw = get_option( $key, null );
		if ( null === $raw || false === $raw || ! is_array( $raw ) ) {
			return array(
				'rows'      => array(),
				'available' => false,
			);
		}
		$rows = array();
		foreach ( $raw as $row ) {
			if ( is_array( $row ) ) {
				$rows[] = $row;
			}
		}

		return array(
			'rows'      => $rows,
			'available' => true,
		);
	}

	/**
	 * Consume Keyscan patterns. class_exists guard; never edit keyscan.php.
	 *
	 * @return list<array{plugin:string,provider:string,key:string}>
	 */
	public static function discover_hits(): array {
		if ( null !== self::$test_hits ) {
			$out = array();
			foreach ( self::$test_hits as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$key = isset( $row['key'] ) ? trim( (string) $row['key'] ) : '';
				if ( '' === $key ) {
					continue;
				}
				$out[] = array(
					'plugin'   => isset( $row['plugin'] ) ? (string) $row['plugin'] : '',
					'provider' => isset( $row['provider'] ) ? (string) $row['provider'] : '',
					'key'      => $key,
				);
			}

			return $out;
		}

		$hits = array();
		if ( ! class_exists( Keyscan::class, false ) ) {
			return $hits;
		}

		if ( method_exists( Keyscan::class, 'active_plugin_basenames' ) && method_exists( Keyscan::class, 'scan_plugin_options' ) ) {
			$active = Keyscan::active_plugin_basenames();
			if ( is_array( $active ) ) {
				foreach ( array_keys( $active ) as $basename ) {
					$basename = (string) $basename;
					if ( '' === $basename || false !== strpos( $basename, 'handl-ai-connector' ) ) {
						continue;
					}
					$found = Keyscan::scan_plugin_options( $basename );
					if ( ! is_array( $found ) ) {
						continue;
					}
					foreach ( $found as $hit ) {
						if ( ! is_array( $hit ) ) {
							continue;
						}
						$key = isset( $hit['key'] ) ? trim( (string) $hit['key'] ) : '';
						if ( '' === $key ) {
							continue;
						}
						$hits[] = array(
							'plugin'   => isset( $hit['plugin'] ) ? (string) $hit['plugin'] : $basename,
							'provider' => isset( $hit['provider'] ) ? (string) $hit['provider'] : '',
							'key'      => $key,
						);
					}
				}
			}
		}

		if ( method_exists( Keyscan::class, 'scan_text' ) ) {
			$pack = self::read_activity_log();
			foreach ( $pack['rows'] as $row ) {
				$text = self::row_as_scan_text( $row );
				if ( '' === $text ) {
					continue;
				}
				$found = Keyscan::scan_text( $text );
				if ( ! is_array( $found ) ) {
					continue;
				}
				$plugin   = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
				$provider = isset( $row['provider'] ) ? (string) $row['provider'] : '';
				foreach ( $found as $hit ) {
					if ( ! is_array( $hit ) ) {
						continue;
					}
					$key = isset( $hit['key'] ) ? trim( (string) $hit['key'] ) : '';
					if ( '' === $key ) {
						continue;
					}
					$hits[] = array(
						'plugin'   => $plugin,
						'provider' => isset( $hit['provider'] ) && '' !== (string) $hit['provider'] ? (string) $hit['provider'] : $provider,
						'key'      => $key,
					);
				}
			}
		}

		return $hits;
	}

	/**
	 * @return array{
	 *   findings:list<array<string,mixed>>,
	 *   call_count:int,
	 *   status:string,
	 *   as_of:int
	 * }
	 */
	public static function census(): array {
		$hits   = self::discover_hits();
		$pack   = self::read_activity_log();
		$as_of  = self::now();
		$buckets = array();

		foreach ( $hits as $hit ) {
			$fp = self::fingerprint( $hit['key'] );
			if ( '' === $fp ) {
				continue;
			}
			if ( ! isset( $buckets[ $fp ] ) ) {
				$buckets[ $fp ] = array(
					'fingerprint' => $fp,
					'short'       => self::short_fingerprint( $fp ),
					'plugins'     => array(),
					'providers'   => array(),
					'last_seen'   => 0,
				);
			}
			$plugin = trim( (string) $hit['plugin'] );
			if ( '' !== $plugin ) {
				$buckets[ $fp ]['plugins'][ $plugin ] = true;
			}
			$provider = trim( (string) $hit['provider'] );
			if ( '' !== $provider ) {
				$buckets[ $fp ]['providers'][ $provider ] = true;
			}
		}

		$call_count = 0;
		foreach ( $pack['rows'] as $row ) {
			$decision = strtolower( (string) ( $row['decision'] ?? '' ) );
			if ( ! in_array( $decision, array( 'allow', 'allowed', 'deny', 'denied' ), true ) ) {
				continue;
			}
			++$call_count;
			$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			$ts     = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( '' === $plugin || $ts <= 0 ) {
				continue;
			}
			foreach ( $buckets as $fp => $bucket ) {
				if ( isset( $bucket['plugins'][ $plugin ] ) && $ts > (int) $buckets[ $fp ]['last_seen'] ) {
					$buckets[ $fp ]['last_seen'] = $ts;
				}
			}
		}

		$findings = array();
		foreach ( $buckets as $bucket ) {
			$plugins = array_keys( $bucket['plugins'] );
			sort( $plugins, SORT_STRING );
			$providers = array_keys( $bucket['providers'] );
			sort( $providers, SORT_STRING );
			$count = count( $plugins );
			if ( $count < 1 ) {
				continue;
			}
			$findings[] = array(
				'fingerprint' => (string) $bucket['fingerprint'],
				'short'       => (string) $bucket['short'],
				'plugins'     => $plugins,
				'providers'   => $providers,
				'last_seen'   => (int) $bucket['last_seen'],
				'grade'       => self::grade_for_plugin_count( $count ),
			);
		}

		usort(
			$findings,
			static function ( $a, $b ) {
				$rank = array(
					self::GRADE_SKELETON => 0,
					self::GRADE_SHARED   => 1,
					self::GRADE_SOLO     => 2,
				);
				$ra = $rank[ $a['grade'] ] ?? 9;
				$rb = $rank[ $b['grade'] ] ?? 9;
				if ( $ra !== $rb ) {
					return $ra <=> $rb;
				}

				return strcmp( (string) $a['short'], (string) $b['short'] );
			}
		);

		$status = $call_count < self::min_calls() ? self::GRADE_INSUFFICIENT : '';

		return array(
			'findings'   => $findings,
			'call_count' => $call_count,
			'status'     => $status,
			'as_of'      => $as_of,
		);
	}

	/**
	 * Persist fingerprints only. Strip any leaked raw-key fields.
	 *
	 * @return array{
	 *   findings:list<array<string,mixed>>,
	 *   call_count:int,
	 *   status:string,
	 *   as_of:int,
	 *   cached:bool
	 * }
	 */
	public static function snapshot(): array {
		if ( ! self::$skip_cache ) {
			$cached = get_option( self::CENSUS_OPTION, null );
			$as_of  = (int) get_option( self::GENERATED_OPTION, 0 );
			if ( is_array( $cached ) && isset( $cached['findings'] ) && is_array( $cached['findings'] ) && $as_of > 0 ) {
				return array(
					'findings'   => self::sanitize_stored_findings( $cached['findings'] ),
					'call_count' => isset( $cached['call_count'] ) ? (int) $cached['call_count'] : 0,
					'status'     => isset( $cached['status'] ) ? (string) $cached['status'] : '',
					'as_of'      => $as_of,
					'cached'     => true,
				);
			}
		}

		$data = self::census();
		$safe = array(
			'findings'   => self::sanitize_stored_findings( $data['findings'] ),
			'call_count' => (int) $data['call_count'],
			'status'     => (string) $data['status'],
			'as_of'      => (int) $data['as_of'],
			'cached'     => false,
		);
		if ( ! self::$skip_cache ) {
			update_option(
				self::CENSUS_OPTION,
				array(
					'findings'   => $safe['findings'],
					'call_count' => $safe['call_count'],
					'status'     => $safe['status'],
				),
				false
			);
			update_option( self::GENERATED_OPTION, $safe['as_of'], false );
		}

		return $safe;
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
			__( 'Roommates', 'handl-ai-connector-access-control' ),
			__( 'Roommates', 'handl-ai-connector-access-control' ),
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
		echo '<h1>' . esc_html__( 'Roommates', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'API credentials shared by more than one plugin. Report only — this screen never changes policy or the activity log.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<ul class="ul-disc">';
		echo '<li><strong>' . esc_html__( 'SOLO-KEY', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'One plugin holds this credential.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'SHARED', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Two plugins hold this credential.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'SKELETON-KEY', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Three or more plugins hold this credential.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '</ul>';

		if ( self::GRADE_INSUFFICIENT === $snap['status'] ) {
			echo '<p>' . esc_html__( 'INSUFFICIENT-DATA: too few logged AI calls to attach last-seen times.', 'handl-ai-connector-access-control' ) . '</p>';
		}

		if ( empty( $snap['findings'] ) ) {
			if ( self::GRADE_INSUFFICIENT !== $snap['status'] ) {
				echo '<p>' . esc_html__( 'No API credentials found.', 'handl-ai-connector-access-control' ) . '</p>';
			}
			echo '</div>';

			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Fingerprint', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Plugins', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Providers', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Last seen', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Grade', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $snap['findings'] as $row ) {
			$plugins   = isset( $row['plugins'] ) && is_array( $row['plugins'] ) ? $row['plugins'] : array();
			$providers = isset( $row['providers'] ) && is_array( $row['providers'] ) ? $row['providers'] : array();
			$last      = isset( $row['last_seen'] ) ? (int) $row['last_seen'] : 0;
			$seen      = $last > 0 ? gmdate( 'Y-m-d H:i', $last ) . ' UTC' : '—';
			echo '<tr>';
			echo '<td><code>' . esc_html( (string) $row['short'] ) . '</code></td>';
			echo '<td>' . esc_html( implode( ', ', array_map( 'strval', $plugins ) ) ) . '</td>';
			echo '<td>' . esc_html( implode( ', ', array_map( 'strval', $providers ) ) ) . '</td>';
			echo '<td>' . esc_html( $seen ) . '</td>';
			echo '<td>' . esc_html( (string) $row['grade'] ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
		echo '</div>';
	}

	/**
	 * Stored rows never keep raw key material.
	 *
	 * @param mixed $findings Raw findings.
	 * @return list<array<string,mixed>>
	 */
	public static function sanitize_stored_findings( $findings ): array {
		if ( ! is_array( $findings ) ) {
			return array();
		}
		$out = array();
		foreach ( $findings as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			unset( $row['key'], $row['full'], $row['secret'], $row['value'], $row['raw'] );
			$fp = isset( $row['fingerprint'] ) ? (string) $row['fingerprint'] : '';
			if ( '' === $fp ) {
				continue;
			}
			$plugins = array();
			if ( isset( $row['plugins'] ) && is_array( $row['plugins'] ) ) {
				foreach ( $row['plugins'] as $plugin ) {
					$plugin = (string) $plugin;
					if ( '' !== $plugin ) {
						$plugins[] = $plugin;
					}
				}
			}
			$providers = array();
			if ( isset( $row['providers'] ) && is_array( $row['providers'] ) ) {
				foreach ( $row['providers'] as $provider ) {
					$provider = (string) $provider;
					if ( '' !== $provider ) {
						$providers[] = $provider;
					}
				}
			}
			$out[] = array(
				'fingerprint' => $fp,
				'short'       => isset( $row['short'] ) && '' !== (string) $row['short'] ? (string) $row['short'] : self::short_fingerprint( $fp ),
				'plugins'     => $plugins,
				'providers'   => $providers,
				'last_seen'   => isset( $row['last_seen'] ) ? (int) $row['last_seen'] : 0,
				'grade'       => isset( $row['grade'] ) ? (string) $row['grade'] : self::grade_for_plugin_count( count( $plugins ) ),
			);
		}

		return $out;
	}

	/**
	 * True when a stored blob still contains a raw key.
	 *
	 * @param mixed  $stored Stored option.
	 * @param string $raw    Raw key.
	 */
	public static function stored_contains_raw_key( $stored, string $raw ): bool {
		$raw = trim( $raw );
		if ( '' === $raw ) {
			return false;
		}
		$json = function_exists( 'wp_json_encode' ) ? wp_json_encode( $stored ) : json_encode( $stored );
		if ( ! is_string( $json ) ) {
			return false;
		}

		return false !== strpos( $json, $raw );
	}

	/**
	 * @param array<string,mixed> $row Activity row.
	 */
	private static function row_as_scan_text( array $row ): string {
		$parts = array();
		foreach ( array( 'plugin', 'provider', 'model', 'url', 'prompt', 'message', 'body' ) as $key ) {
			if ( ! isset( $row[ $key ] ) ) {
				continue;
			}
			$val = $row[ $key ];
			if ( is_string( $val ) && '' !== $val ) {
				$parts[] = $val;
			}
		}

		return implode( ' ', $parts );
	}
}
