<?php
/**
 * AICAC-LUGGAGE (#475): outbound media census.
 *
 * Report-only. Own http_request_args observer (never mutates args).
 * Handshake, PII-Warn, Touched, and Provider_Map are not edited;
 * Touched/Provider_Map are class_exists-guarded read-only. Store
 * metadata only — never payload bytes.
 *
 * README-FREE. Own options only (handl_aicac_luggage*). Own admin screen.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Read-only census of site uploads leaving for AI providers.
 */
final class Luggage {

	public const PAGE_SLUG = 'handl-aicac-luggage';

	public const CENSUS_OPTION = 'handl_aicac_luggage';

	public const GENERATED_OPTION = 'handl_aicac_luggage_generated_at';

	public const SHIPMENTS_OPTION = 'handl_aicac_luggage_shipments';

	public const GRADE_HOMEBODY     = 'HOMEBODY';
	public const GRADE_DAYTRIP      = 'DAY-TRIPPER';
	public const GRADE_PACKED       = 'PACKED-SUITCASE';
	public const GRADE_INSUFFICIENT = 'INSUFFICIENT-DATA';

	public const FRAMING = 'report_only_never_mutates_request_args';

	public const MIN_CALLS_DEFAULT = 1;

	public const MAX_SHIPMENTS = 100;

	public const MAX_FILES_PER_PLUGIN = 20;

	public const KIND_PACKED      = 'packed';
	public const KIND_URL         = 'url';
	public const KIND_ATTACHMENT  = 'attachment';

	/** @var bool */
	private static $registered = false;

	/** @var bool */
	private static $skip_cache = false;

	/** @var list<array<string,mixed>>|null */
	private static $test_log = null;

	/** @var list<array<string,mixed>>|null */
	private static $test_shipments = null;

	/** @var int|null */
	private static $test_now = null;

	/** @var string|null */
	private static $test_plugin = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_filter( 'http_request_args', array( self::class, 'observe' ), 11, 2 );
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
	}

	public static function reset_for_tests(): void {
		self::$registered     = false;
		self::$skip_cache     = false;
		self::$test_log       = null;
		self::$test_shipments = null;
		self::$test_now       = null;
		self::$test_plugin    = null;
		delete_option( self::CENSUS_OPTION );
		delete_option( self::GENERATED_OPTION );
		delete_option( self::SHIPMENTS_OPTION );
	}

	public static function set_skip_cache( bool $skip ): void {
		self::$skip_cache = $skip;
	}

	/**
	 * @param list<array<string,mixed>>|null $log Injected activity rows.
	 */
	public static function set_test_log( ?array $log ): void {
		self::$test_log = $log;
	}

	/**
	 * @param list<array<string,mixed>>|null $rows Injected shipment metadata.
	 */
	public static function set_test_shipments( ?array $rows ): void {
		self::$test_shipments = $rows;
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

	public static function min_calls(): int {
		$default  = self::MIN_CALLS_DEFAULT;
		$filtered = apply_filters( 'handl_aicac_luggage_min_calls', $default );
		$min      = is_numeric( $filtered ) ? (int) $filtered : $default;

		return $min < 1 ? 1 : $min;
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
	 * Read-only sample. Never writes into $args. Never stores payload bytes.
	 *
	 * @param array<string,mixed> $args Request args.
	 */
	public static function sample( array $args, string $url ): void {
		$match = self::match_provider( $url );
		if ( null === $match ) {
			return;
		}
		$hits = self::inspect_payload( $args );
		if ( array() === $hits ) {
			return;
		}
		$plugin = self::caller_plugin();
		$ts     = self::now();
		foreach ( $hits as $hit ) {
			self::persist_shipment(
				array(
					'plugin'         => $plugin,
					'provider'       => $match['id'],
					'host'           => $match['host'],
					'filename'       => (string) $hit['filename'],
					'mime'           => (string) $hit['mime'],
					'size'           => (int) $hit['size'],
					'kind'           => (string) $hit['kind'],
					'ts'             => $ts,
					'attachment_id'  => (int) $hit['attachment_id'],
					'touched'        => ! empty( $hit['touched'] ),
				)
			);
		}
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
	 * Extract media metadata from WP HTTP args. Never returns payload bytes.
	 *
	 * @param array<string,mixed> $args Request args.
	 * @return list<array{filename:string,mime:string,size:int,kind:string,attachment_id:int,touched:bool}>
	 */
	public static function inspect_payload( array $args ): array {
		$hits = array();
		self::walk_value( $args['body'] ?? null, $hits, 0 );
		$headers = isset( $args['headers'] ) && is_array( $args['headers'] ) ? $args['headers'] : array();
		foreach ( $headers as $name => $value ) {
			if ( ! is_string( $value ) && ! is_numeric( $value ) ) {
				continue;
			}
			if ( false !== stripos( (string) $name, 'content-type' ) && false !== stripos( (string) $value, 'multipart/' ) ) {
				self::walk_value( (string) $value, $hits, 0 );
			}
		}

		return self::dedupe_hits( $hits );
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
	 * @return list<array<string,mixed>>
	 */
	public static function read_shipments(): array {
		if ( null !== self::$test_shipments ) {
			return self::sanitize_shipments( self::$test_shipments );
		}
		$raw = get_option( self::SHIPMENTS_OPTION, array() );

		return self::sanitize_shipments( is_array( $raw ) ? $raw : array() );
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
		$pack      = self::read_activity_log();
		$shipments = self::read_shipments();
		$as_of     = self::now();
		$buckets   = array();

		$call_count = 0;
		foreach ( $pack['rows'] as $row ) {
			$decision = strtolower( (string) ( $row['decision'] ?? '' ) );
			if ( ! in_array( $decision, array( 'allow', 'allowed', 'deny', 'denied' ), true ) ) {
				continue;
			}
			++$call_count;
			$plugin = trim( (string) ( $row['plugin'] ?? '' ) );
			if ( '' === $plugin ) {
				continue;
			}
			self::ensure_bucket( $buckets, $plugin );
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts > (int) $buckets[ $plugin ]['last_shipment'] ) {
				$buckets[ $plugin ]['last_shipment'] = $ts;
			}
			$provider = trim( (string) ( $row['provider'] ?? '' ) );
			if ( '' !== $provider ) {
				$buckets[ $plugin ]['providers'][ $provider ] = true;
			}
			foreach ( self::upload_refs_from_row( $row ) as $ref ) {
				self::add_file( $buckets[ $plugin ], $ref['filename'], '', 0, self::KIND_URL );
			}
		}

		foreach ( $shipments as $ship ) {
			$plugin = trim( (string) ( $ship['plugin'] ?? '' ) );
			if ( '' === $plugin ) {
				continue;
			}
			self::ensure_bucket( $buckets, $plugin );
			$kind = (string) ( $ship['kind'] ?? self::KIND_URL );
			self::add_file(
				$buckets[ $plugin ],
				(string) ( $ship['filename'] ?? '' ),
				(string) ( $ship['mime'] ?? '' ),
				(int) ( $ship['size'] ?? 0 ),
				$kind
			);
			$provider = trim( (string) ( $ship['provider'] ?? '' ) );
			if ( '' !== $provider ) {
				$buckets[ $plugin ]['providers'][ $provider ] = true;
			}
			$ts = isset( $ship['ts'] ) ? (int) $ship['ts'] : 0;
			if ( $ts > (int) $buckets[ $plugin ]['last_shipment'] ) {
				$buckets[ $plugin ]['last_shipment'] = $ts;
			}
		}

		$findings = array();
		foreach ( $buckets as $plugin => $bucket ) {
			$files = array_values( $bucket['files'] );
			usort(
				$files,
				static function ( $a, $b ) {
					return strcmp( (string) $a['filename'], (string) $b['filename'] );
				}
			);
			$files = array_slice( $files, 0, self::MAX_FILES_PER_PLUGIN );
			$types = array_keys( $bucket['types'] );
			sort( $types, SORT_STRING );
			$providers = array_keys( $bucket['providers'] );
			sort( $providers, SORT_STRING );
			$findings[] = array(
				'plugin'         => (string) $plugin,
				'files'          => $files,
				'file_count'     => count( $files ),
				'types'          => $types,
				'providers'      => $providers,
				'bytes'          => (int) $bucket['bytes'],
				'last_shipment'  => (int) $bucket['last_shipment'],
				'grade'          => self::grade_for_kinds( $bucket['kinds'] ),
			);
		}

		usort(
			$findings,
			static function ( $a, $b ) {
				$rank = array(
					self::GRADE_PACKED   => 0,
					self::GRADE_DAYTRIP  => 1,
					self::GRADE_HOMEBODY => 2,
				);
				$ra = $rank[ $a['grade'] ] ?? 9;
				$rb = $rank[ $b['grade'] ] ?? 9;
				if ( $ra !== $rb ) {
					return $ra <=> $rb;
				}

				return strcmp( (string) $a['plugin'], (string) $b['plugin'] );
			}
		);

		$status = '';
		if ( ! $pack['available'] && array() === $shipments ) {
			$status = self::GRADE_INSUFFICIENT;
		} elseif ( $call_count < self::min_calls() && array() === $shipments ) {
			$status = self::GRADE_INSUFFICIENT;
		}

		return array(
			'findings'   => $findings,
			'call_count' => $call_count,
			'status'     => $status,
			'as_of'      => $as_of,
		);
	}

	/**
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
					'findings'   => self::sanitize_findings( $cached['findings'] ),
					'call_count' => isset( $cached['call_count'] ) ? (int) $cached['call_count'] : 0,
					'status'     => isset( $cached['status'] ) ? (string) $cached['status'] : '',
					'as_of'      => $as_of,
					'cached'     => true,
				);
			}
		}

		$data = self::census();
		$safe = array(
			'findings'   => self::sanitize_findings( $data['findings'] ),
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

	/**
	 * @param array<string,bool> $kinds Kind flags.
	 */
	public static function grade_for_kinds( array $kinds ): string {
		if ( ! empty( $kinds[ self::KIND_PACKED ] ) ) {
			return self::GRADE_PACKED;
		}
		if ( ! empty( $kinds[ self::KIND_URL ] ) || ! empty( $kinds[ self::KIND_ATTACHMENT ] ) ) {
			return self::GRADE_DAYTRIP;
		}

		return self::GRADE_HOMEBODY;
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
			__( 'Outbound media', 'handl-ai-connector-access-control' ),
			__( 'Outbound media', 'handl-ai-connector-access-control' ),
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
		echo '<h1>' . esc_html__( 'Outbound media', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'See which plugins send site uploads to AI providers. This report does not change your policy or activity log. File contents are never stored.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<ul class="ul-disc">';
		echo '<li><strong>' . esc_html__( 'HOMEBODY', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'No site files in AI requests.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'DAY-TRIPPER', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'A wp-content/uploads URL was referenced.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'PACKED-SUITCASE', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Raw file bytes were in the request body.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '</ul>';

		if ( self::GRADE_INSUFFICIENT === $snap['status'] ) {
			echo '<p>' . esc_html(
				sprintf(
					/* translators: %d: configured minimum logged AI calls. */
					__( 'Limited activity history: fewer than %d AI calls are logged.', 'handl-ai-connector-access-control' ),
					self::min_calls()
				)
			) . '</p>';
		}

		if ( empty( $snap['findings'] ) ) {
			echo '<p>' . esc_html__( 'No AI calls in the activity log yet.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Files', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Types', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Providers', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Bytes outbound', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Last shipment (UTC)', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Grade', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $snap['findings'] as $row ) {
			$files     = isset( $row['files'] ) && is_array( $row['files'] ) ? $row['files'] : array();
			$names     = array();
			foreach ( $files as $file ) {
				if ( is_array( $file ) && isset( $file['filename'] ) && '' !== (string) $file['filename'] ) {
					$names[] = (string) $file['filename'];
				}
			}
			$types     = isset( $row['types'] ) && is_array( $row['types'] ) ? $row['types'] : array();
			$providers = isset( $row['providers'] ) && is_array( $row['providers'] ) ? $row['providers'] : array();
			$last      = isset( $row['last_shipment'] ) ? (int) $row['last_shipment'] : 0;
			$seen      = $last > 0 ? gmdate( 'Y-m-d H:i', $last ) : '—';
			echo '<tr>';
			echo '<td>' . esc_html( (string) $row['plugin'] ) . '</td>';
			echo '<td>' . esc_html( array() === $names ? '—' : implode( ', ', $names ) ) . '</td>';
			echo '<td>' . esc_html( array() === $types ? '—' : implode( ', ', array_map( 'strval', $types ) ) ) . '</td>';
			echo '<td>' . esc_html( implode( ', ', array_map( 'strval', $providers ) ) ) . '</td>';
			echo '<td>' . esc_html( (string) (int) ( $row['bytes'] ?? 0 ) ) . '</td>';
			echo '<td>' . esc_html( $seen ) . '</td>';
			echo '<td>' . esc_html( (string) ( $row['grade'] ?? '' ) ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
		echo '</div>';
	}

	/**
	 * True when a stored blob still contains a raw payload needle.
	 *
	 * @param mixed  $stored Stored option.
	 * @param string $needle Raw payload fragment.
	 */
	public static function stored_contains_payload( $stored, string $needle ): bool {
		$needle = (string) $needle;
		if ( '' === $needle ) {
			return false;
		}
		$json = function_exists( 'wp_json_encode' ) ? wp_json_encode( $stored ) : json_encode( $stored );
		if ( ! is_string( $json ) ) {
			return false;
		}

		return false !== strpos( $json, $needle );
	}

	/**
	 * @param mixed $findings Raw findings.
	 * @return list<array<string,mixed>>
	 */
	public static function sanitize_findings( $findings ): array {
		if ( ! is_array( $findings ) ) {
			return array();
		}
		$out = array();
		foreach ( $findings as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			unset( $row['body'], $row['payload'], $row['contents'], $row['bits'], $row['data'], $row['raw'] );
			$plugin = trim( (string) ( $row['plugin'] ?? '' ) );
			if ( '' === $plugin ) {
				continue;
			}
			$files = array();
			if ( isset( $row['files'] ) && is_array( $row['files'] ) ) {
				foreach ( $row['files'] as $file ) {
					if ( ! is_array( $file ) ) {
						continue;
					}
					$files[] = array(
						'filename' => self::safe_filename( (string) ( $file['filename'] ?? '' ) ),
						'mime'     => self::safe_mime( (string) ( $file['mime'] ?? '' ) ),
						'size'     => isset( $file['size'] ) ? max( 0, (int) $file['size'] ) : 0,
						'kind'     => self::safe_kind( (string) ( $file['kind'] ?? '' ) ),
					);
				}
			}
			$types = array();
			if ( isset( $row['types'] ) && is_array( $row['types'] ) ) {
				foreach ( $row['types'] as $type ) {
					$type = self::safe_mime( (string) $type );
					if ( '' !== $type ) {
						$types[] = $type;
					}
				}
			}
			$providers = array();
			if ( isset( $row['providers'] ) && is_array( $row['providers'] ) ) {
				foreach ( $row['providers'] as $provider ) {
					$provider = trim( (string) $provider );
					if ( '' !== $provider ) {
						$providers[] = $provider;
					}
				}
			}
			$out[] = array(
				'plugin'        => $plugin,
				'files'         => $files,
				'file_count'    => isset( $row['file_count'] ) ? (int) $row['file_count'] : count( $files ),
				'types'         => $types,
				'providers'     => $providers,
				'bytes'         => isset( $row['bytes'] ) ? max( 0, (int) $row['bytes'] ) : 0,
				'last_shipment' => isset( $row['last_shipment'] ) ? (int) $row['last_shipment'] : 0,
				'grade'         => isset( $row['grade'] ) ? (string) $row['grade'] : self::GRADE_HOMEBODY,
			);
		}

		return $out;
	}

	/**
	 * @param mixed $rows Raw shipments.
	 * @return list<array<string,mixed>>
	 */
	public static function sanitize_shipments( $rows ): array {
		if ( ! is_array( $rows ) ) {
			return array();
		}
		$out = array();
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			unset( $row['body'], $row['payload'], $row['contents'], $row['bits'], $row['data'], $row['raw'], $row['tmp_name'] );
			$plugin = trim( (string) ( $row['plugin'] ?? '' ) );
			if ( '' === $plugin ) {
				continue;
			}
			$out[] = array(
				'plugin'        => $plugin,
				'provider'      => trim( (string) ( $row['provider'] ?? '' ) ),
				'host'          => trim( (string) ( $row['host'] ?? '' ) ),
				'filename'      => self::safe_filename( (string) ( $row['filename'] ?? '' ) ),
				'mime'          => self::safe_mime( (string) ( $row['mime'] ?? '' ) ),
				'size'          => isset( $row['size'] ) ? max( 0, (int) $row['size'] ) : 0,
				'kind'          => self::safe_kind( (string) ( $row['kind'] ?? self::KIND_URL ) ),
				'ts'            => isset( $row['ts'] ) ? (int) $row['ts'] : 0,
				'attachment_id' => isset( $row['attachment_id'] ) ? max( 0, (int) $row['attachment_id'] ) : 0,
				'touched'       => ! empty( $row['touched'] ),
			);
		}

		return $out;
	}

	/**
	 * @param array<string,array<string,mixed>> $buckets Buckets by plugin.
	 */
	private static function ensure_bucket( array &$buckets, string $plugin ): void {
		if ( isset( $buckets[ $plugin ] ) ) {
			return;
		}
		$buckets[ $plugin ] = array(
			'files'          => array(),
			'types'          => array(),
			'providers'      => array(),
			'bytes'          => 0,
			'last_shipment'  => 0,
			'kinds'          => array(),
		);
	}

	/**
	 * @param array<string,mixed> $bucket Plugin bucket.
	 */
	private static function add_file( array &$bucket, string $filename, string $mime, int $size, string $kind ): void {
		$filename = self::safe_filename( $filename );
		$mime     = self::safe_mime( $mime );
		$kind     = self::safe_kind( $kind );
		$size     = max( 0, $size );
		$bucket['kinds'][ $kind ] = true;
		if ( '' !== $mime ) {
			$bucket['types'][ $mime ] = true;
		}
		if ( self::KIND_PACKED === $kind ) {
			$bucket['bytes'] += $size;
		}
		if ( '' === $filename ) {
			return;
		}
		$key = $kind . "\t" . $filename;
		if ( ! isset( $bucket['files'][ $key ] ) ) {
			$bucket['files'][ $key ] = array(
				'filename' => $filename,
				'mime'     => $mime,
				'size'     => $size,
				'kind'     => $kind,
			);

			return;
		}
		if ( $size > (int) $bucket['files'][ $key ]['size'] ) {
			$bucket['files'][ $key ]['size'] = $size;
		}
		if ( '' === (string) $bucket['files'][ $key ]['mime'] && '' !== $mime ) {
			$bucket['files'][ $key ]['mime'] = $mime;
		}
	}

	/**
	 * @param array<string,mixed> $row Activity row.
	 * @return list<array{filename:string}>
	 */
	private static function upload_refs_from_row( array $row ): array {
		$hits = array();
		self::walk_value( $row, $hits, 0 );
		$out = array();
		foreach ( $hits as $hit ) {
			if ( self::KIND_URL === $hit['kind'] || self::KIND_ATTACHMENT === $hit['kind'] ) {
				$out[] = array( 'filename' => $hit['filename'] );
			}
		}

		return $out;
	}

	/**
	 * @param mixed                                                         $value Value.
	 * @param list<array{filename:string,mime:string,size:int,kind:string,attachment_id:int,touched:bool}> $hits Hits.
	 */
	private static function walk_value( $value, array &$hits, int $depth ): void {
		if ( $depth > 8 ) {
			return;
		}
		if ( is_object( $value ) ) {
			if ( class_exists( '\CURLFile', false ) && $value instanceof \CURLFile ) {
				$hits[] = self::hit_from_file(
					(string) $value->getPostFilename(),
					(string) $value->getMimeType(),
					0,
					self::KIND_PACKED,
					0
				);

				return;
			}
			if ( $value instanceof \stdClass ) {
				self::walk_value( (array) $value, $hits, $depth + 1 );
			}

			return;
		}
		if ( is_array( $value ) ) {
			if ( self::is_file_shape( $value ) ) {
				$name = '';
				if ( isset( $value['name'] ) && is_scalar( $value['name'] ) ) {
					$name = (string) $value['name'];
				} elseif ( isset( $value['filename'] ) && is_scalar( $value['filename'] ) ) {
					$name = (string) $value['filename'];
				}
				$mime = '';
				if ( isset( $value['type'] ) && is_scalar( $value['type'] ) ) {
					$mime = (string) $value['type'];
				} elseif ( isset( $value['mime'] ) && is_scalar( $value['mime'] ) ) {
					$mime = (string) $value['mime'];
				}
				$size = 0;
				if ( isset( $value['size'] ) && is_numeric( $value['size'] ) ) {
					$size = (int) $value['size'];
				} elseif ( isset( $value['bits'] ) && is_string( $value['bits'] ) ) {
					$size = strlen( $value['bits'] );
				}
				if ( '' === $name ) {
					$path = '';
					if ( isset( $value['tmp_name'] ) && is_scalar( $value['tmp_name'] ) ) {
						$path = (string) $value['tmp_name'];
					} elseif ( isset( $value['file'] ) && is_scalar( $value['file'] ) ) {
						$path = (string) $value['file'];
					}
					$name = self::filename_from_path( $path );
				}
				$hits[] = self::hit_from_file( $name, $mime, $size, self::KIND_PACKED, 0 );

				return;
			}
			foreach ( $value as $child ) {
				self::walk_value( $child, $hits, $depth + 1 );
			}

			return;
		}
		if ( ! is_string( $value ) || '' === $value ) {
			return;
		}
		if ( false !== stripos( $value, 'filename=' ) ) {
			if ( preg_match( '/filename\s*=\s*"([^"]+)"/i', $value, $m ) || preg_match( '/filename\s*=\s*([^;\\s]+)/i', $value, $m ) ) {
				$mime = '';
				if ( preg_match( '/Content-Type:\s*([^\r\n;]+)/i', $value, $cm ) ) {
					$mime = trim( $cm[1] );
				}
				$hits[] = self::hit_from_file( $m[1], $mime, 0, self::KIND_PACKED, 0 );
			}
		}
		if ( preg_match_all( '#wp-content/uploads/([^\s"\'<>]+)#i', $value, $matches ) ) {
			foreach ( $matches[1] as $rest ) {
				$hits[] = self::hit_from_file( self::filename_from_path( (string) $rest ), '', 0, self::KIND_URL, 0 );
			}
		}
		if ( preg_match_all( '/attachment_id["\'\s:=]+(\d+)/i', $value, $am ) ) {
			foreach ( $am[1] as $id_raw ) {
				$id = (int) $id_raw;
				if ( $id < 1 ) {
					continue;
				}
				$hits[] = self::hit_from_file( 'attachment-' . $id, '', 0, self::KIND_ATTACHMENT, $id );
			}
		}
	}

	/**
	 * @param array<string,mixed> $value Candidate.
	 */
	private static function is_file_shape( array $value ): bool {
		$has_name = ( isset( $value['name'] ) && is_scalar( $value['name'] ) && '' !== (string) $value['name'] )
			|| ( isset( $value['filename'] ) && is_scalar( $value['filename'] ) && '' !== (string) $value['filename'] );
		$has_body = isset( $value['tmp_name'] ) || isset( $value['bits'] ) || isset( $value['file'] );
		$has_meta = isset( $value['type'] ) || isset( $value['mime'] ) || isset( $value['size'] ) || isset( $value['error'] );

		return $has_name && ( $has_body || $has_meta );
	}

	/**
	 * @return array{filename:string,mime:string,size:int,kind:string,attachment_id:int,touched:bool}
	 */
	private static function hit_from_file( string $filename, string $mime, int $size, string $kind, int $attachment_id ): array {
		$touched = false;
		if ( $attachment_id > 0 ) {
			$touched = self::touched_knows_post( $attachment_id );
		}

		return array(
			'filename'      => self::safe_filename( $filename ),
			'mime'          => self::safe_mime( $mime ),
			'size'          => max( 0, $size ),
			'kind'          => self::safe_kind( $kind ),
			'attachment_id' => max( 0, $attachment_id ),
			'touched'       => $touched,
		);
	}

	private static function touched_knows_post( int $id ): bool {
		if ( $id < 1 ) {
			return false;
		}
		if ( ! class_exists( Touched::class, false ) || ! method_exists( Touched::class, 'index_ids' ) ) {
			return false;
		}
		$ids = Touched::index_ids();
		if ( ! is_array( $ids ) ) {
			return false;
		}

		return in_array( $id, $ids, true );
	}

	/**
	 * @param list<array{filename:string,mime:string,size:int,kind:string,attachment_id:int,touched:bool}> $hits Hits.
	 * @return list<array{filename:string,mime:string,size:int,kind:string,attachment_id:int,touched:bool}>
	 */
	private static function dedupe_hits( array $hits ): array {
		$out  = array();
		$seen = array();
		foreach ( $hits as $hit ) {
			$key = $hit['kind'] . "\t" . $hit['filename'] . "\t" . $hit['attachment_id'];
			if ( isset( $seen[ $key ] ) ) {
				continue;
			}
			$seen[ $key ] = true;
			$out[]        = $hit;
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $incoming Shipment metadata.
	 */
	private static function persist_shipment( array $incoming ): void {
		$rows = self::read_shipments();
		$row  = array(
			'plugin'        => (string) $incoming['plugin'],
			'provider'      => (string) $incoming['provider'],
			'host'          => (string) $incoming['host'],
			'filename'      => self::safe_filename( (string) $incoming['filename'] ),
			'mime'          => self::safe_mime( (string) $incoming['mime'] ),
			'size'          => max( 0, (int) $incoming['size'] ),
			'kind'          => self::safe_kind( (string) $incoming['kind'] ),
			'ts'            => (int) $incoming['ts'],
			'attachment_id' => max( 0, (int) $incoming['attachment_id'] ),
			'touched'       => ! empty( $incoming['touched'] ),
		);
		$rows[] = $row;
		if ( count( $rows ) > self::MAX_SHIPMENTS ) {
			$rows = array_slice( $rows, -1 * self::MAX_SHIPMENTS );
		}
		update_option( self::SHIPMENTS_OPTION, $rows, false );
		delete_option( self::CENSUS_OPTION );
		delete_option( self::GENERATED_OPTION );
	}

	private static function caller_plugin(): string {
		if ( null !== self::$test_plugin ) {
			return self::$test_plugin;
		}
		if ( class_exists( Attribution::class, false ) && method_exists( Attribution::class, 'resolve_from_backtrace' ) ) {
			$resolved = Attribution::resolve_from_backtrace();
			if ( is_array( $resolved ) && ! empty( $resolved['plugin'] ) && is_string( $resolved['plugin'] ) ) {
				return $resolved['plugin'];
			}
		}

		return 'unknown';
	}

	private static function filename_from_path( string $path ): string {
		$path = str_replace( '\\', '/', $path );
		$base = basename( $path );

		return self::safe_filename( $base );
	}

	private static function safe_filename( string $name ): string {
		$name = str_replace( array( "\0", "\r", "\n" ), '', $name );
		$name = basename( str_replace( '\\', '/', $name ) );
		if ( strlen( $name ) > 180 ) {
			$name = substr( $name, 0, 180 );
		}

		return $name;
	}

	private static function safe_mime( string $mime ): string {
		$mime = strtolower( trim( $mime ) );
		$mime = preg_replace( '/[^a-z0-9.+\-\/]/', '', $mime ) ?? '';
		if ( strlen( $mime ) > 80 ) {
			$mime = substr( $mime, 0, 80 );
		}

		return $mime;
	}

	private static function safe_kind( string $kind ): string {
		if ( in_array( $kind, array( self::KIND_PACKED, self::KIND_URL, self::KIND_ATTACHMENT ), true ) ) {
			return $kind;
		}

		return self::KIND_URL;
	}
}
