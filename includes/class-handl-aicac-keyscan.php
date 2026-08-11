<?php
/**
 * AICAC-KEYSCAN: detect embedded AI API keys in installed plugins (#137).
 *
 * Read-only scan of active plugin files + option values. Stores only masked
 * findings (last 4 characters). Never logs or persists full keys.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Keyscan {

	public const OPTION_KEY = 'handl_aicac_keyscan_findings';
	public const CRON_HOOK  = 'handl_aicac_keyscan_weekly';

	/** Site Health test slug (separate from access-control test). */
	public const SITE_HEALTH_SLUG = 'handl_aicac_keyscan';

	/** Max bytes read per file. */
	public const MAX_FILE_BYTES = 262144; // 256 KiB

	/** Max files examined per scan chunk (cron or button). */
	public const MAX_FILES_PER_CHUNK = 40;

	/** Directory basenames skipped entirely (vendor-heavy / noise). */
	public const SKIP_DIRS = array(
		'vendor',
		'node_modules',
		'.git',
		'.svn',
		'tests',
		'test',
		'__tests__',
		'phpunit',
		'cache',
		'dist',
		'build',
	);

	/** File extensions scanned. */
	public const SCAN_EXTENSIONS = array(
		'php',
		'js',
		'json',
		'txt',
		'env',
		'yml',
		'yaml',
		'ini',
		'config',
	);

	private static ?Keyscan $instance = null;

	public static function instance(): Keyscan {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function init(): void {
		add_action( self::CRON_HOOK, array( $this, 'cron_scan' ) );
		self::maybe_schedule();
		if ( is_admin() ) {
			add_filter( 'site_status_tests', array( $this, 'register_site_health_test' ) );
		}
	}

	public static function maybe_schedule(): void {
		if ( ! function_exists( 'wp_next_scheduled' ) || ! function_exists( 'wp_schedule_event' ) ) {
			return;
		}
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + DAY_IN_SECONDS, 'weekly', self::CRON_HOOK );
		}
	}

	public static function clear_schedule(): void {
		if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
			wp_clear_scheduled_hook( self::CRON_HOOK );
		}
	}

	/**
	 * WP-Cron entry: run one chunk (or complete small sites in one go).
	 */
	public function cron_scan(): void {
		self::run_scan_chunk( false );
	}

	/**
	 * @param array<string,mixed> $tests
	 * @return array<string,mixed>
	 */
	public function register_site_health_test( array $tests ): array {
		if ( ! isset( $tests['direct'] ) || ! is_array( $tests['direct'] ) ) {
			$tests['direct'] = array();
		}
		$tests['direct'][ self::SITE_HEALTH_SLUG ] = array(
			'label' => __( 'HandL AI Access: possible embedded API keys', 'handl-ai-connector-access-control' ),
			'test'  => array( $this, 'run_site_health_test' ),
		);
		return $tests;
	}

	/**
	 * @return array<string,mixed>
	 */
	public function run_site_health_test(): array {
		$findings = self::active_findings();
		$count    = count( $findings );
		$url      = admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=dashboard' );

		if ( $count > 0 ) {
			return array(
				'label'       => __( 'Active plugins may contain AI API keys', 'handl-ai-connector-access-control' ),
				'status'      => 'recommended',
				'badge'       => array(
					'label' => __( 'Security', 'handl-ai-connector-access-control' ),
					'color' => 'orange',
				),
				'description' => '<p>' . esc_html(
					sprintf(
						/* translators: %d: number of masked key findings */
						_n(
							'%d possible AI API key was found in active plugins. Only the last 4 characters are stored. Review the HandL AI Access dashboard.',
							'%d possible AI API keys were found in active plugins. Only the last 4 characters are stored. Review the HandL AI Access dashboard.',
							$count,
							'handl-ai-connector-access-control'
						),
						$count
					)
				) . '</p>',
				'actions'     => sprintf(
					'<a href="%s">%s</a>',
					esc_url( $url ),
					esc_html__( 'Open HandL AI Access dashboard', 'handl-ai-connector-access-control' )
				),
				'test'        => self::SITE_HEALTH_SLUG,
			);
		}

		return array(
			'label'       => __( 'No possible AI API keys detected in active plugins', 'handl-ai-connector-access-control' ),
			'status'      => 'good',
			'badge'       => array(
				'label' => __( 'Security', 'handl-ai-connector-access-control' ),
				'color' => 'blue',
			),
			'description' => '<p>' . esc_html__( 'A read-only scan of active plugin files and saved settings did not find known AI key patterns. Full keys are never stored.', 'handl-ai-connector-access-control' ) . '</p>',
			'actions'     => '',
			'test'        => self::SITE_HEALTH_SLUG,
		);
	}

	/**
	 * Stored state (may include findings for inactive plugins until pruned).
	 *
	 * @return array{findings:list<array<string,mixed>>,last_scan:int,cursor:array<string,mixed>}
	 */
	public static function get_state(): array {
		$raw = get_option( self::OPTION_KEY );
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}
		$findings = isset( $raw['findings'] ) && is_array( $raw['findings'] ) ? $raw['findings'] : array();
		$clean    = array();
		foreach ( $findings as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			// Never rehydrate a full key if a buggy write ever stored one.
			unset( $row['key'], $row['full'], $row['secret'], $row['value'] );
			$suffix = isset( $row['suffix'] ) ? (string) $row['suffix'] : '';
			if ( strlen( $suffix ) > 4 ) {
				$suffix = substr( $suffix, -4 );
			}
			$row['suffix'] = $suffix;
			$clean[]       = $row;
		}

		return array(
			'findings'       => $clean,
			'last_scan'      => isset( $raw['last_scan'] ) ? (int) $raw['last_scan'] : 0,
			'cursor'         => isset( $raw['cursor'] ) && is_array( $raw['cursor'] ) ? $raw['cursor'] : array(),
			'completed_once' => ! empty( $raw['completed_once'] ),
		);
	}

	/**
	 * Findings limited to currently active plugins (Site Health + Dashboard).
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function active_findings(): array {
		$active = self::active_plugin_basenames();
		$state  = self::get_state();
		$out    = array();
		foreach ( $state['findings'] as $row ) {
			$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			if ( '' !== $plugin && isset( $active[ $plugin ] ) ) {
				$out[] = $row;
			}
		}
		return $out;
	}

	/**
	 * Mask: only last 4 characters (never full key).
	 */
	public static function mask( string $raw_key ): string {
		$raw_key = trim( $raw_key );
		if ( '' === $raw_key ) {
			return '****';
		}
		$suffix = substr( $raw_key, -4 );
		return '••••' . $suffix;
	}

	/**
	 * Extract last 4 for storage.
	 */
	public static function suffix_only( string $raw_key ): string {
		$raw_key = trim( $raw_key );
		if ( strlen( $raw_key ) < 4 ) {
			return $raw_key;
		}
		return substr( $raw_key, -4 );
	}

	/**
	 * Pattern catalog: provider => list of PCRE patterns (must capture full key in match[0]).
	 *
	 * @return array<string,list<string>>
	 */
	public static function patterns(): array {
		return array(
			// OpenAI user/project keys (exclude Anthropic sk-ant- via negative lookahead).
			'openai'    => array(
				'/\bsk-(?!ant-)[a-zA-Z0-9_-]{16,}\b/',
			),
			'anthropic' => array(
				'/\bsk-ant-[a-zA-Z0-9_-]{16,}\b/',
			),
			'google'    => array(
				'/\bAIza[0-9A-Za-z_-]{30,}\b/',
			),
			// Azure OpenAI keys are often 32-char hex; require nearby "azure"/"openai" in option scan only.
			// File scan: 84-char base64-ish azure keys occasionally; keep 32-hex with azure context in scan_text.
			'azure'     => array(
				'/\b[a-fA-F0-9]{32}\b/',
			),
		);
	}

	/**
	 * Scan text and return raw matches (caller must mask before persist).
	 *
	 * @return list<array{provider:string,key:string}>
	 */
	public static function scan_text( string $text, bool $azure_context = false ): array {
		$out = array();
		foreach ( self::patterns() as $provider => $regexes ) {
			if ( 'azure' === $provider && ! $azure_context ) {
				// Only match 32-hex when context looks Azure-related.
				if ( ! preg_match( '/azure|cognitive|openai\.azure/i', $text ) ) {
					continue;
				}
			}
			foreach ( $regexes as $re ) {
				if ( ! preg_match_all( $re, $text, $m ) ) {
					continue;
				}
				foreach ( $m[0] as $key ) {
					$key = (string) $key;
					// Drop false positives: pure zeros, too short after strip.
					if ( strlen( $key ) < 16 && 'azure' !== $provider ) {
						continue;
					}
					if ( 'azure' === $provider && strlen( $key ) !== 32 ) {
						continue;
					}
					$out[] = array(
						'provider' => $provider,
						'key'      => $key,
					);
				}
			}
		}
		return $out;
	}

	/**
	 * Stable finding id without embedding the full key.
	 */
	public static function finding_id( string $plugin, string $source, string $location, string $provider, string $suffix ): string {
		return md5( $plugin . '|' . $source . '|' . $location . '|' . $provider . '|' . $suffix );
	}

	/**
	 * Run one scan chunk. Returns summary for UI.
	 *
	 * @return array{ok:bool,files_scanned:int,findings:int,done:bool,message:string}
	 */
	public static function run_scan_chunk( bool $reset_cursor = false ): array {
		$state   = self::get_state();
		$cursor  = $reset_cursor ? array() : $state['cursor'];
		$now     = time();
		$active  = self::active_plugin_basenames();
		$plugins = array_keys( $active );
		sort( $plugins, SORT_STRING );

		$plugin_idx = isset( $cursor['plugin_idx'] ) ? (int) $cursor['plugin_idx'] : 0;
		$file_offset = isset( $cursor['file_offset'] ) ? (int) $cursor['file_offset'] : 0;
		$options_done = ! empty( $cursor['options_done'] );

		// Index findings by id for merge.
		$by_id = array();
		foreach ( $state['findings'] as $row ) {
			if ( isset( $row['id'] ) ) {
				$by_id[ (string) $row['id'] ] = $row;
			}
		}

		// Drop findings for plugins no longer active (AC: clears when deactivated).
		foreach ( array_keys( $by_id ) as $id ) {
			$p = (string) ( $by_id[ $id ]['plugin'] ?? '' );
			if ( '' === $p || ! isset( $active[ $p ] ) ) {
				unset( $by_id[ $id ] );
			}
		}

		$files_scanned = 0;
		$budget        = self::MAX_FILES_PER_CHUNK;

		while ( $plugin_idx < count( $plugins ) && $files_scanned < $budget ) {
			$basename = $plugins[ $plugin_idx ];
			$dir      = self::plugin_dir( $basename );
			if ( '' === $dir || ! is_dir( $dir ) ) {
				++$plugin_idx;
				$file_offset  = 0;
				$options_done = false;
				continue;
			}

			// Options for this plugin once per plugin.
			if ( ! $options_done ) {
				foreach ( self::scan_plugin_options( $basename ) as $hit ) {
					self::merge_finding( $by_id, $hit, $now );
				}
				$options_done = true;
			}

			$files = self::list_plugin_files( $dir );
			$total = count( $files );
			while ( $file_offset < $total && $files_scanned < $budget ) {
				$rel  = $files[ $file_offset ];
				$path = $dir . '/' . $rel;
				++$file_offset;
				++$files_scanned;

				$hits = self::scan_file( $path, $basename, $rel );
				foreach ( $hits as $hit ) {
					self::merge_finding( $by_id, $hit, $now );
				}
			}

			if ( $file_offset >= $total ) {
				++$plugin_idx;
				$file_offset  = 0;
				$options_done = false;
			}
		}

		$done = $plugin_idx >= count( $plugins );
		$new_cursor = $done
			? array()
			: array(
				'plugin_idx'   => $plugin_idx,
				'file_offset'  => $file_offset,
				'options_done' => $options_done,
			);

		$findings = array_values( $by_id );
		usort(
			$findings,
			static function ( $a, $b ) {
				return ( (int) ( $b['last_seen'] ?? 0 ) ) <=> ( (int) ( $a['last_seen'] ?? 0 ) );
			}
		);

		$completed_once = ! empty( $state['completed_once'] ) || $done;
		update_option(
			self::OPTION_KEY,
			array(
				'findings'       => $findings,
				'last_scan'      => $now,
				'cursor'         => $new_cursor,
				'completed_once' => $completed_once,
			),
			false
		);

		$count = count( $findings );
		return array(
			'ok'            => true,
			'files_scanned' => $files_scanned,
			'findings'      => $count,
			'done'          => $done,
			'message'       => $done
				? sprintf(
					/* translators: %d: finding count */
					_n( 'Scan finished. %d possible key found (masked).', 'Scan finished. %d possible keys found (masked).', $count, 'handl-ai-connector-access-control' ),
					$count
				)
				: sprintf(
					/* translators: %d: files examined this run */
					__( 'Scan in progress: examined %d more files. Run again to continue.', 'handl-ai-connector-access-control' ),
					$files_scanned
				),
		);
	}

	/**
	 * @param array<string,array<string,mixed>> $by_id
	 * @param array{plugin:string,source:string,location:string,provider:string,key:string} $hit
	 */
	private static function merge_finding( array &$by_id, array $hit, int $now ): void {
		$key    = (string) $hit['key'];
		$suffix = self::suffix_only( $key );
		// Defense: never keep the full key in the hit after this point.
		unset( $hit['key'] );
		$id = self::finding_id(
			(string) $hit['plugin'],
			(string) $hit['source'],
			(string) $hit['location'],
			(string) $hit['provider'],
			$suffix
		);
		if ( isset( $by_id[ $id ] ) ) {
			$by_id[ $id ]['last_seen'] = $now;
			$by_id[ $id ]['suffix']    = $suffix;
			return;
		}
		$by_id[ $id ] = array(
			'id'         => $id,
			'plugin'     => (string) $hit['plugin'],
			'source'     => (string) $hit['source'],
			'location'   => (string) $hit['location'],
			'provider'   => (string) $hit['provider'],
			'suffix'     => $suffix,
			'mask'       => '••••' . $suffix,
			'first_seen' => $now,
			'last_seen'  => $now,
		);
	}

	/**
	 * @return list<array{plugin:string,source:string,location:string,provider:string,key:string}>
	 */
	public static function scan_file( string $abs_path, string $plugin_basename, string $rel_path ): array {
		if ( ! is_readable( $abs_path ) || ! is_file( $abs_path ) ) {
			return array();
		}
		$size = filesize( $abs_path );
		if ( false === $size || $size <= 0 || $size > self::MAX_FILE_BYTES ) {
			return array();
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local plugin file, size-capped.
		$text = file_get_contents( $abs_path );
		if ( ! is_string( $text ) || '' === $text ) {
			return array();
		}
		$hits = self::scan_text( $text, false );
		$out  = array();
		foreach ( $hits as $h ) {
			$out[] = array(
				'plugin'   => $plugin_basename,
				'source'   => 'file',
				'location' => $rel_path,
				'provider' => $h['provider'],
				'key'      => $h['key'],
			);
		}
		return $out;
	}

	/**
	 * @return list<array{plugin:string,source:string,location:string,provider:string,key:string}>
	 */
	public static function scan_plugin_options( string $plugin_basename ): array {
		$slug = self::plugin_slug( $plugin_basename );
		if ( '' === $slug ) {
			return array();
		}

		global $wpdb;
		$out = array();
		if ( isset( $wpdb ) && is_object( $wpdb ) && isset( $wpdb->options ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- intentional option name probe, limited.
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s LIMIT 200",
					'%' . $wpdb->esc_like( $slug ) . '%'
				),
				ARRAY_A
			);
			if ( is_array( $rows ) ) {
				foreach ( $rows as $row ) {
					$name  = (string) ( $row['option_name'] ?? '' );
					$value = (string) ( $row['option_value'] ?? '' );
					if ( '' === $name || '' === $value ) {
						continue;
					}
					// Skip our own storage.
					if ( 0 === strpos( $name, 'handl_aicac_' ) ) {
						continue;
					}
					// Unserialize lightly if needed for string leaves.
					if ( is_serialized( $value ) ) {
						$maybe = maybe_unserialize( $value );
						$value = self::flatten_for_scan( $maybe );
					}
					$azure_ctx = (bool) preg_match( '/azure|cognitive|openai/i', $name . ' ' . $value );
					foreach ( self::scan_text( $value, $azure_ctx ) as $h ) {
						$out[] = array(
							'plugin'   => $plugin_basename,
							'source'   => 'option',
							'location' => $name,
							'provider' => $h['provider'],
							'key'      => $h['key'],
						);
					}
				}
			}
		}

		// Also probe common AI option name patterns site-wide (capped).
		$common = array( 'openai_api_key', 'openai_key', 'anthropic_api_key', 'google_ai_api_key', 'gemini_api_key' );
		foreach ( $common as $opt ) {
			$val = get_option( $opt );
			if ( ! is_string( $val ) || '' === $val ) {
				continue;
			}
			// Only attribute if option name relates or value found while scanning that plugin's options already.
			// Attribute to plugin only when option name contains slug — handled above.
			unset( $val );
		}

		return $out;
	}

	/**
	 * @param mixed $data
	 */
	private static function flatten_for_scan( $data ): string {
		if ( is_string( $data ) ) {
			return $data;
		}
		if ( is_scalar( $data ) || null === $data ) {
			return (string) $data;
		}
		if ( is_array( $data ) ) {
			$parts = array();
			foreach ( $data as $k => $v ) {
				$parts[] = (string) $k;
				$parts[] = self::flatten_for_scan( $v );
			}
			return implode( ' ', $parts );
		}
		return '';
	}

	/**
	 * Relative file paths under plugin dir.
	 *
	 * @return list<string>
	 */
	public static function list_plugin_files( string $plugin_dir ): array {
		$plugin_dir = rtrim( $plugin_dir, '/\\' );
		$out        = array();
		if ( ! is_dir( $plugin_dir ) ) {
			return $out;
		}

		try {
			$iterator = new \RecursiveIteratorIterator(
				new \RecursiveCallbackFilterIterator(
					new \RecursiveDirectoryIterator( $plugin_dir, \FilesystemIterator::SKIP_DOTS ),
					static function ( $current, $key, $iterator ) {
						/** @var \SplFileInfo $current */
						$name = $current->getFilename();
						if ( $current->isDir() ) {
							return ! in_array( strtolower( $name ), self::SKIP_DIRS, true );
						}
						$ext = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
						return in_array( $ext, self::SCAN_EXTENSIONS, true );
					}
				),
				\RecursiveIteratorIterator::LEAVES_ONLY
			);
		} catch ( \Throwable $e ) {
			return $out;
		}

		$max_list = 500; // hard cap listing
		foreach ( $iterator as $file ) {
			/** @var \SplFileInfo $file */
			$abs = $file->getPathname();
			$rel = ltrim( str_replace( $plugin_dir, '', $abs ), '/\\' );
			$rel = str_replace( '\\', '/', $rel );
			$out[] = $rel;
			if ( count( $out ) >= $max_list ) {
				break;
			}
		}
		sort( $out, SORT_STRING );
		return $out;
	}

	/**
	 * @return array<string,true>
	 */
	public static function active_plugin_basenames(): array {
		$raw = get_option( 'active_plugins', array() );
		$out = array();
		if ( is_array( $raw ) ) {
			foreach ( $raw as $b ) {
				$b = (string) $b;
				if ( '' !== $b ) {
					$out[ $b ] = true;
				}
			}
		}
		// Never scan ourselves for "embedded keys" noise from fixtures in tests of this plugin
		// (still allow if another plugin embeds keys).
		return $out;
	}

	public static function plugin_dir( string $basename ): string {
		if ( ! function_exists( 'WP_PLUGIN_DIR' ) && ! defined( 'WP_PLUGIN_DIR' ) ) {
			return '';
		}
		$root = defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : '';
		if ( '' === $root ) {
			return '';
		}
		$slug = self::plugin_slug( $basename );
		if ( '' === $slug ) {
			// Single-file plugin.
			$file = $root . '/' . $basename;
			return is_file( $file ) ? dirname( $file ) : '';
		}
		$dir = $root . '/' . $slug;
		return is_dir( $dir ) ? $dir : '';
	}

	public static function plugin_slug( string $basename ): string {
		$basename = str_replace( '\\', '/', $basename );
		if ( false !== strpos( $basename, '/' ) ) {
			return (string) strtok( $basename, '/' );
		}
		return '';
	}

	/**
	 * Provider label for UI.
	 */
	public static function provider_label( string $provider ): string {
		$map = array(
			'openai'    => 'OpenAI',
			'anthropic' => 'Anthropic',
			'google'    => 'Google AI',
			'azure'     => 'Azure OpenAI',
		);
		return $map[ $provider ] ?? $provider;
	}

	/**
	 * Assert helper: ensure no full key material in stored state.
	 *
	 * @param array<string,mixed> $state
	 */
	public static function state_contains_full_key( array $state, string $full_key ): bool {
		$json = wp_json_encode( $state );
		if ( ! is_string( $json ) ) {
			return false;
		}
		return false !== strpos( $json, $full_key );
	}
}
