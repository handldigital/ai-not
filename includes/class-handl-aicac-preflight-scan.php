<?php
/**
 * AICAC-PREFLIGHT-SCAN: static AI-endpoint scan at plugin install/update (#297).
 *
 * Reads hosts and SDK needles from Provider_Map::endpoint_signatures() only.
 * Bounded file/time caps. Never blocks the installer on a thrown error.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Install-time scan of plugin (and theme) files for known AI endpoints.
 */
final class Preflight_Scan {

	public const OPTION_KEY = 'handl_aicac_preflight_findings';

	public const CHANNEL = 'preflight_scan';

	public const ACTION_STARTER = 'handl_aicac_preflight_starter';

	public const ACTION_DISMISS = 'handl_aicac_preflight_dismiss';

	public const ACTION_SCAN_ALL = 'handl_aicac_scan_all';

	/** Plugins/themes processed per inner batch of scan_all(). */
	public const SCAN_ALL_BATCH = 25;

	/** Max bytes read per file. */
	public const MAX_FILE_BYTES = 262144;

	/** Max files examined per plugin/theme scan. */
	public const MAX_FILES = 80;

	/** Wall-clock budget for one scan, seconds. */
	public const MAX_SCAN_SECONDS = 2.0;

	/** Directory basenames skipped entirely. */
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
	);

	private static ?Preflight_Scan $instance = null;

	public static function instance(): Preflight_Scan {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public static function reset_for_tests(): void {
		delete_option( self::OPTION_KEY );
		unset( $GLOBALS['handl_aicac_preflight_debug'] );
	}

	public function init(): void {
		add_action( 'upgrader_process_complete', array( $this, 'on_upgrader' ), 10, 2 );
		add_action( 'admin_notices', array( $this, 'maybe_admin_notice' ) );
		add_action( 'admin_post_' . self::ACTION_STARTER, array( $this, 'handle_starter' ) );
		add_action( 'admin_post_' . self::ACTION_DISMISS, array( $this, 'handle_dismiss' ) );
		add_filter( 'plugin_row_meta', array( $this, 'filter_plugin_row_meta' ), 20, 2 );
	}

	/**
	 * @param mixed                $upgrader WP_Upgrader instance (unused).
	 * @param array<string,mixed>  $hook_extra
	 */
	public function on_upgrader( $upgrader, $hook_extra ): void {
		unset( $upgrader );
		try {
			if ( ! is_array( $hook_extra ) ) {
				return;
			}
			$type   = isset( $hook_extra['type'] ) ? (string) $hook_extra['type'] : '';
			$action = isset( $hook_extra['action'] ) ? (string) $hook_extra['action'] : '';
			if ( 'install' !== $action && 'update' !== $action ) {
				return;
			}
			if ( 'plugin' === $type ) {
				foreach ( self::hook_plugin_basenames( $hook_extra ) as $basename ) {
					self::scan_and_record( $basename, $action );
				}
				return;
			}
			if ( 'theme' === $type ) {
				foreach ( self::hook_theme_stylesheets( $hook_extra ) as $stylesheet ) {
					self::scan_theme_and_record( $stylesheet, $action );
				}
			}
		} catch ( \Throwable $e ) {
			unset( $e );
		}
	}

	/**
	 * @param array<string,mixed> $hook_extra
	 * @return list<string>
	 */
	public static function hook_plugin_basenames( array $hook_extra ): array {
		$raw = array();
		if ( ! empty( $hook_extra['plugins'] ) && is_array( $hook_extra['plugins'] ) ) {
			$raw = $hook_extra['plugins'];
		} elseif ( ! empty( $hook_extra['plugin'] ) ) {
			$raw = array( $hook_extra['plugin'] );
		}
		$out = array();
		foreach ( $raw as $item ) {
			$basename = Plugin_Profile::sanitize_plugin( (string) $item );
			if ( '' !== $basename ) {
				$out[] = $basename;
			}
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * @param array<string,mixed> $hook_extra
	 * @return list<string>
	 */
	public static function hook_theme_stylesheets( array $hook_extra ): array {
		$raw = array();
		if ( ! empty( $hook_extra['themes'] ) && is_array( $hook_extra['themes'] ) ) {
			$raw = $hook_extra['themes'];
		} elseif ( ! empty( $hook_extra['theme'] ) ) {
			$raw = array( $hook_extra['theme'] );
		}
		$out = array();
		foreach ( $raw as $item ) {
			$slug = sanitize_key( (string) $item );
			if ( '' !== $slug ) {
				$out[] = $slug;
			}
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * Scan one plugin and persist findings / notices / activity.
	 *
	 * @return array<string,mixed>
	 */
	public static function scan_and_record( string $basename, string $action = 'install' ): array {
		$basename = Plugin_Profile::sanitize_plugin( $basename );
		$empty    = array(
			'plugin'     => $basename,
			'providers'  => array(),
			'file_count' => 0,
			'files'      => array(),
			'notice'     => false,
			'logged'     => false,
		);
		if ( '' === $basename || self::is_self( $basename ) ) {
			return $empty;
		}

		$dir = self::plugin_dir( $basename );
		$hit = self::scan_directory( $dir );
		return self::record_hit( 'plugin', $basename, $action, $hit );
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function scan_theme_and_record( string $stylesheet, string $action = 'install' ): array {
		$stylesheet = sanitize_key( $stylesheet );
		$empty      = array(
			'plugin'     => $stylesheet,
			'providers'  => array(),
			'file_count' => 0,
			'files'      => array(),
			'notice'     => false,
			'logged'     => false,
		);
		if ( '' === $stylesheet ) {
			return $empty;
		}
		$dir = self::theme_dir( $stylesheet );
		$hit = self::scan_directory( $dir );
		return self::record_hit( 'theme', $stylesheet, $action, $hit );
	}

	/**
	 * @param array{providers:list<string>,file_count:int,files:list<string>} $hit
	 * @return array<string,mixed>
	 */
	private static function record_hit( string $kind, string $id, string $action, array $hit ): array {
		$state    = self::get_state();
		$previous = isset( $state['items'][ $kind ][ $id ] ) && is_array( $state['items'][ $kind ][ $id ] )
			? $state['items'][ $kind ][ $id ]
			: array();
		$prev_providers = isset( $previous['providers'] ) && is_array( $previous['providers'] )
			? array_values( array_map( 'strval', $previous['providers'] ) )
			: array();

		$providers = $hit['providers'];
		$added     = array_values( array_diff( $providers, $prev_providers ) );
		$is_update = 'update' === $action;
		$should_notice = ! empty( $providers ) && ( ! $is_update || ! empty( $added ) );

		$entry = array(
			'kind'       => $kind,
			'id'         => $id,
			'providers'  => $providers,
			'file_count' => (int) $hit['file_count'],
			'files'      => array_slice( $hit['files'], 0, 20 ),
			'scanned_at' => time(),
			'action'     => $is_update ? 'update' : 'install',
			'added'      => $added,
		);

		if ( ! isset( $state['items'][ $kind ] ) || ! is_array( $state['items'][ $kind ] ) ) {
			$state['items'][ $kind ] = array();
		}
		$state['items'][ $kind ][ $id ] = $entry;

		$logged = false;
		if ( $should_notice ) {
			if ( ! isset( $state['notices'] ) || ! is_array( $state['notices'] ) ) {
				$state['notices'] = array();
			}
			$state['notices'][ $kind . ':' . $id ] = array(
				'kind'       => $kind,
				'id'         => $id,
				'providers'  => $providers,
				'file_count' => (int) $hit['file_count'],
			);
			$logged = self::log_activity( $id, $providers, (int) $hit['file_count'] );
		} else {
			if ( isset( $state['notices'][ $kind . ':' . $id ] ) ) {
				unset( $state['notices'][ $kind . ':' . $id ] );
			}
			self::debug_quiet_pass( $id );
		}

		self::save_state( $state );

		return array(
			'plugin'     => $id,
			'providers'  => $providers,
			'file_count' => (int) $hit['file_count'],
			'files'      => $hit['files'],
			'notice'     => $should_notice,
			'logged'     => $logged,
			'added'      => $added,
		);
	}

	/**
	 * @return array{providers:list<string>,file_count:int,files:list<string>}
	 */
	public static function scan_directory( string $dir ): array {
		$out = array(
			'providers'  => array(),
			'file_count' => 0,
			'files'      => array(),
		);
		$dir = rtrim( $dir, '/\\' );
		if ( '' === $dir || ! is_dir( $dir ) ) {
			return $out;
		}

		$files     = self::list_scan_files( $dir );
		$found     = array();
		$hit_files = array();
		$start     = microtime( true );
		$scanned   = 0;

		foreach ( $files as $rel ) {
			if ( $scanned >= self::MAX_FILES ) {
				break;
			}
			if ( ( microtime( true ) - $start ) >= self::MAX_SCAN_SECONDS ) {
				break;
			}
			$path = $dir . '/' . $rel;
			++$scanned;
			$ids = self::scan_file( $path );
			if ( empty( $ids ) ) {
				continue;
			}
			foreach ( $ids as $id ) {
				$found[ $id ] = true;
			}
			$hit_files[] = $rel;
		}

		$providers = array_keys( $found );
		sort( $providers, SORT_STRING );

		return array(
			'providers'  => $providers,
			'file_count' => count( $hit_files ),
			'files'      => $hit_files,
		);
	}

	/**
	 * @return list<string> Provider ids.
	 */
	public static function scan_file( string $abs_path ): array {
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

		return Provider_Map::match_text( $text );
	}

	/**
	 * Relative file paths under $root, vendor/minified skipped.
	 *
	 * @return list<string>
	 */
	public static function list_scan_files( string $root ): array {
		$root = rtrim( $root, '/\\' );
		$out  = array();
		if ( ! is_dir( $root ) ) {
			return $out;
		}

		try {
			$iterator = new \RecursiveIteratorIterator(
				new \RecursiveCallbackFilterIterator(
					new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS ),
					static function ( $current ) {
						/** @var \SplFileInfo $current */
						$name = $current->getFilename();
						if ( $current->isDir() ) {
							return ! in_array( strtolower( $name ), self::SKIP_DIRS, true );
						}
						$ext = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
						if ( ! in_array( $ext, self::SCAN_EXTENSIONS, true ) ) {
							return false;
						}
						if ( preg_match( '/\.min\.(js|css)$/i', $name ) ) {
							return false;
						}
						return true;
					}
				),
				\RecursiveIteratorIterator::LEAVES_ONLY
			);
		} catch ( \Throwable $e ) {
			unset( $e );
			return $out;
		}

		$max_list = 500;
		foreach ( $iterator as $file ) {
			/** @var \SplFileInfo $file */
			$abs = $file->getPathname();
			$rel = ltrim( str_replace( $root, '', $abs ), '/\\' );
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
	 * Stored scan state.
	 *
	 * @return array{items:array<string,array<string,array<string,mixed>>>,notices:array<string,array<string,mixed>>,last_run:array<string,mixed>}
	 */
	public static function get_state(): array {
		$raw = get_option( self::OPTION_KEY );
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}
		$items = isset( $raw['items'] ) && is_array( $raw['items'] ) ? $raw['items'] : array();
		if ( empty( $items ) && isset( $raw['plugins'] ) && is_array( $raw['plugins'] ) ) {
			$items = array( 'plugin' => $raw['plugins'] );
		}
		$notices  = isset( $raw['notices'] ) && is_array( $raw['notices'] ) ? $raw['notices'] : array();
		$last_run = isset( $raw['last_run'] ) && is_array( $raw['last_run'] ) ? $raw['last_run'] : array();

		return array(
			'items'    => $items,
			'notices'  => $notices,
			'last_run' => $last_run,
		);
	}

	/**
	 * @param array<string,mixed> $state
	 */
	public static function save_state( array $state ): void {
		update_option(
			self::OPTION_KEY,
			array(
				'items'    => isset( $state['items'] ) && is_array( $state['items'] ) ? $state['items'] : array(),
				'notices'  => isset( $state['notices'] ) && is_array( $state['notices'] ) ? $state['notices'] : array(),
				'last_run' => isset( $state['last_run'] ) && is_array( $state['last_run'] ) ? $state['last_run'] : array(),
			),
			false
		);
	}

	/**
	 * @return array<string,mixed>|null
	 */
	public static function findings_for_plugin( string $basename ): ?array {
		$basename = Plugin_Profile::sanitize_plugin( $basename );
		if ( '' === $basename ) {
			return null;
		}
		$state = self::get_state();
		$row   = $state['items']['plugin'][ $basename ] ?? null;
		return is_array( $row ) ? $row : null;
	}

	/**
	 * Pending admin notices.
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function pending_notices(): array {
		$state = self::get_state();
		$out   = array();
		foreach ( $state['notices'] as $row ) {
			if ( is_array( $row ) && ! empty( $row['id'] ) && ! empty( $row['providers'] ) ) {
				$out[] = $row;
			}
		}
		return $out;
	}

	public function maybe_admin_notice(): void {
		if ( ! Caps::user_can_manage() ) {
			return;
		}
		$pending = self::pending_notices();
		if ( empty( $pending ) ) {
			return;
		}

		foreach ( $pending as $row ) {
			$id         = (string) $row['id'];
			$kind       = isset( $row['kind'] ) ? (string) $row['kind'] : 'plugin';
			$providers  = is_array( $row['providers'] ) ? array_values( array_map( 'strval', $row['providers'] ) ) : array();
			$file_count = isset( $row['file_count'] ) ? (int) $row['file_count'] : 0;
			$label      = self::item_label( $kind, $id );
			$message    = self::notice_message( $label, $providers, $file_count );

			echo '<div class="notice notice-warning is-dismissible"><p>';
			echo esc_html( $message );
			if ( 'plugin' === $kind ) {
				echo ' <a href="' . esc_url( self::starter_url( $id ) ) . '">' . esc_html__( 'Add a Deny rule', 'handl-ai-connector-access-control' ) . '</a>';
				echo ' <a href="' . esc_url( Plugin_Profile::rules_url( $id ) ) . '">' . esc_html__( 'Review rules', 'handl-ai-connector-access-control' ) . '</a>';
			}
			echo ' <a href="' . esc_url( self::dismiss_url( $kind, $id ) ) . '">' . esc_html__( 'Dismiss', 'handl-ai-connector-access-control' ) . '</a>';
			echo '</p></div>';
		}
	}

	/**
	 * @param list<string> $plugin_meta
	 * @param string       $plugin_file
	 * @return list<string>
	 */
	public function filter_plugin_row_meta( $plugin_meta, $plugin_file ): array {
		$meta = is_array( $plugin_meta ) ? $plugin_meta : array();
		if ( ! Caps::user_can_view() ) {
			return $meta;
		}
		$row = self::findings_for_plugin( (string) $plugin_file );
		if ( ! is_array( $row ) || empty( $row['providers'] ) || ! is_array( $row['providers'] ) ) {
			return $meta;
		}
		$labels = self::provider_labels( array_map( 'strval', $row['providers'] ) );
		if ( '' === $labels ) {
			return $meta;
		}
		$url = Plugin_Profile::profile_url( (string) $plugin_file );
		$meta[] = '<a href="' . esc_url( $url ) . '">' . esc_html(
			sprintf(
				/* translators: %s: provider names */
				__( 'AI references found: %s', 'handl-ai-connector-access-control' ),
				$labels
			)
		) . '</a>';

		return $meta;
	}

	public function handle_starter(): void {
		$plugin = isset( $_GET['plugin'] ) ? Plugin_Profile::sanitize_plugin( wp_unslash( (string) $_GET['plugin'] ) ) : '';
		if ( function_exists( 'check_admin_referer' ) ) {
			check_admin_referer( self::ACTION_STARTER . '_' . $plugin );
		}
		if ( ! Caps::user_can_manage() || '' === $plugin ) {
			self::bail();
			return;
		}
		self::apply_starter_rule( $plugin );
		self::redirect_after( Plugin_Profile::rules_url( $plugin ) );
	}

	public function handle_dismiss(): void {
		$kind = isset( $_GET['kind'] ) ? sanitize_key( wp_unslash( (string) $_GET['kind'] ) ) : 'plugin';
		$id   = isset( $_GET['id'] ) ? wp_unslash( (string) $_GET['id'] ) : '';
		if ( 'plugin' === $kind ) {
			$id = Plugin_Profile::sanitize_plugin( $id );
		} else {
			$id = sanitize_key( $id );
		}
		if ( function_exists( 'check_admin_referer' ) ) {
			check_admin_referer( self::ACTION_DISMISS . '_' . $kind . '_' . $id );
		}
		if ( ! Caps::user_can_manage() || '' === $id ) {
			self::bail();
			return;
		}
		self::dismiss_notice( $kind, $id );
		self::redirect_after( admin_url( 'plugins.php' ) );
	}

	/**
	 * One-click starter: land a Deny rule for the scanned plugin, then drop the notice.
	 */
	public static function apply_starter_rule( string $plugin ): bool {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		if ( '' === $plugin ) {
			return false;
		}
		$ok = Policy::set_plugin_rule( $plugin, 'deny' );
		self::dismiss_notice( 'plugin', $plugin );
		return $ok;
	}

	public static function dismiss_notice( string $kind, string $id ): void {
		$state   = self::get_state();
		$key     = $kind . ':' . $id;
		$changed = false;
		if ( isset( $state['notices'][ $key ] ) ) {
			unset( $state['notices'][ $key ] );
			$changed = true;
		}
		if ( isset( $state['last_run']['hits'] ) && is_array( $state['last_run']['hits'] ) ) {
			$kept = array();
			foreach ( $state['last_run']['hits'] as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				if ( (string) ( $row['kind'] ?? '' ) === $kind && (string) ( $row['id'] ?? '' ) === $id ) {
					$changed = true;
					continue;
				}
				$kept[] = $row;
			}
			$state['last_run']['hits']      = $kept;
			$state['last_run']['hit_count'] = count( $kept );
		}
		if ( $changed ) {
			self::save_state( $state );
		}
	}

	public static function starter_url( string $plugin ): string {
		$plugin = Plugin_Profile::sanitize_plugin( $plugin );
		$args   = array(
			'action'   => self::ACTION_STARTER,
			'plugin'   => $plugin,
			'_wpnonce' => wp_create_nonce( self::ACTION_STARTER . '_' . $plugin ),
		);

		return add_query_arg( $args, admin_url( 'admin-post.php' ) );
	}

	public static function dismiss_url( string $kind, string $id ): string {
		$args = array(
			'action'   => self::ACTION_DISMISS,
			'kind'     => $kind,
			'id'       => $id,
			'_wpnonce' => wp_create_nonce( self::ACTION_DISMISS . '_' . $kind . '_' . $id ),
		);

		return add_query_arg( $args, admin_url( 'admin-post.php' ) );
	}

	/**
	 * @param list<string> $providers
	 */
	public static function notice_message( string $label, array $providers, int $file_count ): string {
		$names = self::provider_labels( $providers );
		$n     = max( 0, $file_count );

		return sprintf(
			/* translators: 1: plugin or theme name, 2: provider names, 3: file count */
			_n(
				'%1$s contains references to %2$s in %3$d file. This scan does not confirm that data was sent.',
				'%1$s contains references to %2$s in %3$d files. This scan does not confirm that data was sent.',
				$n,
				'handl-ai-connector-access-control'
			),
			$label,
			$names,
			$n
		);
	}

	/**
	 * @param list<string> $providers
	 */
	public static function provider_labels( array $providers ): string {
		$labels = array();
		foreach ( $providers as $id ) {
			$label = Provider_Map::signature_label( (string) $id );
			if ( '' !== $label ) {
				$labels[] = $label;
			}
		}
		$labels = array_values( array_unique( $labels ) );
		$count  = count( $labels );
		if ( 0 === $count ) {
			return '';
		}
		if ( 1 === $count ) {
			return $labels[0];
		}
		if ( 2 === $count ) {
			return $labels[0] . ' and ' . $labels[1];
		}
		$last = array_pop( $labels );

		return implode( ', ', $labels ) . ', and ' . $last;
	}

	private static function item_label( string $kind, string $id ): string {
		if ( 'plugin' === $kind && function_exists( 'get_plugins' ) ) {
			$plugins = get_plugins();
			if ( isset( $plugins[ $id ]['Name'] ) && is_string( $plugins[ $id ]['Name'] ) && '' !== $plugins[ $id ]['Name'] ) {
				return (string) $plugins[ $id ]['Name'];
			}
		}

		return $id;
	}

	/**
	 * @param list<string> $providers
	 */
	private static function log_activity( string $plugin, array $providers, int $file_count ): bool {
		if ( ! class_exists( Policy::class ) ) {
			return false;
		}
		Policy::append_log_event(
			array(
				'channel'       => self::CHANNEL,
				'ts'            => time(),
				'plugin'        => $plugin,
				'decision'      => 'observe',
				'denial_reason' => 'preflight_scan',
				'operation'     => 'preflight_scan',
				'providers'     => $providers,
				'file_count'    => $file_count,
				'user_id'       => function_exists( 'get_current_user_id' ) ? get_current_user_id() : 0,
			)
		);

		return true;
	}

	private static function debug_quiet_pass( string $id ): void {
		if ( ! isset( $GLOBALS['handl_aicac_preflight_debug'] ) || ! is_array( $GLOBALS['handl_aicac_preflight_debug'] ) ) {
			$GLOBALS['handl_aicac_preflight_debug'] = array();
		}
		$GLOBALS['handl_aicac_preflight_debug'][] = $id;
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- debug-only quiet pass.
			error_log( 'HandL AICAC preflight: ' . $id . ' had no known AI endpoints.' );
		}
	}

	/**
	 * Installed plugins and themes to scan. Self is skipped.
	 *
	 * @return list<array{kind:string,id:string,dir:string}>
	 */
	public static function inventory(): array {
		$out = array();
		if ( function_exists( 'get_plugins' ) ) {
			$plugins = get_plugins();
			if ( is_array( $plugins ) ) {
				foreach ( $plugins as $basename => $_data ) {
					$basename = Plugin_Profile::sanitize_plugin( (string) $basename );
					if ( '' === $basename || self::is_self( $basename ) ) {
						continue;
					}
					$out[] = array(
						'kind' => 'plugin',
						'id'   => $basename,
						'dir'  => self::plugin_dir( $basename ),
					);
				}
			}
		}
		if ( function_exists( 'wp_get_themes' ) ) {
			$themes = wp_get_themes();
			if ( is_array( $themes ) ) {
				foreach ( $themes as $stylesheet => $theme ) {
					$slug = sanitize_key( (string) $stylesheet );
					if ( is_object( $theme ) && method_exists( $theme, 'get_stylesheet' ) ) {
						$from_obj = sanitize_key( (string) $theme->get_stylesheet() );
						if ( '' !== $from_obj ) {
							$slug = $from_obj;
						}
					}
					if ( '' === $slug ) {
						continue;
					}
					$out[] = array(
						'kind' => 'theme',
						'id'   => $slug,
						'dir'  => self::theme_dir( $slug ),
					);
				}
			}
		}

		return $out;
	}

	/**
	 * Scan every installed plugin and theme. Read-only: never writes rules.
	 * One aggregate Activity row. No admin notices, no mail.
	 *
	 * @return array{ts:int,scanned:int,hit_count:int,hits:list<array<string,mixed>>,batch_count:int,batch_size:int}
	 */
	public static function scan_all(): array {
		$targets    = self::inventory();
		$batch_size = self::SCAN_ALL_BATCH;
		$batches    = 0;
		$scanned    = 0;
		$hits       = array();
		$state      = self::get_state();
		if ( ! isset( $state['items'] ) || ! is_array( $state['items'] ) ) {
			$state['items'] = array();
		}

		$chunks = array_chunk( $targets, max( 1, $batch_size ) );
		foreach ( $chunks as $chunk ) {
			++$batches;
			foreach ( $chunk as $target ) {
				++$scanned;
				$kind = (string) $target['kind'];
				$id   = (string) $target['id'];
				$hit  = self::scan_directory( (string) $target['dir'] );
				$entry = array(
					'kind'       => $kind,
					'id'         => $id,
					'providers'  => $hit['providers'],
					'file_count' => (int) $hit['file_count'],
					'files'      => array_slice( $hit['files'], 0, 20 ),
					'scanned_at' => time(),
					'action'     => 'scan_all',
				);
				if ( ! isset( $state['items'][ $kind ] ) || ! is_array( $state['items'][ $kind ] ) ) {
					$state['items'][ $kind ] = array();
				}
				$state['items'][ $kind ][ $id ] = $entry;
				if ( empty( $hit['providers'] ) ) {
					continue;
				}
				$hits[] = array(
					'kind'       => $kind,
					'id'         => $id,
					'label'      => self::item_label( $kind, $id ),
					'providers'  => $hit['providers'],
					'file_count' => (int) $hit['file_count'],
				);
			}
		}

		if ( 0 === $batches && empty( $targets ) ) {
			$batches = 0;
		}

		$run = array(
			'ts'          => time(),
			'scanned'     => $scanned,
			'hit_count'   => count( $hits ),
			'hits'        => $hits,
			'batch_count' => $batches,
			'batch_size'  => $batch_size,
		);
		$state['last_run'] = $run;
		self::save_state( $state );
		self::log_scan_all_activity( $run );

		return $run;
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function last_run(): array {
		$state = self::get_state();

		return isset( $state['last_run'] ) && is_array( $state['last_run'] ) ? $state['last_run'] : array();
	}

	public static function has_last_run(): bool {
		$run = self::last_run();

		return isset( $run['ts'] ) && (int) $run['ts'] > 0;
	}

	/**
	 * Policy Tools body: button, summary table, empty state.
	 */
	public static function render_policy_tools_section(): void {
		$run  = self::last_run();
		$hits = isset( $run['hits'] ) && is_array( $run['hits'] ) ? $run['hits'] : array();
		$done = self::has_last_run();

		echo '<p class="description">' . esc_html__( 'Reads installed plugin and theme files for known AI endpoints. This scan does not change rules and does not confirm that data was sent.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( Caps::user_can_manage() ) {
			echo '<form method="post" style="margin:0 0 1em;">';
			wp_nonce_field( self::ACTION_SCAN_ALL, 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_action" value="scan_all" />';
			echo '<input type="hidden" name="handl_aicac_tab" value="policy-tools" />';
			submit_button( __( 'Scan all installed plugins and themes', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
			echo '</form>';
		}

		if ( ! $done ) {
			return;
		}

		if ( empty( $hits ) ) {
			echo '<p>' . esc_html__( 'No AI provider references to show.', 'handl-ai-connector-access-control' ) . '</p>';
			return;
		}

		echo '<table class="widefat striped" id="handl-aicac-scan-all-results">';
		echo '<thead><tr>';
		echo '<th scope="col">' . esc_html__( 'Plugin or theme', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th scope="col">' . esc_html__( 'Providers', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th scope="col">' . esc_html__( 'Files', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th scope="col">' . esc_html__( 'Actions', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $hits as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$kind      = isset( $row['kind'] ) ? (string) $row['kind'] : 'plugin';
			$id        = isset( $row['id'] ) ? (string) $row['id'] : '';
			$label     = isset( $row['label'] ) && '' !== (string) $row['label'] ? (string) $row['label'] : $id;
			$providers = isset( $row['providers'] ) && is_array( $row['providers'] ) ? array_map( 'strval', $row['providers'] ) : array();
			$files     = isset( $row['file_count'] ) ? (int) $row['file_count'] : 0;
			echo '<tr>';
			echo '<td>' . esc_html( $label ) . '<br /><code>' . esc_html( $id ) . '</code></td>';
			echo '<td>' . esc_html( self::provider_labels( $providers ) ) . '</td>';
			echo '<td>' . esc_html( (string) $files ) . '</td>';
			echo '<td>';
			if ( 'plugin' === $kind && '' !== $id ) {
				echo '<a href="' . esc_url( self::starter_url( $id ) ) . '">' . esc_html__( 'Add a Deny rule', 'handl-ai-connector-access-control' ) . '</a> ';
				echo '<a href="' . esc_url( Plugin_Profile::rules_url( $id ) ) . '">' . esc_html__( 'Review rules', 'handl-ai-connector-access-control' ) . '</a> ';
			}
			echo '<a href="' . esc_url( self::dismiss_url( $kind, $id ) ) . '">' . esc_html__( 'Dismiss', 'handl-ai-connector-access-control' ) . '</a>';
			echo '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
	}

	/**
	 * @param array<string,mixed> $run
	 */
	private static function log_scan_all_activity( array $run ): void {
		if ( ! class_exists( Policy::class ) ) {
			return;
		}
		Policy::append_log_event(
			array(
				'channel'       => self::CHANNEL,
				'ts'            => isset( $run['ts'] ) ? (int) $run['ts'] : time(),
				'plugin'        => '',
				'decision'      => 'observe',
				'denial_reason' => 'scan_all',
				'operation'     => 'scan_all',
				'hit_count'     => isset( $run['hit_count'] ) ? (int) $run['hit_count'] : 0,
				'scanned'       => isset( $run['scanned'] ) ? (int) $run['scanned'] : 0,
				'batch_count'   => isset( $run['batch_count'] ) ? (int) $run['batch_count'] : 0,
				'user_id'       => function_exists( 'get_current_user_id' ) ? get_current_user_id() : 0,
			)
		);
	}

	private static function is_self( string $basename ): bool {
		$basename = str_replace( '\\', '/', $basename );
		return 0 === strpos( $basename, 'handl-ai-connector-access-control/' );
	}

	public static function plugin_dir( string $basename ): string {
		$root = defined( 'WP_PLUGIN_DIR' ) ? (string) WP_PLUGIN_DIR : '';
		if ( '' === $root ) {
			return '';
		}
		$basename = str_replace( '\\', '/', $basename );
		if ( false !== strpos( $basename, '/' ) ) {
			$slug = (string) strtok( $basename, '/' );
			$dir  = $root . '/' . $slug;
			return is_dir( $dir ) ? $dir : '';
		}
		$file = $root . '/' . $basename;
		return is_file( $file ) ? dirname( $file ) : '';
	}

	public static function theme_dir( string $stylesheet ): string {
		if ( function_exists( 'get_theme_root' ) ) {
			$root = (string) get_theme_root();
		} elseif ( defined( 'WP_CONTENT_DIR' ) ) {
			$root = WP_CONTENT_DIR . '/themes';
		} else {
			return '';
		}
		$dir = rtrim( $root, '/\\' ) . '/' . $stylesheet;
		return is_dir( $dir ) ? $dir : '';
	}

	private static function redirect_after( string $url ): void {
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $url );
			self::bail();
		}
	}

	private static function bail(): void {
		if ( function_exists( 'wp_die' ) ) {
			wp_die( '', '', array( 'response' => 200 ) );
		}
	}
}
