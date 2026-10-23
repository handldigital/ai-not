<?php
/**
 * AICAC-STOWAWAY (#461): leftover-data census from departed AI plugins.
 *
 * Report-only. Keyscan owns embedded keys in INSTALLED plugins;
 * Preflight_Scan owns endpoints at install time; TOMBSTONE owns dangling
 * refs in our allowlists. This page censuses foreign leftovers only.
 *
 * README-FREE. Own options only (handl_aicac_stowaway_*). Own admin screen.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Read-only leftover-data census.
 */
final class Stowaway {

	public const PAGE_SLUG = 'handl-aicac-stowaway';

	public const CENSUS_OPTION = 'handl_aicac_stowaway_census';

	public const GENERATED_OPTION = 'handl_aicac_stowaway_generated_at';

	public const GRADE_STOWAWAY = 'STOWAWAY';

	public const GRADE_DORMANT = 'DORMANT-OWNER';

	public const GRADE_CLEAN = 'CLEAN';

	public const SECRETS_SET     = 'set';
	public const SECRETS_NOT_SET = 'not-set';

	/** @var bool */
	private static $registered = false;

	/** @var bool */
	private static $skip_cache = false;

	/** @var list<array<string,mixed>>|null */
	private static $test_signatures = null;

	/** @var list<array<string,mixed>>|null */
	private static $test_option_rows = null;

	/** @var list<string>|null */
	private static $test_tables = null;

	/** @var array<string,bool>|null basename => true if installed */
	private static $test_installed = null;

	/** @var array<string,bool>|null basename => true if active */
	private static $test_active = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
	}

	public static function reset_for_tests(): void {
		self::$registered        = false;
		self::$skip_cache        = false;
		self::$test_signatures   = null;
		self::$test_option_rows  = null;
		self::$test_tables       = null;
		self::$test_installed    = null;
		self::$test_active       = null;
		delete_option( self::CENSUS_OPTION );
		delete_option( self::GENERATED_OPTION );
	}

	public static function set_skip_cache( bool $skip ): void {
		self::$skip_cache = $skip;
	}

	/**
	 * @param list<array<string,mixed>>|null $signatures Injected map.
	 */
	public static function set_test_signatures( ?array $signatures ): void {
		self::$test_signatures = $signatures;
	}

	/**
	 * @param list<array<string,mixed>>|null $rows Injected option rows.
	 */
	public static function set_test_option_rows( ?array $rows ): void {
		self::$test_option_rows = $rows;
	}

	/**
	 * @param list<string>|null $tables Injected table names (unprefixed or prefixed).
	 */
	public static function set_test_tables( ?array $tables ): void {
		self::$test_tables = $tables;
	}

	/**
	 * @param array<string,bool>|null $installed Basename => installed.
	 */
	public static function set_test_installed( ?array $installed ): void {
		self::$test_installed = $installed;
	}

	/**
	 * @param array<string,bool>|null $active Basename => active.
	 */
	public static function set_test_active( ?array $active ): void {
		self::$test_active = $active;
	}

	/**
	 * Curated leftover signatures. Filterable; tests may replace.
	 *
	 * @return list<array{file:string,name:string,option_prefixes:list<string>,tables:list<string>}>
	 */
	public static function signatures(): array {
		if ( null !== self::$test_signatures ) {
			return self::$test_signatures;
		}
		$defaults = array(
			array(
				'file'             => 'ai-engine/ai-engine.php',
				'name'             => 'AI Engine',
				'option_prefixes'  => array( 'mwai_' ),
				'tables'           => array(),
			),
			array(
				'file'             => 'gpt3-ai-content-generator/gpt3-ai-content-generator.php',
				'name'             => 'GPT3 AI Content Generator',
				'option_prefixes'  => array( 'wpaicg_' ),
				'tables'           => array( 'wpaicg_chatlogs' ),
			),
			array(
				'file'             => 'chatbot-chatgpt/chatbot-chatgpt.php',
				'name'             => 'Kognetiks Chatbot',
				'option_prefixes'  => array( 'chatbot_chatgpt_' ),
				'tables'           => array(),
			),
			array(
				'file'             => 'ai-power/ai-power.php',
				'name'             => 'AI Power',
				'option_prefixes'  => array( 'aipwr_', 'aipower_' ),
				'tables'           => array(),
			),
			array(
				'file'             => 'codewp/codewp.php',
				'name'             => 'CodeWP',
				'option_prefixes'  => array( 'codewp_' ),
				'tables'           => array(),
			),
		);
		$filtered = apply_filters( 'handl_aicac_stowaway_signatures', $defaults );
		if ( ! is_array( $filtered ) ) {
			return $defaults;
		}
		$out = array();
		foreach ( $filtered as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$file = isset( $row['file'] ) ? (string) $row['file'] : '';
			if ( '' === $file ) {
				continue;
			}
			$prefixes = array();
			if ( isset( $row['option_prefixes'] ) && is_array( $row['option_prefixes'] ) ) {
				foreach ( $row['option_prefixes'] as $prefix ) {
					$prefix = (string) $prefix;
					if ( '' !== $prefix ) {
						$prefixes[] = $prefix;
					}
				}
			}
			$tables = array();
			if ( isset( $row['tables'] ) && is_array( $row['tables'] ) ) {
				foreach ( $row['tables'] as $table ) {
					$table = (string) $table;
					if ( '' !== $table ) {
						$tables[] = $table;
					}
				}
			}
			$out[] = array(
				'file'            => $file,
				'name'            => isset( $row['name'] ) && '' !== (string) $row['name'] ? (string) $row['name'] : $file,
				'option_prefixes' => $prefixes,
				'tables'          => $tables,
			);
		}

		return $out;
	}

	/**
	 * Name looks secret-like, or the value matches a known key pattern.
	 *
	 * @param mixed $value Raw option value.
	 */
	public static function is_secret_like( string $name, $value ): bool {
		$n = strtolower( $name );
		if ( preg_match( '/(?:^|[_-])(key|token|secret|password|passwd|auth)(?:[_-]|$)/i', $n )
			|| false !== strpos( $n, 'api_key' )
			|| false !== strpos( $n, 'apikey' )
			|| false !== strpos( $n, 'access_token' ) ) {
			return true;
		}
		$text = self::value_as_text( $value );
		if ( '' === $text ) {
			return false;
		}
		if ( class_exists( Keyscan::class, false ) && method_exists( Keyscan::class, 'scan_text' ) ) {
			$hits = Keyscan::scan_text( $text );
			if ( is_array( $hits ) && array() !== $hits ) {
				return true;
			}
		}
		if ( preg_match( '/\bsk-(?:ant-)?[a-zA-Z0-9_-]{16,}\b/', $text ) ) {
			return true;
		}
		if ( preg_match( '/\bAIza[0-9A-Za-z_-]{30,}\b/', $text ) ) {
			return true;
		}

		return false;
	}

	/**
	 * @param mixed $value Raw.
	 */
	public static function byte_len( $value ): int {
		if ( is_string( $value ) ) {
			return strlen( $value );
		}
		if ( is_int( $value ) || is_float( $value ) ) {
			return strlen( (string) $value );
		}
		$json = function_exists( 'wp_json_encode' ) ? wp_json_encode( $value ) : json_encode( $value );

		return is_string( $json ) ? strlen( $json ) : 0;
	}

	/**
	 * @return array{installed:bool,active:bool}
	 */
	public static function plugin_state( string $basename ): array {
		if ( null !== self::$test_installed || null !== self::$test_active ) {
			$installed = null !== self::$test_installed && ! empty( self::$test_installed[ $basename ] );
			$active    = null !== self::$test_active && ! empty( self::$test_active[ $basename ] );

			return array(
				'installed' => $installed,
				'active'    => $active && $installed,
			);
		}
		$installed = false;
		if ( function_exists( 'get_plugins' ) ) {
			$plugins = get_plugins();
			$installed = is_array( $plugins ) && isset( $plugins[ $basename ] );
		}
		$active = false;
		if ( function_exists( 'is_plugin_active' ) ) {
			$active = (bool) is_plugin_active( $basename );
		} else {
			$active_list = get_option( 'active_plugins', array() );
			if ( is_array( $active_list ) ) {
				$active = in_array( $basename, $active_list, true );
			}
		}

		return array(
			'installed' => $installed,
			'active'    => $active,
		);
	}

	/**
	 * @return list<array{name:string,value:mixed,bytes:int,updated:int}>
	 */
	public static function option_rows(): array {
		if ( null !== self::$test_option_rows ) {
			$out = array();
			foreach ( self::$test_option_rows as $row ) {
				if ( ! is_array( $row ) || ! isset( $row['name'] ) ) {
					continue;
				}
				$out[] = array(
					'name'    => (string) $row['name'],
					'value'   => $row['value'] ?? '',
					'bytes'   => isset( $row['bytes'] ) ? (int) $row['bytes'] : self::byte_len( $row['value'] ?? '' ),
					'updated' => isset( $row['updated'] ) ? (int) $row['updated'] : 0,
				);
			}

			return $out;
		}

		global $wpdb;
		if ( isset( $wpdb ) && is_object( $wpdb ) && isset( $wpdb->options ) && method_exists( $wpdb, 'get_results' ) && method_exists( $wpdb, 'prepare' ) && method_exists( $wpdb, 'esc_like' ) ) {
			$collected = array();
			$seen      = array();
			foreach ( self::signatures() as $sig ) {
				foreach ( $sig['option_prefixes'] as $prefix ) {
					foreach ( array( $prefix, '_transient_' . $prefix, '_transient_timeout_' . $prefix ) as $needle ) {
						$like = $wpdb->esc_like( $needle ) . '%';
						$sql  = $wpdb->prepare(
							"SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s LIMIT 200",
							$like
						);
						if ( ! is_string( $sql ) ) {
							continue;
						}
						$rows = $wpdb->get_results( $sql, ARRAY_A );
						if ( ! is_array( $rows ) ) {
							continue;
						}
						foreach ( $rows as $row ) {
							if ( ! is_array( $row ) ) {
								continue;
							}
							$name = isset( $row['option_name'] ) ? (string) $row['option_name'] : '';
							if ( '' === $name || isset( $seen[ $name ] ) ) {
								continue;
							}
							$seen[ $name ] = true;
							$val           = $row['option_value'] ?? '';
							$collected[]   = array(
								'name'    => $name,
								'value'   => $val,
								'bytes'   => self::byte_len( $val ),
								'updated' => self::timeout_as_updated( $name, $val ),
							);
						}
					}
				}
			}

			return $collected;
		}

		$store = isset( $GLOBALS['handl_aicac_test_options'] ) && is_array( $GLOBALS['handl_aicac_test_options'] )
			? $GLOBALS['handl_aicac_test_options']
			: array();
		$out   = array();
		foreach ( $store as $name => $value ) {
			$out[] = array(
				'name'    => (string) $name,
				'value'   => $value,
				'bytes'   => self::byte_len( $value ),
				'updated' => 0,
			);
		}

		return $out;
	}

	/**
	 * @return list<string>
	 */
	public static function present_tables(): array {
		if ( null !== self::$test_tables ) {
			return array_values( self::$test_tables );
		}
		global $wpdb;
		if ( ! isset( $wpdb ) || ! is_object( $wpdb ) || ! method_exists( $wpdb, 'get_var' ) ) {
			return array();
		}
		$found  = array();
		$prefix = isset( $wpdb->prefix ) ? (string) $wpdb->prefix : '';
		foreach ( self::signatures() as $sig ) {
			foreach ( $sig['tables'] as $table ) {
				$full = $table;
				if ( '' !== $prefix && 0 !== strpos( $table, $prefix ) ) {
					$full = $prefix . $table;
				}
				$like = method_exists( $wpdb, 'esc_like' ) ? $wpdb->esc_like( $full ) : $full;
				$hit  = $wpdb->get_var( 'SHOW TABLES LIKE \'' . esc_sql( $like ) . '\'' );
				if ( is_string( $hit ) && '' !== $hit ) {
					$found[] = $hit;
				}
			}
		}

		return $found;
	}

	/**
	 * @return array{findings:list<array<string,mixed>>,as_of:int}
	 */
	public static function census(): array {
		$rows    = self::option_rows();
		$tables  = self::present_tables();
		$as_of   = time();
		$out     = array();

		foreach ( self::signatures() as $sig ) {
			$file   = $sig['file'];
			$state  = self::plugin_state( $file );
			if ( $state['active'] ) {
				continue;
			}
			$matched      = array();
			$row_count    = 0;
			$bytes        = 0;
			$newest       = 0;
			$secret_rows  = 0;
			foreach ( $rows as $row ) {
				if ( ! self::name_matches( $row['name'], $sig['option_prefixes'] ) ) {
					continue;
				}
				if ( 0 === strpos( $row['name'], 'handl_aicac_' ) ) {
					continue;
				}
				++$row_count;
				$bytes += (int) $row['bytes'];
				if ( (int) $row['updated'] > $newest ) {
					$newest = (int) $row['updated'];
				}
				if ( self::is_secret_like( $row['name'], $row['value'] ) ) {
					++$secret_rows;
				}
				$matched[] = $row['name'];
			}
			$table_hits = 0;
			foreach ( $sig['tables'] as $table ) {
				foreach ( $tables as $present ) {
					if ( $present === $table || substr( $present, -strlen( $table ) ) === $table ) {
						++$table_hits;
					}
				}
			}
			if ( $row_count < 1 && $table_hits < 1 ) {
				continue;
			}
			$grade = $state['installed'] ? self::GRADE_DORMANT : self::GRADE_STOWAWAY;
			$out[] = array(
				'file'           => $file,
				'name'           => $sig['name'],
				'grade'          => $grade,
				'row_count'      => $row_count,
				'table_count'    => $table_hits,
				'byte_estimate'  => $bytes,
				'newest'         => $newest,
				'secret_rows'    => $secret_rows,
				'secrets'        => $secret_rows > 0 ? self::SECRETS_SET : self::SECRETS_NOT_SET,
				'recommendation' => self::recommendation( $grade ),
			);
			unset( $matched );
		}

		usort(
			$out,
			static function ( array $a, array $b ): int {
				$order = array(
					self::GRADE_STOWAWAY => 0,
					self::GRADE_DORMANT  => 1,
				);
				$ga = $order[ $a['grade'] ] ?? 9;
				$gb = $order[ $b['grade'] ] ?? 9;
				if ( $ga !== $gb ) {
					return $ga <=> $gb;
				}

				return strcmp( (string) $a['file'], (string) $b['file'] );
			}
		);

		return array(
			'findings' => $out,
			'as_of'    => $as_of,
		);
	}

	/**
	 * @return array{findings:list<array<string,mixed>>,as_of:int,cached:bool}
	 */
	public static function snapshot(): array {
		if ( ! self::$skip_cache ) {
			$cached = get_option( self::CENSUS_OPTION, null );
			$as_of  = (int) get_option( self::GENERATED_OPTION, 0 );
			if ( is_array( $cached ) && isset( $cached['findings'] ) && is_array( $cached['findings'] ) && $as_of > 0 ) {
				return array(
					'findings' => $cached['findings'],
					'as_of'    => $as_of,
					'cached'   => true,
				);
			}
		}

		$data = self::census();
		$snap = array(
			'findings' => $data['findings'],
			'as_of'    => $data['as_of'],
			'cached'   => false,
		);
		if ( ! self::$skip_cache ) {
			update_option(
				self::CENSUS_OPTION,
				array(
					'findings' => $data['findings'],
				),
				false
			);
			update_option( self::GENERATED_OPTION, $data['as_of'], false );
		}

		return $snap;
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
			__( 'Stowaway', 'handl-ai-connector-access-control' ),
			__( 'Stowaway', 'handl-ai-connector-access-control' ),
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
		echo '<h1>' . esc_html__( 'Stowaway', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Leftover data from AI plugins that are no longer active. Report only — this screen never deletes anything.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<ul class="ul-disc">';
		echo '<li><strong>' . esc_html__( 'STOWAWAY', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Plugin is gone; leftover options or tables remain.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '<li><strong>' . esc_html__( 'DORMANT-OWNER', 'handl-ai-connector-access-control' ) . '</strong> — ' . esc_html__( 'Plugin is installed but inactive; leftover data is still present.', 'handl-ai-connector-access-control' ) . '</li>';
		echo '</ul>';

		if ( empty( $snap['findings'] ) ) {
			echo '<p>' . esc_html__( 'This site is clean. No leftover data from departed AI plugins.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Rows', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Bytes', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Secrets', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Grade', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Recommendation', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $snap['findings'] as $row ) {
			echo '<tr>';
			echo '<td>' . esc_html( (string) $row['name'] ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $row['row_count'] ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $row['byte_estimate'] ) . '</td>';
			echo '<td>' . esc_html( (string) $row['secrets'] ) . '</td>';
			echo '<td>' . esc_html( (string) $row['grade'] ) . '</td>';
			echo '<td>' . esc_html( (string) $row['recommendation'] ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
		echo '</div>';
	}

	/**
	 * @param list<string> $prefixes Prefixes.
	 */
	private static function name_matches( string $name, array $prefixes ): bool {
		foreach ( $prefixes as $prefix ) {
			if ( '' === $prefix ) {
				continue;
			}
			if ( 0 === strpos( $name, $prefix ) ) {
				return true;
			}
			if ( 0 === strpos( $name, '_transient_' . $prefix ) ) {
				return true;
			}
			if ( 0 === strpos( $name, '_transient_timeout_' . $prefix ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @param mixed $value Raw.
	 */
	private static function value_as_text( $value ): string {
		if ( is_string( $value ) ) {
			return $value;
		}
		if ( is_scalar( $value ) ) {
			return (string) $value;
		}
		$json = function_exists( 'wp_json_encode' ) ? wp_json_encode( $value ) : json_encode( $value );

		return is_string( $json ) ? $json : '';
	}

	/**
	 * @param mixed $value Timeout option value.
	 */
	private static function timeout_as_updated( string $name, $value ): int {
		if ( 0 !== strpos( $name, '_transient_timeout_' ) ) {
			return 0;
		}
		if ( is_numeric( $value ) ) {
			return (int) $value;
		}

		return 0;
	}

	private static function recommendation( string $grade ): string {
		if ( self::GRADE_DORMANT === $grade ) {
			return __( 'Plugin is inactive. Reactivate it or remove leftover options after you confirm they are unused.', 'handl-ai-connector-access-control' );
		}

		return __( 'Plugin is gone. Review leftover options, then delete them from wp_options if you no longer need them. AICAC does not delete this data.', 'handl-ai-connector-access-control' );
	}
}
