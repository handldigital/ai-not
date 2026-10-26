<?php
/**
 * AICAC-DOSSIER (#435): admin-facing per-user AI governance file.
 *
 * Own admin page (user picker → join). Guarded reads of quota / AUP /
 * access-request stores; skip with "source unavailable" when absent.
 * Read-only. README-FREE. Own options OFF by default.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One admin screen joining one user's AI grants, quota, spend, acks, denials.
 */
final class Dossier {

	public const SETTINGS_OPTION = 'handl_aicac_dossier';

	public const PAGE_SLUG = 'handl-aicac-dossier';

	public const ACTION_SAVE = 'handl_aicac_dossier_save';

	public const POST_PRESENT = 'handl_aicac_dossier_present';

	public const POST_ENABLED = 'handl_aicac_dossier_enabled';

	public const POST_CLI = 'handl_aicac_dossier_cli';

	public const QUERY_USER = 'handl_aicac_dossier_user';

	public const SOURCE_UNAVAILABLE = 'source unavailable';

	public const WINDOW_DAYS = 90;

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		delete_option( self::SETTINGS_OPTION );
		unset( $GLOBALS['handl_aicac_test_dossier_sources'] );
	}

	/**
	 * @return array{enabled:bool,cli_enabled:bool}
	 */
	public static function defaults(): array {
		return array(
			'enabled'     => false,
			'cli_enabled' => false,
		);
	}

	/**
	 * @return array{enabled:bool,cli_enabled:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,cli_enabled:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		$out = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$out['enabled']     = ! empty( $raw['enabled'] );
		$out['cli_enabled'] = ! empty( $raw['cli_enabled'] );

		return $out;
	}

	/**
	 * @param array<string,mixed> $settings Settings.
	 */
	public static function save_settings( array $settings ): bool {
		$clean  = self::sanitize_settings( $settings );
		$before = self::get_settings();
		if ( $clean === $before ) {
			return false;
		}
		if ( $clean === self::defaults() ) {
			delete_option( self::SETTINGS_OPTION );

			return true;
		}
		update_option( self::SETTINGS_OPTION, $clean, false );

		return true;
	}

	public static function is_enabled(): bool {
		return ! empty( self::get_settings()['enabled'] );
	}

	public static function is_cli_enabled(): bool {
		return ! empty( self::get_settings()['cli_enabled'] );
	}

	public static function is_redacted(): bool {
		return class_exists( Caps::class, false ) && method_exists( Caps::class, 'is_read_only' ) && Caps::is_read_only();
	}

	/**
	 * Guarded class_exists read. Tests may force a source on/off via
	 * $GLOBALS['handl_aicac_test_dossier_sources'][ClassName].
	 */
	public static function source_available( string $fqcn, string $method ): bool {
		$key = ltrim( $fqcn, '\\' );
		if ( isset( $GLOBALS['handl_aicac_test_dossier_sources'] ) && is_array( $GLOBALS['handl_aicac_test_dossier_sources'] ) && array_key_exists( $key, $GLOBALS['handl_aicac_test_dossier_sources'] ) ) {
			return (bool) $GLOBALS['handl_aicac_test_dossier_sources'][ $key ];
		}

		return class_exists( $fqcn, false ) && method_exists( $fqcn, $method );
	}

	/**
	 * @return object|false
	 */
	public static function resolve_user( $raw ) {
		if ( is_object( $raw ) && isset( $raw->ID ) && (int) $raw->ID > 0 ) {
			return $raw;
		}
		if ( is_numeric( $raw ) ) {
			$uid = (int) $raw;
			if ( $uid <= 0 ) {
				return false;
			}
			$user = function_exists( 'get_userdata' ) ? get_userdata( $uid ) : false;

			return $user ? $user : false;
		}
		$login = sanitize_text_field( (string) $raw );
		if ( '' === $login ) {
			return false;
		}
		if ( function_exists( 'get_user_by' ) ) {
			foreach ( array( 'login', 'slug', 'email' ) as $field ) {
				$found = get_user_by( $field, $login );
				if ( $found ) {
					return $found;
				}
			}
		}

		return false;
	}

	/**
	 * @return list<object>
	 */
	public static function list_users(): array {
		$store = $GLOBALS['handl_aicac_test_users'] ?? null;
		if ( is_array( $store ) ) {
			$out = array();
			foreach ( $store as $id => $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$out[] = (object) array_merge( $row, array( 'ID' => (int) $id ) );
			}

			return $out;
		}
		if ( function_exists( 'get_users' ) ) {
			$users = get_users(
				array(
					'number'  => 200,
					'orderby' => 'display_name',
					'order'   => 'ASC',
				)
			);

			return is_array( $users ) ? $users : array();
		}

		return array();
	}

	/**
	 * Full join for one user. Each section is either data or unavailable.
	 *
	 * @return array<string,mixed>|null Null when the user does not exist.
	 */
	public static function join( int $user_id, ?int $now = null ): ?array {
		$user = self::resolve_user( $user_id );
		if ( ! $user ) {
			return null;
		}
		$now     = null !== $now ? (int) $now : Clock::now();
		$redact  = self::is_redacted();
		$user_id = (int) $user->ID;
		$roles   = self::roles_of( $user );

		return array(
			'user_id'     => $user_id,
			'login'       => $redact ? '' : self::user_field( $user, 'user_login' ),
			'display'     => $redact ? ( 'user#' . (string) $user_id ) : self::display_name( $user ),
			'email'       => $redact ? '' : self::user_field( $user, 'user_email' ),
			'redacted'    => $redact,
			'roles'       => $roles,
			'grants'      => self::grants_section( $user_id, $roles ),
			'quota'       => self::quota_section( $user_id ),
			'activity'    => self::activity_section( $user_id, $now ),
			'aup'         => self::aup_section( $user_id, $now ),
			'requests'    => self::requests_section( $user_id ),
			'window_days' => self::WINDOW_DAYS,
		);
	}

	/**
	 * @param object $user User.
	 * @return list<string>
	 */
	public static function roles_of( $user ): array {
		if ( isset( $user->roles ) && is_array( $user->roles ) ) {
			return array_values( array_map( 'strval', $user->roles ) );
		}

		return array();
	}

	/**
	 * @param list<string> $roles Roles.
	 * @return array{available:bool,notice:string,role_gate:string,roles:list<string>,lines:list<string>}
	 */
	public static function grants_section( int $user_id, array $roles ): array {
		unset( $user_id );
		$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}
		$gate = 'off';
		if ( ! empty( $policy['role_gate_enabled'] ) ) {
			$allowed = method_exists( Policy::class, 'sanitize_allowed_roles' )
				? Policy::sanitize_allowed_roles( $policy['allowed_roles'] ?? array() )
				: array();
			$gate    = 'denied';
			foreach ( $roles as $role ) {
				if ( in_array( (string) $role, $allowed, true ) ) {
					$gate = 'allowed';
					break;
				}
			}
		}
		$lines = array();
		if ( 'off' === $gate ) {
			$lines[] = __( 'Role gate is off. Access follows the site policy.', 'handl-ai-connector-access-control' );
		} elseif ( 'allowed' === $gate ) {
			$lines[] = __( 'This user is allowed by role.', 'handl-ai-connector-access-control' );
		} else {
			$lines[] = __( 'This user is not in an allowed role.', 'handl-ai-connector-access-control' );
		}

		return array(
			'available' => true,
			'notice'    => '',
			'role_gate' => $gate,
			'roles'     => $roles,
			'lines'     => $lines,
		);
	}

	/**
	 * @return array{available:bool,notice:string,limit:?int,count:int,source:string,prevent:bool,line:string}
	 */
	public static function quota_section( int $user_id ): array {
		$empty = array(
			'available' => false,
			'notice'    => self::SOURCE_UNAVAILABLE,
			'limit'     => null,
			'count'     => 0,
			'source'    => '',
			'prevent'   => false,
			'line'      => '',
		);
		$fqcn = __NAMESPACE__ . '\\User_Quota';
		if ( ! self::source_available( $fqcn, 'evaluate' ) ) {
			return $empty;
		}
		$policy = Policy::get_policy();
		$eval   = $fqcn::evaluate( is_array( $policy ) ? $policy : array(), $user_id );
		if ( ! is_array( $eval ) ) {
			return $empty;
		}
		$limit = array_key_exists( 'limit', $eval ) ? $eval['limit'] : null;
		$count = isset( $eval['count'] ) ? (int) $eval['count'] : 0;
		$line  = null === $limit
			? __( 'No rolling call quota applies to this user.', 'handl-ai-connector-access-control' )
			: sprintf(
				/* translators: 1: usage count, 2: limit */
				__( 'Usage (rolling 24h): %1$s / %2$s', 'handl-ai-connector-access-control' ),
				(string) $count,
				(string) (int) $limit
			);

		return array(
			'available' => true,
			'notice'    => '',
			'limit'     => null === $limit ? null : (int) $limit,
			'count'     => $count,
			'source'    => isset( $eval['source'] ) ? (string) $eval['source'] : '',
			'prevent'   => ! empty( $eval['prevent'] ),
			'line'      => $line,
		);
	}

	/**
	 * Trailing-90d allow/deny counts + estimated spend from the activity log.
	 *
	 * @return array{available:bool,notice:string,allows:int,denies:int,est_usd:?float,line:string}
	 */
	public static function activity_section( int $user_id, int $now ): array {
		$empty = array(
			'available' => false,
			'notice'    => self::SOURCE_UNAVAILABLE,
			'allows'    => 0,
			'denies'    => 0,
			'est_usd'   => null,
			'line'      => '',
		);
		if ( ! class_exists( Plugin::class, false ) ) {
			return $empty;
		}
		$raw = get_option( Plugin::LOG_OPTION_KEY, null );
		if ( null === $raw || false === $raw || ! is_array( $raw ) ) {
			return $empty;
		}
		$cutoff = $now - ( self::WINDOW_DAYS * ( defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400 ) );
		$allows = 0;
		$denies = 0;
		$usd    = 0.0;
		$has    = false;
		$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		$policy = is_array( $policy ) ? $policy : array();
		foreach ( $raw as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( (int) ( $row['user_id'] ?? 0 ) !== $user_id ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts > 0 && $ts < $cutoff ) {
				continue;
			}
			$decision = (string) ( $row['decision'] ?? '' );
			if ( 'deny' === $decision ) {
				++$denies;
			} else {
				++$allows;
			}
			if ( class_exists( Cost::class, false ) && method_exists( Cost::class, 'estimate_usd' ) ) {
				$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
				$out = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
				if ( null !== $in || null !== $out ) {
					$provider = isset( $row['provider'] ) ? (string) $row['provider'] : '';
					$rates    = method_exists( Cost::class, 'rates_from_policy' )
						? Cost::rates_from_policy( $policy, $provider )
						: null;
					$est = Cost::estimate_usd( $in, $out, $rates );
					if ( null !== $est ) {
						$usd += (float) $est;
						$has  = true;
					}
				}
			}
		}
		$est  = $has ? $usd : null;
		$spend = null === $est
			? __( 'No estimated spend (no token counts).', 'handl-ai-connector-access-control' )
			: sprintf(
				/* translators: %s: formatted USD */
				__( 'Estimated spend: %s', 'handl-ai-connector-access-control' ),
				class_exists( Cost::class, false ) ? Cost::format_usd( $est ) : ( '$' . number_format( $est, 2, '.', ',' ) )
			);
		$line = sprintf(
			/* translators: 1: allow count, 2: deny count, 3: spend sentence */
			__( 'Allows: %1$d. Denies: %2$d. %3$s', 'handl-ai-connector-access-control' ),
			$allows,
			$denies,
			$spend
		);

		return array(
			'available' => true,
			'notice'    => '',
			'allows'    => $allows,
			'denies'    => $denies,
			'est_usd'   => $est,
			'line'      => $line,
		);
	}

	/**
	 * @return array{available:bool,notice:string,status:string,line:string}
	 */
	public static function aup_section( int $user_id, int $now ): array {
		$empty = array(
			'available' => false,
			'notice'    => self::SOURCE_UNAVAILABLE,
			'status'    => '',
			'line'      => '',
		);
		$fqcn = __NAMESPACE__ . '\\Aup';
		if ( ! self::source_available( $fqcn, 'status_for_user' ) ) {
			return $empty;
		}
		$status = (string) $fqcn::status_for_user( $user_id, null, $now );
		$label  = ( class_exists( $fqcn, false ) && method_exists( $fqcn, 'status_label' ) )
			? (string) $fqcn::status_label( $status )
			: $status;
		$line = sprintf(
			/* translators: %s: acknowledgement status */
			__( 'Acknowledgement: %s', 'handl-ai-connector-access-control' ),
			$label
		);

		return array(
			'available' => true,
			'notice'    => '',
			'status'    => $status,
			'line'      => $line,
		);
	}

	/**
	 * @return array{available:bool,notice:string,count:int,rows:list<array<string,mixed>>,line:string}
	 */
	public static function requests_section( int $user_id ): array {
		$empty = array(
			'available' => false,
			'notice'    => self::SOURCE_UNAVAILABLE,
			'count'     => 0,
			'rows'      => array(),
			'line'      => '',
		);
		$fqcn = __NAMESPACE__ . '\\Access_Request';
		if ( ! self::source_available( $fqcn, 'pending_rows' ) ) {
			return $empty;
		}
		$rows = array();
		foreach ( $fqcn::pending_rows() as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( (int) ( $row['user_id'] ?? 0 ) !== $user_id ) {
				continue;
			}
			$rows[] = $row;
		}
		$line = empty( $rows )
			? __( 'No open requests.', 'handl-ai-connector-access-control' )
			: sprintf(
				/* translators: %d: pending request count */
				_n( '%d open request.', '%d open requests.', count( $rows ), 'handl-ai-connector-access-control' ),
				count( $rows )
			);

		return array(
			'available' => true,
			'notice'    => '',
			'count'     => count( $rows ),
			'rows'      => $rows,
			'line'      => $line,
		);
	}

	/**
	 * Plain-text lines for CLI / tests (same join as the screen).
	 *
	 * @return array{ok:bool,code:int,lines:list<string>,join:?array<string,mixed>}
	 */
	public static function cli_print( $user_raw, bool $as_csv = false ): array {
		if ( ! self::is_cli_enabled() ) {
			return array(
				'ok'    => false,
				'code'  => 1,
				'lines' => array( __( 'User files CLI is off.', 'handl-ai-connector-access-control' ) ),
				'join'  => null,
			);
		}
		$user = self::resolve_user( $user_raw );
		if ( ! $user ) {
			return array(
				'ok'    => false,
				'code'  => 1,
				'lines' => array( __( 'Unknown user', 'handl-ai-connector-access-control' ) ),
				'join'  => null,
			);
		}
		$join = self::join( (int) $user->ID );
		if ( null === $join ) {
			return array(
				'ok'    => false,
				'code'  => 1,
				'lines' => array( __( 'Unknown user', 'handl-ai-connector-access-control' ) ),
				'join'  => null,
			);
		}
		if ( $as_csv ) {
			return array(
				'ok'    => true,
				'code'  => 0,
				'lines' => array( self::csv_for_join( $join ) ),
				'join'  => $join,
			);
		}

		return array(
			'ok'    => true,
			'code'  => 0,
			'lines' => self::text_lines( $join ),
			'join'  => $join,
		);
	}

	/**
	 * @param array<string,mixed> $join Join.
	 * @return list<string>
	 */
	public static function text_lines( array $join ): array {
		$lines   = array();
		$lines[] = 'user_id: ' . (string) (int) ( $join['user_id'] ?? 0 );
		$lines[] = 'display: ' . (string) ( $join['display'] ?? '' );
		if ( empty( $join['redacted'] ) ) {
			$lines[] = 'login: ' . (string) ( $join['login'] ?? '' );
		}
		$roles = isset( $join['roles'] ) && is_array( $join['roles'] ) ? $join['roles'] : array();
		$lines[] = 'roles: ' . ( empty( $roles ) ? '—' : implode( ',', array_map( 'strval', $roles ) ) );
		$lines[] = self::section_line( 'grants', $join['grants'] ?? array() );
		$lines[] = self::section_line( 'quota', $join['quota'] ?? array() );
		$lines[] = self::section_line( 'activity', $join['activity'] ?? array() );
		$lines[] = self::section_line( 'aup', $join['aup'] ?? array() );
		$lines[] = self::section_line( 'requests', $join['requests'] ?? array() );

		return $lines;
	}

	/**
	 * @param array<string,mixed> $section Section.
	 */
	private static function section_line( string $name, $section ): string {
		if ( ! is_array( $section ) || empty( $section['available'] ) ) {
			return $name . ': ' . self::SOURCE_UNAVAILABLE;
		}
		$line = isset( $section['line'] ) ? (string) $section['line'] : '';
		if ( '' === $line && isset( $section['lines'] ) && is_array( $section['lines'] ) ) {
			$line = implode( ' ', array_map( 'strval', $section['lines'] ) );
		}

		return $name . ': ' . $line;
	}

	/**
	 * @param array<string,mixed> $join Join.
	 */
	public static function csv_for_join( array $join ): string {
		$header = array( 'user_id', 'display', 'login', 'roles', 'grants', 'quota', 'activity', 'aup', 'requests', 'redacted' );
		$row    = array(
			(string) (int) ( $join['user_id'] ?? 0 ),
			(string) ( $join['display'] ?? '' ),
			(string) ( $join['login'] ?? '' ),
			implode( ',', array_map( 'strval', is_array( $join['roles'] ?? null ) ? $join['roles'] : array() ) ),
			self::csv_section( $join['grants'] ?? array() ),
			self::csv_section( $join['quota'] ?? array() ),
			self::csv_section( $join['activity'] ?? array() ),
			self::csv_section( $join['aup'] ?? array() ),
			self::csv_section( $join['requests'] ?? array() ),
			! empty( $join['redacted'] ) ? '1' : '0',
		);

		return self::csv_line( $header ) . "\n" . self::csv_line( $row ) . "\n";
	}

	/**
	 * @param mixed $section Section.
	 */
	private static function csv_section( $section ): string {
		if ( ! is_array( $section ) || empty( $section['available'] ) ) {
			return self::SOURCE_UNAVAILABLE;
		}
		if ( isset( $section['line'] ) && is_string( $section['line'] ) && '' !== $section['line'] ) {
			return $section['line'];
		}
		if ( isset( $section['lines'] ) && is_array( $section['lines'] ) ) {
			return implode( ' ', array_map( 'strval', $section['lines'] ) );
		}

		return '';
	}

	/**
	 * @param list<string> $cols Columns.
	 */
	public static function csv_line( array $cols ): string {
		$out = array();
		foreach ( $cols as $col ) {
			$col = (string) $col;
			if ( strpbrk( $col, ",\"\n\r" ) !== false ) {
				$col = '"' . str_replace( '"', '""', $col ) . '"';
			}
			$out[] = $col;
		}

		return implode( ',', $out );
	}

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'User file', 'handl-ai-connector-access-control' ),
			__( 'User file', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$settings   = self::get_settings();
		$can_manage = Caps::user_can_manage();
		$enabled    = ! empty( $settings['enabled'] );
		$user_raw   = isset( $_GET[ self::QUERY_USER ] ) ? wp_unslash( $_GET[ self::QUERY_USER ] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$picked     = '' !== (string) $user_raw ? self::resolve_user( $user_raw ) : false;
		$join       = $picked ? self::join( (int) $picked->ID ) : null;

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'User file', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'One place to see one user\'s AI access, quota, spend, acknowledgements, and open requests. This screen does not change access.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'User files', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( $enabled, true, false ) . ' /> ';
			echo esc_html__( 'Show user files', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row">' . esc_html__( 'WP-CLI', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_CLI ) . '" value="1" ' . checked( ! empty( $settings['cli_enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Allow WP-CLI', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '</tbody></table>';
			if ( function_exists( 'submit_button' ) ) {
				submit_button( __( 'Save user file settings', 'handl-ai-connector-access-control' ) );
			} else {
				echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Save user file settings', 'handl-ai-connector-access-control' ) . '</button></p>';
			}
			echo '</form>';
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'User files are off.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		if ( self::is_redacted() ) {
			echo '<p>' . esc_html__( 'This view hides names and emails.', 'handl-ai-connector-access-control' ) . '</p>';
		}

		echo '<form method="get" action="' . esc_url( admin_url( 'admin.php' ) ) . '">';
		echo '<input type="hidden" name="page" value="' . esc_attr( self::PAGE_SLUG ) . '" />';
		echo '<p><label>' . esc_html__( 'Pick a user', 'handl-ai-connector-access-control' ) . ' ';
		echo '<select name="' . esc_attr( self::QUERY_USER ) . '">';
		echo '<option value="">' . esc_html__( 'Select…', 'handl-ai-connector-access-control' ) . '</option>';
		$selected_id = $picked ? (int) $picked->ID : 0;
		foreach ( self::list_users() as $u ) {
			$uid  = isset( $u->ID ) ? (int) $u->ID : 0;
			$label = self::is_redacted() ? ( 'user#' . (string) $uid ) : self::display_name( $u );
			echo '<option value="' . esc_attr( (string) $uid ) . '"' . selected( $selected_id, $uid, false ) . '>' . esc_html( $label ) . '</option>';
		}
		echo '</select></label> ';
		echo '<button type="submit" class="button">' . esc_html__( 'Open', 'handl-ai-connector-access-control' ) . '</button></p>';
		echo '</form>';

		if ( '' !== (string) $user_raw && null === $join ) {
			echo '<p>' . esc_html__( 'Unknown user', 'handl-ai-connector-access-control' ) . '</p>';
		}

		if ( is_array( $join ) ) {
			self::render_join( $join );
			$csv = add_query_arg(
				array(
					'page'                 => self::PAGE_SLUG,
					self::QUERY_USER       => (string) (int) $join['user_id'],
					'handl_aicac_dossier_csv' => '1',
				),
				admin_url( 'admin.php' )
			);
			echo '<p><a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a></p>';
		}

		echo '</div>';
	}

	/**
	 * @param array<string,mixed> $join Join.
	 */
	public static function render_join( array $join ): void {
		echo '<h2>' . esc_html( (string) ( $join['display'] ?? '' ) ) . '</h2>';
		self::render_block( __( 'Role and grants', 'handl-ai-connector-access-control' ), $join['grants'] ?? array(), 'activity' );
		self::render_block( __( 'Quota', 'handl-ai-connector-access-control' ), $join['quota'] ?? array(), 'activity' );
		self::render_block( __( 'Last 90 days', 'handl-ai-connector-access-control' ), $join['activity'] ?? array(), 'activity' );
		self::render_block( __( 'Acknowledgements', 'handl-ai-connector-access-control' ), $join['aup'] ?? array(), 'protections' );
		self::render_block( __( 'Open requests', 'handl-ai-connector-access-control' ), $join['requests'] ?? array(), 'protections' );
	}

	/**
	 * @param array<string,mixed> $section Section.
	 */
	private static function render_block( string $heading, $section, string $link_screen ): void {
		echo '<h3>' . esc_html( $heading ) . '</h3>';
		if ( ! is_array( $section ) || empty( $section['available'] ) ) {
			echo '<p>' . esc_html__( 'source unavailable', 'handl-ai-connector-access-control' ) . '</p>';

			return;
		}
		if ( isset( $section['lines'] ) && is_array( $section['lines'] ) ) {
			echo '<ul>';
			foreach ( $section['lines'] as $line ) {
				echo '<li>' . esc_html( (string) $line ) . '</li>';
			}
			echo '</ul>';
		} elseif ( isset( $section['line'] ) ) {
			echo '<p>' . esc_html( (string) $section['line'] ) . '</p>';
		}
		if ( isset( $section['rows'] ) && is_array( $section['rows'] ) && ! empty( $section['rows'] ) ) {
			echo '<ul>';
			foreach ( $section['rows'] as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
				echo '<li>' . esc_html( '' !== $plugin ? $plugin : __( '(unknown plugin)', 'handl-ai-connector-access-control' ) ) . '</li>';
			}
			echo '</ul>';
		}
		$url = class_exists( Admin::class, false ) && method_exists( Admin::class, 'screen_url' ) ? Admin::screen_url( $link_screen ) : '';
		if ( '' !== $url ) {
			echo '<p><a href="' . esc_url( $url ) . '">' . esc_html__( 'Open this setting', 'handl-ai-connector-access-control' ) . '</a></p>';
		}
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'You do not have permission to save user file settings.', 'handl-ai-connector-access-control' ) );
			}

			return;
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );
			}

			return;
		}
		self::save_settings(
			array(
				'enabled'     => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'cli_enabled' => ! empty( $_POST[ self::POST_CLI ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
			)
		);
		$redirect = add_query_arg(
			array(
				'page'    => self::PAGE_SLUG,
				'updated' => '1',
			),
			admin_url( 'admin.php' )
		);
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $redirect );
			exit;
		}
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_dossier_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! self::is_enabled() ) {
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		$raw  = isset( $_GET[ self::QUERY_USER ] ) ? wp_unslash( $_GET[ self::QUERY_USER ] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$join = self::join( (int) $raw );
		if ( null === $join ) {
			return;
		}
		$csv = self::csv_for_join( $join );
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename="aicac-dossier-' . (int) $join['user_id'] . '.csv"' );
		}
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac dossier', CLI_Dossier::class );
	}

	/**
	 * @param object $user User.
	 */
	private static function display_name( $user ): string {
		foreach ( array( 'display_name', 'user_login', 'user_email' ) as $field ) {
			$v = self::user_field( $user, $field );
			if ( '' !== $v ) {
				return $v;
			}
		}
		$id = isset( $user->ID ) ? (int) $user->ID : 0;

		return $id > 0 ? ( 'user#' . (string) $id ) : '';
	}

	/**
	 * @param object $user User.
	 */
	private static function user_field( $user, string $field ): string {
		if ( isset( $user->{$field} ) && is_string( $user->{$field} ) ) {
			return $user->{$field};
		}

		return '';
	}
}

/**
 * WP-CLI: wp handl-aicac dossier <user>
 */
final class CLI_Dossier {

	/**
	 * Print one user's AI file.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login, or email.
	 *
	 * [--format=<format>]
	 * : table or csv.
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function __invoke( $args, $assoc_args ): void {
		$user = isset( $args[0] ) ? (string) $args[0] : '';
		$csv  = isset( $assoc_args['format'] ) && 'csv' === (string) $assoc_args['format'];
		$out  = Dossier::cli_print( $user, $csv );
		foreach ( $out['lines'] as $line ) {
			\WP_CLI::log( $line );
		}
		if ( empty( $out['ok'] ) ) {
			\WP_CLI::error( '', (int) $out['code'] );
		}
	}
}
