<?php
/**
 * AICAC-DENY-RECEIPT (#430): quotable reference code on every denied call.
 *
 * HMAC of log-row id + UTC day with a stored site salt. One extra `receipt`
 * key on the existing Activity row. Optional suffix on the caller deny
 * message. Admin lookup + WP-CLI. OFF by default. README-FREE.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Support-bridge receipt codes for denied AI Client calls.
 */
final class Deny_Receipt {

	public const SETTINGS_OPTION = 'handl_aicac_deny_receipt';

	public const SALT_OPTION = 'handl_aicac_deny_receipt_salt';

	public const PAGE_SLUG = 'handl-aicac-deny-receipt';

	public const ACTION_SAVE = 'handl_aicac_deny_receipt_save';

	public const POST_PRESENT = 'handl_aicac_deny_receipt_present';

	public const POST_MESSAGE = 'handl_aicac_deny_receipt_message';

	public const POST_LOOKUP = 'handl_aicac_deny_receipt_lookup';

	public const ROW_KEY = 'receipt';

	public const PREFIX = 'AICAC-';

	public const FRAMING = 'support_bridge_never_changes_deny';

	/** Crockford base32 without I L O U. */
	public const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

	public const SUFFIX_TEMPLATE = 'Reference: %s';

	/** @var bool */
	private static $registered = false;

	/** @var string */
	private static $last_halt = '';

	/** @var bool|null */
	private static $test_redacted = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered    = false;
		self::$last_halt     = '';
		self::$test_redacted = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::SALT_OPTION );
	}

	public static function last_halt(): string {
		return self::$last_halt;
	}

	public static function set_test_redacted( ?bool $redacted ): void {
		self::$test_redacted = $redacted;
	}

	/**
	 * @return array{message_enabled:bool,lookup_enabled:bool}
	 */
	public static function defaults(): array {
		return array(
			'message_enabled' => false,
			'lookup_enabled'  => false,
		);
	}

	/**
	 * @return array{message_enabled:bool,lookup_enabled:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw.
	 * @return array{message_enabled:bool,lookup_enabled:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return self::defaults();
		}

		return array(
			'message_enabled' => ! empty( $raw['message_enabled'] ),
			'lookup_enabled'  => ! empty( $raw['lookup_enabled'] ),
		);
	}

	/**
	 * @param array<string,mixed> $settings Incoming.
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

	public static function message_enabled(): bool {
		return ! empty( self::get_settings()['message_enabled'] );
	}

	public static function lookup_enabled(): bool {
		return ! empty( self::get_settings()['lookup_enabled'] );
	}

	/**
	 * Stamp receipt onto a deny event. Mutates $event in place.
	 *
	 * @param array<string,mixed> $event Activity event.
	 */
	public static function stamp( array &$event ): void {
		$decision = isset( $event['decision'] ) ? (string) $event['decision'] : '';
		if ( 'deny' !== $decision ) {
			return;
		}

		if ( empty( $event['log_key'] ) || ! is_string( $event['log_key'] ) ) {
			$event['log_key'] = self::generate_log_key();
		}

		$ts = isset( $event['ts'] ) ? (int) $event['ts'] : 0;
		if ( $ts <= 0 ) {
			$ts = class_exists( Clock::class, false ) ? Clock::now() : time();
			$event['ts'] = $ts;
		}

		$code                 = self::code_for( (string) $event['log_key'], $ts );
		$event[ self::ROW_KEY ] = $code;

		if ( ! self::message_enabled() ) {
			return;
		}

		$msg = isset( $event['returned_error'] ) ? (string) $event['returned_error'] : '';
		if ( '' === $msg ) {
			return;
		}
		$event['returned_error'] = self::suffix_message( $msg, $code );
	}

	public static function suffix_message( string $message, string $code ): string {
		$suffix = sprintf( self::SUFFIX_TEMPLATE, $code );
		if ( false !== strpos( $message, $suffix ) ) {
			return $message;
		}

		return rtrim( $message ) . ' ' . $suffix;
	}

	public static function code_for( string $log_key, int $ts ): string {
		$day  = gmdate( 'Y-m-d', $ts );
		$raw  = hash_hmac( 'sha256', $log_key . '|' . $day, self::salt(), true );
		$body = self::crockford8( substr( $raw, 0, 5 ) );

		return self::PREFIX . substr( $body, 0, 4 ) . '-' . substr( $body, 4, 4 );
	}

	public static function normalize_code( string $raw ): string {
		$s = strtoupper( $raw );
		$s = preg_replace( '/[^0-9A-Z]/', '', $s ) ?? '';
		if ( 0 === strpos( $s, 'AICAC' ) ) {
			$s = substr( $s, 5 );
		}
		$s = strtr( $s, array( 'I' => '1', 'L' => '1', 'O' => '0' ) );
		if ( 8 !== strlen( $s ) ) {
			return '';
		}

		return self::PREFIX . substr( $s, 0, 4 ) . '-' . substr( $s, 4, 4 );
	}

	/**
	 * @return array<string,mixed>|null
	 */
	public static function lookup( string $code ): ?array {
		$want = self::normalize_code( $code );
		if ( '' === $want ) {
			return null;
		}

		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) ) {
			return null;
		}

		for ( $i = count( $log ) - 1; $i >= 0; $i-- ) {
			$row = $log[ $i ];
			if ( ! is_array( $row ) ) {
				continue;
			}
			$have = isset( $row[ self::ROW_KEY ] ) ? self::normalize_code( (string) $row[ self::ROW_KEY ] ) : '';
			if ( $have === $want ) {
				return self::present_row( $row );
			}
		}

		return null;
	}

	/**
	 * @param array<string,mixed> $row Activity row.
	 * @return array<string,mixed>
	 */
	public static function present_row( array $row, ?bool $redact = null ): array {
		if ( null === $redact ) {
			$redact = self::is_redacted();
		}
		if ( ! $redact ) {
			return $row;
		}
		foreach ( array( 'prompt_preview', 'prompt', 'uri', 'user_id', 'user_role', 'caller' ) as $key ) {
			if ( array_key_exists( $key, $row ) ) {
				$row[ $key ] = is_int( $row[ $key ] ) ? 0 : '';
			}
		}

		return $row;
	}

	public static function is_redacted(): bool {
		if ( null !== self::$test_redacted ) {
			return self::$test_redacted;
		}

		return class_exists( Caps::class, false ) && Caps::is_read_only();
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
			__( 'Deny receipts', 'handl-ai-connector-access-control' ),
			__( 'Deny receipts', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		$settings   = self::get_settings();
		$can_manage = Caps::user_can_manage();
		$code_in    = isset( $_GET['receipt'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['receipt'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Deny receipts', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Give blocked callers a short reference code they can quote. Paste a code here to open the matching Activity row. Off by default. This does not change Allow or Deny rules.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Show code to callers', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_MESSAGE ) . '" value="1" ' . checked( ! empty( $settings['message_enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Add "Reference: AICAC-XXXX-XXXX" to the blocked-call message', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row">' . esc_html__( 'Lookup screen', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_LOOKUP ) . '" value="1" ' . checked( ! empty( $settings['lookup_enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Let admins paste a code to open the matching Activity row', 'handl-ai-connector-access-control' );
			echo '</label></td></tr></tbody></table>';
			submit_button( __( 'Save deny receipts settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( empty( $settings['message_enabled'] ) && empty( $settings['lookup_enabled'] ) ) {
			echo '<p>' . esc_html__( 'Deny receipts are off. Blocked callers do not see a reference code.', 'handl-ai-connector-access-control' ) . '</p>';
		}

		if ( empty( $settings['lookup_enabled'] ) ) {
			echo '</div>';

			return;
		}

		echo '<h2>' . esc_html__( 'Look up a code', 'handl-ai-connector-access-control' ) . '</h2>';
		$lookup_url = function_exists( 'admin_url' )
			? add_query_arg( array( 'page' => self::PAGE_SLUG ), admin_url( 'admin.php' ) )
			: '';
		echo '<form method="get" action="' . esc_url( $lookup_url ) . '">';
		echo '<input type="hidden" name="page" value="' . esc_attr( self::PAGE_SLUG ) . '" />';
		echo '<p><label for="handl-aicac-deny-receipt-code">' . esc_html__( 'Receipt code', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<input name="receipt" id="handl-aicac-deny-receipt-code" type="text" value="' . esc_attr( $code_in ) . '" class="regular-text" placeholder="AICAC-XXXX-XXXX" /></p>';
		echo '<p><button type="submit" class="button">' . esc_html__( 'Look up', 'handl-ai-connector-access-control' ) . '</button></p>';
		echo '</form>';

		if ( '' !== $code_in ) {
			self::render_lookup_result( $code_in );
		}

		echo '</div>';
	}

	public static function render_lookup_result( string $code ): void {
		$row = self::lookup( $code );
		if ( null === $row ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'No Activity row matches that code. It may have aged out of the saved log.', 'handl-ai-connector-access-control' ) . '</p></div>';

			return;
		}

		$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
		$ts     = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		$when   = $ts > 0 ? gmdate( 'Y-m-d H:i:s', $ts ) . ' UTC' : '';
		$why    = class_exists( Why::class, false ) ? Why::explain_line( $row ) : '';
		$err    = isset( $row['returned_error'] ) ? (string) $row['returned_error'] : '';
		$code_n = isset( $row[ self::ROW_KEY ] ) ? (string) $row[ self::ROW_KEY ] : self::normalize_code( $code );

		echo '<div class="notice notice-success"><p>' . esc_html__( 'Match found.', 'handl-ai-connector-access-control' ) . '</p></div>';
		echo '<table class="widefat striped" style="max-width:52em;"><tbody>';
		echo '<tr><th>' . esc_html__( 'Code', 'handl-ai-connector-access-control' ) . '</th><td><code>' . esc_html( $code_n ) . '</code></td></tr>';
		echo '<tr><th>' . esc_html__( 'When', 'handl-ai-connector-access-control' ) . '</th><td>' . esc_html( $when ) . '</td></tr>';
		echo '<tr><th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th><td><code>' . esc_html( $plugin ) . '</code></td></tr>';
		if ( class_exists( Why::class, false ) ) {
			echo '<tr><th>' . esc_html__( 'Why', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo Why::render_expander( $row ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside Why.
			echo '</td></tr>';
		} elseif ( '' !== $why ) {
			echo '<tr><th>' . esc_html__( 'Why', 'handl-ai-connector-access-control' ) . '</th><td>' . esc_html( $why ) . '</td></tr>';
		}
		if ( '' !== $err ) {
			echo '<tr><th>' . esc_html__( 'Caller message', 'handl-ai-connector-access-control' ) . '</th><td>' . esc_html( $err ) . '</td></tr>';
		}
		if ( self::is_redacted() ) {
			echo '<tr><th>' . esc_html__( 'Payload', 'handl-ai-connector-access-control' ) . '</th><td>' . esc_html__( 'Hidden in read-only mode.', 'handl-ai-connector-access-control' ) . '</td></tr>';
		}
		echo '</tbody></table>';
	}

	public static function handle_save(): void {
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_manage() ) {
			self::halt( __( 'You need permission to manage these settings.', 'handl-ai-connector-access-control' ) );

			return;
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			self::halt( __( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );

			return;
		}
		self::save_settings(
			array(
				'message_enabled' => ! empty( $_POST[ self::POST_MESSAGE ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'lookup_enabled'  => ! empty( $_POST[ self::POST_LOOKUP ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
			)
		);
		$url = function_exists( 'admin_url' )
			? add_query_arg(
				array(
					'page'    => self::PAGE_SLUG,
					'updated' => '1',
				),
				admin_url( 'admin.php' )
			)
			: '';
		if ( '' !== $url && function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $url );
			exit;
		}
		self::halt( __( 'Deny receipts settings saved.', 'handl-ai-connector-access-control' ) );
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'aicac receipt', CLI_Deny_Receipt::class );
	}

	public static function salt(): string {
		$existing = get_option( self::SALT_OPTION, '' );
		if ( is_string( $existing ) && '' !== $existing ) {
			return $existing;
		}
		if ( function_exists( 'wp_generate_password' ) ) {
			$salt = wp_generate_password( 64, true, true );
		} else {
			$salt = bin2hex( random_bytes( 32 ) );
		}
		update_option( self::SALT_OPTION, $salt, false );

		return $salt;
	}

	private static function crockford8( string $bytes5 ): string {
		$pad = str_pad( $bytes5, 5, "\0" );
		$n   = 0;
		for ( $i = 0; $i < 5; $i++ ) {
			$n = ( $n << 8 ) | ord( $pad[ $i ] );
		}
		$out = '';
		for ( $i = 0; $i < 8; $i++ ) {
			$out  = self::ALPHABET[ $n & 31 ] . $out;
			$n  >>= 5;
		}

		return $out;
	}

	private static function generate_log_key(): string {
		if ( function_exists( 'wp_generate_uuid4' ) ) {
			return 'aicac_' . wp_generate_uuid4();
		}

		return 'aicac_' . uniqid( '', true );
	}

	private static function halt( string $message ): void {
		self::$last_halt = $message;
		if ( function_exists( 'wp_die' ) ) {
			wp_die( esc_html( $message ) );
		}
	}
}

/**
 * WP-CLI: wp aicac receipt <code>
 */
final class CLI_Deny_Receipt {

	/**
	 * Print the Activity row for a deny receipt code. Exits non-zero if unknown.
	 *
	 * ## OPTIONS
	 *
	 * <code>
	 * : Receipt code (AICAC-XXXX-XXXX).
	 *
	 * [--format=<format>]
	 * : table or json. Default json.
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function __invoke( $args, $assoc_args ): void {
		$code = isset( $args[0] ) ? (string) $args[0] : '';
		$row  = Deny_Receipt::lookup( $code );
		if ( null === $row ) {
			\WP_CLI::error( 'Unknown receipt code.' );
		}
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'json';
		if ( 'table' === $format ) {
			\WP_CLI::print_value(
				array(
					'receipt'  => (string) ( $row[ Deny_Receipt::ROW_KEY ] ?? '' ),
					'ts'       => (int) ( $row['ts'] ?? 0 ),
					'plugin'   => (string) ( $row['plugin'] ?? '' ),
					'decision' => (string) ( $row['decision'] ?? '' ),
					'why'      => class_exists( Why::class, false ) ? Why::explain_line( $row ) : '',
				),
				array( 'format' => 'table' )
			);

			return;
		}
		\WP_CLI::print_value( $row, array( 'format' => 'json' ) );
	}
}
