<?php
/**
 * AICAC-KEY-CUSTODY (#335): AI Not holds provider API keys; plugins borrow them.
 *
 * Vault screen + sodium secretbox (keyed from WP salts). Injects via pre_option_*
 * for the top keyscan-known *_api_key option names. Policy consult (public methods
 * read-only) before handoff. Revoke returns empty + distinct deny reason. Activity
 * rows append via Plugin::LOG_OPTION_KEY with key_source=custody. Migration helper
 * reads Keyscan findings (public, read-only). OFF by default. No admin.php edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Encrypted API-key custody vault + option injection.
 */
final class Key_Custody {

	public const REASON = 'key_custody';

	public const SETTINGS_OPTION = 'handl_aicac_key_custody';

	public const VAULT_OPTION = 'handl_aicac_key_custody_vault';

	public const PAGE_SLUG = 'handl-aicac-key-custody';

	public const CHANNEL = 'key_custody';

	public const POST_PRESENT = 'handl_aicac_key_custody_present';

	public const POST_ENABLED = 'handl_aicac_key_custody_enabled';

	/** @var bool */
	private static $registered = false;

	/** @var bool Skip inject while reading raw plugin options (migration). */
	private static $skip_inject = false;

	/** @var array<string,bool> Per-request handoff log dedupe. */
	private static $logged_handoffs = array();

	/**
	 * Top-3 option → provider map (keyscan common patterns).
	 *
	 * @return array<string,string>
	 */
	public static function inject_map(): array {
		return array(
			'openai_api_key'     => 'openai',
			'anthropic_api_key'  => 'anthropic',
			'google_ai_api_key'  => 'google',
		);
	}

	/**
	 * @return list<string>
	 */
	public static function providers(): array {
		return array( 'openai', 'anthropic', 'google' );
	}

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		foreach ( array_keys( self::inject_map() ) as $option ) {
			add_filter( 'pre_option_' . $option, array( self::class, 'filter_pre_option' ), 10, 3 );
		}
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_post' ), 6 );
	}

	public static function reset_for_tests(): void {
		self::$registered       = false;
		self::$skip_inject      = false;
		self::$logged_handoffs  = array();
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::VAULT_OPTION );
	}

	/**
	 * @return array{enabled:bool}
	 */
	public static function defaults(): array {
		return array( 'enabled' => false );
	}

	/**
	 * @return array{enabled:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		$enabled = false;
		if ( is_array( $raw ) && ! empty( $raw['enabled'] ) ) {
			$enabled = true;
		}

		return array( 'enabled' => $enabled );
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

	/**
	 * @return array<string,array{suffix:string,revoked:bool,updated_at:int,n?:string,c?:string}>
	 */
	public static function get_vault(): array {
		$raw = get_option( self::VAULT_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$keys = isset( $raw['keys'] ) && is_array( $raw['keys'] ) ? $raw['keys'] : array();
		$out  = array();
		foreach ( self::providers() as $provider ) {
			if ( ! isset( $keys[ $provider ] ) || ! is_array( $keys[ $provider ] ) ) {
				continue;
			}
			$row = $keys[ $provider ];
			$out[ $provider ] = array(
				'suffix'     => isset( $row['suffix'] ) ? self::sanitize_suffix( (string) $row['suffix'] ) : '',
				'revoked'    => ! empty( $row['revoked'] ),
				'updated_at' => isset( $row['updated_at'] ) ? (int) $row['updated_at'] : 0,
				'n'          => isset( $row['n'] ) ? (string) $row['n'] : '',
				'c'          => isset( $row['c'] ) ? (string) $row['c'] : '',
			);
		}

		return $out;
	}

	/**
	 * Persist vault map. Empty vault deletes the option (no-op save invariant).
	 *
	 * @param array<string,array<string,mixed>> $keys Provider => row.
	 */
	public static function save_vault( array $keys ): void {
		$clean = array();
		foreach ( self::providers() as $provider ) {
			if ( ! isset( $keys[ $provider ] ) || ! is_array( $keys[ $provider ] ) ) {
				continue;
			}
			$row = $keys[ $provider ];
			$clean[ $provider ] = array(
				'suffix'     => self::sanitize_suffix( (string) ( $row['suffix'] ?? '' ) ),
				'revoked'    => ! empty( $row['revoked'] ),
				'updated_at' => isset( $row['updated_at'] ) ? (int) $row['updated_at'] : 0,
				'n'          => isset( $row['n'] ) ? (string) $row['n'] : '',
				'c'          => isset( $row['c'] ) ? (string) $row['c'] : '',
			);
		}
		if ( empty( $clean ) ) {
			delete_option( self::VAULT_OPTION );

			return;
		}
		update_option( self::VAULT_OPTION, array( 'keys' => $clean ), false );
	}

	public static function sanitize_provider( string $provider ): string {
		$provider = strtolower( trim( $provider ) );
		if ( ! in_array( $provider, self::providers(), true ) ) {
			return '';
		}

		return $provider;
	}

	public static function sanitize_suffix( string $suffix ): string {
		$suffix = preg_replace( '/[^a-zA-Z0-9_\-]/', '', $suffix ) ?? '';
		if ( strlen( $suffix ) > 4 ) {
			$suffix = substr( $suffix, -4 );
		}

		return $suffix;
	}

	public static function mask_suffix( string $suffix ): string {
		$suffix = self::sanitize_suffix( $suffix );
		if ( '' === $suffix ) {
			return '••••';
		}

		return '••••' . $suffix;
	}

	/**
	 * Store or rotate a plaintext key for a provider (encrypted at rest).
	 */
	public static function store_key( string $provider, string $plaintext, ?int $now = null ): bool {
		$provider  = self::sanitize_provider( $provider );
		$plaintext = trim( $plaintext );
		if ( '' === $provider || '' === $plaintext ) {
			return false;
		}
		if ( ! self::crypto_available() ) {
			return false;
		}
		$enc = self::encrypt( $plaintext );
		if ( null === $enc ) {
			return false;
		}
		$now  = null !== $now && $now > 0 ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$keys = self::get_vault();
		$keys[ $provider ] = array(
			'suffix'     => class_exists( Keyscan::class, false ) ? Keyscan::suffix_only( $plaintext ) : self::sanitize_suffix( substr( $plaintext, -4 ) ),
			'revoked'    => false,
			'updated_at' => $now,
			'n'          => $enc['n'],
			'c'          => $enc['c'],
		);
		self::save_vault( $keys );

		return true;
	}

	/**
	 * Revoke: keep vault row, refuse to hand out the key.
	 */
	public static function revoke_key( string $provider, ?int $now = null ): bool {
		$provider = self::sanitize_provider( $provider );
		if ( '' === $provider ) {
			return false;
		}
		$keys = self::get_vault();
		if ( ! isset( $keys[ $provider ] ) ) {
			return false;
		}
		$now = null !== $now && $now > 0 ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$keys[ $provider ]['revoked']    = true;
		$keys[ $provider ]['updated_at'] = $now;
		$keys[ $provider ]['n']          = '';
		$keys[ $provider ]['c']          = '';
		self::save_vault( $keys );

		return true;
	}

	/**
	 * Decrypt a stored key, or empty string if missing/revoked/unavailable.
	 */
	public static function plaintext_for( string $provider ): string {
		$provider = self::sanitize_provider( $provider );
		if ( '' === $provider ) {
			return '';
		}
		$keys = self::get_vault();
		if ( ! isset( $keys[ $provider ] ) ) {
			return '';
		}
		$row = $keys[ $provider ];
		if ( ! empty( $row['revoked'] ) || '' === (string) ( $row['n'] ?? '' ) || '' === (string) ( $row['c'] ?? '' ) ) {
			return '';
		}

		return self::decrypt( (string) $row['n'], (string) $row['c'] );
	}

	public static function has_vault_entry( string $provider ): bool {
		$provider = self::sanitize_provider( $provider );

		return '' !== $provider && isset( self::get_vault()[ $provider ] );
	}

	public static function is_revoked( string $provider ): bool {
		$provider = self::sanitize_provider( $provider );
		if ( '' === $provider ) {
			return false;
		}
		$keys = self::get_vault();

		return isset( $keys[ $provider ] ) && ! empty( $keys[ $provider ]['revoked'] );
	}

	/**
	 * pre_option_* callback. Returning non-false short-circuits get_option.
	 *
	 * @param mixed  $pre     Prior filter value (false = load from DB).
	 * @param string $option  Option name (WP 5.5+).
	 * @param mixed  $default Default (unused).
	 * @return mixed
	 */
	public static function filter_pre_option( $pre, $option = '', $default = false ) {
		unset( $default );
		if ( self::$skip_inject || ! self::is_enabled() ) {
			return $pre;
		}
		// Another filter already short-circuited.
		if ( false !== $pre ) {
			return $pre;
		}

		$option = is_string( $option ) && '' !== $option ? $option : self::option_from_current_filter();
		$map    = self::inject_map();
		if ( ! isset( $map[ $option ] ) ) {
			return $pre;
		}
		$provider = $map[ $option ];
		if ( ! self::has_vault_entry( $provider ) ) {
			return $pre;
		}

		$plugin = null;
		if ( class_exists( Attribution::class, false ) ) {
			$attrib = Attribution::resolve_from_backtrace();
			$plugin = is_string( $attrib['plugin'] ?? null ) ? (string) $attrib['plugin'] : null;
		}

		// Selftest must keep using its own fixtures (demo/selftest unaffected).
		if ( class_exists( Selftest::class, false ) && Selftest::is_synthetic_plugin( $plugin ) ) {
			return $pre;
		}

		if ( self::is_revoked( $provider ) ) {
			self::log_deny( $provider, $option, 'revoked', $plugin );

			return '';
		}

		$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		if ( class_exists( Policy::class, false ) && Policy::would_prevent( $policy, $plugin ) ) {
			self::log_deny( $provider, $option, 'policy', $plugin );

			return '';
		}

		$plain = self::plaintext_for( $provider );
		if ( '' === $plain ) {
			self::log_deny( $provider, $option, 'unavailable', $plugin );

			return '';
		}

		self::log_handoff( $provider, $option, $plugin );

		return $plain;
	}

	/**
	 * Resolve option name when older WP calls the filter with one arg.
	 */
	private static function option_from_current_filter(): string {
		if ( ! function_exists( 'current_filter' ) ) {
			return '';
		}
		$hook = (string) current_filter();
		if ( 0 !== strpos( $hook, 'pre_option_' ) ) {
			return '';
		}

		return substr( $hook, strlen( 'pre_option_' ) );
	}

	/**
	 * Migration helper: copy a live option into the vault (Keyscan findings guide the UI).
	 *
	 * @return array{ok:bool,status:string,provider:string}
	 */
	public static function migrate_option( string $option_name, bool $clear_source = true, ?int $now = null ): array {
		$map = self::inject_map();
		if ( ! isset( $map[ $option_name ] ) ) {
			return array(
				'ok'       => false,
				'status'   => 'unsupported_option',
				'provider' => '',
			);
		}
		$provider = $map[ $option_name ];
		self::$skip_inject = true;
		$raw               = get_option( $option_name, '' );
		self::$skip_inject = false;
		if ( ! is_string( $raw ) || '' === trim( $raw ) ) {
			return array(
				'ok'       => false,
				'status'   => 'empty_option',
				'provider' => $provider,
			);
		}
		if ( ! self::store_key( $provider, $raw, $now ) ) {
			return array(
				'ok'       => false,
				'status'   => 'store_failed',
				'provider' => $provider,
			);
		}
		if ( $clear_source ) {
			delete_option( $option_name );
		}

		return array(
			'ok'       => true,
			'status'   => 'migrated',
			'provider' => $provider,
		);
	}

	/**
	 * Keyscan findings that map to custody inject options (for migration UI).
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function migration_candidates(): array {
		if ( ! class_exists( Keyscan::class, false ) ) {
			return array();
		}
		$map = self::inject_map();
		$out = array();
		foreach ( Keyscan::active_findings() as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( (string) ( $row['source'] ?? '' ) !== 'option' ) {
				continue;
			}
			$location = (string) ( $row['location'] ?? '' );
			if ( ! isset( $map[ $location ] ) ) {
				continue;
			}
			$out[] = $row;
		}

		return $out;
	}

	public static function register_menu(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		if ( ! class_exists( Admin::class, false ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Key custody', 'handl-ai-connector-access-control' ),
			__( 'Key custody', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function maybe_handle_post(): void {
		if ( function_exists( 'is_admin' ) && ! is_admin() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified below.
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) {
			return;
		}
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_manage() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_key_custody', 'handl_aicac_key_custody_nonce' );

		$enabled = ! empty( $_POST[ self::POST_ENABLED ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
		self::save_settings( array( 'enabled' => $enabled ) );

		// Store / rotate keys (blank = leave unchanged).
		foreach ( self::providers() as $provider ) {
			$field = 'handl_aicac_key_custody_key_' . $provider;
			// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			$posted = isset( $_POST[ $field ] ) ? trim( (string) wp_unslash( $_POST[ $field ] ) ) : '';
			if ( '' !== $posted ) {
				self::store_key( $provider, $posted );
			}
		}

		// Revokes.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$revokes = isset( $_POST['handl_aicac_key_custody_revoke'] ) && is_array( $_POST['handl_aicac_key_custody_revoke'] )
			? wp_unslash( $_POST['handl_aicac_key_custody_revoke'] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			: array();
		foreach ( $revokes as $provider => $on ) {
			if ( empty( $on ) ) {
				continue;
			}
			self::revoke_key( (string) $provider );
		}

		// Migration one-clicks.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$migrate = isset( $_POST['handl_aicac_key_custody_migrate'] ) ? sanitize_key( wp_unslash( (string) $_POST['handl_aicac_key_custody_migrate'] ) ) : '';
		if ( '' !== $migrate && isset( self::inject_map()[ $migrate ] ) ) {
			self::migrate_option( $migrate, true );
		}

		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect(
				add_query_arg(
					array(
						'page'    => self::PAGE_SLUG,
						'updated' => '1',
					),
					admin_url( 'admin.php' )
				)
			);
			exit;
		}
	}

	public static function render_page(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		$settings = self::get_settings();
		$vault    = self::get_vault();
		$crypto   = self::crypto_available();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Key custody', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p>' . esc_html__( 'Store provider API keys here. Plugins receive them only when AI Access Control allows the call. A deny means the key was never handed over.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( ! $crypto ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Sodium encryption is not available on this server. Key custody cannot store keys.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}

		if ( ! empty( $_GET['updated'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Key custody settings saved.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}

		if ( Caps::user_can_manage() ) {
			echo '<form method="post" action="">';
			wp_nonce_field( 'handl_aicac_key_custody', 'handl_aicac_key_custody_nonce' );
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable key custody', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Inject custody keys into known plugin API key options', 'handl-ai-connector-access-control' ) . '</label>';
			echo '<p class="description">' . esc_html__( 'Off by default. When on, stored keys replace openai_api_key, anthropic_api_key, and google_ai_api_key for allowed callers.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr>';

			foreach ( self::providers() as $provider ) {
				$row    = $vault[ $provider ] ?? null;
				$mask   = $row ? self::mask_suffix( (string) $row['suffix'] ) : '';
				$revoked = $row && ! empty( $row['revoked'] );
				$label  = class_exists( Keyscan::class, false ) ? Keyscan::provider_label( $provider ) : $provider;
				echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td>';
				if ( $row ) {
					echo '<p>' . esc_html(
						$revoked
							? sprintf(
								/* translators: %s: masked key suffix */
								__( 'Revoked (%s). Paste a new key to restore.', 'handl-ai-connector-access-control' ),
								$mask
							)
							: sprintf(
								/* translators: %s: masked key suffix */
								__( 'Stored key %s. Leave blank to keep.', 'handl-ai-connector-access-control' ),
								$mask
							)
					) . '</p>';
				}
				echo '<input type="password" autocomplete="new-password" class="regular-text" name="' . esc_attr( 'handl_aicac_key_custody_key_' . $provider ) . '" value="" />';
				if ( $row && ! $revoked ) {
					echo '<p><label><input type="checkbox" name="' . esc_attr( 'handl_aicac_key_custody_revoke[' . $provider . ']' ) . '" value="1" /> ';
					echo esc_html__( 'Revoke this key (next call gets an empty key)', 'handl-ai-connector-access-control' ) . '</label></p>';
				}
				echo '</td></tr>';
			}
			echo '</tbody></table>';

			$candidates = self::migration_candidates();
			if ( ! empty( $candidates ) ) {
				echo '<h2>' . esc_html__( 'Move keys from plugins', 'handl-ai-connector-access-control' ) . '</h2>';
				echo '<p class="description">' . esc_html__( 'Keyscan found these option keys. Move copies them into custody and clears the plugin option.', 'handl-ai-connector-access-control' ) . '</p>';
				echo '<ul>';
				$seen = array();
				foreach ( $candidates as $c ) {
					$loc = (string) ( $c['location'] ?? '' );
					if ( '' === $loc || isset( $seen[ $loc ] ) ) {
						continue;
					}
					$seen[ $loc ] = true;
					$mask = isset( $c['mask'] ) ? (string) $c['mask'] : self::mask_suffix( (string) ( $c['suffix'] ?? '' ) );
					echo '<li><label><input type="radio" name="handl_aicac_key_custody_migrate" value="' . esc_attr( $loc ) . '" /> ';
					echo esc_html( $loc . ' — ' . $mask ) . '</label></li>';
				}
				echo '</ul>';
			}

			submit_button( __( 'Save key custody', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		} else {
			echo '<p>' . esc_html__( 'You can view this screen. An administrator must change custody settings.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '<ul>';
			foreach ( self::providers() as $provider ) {
				$row = $vault[ $provider ] ?? null;
				$label = class_exists( Keyscan::class, false ) ? Keyscan::provider_label( $provider ) : $provider;
				if ( ! $row ) {
					echo '<li>' . esc_html( $label . ': —' ) . '</li>';
					continue;
				}
				$status = ! empty( $row['revoked'] ) ? __( 'revoked', 'handl-ai-connector-access-control' ) : self::mask_suffix( (string) $row['suffix'] );
				echo '<li>' . esc_html( $label . ': ' . $status ) . '</li>';
			}
			echo '</ul>';
		}
		echo '</div>';
	}

	/**
	 * @param string      $provider Provider id.
	 * @param string      $option   Option name.
	 * @param string      $why      revoked|policy|unavailable.
	 * @param string|null $plugin   Caller plugin.
	 */
	private static function log_deny( string $provider, string $option, string $why, ?string $plugin = null ): void {
		$dedupe = 'deny|' . $provider . '|' . $option . '|' . $why . '|' . (string) $plugin;
		if ( isset( self::$logged_handoffs[ $dedupe ] ) ) {
			return;
		}
		self::$logged_handoffs[ $dedupe ] = true;

		$message = self::deny_message( $provider, $why );
		$now     = class_exists( Clock::class, false ) ? Clock::now() : time();
		$event   = array(
			'ts'              => $now,
			'plugin'          => $plugin,
			'decision'        => 'deny',
			'would_decision'  => 'deny',
			'denial_reason'   => $message,
			'decision_source' => self::REASON,
			'provider'        => $provider,
			'option'          => $option,
			'key_source'      => 'custody',
			'key_custody'     => $why,
			'channel'         => self::CHANNEL,
			'user_id'         => class_exists( Policy::class, false ) ? Policy::current_user_id_for_gate() : 0,
			'user_role'       => class_exists( Policy::class, false ) ? Policy::current_user_role_for_log() : '',
		);
		if ( class_exists( Policy::class, false ) ) {
			Policy::append_log_event( $event );
		} else {
			self::append_log_fallback( $event );
		}
	}

	/**
	 * @param string      $provider Provider.
	 * @param string      $option   Option.
	 * @param string|null $plugin   Caller.
	 */
	private static function log_handoff( string $provider, string $option, ?string $plugin ): void {
		$dedupe = 'allow|' . $provider . '|' . $option . '|' . (string) $plugin;
		if ( isset( self::$logged_handoffs[ $dedupe ] ) ) {
			return;
		}
		self::$logged_handoffs[ $dedupe ] = true;

		$now   = class_exists( Clock::class, false ) ? Clock::now() : time();
		$event = array(
			'ts'              => $now,
			'plugin'          => $plugin,
			'decision'        => 'allow',
			'would_decision'  => 'allow',
			'decision_source' => self::REASON,
			'provider'        => $provider,
			'option'          => $option,
			'key_source'      => 'custody',
			'channel'         => self::CHANNEL,
			'user_id'         => class_exists( Policy::class, false ) ? Policy::current_user_id_for_gate() : 0,
			'user_role'       => class_exists( Policy::class, false ) ? Policy::current_user_role_for_log() : '',
		);
		if ( class_exists( Policy::class, false ) ) {
			Policy::append_log_event( $event );
		} else {
			self::append_log_fallback( $event );
		}
	}

	/**
	 * @param array<string,mixed> $event Event.
	 */
	private static function append_log_fallback( array $event ): void {
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		if ( ! is_array( $log ) ) {
			$log = array();
		}
		$log[] = $event;
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
	}

	public static function deny_message( string $provider, string $why ): string {
		$provider = self::sanitize_provider( $provider );
		if ( 'revoked' === $why ) {
			return sprintf(
				/* translators: %s: provider id */
				__( 'Key custody: %s key revoked — empty key returned.', 'handl-ai-connector-access-control' ),
				$provider
			);
		}
		if ( 'policy' === $why ) {
			return sprintf(
				/* translators: %s: provider id */
				__( 'Key custody: policy denied handoff of %s key.', 'handl-ai-connector-access-control' ),
				$provider
			);
		}

		return sprintf(
			/* translators: %s: provider id */
			__( 'Key custody: %s key unavailable.', 'handl-ai-connector-access-control' ),
			$provider
		);
	}

	public static function crypto_available(): bool {
		return function_exists( 'sodium_crypto_secretbox' )
			&& function_exists( 'sodium_crypto_secretbox_open' )
			&& defined( 'SODIUM_CRYPTO_SECRETBOX_KEYBYTES' )
			&& defined( 'SODIUM_CRYPTO_SECRETBOX_NONCEBYTES' );
	}

	/**
	 * @return array{n:string,c:string}|null
	 */
	public static function encrypt( string $plaintext ): ?array {
		if ( ! self::crypto_available() ) {
			return null;
		}
		try {
			$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$cipher = sodium_crypto_secretbox( $plaintext, $nonce, self::derived_key() );
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			return null;
		}

		return array(
			'n' => base64_encode( $nonce ),
			'c' => base64_encode( $cipher ),
		);
	}

	public static function decrypt( string $nonce_b64, string $cipher_b64 ): string {
		if ( ! self::crypto_available() || '' === $nonce_b64 || '' === $cipher_b64 ) {
			return '';
		}
		$nonce  = base64_decode( $nonce_b64, true );
		$cipher = base64_decode( $cipher_b64, true );
		if ( false === $nonce || false === $cipher ) {
			return '';
		}
		if ( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES !== strlen( $nonce ) ) {
			return '';
		}
		$plain = sodium_crypto_secretbox_open( $cipher, $nonce, self::derived_key() );
		if ( false === $plain ) {
			return '';
		}

		return (string) $plain;
	}

	/**
	 * 32-byte key from WP salts.
	 */
	public static function derived_key(): string {
		$auth   = function_exists( 'wp_salt' ) ? (string) wp_salt( 'auth' ) : 'handl-aicac-auth';
		$secure = function_exists( 'wp_salt' ) ? (string) wp_salt( 'secure_auth' ) : 'handl-aicac-secure';
		$hash   = hash( 'sha256', $auth . '|' . $secure . '|handl_aicac_key_custody_v1', true );

		return substr( $hash, 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES );
	}
}
