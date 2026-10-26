<?php
/**
 * AICAC-KEY-AGE (#399): API key rotation hygiene.
 *
 * Observed-rotation ledger (per provider: salted HMAC fingerprint + first-seen
 * / rotated-at timestamp) built by watching the top-3 provider key options and
 * the Key_Custody vault option. NEVER stores key material, prefixes or
 * suffixes — only a salted HMAC-SHA256. Age tiers ok / due / overdue (default
 * 90 days, last 14 days before max = due) plus "unmanaged" for keys Keyscan
 * can see in plugin files/options that have no custody vault entry. Roster
 * with deep link to the Key Custody screen (when present), one alert per
 * provider on first overdue crossing (re-armed on observed rotation), print +
 * CSV + WP-CLI aicac key-age status|export (status non-zero on overdue or
 * unmanaged). Informational only — never denies, rotates or revokes. OFF by
 * default. Own two options. Key_Custody is optional (class_exists-guarded).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Key rotation age ledger + overdue nudges.
 */
final class Key_Age {

	public const SETTINGS_OPTION = 'handl_aicac_key_age';

	public const ALERTED_OPTION = 'handl_aicac_key_age_alerted';

	/** Key_Custody vault option (literal so hooks register without the class). */
	public const VAULT_OPTION = 'handl_aicac_key_custody_vault';

	public const PAGE_SLUG = 'handl-aicac-key-age';

	public const CUSTODY_PAGE_SLUG = 'handl-aicac-key-custody';

	public const FILTER_MAX_DAYS = 'handl_aicac_key_age_max_days';

	public const ALERT_KIND = 'key_age';

	public const DEFAULT_MAX_DAYS = 90;

	public const MIN_MAX_DAYS = 7;

	public const MAX_MAX_DAYS = 3650;

	/** Days before max during which a key is "due". */
	public const DUE_WINDOW_DAYS = 14;

	public const TIER_OK = 'ok';

	public const TIER_DUE = 'due';

	public const TIER_OVERDUE = 'overdue';

	public const TIER_UNMANAGED = 'unmanaged';

	public const SALT_SUFFIX = '|handl_aicac_key_age_v1';

	public const POST_PRESENT = 'handl_aicac_key_age_present';

	public const POST_ENABLED = 'handl_aicac_key_age_enabled';

	public const POST_MAX_DAYS = 'handl_aicac_key_age_max_days';

	public const POST_PROVIDER_PREFIX = 'handl_aicac_key_age_provider_';

	public const ACTION_SAVE = 'handl_aicac_key_age_save';

	public const FRAMING = 'informational_never_blocks';

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		// Observers always registered; each bails when the feature is off.
		foreach ( array_keys( self::inject_map() ) as $option ) {
			add_action( 'update_option_' . $option, array( self::class, 'observe_plugin_option' ), 10, 3 );
			add_action( 'add_option_' . $option, array( self::class, 'observe_plugin_option_added' ), 10, 2 );
		}
		add_action( 'update_option_' . self::VAULT_OPTION, array( self::class, 'observe_vault' ), 10, 3 );
		add_action( 'add_option_' . self::VAULT_OPTION, array( self::class, 'observe_vault_added' ), 10, 2 );

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_print' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );

		if ( self::is_enabled() ) {
			add_action( 'init', array( self::class, 'maybe_fire_alerts' ), 30 );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$test_mails = array();
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::ALERTED_OPTION );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	/**
	 * Local copy of the top-3 option → provider map (Key_Custody may be absent).
	 *
	 * @return array<string,string>
	 */
	public static function inject_map(): array {
		return array(
			'openai_api_key'    => 'openai',
			'anthropic_api_key' => 'anthropic',
			'google_ai_api_key' => 'google',
		);
	}

	/**
	 * @return list<string>
	 */
	public static function providers(): array {
		return array_values( array_unique( array_values( self::inject_map() ) ) );
	}

	public static function sanitize_provider( string $provider ): string {
		$provider = strtolower( trim( $provider ) );

		return in_array( $provider, self::providers(), true ) ? $provider : '';
	}

	public static function provider_label( string $provider ): string {
		if ( class_exists( Keyscan::class, false ) && method_exists( Keyscan::class, 'provider_label' ) ) {
			return (string) Keyscan::provider_label( $provider );
		}
		$map = array(
			'openai'    => 'OpenAI',
			'anthropic' => 'Anthropic',
			'google'    => 'Google AI',
			'azure'     => 'Azure OpenAI',
		);

		return $map[ $provider ] ?? $provider;
	}

	private static function now(): int {
		return class_exists( Clock::class, false ) ? Clock::now() : time();
	}

	private static function day(): int {
		return defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
	}

	/**
	 * @return array{enabled:bool,max_age_days:int,provider_max_days:array<string,int>,ledger:array<string,array<string,mixed>>}
	 */
	public static function defaults(): array {
		return array(
			'enabled'           => false,
			'max_age_days'      => self::DEFAULT_MAX_DAYS,
			'provider_max_days' => array(),
			'ledger'            => array(),
		);
	}

	/**
	 * @return array{enabled:bool,max_age_days:int,provider_max_days:array<string,int>,ledger:array<string,array<string,mixed>>}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * Always returns enabled, max_age_days, provider_max_days, ledger.
	 *
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,max_age_days:int,provider_max_days:array<string,int>,ledger:array<string,array<string,mixed>>}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		$per = array();
		$src = isset( $raw['provider_max_days'] ) && is_array( $raw['provider_max_days'] ) ? $raw['provider_max_days'] : array();
		foreach ( self::providers() as $provider ) {
			if ( ! isset( $src[ $provider ] ) || ! is_numeric( $src[ $provider ] ) || (int) $src[ $provider ] <= 0 ) {
				continue;
			}
			$per[ $provider ] = self::sanitize_max_days( $src[ $provider ] );
		}

		return array(
			'enabled'           => ! empty( $raw['enabled'] ),
			'max_age_days'      => self::sanitize_max_days( $raw['max_age_days'] ?? $defaults['max_age_days'] ),
			'provider_max_days' => $per,
			'ledger'            => self::sanitize_ledger( $raw['ledger'] ?? array() ),
		);
	}

	/**
	 * @param mixed $raw Raw days.
	 */
	public static function sanitize_max_days( $raw ): int {
		if ( ! is_numeric( $raw ) ) {
			return self::DEFAULT_MAX_DAYS;
		}
		$v = (int) $raw;
		if ( $v < self::MIN_MAX_DAYS ) {
			$v = self::MIN_MAX_DAYS;
		}
		if ( $v > self::MAX_MAX_DAYS ) {
			$v = self::MAX_MAX_DAYS;
		}

		return $v;
	}

	public static function sanitize_fingerprint( string $raw ): string {
		$raw = strtolower( trim( $raw ) );

		return 1 === preg_match( '/^[a-f0-9]{64}$/', $raw ) ? $raw : '';
	}

	private static function sanitize_token( string $raw, int $max ): string {
		$raw = strtolower( trim( $raw ) );
		$raw = preg_replace( '/[^a-z0-9_.\-]/', '', $raw ) ?? '';

		return substr( $raw, 0, $max );
	}

	/**
	 * @param mixed $raw Raw entry.
	 * @return array{fp:string,rotated_at:int,source:string,slot:string}|null
	 */
	public static function sanitize_ledger_entry( $raw ): ?array {
		if ( ! is_array( $raw ) ) {
			return null;
		}
		$fp = self::sanitize_fingerprint( (string) ( $raw['fp'] ?? '' ) );
		$ts = isset( $raw['rotated_at'] ) ? (int) $raw['rotated_at'] : 0;
		if ( '' === $fp || $ts <= 0 ) {
			return null;
		}
		$source = self::sanitize_token( (string) ( $raw['source'] ?? '' ), 24 );
		$slot   = self::sanitize_token( (string) ( $raw['slot'] ?? '' ), 48 );

		return array(
			'fp'         => $fp,
			'rotated_at' => $ts,
			'source'     => '' !== $source ? $source : 'option',
			'slot'       => $slot,
		);
	}

	/**
	 * @param mixed $raw Raw ledger.
	 * @return array<string,array{fp:string,rotated_at:int,source:string,slot:string}>
	 */
	public static function sanitize_ledger( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( self::providers() as $provider ) {
			if ( ! isset( $raw[ $provider ] ) ) {
				continue;
			}
			$entry = self::sanitize_ledger_entry( $raw[ $provider ] );
			if ( null !== $entry ) {
				$out[ $provider ] = $entry;
			}
		}

		return $out;
	}

	/**
	 * Persist settings. When $settings omits 'ledger' the existing ledger is kept.
	 *
	 * @param array<string,mixed> $settings Settings.
	 */
	public static function save_settings( array $settings ): bool {
		$before = self::get_settings();
		if ( ! array_key_exists( 'ledger', $settings ) ) {
			$settings['ledger'] = $before['ledger'];
		}
		$clean = self::sanitize_settings( $settings );
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
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] );
	}

	/**
	 * Effective max age (days) for a provider: per-provider override, then
	 * global setting, then filter.
	 */
	public static function max_age_days( string $provider = '' ): int {
		$settings = self::get_settings();
		$base     = (int) $settings['max_age_days'];
		$provider = self::sanitize_provider( $provider );
		if ( '' !== $provider && ! empty( $settings['provider_max_days'][ $provider ] ) ) {
			$base = (int) $settings['provider_max_days'][ $provider ];
		}
		if ( function_exists( 'apply_filters' ) ) {
			return self::sanitize_max_days( apply_filters( self::FILTER_MAX_DAYS, $base, $provider ) );
		}

		return $base;
	}

	/* ---------------------------------------------------------------------
	 * Fingerprints
	 * ------------------------------------------------------------------ */

	private static function hmac( string $material ): string {
		$salt = function_exists( 'wp_salt' ) ? (string) wp_salt( 'auth' ) : 'handl-aicac';

		return hash_hmac( 'sha256', $material, $salt . self::SALT_SUFFIX );
	}

	/**
	 * Salted HMAC of a plaintext key. Empty input → ''.
	 *
	 * @param mixed $plain Plaintext key.
	 */
	public static function fingerprint_plaintext( $plain ): string {
		if ( ! is_string( $plain ) ) {
			return '';
		}
		$plain = trim( $plain );
		if ( '' === $plain ) {
			return '';
		}

		return self::hmac( $plain );
	}

	/**
	 * Salted HMAC of a vault row's n|c. Revoked / empty rows → ''.
	 *
	 * @param mixed $row Vault row.
	 */
	public static function fingerprint_vault_row( $row ): string {
		if ( ! is_array( $row ) || ! empty( $row['revoked'] ) ) {
			return '';
		}
		$n = isset( $row['n'] ) ? (string) $row['n'] : '';
		$c = isset( $row['c'] ) ? (string) $row['c'] : '';
		if ( '' === $n || '' === $c ) {
			return '';
		}

		return self::hmac( $n . '|' . $c );
	}

	/* ---------------------------------------------------------------------
	 * Ledger
	 * ------------------------------------------------------------------ */

	/**
	 * @return array<string,array{fp:string,rotated_at:int,source:string,slot:string}>
	 */
	public static function get_ledger(): array {
		return self::get_settings()['ledger'];
	}

	/**
	 * Write one provider ledger entry (own option only). No-op when identical.
	 *
	 * @param array<string,mixed> $entry fp, rotated_at, source, slot.
	 */
	public static function put_ledger_entry( string $provider, array $entry ): bool {
		$provider = self::sanitize_provider( $provider );
		$clean    = self::sanitize_ledger_entry( $entry );
		if ( '' === $provider || null === $clean ) {
			return false;
		}
		$settings                      = self::get_settings();
		$settings['ledger'][ $provider ] = $clean;

		return self::save_settings( $settings );
	}

	/**
	 * Record an observed fingerprint. Rotation (fp change) re-arms the alert.
	 *
	 * @return bool True when the ledger changed.
	 */
	private static function record( string $provider, string $fp, string $source, string $slot, int $at ): bool {
		$provider = self::sanitize_provider( $provider );
		$fp       = self::sanitize_fingerprint( $fp );
		if ( '' === $provider || '' === $fp ) {
			return false;
		}
		$ledger = self::get_ledger();
		if ( isset( $ledger[ $provider ] ) && $ledger[ $provider ]['fp'] === $fp ) {
			return false;
		}
		$changed = self::put_ledger_entry(
			$provider,
			array(
				'fp'         => $fp,
				'rotated_at' => $at > 0 ? $at : self::now(),
				'source'     => $source,
				'slot'       => $slot,
			)
		);
		if ( $changed ) {
			$alerted = self::get_alerted();
			if ( isset( $alerted[ $provider ] ) ) {
				unset( $alerted[ $provider ] );
				self::put_alerted( $alerted );
			}
		}

		return $changed;
	}

	/**
	 * Hook: update_option_{openai_api_key|anthropic_api_key|google_ai_api_key}.
	 *
	 * @param mixed  $old_value Old value (unused).
	 * @param mixed  $value     New value.
	 * @param string $option    Option name.
	 */
	public static function observe_plugin_option( $old_value, $value, $option = '' ): void {
		unset( $old_value );
		if ( ! self::is_enabled() ) {
			return;
		}
		$map    = self::inject_map();
		$option = (string) $option;
		if ( ! isset( $map[ $option ] ) ) {
			return;
		}
		$fp = self::fingerprint_plaintext( $value );
		if ( '' === $fp ) {
			return;
		}
		self::record( $map[ $option ], $fp, 'option', $option, self::now() );
	}

	/**
	 * Hook: add_option_{...}.
	 *
	 * @param string $option Option name.
	 * @param mixed  $value  Value.
	 */
	public static function observe_plugin_option_added( $option, $value ): void {
		self::observe_plugin_option( null, $value, (string) $option );
	}

	/**
	 * Hook: update_option_handl_aicac_key_custody_vault.
	 *
	 * @param mixed  $old_value Old value (unused).
	 * @param mixed  $value     New vault option value.
	 * @param string $option    Option name (unused).
	 */
	public static function observe_vault( $old_value, $value, $option = '' ): void {
		unset( $old_value, $option );
		if ( ! self::is_enabled() ) {
			return;
		}
		foreach ( self::parse_vault( $value ) as $provider => $row ) {
			$fp = self::fingerprint_vault_row( $row );
			if ( '' === $fp ) {
				continue;
			}
			$at = (int) ( $row['updated_at'] ?? 0 );
			self::record( $provider, $fp, 'vault', 'vault', $at );
		}
	}

	/**
	 * Hook: add_option_handl_aicac_key_custody_vault.
	 *
	 * @param string $option Option name.
	 * @param mixed  $value  Value.
	 */
	public static function observe_vault_added( $option, $value ): void {
		self::observe_vault( null, $value, (string) $option );
	}

	/* ---------------------------------------------------------------------
	 * Custody vault (read-only; Key_Custody optional)
	 * ------------------------------------------------------------------ */

	/**
	 * @param mixed $raw Vault option value or Key_Custody::get_vault() map.
	 * @return array<string,array{revoked:bool,updated_at:int,n:string,c:string}>
	 */
	private static function parse_vault( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$keys = isset( $raw['keys'] ) && is_array( $raw['keys'] ) ? $raw['keys'] : $raw;
		$out  = array();
		foreach ( self::providers() as $provider ) {
			if ( ! isset( $keys[ $provider ] ) || ! is_array( $keys[ $provider ] ) ) {
				continue;
			}
			$row              = $keys[ $provider ];
			$out[ $provider ] = array(
				'revoked'    => ! empty( $row['revoked'] ),
				'updated_at' => isset( $row['updated_at'] ) ? (int) $row['updated_at'] : 0,
				'n'          => isset( $row['n'] ) ? (string) $row['n'] : '',
				'c'          => isset( $row['c'] ) ? (string) $row['c'] : '',
			);
		}

		return $out;
	}

	/**
	 * @return array<string,array{revoked:bool,updated_at:int,n:string,c:string}>
	 */
	public static function read_vault(): array {
		if ( class_exists( 'HandL\\AICAC\\Key_Custody', false ) && method_exists( 'HandL\\AICAC\\Key_Custody', 'get_vault' ) ) {
			return self::parse_vault( call_user_func( array( 'HandL\\AICAC\\Key_Custody', 'get_vault' ) ) );
		}

		return self::parse_vault( get_option( self::VAULT_OPTION, array() ) );
	}

	public static function has_custody_entry( string $provider ): bool {
		$provider = self::sanitize_provider( $provider );
		if ( '' === $provider ) {
			return false;
		}
		if ( class_exists( 'HandL\\AICAC\\Key_Custody', false ) && method_exists( 'HandL\\AICAC\\Key_Custody', 'has_vault_entry' )
			&& call_user_func( array( 'HandL\\AICAC\\Key_Custody', 'has_vault_entry' ), $provider ) ) {
			return true;
		}
		$vault = self::read_vault();

		return isset( $vault[ $provider ] ) && '' !== self::fingerprint_vault_row( $vault[ $provider ] );
	}

	/**
	 * Seed ledger entries for custody keys not yet observed (own option only).
	 *
	 * @return list<string> Providers seeded.
	 */
	public static function seed_from_vault( ?int $now = null ): array {
		if ( ! self::is_enabled() ) {
			return array();
		}
		$now    = null !== $now && $now > 0 ? $now : self::now();
		$ledger = self::get_ledger();
		$seeded = array();
		foreach ( self::read_vault() as $provider => $row ) {
			if ( isset( $ledger[ $provider ] ) ) {
				continue;
			}
			$fp = self::fingerprint_vault_row( $row );
			if ( '' === $fp ) {
				continue;
			}
			$at = (int) $row['updated_at'];
			if ( self::put_ledger_entry(
				$provider,
				array(
					'fp'         => $fp,
					'rotated_at' => $at > 0 ? $at : $now,
					'source'     => 'vault_seed',
					'slot'       => 'vault',
				)
			) ) {
				$seeded[] = $provider;
			}
		}

		return $seeded;
	}

	/* ---------------------------------------------------------------------
	 * Tiers + roster
	 * ------------------------------------------------------------------ */

	/**
	 * Whole days since a ledger entry's rotated_at.
	 *
	 * @param array<string,mixed> $entry Ledger entry.
	 */
	public static function age_days( array $entry, ?int $now = null ): int {
		$now = null !== $now && $now > 0 ? $now : self::now();
		$at  = (int) ( $entry['rotated_at'] ?? 0 );
		if ( $at <= 0 ) {
			return 0;
		}

		return max( 0, (int) floor( ( $now - $at ) / self::day() ) );
	}

	/**
	 * ok / due / overdue for an age against a max.
	 */
	public static function tier( int $age_days, int $max_days ): string {
		if ( $age_days >= $max_days ) {
			return self::TIER_OVERDUE;
		}
		if ( $age_days >= $max_days - self::DUE_WINDOW_DAYS ) {
			return self::TIER_DUE;
		}

		return self::TIER_OK;
	}

	/**
	 * Providers Keyscan sees in active plugins that have no custody entry.
	 *
	 * @return array<string,list<string>> provider => plugin basenames.
	 */
	private static function unmanaged_providers(): array {
		if ( ! class_exists( Keyscan::class, false ) || ! method_exists( Keyscan::class, 'active_findings' ) ) {
			return array();
		}
		$out = array();
		foreach ( (array) Keyscan::active_findings() as $finding ) {
			if ( ! is_array( $finding ) ) {
				continue;
			}
			$provider = self::sanitize_token( (string) ( $finding['provider'] ?? '' ), 32 );
			if ( '' === $provider || self::has_custody_entry( $provider ) ) {
				continue;
			}
			$plugin = isset( $finding['plugin'] ) ? (string) $finding['plugin'] : '';
			if ( ! isset( $out[ $provider ] ) ) {
				$out[ $provider ] = array();
			}
			if ( '' !== $plugin && ! in_array( $plugin, $out[ $provider ], true ) ) {
				$out[ $provider ][] = $plugin;
			}
		}
		ksort( $out );

		return $out;
	}

	/**
	 * @return array{enabled:bool,rows:list<array<string,mixed>>,overdue:int,due:int,unmanaged:int,framing:string}
	 */
	public static function snapshot( ?int $now = null ): array {
		$empty = array(
			'enabled'   => false,
			'rows'      => array(),
			'overdue'   => 0,
			'due'       => 0,
			'unmanaged' => 0,
			'framing'   => self::FRAMING,
		);
		if ( ! self::is_enabled() ) {
			return $empty;
		}
		$now = null !== $now && $now > 0 ? $now : self::now();
		self::seed_from_vault( $now );

		$rows      = array();
		$overdue   = 0;
		$due       = 0;
		$unmanaged = 0;
		$link      = self::custody_url();

		foreach ( self::get_ledger() as $provider => $entry ) {
			$max  = self::max_age_days( $provider );
			$age  = self::age_days( $entry, $now );
			$tier = self::tier( $age, $max );
			if ( self::TIER_OVERDUE === $tier ) {
				++$overdue;
			} elseif ( self::TIER_DUE === $tier ) {
				++$due;
			}
			$rows[] = array(
				'provider'       => $provider,
				'label'          => self::provider_label( $provider ),
				'managed'        => true,
				'tier'           => $tier,
				'age_days'       => $age,
				'max_days'       => $max,
				'days_remaining' => $max - $age,
				'rotated_at'     => (int) $entry['rotated_at'],
				'source'         => (string) $entry['source'],
				'slot'           => (string) $entry['slot'],
				'plugins'        => array(),
				'custody'        => self::has_custody_entry( $provider ),
				'deep_link'      => $link,
				'framing'        => self::FRAMING,
			);
		}

		foreach ( self::unmanaged_providers() as $provider => $plugins ) {
			++$unmanaged;
			$rows[] = array(
				'provider'       => $provider,
				'label'          => self::provider_label( $provider ),
				'managed'        => false,
				'tier'           => self::TIER_UNMANAGED,
				'age_days'       => 0,
				'max_days'       => self::max_age_days( $provider ),
				'days_remaining' => 0,
				'rotated_at'     => 0,
				'source'         => 'keyscan',
				'slot'           => '',
				'plugins'        => $plugins,
				'custody'        => false,
				'deep_link'      => $link,
				'framing'        => self::FRAMING,
			);
		}

		return array(
			'enabled'   => true,
			'rows'      => $rows,
			'overdue'   => $overdue,
			'due'       => $due,
			'unmanaged' => $unmanaged,
			'framing'   => self::FRAMING,
		);
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function roster( ?int $now = null ): array {
		return self::snapshot( $now )['rows'];
	}

	public static function has_overdue_or_unmanaged( ?int $now = null ): bool {
		$snap = self::snapshot( $now );

		return $snap['overdue'] > 0 || $snap['unmanaged'] > 0;
	}

	/* ---------------------------------------------------------------------
	 * Alerts
	 * ------------------------------------------------------------------ */

	/**
	 * @return array<string,bool>
	 */
	public static function get_alerted(): array {
		$raw = get_option( self::ALERTED_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $provider => $flag ) {
			$provider = self::sanitize_provider( (string) $provider );
			if ( '' === $provider || empty( $flag ) ) {
				continue;
			}
			$out[ $provider ] = true;
		}

		return $out;
	}

	/**
	 * @param array<string,bool> $alerted Providers alerted.
	 */
	public static function put_alerted( array $alerted ): void {
		$clean = array();
		foreach ( $alerted as $provider => $flag ) {
			$provider = self::sanitize_provider( (string) $provider );
			if ( '' === $provider || empty( $flag ) ) {
				continue;
			}
			$clean[ $provider ] = true;
		}
		if ( empty( $clean ) ) {
			delete_option( self::ALERTED_OPTION );

			return;
		}
		update_option( self::ALERTED_OPTION, $clean, false );
	}

	/**
	 * One alert per provider on first overdue crossing; re-armed by rotation.
	 *
	 * @return list<string> Providers newly alerted.
	 */
	public static function maybe_fire_alerts( ?int $now = null ): array {
		if ( ! self::is_enabled() ) {
			return array();
		}
		$now     = null !== $now && $now > 0 ? $now : self::now();
		$snap    = self::snapshot( $now );
		$alerted = self::get_alerted();
		$fired   = array();

		foreach ( $snap['rows'] as $row ) {
			if ( self::TIER_OVERDUE !== (string) ( $row['tier'] ?? '' ) ) {
				continue;
			}
			$provider = (string) $row['provider'];
			if ( isset( $alerted[ $provider ] ) ) {
				continue;
			}
			if ( ! self::fire_alert( $row, $now ) ) {
				continue;
			}
			$alerted[ $provider ] = true;
			$fired[]              = $provider;
		}
		if ( ! empty( $fired ) ) {
			self::put_alerted( $alerted );
		}

		return $fired;
	}

	/**
	 * @param array<string,mixed> $payload Roster row.
	 */
	private static function fire_alert( array $payload, int $now ): bool {
		$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}
		$email = '';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		}
		if ( '' === $email ) {
			return false;
		}

		$subject = self::build_subject( $payload );
		$body    = self::build_body( $payload );
		$ok      = false;
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'safe_wp_mail' ) ) {
			$ok = (bool) Alerts::safe_wp_mail( $email, $subject, $body );
		} elseif ( function_exists( 'wp_mail' ) ) {
			$ok = (bool) wp_mail( $email, $subject, $body );
		}
		self::$test_mails[] = array(
			'to'       => $email,
			'subject'  => $subject,
			'body'     => $body,
			'provider' => (string) ( $payload['provider'] ?? '' ),
		);

		if ( $ok && class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'     => 'handl_aicac_key_age',
						'provider' => (string) ( $payload['provider'] ?? '' ),
						'age_days' => (int) ( $payload['age_days'] ?? 0 ),
						'max_days' => (int) ( $payload['max_days'] ?? 0 ),
						'site'     => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'       => $now,
					)
				);
			}
		}

		return $ok;
	}

	/**
	 * @param array<string,mixed> $payload Roster row.
	 */
	public static function build_subject( array $payload ): string {
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';

		return sprintf(
			/* translators: 1: site name, 2: provider label, 3: key age in days */
			__( '[%1$s] [KEY-AGE] %2$s API key rotation overdue (%3$d days old)', 'handl-ai-connector-access-control' ),
			$site,
			(string) ( $payload['label'] ?? $payload['provider'] ?? '' ),
			(int) ( $payload['age_days'] ?? 0 )
		);
	}

	/**
	 * @param array<string,mixed> $payload Roster row.
	 */
	public static function build_body( array $payload ): string {
		$lines   = array();
		$lines[] = __( 'An AI provider API key has not been observed rotating within your key-age limit. Rotate it at the provider, then update it here (or in Key Custody). This alert never blocks, revokes, or rotates anything.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: provider label */
			__( 'Provider: %s', 'handl-ai-connector-access-control' ),
			(string) ( $payload['label'] ?? $payload['provider'] ?? '' )
		);
		$lines[] = sprintf(
			/* translators: 1: age in days, 2: max age in days */
			__( 'Key age: %1$d days (limit %2$d days)', 'handl-ai-connector-access-control' ),
			(int) ( $payload['age_days'] ?? 0 ),
			(int) ( $payload['max_days'] ?? self::DEFAULT_MAX_DAYS )
		);
		if ( ! empty( $payload['rotated_at'] ) ) {
			$lines[] = sprintf(
				/* translators: %s: UTC date */
				__( 'Last observed rotation: %s (UTC)', 'handl-ai-connector-access-control' ),
				gmdate( 'Y-m-d', (int) $payload['rotated_at'] )
			);
		}
		$lines[] = '';
		$lines[] = __( 'Age is measured from the last rotation this plugin observed (a salted fingerprint changed) — never from key contents. No key material is stored or sent.', 'handl-ai-connector-access-control' );
		$url     = (string) ( $payload['deep_link'] ?? '' );
		if ( '' === $url ) {
			$url = self::admin_url();
		}
		if ( '' !== $url ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Review key age: %s', 'handl-ai-connector-access-control' ),
				$url
			);
		}

		return implode( "\n", $lines );
	}

	/* ---------------------------------------------------------------------
	 * URLs
	 * ------------------------------------------------------------------ */

	public static function admin_url(): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg( 'page', self::PAGE_SLUG, admin_url( 'admin.php' ) );
	}

	/**
	 * Key Custody admin page, or '' when Key_Custody is not loaded.
	 */
	public static function custody_url(): string {
		if ( ! class_exists( 'HandL\\AICAC\\Key_Custody', false ) || ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg( 'page', self::CUSTODY_PAGE_SLUG, admin_url( 'admin.php' ) );
	}

	/* ---------------------------------------------------------------------
	 * CSV + print
	 * ------------------------------------------------------------------ */

	/**
	 * @param list<array<string,mixed>>|null $rows Optional roster.
	 */
	public static function csv_for_roster( ?array $rows = null ): string {
		if ( null === $rows ) {
			$rows = self::roster();
		}
		$lines   = array();
		$lines[] = self::csv_line(
			array(
				'provider',
				'tier',
				'age_days',
				'max_days',
				'days_remaining',
				'rotated_at',
				'source',
				'slot',
				'custody',
				'plugins',
				'deep_link',
				'framing',
			)
		);
		foreach ( $rows as $row ) {
			$plugins = is_array( $row['plugins'] ?? null ) ? implode( ';', array_map( 'strval', (array) $row['plugins'] ) ) : '';
			$rotated = (int) ( $row['rotated_at'] ?? 0 );
			$lines[] = self::csv_line(
				array(
					(string) ( $row['provider'] ?? '' ),
					(string) ( $row['tier'] ?? '' ),
					(string) (int) ( $row['age_days'] ?? 0 ),
					(string) (int) ( $row['max_days'] ?? 0 ),
					(string) (int) ( $row['days_remaining'] ?? 0 ),
					$rotated > 0 ? gmdate( 'Y-m-d', $rotated ) : '',
					(string) ( $row['source'] ?? '' ),
					(string) ( $row['slot'] ?? '' ),
					! empty( $row['custody'] ) ? 'yes' : 'no',
					$plugins,
					(string) ( $row['deep_link'] ?? '' ),
					self::FRAMING,
				)
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param list<string> $cols Columns.
	 */
	public static function csv_line( array $cols ): string {
		$out = array();
		foreach ( $cols as $col ) {
			$col   = (string) $col;
			$needs = str_contains( $col, ',' ) || str_contains( $col, '"' ) || str_contains( $col, "\n" );
			$col   = str_replace( '"', '""', $col );
			$out[] = $needs ? '"' . $col . '"' : $col;
		}

		return implode( ',', $out );
	}

	/**
	 * @param list<array<string,mixed>> $rows Roster.
	 */
	public static function build_print_html( array $rows ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
		$html .= esc_html__( 'AI key age', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%;margin-bottom:24px}th,td{border:1px solid #ccc;padding:6px 8px;text-align:left}th{background:#f6f7f7}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'AI key age', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Key rotation hygiene from observed rotations only. No key material is stored. Informational — never blocks, rotates, or revokes.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Status', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Age (days)', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Limit (days)', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Last rotation', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Source', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Custody', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$rotated = (int) ( $row['rotated_at'] ?? 0 );
			$html   .= '<tr>';
			$html   .= '<td>' . esc_html( (string) ( $row['label'] ?? $row['provider'] ?? '' ) ) . '</td>';
			$html   .= '<td>' . esc_html( (string) ( $row['tier'] ?? '' ) ) . '</td>';
			$html   .= '<td>' . esc_html( (string) (int) ( $row['age_days'] ?? 0 ) ) . '</td>';
			$html   .= '<td>' . esc_html( (string) (int) ( $row['max_days'] ?? 0 ) ) . '</td>';
			$html   .= '<td>' . esc_html( $rotated > 0 ? gmdate( 'Y-m-d', $rotated ) : '—' ) . '</td>';
			$html   .= '<td>' . esc_html( (string) ( $row['source'] ?? '' ) ) . '</td>';
			$html   .= '<td>' . esc_html( ! empty( $row['custody'] ) ? 'yes' : 'no' ) . '</td>';
			$html   .= '</tr>';
		}
		$html .= '</tbody></table></body></html>';

		return $html;
	}

	/* ---------------------------------------------------------------------
	 * Admin UI
	 * ------------------------------------------------------------------ */

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'AI key age', 'handl-ai-connector-access-control' ),
			__( 'Key age', 'handl-ai-connector-access-control' ),
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
		$enabled    = self::is_enabled();
		$rows       = $enabled ? self::roster() : array();
		$csv        = add_query_arg(
			array(
				'page'                   => self::PAGE_SLUG,
				'handl_aicac_key_age_csv' => '1',
				'_wpnonce'               => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_key_age_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print      = add_query_arg(
			array(
				'page'                     => self::PAGE_SLUG,
				'handl_aicac_key_age_print' => '1',
				'_wpnonce'                 => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_key_age_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'AI key age', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Key rotation hygiene. Age is measured from the last rotation this plugin observed — a salted fingerprint of the key changing, never the key itself. Informational; off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable key-age tracking', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Track observed key rotations and alert once when a key is overdue', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-key-age-max">' . esc_html__( 'Maximum key age (days)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="' . esc_attr( self::POST_MAX_DAYS ) . '" id="handl-aicac-key-age-max" type="number" min="' . esc_attr( (string) self::MIN_MAX_DAYS ) . '" max="' . esc_attr( (string) self::MAX_MAX_DAYS ) . '" step="1" value="' . esc_attr( (string) (int) $settings['max_age_days'] ) . '" class="small-text" />';
			echo '<p class="description">' . esc_html__( 'Default 90. Keys become "due" during the last 14 days before this limit and "overdue" at the limit.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr>';
			foreach ( self::providers() as $provider ) {
				$value = isset( $settings['provider_max_days'][ $provider ] ) ? (string) (int) $settings['provider_max_days'][ $provider ] : '';
				echo '<tr><th scope="row"><label for="handl-aicac-key-age-' . esc_attr( $provider ) . '">';
				echo esc_html(
					sprintf(
						/* translators: %s: provider label */
						__( '%s override (days)', 'handl-ai-connector-access-control' ),
						self::provider_label( $provider )
					)
				);
				echo '</label></th><td>';
				echo '<input name="' . esc_attr( self::POST_PROVIDER_PREFIX . $provider ) . '" id="handl-aicac-key-age-' . esc_attr( $provider ) . '" type="number" min="' . esc_attr( (string) self::MIN_MAX_DAYS ) . '" max="' . esc_attr( (string) self::MAX_MAX_DAYS ) . '" step="1" value="' . esc_attr( $value ) . '" class="small-text" />';
				echo '<span class="description"> ' . esc_html__( 'Leave blank to use the maximum above.', 'handl-ai-connector-access-control' ) . '</span>';
				echo '</td></tr>';
			}
			echo '</tbody></table>';
			submit_button( __( 'Save key-age settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Key-age tracking is off. Enable it to start recording observed key rotations.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Informational — never blocks, rotates, or revokes.', 'handl-ai-connector-access-control' ) . '</strong> ';
		echo esc_html__( 'A key first seen after you enable tracking starts its age clock at first sight. Keys Keyscan finds in plugins without a custody entry are listed as unmanaged.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Key roster', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $rows ) ) {
			echo '<p>' . esc_html__( 'No provider key rotations observed yet. Rotations are recorded when a provider key is saved or stored in custody.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Status', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Age (days)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Limit (days)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Last rotation', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Source', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Custody', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $rows as $row ) {
				$rotated = (int) $row['rotated_at'];
				$link    = (string) ( $row['deep_link'] ?? '' );
				echo '<tr>';
				echo '<td>' . esc_html( (string) $row['label'] ) . '</td>';
				echo '<td>' . esc_html( (string) $row['tier'] ) . '</td>';
				echo '<td>' . esc_html( empty( $row['managed'] ) ? '—' : (string) (int) $row['age_days'] ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $row['max_days'] ) . '</td>';
				echo '<td>' . esc_html( $rotated > 0 ? gmdate( 'Y-m-d', $rotated ) : '—' ) . '</td>';
				echo '<td>' . esc_html( empty( $row['plugins'] ) ? (string) $row['source'] : (string) $row['source'] . ': ' . implode( ', ', array_map( 'strval', (array) $row['plugins'] ) ) ) . '</td>';
				if ( '' !== $link ) {
					echo '<td><a href="' . esc_url( $link ) . '">' . esc_html__( 'Open Key Custody', 'handl-ai-connector-access-control' ) . '</a></td>';
				} else {
					echo '<td>—</td>';
				}
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '</div>';
	}

	public static function maybe_handle_csv(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_key_age_csv'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_key_age_csv' );
		$csv = self::csv_for_roster();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename=handl-aicac-key-age.csv' );
		}
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_key_age_print'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_key_age_print' );
		$rows = self::roster();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=utf-8' );
		}
		echo self::build_print_html( $rows ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside builder.
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save key-age settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$max_raw = isset( $_POST[ self::POST_MAX_DAYS ] ) ? wp_unslash( (string) $_POST[ self::POST_MAX_DAYS ] ) : '';
		$per     = array();
		foreach ( self::providers() as $provider ) {
			$field = self::POST_PROVIDER_PREFIX . $provider;
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$raw = isset( $_POST[ $field ] ) ? trim( wp_unslash( (string) $_POST[ $field ] ) ) : '';
			if ( '' !== $raw ) {
				$per[ $provider ] = $raw;
			}
		}
		// Ledger intentionally omitted: save_settings() preserves it.
		self::save_settings(
			array(
				'enabled'           => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'max_age_days'      => self::sanitize_max_days( '' !== $max_raw ? $max_raw : self::DEFAULT_MAX_DAYS ),
				'provider_max_days' => $per,
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

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'aicac key-age', CLI_Key_Age::class );
	}
}

/**
 * WP-CLI: wp aicac key-age status|export
 */
final class CLI_Key_Age {

	/**
	 * Show key-age status. Exits non-zero when any key is overdue or unmanaged.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table or json. Default table.
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args );
		if ( ! Key_Age::is_enabled() ) {
			\WP_CLI::log( 'enabled=no framing=' . Key_Age::FRAMING );
			\WP_CLI::log( 'Key-age tracking is disabled.' );
			return;
		}
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$snap   = Key_Age::snapshot();
		$bad    = $snap['overdue'] > 0 || $snap['unmanaged'] > 0;

		\WP_CLI::log(
			sprintf(
				'enabled=yes max_age_days=%d overdue=%d due=%d unmanaged=%d framing=%s',
				Key_Age::max_age_days(),
				$snap['overdue'],
				$snap['due'],
				$snap['unmanaged'],
				Key_Age::FRAMING
			)
		);

		$rows = $snap['rows'];
		if ( empty( $rows ) ) {
			\WP_CLI::log( 'No key-age rows.' );
			return;
		}

		$display = array();
		foreach ( $rows as $row ) {
			$display[] = array(
				'provider'   => (string) $row['provider'],
				'tier'       => (string) $row['tier'],
				'age_days'   => (int) $row['age_days'],
				'max_days'   => (int) $row['max_days'],
				'rotated_at' => (int) $row['rotated_at'] > 0 ? gmdate( 'Y-m-d', (int) $row['rotated_at'] ) : '',
				'source'     => (string) $row['source'],
				'custody'    => ! empty( $row['custody'] ) ? 'yes' : 'no',
			);
		}
		if ( 'json' === $format ) {
			\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
		} elseif ( class_exists( '\WP_CLI\Utils' ) ) {
			\WP_CLI\Utils\format_items(
				'table',
				$display,
				array( 'provider', 'tier', 'age_days', 'max_days', 'rotated_at', 'source', 'custody' )
			);
		} else {
			foreach ( $display as $row ) {
				\WP_CLI::log( implode( "\t", $row ) );
			}
		}

		if ( $bad ) {
			\WP_CLI::error( 'Key-age: overdue or unmanaged provider key(s) found.', false );
			if ( method_exists( '\WP_CLI', 'halt' ) ) {
				\WP_CLI::halt( 1 );
			}
		}
	}

	/**
	 * Export the key-age roster as CSV.
	 *
	 * ## OPTIONS
	 *
	 * [--porcelain]
	 * : Print CSV only.
	 *
	 * @when after_wp_load
	 *
	 * @param array<int,string>    $args       Positional.
	 * @param array<string,string> $assoc_args Flags.
	 */
	public function export( $args, $assoc_args ): void {
		unset( $args );
		$csv = Key_Age::csv_for_roster();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
