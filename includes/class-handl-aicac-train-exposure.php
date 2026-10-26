<?php
/**
 * AICAC-TRAIN-EXPOSURE (#389): who trains on our words.
 *
 * Bundled provider data-use table (trains-by-default / opt-out mechanism /
 * zero-retention tier) + handl_aicac_train_exposure_table filter + staleness
 * nudge. Cross-references providers in traffic from the activity log +
 * Provider_Map (class_exists-guarded, read-only). Per-provider dated opt-out
 * attestations in the class's own option (append-only history). Exposure
 * roster + print + CSV. One alert the first time a trains-by-default provider
 * appears in traffic. WP-CLI train-exposure status|export. Informational only
 * — never denies. OFF by default. No admin.php/policy.php/cost.php/logger/
 * register/rates-feed edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Record who was asked about training on site content — and who was not.
 */
final class Train_Exposure {

	public const SETTINGS_OPTION = 'handl_aicac_train_exposure';

	public const ATTESTATIONS_OPTION = 'handl_aicac_train_exposure_attestations';

	public const ALERTED_OPTION = 'handl_aicac_train_exposure_alerted';

	public const PAGE_SLUG = 'handl-aicac-train-exposure';

	public const FILTER_TABLE = 'handl_aicac_train_exposure_table';

	/** Absolute ship date of the bundled data-use table (Y-m-d). */
	public const BUNDLED_SHIPPED = '2026-10-01';

	/** Days after table age before the on-screen staleness nudge. */
	public const STALE_AFTER_DAYS = 120;

	/** Cap append-only attestation history entries per provider. */
	public const HISTORY_CAP = 20;

	public const ALERT_KIND = 'train_exposure';

	public const TRAINS_YES = 'yes';

	public const TRAINS_NO = 'no';

	public const TRAINS_UNKNOWN = 'unknown';

	public const POST_PRESENT = 'handl_aicac_train_exposure_present';

	public const POST_ENABLED = 'handl_aicac_train_exposure_enabled';

	public const POST_ATTEST = 'handl_aicac_train_exposure_attest';

	public const ACTION_SAVE = 'handl_aicac_train_exposure_save';

	public const ACTION_ATTEST = 'handl_aicac_train_exposure_attest_save';

	public const UNKNOWN_PLUGIN = '(unknown)';

	/** @var bool */
	private static $registered = false;

	/** @var list<array{to:string,subject:string,body:string}> */
	private static $test_mails = array();

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_print' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_ATTEST, array( self::class, 'handle_attest_save' ) );

		if ( self::is_enabled() ) {
			add_action( 'init', array( self::class, 'maybe_fire_alerts' ), 30 );
			if ( function_exists( 'is_admin' ) && is_admin() ) {
				add_action( 'admin_notices', array( self::class, 'maybe_staleness_notice' ) );
			}
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$test_mails = array();
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::ATTESTATIONS_OPTION );
		delete_option( self::ALERTED_OPTION );
	}

	/**
	 * @return list<array{to:string,subject:string,body:string}>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	/**
	 * @return array{enabled:bool}
	 */
	public static function defaults(): array {
		return array(
			'enabled' => false,
		);
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
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled' => ! empty( $raw['enabled'] ),
		);
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
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] );
	}

	/**
	 * Bundled provider data-use postures. Directional research-shaped defaults
	 * for API traffic — not legal advice. Override via {@see FILTER_TABLE}.
	 *
	 * @return array{
	 *   shipped:string,
	 *   providers:array<string,array{trains_by_default:string,opt_out:string,zero_retention:string}>
	 * }
	 */
	public static function bundled_table(): array {
		return array(
			'shipped'   => self::BUNDLED_SHIPPED,
			'providers' => array(
				'openai'     => array(
					'trains_by_default' => self::TRAINS_NO,
					'opt_out'           => 'API inputs not used for training by default; Zero Data Retention available',
					'zero_retention'    => self::TRAINS_YES,
				),
				'anthropic'  => array(
					'trains_by_default' => self::TRAINS_NO,
					'opt_out'           => 'API inputs not used for model training by default',
					'zero_retention'    => self::TRAINS_UNKNOWN,
				),
				'google'     => array(
					'trains_by_default' => self::TRAINS_UNKNOWN,
					'opt_out'           => 'Check Gemini / Vertex AI data-governance controls for the product in use',
					'zero_retention'    => self::TRAINS_UNKNOWN,
				),
				'cohere'     => array(
					'trains_by_default' => self::TRAINS_YES,
					'opt_out'           => 'Org-level privacy / opt-out controls — request and record reference',
					'zero_retention'    => self::TRAINS_UNKNOWN,
				),
				'mistral'    => array(
					'trains_by_default' => self::TRAINS_UNKNOWN,
					'opt_out'           => 'Confirm current Mistral API data-use terms for your plan',
					'zero_retention'    => self::TRAINS_UNKNOWN,
				),
				'groq'       => array(
					'trains_by_default' => self::TRAINS_UNKNOWN,
					'opt_out'           => 'Confirm current Groq API data-use terms for your plan',
					'zero_retention'    => self::TRAINS_UNKNOWN,
				),
				'together'   => array(
					'trains_by_default' => self::TRAINS_UNKNOWN,
					'opt_out'           => 'Confirm current Together AI data-use terms for your plan',
					'zero_retention'    => self::TRAINS_UNKNOWN,
				),
				'fireworks'  => array(
					'trains_by_default' => self::TRAINS_UNKNOWN,
					'opt_out'           => 'Confirm current Fireworks data-use terms for your plan',
					'zero_retention'    => self::TRAINS_UNKNOWN,
				),
				'perplexity' => array(
					'trains_by_default' => self::TRAINS_UNKNOWN,
					'opt_out'           => 'Confirm current Perplexity API data-use terms for your plan',
					'zero_retention'    => self::TRAINS_UNKNOWN,
				),
				'xai'        => array(
					'trains_by_default' => self::TRAINS_UNKNOWN,
					'opt_out'           => 'Confirm current xAI API data-use terms for your plan',
					'zero_retention'    => self::TRAINS_UNKNOWN,
				),
				'deepseek'   => array(
					'trains_by_default' => self::TRAINS_YES,
					'opt_out'           => 'Assume training risk until an opt-out / contract term is on file',
					'zero_retention'    => self::TRAINS_NO,
				),
				'openrouter' => array(
					'trains_by_default' => self::TRAINS_UNKNOWN,
					'opt_out'           => 'Passthrough — data-use follows the upstream model provider',
					'zero_retention'    => self::TRAINS_UNKNOWN,
				),
			),
		);
	}

	/**
	 * Effective table after filter + sanitize.
	 *
	 * @return array{
	 *   shipped:string,
	 *   providers:array<string,array{trains_by_default:string,opt_out:string,zero_retention:string}>
	 * }
	 */
	public static function table(): array {
		$bundled = self::bundled_table();
		$raw     = apply_filters( self::FILTER_TABLE, $bundled );

		return self::sanitize_table( $raw, $bundled );
	}

	/**
	 * @param mixed                                                         $raw      Filtered table.
	 * @param array{shipped:string,providers:array<string,array<string,string>>}|null $fallback Fallback.
	 * @return array{
	 *   shipped:string,
	 *   providers:array<string,array{trains_by_default:string,opt_out:string,zero_retention:string}>
	 * }
	 */
	public static function sanitize_table( $raw, ?array $fallback = null ): array {
		if ( null === $fallback ) {
			$fallback = self::bundled_table();
		}
		if ( ! is_array( $raw ) ) {
			return $fallback;
		}

		$shipped = isset( $raw['shipped'] ) ? self::sanitize_date( (string) $raw['shipped'] ) : '';
		if ( '' === $shipped ) {
			$shipped = self::sanitize_date( (string) ( $fallback['shipped'] ?? self::BUNDLED_SHIPPED ) );
		}
		if ( '' === $shipped ) {
			$shipped = self::BUNDLED_SHIPPED;
		}

		$providers_raw = isset( $raw['providers'] ) && is_array( $raw['providers'] )
			? $raw['providers']
			: ( isset( $fallback['providers'] ) && is_array( $fallback['providers'] ) ? $fallback['providers'] : array() );

		$providers = array();
		foreach ( $providers_raw as $id => $row ) {
			$provider = self::sanitize_provider( (string) $id );
			if ( '' === $provider || ! is_array( $row ) ) {
				continue;
			}
			$providers[ $provider ] = array(
				'trains_by_default' => self::sanitize_tri_state( (string) ( $row['trains_by_default'] ?? self::TRAINS_UNKNOWN ) ),
				'opt_out'           => self::sanitize_note( (string) ( $row['opt_out'] ?? '' ), 500 ),
				'zero_retention'    => self::sanitize_tri_state( (string) ( $row['zero_retention'] ?? self::TRAINS_UNKNOWN ) ),
			);
		}
		ksort( $providers );

		return array(
			'shipped'   => $shipped,
			'providers' => $providers,
		);
	}

	public static function sanitize_tri_state( string $raw ): string {
		$raw = sanitize_key( $raw );
		$allowed = array( self::TRAINS_YES, self::TRAINS_NO, self::TRAINS_UNKNOWN );

		return in_array( $raw, $allowed, true ) ? $raw : self::TRAINS_UNKNOWN;
	}

	public static function sanitize_provider( string $raw ): string {
		if ( class_exists( Cost::class, false ) ) {
			return Cost::normalize_provider_id( $raw );
		}
		$raw = strtolower( trim( $raw ) );

		return preg_replace( '/[^a-z0-9_-]/', '', $raw ) ?? '';
	}

	public static function sanitize_date( string $date ): string {
		$date = trim( $date );
		if ( '' === $date ) {
			return '';
		}
		if ( ! preg_match( '/^\d{4}-\d{2}-\d{2}$/', $date ) ) {
			return '';
		}
		$parts = explode( '-', $date );
		if ( 3 !== count( $parts ) ) {
			return '';
		}
		$y = (int) $parts[0];
		$m = (int) $parts[1];
		$d = (int) $parts[2];
		if ( $y < 1970 || $y > 2100 || ! checkdate( $m, $d, $y ) ) {
			return '';
		}

		return sprintf( '%04d-%02d-%02d', $y, $m, $d );
	}

	public static function sanitize_note( string $note, int $max = 2000 ): string {
		$note = trim( $note );
		if ( function_exists( 'sanitize_text_field' ) ) {
			$note = sanitize_text_field( $note );
		} else {
			$note = strip_tags( $note );
		}
		if ( strlen( $note ) > $max ) {
			$note = substr( $note, 0, $max );
		}

		return $note;
	}

	public static function sanitize_reference( string $ref ): string {
		$ref = trim( $ref );
		if ( '' === $ref ) {
			return '';
		}
		if ( preg_match( '#^https?://#i', $ref ) && function_exists( 'esc_url_raw' ) ) {
			$ref = (string) esc_url_raw( $ref );
		} elseif ( function_exists( 'sanitize_text_field' ) ) {
			$ref = sanitize_text_field( $ref );
		} else {
			$ref = strip_tags( $ref );
		}
		if ( strlen( $ref ) > 2000 ) {
			$ref = substr( $ref, 0, 2000 );
		}

		return $ref;
	}

	public static function table_age_ts( ?int $now = null ): int {
		unset( $now );
		$table = self::table();
		$ts    = strtotime( (string) $table['shipped'] . ' UTC' );

		return $ts > 0 ? $ts : 0;
	}

	public static function is_table_stale( ?int $now = null ): bool {
		$now = null !== $now && $now > 0 ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$age = self::table_age_ts( $now );
		if ( $age <= 0 ) {
			return true;
		}

		return ( $now - $age ) > ( self::STALE_AFTER_DAYS * DAY_IN_SECONDS );
	}

	/**
	 * @return array{trains_by_default:string,opt_out:string,zero_retention:string}|null
	 */
	public static function table_row_for( string $provider, ?array $table = null ): ?array {
		$provider = self::sanitize_provider( $provider );
		if ( '' === $provider ) {
			return null;
		}
		if ( null === $table ) {
			$table = self::table();
		}
		if ( isset( $table['providers'][ $provider ] ) && is_array( $table['providers'][ $provider ] ) ) {
			return $table['providers'][ $provider ];
		}

		return null;
	}

	/**
	 * @return array{requested_at:string,requested_by:string,reference:string,updated_at:int,history:list<array<string,mixed>>}
	 */
	public static function attestation_defaults(): array {
		return array(
			'requested_at' => '',
			'requested_by' => '',
			'reference'    => '',
			'updated_at'   => 0,
			'history'      => array(),
		);
	}

	/**
	 * @return array<string,array{requested_at:string,requested_by:string,reference:string,updated_at:int,history:list<array<string,mixed>>}>
	 */
	public static function get_attestations(): array {
		return self::sanitize_attestations( get_option( self::ATTESTATIONS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw map.
	 * @return array<string,array{requested_at:string,requested_by:string,reference:string,updated_at:int,history:list<array<string,mixed>>}>
	 */
	public static function sanitize_attestations( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $provider => $row ) {
			$id = self::sanitize_provider( (string) $provider );
			if ( '' === $id || ! is_array( $row ) ) {
				continue;
			}
			$clean = self::sanitize_attestation_row( $row );
			if ( self::attestation_is_empty( $clean ) ) {
				continue;
			}
			$out[ $id ] = $clean;
		}
		ksort( $out );

		return $out;
	}

	/**
	 * @param array<string,mixed> $row Raw row.
	 * @return array{requested_at:string,requested_by:string,reference:string,updated_at:int,history:list<array<string,mixed>>}
	 */
	public static function sanitize_attestation_row( array $row ): array {
		$defaults = self::attestation_defaults();
		$history  = array();
		if ( isset( $row['history'] ) && is_array( $row['history'] ) ) {
			foreach ( $row['history'] as $entry ) {
				if ( ! is_array( $entry ) ) {
					continue;
				}
				$history[] = array(
					'requested_at' => self::sanitize_date( (string) ( $entry['requested_at'] ?? '' ) ),
					'requested_by' => self::sanitize_note( (string) ( $entry['requested_by'] ?? '' ), 200 ),
					'reference'    => self::sanitize_reference( (string) ( $entry['reference'] ?? '' ) ),
					'replaced_at'  => max( 0, (int) ( $entry['replaced_at'] ?? 0 ) ),
				);
			}
			if ( count( $history ) > self::HISTORY_CAP ) {
				$history = array_slice( $history, -1 * self::HISTORY_CAP );
			}
		}

		return array(
			'requested_at' => self::sanitize_date( (string) ( $row['requested_at'] ?? '' ) ),
			'requested_by' => self::sanitize_note( (string) ( $row['requested_by'] ?? '' ), 200 ),
			'reference'    => self::sanitize_reference( (string) ( $row['reference'] ?? '' ) ),
			'updated_at'   => max( 0, (int) ( $row['updated_at'] ?? 0 ) ),
			'history'      => $history,
		);
	}

	/**
	 * @param array{requested_at?:string,requested_by?:string,reference?:string} $row Row.
	 */
	public static function attestation_is_empty( array $row ): bool {
		return '' === (string) ( $row['requested_at'] ?? '' )
			&& '' === (string) ( $row['requested_by'] ?? '' )
			&& '' === (string) ( $row['reference'] ?? '' );
	}

	/**
	 * Dated claim on file (auditor-readable).
	 *
	 * @param array{requested_at?:string}|null $row Attestation.
	 */
	public static function has_recorded_opt_out( ?array $row ): bool {
		if ( null === $row ) {
			return false;
		}

		return '' !== (string) ( $row['requested_at'] ?? '' );
	}

	/**
	 * @param array<string,array<string,mixed>> $attestations Map.
	 */
	public static function put_attestations( array $attestations ): void {
		$clean = self::sanitize_attestations( $attestations );
		if ( array() === $clean ) {
			delete_option( self::ATTESTATIONS_OPTION );

			return;
		}
		update_option( self::ATTESTATIONS_OPTION, $clean, false );
	}

	/**
	 * Record / replace an attestation. Prior non-empty values append to history.
	 *
	 * @param array{requested_at?:string,requested_by?:string,reference?:string} $fields Fields.
	 */
	public static function record_attestation( string $provider, array $fields, ?int $now = null ): bool {
		$provider = self::sanitize_provider( $provider );
		if ( '' === $provider ) {
			return false;
		}
		$now  = null !== $now && $now > 0 ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$next = self::sanitize_attestation_row(
			array(
				'requested_at' => (string) ( $fields['requested_at'] ?? '' ),
				'requested_by' => (string) ( $fields['requested_by'] ?? '' ),
				'reference'    => (string) ( $fields['reference'] ?? '' ),
				'updated_at'   => $now,
				'history'      => array(),
			)
		);

		$map = self::get_attestations();
		if ( isset( $map[ $provider ] ) ) {
			$prev = $map[ $provider ];
			if ( ! self::attestation_is_empty( $prev ) ) {
				$same = (string) $prev['requested_at'] === (string) $next['requested_at']
					&& (string) $prev['requested_by'] === (string) $next['requested_by']
					&& (string) $prev['reference'] === (string) $next['reference'];
				if ( $same ) {
					return false;
				}
				$history   = isset( $prev['history'] ) && is_array( $prev['history'] ) ? $prev['history'] : array();
				$history[] = array(
					'requested_at' => (string) $prev['requested_at'],
					'requested_by' => (string) $prev['requested_by'],
					'reference'    => (string) $prev['reference'],
					'replaced_at'  => $now,
				);
				if ( count( $history ) > self::HISTORY_CAP ) {
					$history = array_slice( $history, -1 * self::HISTORY_CAP );
				}
				$next['history'] = $history;
			}
		}

		if ( self::attestation_is_empty( $next ) ) {
			unset( $map[ $provider ] );
		} else {
			$map[ $provider ] = $next;
		}
		self::put_attestations( $map );

		return true;
	}

	/**
	 * Providers observed in traffic (activity log), with optional Provider_Map label.
	 *
	 * @param array<int,array<string,mixed>>|null $log Retained log.
	 * @return array<string,array{provider:string,label:string,plugins:list<string>,calls:int,first_seen:int,last_seen:int}>
	 */
	public static function providers_in_traffic( ?array $log = null ): array {
		if ( null === $log ) {
			$log = class_exists( Policy::class, false ) ? Policy::get_retained_log() : array();
		}
		if ( class_exists( Demo_Mode::class, false ) ) {
			$log = Demo_Mode::without_demo( $log );
		}

		$stats = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( class_exists( Selftest::class, false ) && Selftest::is_synthetic_row( $row ) ) {
				continue;
			}
			if ( class_exists( Usage_Trends::class, false ) && ! Usage_Trends::is_activity_row( $row ) ) {
				continue;
			}
			$provider = self::sanitize_provider( (string) ( $row['provider'] ?? '' ) );
			if ( '' === $provider ) {
				continue;
			}
			if ( ! isset( $stats[ $provider ] ) ) {
				$stats[ $provider ] = array(
					'provider'   => $provider,
					'label'      => self::provider_label( $provider ),
					'plugins'    => array(),
					'calls'      => 0,
					'first_seen' => 0,
					'last_seen'  => 0,
				);
			}
			$ts    = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			$count = isset( $row['count'] ) ? max( 1, (int) $row['count'] ) : 1;
			$stats[ $provider ]['calls'] += $count;
			if ( $ts > 0 ) {
				if ( 0 === $stats[ $provider ]['first_seen'] || $ts < $stats[ $provider ]['first_seen'] ) {
					$stats[ $provider ]['first_seen'] = $ts;
				}
				if ( $ts > $stats[ $provider ]['last_seen'] ) {
					$stats[ $provider ]['last_seen'] = $ts;
				}
			}
			$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			if ( '' === $plugin ) {
				$plugin = self::UNKNOWN_PLUGIN;
			}
			$stats[ $provider ]['plugins'][ $plugin ] = true;
		}

		$out = array();
		foreach ( $stats as $provider => $stat ) {
			$plugins = array_keys( $stat['plugins'] );
			sort( $plugins );
			$out[ $provider ] = array(
				'provider'   => $provider,
				'label'      => (string) $stat['label'],
				'plugins'    => $plugins,
				'calls'      => (int) $stat['calls'],
				'first_seen' => (int) $stat['first_seen'],
				'last_seen'  => (int) $stat['last_seen'],
			);
		}
		ksort( $out );

		return $out;
	}

	public static function provider_label( string $provider ): string {
		$provider = self::sanitize_provider( $provider );
		if ( '' === $provider ) {
			return '';
		}
		if ( class_exists( Provider_Map::class, false ) && method_exists( Provider_Map::class, 'signature_label' ) ) {
			$label = (string) Provider_Map::signature_label( $provider );
			if ( '' !== $label ) {
				return $label;
			}
		}

		return $provider;
	}

	/**
	 * Provider roster: in-traffic providers joined to table + attestation.
	 *
	 * @param array<int,array<string,mixed>>|null $log Retained log.
	 * @return list<array<string,mixed>>
	 */
	public static function provider_roster( ?array $log = null ): array {
		$table         = self::table();
		$attestations  = self::get_attestations();
		$in_traffic    = self::providers_in_traffic( $log );
		$rows          = array();

		foreach ( $in_traffic as $provider => $traffic ) {
			$trow   = self::table_row_for( $provider, $table );
			$attest = isset( $attestations[ $provider ] ) ? $attestations[ $provider ] : null;
			$trains = $trow ? (string) $trow['trains_by_default'] : self::TRAINS_UNKNOWN;
			$recorded = self::has_recorded_opt_out( $attest );
			$exposed  = ( self::TRAINS_YES === $trains ) && ! $recorded;

			$rows[] = array(
				'provider'          => $provider,
				'label'             => (string) $traffic['label'],
				'trains_by_default' => $trains,
				'opt_out'           => $trow ? (string) $trow['opt_out'] : '',
				'zero_retention'    => $trow ? (string) $trow['zero_retention'] : self::TRAINS_UNKNOWN,
				'in_table'          => null !== $trow,
				'calls'             => (int) $traffic['calls'],
				'plugins'           => $traffic['plugins'],
				'plugin_count'      => count( $traffic['plugins'] ),
				'first_seen'        => (int) $traffic['first_seen'],
				'last_seen'         => (int) $traffic['last_seen'],
				'attested'          => $recorded,
				'requested_at'      => $attest ? (string) $attest['requested_at'] : '',
				'requested_by'      => $attest ? (string) $attest['requested_by'] : '',
				'reference'         => $attest ? (string) $attest['reference'] : '',
				'exposed'           => $exposed,
				'assertion'         => true,
			);
		}

		usort(
			$rows,
			static function ( array $a, array $b ): int {
				if ( (int) $a['exposed'] !== (int) $b['exposed'] ) {
					return (int) $b['exposed'] <=> (int) $a['exposed'];
				}
				if ( (int) $a['calls'] !== (int) $b['calls'] ) {
					return (int) $b['calls'] <=> (int) $a['calls'];
				}

				return strcmp( (string) $a['provider'], (string) $b['provider'] );
			}
		);

		return $rows;
	}

	/**
	 * Exposure roster: plugin→provider pairs flagged (train-by-default, no opt-out on file).
	 *
	 * @param array<int,array<string,mixed>>|null $log Retained log.
	 * @return list<array<string,mixed>>
	 */
	public static function exposure_roster( ?array $log = null ): array {
		$providers = self::provider_roster( $log );
		$out       = array();
		foreach ( $providers as $row ) {
			if ( empty( $row['exposed'] ) ) {
				continue;
			}
			$plugins = isset( $row['plugins'] ) && is_array( $row['plugins'] ) ? $row['plugins'] : array();
			if ( empty( $plugins ) ) {
				$plugins = array( self::UNKNOWN_PLUGIN );
			}
			foreach ( $plugins as $plugin ) {
				$out[] = array(
					'plugin'            => (string) $plugin,
					'provider'          => (string) $row['provider'],
					'label'             => (string) $row['label'],
					'trains_by_default' => (string) $row['trains_by_default'],
					'opt_out'           => (string) $row['opt_out'],
					'zero_retention'    => (string) $row['zero_retention'],
					'calls'             => (int) $row['calls'],
					'requested_at'      => '',
					'requested_by'      => '',
					'reference'         => '',
					'exposed'           => true,
					'assertion'         => true,
					'flag'              => 'train_by_default_no_opt_out_on_file',
				);
			}
		}
		usort(
			$out,
			static function ( array $a, array $b ): int {
				$cmp = strcmp( (string) $a['provider'], (string) $b['provider'] );
				if ( 0 !== $cmp ) {
					return $cmp;
				}

				return strcmp( (string) $a['plugin'], (string) $b['plugin'] );
			}
		);

		return $out;
	}

	/**
	 * @return array<string,bool>
	 */
	public static function get_alerted(): array {
		$raw = get_option( self::ALERTED_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $fp => $flag ) {
			$fp = sanitize_key( (string) $fp );
			if ( '' === $fp || empty( $flag ) ) {
				continue;
			}
			$out[ $fp ] = true;
		}

		return $out;
	}

	/**
	 * @param array<string,bool> $alerted Fingerprints.
	 */
	public static function put_alerted( array $alerted ): void {
		$clean = array();
		foreach ( $alerted as $fp => $flag ) {
			$fp = sanitize_key( (string) $fp );
			if ( '' === $fp || empty( $flag ) ) {
				continue;
			}
			$clean[ $fp ] = true;
		}
		if ( array() === $clean ) {
			delete_option( self::ALERTED_OPTION );

			return;
		}
		update_option( self::ALERTED_OPTION, $clean, false );
	}

	public static function alert_fingerprint( string $provider ): string {
		return 'train_exposure_' . self::sanitize_provider( $provider );
	}

	/**
	 * Fire once the first time a trains-by-default provider appears in traffic.
	 *
	 * @param array<int,array<string,mixed>>|null $log    Log.
	 * @param array<string,mixed>|null            $policy Policy.
	 * @return array{fired:int,skipped:int}
	 */
	public static function maybe_fire_alerts( ?array $log = null, ?array $policy = null, ?int $now = null ): array {
		$result = array(
			'fired'   => 0,
			'skipped' => 0,
		);
		if ( ! self::is_enabled() ) {
			return $result;
		}
		$now = null !== $now && $now > 0 ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		if ( null === $policy ) {
			$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		}
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}

		$table   = self::table();
		$alerted = self::get_alerted();
		$traffic = self::providers_in_traffic( $log );

		foreach ( $traffic as $provider => $row ) {
			$trow = self::table_row_for( $provider, $table );
			if ( null === $trow || self::TRAINS_YES !== (string) $trow['trains_by_default'] ) {
				continue;
			}
			$fp = self::alert_fingerprint( $provider );
			if ( isset( $alerted[ $fp ] ) ) {
				++$result['skipped'];
				continue;
			}
			$plugin_for_snooze = ! empty( $row['plugins'][0] ) ? (string) $row['plugins'][0] : '';
			if ( '' !== $plugin_for_snooze
				&& class_exists( Alert_Snooze::class, false )
				&& Alert_Snooze::should_suppress( $plugin_for_snooze, self::ALERT_KIND, $now ) ) {
				++$result['skipped'];
				continue;
			}
			$payload = array(
				'provider' => $provider,
				'label'    => (string) $row['label'],
				'opt_out'  => (string) $trow['opt_out'],
				'plugins'  => $row['plugins'],
				'calls'    => (int) $row['calls'],
			);
			$ok = self::fire_alert( $payload, $policy, $now );
			if ( $ok ) {
				$alerted[ $fp ] = true;
				++$result['fired'];
			} else {
				++$result['skipped'];
			}
		}
		self::put_alerted( $alerted );

		return $result;
	}

	/**
	 * @param array<string,mixed> $payload Alert payload.
	 * @param array<string,mixed> $policy  Policy.
	 */
	private static function fire_alert( array $payload, array $policy, int $now ): bool {
		$email = '';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		}
		if ( '' === $email ) {
			return false;
		}

		$subject = self::build_subject( $payload );
		$body    = self::build_body( $payload );

		$ok = false;
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'safe_wp_mail' ) ) {
			$ok = (bool) Alerts::safe_wp_mail( $email, $subject, $body );
		} elseif ( function_exists( 'wp_mail' ) ) {
			$ok = (bool) wp_mail( $email, $subject, $body );
		}
		self::$test_mails[] = array(
			'to'      => $email,
			'subject' => $subject,
			'body'    => $body,
		);

		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'     => 'handl_aicac_train_exposure_alert',
						'provider' => (string) $payload['provider'],
						'opt_out'  => (string) $payload['opt_out'],
						'plugins'  => isset( $payload['plugins'] ) && is_array( $payload['plugins'] ) ? $payload['plugins'] : array(),
						'site'     => function_exists( 'home_url' ) ? home_url( '/' ) : '',
					)
				);
			}
		}

		if ( ! $ok ) {
			return false;
		}

		if ( class_exists( Policy::class, false ) ) {
			Policy::append_log_event(
				array(
					'ts'       => $now,
					'decision' => 'train_exposure_alert',
					'channel'  => 'train_exposure',
					'provider' => (string) $payload['provider'],
				)
			);
		}

		return true;
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	public static function build_subject( array $payload ): string {
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$provider = (string) ( $payload['provider'] ?? '' );

		return sprintf(
			/* translators: 1: site name, 2: provider id */
			__( '[%1$s] New train-by-default AI provider in traffic: %2$s', 'handl-ai-connector-access-control' ),
			$site,
			$provider
		);
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	public static function build_body( array $payload ): string {
		$provider = (string) ( $payload['provider'] ?? '' );
		$opt_out  = (string) ( $payload['opt_out'] ?? '' );
		$plugins  = isset( $payload['plugins'] ) && is_array( $payload['plugins'] )
			? implode( ', ', array_map( 'strval', $payload['plugins'] ) )
			: '';
		$lines    = array(
			__( 'A provider whose bundled data-use table marks trains-by-default=yes first appeared in AI traffic on this site.', 'handl-ai-connector-access-control' ),
			'',
			sprintf(
				/* translators: %s: provider id */
				__( 'Provider: %s', 'handl-ai-connector-access-control' ),
				$provider
			),
			sprintf(
				/* translators: %s: opt-out mechanism summary */
				__( 'Opt-out mechanism (table): %s', 'handl-ai-connector-access-control' ),
				'' !== $opt_out ? $opt_out : '—'
			),
			sprintf(
				/* translators: %s: plugin list */
				__( 'Plugins: %s', 'handl-ai-connector-access-control' ),
				'' !== $plugins ? $plugins : '—'
			),
			'',
			__( 'This alert is informational. Record an opt-out attestation on the Training exposure screen if counsel requested one.', 'handl-ai-connector-access-control' ),
			self::admin_url(),
		);

		return implode( "\n", $lines );
	}

	public static function admin_url(): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg(
			array( 'page' => self::PAGE_SLUG ),
			admin_url( 'admin.php' )
		);
	}

	/**
	 * @param list<array<string,mixed>>|null $rows Rows.
	 */
	public static function csv_for_exposure( ?array $rows = null ): string {
		if ( null === $rows ) {
			$rows = self::exposure_roster();
		}
		$lines   = array();
		$lines[] = self::csv_line(
			array(
				'framing',
				'plugin',
				'provider',
				'trains_by_default',
				'opt_out_mechanism',
				'zero_retention',
				'flag',
				'calls_on_provider',
			)
		);
		foreach ( $rows as $row ) {
			$lines[] = self::csv_line(
				array(
					'assertion_not_legal_advice',
					(string) ( $row['plugin'] ?? '' ),
					(string) ( $row['provider'] ?? '' ),
					(string) ( $row['trains_by_default'] ?? '' ),
					(string) ( $row['opt_out'] ?? '' ),
					(string) ( $row['zero_retention'] ?? '' ),
					(string) ( $row['flag'] ?? '' ),
					(string) (int) ( $row['calls'] ?? 0 ),
				)
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param list<array<string,mixed>>|null $rows Rows.
	 */
	public static function csv_for_providers( ?array $rows = null ): string {
		if ( null === $rows ) {
			$rows = self::provider_roster();
		}
		$lines   = array();
		$lines[] = self::csv_line(
			array(
				'framing',
				'provider',
				'trains_by_default',
				'opt_out_mechanism',
				'zero_retention',
				'in_traffic',
				'calls',
				'plugin_count',
				'opt_out_requested_at',
				'opt_out_requested_by',
				'reference',
				'exposed',
			)
		);
		foreach ( $rows as $row ) {
			$lines[] = self::csv_line(
				array(
					'assertion_not_legal_advice',
					(string) ( $row['provider'] ?? '' ),
					(string) ( $row['trains_by_default'] ?? '' ),
					(string) ( $row['opt_out'] ?? '' ),
					(string) ( $row['zero_retention'] ?? '' ),
					'yes',
					(string) (int) ( $row['calls'] ?? 0 ),
					(string) (int) ( $row['plugin_count'] ?? 0 ),
					(string) ( $row['requested_at'] ?? '' ),
					(string) ( $row['requested_by'] ?? '' ),
					(string) ( $row['reference'] ?? '' ),
					! empty( $row['exposed'] ) ? 'yes' : 'no',
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
			$col   = str_replace( '"', '""', $col );
			$out[] = '"' . $col . '"';
		}

		return implode( ',', $out );
	}

	/**
	 * @param list<array<string,mixed>> $rows Exposure rows.
	 */
	public static function build_print_html( array $rows ): string {
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8" />';
		$html .= '<title>' . esc_html__( 'Training exposure roster', 'handl-ai-connector-access-control' ) . '</title>';
		$html .= '<style>body{font-family:system-ui,sans-serif;margin:2rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:.4rem;text-align:left}th{background:#f3f3f3}.flag{color:#8a1f1f;font-weight:600}</style>';
		$html .= '</head><body>';
		$html .= '<h1>' . esc_html__( 'Training exposure roster', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html( $site ) . ' — ' . esc_html( gmdate( 'Y-m-d H:i:s' ) ) . ' UTC</p>';
		$html .= '<p><strong>' . esc_html__( 'Assertion framing — not legal advice.', 'handl-ai-connector-access-control' ) . '</strong> ';
		$html .= esc_html__( 'Rows flag plugins sending traffic to providers marked trains-by-default=yes with no dated opt-out attestation on file.', 'handl-ai-connector-access-control' );
		$html .= '</p>';
		if ( empty( $rows ) ) {
			$html .= '<p>' . esc_html__( 'No exposed plugin/provider pairs in the retained log.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			$html .= '<table><thead><tr>';
			$html .= '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			$html .= '<th>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
			$html .= '<th>' . esc_html__( 'Trains by default', 'handl-ai-connector-access-control' ) . '</th>';
			$html .= '<th>' . esc_html__( 'Opt-out mechanism', 'handl-ai-connector-access-control' ) . '</th>';
			$html .= '<th>' . esc_html__( 'Flag', 'handl-ai-connector-access-control' ) . '</th>';
			$html .= '</tr></thead><tbody>';
			foreach ( $rows as $row ) {
				$html .= '<tr>';
				$html .= '<td><code>' . esc_html( (string) $row['plugin'] ) . '</code></td>';
				$html .= '<td>' . esc_html( (string) $row['provider'] ) . '</td>';
				$html .= '<td>' . esc_html( (string) $row['trains_by_default'] ) . '</td>';
				$html .= '<td>' . esc_html( (string) $row['opt_out'] ) . '</td>';
				$html .= '<td class="flag">' . esc_html( (string) $row['flag'] ) . '</td>';
				$html .= '</tr>';
			}
			$html .= '</tbody></table>';
		}
		$html .= '</body></html>';

		return $html;
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
			__( 'Training exposure', 'handl-ai-connector-access-control' ),
			__( 'Training exposure', 'handl-ai-connector-access-control' ),
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
		$providers  = $enabled ? self::provider_roster() : array();
		$exposed    = $enabled ? self::exposure_roster() : array();
		$stale      = $enabled && self::is_table_stale();
		$age_ts     = self::table_age_ts();
		$csv        = add_query_arg(
			array(
				'page'                            => self::PAGE_SLUG,
				'handl_aicac_train_exposure_csv'  => '1',
				'_wpnonce'                        => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_train_exposure_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print = add_query_arg(
			array(
				'page'                              => self::PAGE_SLUG,
				'handl_aicac_train_exposure_print'  => '1',
				'_wpnonce'                          => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_train_exposure_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Training exposure', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Who trains on words that leave this site — and who was asked to stop. Bundled provider data-use table plus dated opt-out attestations. Informational only; off by default. Not legal advice.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable training exposure', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( $enabled, true, false ) . ' /> ';
			echo esc_html__( 'Build the provider data-use roster from AI traffic already logged on this site', 'handl-ai-connector-access-control' );
			echo '</label></td></tr></tbody></table>';
			submit_button( __( 'Save training exposure settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Training exposure is off. Enable it to cross-reference providers in traffic against the data-use table and record opt-out attestations.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<div class="notice notice-info"><p><strong>' . esc_html__( 'Assertion framing — not legal advice.', 'handl-ai-connector-access-control' ) . '</strong> ';
		echo esc_html__( 'The bundled table is a directional starting point. Override with the handl_aicac_train_exposure_table filter. Attestations are your dated claims — hallway hearsay becomes a record an auditor can read.', 'handl-ai-connector-access-control' );
		echo '</p></div>';

		echo '<p class="description">';
		echo esc_html(
			sprintf(
				/* translators: 1: Y-m-d date, 2: age label */
				__( 'Data-use table age: %1$s (%2$s).', 'handl-ai-connector-access-control' ),
				$age_ts > 0 ? gmdate( 'Y-m-d', $age_ts ) : '—',
				$stale
					? __( 'stale — refresh or override recommended', 'handl-ai-connector-access-control' )
					: __( 'current', 'handl-ai-connector-access-control' )
			)
		);
		echo '</p>';

		if ( $stale ) {
			echo '<div class="notice notice-warning"><p>';
			echo esc_html__( 'The provider data-use table is older than 120 days. Confirm postures against current vendor terms or override via handl_aicac_train_exposure_table.', 'handl-ai-connector-access-control' );
			echo '</p></div>';
		}

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download exposure CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Exposed (train-by-default, no opt-out on file)', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $exposed ) ) {
			echo '<p>' . esc_html__( 'No exposed plugin/provider pairs. Either no train-by-default providers are in traffic, or every such provider has a dated opt-out attestation.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Opt-out mechanism', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Flag', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $exposed as $row ) {
				echo '<tr>';
				echo '<td><code>' . esc_html( (string) $row['plugin'] ) . '</code></td>';
				echo '<td><code>' . esc_html( (string) $row['provider'] ) . '</code></td>';
				echo '<td>' . esc_html( (string) $row['opt_out'] ) . '</td>';
				echo '<td>' . esc_html( (string) $row['flag'] ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '<h2>' . esc_html__( 'Providers in traffic', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $providers ) ) {
			echo '<p>' . esc_html__( 'No provider ids in the retained activity log yet.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Trains by default', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Zero retention', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Opt-out on file', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Exposed', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $providers as $row ) {
				$on_file = ! empty( $row['attested'] )
					? sprintf(
						/* translators: 1: date, 2: who */
						__( '%1$s by %2$s', 'handl-ai-connector-access-control' ),
						(string) $row['requested_at'],
						'' !== (string) $row['requested_by'] ? (string) $row['requested_by'] : '—'
					)
					: __( 'No', 'handl-ai-connector-access-control' );
				echo '<tr>';
				echo '<td><code>' . esc_html( (string) $row['provider'] ) . '</code></td>';
				echo '<td>' . esc_html( (string) $row['trains_by_default'] ) . '</td>';
				echo '<td>' . esc_html( (string) $row['zero_retention'] ) . '</td>';
				echo '<td class="num">' . esc_html( (string) (int) $row['calls'] ) . '</td>';
				echo '<td>' . esc_html( $on_file ) . '</td>';
				echo '<td>' . esc_html( ! empty( $row['exposed'] ) ? __( 'Yes', 'handl-ai-connector-access-control' ) : __( 'No', 'handl-ai-connector-access-control' ) ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		if ( $can_manage && ! empty( $providers ) ) {
			echo '<h2>' . esc_html__( 'Record opt-out attestation', 'handl-ai-connector-access-control' ) . '</h2>';
			echo '<p class="description">' . esc_html__( 'Turns "I think we opted out" into a dated record. Prior values stay in an append-only history.', 'handl-ai-connector-access-control' ) . '</p>';
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_ATTEST ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_ATTEST );
			}
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row"><label for="handl-aicac-te-provider">' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<select name="provider" id="handl-aicac-te-provider">';
			foreach ( $providers as $row ) {
				echo '<option value="' . esc_attr( (string) $row['provider'] ) . '">' . esc_html( (string) $row['provider'] ) . '</option>';
			}
			echo '</select></td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-te-date">' . esc_html__( 'Opt-out requested (date)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input type="date" class="regular-text" name="requested_at" id="handl-aicac-te-date" value="" />';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-te-by">' . esc_html__( 'Requested by', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input type="text" class="regular-text" name="requested_by" id="handl-aicac-te-by" value="" maxlength="200" />';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-te-ref">' . esc_html__( 'Reference / ticket', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input type="text" class="regular-text" name="reference" id="handl-aicac-te-ref" value="" maxlength="2000" />';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save attestation', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		echo '</div>';
	}

	public static function maybe_staleness_notice(): void {
		if ( ! self::is_enabled() || ! Caps::user_can_view() ) {
			return;
		}
		if ( ! self::is_table_stale() ) {
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		echo '<div class="notice notice-warning"><p>';
		echo esc_html__( 'Training exposure: the bundled provider data-use table is older than 120 days.', 'handl-ai-connector-access-control' );
		echo '</p></div>';
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_train_exposure_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_train_exposure_csv' );
		$csv = self::csv_for_exposure();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename=aicac-train-exposure.csv' );
		}
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		if ( empty( $_GET['handl_aicac_train_exposure_print'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_train_exposure_print' );
		$rows = self::exposure_roster();
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
			wp_die( esc_html__( 'You do not have permission to save training exposure settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );
		}
		self::save_settings(
			array(
				'enabled' => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
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

	public static function handle_attest_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save training exposure attestations.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_ATTEST );
		$provider = isset( $_POST['provider'] ) ? self::sanitize_provider( wp_unslash( (string) $_POST['provider'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( '' === $provider ) {
			wp_die( esc_html__( 'Invalid provider', 'handl-ai-connector-access-control' ) );
		}
		self::record_attestation(
			$provider,
			array(
				'requested_at' => isset( $_POST['requested_at'] ) ? wp_unslash( (string) $_POST['requested_at'] ) : '', // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'requested_by' => isset( $_POST['requested_by'] ) ? wp_unslash( (string) $_POST['requested_by'] ) : '', // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'reference'    => isset( $_POST['reference'] ) ? wp_unslash( (string) $_POST['reference'] ) : '', // phpcs:ignore WordPress.Security.NonceVerification.Missing
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
		\WP_CLI::add_command( 'handl-aicac train-exposure', CLI_Train_Exposure::class );
	}
}

/**
 * WP-CLI: wp handl-aicac train-exposure status|export
 */
final class CLI_Train_Exposure {

	/**
	 * Show training exposure status.
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
		$settings = Train_Exposure::get_settings();
		$exposed  = Train_Exposure::is_enabled() ? Train_Exposure::exposure_roster() : array();
		$providers = Train_Exposure::is_enabled() ? Train_Exposure::provider_roster() : array();
		$format   = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$age      = Train_Exposure::table_age_ts();

		\WP_CLI::log(
			sprintf(
				'enabled=%s providers=%d exposed=%d table_age=%s stale=%s framing=assertion_not_legal_advice',
				! empty( $settings['enabled'] ) ? 'yes' : 'no',
				count( $providers ),
				count( $exposed ),
				$age > 0 ? gmdate( 'Y-m-d', $age ) : '—',
				Train_Exposure::is_table_stale() ? 'yes' : 'no'
			)
		);

		if ( empty( $exposed ) ) {
			\WP_CLI::log( 'No exposed rows.' );
			return;
		}

		$display = array();
		foreach ( $exposed as $row ) {
			$display[] = array(
				'plugin'   => (string) $row['plugin'],
				'provider' => (string) $row['provider'],
				'flag'     => (string) $row['flag'],
			);
		}
		if ( 'json' === $format ) {
			\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			return;
		}
		if ( class_exists( '\WP_CLI\Utils' ) ) {
			\WP_CLI\Utils\format_items(
				'table',
				$display,
				array( 'plugin', 'provider', 'flag' )
			);
		} else {
			foreach ( $display as $row ) {
				\WP_CLI::log( implode( "\t", $row ) );
			}
		}
	}

	/**
	 * Export the exposure roster as CSV.
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
		$csv = Train_Exposure::csv_for_exposure();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
