<?php
/**
 * AICAC-LEGAL-HOLD (#383): litigation hold that pauses the evidence shredder.
 *
 * Named holds scoped to user / plugin / provider / date-range / site-wide in
 * the class's own option. Retention purge (and the admin "delete without
 * download" path that calls the same prune) skip held rows via the
 * `handl_aicac_log_retention_kept_rows` filter. Snapshot bundle under uploads
 * at hold creation. Append-only hold ledger with actor + reason. Roster + CSV
 * + WP-CLI. Informational only — never denies. Inert until a hold exists
 * (OFF by default). No admin.php/policy.php/cost.php/logger edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Scoped preservation of AI activity log rows.
 */
final class Legal_Hold {

	public const HOLDS_OPTION = 'handl_aicac_legal_holds';

	public const LEDGER_OPTION = 'handl_aicac_legal_hold_ledger';

	public const PAGE_SLUG = 'handl-aicac-legal-hold';

	public const DIR_NAME = 'handl-aicac';

	public const SNAPSHOTS_SUB = 'legal-holds';

	public const ACTION_CREATE = 'handl_aicac_legal_hold_create';

	public const ACTION_RELEASE = 'handl_aicac_legal_hold_release';

	public const SCOPE_SITE = 'site';

	public const SCOPE_USER = 'user';

	public const SCOPE_PLUGIN = 'plugin';

	public const SCOPE_PROVIDER = 'provider';

	public const SCOPE_RANGE = 'date_range';

	public const LEDGER_CAP = 2000;

	public const NAME_MAX = 120;

	public const REASON_MAX = 500;

	/** @var bool */
	private static $registered = false;

	/** @var string|null */
	private static $test_dir = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_filter( 'handl_aicac_log_retention_kept_rows', array( self::class, 'filter_kept_rows' ), 10, 4 );
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_post_' . self::ACTION_CREATE, array( self::class, 'handle_create' ) );
		add_action( 'admin_post_' . self::ACTION_RELEASE, array( self::class, 'handle_release' ) );
		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$test_dir   = null;
		delete_option( self::HOLDS_OPTION );
		delete_option( self::LEDGER_OPTION );
	}

	/**
	 * @internal Tests only.
	 */
	public static function set_test_dir( ?string $dir ): void {
		self::$test_dir = ( null !== $dir && '' !== $dir ) ? $dir : null;
	}

	/**
	 * @return list<string>
	 */
	public static function scopes(): array {
		return array(
			self::SCOPE_SITE,
			self::SCOPE_USER,
			self::SCOPE_PLUGIN,
			self::SCOPE_PROVIDER,
			self::SCOPE_RANGE,
		);
	}

	/**
	 * @return array<string,array<string,mixed>>
	 */
	public static function get_holds(): array {
		$raw = get_option( self::HOLDS_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $id => $hold ) {
			$clean = self::sanitize_hold( $hold );
			if ( null === $clean ) {
				continue;
			}
			$out[ (string) $clean['id'] ] = $clean;
		}

		return $out;
	}

	/**
	 * @return array<string,array<string,mixed>>
	 */
	public static function get_active_holds(): array {
		$out = array();
		foreach ( self::get_holds() as $id => $hold ) {
			if ( empty( $hold['released_at'] ) ) {
				$out[ $id ] = $hold;
			}
		}

		return $out;
	}

	public static function has_active_holds(): bool {
		return ! empty( self::get_active_holds() );
	}

	/**
	 * @param mixed $raw Raw hold.
	 * @return array<string,mixed>|null
	 */
	public static function sanitize_hold( $raw ): ?array {
		if ( ! is_array( $raw ) ) {
			return null;
		}
		$id = isset( $raw['id'] ) ? sanitize_key( (string) $raw['id'] ) : '';
		if ( '' === $id ) {
			return null;
		}
		$scope = isset( $raw['scope'] ) ? sanitize_key( (string) $raw['scope'] ) : '';
		if ( ! in_array( $scope, self::scopes(), true ) ) {
			return null;
		}
		$name = isset( $raw['name'] ) ? sanitize_text_field( (string) $raw['name'] ) : '';
		if ( '' === $name ) {
			$name = $id;
		}
		if ( strlen( $name ) > self::NAME_MAX ) {
			$name = substr( $name, 0, self::NAME_MAX );
		}
		$reason = isset( $raw['reason'] ) ? sanitize_textarea_field( (string) $raw['reason'] ) : '';
		if ( strlen( $reason ) > self::REASON_MAX ) {
			$reason = substr( $reason, 0, self::REASON_MAX );
		}

		$users = array();
		if ( isset( $raw['users'] ) && is_array( $raw['users'] ) ) {
			foreach ( $raw['users'] as $uid ) {
				$n = (int) $uid;
				if ( $n > 0 ) {
					$users[] = $n;
				}
			}
		}
		$users = array_values( array_unique( $users ) );

		$plugins = array();
		if ( isset( $raw['plugins'] ) && is_array( $raw['plugins'] ) ) {
			foreach ( $raw['plugins'] as $plugin ) {
				$p = sanitize_text_field( (string) $plugin );
				if ( '' !== $p ) {
					$plugins[] = $p;
				}
			}
		}
		$plugins = array_values( array_unique( $plugins ) );

		$providers = array();
		if ( isset( $raw['providers'] ) && is_array( $raw['providers'] ) ) {
			foreach ( $raw['providers'] as $provider ) {
				$p = sanitize_key( (string) $provider );
				if ( '' !== $p ) {
					$providers[] = $p;
				}
			}
		}
		$providers = array_values( array_unique( $providers ) );

		$date_from = isset( $raw['date_from'] ) ? (int) $raw['date_from'] : 0;
		$date_to   = isset( $raw['date_to'] ) ? (int) $raw['date_to'] : 0;
		if ( $date_from < 0 ) {
			$date_from = 0;
		}
		if ( $date_to < 0 ) {
			$date_to = 0;
		}

		$created_by   = isset( $raw['created_by'] ) ? (int) $raw['created_by'] : 0;
		$created_at   = isset( $raw['created_at'] ) ? (int) $raw['created_at'] : 0;
		$released_at  = isset( $raw['released_at'] ) ? (int) $raw['released_at'] : 0;
		$released_by  = isset( $raw['released_by'] ) ? (int) $raw['released_by'] : 0;
		$release_note = isset( $raw['release_reason'] ) ? sanitize_textarea_field( (string) $raw['release_reason'] ) : '';
		if ( strlen( $release_note ) > self::REASON_MAX ) {
			$release_note = substr( $release_note, 0, self::REASON_MAX );
		}
		$snapshot = isset( $raw['snapshot_path'] ) ? sanitize_text_field( (string) $raw['snapshot_path'] ) : '';
		$matched  = isset( $raw['matched_count'] ) ? max( 0, (int) $raw['matched_count'] ) : 0;

		return array(
			'id'             => $id,
			'name'           => $name,
			'scope'          => $scope,
			'users'          => $users,
			'plugins'        => $plugins,
			'providers'      => $providers,
			'date_from'      => $date_from > 0 ? $date_from : 0,
			'date_to'        => $date_to > 0 ? $date_to : 0,
			'reason'         => $reason,
			'created_by'     => $created_by > 0 ? $created_by : 0,
			'created_at'     => $created_at > 0 ? $created_at : 0,
			'released_at'    => $released_at > 0 ? $released_at : 0,
			'released_by'    => $released_by > 0 ? $released_by : 0,
			'release_reason' => $release_note,
			'snapshot_path'  => $snapshot,
			'matched_count'  => $matched,
		);
	}

	/**
	 * @param array<string,mixed> $args Create args.
	 * @return array{ok:bool,id?:string,error?:string,hold?:array<string,mixed>,matched?:int}
	 */
	public static function create_hold( array $args, ?int $actor_id = null, ?int $now = null ): array {
		$now      = ( null !== $now && $now > 0 ) ? $now : Clock::now();
		$actor_id = null !== $actor_id ? (int) $actor_id : ( function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0 );

		$scope = isset( $args['scope'] ) ? sanitize_key( (string) $args['scope'] ) : '';
		if ( ! in_array( $scope, self::scopes(), true ) ) {
			return array(
				'ok'    => false,
				'error' => 'invalid_scope',
			);
		}

		$name = isset( $args['name'] ) ? sanitize_text_field( (string) $args['name'] ) : '';
		if ( '' === $name ) {
			$name = 'Hold ' . gmdate( 'Y-m-d H:i', $now );
		}
		$reason = isset( $args['reason'] ) ? sanitize_textarea_field( (string) $args['reason'] ) : '';
		if ( '' === $reason ) {
			return array(
				'ok'    => false,
				'error' => 'reason_required',
			);
		}

		$users     = array();
		$plugins   = array();
		$providers = array();
		$date_from = 0;
		$date_to   = 0;

		if ( self::SCOPE_USER === $scope ) {
			$raw_users = $args['users'] ?? ( $args['user'] ?? array() );
			if ( ! is_array( $raw_users ) ) {
				$raw_users = preg_split( '/[\s,]+/', (string) $raw_users ) ?: array();
			}
			foreach ( $raw_users as $uid ) {
				$n = (int) $uid;
				if ( $n > 0 ) {
					$users[] = $n;
				}
			}
			$users = array_values( array_unique( $users ) );
			if ( empty( $users ) ) {
				return array(
					'ok'    => false,
					'error' => 'users_required',
				);
			}
		} elseif ( self::SCOPE_PLUGIN === $scope ) {
			$raw_plugins = $args['plugins'] ?? ( $args['plugin'] ?? array() );
			if ( ! is_array( $raw_plugins ) ) {
				$raw_plugins = preg_split( '/[\s,]+/', (string) $raw_plugins ) ?: array();
			}
			foreach ( $raw_plugins as $plugin ) {
				$p = sanitize_text_field( (string) $plugin );
				if ( '' !== $p ) {
					$plugins[] = $p;
				}
			}
			$plugins = array_values( array_unique( $plugins ) );
			if ( empty( $plugins ) ) {
				return array(
					'ok'    => false,
					'error' => 'plugins_required',
				);
			}
		} elseif ( self::SCOPE_PROVIDER === $scope ) {
			$raw_providers = $args['providers'] ?? ( $args['provider'] ?? array() );
			if ( ! is_array( $raw_providers ) ) {
				$raw_providers = preg_split( '/[\s,]+/', (string) $raw_providers ) ?: array();
			}
			foreach ( $raw_providers as $provider ) {
				$p = sanitize_key( (string) $provider );
				if ( '' !== $p ) {
					$providers[] = $p;
				}
			}
			$providers = array_values( array_unique( $providers ) );
			if ( empty( $providers ) ) {
				return array(
					'ok'    => false,
					'error' => 'providers_required',
				);
			}
		} elseif ( self::SCOPE_RANGE === $scope ) {
			$date_from = self::parse_date_arg( $args['date_from'] ?? ( $args['from'] ?? 0 ) );
			$date_to   = self::parse_date_arg( $args['date_to'] ?? ( $args['to'] ?? 0 ) );
			if ( $date_from < 1 || $date_to < 1 || $date_to < $date_from ) {
				return array(
					'ok'    => false,
					'error' => 'date_range_invalid',
				);
			}
		}

		$id   = self::new_hold_id( $now );
		$hold = self::sanitize_hold(
			array(
				'id'         => $id,
				'name'       => $name,
				'scope'      => $scope,
				'users'      => $users,
				'plugins'    => $plugins,
				'providers'  => $providers,
				'date_from'  => $date_from,
				'date_to'    => $date_to,
				'reason'     => $reason,
				'created_by' => $actor_id,
				'created_at' => $now,
			)
		);
		if ( null === $hold ) {
			return array(
				'ok'    => false,
				'error' => 'sanitize_failed',
			);
		}

		$rows    = self::matching_rows( $hold );
		$snap    = self::write_snapshot_bundle( $id, $hold, $rows );
		$hold['matched_count'] = count( $rows );
		$hold['snapshot_path'] = ! empty( $snap['ok'] ) ? (string) ( $snap['path'] ?? '' ) : '';

		$holds        = self::get_holds();
		$holds[ $id ] = $hold;
		update_option( self::HOLDS_OPTION, $holds, false );

		self::append_ledger(
			array(
				'ts'      => $now,
				'action'  => 'create',
				'hold_id' => $id,
				'actor'   => $actor_id,
				'reason'  => $reason,
				'scope'   => $scope,
				'name'    => $name,
				'matched' => count( $rows ),
			)
		);

		return array(
			'ok'      => true,
			'id'      => $id,
			'hold'    => $hold,
			'matched' => count( $rows ),
		);
	}

	/**
	 * @return array{ok:bool,error?:string}
	 */
	public static function release_hold( string $id, string $reason = '', ?int $actor_id = null, ?int $now = null ): array {
		$id = sanitize_key( $id );
		if ( '' === $id ) {
			return array(
				'ok'    => false,
				'error' => 'missing_id',
			);
		}
		$holds = self::get_holds();
		if ( ! isset( $holds[ $id ] ) ) {
			return array(
				'ok'    => false,
				'error' => 'not_found',
			);
		}
		if ( ! empty( $holds[ $id ]['released_at'] ) ) {
			return array(
				'ok'    => false,
				'error' => 'already_released',
			);
		}

		$now      = ( null !== $now && $now > 0 ) ? $now : Clock::now();
		$actor_id = null !== $actor_id ? (int) $actor_id : ( function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0 );
		$reason   = sanitize_textarea_field( $reason );
		if ( '' === $reason ) {
			$reason = 'released';
		}
		if ( strlen( $reason ) > self::REASON_MAX ) {
			$reason = substr( $reason, 0, self::REASON_MAX );
		}

		$holds[ $id ]['released_at']    = $now;
		$holds[ $id ]['released_by']    = $actor_id;
		$holds[ $id ]['release_reason'] = $reason;
		update_option( self::HOLDS_OPTION, $holds, false );

		self::append_ledger(
			array(
				'ts'      => $now,
				'action'  => 'release',
				'hold_id' => $id,
				'actor'   => $actor_id,
				'reason'  => $reason,
				'scope'   => (string) ( $holds[ $id ]['scope'] ?? '' ),
				'name'    => (string) ( $holds[ $id ]['name'] ?? '' ),
				'matched' => (int) ( $holds[ $id ]['matched_count'] ?? 0 ),
			)
		);

		return array( 'ok' => true );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function get_ledger(): array {
		$raw = get_option( self::LEDGER_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$out[] = array(
				'ts'      => isset( $row['ts'] ) ? (int) $row['ts'] : 0,
				'action'  => isset( $row['action'] ) ? sanitize_key( (string) $row['action'] ) : '',
				'hold_id' => isset( $row['hold_id'] ) ? sanitize_key( (string) $row['hold_id'] ) : '',
				'actor'   => isset( $row['actor'] ) ? (int) $row['actor'] : 0,
				'reason'  => isset( $row['reason'] ) ? sanitize_textarea_field( (string) $row['reason'] ) : '',
				'scope'   => isset( $row['scope'] ) ? sanitize_key( (string) $row['scope'] ) : '',
				'name'    => isset( $row['name'] ) ? sanitize_text_field( (string) $row['name'] ) : '',
				'matched' => isset( $row['matched'] ) ? (int) $row['matched'] : 0,
			);
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $entry Ledger entry.
	 */
	public static function append_ledger( array $entry ): void {
		$ledger   = self::get_ledger();
		$ledger[] = array(
			'ts'      => isset( $entry['ts'] ) ? (int) $entry['ts'] : Clock::now(),
			'action'  => isset( $entry['action'] ) ? sanitize_key( (string) $entry['action'] ) : '',
			'hold_id' => isset( $entry['hold_id'] ) ? sanitize_key( (string) $entry['hold_id'] ) : '',
			'actor'   => isset( $entry['actor'] ) ? (int) $entry['actor'] : 0,
			'reason'  => isset( $entry['reason'] ) ? sanitize_textarea_field( (string) $entry['reason'] ) : '',
			'scope'   => isset( $entry['scope'] ) ? sanitize_key( (string) $entry['scope'] ) : '',
			'name'    => isset( $entry['name'] ) ? sanitize_text_field( (string) $entry['name'] ) : '',
			'matched' => isset( $entry['matched'] ) ? (int) $entry['matched'] : 0,
		);
		if ( count( $ledger ) > self::LEDGER_CAP ) {
			$ledger = array_slice( $ledger, -1 * self::LEDGER_CAP );
		}
		update_option( self::LEDGER_OPTION, $ledger, false );
	}

	/**
	 * @param array<string,mixed> $row  Log row.
	 * @param array<string,mixed> $hold Hold.
	 */
	public static function row_matches_hold( array $row, array $hold ): bool {
		if ( ! empty( $hold['released_at'] ) ) {
			return false;
		}
		$scope = (string) ( $hold['scope'] ?? '' );
		if ( self::SCOPE_SITE === $scope ) {
			return true;
		}
		if ( self::SCOPE_USER === $scope ) {
			$uid   = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
			$users = isset( $hold['users'] ) && is_array( $hold['users'] ) ? $hold['users'] : array();

			return $uid > 0 && in_array( $uid, $users, true );
		}
		if ( self::SCOPE_PLUGIN === $scope ) {
			$plugin  = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			$plugins = isset( $hold['plugins'] ) && is_array( $hold['plugins'] ) ? $hold['plugins'] : array();

			return '' !== $plugin && in_array( $plugin, $plugins, true );
		}
		if ( self::SCOPE_PROVIDER === $scope ) {
			$provider  = isset( $row['provider'] ) ? sanitize_key( (string) $row['provider'] ) : '';
			$providers = isset( $hold['providers'] ) && is_array( $hold['providers'] ) ? $hold['providers'] : array();

			return '' !== $provider && in_array( $provider, $providers, true );
		}
		if ( self::SCOPE_RANGE === $scope ) {
			$ts   = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			$from = isset( $hold['date_from'] ) ? (int) $hold['date_from'] : 0;
			$to   = isset( $hold['date_to'] ) ? (int) $hold['date_to'] : 0;
			if ( $ts < 1 || $from < 1 || $to < 1 ) {
				return false;
			}

			return $ts >= $from && $ts <= $to;
		}

		return false;
	}

	/**
	 * @param array<string,mixed>              $row   Log row.
	 * @param array<string,array<string,mixed>>|null $holds Active holds override.
	 */
	public static function row_is_held( array $row, ?array $holds = null ): bool {
		$holds = null !== $holds ? $holds : self::get_active_holds();
		foreach ( $holds as $hold ) {
			if ( self::row_matches_hold( $row, $hold ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Filter callback for Log_Retention::run_prune_batch.
	 *
	 * @param mixed                $kept   Rows about to be saved.
	 * @param mixed                $log    Pre-prune log.
	 * @param array<string,mixed>  $policy Policy.
	 * @param int                  $now    Now.
	 * @return list<array<string,mixed>>
	 */
	public static function filter_kept_rows( $kept, $log, $policy, $now ): array {
		unset( $policy, $now );
		if ( ! is_array( $kept ) ) {
			$kept = array();
		}
		if ( ! self::has_active_holds() ) {
			$out = array();
			foreach ( $kept as $row ) {
				if ( is_array( $row ) ) {
					$out[] = $row;
				}
			}

			return $out;
		}
		if ( ! is_array( $log ) ) {
			$log = array();
		}

		$kept_ids = array();
		foreach ( $kept as $row ) {
			if ( is_array( $row ) ) {
				$kept_ids[ self::row_identity( $row ) ] = true;
			}
		}

		$out = array();
		$seen = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$id = self::row_identity( $row );
			if ( isset( $seen[ $id ] ) ) {
				continue;
			}
			if ( isset( $kept_ids[ $id ] ) || self::row_is_held( $row ) ) {
				$out[]      = $row;
				$seen[ $id ] = true;
			}
		}

		return $out;
	}

	/**
	 * @param array<string,mixed>|null $hold Hold or null for any active.
	 * @return list<array<string,mixed>>
	 */
	public static function matching_rows( ?array $hold = null ): array {
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		if ( ! is_array( $log ) ) {
			return array();
		}
		$out = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( null === $hold ) {
				if ( self::row_is_held( $row ) ) {
					$out[] = $row;
				}
				continue;
			}
			if ( self::row_matches_hold( $row, $hold ) ) {
				$out[] = $row;
			}
		}

		return $out;
	}

	/**
	 * @param array<string,mixed>      $hold Hold.
	 * @param list<array<string,mixed>> $rows Rows.
	 * @return array{ok:bool,path?:string,error?:string}
	 */
	public static function write_snapshot_bundle( string $hold_id, array $hold, array $rows ): array {
		$hold_id = sanitize_key( $hold_id );
		if ( '' === $hold_id ) {
			return array(
				'ok'    => false,
				'error' => 'missing_id',
			);
		}
		$dir = self::hold_dir( $hold_id );
		if ( '' === $dir ) {
			return array(
				'ok'    => false,
				'error' => 'no_dir',
			);
		}
		if ( ! is_dir( $dir ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- local uploads snapshot.
			if ( ! @mkdir( $dir, 0755, true ) && ! is_dir( $dir ) ) {
				return array(
					'ok'    => false,
					'error' => 'mkdir_failed',
				);
			}
		}

		$plugins = function_exists( 'get_plugins' ) ? get_plugins() : array();
		if ( ! is_array( $plugins ) ) {
			$plugins = array();
		}
		$policy = class_exists( Policy::class ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}
		$empty_filters = array(
			'decision'  => '',
			'operation' => '',
			'provider'  => '',
			'model'     => '',
			'plugin'    => '',
			'source'    => '',
		);
		$csv = class_exists( Audit_Export::class )
			? Audit_Export::build_csv( $rows, $empty_filters, $plugins, $policy )
			: '';

		$manifest = array(
			'hold_id'       => $hold_id,
			'name'          => (string) ( $hold['name'] ?? '' ),
			'scope'         => (string) ( $hold['scope'] ?? '' ),
			'reason'        => (string) ( $hold['reason'] ?? '' ),
			'created_at'    => (int) ( $hold['created_at'] ?? 0 ),
			'created_by'    => (int) ( $hold['created_by'] ?? 0 ),
			'matched_count' => count( $rows ),
			'users'         => isset( $hold['users'] ) && is_array( $hold['users'] ) ? $hold['users'] : array(),
			'plugins'       => isset( $hold['plugins'] ) && is_array( $hold['plugins'] ) ? $hold['plugins'] : array(),
			'providers'     => isset( $hold['providers'] ) && is_array( $hold['providers'] ) ? $hold['providers'] : array(),
			'date_from'     => (int) ( $hold['date_from'] ?? 0 ),
			'date_to'       => (int) ( $hold['date_to'] ?? 0 ),
		);
		$json = function_exists( 'wp_json_encode' )
			? wp_json_encode( $manifest, JSON_PRETTY_PRINT )
			: (string) json_encode( $manifest );

		$base          = rtrim( $dir, '/\\' ) . '/';
		$manifest_path = $base . 'manifest.json';
		$csv_path      = $base . 'activity.csv';
		$json_path     = $base . 'activity.json';

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		@file_put_contents( $manifest_path, is_string( $json ) ? $json : '{}' );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		@file_put_contents( $csv_path, is_string( $csv ) ? $csv : '' );
		$rows_json = function_exists( 'wp_json_encode' )
			? wp_json_encode( $rows )
			: (string) json_encode( $rows );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		@file_put_contents( $json_path, is_string( $rows_json ) ? $rows_json : '[]' );

		$rel = self::SNAPSHOTS_SUB . '/' . $hold_id;

		return array(
			'ok'   => true,
			'path' => $rel,
		);
	}

	public static function resolve_dir(): string {
		if ( null !== self::$test_dir && '' !== self::$test_dir ) {
			return rtrim( self::$test_dir, '/\\' );
		}
		if ( ! function_exists( 'wp_upload_dir' ) ) {
			return '';
		}
		$uploads = wp_upload_dir();
		if ( ! is_array( $uploads ) || ! empty( $uploads['error'] ) || empty( $uploads['basedir'] ) ) {
			return '';
		}

		return rtrim( (string) $uploads['basedir'], '/\\' ) . '/' . self::DIR_NAME . '/' . self::SNAPSHOTS_SUB;
	}

	public static function hold_dir( string $id ): string {
		$base = self::resolve_dir();
		$id   = sanitize_key( $id );
		if ( '' === $base || '' === $id ) {
			return '';
		}

		return $base . '/' . $id;
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function roster_rows(): array {
		$rows = array();
		foreach ( self::get_holds() as $hold ) {
			$rows[] = array(
				'id'            => (string) $hold['id'],
				'name'          => (string) $hold['name'],
				'scope'         => (string) $hold['scope'],
				'status'        => empty( $hold['released_at'] ) ? 'active' : 'released',
				'reason'        => (string) $hold['reason'],
				'created_at'    => (int) $hold['created_at'],
				'created_by'    => (int) $hold['created_by'],
				'released_at'   => (int) $hold['released_at'],
				'matched_count' => (int) $hold['matched_count'],
				'scope_detail'  => self::scope_detail( $hold ),
				'snapshot_path' => (string) $hold['snapshot_path'],
			);
		}
		usort(
			$rows,
			static function ( $a, $b ): int {
				return ( (int) ( $b['created_at'] ?? 0 ) ) <=> ( (int) ( $a['created_at'] ?? 0 ) );
			}
		);

		return $rows;
	}

	/**
	 * @param array<string,mixed> $hold Hold.
	 */
	public static function scope_detail( array $hold ): string {
		$scope = (string) ( $hold['scope'] ?? '' );
		if ( self::SCOPE_SITE === $scope ) {
			return 'site-wide';
		}
		if ( self::SCOPE_USER === $scope ) {
			$users = isset( $hold['users'] ) && is_array( $hold['users'] ) ? $hold['users'] : array();

			return 'user:' . implode( ',', array_map( 'strval', $users ) );
		}
		if ( self::SCOPE_PLUGIN === $scope ) {
			$plugins = isset( $hold['plugins'] ) && is_array( $hold['plugins'] ) ? $hold['plugins'] : array();

			return 'plugin:' . implode( ',', $plugins );
		}
		if ( self::SCOPE_PROVIDER === $scope ) {
			$providers = isset( $hold['providers'] ) && is_array( $hold['providers'] ) ? $hold['providers'] : array();

			return 'provider:' . implode( ',', $providers );
		}
		if ( self::SCOPE_RANGE === $scope ) {
			return 'range:' . (int) ( $hold['date_from'] ?? 0 ) . '-' . (int) ( $hold['date_to'] ?? 0 );
		}

		return $scope;
	}

	/**
	 * @param list<array<string,mixed>>|null $rows Roster rows.
	 */
	public static function csv_for_roster( ?array $rows = null ): string {
		$rows = null !== $rows ? $rows : self::roster_rows();
		$fh   = fopen( 'php://temp', 'r+' );
		if ( false === $fh ) {
			return '';
		}
		fputcsv(
			$fh,
			array( 'id', 'name', 'scope', 'status', 'scope_detail', 'reason', 'created_at', 'created_by', 'released_at', 'matched_count', 'snapshot_path' )
		);
		foreach ( $rows as $row ) {
			fputcsv(
				$fh,
				array(
					(string) ( $row['id'] ?? '' ),
					(string) ( $row['name'] ?? '' ),
					(string) ( $row['scope'] ?? '' ),
					(string) ( $row['status'] ?? '' ),
					(string) ( $row['scope_detail'] ?? '' ),
					(string) ( $row['reason'] ?? '' ),
					(string) (int) ( $row['created_at'] ?? 0 ),
					(string) (int) ( $row['created_by'] ?? 0 ),
					(string) (int) ( $row['released_at'] ?? 0 ),
					(string) (int) ( $row['matched_count'] ?? 0 ),
					(string) ( $row['snapshot_path'] ?? '' ),
				)
			);
		}
		rewind( $fh );
		$csv = stream_get_contents( $fh );
		fclose( $fh );

		return is_string( $csv ) ? $csv : '';
	}

	public static function csv_for_ledger(): string {
		$fh = fopen( 'php://temp', 'r+' );
		if ( false === $fh ) {
			return '';
		}
		fputcsv( $fh, array( 'ts', 'action', 'hold_id', 'actor', 'reason', 'scope', 'name', 'matched' ) );
		foreach ( self::get_ledger() as $row ) {
			fputcsv(
				$fh,
				array(
					(string) (int) ( $row['ts'] ?? 0 ),
					(string) ( $row['action'] ?? '' ),
					(string) ( $row['hold_id'] ?? '' ),
					(string) (int) ( $row['actor'] ?? 0 ),
					(string) ( $row['reason'] ?? '' ),
					(string) ( $row['scope'] ?? '' ),
					(string) ( $row['name'] ?? '' ),
					(string) (int) ( $row['matched'] ?? 0 ),
				)
			);
		}
		rewind( $fh );
		$csv = stream_get_contents( $fh );
		fclose( $fh );

		return is_string( $csv ) ? $csv : '';
	}

	/**
	 * @return array{active:int,released:int,ledger:int,held_rows:int}
	 */
	public static function status_summary(): array {
		$active   = 0;
		$released = 0;
		foreach ( self::get_holds() as $hold ) {
			if ( empty( $hold['released_at'] ) ) {
				++$active;
			} else {
				++$released;
			}
		}

		return array(
			'active'    => $active,
			'released'  => $released,
			'ledger'    => count( self::get_ledger() ),
			'held_rows' => count( self::matching_rows( null ) ),
		);
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
			__( 'Legal holds', 'handl-ai-connector-access-control' ),
			__( 'Legal hold', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$can_manage = Caps::user_can_manage();
		$roster     = self::roster_rows();
		$summary    = self::status_summary();
		$csv        = add_query_arg(
			array(
				'page'                        => self::PAGE_SLUG,
				'handl_aicac_legal_hold_csv'  => '1',
				'handl_aicac_legal_hold_kind' => 'roster',
				'_wpnonce'                    => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_legal_hold_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$ledger_csv = add_query_arg(
			array(
				'page'                        => self::PAGE_SLUG,
				'handl_aicac_legal_hold_csv'  => '1',
				'handl_aicac_legal_hold_kind' => 'ledger',
				'_wpnonce'                    => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_legal_hold_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Legal holds', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Preserve matching AI activity log rows so retention purge cannot delete them. Never denies AI calls. Off until you create a hold.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p>' . esc_html(
			sprintf(
				/* translators: 1: active holds, 2: released, 3: held rows still in log */
				__( 'Active holds: %1$d · released: %2$d · held rows in log: %3$d', 'handl-ai-connector-access-control' ),
				(int) $summary['active'],
				(int) $summary['released'],
				(int) $summary['held_rows']
			)
		) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<h2>' . esc_html__( 'Create hold', 'handl-ai-connector-access-control' ) . '</h2>';
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_CREATE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_CREATE );
			}
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row"><label for="handl-aicac-lh-name">' . esc_html__( 'Name', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="name" id="handl-aicac-lh-name" type="text" class="regular-text" maxlength="' . esc_attr( (string) self::NAME_MAX ) . '" />';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-lh-scope">' . esc_html__( 'Scope', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<select name="scope" id="handl-aicac-lh-scope">';
			echo '<option value="site">' . esc_html__( 'Site-wide', 'handl-ai-connector-access-control' ) . '</option>';
			echo '<option value="user">' . esc_html__( 'User ID(s)', 'handl-ai-connector-access-control' ) . '</option>';
			echo '<option value="plugin">' . esc_html__( 'Plugin(s)', 'handl-ai-connector-access-control' ) . '</option>';
			echo '<option value="provider">' . esc_html__( 'Provider(s)', 'handl-ai-connector-access-control' ) . '</option>';
			echo '<option value="date_range">' . esc_html__( 'Date range', 'handl-ai-connector-access-control' ) . '</option>';
			echo '</select>';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-lh-users">' . esc_html__( 'User IDs', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="users" id="handl-aicac-lh-users" type="text" class="regular-text" placeholder="12,34" />';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-lh-plugins">' . esc_html__( 'Plugins', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="plugins" id="handl-aicac-lh-plugins" type="text" class="regular-text" placeholder="acme/acme.php" />';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-lh-providers">' . esc_html__( 'Providers', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="providers" id="handl-aicac-lh-providers" type="text" class="regular-text" placeholder="openai,anthropic" />';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-lh-from">' . esc_html__( 'From (YYYY-MM-DD or unix)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="date_from" id="handl-aicac-lh-from" type="text" class="regular-text" />';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-lh-to">' . esc_html__( 'To (YYYY-MM-DD or unix)', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<input name="date_to" id="handl-aicac-lh-to" type="text" class="regular-text" />';
			echo '</td></tr>';
			echo '<tr><th scope="row"><label for="handl-aicac-lh-reason">' . esc_html__( 'Reason', 'handl-ai-connector-access-control' ) . '</label></th><td>';
			echo '<textarea name="reason" id="handl-aicac-lh-reason" class="large-text" rows="3" required></textarea>';
			echo '<p class="description">' . esc_html__( 'Required. Stored forever in the append-only hold ledger.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Create legal hold', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		echo '<h2>' . esc_html__( 'Hold roster', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download roster CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $ledger_csv ) . '">' . esc_html__( 'Download ledger CSV', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		if ( empty( $roster ) ) {
			echo '<p>' . esc_html__( 'No legal holds yet.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Name', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Scope', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Status', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Matched', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Reason', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Actions', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $roster as $row ) {
			echo '<tr>';
			echo '<td>' . esc_html( (string) $row['name'] ) . '<br><code>' . esc_html( (string) $row['id'] ) . '</code></td>';
			echo '<td>' . esc_html( (string) $row['scope_detail'] ) . '</td>';
			echo '<td>' . esc_html( (string) $row['status'] ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $row['matched_count'] ) . '</td>';
			echo '<td>' . esc_html( (string) $row['reason'] ) . '</td>';
			echo '<td>';
			if ( $can_manage && 'active' === (string) $row['status'] ) {
				$rel = admin_url( 'admin-post.php' );
				echo '<form method="post" action="' . esc_url( $rel ) . '" style="display:inline">';
				echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_RELEASE ) . '" />';
				echo '<input type="hidden" name="hold_id" value="' . esc_attr( (string) $row['id'] ) . '" />';
				if ( function_exists( 'wp_nonce_field' ) ) {
					wp_nonce_field( self::ACTION_RELEASE );
				}
				echo '<input name="reason" type="text" class="regular-text" placeholder="' . esc_attr__( 'Release reason', 'handl-ai-connector-access-control' ) . '" /> ';
				submit_button( __( 'Release', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
				echo '</form>';
			} else {
				echo '&mdash;';
			}
			echo '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
		echo '</div>';
	}

	public static function handle_create(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You cannot create legal holds.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_CREATE );
		$result = self::create_hold(
			array(
				'name'      => isset( $_POST['name'] ) ? wp_unslash( (string) $_POST['name'] ) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				'scope'     => isset( $_POST['scope'] ) ? wp_unslash( (string) $_POST['scope'] ) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				'users'     => isset( $_POST['users'] ) ? wp_unslash( (string) $_POST['users'] ) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				'plugins'   => isset( $_POST['plugins'] ) ? wp_unslash( (string) $_POST['plugins'] ) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				'providers' => isset( $_POST['providers'] ) ? wp_unslash( (string) $_POST['providers'] ) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				'date_from' => isset( $_POST['date_from'] ) ? wp_unslash( (string) $_POST['date_from'] ) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				'date_to'   => isset( $_POST['date_to'] ) ? wp_unslash( (string) $_POST['date_to'] ) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				'reason'    => isset( $_POST['reason'] ) ? wp_unslash( (string) $_POST['reason'] ) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			)
		);
		$url = add_query_arg(
			array(
				'page'                 => self::PAGE_SLUG,
				'handl_aicac_lh_flash' => ! empty( $result['ok'] ) ? 'created' : 'create_error',
			),
			admin_url( 'admin.php' )
		);
		wp_safe_redirect( $url );
		exit;
	}

	public static function handle_release(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You cannot release legal holds.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_RELEASE );
		$id     = isset( $_POST['hold_id'] ) ? sanitize_key( wp_unslash( (string) $_POST['hold_id'] ) ) : '';
		$reason = isset( $_POST['reason'] ) ? wp_unslash( (string) $_POST['reason'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$result = self::release_hold( $id, $reason );
		$url    = add_query_arg(
			array(
				'page'                 => self::PAGE_SLUG,
				'handl_aicac_lh_flash' => ! empty( $result['ok'] ) ? 'released' : 'release_error',
			),
			admin_url( 'admin.php' )
		);
		wp_safe_redirect( $url );
		exit;
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_legal_hold_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			wp_die( esc_html__( 'You cannot export legal holds.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( 'handl_aicac_legal_hold_csv' );
		$kind = isset( $_GET['handl_aicac_legal_hold_kind'] ) ? sanitize_key( wp_unslash( (string) $_GET['handl_aicac_legal_hold_kind'] ) ) : 'roster';
		$csv  = ( 'ledger' === $kind ) ? self::csv_for_ledger() : self::csv_for_roster();
		$filename = ( 'ledger' === $kind ) ? 'aicac-legal-hold-ledger.csv' : 'aicac-legal-hold-roster.csv';
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
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
		\WP_CLI::add_command( 'handl-aicac legal-hold', CLI_Legal_Hold::class );
	}

	/**
	 * @param array<string,mixed> $row Log row.
	 */
	public static function row_identity( array $row ): string {
		$ts       = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		$plugin   = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
		$decision = isset( $row['decision'] ) ? (string) $row['decision'] : '';
		$op       = isset( $row['operation'] ) ? (string) $row['operation'] : '';
		$json     = function_exists( 'wp_json_encode' ) ? wp_json_encode( $row ) : (string) json_encode( $row );

		return $ts . '|' . $plugin . '|' . $decision . '|' . $op . '|' . md5( is_string( $json ) ? $json : '' );
	}

	/**
	 * Recursively remove snapshot directory tree (uninstall / tests).
	 */
	public static function purge_snapshot_files( ?string $base = null ): void {
		$dir = null !== $base ? rtrim( $base, '/\\' ) : self::resolve_dir();
		if ( '' === $dir || ! is_dir( $dir ) ) {
			return;
		}
		self::rm_rf( $dir );
	}

	/**
	 * @param mixed $raw Date string or unix.
	 */
	private static function parse_date_arg( $raw ): int {
		if ( is_numeric( $raw ) ) {
			$n = (int) $raw;
			return $n > 0 ? $n : 0;
		}
		$raw = trim( (string) $raw );
		if ( '' === $raw ) {
			return 0;
		}
		if ( preg_match( '/^\d{4}-\d{2}-\d{2}$/', $raw ) ) {
			$ts = strtotime( $raw . ' UTC' );

			return false !== $ts ? (int) $ts : 0;
		}
		$ts = strtotime( $raw );

		return false !== $ts ? (int) $ts : 0;
	}

	private static function new_hold_id( int $now ): string {
		$rand = function_exists( 'wp_generate_password' )
			? wp_generate_password( 8, false, false )
			: substr( md5( (string) mt_rand() ), 0, 8 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.rand_mt_rand -- test/fallback id.

		return 'lh_' . gmdate( 'YmdHis', $now ) . '_' . strtolower( $rand );
	}

	private static function rm_rf( string $dir ): void {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$items = scandir( $dir );
		if ( ! is_array( $items ) ) {
			return;
		}
		foreach ( $items as $item ) {
			if ( '.' === $item || '..' === $item ) {
				continue;
			}
			$path = $dir . '/' . $item;
			if ( is_dir( $path ) ) {
				self::rm_rf( $path );
				continue;
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
			@unlink( $path );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
		@rmdir( $dir );
	}
}

/**
 * WP-CLI: wp handl-aicac legal-hold create|release|status|export
 */
final class CLI_Legal_Hold {

	/**
	 * Create a legal hold.
	 *
	 * ## OPTIONS
	 *
	 * --scope=<scope>
	 * : site, user, plugin, provider, or date_range.
	 *
	 * --reason=<reason>
	 * : Required reason (stored in the append-only ledger).
	 *
	 * [--name=<name>]
	 * : Display name.
	 *
	 * [--user=<ids>]
	 * : Comma-separated user IDs (scope=user).
	 *
	 * [--plugin=<basenames>]
	 * : Comma-separated plugin basenames (scope=plugin).
	 *
	 * [--provider=<ids>]
	 * : Comma-separated provider ids (scope=provider).
	 *
	 * [--from=<date>]
	 * : Range start YYYY-MM-DD or unix (scope=date_range).
	 *
	 * [--to=<date>]
	 * : Range end YYYY-MM-DD or unix (scope=date_range).
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function create( $args, $assoc_args ): void {
		unset( $args );
		$result = Legal_Hold::create_hold(
			array(
				'scope'     => $assoc_args['scope'] ?? '',
				'reason'    => $assoc_args['reason'] ?? '',
				'name'      => $assoc_args['name'] ?? '',
				'users'     => $assoc_args['user'] ?? '',
				'plugins'   => $assoc_args['plugin'] ?? '',
				'providers' => $assoc_args['provider'] ?? '',
				'date_from' => $assoc_args['from'] ?? '',
				'date_to'   => $assoc_args['to'] ?? '',
			)
		);
		if ( empty( $result['ok'] ) ) {
			\WP_CLI::error( 'Could not create hold: ' . (string) ( $result['error'] ?? 'unknown' ) );
		}
		\WP_CLI::success(
			sprintf(
				'Created hold %s (matched %d rows at creation).',
				(string) ( $result['id'] ?? '' ),
				(int) ( $result['matched'] ?? 0 )
			)
		);
	}

	/**
	 * Release a legal hold.
	 *
	 * ## OPTIONS
	 *
	 * <id>
	 * : Hold id.
	 *
	 * [--reason=<reason>]
	 * : Release reason.
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function release( $args, $assoc_args ): void {
		$id     = isset( $args[0] ) ? sanitize_key( (string) $args[0] ) : '';
		$reason = isset( $assoc_args['reason'] ) ? (string) $assoc_args['reason'] : '';
		$result = Legal_Hold::release_hold( $id, $reason );
		if ( empty( $result['ok'] ) ) {
			\WP_CLI::error( 'Could not release hold: ' . (string) ( $result['error'] ?? 'unknown' ) );
		}
		\WP_CLI::success( 'Released hold ' . $id );
	}

	/**
	 * Show legal-hold status.
	 *
	 * ## OPTIONS
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		$summary = Legal_Hold::status_summary();
		\WP_CLI::log(
			sprintf(
				'active=%d released=%d ledger=%d held_rows=%d',
				(int) $summary['active'],
				(int) $summary['released'],
				(int) $summary['ledger'],
				(int) $summary['held_rows']
			)
		);
		foreach ( Legal_Hold::roster_rows() as $row ) {
			\WP_CLI::log(
				sprintf(
					'%s %s scope=%s status=%s matched=%d reason=%s',
					(string) $row['id'],
					(string) $row['name'],
					(string) $row['scope_detail'],
					(string) $row['status'],
					(int) $row['matched_count'],
					(string) $row['reason']
				)
			);
		}
	}

	/**
	 * Export roster or ledger.
	 *
	 * ## OPTIONS
	 *
	 * [--kind=<kind>]
	 * : roster or ledger. Default roster.
	 *
	 * [--format=<format>]
	 * : table, json, csv, or yaml. Default csv.
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function export( $args, $assoc_args ): void {
		unset( $args );
		$kind   = isset( $assoc_args['kind'] ) ? sanitize_key( (string) $assoc_args['kind'] ) : 'roster';
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'csv';
		if ( 'csv' === $format ) {
			echo ( 'ledger' === $kind ) ? Legal_Hold::csv_for_ledger() : Legal_Hold::csv_for_roster(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			return;
		}
		if ( 'ledger' === $kind ) {
			$rows = Legal_Hold::get_ledger();
			$cols = array( 'ts', 'action', 'hold_id', 'actor', 'reason', 'scope', 'name', 'matched' );
		} else {
			$rows = Legal_Hold::roster_rows();
			$cols = array( 'id', 'name', 'scope', 'status', 'scope_detail', 'reason', 'created_at', 'matched_count' );
		}
		if ( empty( $rows ) ) {
			\WP_CLI::log( 'No rows.' );
			return;
		}
		\WP_CLI\Utils\format_items( $format, $rows, $cols );
	}
}
