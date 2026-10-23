<?php
/**
 * AICAC-RELIC (#431): legacy AI-content census.
 *
 * Joins the Touched provenance ledger with the Model-EOL retirement calendar
 * (both class_exists-guarded, read-only). Posts shaped by a retired model are
 * RELIC; posts shaped by a model retiring within 90 days are AGING. Per-post
 * ack silences a finding until the post is later touched by another
 * retiring/retired model. One re-arming [RELIC] alert on new unacked findings.
 * Own two options. OFF by default. Throttled admin_init scan. Never edits or
 * flags content publicly. No policy.php / Activity row writes.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Content that still carries a retired or soon-retiring model fingerprint.
 */
final class Relic {

	public const SETTINGS_OPTION = 'handl_aicac_relic';

	public const STATE_OPTION = 'handl_aicac_relic_state';

	public const PAGE_SLUG = 'handl-aicac-relic';

	public const ALERT_KIND = 'relic';

	public const VERDICT_RELIC = 'RELIC';

	public const VERDICT_AGING = 'AGING';

	public const VERDICT_SKIP = 'SKIP';

	/** Days until EOL that still count as AGING (inclusive of today). */
	public const AGING_DAYS = 90;

	/** Admin check throttle in seconds (5 minutes). */
	public const CHECK_THROTTLE_SECONDS = 300;

	public const FINDINGS_CAP = 500;

	public const POST_PRESENT = 'handl_aicac_relic_present';

	public const POST_ENABLED = 'handl_aicac_relic_enabled';

	public const ACTION_SAVE = 'handl_aicac_relic_save';

	public const ACTION_ACK = 'handl_aicac_relic_ack';

	/** @var bool */
	private static $registered = false;

	/** @var list<array{to:string,subject:string,body:string}> */
	private static $test_mails = array();

	/** @var int|null */
	private static $test_now = null;

	/** @var list<int>|null Injected Touched index ids. */
	private static $test_post_ids = null;

	/**
	 * Injected history map: post_id => history rows.
	 *
	 * @var array<int,list<array<string,mixed>>>|null
	 */
	private static $test_histories = null;

	/**
	 * Injected calendar rows (Model_Eol shape).
	 *
	 * @var list<array{provider:string,model:string,eol:string,replacement?:string,source?:string}>|null
	 */
	private static $test_calendar = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_ACK, array( self::class, 'handle_ack' ) );

		if ( self::is_enabled() ) {
			add_action( 'admin_init', array( self::class, 'maybe_check' ), 30 );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered     = false;
		self::$test_mails     = array();
		self::$test_now       = null;
		self::$test_post_ids  = null;
		self::$test_histories = null;
		self::$test_calendar  = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATE_OPTION );
	}

	/**
	 * @return list<array{to:string,subject:string,body:string}>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	/**
	 * @param list<int>|null $ids Touched post ids.
	 */
	public static function set_test_post_ids( ?array $ids ): void {
		self::$test_post_ids = $ids;
	}

	/**
	 * @param array<int,list<array<string,mixed>>>|null $histories Histories by post.
	 */
	public static function set_test_histories( ?array $histories ): void {
		self::$test_histories = $histories;
	}

	/**
	 * @param list<array{provider:string,model:string,eol:string,replacement?:string,source?:string}>|null $calendar Calendar.
	 */
	public static function set_test_calendar( ?array $calendar ): void {
		self::$test_calendar = $calendar;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

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
		if ( ! is_array( $raw ) ) {
			return self::defaults();
		}

		return array( 'enabled' => ! empty( $raw['enabled'] ) );
	}

	/**
	 * @param array<string,mixed> $settings Settings.
	 * @return bool True when the stored value changed.
	 */
	public static function save_settings( array $settings ): bool {
		$clean  = self::sanitize_settings( $settings );
		$before = self::get_settings();
		if ( $clean === $before ) {
			return false;
		}
		if ( $clean === self::defaults() ) {
			delete_option( self::SETTINGS_OPTION );
		} else {
			update_option( self::SETTINGS_OPTION, $clean, false );
		}

		return true;
	}

	public static function is_enabled(): bool {
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] );
	}

	/* ---------------------------------------------------------------------
	 * State
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{
	 *   alerted:bool,
	 *   last_check_ts:int,
	 *   last_alert_ts:int,
	 *   acks:array<string,array{ts:int,models:list<string>}>
	 * }
	 */
	public static function defaults_state(): array {
		return array(
			'alerted'       => false,
			'last_check_ts' => 0,
			'last_alert_ts' => 0,
			'acks'          => array(),
		);
	}

	/**
	 * @return array{
	 *   alerted:bool,
	 *   last_check_ts:int,
	 *   last_alert_ts:int,
	 *   acks:array<string,array{ts:int,models:list<string>}>
	 * }
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw state.
	 * @return array{
	 *   alerted:bool,
	 *   last_check_ts:int,
	 *   last_alert_ts:int,
	 *   acks:array<string,array{ts:int,models:list<string>}>
	 * }
	 */
	public static function sanitize_state( $raw ): array {
		$state = self::defaults_state();
		if ( ! is_array( $raw ) ) {
			return $state;
		}

		$state['alerted']       = ! empty( $raw['alerted'] );
		$state['last_check_ts'] = max( 0, (int) ( $raw['last_check_ts'] ?? 0 ) );
		$state['last_alert_ts'] = max( 0, (int) ( $raw['last_alert_ts'] ?? 0 ) );

		if ( ! empty( $raw['acks'] ) && is_array( $raw['acks'] ) ) {
			foreach ( $raw['acks'] as $post_key => $ack ) {
				$post_id = (int) $post_key;
				if ( $post_id <= 0 || ! is_array( $ack ) ) {
					continue;
				}
				$models = array();
				if ( isset( $ack['models'] ) && is_array( $ack['models'] ) ) {
					foreach ( $ack['models'] as $mk ) {
						$mk = self::sanitize_model_key( (string) $mk );
						if ( '' !== $mk ) {
							$models[ $mk ] = true;
						}
					}
				}
				$state['acks'][ (string) $post_id ] = array(
					'ts'     => max( 0, (int) ( $ack['ts'] ?? 0 ) ),
					'models' => array_keys( $models ),
				);
				if ( count( $state['acks'] ) >= self::FINDINGS_CAP ) {
					break;
				}
			}
		}

		return $state;
	}

	/**
	 * @param array<string,mixed> $state State.
	 */
	public static function put_state( array $state ): void {
		$clean = self::sanitize_state( $state );
		if ( $clean === self::defaults_state() ) {
			delete_option( self::STATE_OPTION );

			return;
		}
		update_option( self::STATE_OPTION, $clean, false );
	}

	private static function resolve_now( ?int $now ): int {
		if ( null !== $now && $now > 0 ) {
			return $now;
		}
		if ( null !== self::$test_now ) {
			return self::$test_now;
		}

		return class_exists( Clock::class, false ) ? Clock::now() : time();
	}

	public static function model_key( string $provider, string $model ): string {
		$provider = self::normalize_provider( $provider );
		$model    = self::normalize_model( $model );
		if ( '' === $provider || '' === $model ) {
			return '';
		}

		return $provider . '|' . $model;
	}

	public static function sanitize_model_key( string $key ): string {
		$key = strtolower( trim( $key ) );
		if ( '' === $key || false === strpos( $key, '|' ) ) {
			return '';
		}
		$parts = explode( '|', $key, 2 );

		return self::model_key( (string) ( $parts[0] ?? '' ), (string) ( $parts[1] ?? '' ) );
	}

	private static function normalize_provider( string $provider ): string {
		if ( class_exists( Cost::class, false ) && method_exists( Cost::class, 'normalize_provider_id' ) ) {
			return Cost::normalize_provider_id( $provider );
		}
		$provider = strtolower( trim( $provider ) );
		$provider = preg_replace( '/[^a-z0-9_\-\.]/', '', $provider ) ?? '';

		return $provider;
	}

	private static function normalize_model( string $model ): string {
		if ( class_exists( Model_Eol::class, false ) && method_exists( Model_Eol::class, 'sanitize_model_id' ) ) {
			return Model_Eol::sanitize_model_id( $model );
		}
		$model = strtolower( trim( $model ) );
		$model = preg_replace( '/[^a-z0-9._*:\/+-]+/', '', $model ) ?? '';

		return substr( $model, 0, 128 );
	}

	/* ---------------------------------------------------------------------
	 * Guarded ledger / calendar reads
	 * ------------------------------------------------------------------ */

	/**
	 * @return list<int>
	 */
	private static function touched_post_ids(): array {
		if ( null !== self::$test_post_ids ) {
			$out = array();
			foreach ( self::$test_post_ids as $id ) {
				$id = (int) $id;
				if ( $id > 0 ) {
					$out[] = $id;
				}
			}

			return array_values( array_unique( $out ) );
		}
		if ( ! class_exists( Touched::class, false ) || ! method_exists( Touched::class, 'index_ids' ) ) {
			return array();
		}
		$ids = Touched::index_ids();
		if ( ! is_array( $ids ) ) {
			return array();
		}
		$out = array();
		foreach ( $ids as $id ) {
			$id = (int) $id;
			if ( $id > 0 ) {
				$out[] = $id;
			}
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * @return list<array{ts:int,provider:string,model:string,capability:string,user_id:int,outcome:string}>
	 */
	private static function history_for_post( int $post_id ): array {
		if ( null !== self::$test_histories ) {
			$rows = self::$test_histories[ $post_id ] ?? array();
			if ( ! is_array( $rows ) ) {
				return array();
			}
			$out = array();
			foreach ( $rows as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$out[] = array(
					'ts'         => (int) ( $row['ts'] ?? 0 ),
					'provider'   => self::normalize_provider( (string) ( $row['provider'] ?? '' ) ),
					'model'      => self::normalize_model( (string) ( $row['model'] ?? '' ) ),
					'capability' => (string) ( $row['capability'] ?? '' ),
					'user_id'    => max( 0, (int) ( $row['user_id'] ?? 0 ) ),
					'outcome'    => (string) ( $row['outcome'] ?? 'success' ),
				);
			}

			return $out;
		}
		if ( ! class_exists( Touched::class, false ) || ! method_exists( Touched::class, 'history_for_post' ) ) {
			return array();
		}
		$history = Touched::history_for_post( $post_id );

		return is_array( $history ) ? $history : array();
	}

	/**
	 * @return list<array{provider:string,model:string,eol:string,replacement:string,source:string}>
	 */
	private static function calendar_rows(): array {
		if ( null !== self::$test_calendar ) {
			$out = array();
			foreach ( self::$test_calendar as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$provider = self::normalize_provider( (string) ( $row['provider'] ?? '' ) );
				$model    = self::normalize_model( (string) ( $row['model'] ?? '' ) );
				$eol      = '';
				if ( class_exists( Model_Eol::class, false ) && method_exists( Model_Eol::class, 'sanitize_date' ) ) {
					$eol = Model_Eol::sanitize_date( (string) ( $row['eol'] ?? '' ) );
				} else {
					$eol = preg_match( '/^\d{4}-\d{2}-\d{2}$/', (string) ( $row['eol'] ?? '' ) ) ? (string) $row['eol'] : '';
				}
				if ( '' === $provider || '' === $model || '' === $eol ) {
					continue;
				}
				$out[] = array(
					'provider'    => $provider,
					'model'       => $model,
					'eol'         => $eol,
					'replacement' => self::normalize_model( (string) ( $row['replacement'] ?? '' ) ),
					'source'      => sanitize_key( (string) ( $row['source'] ?? 'test' ) ),
				);
			}

			return $out;
		}
		if ( ! class_exists( Model_Eol::class, false ) || ! method_exists( Model_Eol::class, 'calendar' ) ) {
			return array();
		}
		$cal = Model_Eol::calendar();

		return is_array( $cal ) ? $cal : array();
	}

	/**
	 * @param list<array{provider:string,model:string,eol:string,replacement:string,source?:string}> $calendar
	 * @return array{provider:string,model:string,eol:string,replacement:string,source:string}|null
	 */
	private static function match_calendar( string $provider, string $model, array $calendar ): ?array {
		if ( class_exists( Model_Eol::class, false ) && method_exists( Model_Eol::class, 'match_calendar_row' ) ) {
			$match = Model_Eol::match_calendar_row( $provider, $model, $calendar );

			return is_array( $match ) ? $match : null;
		}
		$provider = self::normalize_provider( $provider );
		$model    = self::normalize_model( $model );
		foreach ( $calendar as $row ) {
			if ( $provider === (string) ( $row['provider'] ?? '' ) && $model === (string) ( $row['model'] ?? '' ) ) {
				return array(
					'provider'    => $provider,
					'model'       => (string) $row['model'],
					'eol'         => (string) $row['eol'],
					'replacement' => (string) ( $row['replacement'] ?? '' ),
					'source'      => (string) ( $row['source'] ?? 'bundled' ),
				);
			}
		}

		return null;
	}

	private static function days_until( string $eol, int $now ): ?int {
		if ( class_exists( Model_Eol::class, false ) && method_exists( Model_Eol::class, 'days_until_eol' ) ) {
			$days = Model_Eol::days_until_eol( $eol, $now );

			return null === $days ? null : (int) $days;
		}
		$eol_ts = strtotime( $eol . ' 00:00:00 UTC' );
		if ( false === $eol_ts ) {
			return null;
		}
		$now_mid = gmmktime( 0, 0, 0, (int) gmdate( 'n', $now ), (int) gmdate( 'j', $now ), (int) gmdate( 'Y', $now ) );
		if ( false === $now_mid ) {
			return null;
		}
		$day = defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;

		return (int) floor( ( (int) $eol_ts - (int) $now_mid ) / $day );
	}

	/* ---------------------------------------------------------------------
	 * Census
	 * ------------------------------------------------------------------ */

	/**
	 * Classify one post against the calendar.
	 *
	 * @param list<array{ts:int,provider:string,model:string,capability?:string,user_id?:int,outcome?:string}> $history
	 * @param list<array{provider:string,model:string,eol:string,replacement:string,source?:string}> $calendar
	 * @param array{ts:int,models:list<string>}|null $ack Ack record for this post.
	 * @return array{
	 *   post_id:int,
	 *   verdict:string,
	 *   provider:string,
	 *   model:string,
	 *   eol:string,
	 *   days_left:int|null,
	 *   model_key:string,
	 *   finding_models:list<string>,
	 *   acked:bool,
	 *   skip_reason:string,
	 *   summary:string
	 * }
	 */
	public static function classify_post( int $post_id, array $history, array $calendar, ?array $ack, int $now ): array {
		$base = array(
			'post_id'         => $post_id,
			'verdict'         => self::VERDICT_SKIP,
			'provider'        => '',
			'model'           => '',
			'eol'             => '',
			'days_left'       => null,
			'model_key'       => '',
			'finding_models'  => array(),
			'acked'           => false,
			'skip_reason'     => '',
			'summary'         => '',
		);

		if ( $post_id <= 0 ) {
			$base['skip_reason'] = 'not enough provenance history';
			$base['summary']     = __( 'not enough provenance history', 'handl-ai-connector-access-control' );

			return $base;
		}

		if ( empty( $history ) ) {
			$base['skip_reason'] = 'not enough provenance history';
			$base['summary']     = __( 'not enough provenance history', 'handl-ai-connector-access-control' );

			return $base;
		}

		$findings = array();
		foreach ( $history as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$provider = self::normalize_provider( (string) ( $row['provider'] ?? '' ) );
			$model    = self::normalize_model( (string) ( $row['model'] ?? '' ) );
			if ( '' === $provider || '' === $model || 'unknown' === $provider ) {
				continue;
			}
			$match = self::match_calendar( $provider, $model, $calendar );
			if ( null === $match ) {
				continue;
			}
			$days = self::days_until( (string) $match['eol'], $now );
			if ( null === $days ) {
				continue;
			}
			$verdict = '';
			if ( $days < 0 ) {
				$verdict = self::VERDICT_RELIC;
			} elseif ( $days <= self::AGING_DAYS ) {
				$verdict = self::VERDICT_AGING;
			}
			if ( '' === $verdict ) {
				continue;
			}
			$key = self::model_key( $provider, $model );
			if ( '' === $key ) {
				continue;
			}
			// Prefer the worst verdict / soonest EOL for the same model key.
			if ( ! isset( $findings[ $key ] ) || self::verdict_rank( $verdict ) > self::verdict_rank( (string) $findings[ $key ]['verdict'] ) ) {
				$findings[ $key ] = array(
					'provider'  => $provider,
					'model'     => $model,
					'eol'       => (string) $match['eol'],
					'days_left' => $days,
					'verdict'   => $verdict,
					'model_key' => $key,
				);
			}
		}

		if ( empty( $findings ) ) {
			// History existed but no usable model ids matched the calendar.
			$has_model = false;
			foreach ( $history as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$model = self::normalize_model( (string) ( $row['model'] ?? '' ) );
				if ( '' !== $model ) {
					$has_model = true;
					break;
				}
			}
			$base['skip_reason'] = $has_model ? 'no retiring models in provenance' : 'not enough provenance history';
			$base['summary']     = $has_model
				? __( 'no retiring models in provenance', 'handl-ai-connector-access-control' )
				: __( 'not enough provenance history', 'handl-ai-connector-access-control' );

			return $base;
		}

		// Pick the primary finding: RELIC over AGING, then soonest/past-most EOL.
		uasort(
			$findings,
			static function ( array $a, array $b ): int {
				$rank = self::verdict_rank( (string) $a['verdict'] ) <=> self::verdict_rank( (string) $b['verdict'] );
				if ( 0 !== $rank ) {
					return -$rank;
				}
				if ( (int) $a['days_left'] === (int) $b['days_left'] ) {
					return strcmp( (string) $a['model_key'], (string) $b['model_key'] );
				}

				return (int) $a['days_left'] <=> (int) $b['days_left'];
			}
		);

		$primary = reset( $findings );
		$keys    = array_keys( $findings );

		$acked_models = array();
		if ( is_array( $ack ) && isset( $ack['models'] ) && is_array( $ack['models'] ) ) {
			foreach ( $ack['models'] as $mk ) {
				$mk = self::sanitize_model_key( (string) $mk );
				if ( '' !== $mk ) {
					$acked_models[ $mk ] = true;
				}
			}
		}

		$new_models = false;
		foreach ( $keys as $mk ) {
			if ( ! isset( $acked_models[ $mk ] ) ) {
				$new_models = true;
				break;
			}
		}
		$acked = ! empty( $acked_models ) && ! $new_models;

		$summary = self::build_finding_sentence(
			$post_id,
			(string) $primary['provider'],
			(string) $primary['model'],
			(string) $primary['eol'],
			(int) $primary['days_left'],
			(string) $primary['verdict']
		);

		return array(
			'post_id'        => $post_id,
			'verdict'        => (string) $primary['verdict'],
			'provider'       => (string) $primary['provider'],
			'model'          => (string) $primary['model'],
			'eol'            => (string) $primary['eol'],
			'days_left'      => (int) $primary['days_left'],
			'model_key'      => (string) $primary['model_key'],
			'finding_models' => $keys,
			'acked'          => $acked,
			'skip_reason'    => '',
			'summary'        => $summary,
		);
	}

	private static function verdict_rank( string $verdict ): int {
		if ( self::VERDICT_RELIC === $verdict ) {
			return 2;
		}
		if ( self::VERDICT_AGING === $verdict ) {
			return 1;
		}

		return 0;
	}

	public static function build_finding_sentence( int $post_id, string $provider, string $model, string $eol, int $days_left, string $verdict ): string {
		if ( self::VERDICT_RELIC === $verdict ) {
			return sprintf(
				/* translators: 1: post ID, 2: provider, 3: model, 4: Y-m-d retire date */
				__( 'Post #%1$d was shaped by %2$s/%3$s which retired on %4$s (RELIC).', 'handl-ai-connector-access-control' ),
				$post_id,
				$provider,
				$model,
				$eol
			);
		}

		return sprintf(
			/* translators: 1: post ID, 2: provider, 3: model, 4: Y-m-d retire date, 5: days left */
			__( 'Post #%1$d was shaped by %2$s/%3$s which retires on %4$s in %5$d days (AGING).', 'handl-ai-connector-access-control' ),
			$post_id,
			$provider,
			$model,
			$eol,
			max( 0, $days_left )
		);
	}

	/**
	 * Build the full census (writes nothing).
	 *
	 * @return array{
	 *   enabled:bool,
	 *   now:int,
	 *   findings:list<array<string,mixed>>,
	 *   relic_count:int,
	 *   aging_count:int,
	 *   unacked_relic:int,
	 *   unacked_aging:int,
	 *   unacked_total:int,
	 *   alerted:bool,
	 *   last_check_ts:int,
	 *   last_alert_ts:int,
	 *   sources_ready:bool
	 * }
	 */
	public static function snapshot( ?int $now = null ): array {
		$now = self::resolve_now( $now );
		if ( ! self::is_enabled() ) {
			$state = self::get_state();

			return array(
				'enabled'        => false,
				'now'            => $now,
				'findings'       => array(),
				'relic_count'    => 0,
				'aging_count'    => 0,
				'unacked_relic'  => 0,
				'unacked_aging'  => 0,
				'unacked_total'  => 0,
				'alerted'        => ! empty( $state['alerted'] ),
				'last_check_ts'  => (int) $state['last_check_ts'],
				'last_alert_ts'  => (int) $state['last_alert_ts'],
				'sources_ready'  => false,
			);
		}

		$state    = self::get_state();
		$calendar = self::calendar_rows();
		$ids      = self::touched_post_ids();
		$ready    = ( null !== self::$test_histories || class_exists( Touched::class, false ) )
			&& ( null !== self::$test_calendar || class_exists( Model_Eol::class, false ) );

		$findings      = array();
		$relic_count   = 0;
		$aging_count   = 0;
		$unacked_relic = 0;
		$unacked_aging = 0;

		foreach ( $ids as $post_id ) {
			$ack_key = (string) $post_id;
			$ack     = isset( $state['acks'][ $ack_key ] ) ? $state['acks'][ $ack_key ] : null;
			$row     = self::classify_post( $post_id, self::history_for_post( $post_id ), $calendar, $ack, $now );
			if ( self::VERDICT_SKIP === $row['verdict'] ) {
				continue;
			}
			$findings[] = $row;
			if ( self::VERDICT_RELIC === $row['verdict'] ) {
				++$relic_count;
				if ( empty( $row['acked'] ) ) {
					++$unacked_relic;
				}
			} elseif ( self::VERDICT_AGING === $row['verdict'] ) {
				++$aging_count;
				if ( empty( $row['acked'] ) ) {
					++$unacked_aging;
				}
			}
			if ( count( $findings ) >= self::FINDINGS_CAP ) {
				break;
			}
		}

		usort(
			$findings,
			static function ( array $a, array $b ): int {
				$acked_cmp = (int) ! empty( $a['acked'] ) <=> (int) ! empty( $b['acked'] );
				if ( 0 !== $acked_cmp ) {
					return $acked_cmp;
				}
				$rank = self::verdict_rank( (string) $a['verdict'] ) <=> self::verdict_rank( (string) $b['verdict'] );
				if ( 0 !== $rank ) {
					return -$rank;
				}
				$days_a = null === $a['days_left'] ? 99999 : (int) $a['days_left'];
				$days_b = null === $b['days_left'] ? 99999 : (int) $b['days_left'];
				if ( $days_a === $days_b ) {
					return (int) $a['post_id'] <=> (int) $b['post_id'];
				}

				return $days_a <=> $days_b;
			}
		);

		return array(
			'enabled'       => true,
			'now'           => $now,
			'findings'      => $findings,
			'relic_count'   => $relic_count,
			'aging_count'   => $aging_count,
			'unacked_relic' => $unacked_relic,
			'unacked_aging' => $unacked_aging,
			'unacked_total' => $unacked_relic + $unacked_aging,
			'alerted'       => ! empty( $state['alerted'] ),
			'last_check_ts' => (int) $state['last_check_ts'],
			'last_alert_ts' => (int) $state['last_alert_ts'],
			'sources_ready' => $ready,
		);
	}

	/* ---------------------------------------------------------------------
	 * Scan + ack + alerts
	 * ------------------------------------------------------------------ */

	/**
	 * Throttled detection entry point (admin_init only — never cron).
	 *
	 * @param int|null $now   Optional timestamp.
	 * @param bool     $force Skip the throttle.
	 * @return bool True when a scan ran.
	 */
	public static function maybe_check( ?int $now = null, bool $force = false ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now   = self::resolve_now( is_int( $now ) ? $now : null );
		$state = self::get_state();
		$last  = (int) $state['last_check_ts'];
		if ( ! $force && $last > 0 && $now >= $last && ( $now - $last ) < self::CHECK_THROTTLE_SECONDS ) {
			return false;
		}
		self::scan( $now );

		return true;
	}

	/**
	 * Refresh last_check_ts and run the alert latch. Writes own state only.
	 *
	 * @return array<string,mixed> Snapshot after scan.
	 */
	public static function scan( ?int $now = null ): array {
		$now   = self::resolve_now( $now );
		$state = self::get_state();
		$state['last_check_ts'] = $now;
		self::put_state( $state );

		$snap = self::snapshot( $now );
		self::maybe_fire_alerts( $now, $snap );

		return self::snapshot( $now );
	}

	/**
	 * Ack a post's current finding-model set ("reviewed, keeping as-is").
	 *
	 * @param list<string>|null $models Optional model keys; null uses current findings.
	 */
	public static function ack_post( int $post_id, ?array $models = null, ?int $now = null ): bool {
		if ( $post_id <= 0 || ! self::is_enabled() ) {
			return false;
		}
		$now = self::resolve_now( $now );
		if ( null === $models ) {
			$snap = self::snapshot( $now );
			foreach ( (array) $snap['findings'] as $row ) {
				if ( (int) ( $row['post_id'] ?? 0 ) === $post_id ) {
					$models = isset( $row['finding_models'] ) && is_array( $row['finding_models'] )
						? $row['finding_models']
						: array( (string) ( $row['model_key'] ?? '' ) );
					break;
				}
			}
		}
		if ( ! is_array( $models ) || empty( $models ) ) {
			return false;
		}
		$clean = array();
		foreach ( $models as $mk ) {
			$mk = self::sanitize_model_key( (string) $mk );
			if ( '' !== $mk ) {
				$clean[ $mk ] = true;
			}
		}
		if ( empty( $clean ) ) {
			return false;
		}

		$state = self::get_state();
		$state['acks'][ (string) $post_id ] = array(
			'ts'     => $now,
			'models' => array_keys( $clean ),
		);
		// Cap acks map.
		if ( count( $state['acks'] ) > self::FINDINGS_CAP ) {
			$state['acks'] = array_slice( $state['acks'], -self::FINDINGS_CAP, null, true );
		}
		self::put_state( $state );

		// Re-evaluate alert latch after ack.
		self::maybe_fire_alerts( $now );

		return true;
	}

	/**
	 * One alert per unacked-finding episode; re-arms once none remain.
	 *
	 * @param array<string,mixed>|null $snap Optional precomputed snapshot.
	 * @return bool True when a new alert was sent.
	 */
	public static function maybe_fire_alerts( ?int $now = null, ?array $snap = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now  = self::resolve_now( $now );
		$snap = null !== $snap ? $snap : self::snapshot( $now );
		$state = self::get_state();

		if ( (int) ( $snap['unacked_total'] ?? 0 ) <= 0 ) {
			if ( ! empty( $state['alerted'] ) ) {
				$state['alerted']       = false;
				$state['last_alert_ts'] = 0;
				self::put_state( $state );
			}

			return false;
		}
		if ( ! empty( $state['alerted'] ) ) {
			return false;
		}
		if ( ! self::fire_alert( $snap, $now ) ) {
			return false;
		}

		$state                  = self::get_state();
		$state['alerted']       = true;
		$state['last_alert_ts'] = $now;
		self::put_state( $state );

		return true;
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	private static function fire_alert( array $snap, int $now ): bool {
		$policy = class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' )
			? Policy::get_policy()
			: get_option( Plugin::OPTION_KEY, array() );
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}

		$email = '';
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			$email = (string) Alerts::resolve_email( $policy );
		}
		if ( '' === $email ) {
			$email = function_exists( 'sanitize_email' )
				? sanitize_email( (string) get_option( 'admin_email' ) )
				: (string) get_option( 'admin_email' );
		}
		if ( '' === $email ) {
			return false;
		}

		$subject = self::build_subject( $snap );
		$body    = self::build_body( $snap );
		$ok      = false;
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

		if ( $ok && class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'          => 'handl_aicac_relic',
						'unacked_relic' => (int) ( $snap['unacked_relic'] ?? 0 ),
						'unacked_aging' => (int) ( $snap['unacked_aging'] ?? 0 ),
						'site'          => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'            => $now,
					)
				);
			}
		}

		return $ok;
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_subject( array $snap ): string {
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';

		return sprintf(
			/* translators: 1: site name, 2: unacked RELIC count, 3: unacked AGING count */
			__( '[%1$s] [RELIC] %2$d unacked retired-model post(s), %3$d aging', 'handl-ai-connector-access-control' ),
			$site,
			(int) ( $snap['unacked_relic'] ?? 0 ),
			(int) ( $snap['unacked_aging'] ?? 0 )
		);
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_body( array $snap ): string {
		$lines   = array();
		$lines[] = __( 'HandL AI Connector Access Control: legacy AI-content census', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = __( 'Posts shaped by a retired or soon-retiring model need a quiet re-review. Nothing was changed on the public site.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$shown   = 0;
		foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) || ! empty( $row['acked'] ) ) {
				continue;
			}
			$lines[] = '- ' . (string) ( $row['summary'] ?? '' );
			++$shown;
			if ( $shown >= 20 ) {
				break;
			}
		}
		$lines[] = '';
		$lines[] = __( 'Open the re-review queue:', 'handl-ai-connector-access-control' );
		$lines[] = self::admin_url();

		return implode( "\n", $lines ) . "\n";
	}

	public static function admin_url(): string {
		if ( function_exists( 'admin_url' ) ) {
			return (string) admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		}

		return '';
	}

	/* ---------------------------------------------------------------------
	 * CSV / admin / CLI
	 * ------------------------------------------------------------------ */

	/**
	 * @param array<string,mixed>|null $snap Snapshot.
	 */
	public static function csv_for_snapshot( ?array $snap = null ): string {
		if ( null === $snap ) {
			$snap = self::snapshot();
		}
		$lines   = array();
		$lines[] = self::csv_line(
			array(
				'post_id',
				'model',
				'provider',
				'retire_date',
				'verdict',
				'ack_state',
				'days_left',
				'summary',
			)
		);
		foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$lines[] = self::csv_line(
				array(
					(string) (int) ( $row['post_id'] ?? 0 ),
					(string) ( $row['model'] ?? '' ),
					(string) ( $row['provider'] ?? '' ),
					(string) ( $row['eol'] ?? '' ),
					(string) ( $row['verdict'] ?? '' ),
					! empty( $row['acked'] ) ? 'acked' : 'unacked',
					null === ( $row['days_left'] ?? null ) ? '' : (string) (int) $row['days_left'],
					(string) ( $row['summary'] ?? '' ),
				)
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param list<string> $fields CSV fields.
	 */
	private static function csv_line( array $fields ): string {
		$out = array();
		foreach ( $fields as $field ) {
			$field = (string) $field;
			if ( strpbrk( $field, ",\"\n\r" ) !== false ) {
				$field = '"' . str_replace( '"', '""', $field ) . '"';
			}
			$out[] = $field;
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
			__( 'Legacy AI content', 'handl-ai-connector-access-control' ),
			__( 'Legacy AI content', 'handl-ai-connector-access-control' ),
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
		$snap       = self::snapshot();
		$csv        = add_query_arg(
			array(
				'page'                   => self::PAGE_SLUG,
				'handl_aicac_relic_csv'  => '1',
				'_wpnonce'               => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_relic_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Legacy AI content', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Finds posts shaped by a model that has already retired (RELIC) or that retires within 90 days (AGING). Ack means you reviewed it and are keeping it as-is; a later touch by another retiring model re-opens the row. Never edits or flags content on the public site. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable legacy AI census', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( $enabled, true, false ) . ' /> ';
			echo esc_html__( 'Join AI-touched provenance with the model retirement calendar and alert on new unacked findings', 'handl-ai-connector-access-control' );
			echo '</label></td></tr></tbody></table>';
			submit_button( __( 'Save legacy AI content settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Legacy AI census is off. Enable it to build the re-review queue.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';
			return;
		}

		echo '<ul>';
		echo '<li>' . esc_html( sprintf( /* translators: %d: count */ __( 'RELIC posts: %d', 'handl-ai-connector-access-control' ), (int) $snap['relic_count'] ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( /* translators: %d: count */ __( 'AGING posts: %d', 'handl-ai-connector-access-control' ), (int) $snap['aging_count'] ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( /* translators: %d: count */ __( 'Unacked RELIC: %d', 'handl-ai-connector-access-control' ), (int) $snap['unacked_relic'] ) ) . '</li>';
		echo '</ul>';

		echo '<p><a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a></p>';

		if ( empty( $snap['findings'] ) ) {
			echo '<p>' . esc_html__( 'No RELIC or AGING posts in the current census.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';
			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Post', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Model', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Retires', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Verdict', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Ack', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Finding', 'handl-ai-connector-access-control' ) . '</th>';
		if ( $can_manage ) {
			echo '<th>' . esc_html__( 'Action', 'handl-ai-connector-access-control' ) . '</th>';
		}
		echo '</tr></thead><tbody>';

		foreach ( (array) $snap['findings'] as $row ) {
			$post_id = (int) $row['post_id'];
			$edit    = function_exists( 'get_edit_post_link' ) ? get_edit_post_link( $post_id ) : '';
			echo '<tr>';
			echo '<td>';
			if ( is_string( $edit ) && '' !== $edit ) {
				echo '<a href="' . esc_url( $edit ) . '">#' . esc_html( (string) $post_id ) . '</a>';
			} else {
				echo '#' . esc_html( (string) $post_id );
			}
			echo '</td>';
			echo '<td><code>' . esc_html( (string) $row['provider'] ) . '</code> / <strong>' . esc_html( (string) $row['model'] ) . '</strong></td>';
			echo '<td>' . esc_html( (string) $row['eol'] ) . '</td>';
			echo '<td>' . esc_html( (string) $row['verdict'] ) . '</td>';
			echo '<td>' . esc_html( ! empty( $row['acked'] ) ? __( 'acked', 'handl-ai-connector-access-control' ) : __( 'unacked', 'handl-ai-connector-access-control' ) ) . '</td>';
			echo '<td>' . esc_html( (string) $row['summary'] ) . '</td>';
			if ( $can_manage ) {
				echo '<td>';
				if ( empty( $row['acked'] ) ) {
					$action = admin_url( 'admin-post.php' );
					echo '<form method="post" action="' . esc_url( $action ) . '" style="display:inline">';
					echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_ACK ) . '" />';
					echo '<input type="hidden" name="post_id" value="' . esc_attr( (string) $post_id ) . '" />';
					if ( function_exists( 'wp_nonce_field' ) ) {
						wp_nonce_field( self::ACTION_ACK );
					}
					echo '<button type="submit" class="button button-small">' . esc_html__( 'Reviewed, keeping as-is', 'handl-ai-connector-access-control' ) . '</button>';
					echo '</form>';
				} else {
					echo '&mdash;';
				}
				echo '</td>';
			}
			echo '</tr>';
		}
		echo '</tbody></table></div>';
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_relic_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		$nonce = isset( $_GET['_wpnonce'] ) ? (string) wp_unslash( $_GET['_wpnonce'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( function_exists( 'wp_verify_nonce' ) && ! wp_verify_nonce( $nonce, 'handl_aicac_relic_csv' ) ) {
			return;
		}
		$csv = self::csv_for_snapshot();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=handl-aicac-relic.csv' );
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save legacy AI content settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Invalid form', 'handl-ai-connector-access-control' ) );
		}
		self::save_settings( array( 'enabled' => ! empty( $_POST[ self::POST_ENABLED ] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing

		$redirect = self::admin_url();
		if ( '' === $redirect && function_exists( 'admin_url' ) ) {
			$redirect = admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	public static function handle_ack(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to acknowledge legacy AI findings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_ACK );
		$post_id = isset( $_POST['post_id'] ) ? (int) wp_unslash( (string) $_POST['post_id'] ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		self::ack_post( $post_id );

		$redirect = self::admin_url();
		if ( '' === $redirect && function_exists( 'admin_url' ) ) {
			$redirect = admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac relic', CLI_Relic::class );
	}
}

/**
 * WP-CLI: wp handl-aicac relic status|check|export
 */
final class CLI_Relic {

	/**
	 * Exit non-zero only when unacked RELIC rows remain.
	 *
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function exit_code( array $snap ): int {
		return (int) ( $snap['unacked_relic'] ?? 0 ) > 0 ? 1 : 0;
	}

	/**
	 * Show the legacy AI census.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table or json. Default table.
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function status( $args, $assoc_args ): void {
		unset( $args );
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';

		if ( ! Relic::is_enabled() ) {
			\WP_CLI::log( 'enabled=no' );
			\WP_CLI::log( 'Legacy AI census is disabled.' );

			return;
		}

		Relic::maybe_check( null, true );
		$snap = Relic::snapshot();

		\WP_CLI::log(
			sprintf(
				'enabled=yes relic=%d aging=%d unacked_relic=%d unacked_aging=%d alerted=%s',
				(int) $snap['relic_count'],
				(int) $snap['aging_count'],
				(int) $snap['unacked_relic'],
				(int) $snap['unacked_aging'],
				! empty( $snap['alerted'] ) ? 'yes' : 'no'
			)
		);

		$display = array();
		foreach ( (array) $snap['findings'] as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$display[] = array(
				'post_id'  => (string) (int) $row['post_id'],
				'verdict'  => (string) $row['verdict'],
				'model'    => (string) $row['provider'] . '/' . (string) $row['model'],
				'eol'      => (string) $row['eol'],
				'ack'      => ! empty( $row['acked'] ) ? 'acked' : 'unacked',
			);
		}
		if ( ! empty( $display ) ) {
			if ( 'json' === $format ) {
				\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			} elseif ( class_exists( '\WP_CLI\Utils' ) ) {
				\WP_CLI\Utils\format_items( 'table', $display, array( 'post_id', 'verdict', 'model', 'eol', 'ack' ) );
			}
		}
	}

	/**
	 * Exit non-zero when any unacked RELIC row remains.
	 *
	 * ## OPTIONS
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function check( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		if ( ! Relic::is_enabled() ) {
			\WP_CLI::success( 'Legacy AI census is off.' );
			return;
		}
		Relic::maybe_check( null, true );
		$snap = Relic::snapshot();
		if ( 0 === self::exit_code( $snap ) ) {
			\WP_CLI::success( 'No unacked RELIC posts.' );
			return;
		}
		foreach ( (array) $snap['findings'] as $row ) {
			if ( ! is_array( $row ) || Relic::VERDICT_RELIC !== (string) ( $row['verdict'] ?? '' ) || ! empty( $row['acked'] ) ) {
				continue;
			}
			\WP_CLI::log( (string) $row['summary'] );
		}
		\WP_CLI::error(
			sprintf(
				'%d unacked RELIC post(s).',
				(int) $snap['unacked_relic']
			)
		);
	}

	/**
	 * Export the census as CSV.
	 *
	 * ## OPTIONS
	 *
	 * [--porcelain]
	 * : Print CSV only.
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function export( $args, $assoc_args ): void {
		unset( $args );
		$csv = Relic::csv_for_snapshot();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
