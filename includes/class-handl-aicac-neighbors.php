<?php
/**
 * AICAC-NEIGHBORS (#492): anonymized peer benchmark.
 *
 * Phase 1 is fully local. Reads cost/usage/activity behind class_exists
 * and never edits those classes. Bundled table under includes/data/.
 * Zero outbound HTTP. Own options only (handl_aicac_neighbors*). Own
 * admin screen and dashboard card. Digest: consume an existing extra-lines
 * filter if present; skip otherwise — no edits to digest classes.
 *
 * README-FREE.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Read-only local peer-comparison census.
 */
final class Neighbors {

	public const PAGE_SLUG = 'handl-aicac-neighbors';

	public const SETTINGS_OPTION = 'handl_aicac_neighbors';

	public const CENSUS_OPTION = 'handl_aicac_neighbors_census';

	public const GENERATED_OPTION = 'handl_aicac_neighbors_generated_at';

	public const ACTION_SAVE = 'handl_aicac_neighbors_save';

	public const POST_PRESENT = 'handl_aicac_neighbors_present';

	public const POST_ENABLED = 'handl_aicac_neighbors_enabled';

	public const WIDGET_ID = 'handl_aicac_neighbors';

	public const TABLE_VERSION = 1;

	public const TABLE_FORMAT = 'handl_aicac_neighbors_v1';

	public const STATUS_OFF           = 'OFF';
	public const STATUS_EMPTY         = 'EMPTY';
	public const STATUS_INSUFFICIENT  = 'INSUFFICIENT-DATA';
	public const STATUS_OK            = 'OK';

	public const FRAMING = 'report_only_never_sends_telemetry';

	public const WINDOW_SECONDS = 604800;

	/** @var bool */
	private static $registered = false;

	/** @var bool */
	private static $skip_cache = false;

	/** @var list<array<string,mixed>>|null */
	private static $test_log = null;

	/** @var int|null */
	private static $test_now = null;

	/** @var int|null */
	private static $test_posts = null;

	/** @var array<string,mixed>|null */
	private static $test_table = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'wp_dashboard_setup', array( self::class, 'register_dashboard' ) );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		self::maybe_hook_digest();
	}

	public static function reset_for_tests(): void {
		self::$registered  = false;
		self::$skip_cache  = false;
		self::$test_log    = null;
		self::$test_now    = null;
		self::$test_posts  = null;
		self::$test_table  = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::CENSUS_OPTION );
		delete_option( self::GENERATED_OPTION );
	}

	public static function set_skip_cache( bool $skip ): void {
		self::$skip_cache = $skip;
	}

	/**
	 * @param list<array<string,mixed>>|null $log Injected activity rows.
	 */
	public static function set_test_log( ?array $log ): void {
		self::$test_log = $log;
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	public static function set_test_posts( ?int $posts ): void {
		self::$test_posts = $posts;
	}

	/**
	 * @param array<string,mixed>|null $table Injected table.
	 */
	public static function set_test_table( ?array $table ): void {
		self::$test_table = $table;
	}

	public static function now(): int {
		if ( null !== self::$test_now ) {
			return (int) self::$test_now;
		}
		if ( class_exists( Clock::class, false ) && method_exists( Clock::class, 'now' ) ) {
			return (int) Clock::now();
		}

		return time();
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
	 * @param mixed $raw Raw option.
	 * @return array{enabled:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		$out = self::defaults();
		if ( is_array( $raw ) ) {
			$out['enabled'] = ! empty( $raw['enabled'] );
		}

		return $out;
	}

	public static function is_enabled(): bool {
		return ! empty( self::get_settings()['enabled'] );
	}

	/**
	 * @param array<string,mixed> $raw Incoming settings.
	 */
	public static function save_settings( array $raw ): bool {
		$clean  = self::sanitize_settings( $raw );
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

	/**
	 * Versioned bundled table. Never fetched.
	 *
	 * @return array<string,mixed>
	 */
	public static function table(): array {
		if ( null !== self::$test_table ) {
			return self::sanitize_table( self::$test_table );
		}
		$path = ( defined( 'HANDL_AICAC_DIR' ) ? HANDL_AICAC_DIR : dirname( __DIR__ ) ) . '/includes/data/neighbors-table.php';
		$raw  = array();
		if ( is_readable( $path ) ) {
			$loaded = include $path;
			if ( is_array( $loaded ) ) {
				$raw = $loaded;
			}
		}
		$filtered = apply_filters( 'handl_aicac_neighbors_table', $raw );

		return self::sanitize_table( is_array( $filtered ) ? $filtered : $raw );
	}

	/**
	 * @param mixed $raw Raw table.
	 * @return array<string,mixed>
	 */
	public static function sanitize_table( $raw ): array {
		$empty = array(
			'version'            => self::TABLE_VERSION,
			'format'             => self::TABLE_FORMAT,
			'as_of'              => '',
			'site_size_buckets'  => array(),
			'weekly_call_bands'  => array(),
			'deny_rate_bands'    => array(),
			'spend_bands'        => array(),
			'distributions'      => array(),
		);
		if ( ! is_array( $raw ) ) {
			return $empty;
		}
		$out            = $empty;
		$out['version'] = isset( $raw['version'] ) ? (int) $raw['version'] : self::TABLE_VERSION;
		$out['format']  = isset( $raw['format'] ) ? (string) $raw['format'] : self::TABLE_FORMAT;
		$out['as_of']   = isset( $raw['as_of'] ) ? (string) $raw['as_of'] : '';
		foreach ( array( 'site_size_buckets', 'weekly_call_bands', 'deny_rate_bands', 'spend_bands', 'distributions' ) as $key ) {
			$out[ $key ] = isset( $raw[ $key ] ) && is_array( $raw[ $key ] ) ? $raw[ $key ] : array();
		}

		return $out;
	}

	public static function table_version(): int {
		return (int) self::table()['version'];
	}

	/**
	 * Guarded soft-read of the activity log. Never writes it.
	 *
	 * @return array{rows:list<array<string,mixed>>,available:bool}
	 */
	public static function read_activity_log(): array {
		if ( null !== self::$test_log ) {
			return array(
				'rows'      => array_values( self::$test_log ),
				'available' => true,
			);
		}
		$key = class_exists( Plugin::class, false ) ? Plugin::LOG_OPTION_KEY : 'handl_aicac_recent_calls';
		$raw = get_option( $key, null );
		if ( null === $raw || false === $raw || ! is_array( $raw ) ) {
			return array(
				'rows'      => array(),
				'available' => false,
			);
		}
		$rows = array();
		foreach ( $raw as $row ) {
			if ( is_array( $row ) ) {
				$rows[] = $row;
			}
		}

		return array(
			'rows'      => $rows,
			'available' => true,
		);
	}

	public static function published_posts(): int {
		if ( null !== self::$test_posts ) {
			return max( 0, (int) self::$test_posts );
		}
		if ( function_exists( 'wp_count_posts' ) ) {
			$counts = wp_count_posts( 'post' );
			if ( is_object( $counts ) && isset( $counts->publish ) ) {
				return max( 0, (int) $counts->publish );
			}
		}

		return 0;
	}

	public static function site_size_bucket( int $posts ): string {
		$table = self::table();
		$buckets = isset( $table['site_size_buckets'] ) && is_array( $table['site_size_buckets'] ) ? $table['site_size_buckets'] : array();
		$chosen  = 'xs';
		foreach ( $buckets as $id => $spec ) {
			$id  = (string) $id;
			$max = is_array( $spec ) && array_key_exists( 'max_posts', $spec ) ? $spec['max_posts'] : null;
			$chosen = $id;
			if ( null === $max || $posts <= (int) $max ) {
				return $id;
			}
		}

		return $chosen;
	}

	/**
	 * @param array<string,array{max:mixed}> $bands Band map.
	 * @param float                          $value Value.
	 */
	public static function band_for( array $bands, float $value ): string {
		$chosen = '';
		foreach ( $bands as $id => $spec ) {
			$id  = (string) $id;
			$max = is_array( $spec ) && array_key_exists( 'max', $spec ) ? $spec['max'] : null;
			$chosen = $id;
			if ( null === $max || $value <= (float) $max ) {
				return $id;
			}
		}

		return $chosen;
	}

	/**
	 * Percentile rank of $value against discrete p10..p90 points. Deterministic.
	 *
	 * @param array<string,float|int> $points CDF points.
	 */
	public static function percentile_rank( float $value, array $points ): int {
		$order = array( 10, 25, 50, 75, 90 );
		$prev_p = 0;
		$prev_v = 0.0;
		$have   = false;
		foreach ( $order as $p ) {
			$key = 'p' . $p;
			if ( ! isset( $points[ $key ] ) || ! is_numeric( $points[ $key ] ) ) {
				continue;
			}
			$v = (float) $points[ $key ];
			if ( ! $have ) {
				if ( $value <= $v ) {
					return $value <= 0.0 ? 0 : (int) $p;
				}
				$have   = true;
				$prev_p = $p;
				$prev_v = $v;
				continue;
			}
			if ( $value <= $v ) {
				$span = $v - $prev_v;
				if ( $span <= 0.0 ) {
					return (int) $p;
				}

				return (int) round( $prev_p + ( ( $p - $prev_p ) * ( ( $value - $prev_v ) / $span ) ) );
			}
			$prev_p = $p;
			$prev_v = $v;
		}

		return $have ? 95 : 50;
	}

	/**
	 * Local 7-day aggregates from the activity log. Never mutates the log.
	 *
	 * @return array{
	 *   calls:int,
	 *   denies:int,
	 *   deny_rate:float,
	 *   spend_usd:float,
	 *   calls_with_cost:int,
	 *   first_ts:int,
	 *   last_ts:int,
	 *   span:int,
	 *   available:bool
	 * }
	 */
	public static function local_aggregates(): array {
		$pack = self::read_activity_log();
		$now  = self::now();
		$cut  = $now - self::WINDOW_SECONDS;
		$out  = array(
			'calls'           => 0,
			'denies'          => 0,
			'deny_rate'       => 0.0,
			'spend_usd'       => 0.0,
			'calls_with_cost' => 0,
			'first_ts'        => 0,
			'last_ts'         => 0,
			'span'            => 0,
			'available'       => $pack['available'],
		);
		$spend = 0.0;
		foreach ( $pack['rows'] as $row ) {
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts > 0 ) {
				if ( 0 === $out['first_ts'] || $ts < $out['first_ts'] ) {
					$out['first_ts'] = $ts;
				}
				if ( $ts > $out['last_ts'] ) {
					$out['last_ts'] = $ts;
				}
			}
			if ( $ts > 0 && $ts < $cut ) {
				continue;
			}
			$decision = strtolower( (string) ( $row['decision'] ?? '' ) );
			if ( ! in_array( $decision, array( 'allow', 'allowed', 'deny', 'denied' ), true ) ) {
				continue;
			}
			++$out['calls'];
			if ( in_array( $decision, array( 'deny', 'denied' ), true ) ) {
				++$out['denies'];
			}
			$usd = self::row_spend_usd( $row );
			if ( null !== $usd ) {
				$spend += $usd;
				++$out['calls_with_cost'];
			}
		}
		$out['spend_usd'] = $spend;
		$out['deny_rate'] = $out['calls'] > 0 ? ( $out['denies'] / $out['calls'] ) : 0.0;
		if ( $out['first_ts'] > 0 && $out['last_ts'] >= $out['first_ts'] ) {
			$out['span'] = $out['last_ts'] - $out['first_ts'];
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $row Activity row.
	 */
	public static function row_spend_usd( array $row ): ?float {
		if ( isset( $row['estimated_usd'] ) && is_numeric( $row['estimated_usd'] ) ) {
			return (float) $row['estimated_usd'];
		}
		if ( ! class_exists( Cost::class, false ) || ! method_exists( Cost::class, 'estimate_usd' ) ) {
			return null;
		}
		$has_in  = array_key_exists( 'input_tokens', $row );
		$has_out = array_key_exists( 'output_tokens', $row );
		if ( ! $has_in && ! $has_out ) {
			return null;
		}
		$est = Cost::estimate_usd(
			$has_in ? (int) $row['input_tokens'] : null,
			$has_out ? (int) $row['output_tokens'] : null
		);

		return is_numeric( $est ) ? (float) $est : null;
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function census(): array {
		$table = self::table();
		$agg   = self::local_aggregates();
		$posts = self::published_posts();
		$size  = self::site_size_bucket( $posts );
		$dist  = isset( $table['distributions'][ $size ] ) && is_array( $table['distributions'][ $size ] )
			? $table['distributions'][ $size ]
			: array();

		$weekly_band = self::band_for(
			isset( $table['weekly_call_bands'] ) && is_array( $table['weekly_call_bands'] ) ? $table['weekly_call_bands'] : array(),
			(float) $agg['calls']
		);
		$deny_band   = self::band_for(
			isset( $table['deny_rate_bands'] ) && is_array( $table['deny_rate_bands'] ) ? $table['deny_rate_bands'] : array(),
			(float) $agg['deny_rate']
		);
		$spend_band  = self::band_for(
			isset( $table['spend_bands'] ) && is_array( $table['spend_bands'] ) ? $table['spend_bands'] : array(),
			(float) $agg['spend_usd']
		);

		$status = self::STATUS_OK;
		if ( ! self::is_enabled() ) {
			$status = self::STATUS_OFF;
		} elseif ( $agg['calls'] < 1 ) {
			$status = self::STATUS_EMPTY;
		} elseif ( $agg['span'] < self::WINDOW_SECONDS ) {
			$status = self::STATUS_INSUFFICIENT;
		}

		$deny_pts  = isset( $dist['deny_rate'] ) && is_array( $dist['deny_rate'] ) ? $dist['deny_rate'] : array();
		$call_pts  = isset( $dist['weekly_calls'] ) && is_array( $dist['weekly_calls'] ) ? $dist['weekly_calls'] : array();
		$spend_pts = isset( $dist['spend_usd'] ) && is_array( $dist['spend_usd'] ) ? $dist['spend_usd'] : array();

		$with_cost = (int) $agg['calls_with_cost'];
		$calls     = (int) $agg['calls'];
		if ( $with_cost < 1 ) {
			$spend_coverage = 'none';
		} elseif ( $with_cost < $calls ) {
			$spend_coverage = 'partial';
		} else {
			$spend_coverage = 'complete';
		}

		return array(
			'status'           => $status,
			'as_of'            => self::now(),
			'table_version'    => (int) $table['version'],
			'table_format'     => (string) $table['format'],
			'site_size'        => $size,
			'posts'            => $posts,
			'weekly_calls'     => $calls,
			'denies'           => (int) $agg['denies'],
			'deny_rate'        => (float) $agg['deny_rate'],
			'spend_usd'        => (float) $agg['spend_usd'],
			'calls_with_cost'  => $with_cost,
			'spend_coverage'   => $spend_coverage,
			'span'             => (int) $agg['span'],
			'weekly_call_band' => $weekly_band,
			'deny_rate_band'   => $deny_band,
			'spend_band'       => $spend_band,
			'deny_typical'     => array(
				'p25' => isset( $deny_pts['p25'] ) ? (float) $deny_pts['p25'] : 0.0,
				'p75' => isset( $deny_pts['p75'] ) ? (float) $deny_pts['p75'] : 0.0,
			),
			'calls_typical'    => array(
				'p25' => isset( $call_pts['p25'] ) ? (float) $call_pts['p25'] : 0.0,
				'p75' => isset( $call_pts['p75'] ) ? (float) $call_pts['p75'] : 0.0,
			),
			'spend_typical'    => array(
				'p25' => isset( $spend_pts['p25'] ) ? (float) $spend_pts['p25'] : 0.0,
				'p75' => isset( $spend_pts['p75'] ) ? (float) $spend_pts['p75'] : 0.0,
			),
			'deny_percentile'  => self::percentile_rank( (float) $agg['deny_rate'], $deny_pts ),
			'calls_percentile' => self::percentile_rank( (float) $agg['calls'], $call_pts ),
			'spend_percentile' => self::percentile_rank( (float) $agg['spend_usd'], $spend_pts ),
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function snapshot(): array {
		if ( ! self::$skip_cache ) {
			$cached = get_option( self::CENSUS_OPTION, null );
			$as_of  = (int) get_option( self::GENERATED_OPTION, 0 );
			if ( is_array( $cached ) && isset( $cached['status'] ) && $as_of > 0 ) {
				$cached['cached'] = true;
				$cached['as_of']  = $as_of;

				return $cached;
			}
		}

		$data           = self::census();
		$data['cached'] = false;
		if ( ! self::$skip_cache ) {
			$store = $data;
			unset( $store['cached'] );
			update_option( self::CENSUS_OPTION, $store, false );
			update_option( self::GENERATED_OPTION, (int) $data['as_of'], false );
		}

		return $data;
	}

	/**
	 * Percentile sentences from a census snapshot. Empty when not OK.
	 *
	 * @param array<string,mixed> $snap Snapshot.
	 * @return list<string>
	 */
	public static function sentences( array $snap ): array {
		if ( self::STATUS_OK !== ( $snap['status'] ?? '' ) ) {
			return array();
		}
		$deny_p25 = (float) ( $snap['deny_typical']['p25'] ?? 0 );
		$deny_p75 = (float) ( $snap['deny_typical']['p75'] ?? 0 );
		$call_p25 = (float) ( $snap['calls_typical']['p25'] ?? 0 );
		$call_p75 = (float) ( $snap['calls_typical']['p75'] ?? 0 );
		$usd_p25  = (float) ( $snap['spend_typical']['p25'] ?? 0 );
		$usd_p75  = (float) ( $snap['spend_typical']['p75'] ?? 0 );

		$out   = array();
		$out[] = sprintf(
			/* translators: 1: example low deny percent, 2: example high deny percent, 3: this site's recorded deny percent */
			__( 'Example deny-rate range: %1$s–%2$s. This site\'s recorded deny rate over the past 7 days: %3$s.', 'handl-ai-connector-access-control' ),
			self::pct_label( $deny_p25 ),
			self::pct_label( $deny_p75 ),
			self::pct_label( (float) ( $snap['deny_rate'] ?? 0 ) )
		);
		$out[] = sprintf(
			/* translators: 1: example low weekly calls, 2: example high weekly calls, 3: this site's recorded weekly calls */
			__( 'Example weekly call range: %1$s–%2$s. This site\'s recorded calls over the past 7 days: %3$s.', 'handl-ai-connector-access-control' ),
			self::int_label( $call_p25 ),
			self::int_label( $call_p75 ),
			self::int_label( (float) ( $snap['weekly_calls'] ?? 0 ) )
		);

		$coverage = (string) ( $snap['spend_coverage'] ?? 'none' );
		if ( 'complete' === $coverage ) {
			$out[] = sprintf(
				/* translators: 1: example low weekly spend, 2: example high weekly spend, 3: this site's estimated weekly spend */
				__( 'Example weekly spend range (USD): %1$s–%2$s. This site\'s estimated spend over the past 7 days (USD): %3$s.', 'handl-ai-connector-access-control' ),
				self::usd_label( $usd_p25 ),
				self::usd_label( $usd_p75 ),
				self::usd_label( (float) ( $snap['spend_usd'] ?? 0 ) )
			);
		} elseif ( 'partial' === $coverage ) {
			$out[] = sprintf(
				/* translators: %s: estimated spend for calls that have cost data */
				__( 'Estimated spend for calls with cost data over the past 7 days (USD): %s. Some calls have no cost data.', 'handl-ai-connector-access-control' ),
				self::usd_label( (float) ( $snap['spend_usd'] ?? 0 ) )
			);
		} else {
			$out[] = __( 'Spend estimate unavailable.', 'handl-ai-connector-access-control' );
		}

		return $out;
	}

	public static function digest_line(): string {
		if ( ! self::is_enabled() ) {
			return '';
		}
		$lines = self::sentences( self::snapshot() );

		return $lines[0] ?? '';
	}

	/**
	 * @param mixed $lines Digest lines.
	 * @return mixed
	 */
	public static function append_digest_line( $lines ) {
		$line = self::digest_line();
		if ( '' === $line ) {
			return $lines;
		}
		if ( ! is_array( $lines ) ) {
			return $lines;
		}
		$lines[] = $line;

		return $lines;
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
			__( 'Usage reference', 'handl-ai-connector-access-control' ),
			__( 'Usage reference', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function register_dashboard(): void {
		if ( ! self::is_enabled() ) {
			return;
		}
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'wp_add_dashboard_widget' ) ) {
			return;
		}
		wp_add_dashboard_widget(
			self::WIDGET_ID,
			__( 'AI usage reference', 'handl-ai-connector-access-control' ),
			array( self::class, 'render_dashboard' )
		);
	}

	public static function handle_save(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save these settings.', 'handl-ai-connector-access-control' ) );
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
		$url = admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $url );
			exit;
		}
	}

	public static function render_page(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		$enabled    = self::is_enabled();
		$can_manage = Caps::user_can_manage();

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Usage reference', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Compare this site\'s recorded AI activity with example ranges grouped by published post count. These ranges do not represent measured peer usage. This comparison does not upload site data.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Compare', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1"' . checked( $enabled, true, false ) . ' /> ';
			echo esc_html__( 'Show usage reference', 'handl-ai-connector-access-control' ) . '</label>';
			echo '</td></tr></tbody></table>';
			if ( function_exists( 'submit_button' ) ) {
				submit_button( __( 'Save changes', 'handl-ai-connector-access-control' ) );
			} else {
				echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Save changes', 'handl-ai-connector-access-control' ) . '</button></p>';
			}
			echo '</form>';
		}

		if ( ! $enabled ) {
			echo '<p>' . esc_html__( 'Usage reference is off.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		self::render_card( self::snapshot() );
		echo '</div>';
	}

	public static function render_dashboard(): void {
		if ( ! class_exists( Caps::class, false ) || ! Caps::user_can_view() ) {
			return;
		}
		if ( ! self::is_enabled() ) {
			return;
		}
		echo '<div class="handl-aicac-neighbors-dash">';
		self::render_card( self::snapshot() );
		echo '</div>';
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function render_card( array $snap ): void {
		$status = (string) ( $snap['status'] ?? '' );
		if ( self::STATUS_EMPTY === $status ) {
			echo '<p>' . esc_html__( 'No AI activity is available for this report yet.', 'handl-ai-connector-access-control' ) . '</p>';

			return;
		}
		if ( self::STATUS_INSUFFICIENT === $status ) {
			echo '<p>' . esc_html__( 'Not enough activity yet. This report needs at least one week of AI activity.', 'handl-ai-connector-access-control' ) . '</p>';

			return;
		}
		if ( self::STATUS_OK !== $status ) {
			return;
		}

		echo '<ul class="ul-disc">';
		foreach ( self::sentences( $snap ) as $sentence ) {
			echo '<li>' . esc_html( $sentence ) . '</li>';
		}
		echo '</ul>';
		echo '<p class="description">' . esc_html__( 'Example ranges are grouped by published post count, not measured peer usage.', 'handl-ai-connector-access-control' ) . '</p>';
	}

	private static function maybe_hook_digest(): void {
		if ( ! function_exists( 'has_filter' ) || ! function_exists( 'add_filter' ) ) {
			return;
		}
		foreach ( array( 'handl_aicac_digest_extra_lines', 'handl_aicac_weekly_digest_lines' ) as $hook ) {
			if ( has_filter( $hook ) ) {
				add_filter( $hook, array( self::class, 'append_digest_line' ) );
			}
		}
	}

	public static function pct_label( float $rate ): string {
		$pct = (int) round( $rate * 100 );

		return (string) $pct . '%';
	}

	public static function int_label( float $n ): string {
		$n = (int) round( $n );
		if ( function_exists( 'number_format_i18n' ) ) {
			return (string) number_format_i18n( $n );
		}

		return (string) $n;
	}

	public static function usd_label( float $amount ): string {
		if ( class_exists( Cost::class, false ) && method_exists( Cost::class, 'format_usd' ) ) {
			return (string) Cost::format_usd( $amount );
		}
		$formatted = function_exists( 'number_format_i18n' )
			? number_format_i18n( $amount, 2 )
			: number_format( $amount, 2, '.', ',' );

		return '$' . $formatted;
	}
}
