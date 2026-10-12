<?php
/**
 * AICAC-TOUCHED (#367): per-post AI provenance ledger.
 *
 * Records which posts an AI call shaped via wp_ai_client_after_generate_result
 * (hooks-only). Own post_meta keys + index option. Posts-list AI column,
 * per-post history metabox, OFF-by-default front badge shortcode, WP-CLI audit
 * + CSV from this class. No admin.php/policy.php/logger/cost edits.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Content provenance: which posts did AI touch.
 */
final class Touched {

	public const META_HISTORY = '_handl_aicac_touched_history';

	public const META_SUMMARY = '_handl_aicac_touched_summary';

	public const SETTINGS_OPTION = 'handl_aicac_touched';

	public const INDEX_OPTION = 'handl_aicac_touched_index';

	public const SHORTCODE = 'handl_aicac_touched';

	public const PAGE_SLUG = 'handl-aicac-touched';

	public const HISTORY_CAP = 50;

	public const INDEX_CAP = 2000;

	public const POST_PRESENT = 'handl_aicac_touched_present';

	public const POST_BADGE = 'handl_aicac_touched_badge';

	public const CHANNEL = 'touched';

	/** @var bool */
	private static $registered = false;

	/**
	 * Test override for resolve_post_context() — null means "use live detection".
	 *
	 * @var int|null|false
	 */
	private static $test_post_id = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'wp_ai_client_after_generate_result', array( self::class, 'maybe_record_outcome' ), 13, 1 );
		add_action( 'handl_aicac_protections_settings', array( self::class, 'render_settings' ) );
		add_filter( 'pre_update_option_' . Plugin::OPTION_KEY, array( self::class, 'capture_settings_on_policy_save' ), 10, 2 );
		add_shortcode( self::SHORTCODE, array( self::class, 'render_shortcode' ) );
		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'add_meta_boxes', array( self::class, 'register_metabox' ) );
		add_filter( 'manage_posts_columns', array( self::class, 'posts_column' ) );
		add_action( 'manage_posts_custom_column', array( self::class, 'posts_column_content' ), 10, 2 );
		add_filter( 'manage_pages_columns', array( self::class, 'posts_column' ) );
		add_action( 'manage_pages_custom_column', array( self::class, 'posts_column_content' ), 10, 2 );
		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered  = false;
		self::$test_post_id = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::INDEX_OPTION );
	}

	/**
	 * @internal Tests only. Pass false to force "no context"; null clears override.
	 *
	 * @param int|null|false $post_id Override.
	 */
	public static function set_test_post_id( $post_id ): void {
		self::$test_post_id = $post_id;
	}

	/**
	 * @return array{badge_enabled:bool}
	 */
	public static function defaults(): array {
		return array(
			'badge_enabled' => false,
		);
	}

	/**
	 * @return array{badge_enabled:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{badge_enabled:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		$badge = false;
		if ( is_array( $raw ) && ! empty( $raw['badge_enabled'] ) ) {
			$badge = true;
		}

		return array( 'badge_enabled' => $badge );
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
		update_option( self::SETTINGS_OPTION, $clean, false );

		return true;
	}

	public static function is_badge_enabled(): bool {
		return ! empty( self::get_settings()['badge_enabled'] );
	}

	/**
	 * Best-effort post ID for the current AI call. Unlinkable → null (no guess).
	 */
	public static function resolve_post_context(): ?int {
		if ( null !== self::$test_post_id ) {
			if ( false === self::$test_post_id ) {
				return null;
			}
			$id = (int) self::$test_post_id;

			return $id > 0 ? $id : null;
		}

		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( 'handl_aicac_touched_post_id', null );
			if ( is_numeric( $filtered ) ) {
				$id = (int) $filtered;
				if ( $id > 0 ) {
					return $id;
				}
			}
		}

		// Classic editor / autosave / bulk edit POST body.
		foreach ( array( 'post_ID', 'post_id', 'post' ) as $key ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.NonceVerification.Recommended
			if ( isset( $_POST[ $key ] ) && is_scalar( $_POST[ $key ] ) ) {
				$id = (int) wp_unslash( (string) $_POST[ $key ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
				if ( $id > 0 ) {
					return $id;
				}
			}
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( isset( $_REQUEST[ $key ] ) && is_scalar( $_REQUEST[ $key ] ) ) {
				$id = (int) wp_unslash( (string) $_REQUEST[ $key ] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				if ( $id > 0 ) {
					return $id;
				}
			}
		}

		// REST: /wp/v2/posts/123 or /wp/v2/pages/123.
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST && isset( $GLOBALS['wp']->query_vars['rest_route'] ) ) {
			$route = (string) $GLOBALS['wp']->query_vars['rest_route'];
			if ( 1 === preg_match( '#^/wp/v2/(?:posts|pages)/(\d+)(?:/|$)#', $route, $m ) ) {
				$id = (int) $m[1];
				if ( $id > 0 ) {
					return $id;
				}
			}
		}

		// Admin post editor screen only — never front-end singular.
		if ( function_exists( 'is_admin' ) && is_admin() && function_exists( 'get_current_screen' ) ) {
			$screen = get_current_screen();
			if ( is_object( $screen ) && isset( $screen->base ) && 'post' === (string) $screen->base ) {
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended
				if ( isset( $_GET['post'] ) && is_scalar( $_GET['post'] ) ) {
					$id = (int) wp_unslash( (string) $_GET['post'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
					if ( $id > 0 ) {
						return $id;
					}
				}
				if ( isset( $GLOBALS['post'] ) && is_object( $GLOBALS['post'] ) && isset( $GLOBALS['post']->ID ) ) {
					$id = (int) $GLOBALS['post']->ID;
					if ( $id > 0 ) {
						return $id;
					}
				}
			}
		}

		return null;
	}

	/**
	 * @param object $event AfterGenerateResultEvent.
	 */
	public static function maybe_record_outcome( object $event ): void {
		$post_id = self::resolve_post_context();
		if ( null === $post_id ) {
			return;
		}

		$provider   = self::provider_from_event( $event );
		$capability = self::capability_from_event( $event );
		$model      = self::model_from_event( $event );
		$outcome    = self::event_is_success( $event ) ? 'success' : 'error';
		$user_id    = (int) get_current_user_id();
		$now        = Clock::now();

		self::record_touch(
			$post_id,
			array(
				'ts'         => $now,
				'provider'   => $provider,
				'model'      => $model,
				'capability' => $capability,
				'user_id'    => $user_id,
				'outcome'    => $outcome,
			)
		);
	}

	/**
	 * Append a provenance row and refresh summary + index.
	 *
	 * @param array{
	 *   ts?:int,
	 *   provider?:string,
	 *   model?:string,
	 *   capability?:string,
	 *   user_id?:int,
	 *   outcome?:string
	 * } $row Provenance fields.
	 */
	public static function record_touch( int $post_id, array $row ): bool {
		if ( $post_id <= 0 || ! function_exists( 'update_post_meta' ) ) {
			return false;
		}

		$entry = array(
			'ts'         => isset( $row['ts'] ) ? (int) $row['ts'] : Clock::now(),
			'provider'   => self::sanitize_provider( (string) ( $row['provider'] ?? '' ) ),
			'model'      => self::sanitize_model( (string) ( $row['model'] ?? '' ) ),
			'capability' => self::sanitize_capability( (string) ( $row['capability'] ?? '' ) ),
			'user_id'    => isset( $row['user_id'] ) ? max( 0, (int) $row['user_id'] ) : 0,
			'outcome'    => self::sanitize_outcome( (string) ( $row['outcome'] ?? 'success' ) ),
		);

		$history   = self::history_for_post( $post_id );
		$history[] = $entry;
		if ( count( $history ) > self::HISTORY_CAP ) {
			$history = array_slice( $history, -self::HISTORY_CAP );
		}
		update_post_meta( $post_id, self::META_HISTORY, $history );
		update_post_meta( $post_id, self::META_SUMMARY, self::build_summary( $history ) );
		self::index_add( $post_id );
		self::maybe_append_activity( $post_id, $entry );

		return true;
	}

	/**
	 * @return list<array{ts:int,provider:string,model:string,capability:string,user_id:int,outcome:string}>
	 */
	public static function history_for_post( int $post_id ): array {
		if ( $post_id <= 0 || ! function_exists( 'get_post_meta' ) ) {
			return array();
		}
		$raw = get_post_meta( $post_id, self::META_HISTORY, true );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$out[] = array(
				'ts'         => (int) ( $row['ts'] ?? 0 ),
				'provider'   => self::sanitize_provider( (string) ( $row['provider'] ?? '' ) ),
				'model'      => self::sanitize_model( (string) ( $row['model'] ?? '' ) ),
				'capability' => self::sanitize_capability( (string) ( $row['capability'] ?? '' ) ),
				'user_id'    => max( 0, (int) ( $row['user_id'] ?? 0 ) ),
				'outcome'    => self::sanitize_outcome( (string) ( $row['outcome'] ?? 'success' ) ),
			);
		}

		return $out;
	}

	/**
	 * @return array{count:int,last_ts:int,last_provider:string,providers:list<string>}|null
	 */
	public static function summary_for_post( int $post_id ): ?array {
		if ( $post_id <= 0 || ! function_exists( 'get_post_meta' ) ) {
			return null;
		}
		$raw = get_post_meta( $post_id, self::META_SUMMARY, true );
		if ( is_array( $raw ) && isset( $raw['count'] ) && (int) $raw['count'] > 0 ) {
			$providers = array();
			if ( isset( $raw['providers'] ) && is_array( $raw['providers'] ) ) {
				foreach ( $raw['providers'] as $p ) {
					$p = self::sanitize_provider( (string) $p );
					if ( '' !== $p && 'unknown' !== $p ) {
						$providers[] = $p;
					}
				}
			}

			return array(
				'count'         => (int) $raw['count'],
				'last_ts'       => (int) ( $raw['last_ts'] ?? 0 ),
				'last_provider' => self::sanitize_provider( (string) ( $raw['last_provider'] ?? '' ) ),
				'providers'     => array_values( array_unique( $providers ) ),
			);
		}
		$history = self::history_for_post( $post_id );
		if ( empty( $history ) ) {
			return null;
		}

		return self::build_summary( $history );
	}

	/**
	 * @return list<array{post_id:int,count:int,last_ts:int,last_provider:string,providers:list<string>}>
	 */
	public static function list_touched( int $limit = 100 ): array {
		$limit = max( 1, min( 500, $limit ) );
		$ids   = self::index_ids();
		$out   = array();
		foreach ( $ids as $post_id ) {
			$summary = self::summary_for_post( $post_id );
			if ( null === $summary ) {
				continue;
			}
			$out[] = array(
				'post_id'       => $post_id,
				'count'         => (int) $summary['count'],
				'last_ts'       => (int) $summary['last_ts'],
				'last_provider' => (string) $summary['last_provider'],
				'providers'     => $summary['providers'],
			);
			if ( count( $out ) >= $limit ) {
				break;
			}
		}
		usort(
			$out,
			static function ( array $a, array $b ): int {
				return (int) $b['last_ts'] <=> (int) $a['last_ts'];
			}
		);

		return array_slice( $out, 0, $limit );
	}

	/**
	 * CSV body for the audit screen / export.
	 */
	public static function csv_for_list( int $limit = 500 ): string {
		$rows    = self::list_touched( $limit );
		$lines   = array();
		$lines[] = 'post_id,call_count,last_ts,last_provider,providers';
		foreach ( $rows as $r ) {
			$lines[] = self::csv_line(
				array(
					(string) (int) $r['post_id'],
					(string) (int) $r['count'],
					(string) (int) $r['last_ts'],
					(string) $r['last_provider'],
					implode( '|', $r['providers'] ),
				)
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param array<string,mixed>|string $atts Shortcode attributes.
	 */
	public static function render_shortcode( $atts = array() ): string {
		if ( ! self::is_badge_enabled() ) {
			return '';
		}
		$atts    = is_array( $atts ) ? $atts : array();
		$post_id = 0;
		if ( isset( $atts['post_id'] ) ) {
			$post_id = (int) $atts['post_id'];
		}
		if ( $post_id <= 0 && function_exists( 'get_the_ID' ) ) {
			$post_id = (int) get_the_ID();
		}
		if ( $post_id <= 0 ) {
			return '';
		}
		$summary = self::summary_for_post( $post_id );
		if ( null === $summary ) {
			return '';
		}
		$family = self::provider_family_label( (string) $summary['last_provider'] );
		if ( '' === $family ) {
			$family = __( 'AI', 'handl-ai-connector-access-control' );
		}
		$label = sprintf(
			/* translators: %s: provider family label */
			__( 'AI-assisted (%s)', 'handl-ai-connector-access-control' ),
			$family
		);

		return '<span class="handl-aicac-touched-badge">' . esc_html( $label ) . '</span>';
	}

	/**
	 * @param array<string,string> $columns Columns.
	 * @return array<string,string>
	 */
	public static function posts_column( $columns ) {
		if ( ! is_array( $columns ) ) {
			$columns = array();
		}
		if ( ! Caps::user_can_view() ) {
			return $columns;
		}
		$columns['handl_aicac_touched'] = __( 'AI', 'handl-ai-connector-access-control' );

		return $columns;
	}

	/**
	 * @param string $column  Column key.
	 * @param int    $post_id Post ID.
	 */
	public static function posts_column_content( $column, $post_id ): void {
		if ( 'handl_aicac_touched' !== (string) $column ) {
			return;
		}
		$post_id = (int) $post_id;
		$summary = self::summary_for_post( $post_id );
		if ( null === $summary ) {
			echo '&mdash;';
			return;
		}
		$label = self::provider_family_label( (string) $summary['last_provider'] );
		if ( '' === $label ) {
			$label = __( 'AI', 'handl-ai-connector-access-control' );
		}
		echo esc_html( $label );
		echo ' <span class="description">(' . esc_html( (string) (int) $summary['count'] ) . ')</span>';
	}

	public static function register_metabox(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_meta_box' ) ) {
			return;
		}
		add_meta_box(
			'handl-aicac-touched',
			__( 'AI provenance', 'handl-ai-connector-access-control' ),
			array( self::class, 'render_metabox' ),
			null,
			'side',
			'default'
		);
	}

	/**
	 * @param \WP_Post|object|null $post Post.
	 */
	public static function render_metabox( $post ): void {
		$post_id = 0;
		if ( is_object( $post ) && isset( $post->ID ) ) {
			$post_id = (int) $post->ID;
		}
		if ( $post_id <= 0 ) {
			echo '<p>' . esc_html__( 'No post context.', 'handl-ai-connector-access-control' ) . '</p>';
			return;
		}
		$history = self::history_for_post( $post_id );
		if ( empty( $history ) ) {
			echo '<p>' . esc_html__( 'No AI calls linked to this post yet. Only calls made while editing this post are recorded.', 'handl-ai-connector-access-control' ) . '</p>';
			return;
		}
		$summary = self::summary_for_post( $post_id );
		if ( null !== $summary ) {
			echo '<p><strong>' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . ':</strong> ';
			echo esc_html( (string) (int) $summary['count'] );
			echo '</p>';
		}
		echo '<ul class="handl-aicac-touched-history">';
		$recent = array_reverse( $history );
		$shown  = 0;
		foreach ( $recent as $row ) {
			if ( $shown >= 20 ) {
				break;
			}
			++$shown;
			$when = self::format_ts( (int) $row['ts'] );
			$prov = self::provider_family_label( (string) $row['provider'] );
			if ( '' === $prov ) {
				$prov = (string) $row['provider'];
			}
			$cap = (string) $row['capability'];
			echo '<li>';
			echo esc_html( $when );
			echo ' — ';
			echo esc_html( $prov );
			if ( '' !== $cap ) {
				echo ' / ' . esc_html( $cap );
			}
			echo '</li>';
		}
		echo '</ul>';
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
			__( 'AI-touched content', 'handl-ai-connector-access-control' ),
			__( 'AI-touched', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$rows = self::list_touched( 200 );
		$csv  = add_query_arg(
			array(
				'page'                    => self::PAGE_SLUG,
				'handl_aicac_touched_csv' => '1',
				'_wpnonce'                => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_touched_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'AI-touched content', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Posts and pages linked to AI calls made while editing them. Calls outside an editing context are not linked.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p><a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a></p>';

		if ( empty( $rows ) ) {
			echo '<p>' . esc_html__( 'No linked content yet.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';
			return;
		}

		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Post', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Last provider', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Last touch', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( $rows as $r ) {
			$edit = function_exists( 'get_edit_post_link' ) ? get_edit_post_link( (int) $r['post_id'] ) : '';
			echo '<tr><td>';
			if ( is_string( $edit ) && '' !== $edit ) {
				echo '<a href="' . esc_url( $edit ) . '">#' . esc_html( (string) (int) $r['post_id'] ) . '</a>';
			} else {
				echo '#' . esc_html( (string) (int) $r['post_id'] );
			}
			echo '</td><td>' . esc_html( (string) (int) $r['count'] ) . '</td>';
			echo '<td>' . esc_html( self::provider_family_label( (string) $r['last_provider'] ) ) . '</td>';
			echo '<td>' . esc_html( self::format_ts( (int) $r['last_ts'] ) ) . '</td></tr>';
		}
		echo '</tbody></table></div>';
	}

	public static function maybe_handle_csv(): void {
		if ( function_exists( 'is_admin' ) && ! is_admin() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action = isset( $_GET['handl_aicac_touched_csv'] ) ? sanitize_key( wp_unslash( (string) $_GET['handl_aicac_touched_csv'] ) ) : '';
		if ( '1' !== $action ) {
			return;
		}
		if ( ! Caps::user_can_view() ) {
			if ( function_exists( 'wp_die' ) ) {
				wp_die( esc_html__( 'You do not have permission to export this list.', 'handl-ai-connector-access-control' ) );
			}
			return;
		}
		check_admin_referer( 'handl_aicac_touched_csv' );

		$csv = self::csv_for_list( 500 );
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( function_exists( 'header' ) ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename="handl-aicac-touched.csv"' );
		}
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- raw CSV download body.
		echo $csv;
		exit;
	}

	public static function render_settings(): void {
		$settings = self::get_settings();
		echo '<div class="handl-aicac-touched-settings">';
		echo '<h3>' . esc_html__( 'AI-touched content badge', 'handl-ai-connector-access-control' ) . '</h3>';
		echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
		echo '<label><input type="checkbox" name="' . esc_attr( self::POST_BADGE ) . '" value="1" ' . checked( ! empty( $settings['badge_enabled'] ), true, false ) . ' /> ';
		echo esc_html__( 'Show the [handl_aicac_touched] badge on posts that have AI provenance (off by default)', 'handl-ai-connector-access-control' );
		echo '</label>';
		echo '<p class="description">' . esc_html__( 'Provenance is recorded whenever an AI call runs while a post is being edited. Calls outside that context stay unlinked.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</div>';
	}

	/**
	 * @param mixed $value     New policy value.
	 * @param mixed $old_value Previous policy value.
	 * @return mixed
	 */
	public static function capture_settings_on_policy_save( $value, $old_value ) {
		unset( $old_value );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- policy form already verified upstream.
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) {
			return $value;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$badge = ! empty( $_POST[ self::POST_BADGE ] );
		self::save_settings( array( 'badge_enabled' => $badge ) );

		return $value;
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac touched', CLI_Touched::class );
	}

	/**
	 * @param list<array{ts:int,provider:string,model:string,capability:string,user_id:int,outcome:string}> $history
	 * @return array{count:int,last_ts:int,last_provider:string,providers:list<string>}
	 */
	public static function build_summary( array $history ): array {
		$count     = count( $history );
		$last      = $count > 0 ? $history[ $count - 1 ] : null;
		$providers = array();
		foreach ( $history as $row ) {
			$p = self::sanitize_provider( (string) ( $row['provider'] ?? '' ) );
			if ( '' !== $p && 'unknown' !== $p ) {
				$providers[ $p ] = true;
			}
		}

		return array(
			'count'         => $count,
			'last_ts'       => is_array( $last ) ? (int) ( $last['ts'] ?? 0 ) : 0,
			'last_provider' => is_array( $last ) ? self::sanitize_provider( (string) ( $last['provider'] ?? '' ) ) : '',
			'providers'     => array_keys( $providers ),
		);
	}

	public static function provider_family_label( string $provider ): string {
		$provider = self::sanitize_provider( $provider );
		if ( '' === $provider || 'unknown' === $provider ) {
			return '';
		}
		if ( class_exists( Disclosure::class, false ) && method_exists( Disclosure::class, 'provider_label' ) ) {
			$label = Disclosure::provider_label( $provider );
			if ( is_string( $label ) && '' !== $label ) {
				return $label;
			}
		}

		return $provider;
	}

	public static function sanitize_provider( string $provider ): string {
		if ( class_exists( Latency::class, false ) && method_exists( Latency::class, 'sanitize_provider' ) ) {
			return Latency::sanitize_provider( $provider );
		}
		$provider = strtolower( trim( $provider ) );
		$provider = preg_replace( '/[^a-z0-9_\-\.]/', '', $provider ) ?? '';

		return '' === $provider ? 'unknown' : $provider;
	}

	public static function sanitize_model( string $model ): string {
		$model = strtolower( trim( $model ) );
		$model = preg_replace( '/[^a-z0-9_\-\.\/]/', '', $model ) ?? '';

		return substr( $model, 0, 120 );
	}

	public static function sanitize_capability( string $capability ): string {
		$capability = strtolower( trim( $capability ) );
		$capability = preg_replace( '/[^a-z0-9_\-]/', '', $capability ) ?? '';

		return substr( $capability, 0, 64 );
	}

	public static function sanitize_outcome( string $outcome ): string {
		$outcome = strtolower( trim( $outcome ) );

		return in_array( $outcome, array( 'success', 'error' ), true ) ? $outcome : 'success';
	}

	/**
	 * @return list<int>
	 */
	public static function index_ids(): array {
		$raw = get_option( self::INDEX_OPTION, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $id ) {
			$id = (int) $id;
			if ( $id > 0 ) {
				$out[] = $id;
			}
		}

		return array_values( array_unique( $out ) );
	}

	private static function index_add( int $post_id ): void {
		$ids = self::index_ids();
		if ( ! in_array( $post_id, $ids, true ) ) {
			array_unshift( $ids, $post_id );
		} else {
			$ids = array_values(
				array_filter(
					$ids,
					static function ( $id ) use ( $post_id ) {
						return (int) $id !== $post_id;
					}
				)
			);
			array_unshift( $ids, $post_id );
		}
		if ( count( $ids ) > self::INDEX_CAP ) {
			$ids = array_slice( $ids, 0, self::INDEX_CAP );
		}
		update_option( self::INDEX_OPTION, $ids, false );
	}

	/**
	 * @param array{ts:int,provider:string,model:string,capability:string,user_id:int,outcome:string} $entry
	 */
	private static function maybe_append_activity( int $post_id, array $entry ): void {
		if ( ! class_exists( Policy::class, false ) || ! method_exists( Policy::class, 'append_log_event' ) ) {
			return;
		}
		Policy::append_log_event(
			array(
				'ts'              => (int) $entry['ts'],
				'decision'        => self::CHANNEL,
				'channel'         => self::CHANNEL,
				'provider'        => (string) $entry['provider'],
				'user_id'         => (int) $entry['user_id'],
				'post_id'         => $post_id,
				'touched_outcome' => (string) $entry['outcome'],
				'capability'      => (string) $entry['capability'],
			)
		);
	}

	/**
	 * @param object $event AfterGenerateResultEvent.
	 */
	private static function provider_from_event( object $event ): string {
		foreach ( array( 'getProviderId', 'get_provider_id', 'getProvider' ) as $method ) {
			if ( method_exists( $event, $method ) ) {
				$raw = $event->{$method}();
				if ( is_string( $raw ) && '' !== $raw ) {
					return self::sanitize_provider( $raw );
				}
			}
		}
		if ( method_exists( $event, 'getResult' ) ) {
			$result = $event->getResult();
			if ( is_object( $result ) && method_exists( $result, 'getProviderId' ) ) {
				$raw = $result->getProviderId();
				if ( is_string( $raw ) && '' !== $raw ) {
					return self::sanitize_provider( $raw );
				}
			}
		}
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( 'handl_aicac_touched_provider', '', $event );
			if ( is_string( $filtered ) && '' !== $filtered ) {
				return self::sanitize_provider( $filtered );
			}
		}

		return 'unknown';
	}

	/**
	 * @param object $event AfterGenerateResultEvent.
	 */
	private static function model_from_event( object $event ): string {
		foreach ( array( 'getModelId', 'get_model_id', 'getModel' ) as $method ) {
			if ( method_exists( $event, $method ) ) {
				$raw = $event->{$method}();
				if ( is_string( $raw ) && '' !== $raw ) {
					return self::sanitize_model( $raw );
				}
			}
		}

		return '';
	}

	/**
	 * @param object $event AfterGenerateResultEvent.
	 */
	private static function capability_from_event( object $event ): string {
		foreach ( array( 'getCapability', 'get_capability' ) as $method ) {
			if ( method_exists( $event, $method ) ) {
				$raw = $event->{$method}();
				if ( is_string( $raw ) && '' !== $raw ) {
					return self::sanitize_capability( $raw );
				}
				if ( is_object( $raw ) && method_exists( $raw, 'value' ) ) {
					return self::sanitize_capability( (string) $raw->value() );
				}
			}
		}
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( 'handl_aicac_touched_capability', '', $event );
			if ( is_string( $filtered ) && '' !== $filtered ) {
				return self::sanitize_capability( $filtered );
			}
		}

		return '';
	}

	/**
	 * @param object $event AfterGenerateResultEvent.
	 */
	private static function event_is_success( object $event ): bool {
		if ( ! method_exists( $event, 'getResult' ) ) {
			return true;
		}
		$result = $event->getResult();
		if ( $result instanceof \WP_Error ) {
			return false;
		}
		if ( is_object( $result ) && method_exists( $result, 'get_error_code' ) && ! method_exists( $result, 'getTokenUsage' ) ) {
			return false;
		}

		return true;
	}

	private static function format_ts( int $ts ): string {
		if ( $ts <= 0 ) {
			return '—';
		}
		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( 'Y-m-d H:i', $ts );
		}

		return gmdate( 'Y-m-d H:i', $ts );
	}

	/**
	 * @param list<string> $fields Fields.
	 */
	private static function csv_line( array $fields ): string {
		$out = array();
		foreach ( $fields as $f ) {
			$f = str_replace( '"', '""', (string) $f );
			if ( preg_match( '/[",\n\r]/', $f ) ) {
				$out[] = '"' . $f . '"';
			} else {
				$out[] = $f;
			}
		}

		return implode( ',', $out );
	}
}

/**
 * WP-CLI: wp handl-aicac touched list|post <id>
 */
final class CLI_Touched {

	/**
	 * List posts with AI provenance.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table, json, csv, or yaml.
	 *
	 * [--limit=<n>]
	 * : Max rows (default 100).
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function list( $args, $assoc_args ): void {
		unset( $args );
		$limit  = isset( $assoc_args['limit'] ) ? (int) $assoc_args['limit'] : 100;
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$rows   = Touched::list_touched( $limit );
		if ( 'csv' === $format ) {
			\WP_CLI::print_value( Touched::csv_for_list( $limit ), array( 'format' => 'csv' ) );
			return;
		}
		$table = array();
		foreach ( $rows as $r ) {
			$table[] = array(
				'post_id'       => (int) $r['post_id'],
				'calls'         => (int) $r['count'],
				'last_provider' => (string) $r['last_provider'],
				'last_ts'       => (int) $r['last_ts'],
				'providers'     => implode( ',', $r['providers'] ),
			);
		}
		if ( empty( $table ) ) {
			\WP_CLI::log( 'No AI-touched posts.' );
			return;
		}
		\WP_CLI\Utils\format_items( $format, $table, array( 'post_id', 'calls', 'last_provider', 'last_ts', 'providers' ) );
	}

	/**
	 * Show provenance history for one post.
	 *
	 * ## OPTIONS
	 *
	 * <id>
	 * : Post ID.
	 *
	 * [--format=<format>]
	 * : table, json, csv, or yaml.
	 *
	 * @when after_wp_load
	 *
	 * @param list<string>             $args       Positional.
	 * @param array<string,string|int> $assoc_args Flags.
	 */
	public function post( $args, $assoc_args ): void {
		$id = isset( $args[0] ) ? (int) $args[0] : 0;
		if ( $id <= 0 ) {
			\WP_CLI::error( 'Need a post id.' );
		}
		$format  = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		$history = Touched::history_for_post( $id );
		$summary = Touched::summary_for_post( $id );
		if ( null === $summary ) {
			\WP_CLI::log( 'No AI provenance for post ' . $id . '.' );
			return;
		}
		\WP_CLI::log(
			sprintf(
				'post=%d calls=%d last_provider=%s',
				$id,
				(int) $summary['count'],
				(string) $summary['last_provider']
			)
		);
		$table = array();
		foreach ( $history as $row ) {
			$table[] = array(
				'ts'         => (int) $row['ts'],
				'provider'   => (string) $row['provider'],
				'model'      => (string) $row['model'],
				'capability' => (string) $row['capability'],
				'user_id'    => (int) $row['user_id'],
				'outcome'    => (string) $row['outcome'],
			);
		}
		\WP_CLI\Utils\format_items( $format, $table, array( 'ts', 'provider', 'model', 'capability', 'user_id', 'outcome' ) );
	}
}
