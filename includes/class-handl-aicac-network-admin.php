<?php
/**
 * Network Admin read-only rollup (multisite only).
 *
 * AICAC-105: lists sites where this plugin is active with kill-switch,
 * learn/logging state, denial count, last activity, and a link to that
 * site's Activity tab. No policy writes from this screen.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Network_Admin {
	public const PAGE_SLUG = 'handl-aicac-network';

	/**
	 * Max network sites processed per page load (bounds switch_to_blog).
	 * Pagination is over network sites; inactive sites on a page are omitted from the table.
	 */
	public const SITES_PER_PAGE = 50;

	private static ?Network_Admin $instance = null;

	public static function instance(): Network_Admin {
		if ( null === self::$instance ) {
			self::$instance = new Network_Admin();
		}
		return self::$instance;
	}

	/**
	 * Register network menu only on multisite (AC1).
	 */
	public function init(): void {
		if ( ! function_exists( 'is_multisite' ) || ! is_multisite() ) {
			return;
		}

		add_action( 'network_admin_menu', array( $this, 'register_menu' ) );
	}

	public function register_menu(): void {
		add_submenu_page(
			'settings.php',
			__( 'HandL AI Connector Access Control', 'handl-ai-connector-access-control' ),
			__( 'HandL AI Connector Access Control', 'handl-ai-connector-access-control' ),
			'manage_network_options',
			self::PAGE_SLUG,
			array( $this, 'render_page' )
		);
	}

	public function render_page(): void {
		if ( ! current_user_can( 'manage_network_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'handl-ai-connector-access-control' ) );
		}

		$page = self::sanitize_page(
			isset( $_GET['paged'] ) ? wp_unslash( (string) $_GET['paged'] ) : '1' // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only list pagination.
		);

		$total_sites = self::count_network_sites();
		$total_pages = self::total_pages( $total_sites, self::SITES_PER_PAGE );
		if ( $page > $total_pages ) {
			$page = $total_pages;
		}

		$rows = $this->collect_page_rows( $page );

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'HandL AI Connector Access Control — Network', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Read-only rollup of sites where this plugin is active. Open a site’s Activity tab for detail. Policy changes are not available from this screen.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p class="description">';
		printf(
			/* translators: %d: sites processed per page */
			esc_html__( 'Shows up to %d network sites per page (inactive installs are omitted from the table).', 'handl-ai-connector-access-control' ),
			(int) self::SITES_PER_PAGE
		);
		echo '</p>';

		if ( empty( $rows ) ) {
			echo '<div class="notice notice-info inline"><p>';
			if ( $total_sites < 1 ) {
				echo esc_html__( 'This network has no sites yet.', 'handl-ai-connector-access-control' );
			} elseif ( 1 === $page ) {
				echo esc_html__( 'No sites in this network have HandL AI Connector Access Control active yet.', 'handl-ai-connector-access-control' );
			} else {
				echo esc_html__( 'No sites with the plugin active on this page of the network.', 'handl-ai-connector-access-control' );
			}
			echo '</p></div>';
		} else {
			$this->render_table( $rows );
		}

		$this->render_pagination( $page, $total_pages, $total_sites );
		echo '</div>';
	}

	/**
	 * @param list<array<string,mixed>> $rows
	 */
	private function render_table( array $rows ): void {
		echo '<table class="widefat striped">';
		echo '<thead><tr>';
		echo '<th scope="col">' . esc_html__( 'Site', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th scope="col">' . esc_html__( 'Kill switch', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th scope="col">' . esc_html__( 'Logging / learn mode', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th scope="col">' . esc_html__( 'Denials (retained)', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th scope="col">' . esc_html__( 'Last activity', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th scope="col">' . esc_html__( 'Activity', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';

		foreach ( $rows as $row ) {
			$site_label = (string) ( $row['site_url'] ?? '' );
			if ( '' === $site_label ) {
				$site_label = '#' . (int) ( $row['blog_id'] ?? 0 );
			}

			echo '<tr>';
			echo '<td>' . esc_html( $site_label ) . '</td>';
			echo '<td>' . esc_html( ! empty( $row['kill_switch'] ) ? __( 'On', 'handl-ai-connector-access-control' ) : __( 'Off', 'handl-ai-connector-access-control' ) ) . '</td>';
			echo '<td>' . esc_html( ! empty( $row['logging_or_learn'] ) ? __( 'On', 'handl-ai-connector-access-control' ) : __( 'Off', 'handl-ai-connector-access-control' ) ) . '</td>';

			echo '<td>';
			if ( ! empty( $row['ai_disabled'] ) ) {
				echo esc_html__( 'AI disabled', 'handl-ai-connector-access-control' );
			} else {
				echo esc_html( (string) (int) ( $row['denial_count'] ?? 0 ) );
			}
			echo '</td>';

			$last_ts = (int) ( $row['last_activity_ts'] ?? 0 );
			echo '<td>';
			if ( $last_ts > 0 && function_exists( 'wp_date' ) ) {
				echo esc_html( (string) wp_date( 'Y-m-d H:i:s', $last_ts ) );
			} elseif ( $last_ts > 0 ) {
				echo esc_html( gmdate( 'Y-m-d H:i:s', $last_ts ) );
			} else {
				echo '—';
			}
			echo '</td>';

			$activity_url = (string) ( $row['activity_url'] ?? '' );
			echo '<td>';
			if ( '' !== $activity_url ) {
				echo '<a href="' . esc_url( $activity_url ) . '">' . esc_html__( 'Open Activity', 'handl-ai-connector-access-control' ) . '</a>';
			} else {
				echo '—';
			}
			echo '</td>';
			echo '</tr>';
		}

		echo '</tbody></table>';
	}

	private function render_pagination( int $page, int $total_pages, int $total_sites ): void {
		if ( $total_pages <= 1 ) {
			return;
		}

		$base = network_admin_url( 'settings.php?page=' . self::PAGE_SLUG );

		echo '<div class="tablenav bottom"><div class="tablenav-pages">';
		printf(
			/* translators: 1: current page, 2: total pages, 3: total network sites */
			esc_html__( 'Page %1$d of %2$d (%3$d network sites)', 'handl-ai-connector-access-control' ),
			$page,
			$total_pages,
			$total_sites
		);
		echo ' &nbsp; ';

		if ( $page > 1 ) {
			$prev = add_query_arg( 'paged', $page - 1, $base );
			echo '<a class="prev-page button" href="' . esc_url( $prev ) . '">&lsaquo;</a> ';
		}
		if ( $page < $total_pages ) {
			$next = add_query_arg( 'paged', $page + 1, $base );
			echo '<a class="next-page button" href="' . esc_url( $next ) . '">&rsaquo;</a>';
		}
		echo '</div></div>';
	}

	/**
	 * Collect rollup rows for one page of network sites.
	 *
	 * @return list<array<string,mixed>>
	 */
	public function collect_page_rows( int $page ): array {
		$page   = max( 1, $page );
		$offset = self::offset_for_page( $page, self::SITES_PER_PAGE );
		$sites  = $this->fetch_sites_page( $offset, self::SITES_PER_PAGE );
		$plugin = self::plugin_basename();
		$rows   = array();

		foreach ( $sites as $site ) {
			$blog_id = self::blog_id_from_site( $site );
			if ( $blog_id < 1 ) {
				continue;
			}
			if ( ! $this->is_plugin_active_on_site( $blog_id, $plugin ) ) {
				continue;
			}
			$row = $this->summarize_active_site( $blog_id );
			if ( null !== $row ) {
				$rows[] = $row;
			}
		}

		return $rows;
	}

	/**
	 * @return list<object|array<string,mixed>>
	 */
	private function fetch_sites_page( int $offset, int $number ): array {
		if ( ! function_exists( 'get_sites' ) ) {
			return array();
		}
		$sites = get_sites(
			array(
				'number'  => $number,
				'offset'  => $offset,
				'orderby' => 'id',
				'order'   => 'ASC',
			)
		);
		return is_array( $sites ) ? $sites : array();
	}

	public static function count_network_sites(): int {
		if ( ! function_exists( 'get_sites' ) ) {
			return 0;
		}
		$count = get_sites( array( 'count' => true ) );
		return is_numeric( $count ) ? (int) $count : 0;
	}

	/**
	 * @param object|array<string,mixed> $site
	 */
	public static function blog_id_from_site( $site ): int {
		if ( is_object( $site ) && isset( $site->blog_id ) ) {
			return (int) $site->blog_id;
		}
		if ( is_array( $site ) && isset( $site['blog_id'] ) ) {
			return (int) $site['blog_id'];
		}
		return 0;
	}

	public function is_plugin_active_on_site( int $blog_id, string $plugin_basename ): bool {
		if ( '' === $plugin_basename || $blog_id < 1 ) {
			return false;
		}

		if ( ! function_exists( 'is_plugin_active_for_network' ) && defined( 'ABSPATH' ) ) {
			$plugin_admin = ABSPATH . 'wp-admin/includes/plugin.php';
			if ( is_readable( $plugin_admin ) ) {
				require_once $plugin_admin;
			}
		}
		if ( function_exists( 'is_plugin_active_for_network' ) && is_plugin_active_for_network( $plugin_basename ) ) {
			return true;
		}

		$active = get_blog_option( $blog_id, 'active_plugins', array() );
		if ( ! is_array( $active ) ) {
			return false;
		}
		return in_array( $plugin_basename, $active, true );
	}

	/**
	 * Switch into a site, read options, always restore.
	 *
	 * @return array<string,mixed>|null
	 */
	public function summarize_active_site( int $blog_id ): ?array {
		if ( $blog_id < 1 || ! function_exists( 'switch_to_blog' ) ) {
			return null;
		}

		switch_to_blog( $blog_id );
		try {
			$policy_raw = get_option( Plugin::OPTION_KEY, array() );
			$log_raw    = get_option( Plugin::LOG_OPTION_KEY, array() );
			$ai_disabled = function_exists( 'wp_supports_ai' ) && ! wp_supports_ai();
			$site_url    = function_exists( 'get_site_url' ) ? (string) get_site_url( $blog_id ) : '';
			$activity    = self::activity_admin_url( $blog_id );

			return self::summarize_site_data(
				$blog_id,
				$site_url,
				$activity,
				is_array( $policy_raw ) ? $policy_raw : array(),
				is_array( $log_raw ) ? $log_raw : array(),
				$ai_disabled
			);
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * Pure row builder for tests and summarize_active_site().
	 *
	 * @param array<string,mixed> $policy_raw
	 * @param array<int,mixed>    $log_raw
	 * @return array{
	 *   blog_id:int,
	 *   site_url:string,
	 *   activity_url:string,
	 *   kill_switch:bool,
	 *   learn_mode:bool,
	 *   log_enabled:bool,
	 *   logging_or_learn:bool,
	 *   denial_count:int,
	 *   last_activity_ts:int,
	 *   ai_disabled:bool
	 * }
	 */
	public static function summarize_site_data(
		int $blog_id,
		string $site_url,
		string $activity_url,
		array $policy_raw,
		array $log_raw,
		bool $ai_disabled
	): array {
		$kill   = ! empty( $policy_raw['kill_switch'] );
		$learn  = ! empty( $policy_raw['audit_only'] );
		$log_on = ! empty( $policy_raw['log_enabled'] );

		return array(
			'blog_id'           => $blog_id,
			'site_url'          => $site_url,
			'activity_url'      => $activity_url,
			'kill_switch'       => $kill,
			'learn_mode'        => $learn,
			'log_enabled'       => $log_on,
			'logging_or_learn'  => ( $log_on || $learn ),
			'denial_count'      => self::count_denials( $log_raw ),
			'last_activity_ts'  => self::newest_log_timestamp( $log_raw ),
			'ai_disabled'       => $ai_disabled,
		);
	}

	/**
	 * Denial rows in the retained window (Dashboard-compatible).
	 *
	 * @param array<int,mixed> $log
	 */
	public static function count_denials( array $log ): int {
		$n = 0;
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$is_direct = isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'];
			if ( ! $is_direct && 'deny' === (string) ( $row['decision'] ?? '' ) ) {
				++$n;
			}
		}
		return $n;
	}

	/**
	 * Newest retained activity timestamp (any channel).
	 *
	 * @param array<int,mixed> $log
	 */
	public static function newest_log_timestamp( array $log ): int {
		$max = 0;
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts > $max ) {
				$max = $ts;
			}
		}
		return $max;
	}

	public static function activity_admin_url( int $blog_id ): string {
		$path = 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=activity';
		if ( function_exists( 'get_admin_url' ) ) {
			return (string) get_admin_url( $blog_id, $path );
		}
		return $path;
	}

	public static function plugin_basename(): string {
		if ( defined( 'HANDL_AICAC_FILE' ) && function_exists( 'plugin_basename' ) ) {
			return (string) plugin_basename( HANDL_AICAC_FILE );
		}
		if ( defined( 'HANDL_AICAC_FILE' ) ) {
			return basename( dirname( HANDL_AICAC_FILE ) ) . '/' . basename( HANDL_AICAC_FILE );
		}
		return 'handl-ai-connector-access-control/handl-ai-connector-access-control.php';
	}

	/**
	 * @param mixed $raw
	 */
	public static function sanitize_page( $raw ): int {
		$page = (int) $raw;
		return $page < 1 ? 1 : $page;
	}

	public static function offset_for_page( int $page, int $per_page ): int {
		$page     = max( 1, $page );
		$per_page = max( 1, $per_page );
		return ( $page - 1 ) * $per_page;
	}

	public static function total_pages( int $total_items, int $per_page ): int {
		$per_page = max( 1, $per_page );
		if ( $total_items < 1 ) {
			return 1;
		}
		return (int) ceil( $total_items / $per_page );
	}
}
