<?php
/**
 * Admin UI.
 *
 * @package AINot
 */

namespace AINot;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Admin {
	private static ?Admin $instance = null;

	public static function instance(): Admin {
		if ( null === self::$instance ) {
			self::$instance = new Admin();
		}
		return self::$instance;
	}

	public function init(): void {
		if ( ! is_admin() ) {
			return;
		}

		add_action( 'admin_menu', array( $this, 'register_menu' ) );
	}

	public function register_menu(): void {
		add_options_page(
			__( 'AI Not', 'ai-not' ),
			__( 'AI Not', 'ai-not' ),
			'manage_options',
			'ai-not',
			array( $this, 'render_page' )
		);
	}

	public function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'ai-not' ) );
		}

		$plugin_status_filter = 'all';
		if ( isset( $_REQUEST['ai_not_status'] ) ) {
			$plugin_status_filter = sanitize_text_field( wp_unslash( (string) $_REQUEST['ai_not_status'] ) );
		}
		if ( 'active' !== $plugin_status_filter && 'inactive' !== $plugin_status_filter ) {
			$plugin_status_filter = 'all';
		}

		$plugin_access_filter = 'all';
		if ( isset( $_REQUEST['ai_not_access'] ) ) {
			$plugin_access_filter = sanitize_text_field( wp_unslash( (string) $_REQUEST['ai_not_access'] ) );
		}
		if ( 'effective-allow' !== $plugin_access_filter && 'effective-deny' !== $plugin_access_filter && 'default-only' !== $plugin_access_filter ) {
			$plugin_access_filter = 'all';
		}

		if ( isset( $_POST['ai_not_action'] ) && 'save' === $_POST['ai_not_action'] ) {
			check_admin_referer( 'ai_not_save_policy', 'ai_not_nonce' );
			$this->handle_save();
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Saved.', 'ai-not' ) . '</p></div>';
		}

		$policy = Policy::get_policy();

		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$plugins = get_plugins();
		$active  = array_flip( (array) get_option( 'active_plugins', array() ) );

		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) ) {
			$log = array();
		}

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'AI Not', 'ai-not' ) . '</h1>';
		echo '<p>' . esc_html__( 'Allow/deny which plugins may execute prompts via the WordPress AI Client. Default policy is allow.', 'ai-not' ) . '</p>';

		echo '<form method="get" style="margin: 0 0 12px 0;">';
		echo '<input type="hidden" name="page" value="ai-not" />';
		echo '<p style="margin: 0;">';
		echo '<label for="ai-not-status-filter"><strong>' . esc_html__( 'Show', 'ai-not' ) . '</strong></label> ';
		echo '<select id="ai-not-status-filter" name="ai_not_status" onchange="if (this.form) { if (this.form.requestSubmit) { this.form.requestSubmit(); } else { HTMLFormElement.prototype.submit.call(this.form); } }">';
		$this->render_option( 'all', $plugin_status_filter, __( 'All plugins', 'ai-not' ) );
		$this->render_option( 'active', $plugin_status_filter, __( 'Active only', 'ai-not' ) );
		$this->render_option( 'inactive', $plugin_status_filter, __( 'Inactive only', 'ai-not' ) );
		echo '</select>';
		echo ' ';
		echo '<label for="ai-not-access-filter"><strong>' . esc_html__( 'AI access', 'ai-not' ) . '</strong></label> ';
		echo '<select id="ai-not-access-filter" name="ai_not_access" onchange="if (this.form) { if (this.form.requestSubmit) { this.form.requestSubmit(); } else { HTMLFormElement.prototype.submit.call(this.form); } }">';
		$this->render_option( 'all', $plugin_access_filter, __( 'All', 'ai-not' ) );
		$this->render_option( 'effective-allow', $plugin_access_filter, __( 'Effective allow', 'ai-not' ) );
		$this->render_option( 'effective-deny', $plugin_access_filter, __( 'Effective deny', 'ai-not' ) );
		$this->render_option( 'default-only', $plugin_access_filter, __( 'Default only', 'ai-not' ) );
		echo '</select>';
		echo '</p>';
		echo '</form>';

		echo '<form method="post">';
		wp_nonce_field( 'ai_not_save_policy', 'ai_not_nonce' );
		echo '<input type="hidden" name="ai_not_action" value="save" />';
		echo '<input type="hidden" name="ai_not_status" value="' . esc_attr( $plugin_status_filter ) . '" />';
		echo '<input type="hidden" name="ai_not_access" value="' . esc_attr( $plugin_access_filter ) . '" />';

		echo '<table class="form-table" role="presentation">';
		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Default policy', 'ai-not' ) . '</th>';
		echo '<td>';
		echo '<select name="ai_not_default">';
		$this->render_option( 'allow', $policy['default'] ?? 'allow', __( 'Allow', 'ai-not' ) );
		$this->render_option( 'deny', $policy['default'] ?? 'allow', __( 'Deny', 'ai-not' ) );
		echo '</select>';
		echo '<p class="description">' . esc_html__( 'Used when the calling plugin cannot be resolved or has no explicit rule.', 'ai-not' ) . '</p>';
		echo '</td>';
		echo '</tr>';

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Logging', 'ai-not' ) . '</th>';
		echo '<td>';
		echo '<label><input type="checkbox" name="ai_not_log_enabled" value="1" ' . checked( ! empty( $policy['log_enabled'] ), true, false ) . ' /> ' . esc_html__( 'Enable recent-call logging', 'ai-not' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'When enabled, this stores a local “recent calls” log (plugin attribution, decision, user id, and request URI). Nothing is sent off-site.', 'ai-not' ) . '</p>';
		echo '</td>';
		echo '</tr>';
		echo '</table>';

		echo '<h2>' . esc_html__( 'Plugin rules', 'ai-not' ) . '</h2>';
		echo '<table class="widefat striped">';
		echo '<thead><tr>';
		echo '<th>' . esc_html__( 'Plugin', 'ai-not' ) . '</th>';
		echo '<th>' . esc_html__( 'Status', 'ai-not' ) . '</th>';
		echo '<th>' . esc_html__( 'AI access', 'ai-not' ) . '</th>';
		echo '<th>' . esc_html__( 'Plugin file', 'ai-not' ) . '</th>';
		echo '</tr></thead>';
		echo '<tbody>';

		foreach ( $plugins as $basename => $data ) {
			$name    = isset( $data['Name'] ) ? (string) $data['Name'] : $basename;
			$rule    = $policy['plugins'][ $basename ] ?? '';
			$enabled = isset( $active[ $basename ] );

			if ( 'active' === $plugin_status_filter && ! $enabled ) {
				continue;
			}
			if ( 'inactive' === $plugin_status_filter && $enabled ) {
				continue;
			}

			$explicit = ( 'allow' === $rule || 'deny' === $rule ) ? $rule : '';
			$effective = $explicit ? $explicit : ( ( $policy['default'] ?? 'allow' ) === 'deny' ? 'deny' : 'allow' );

			if ( 'default-only' === $plugin_access_filter && '' !== $explicit ) {
				continue;
			}
			if ( 'effective-allow' === $plugin_access_filter && 'allow' !== $effective ) {
				continue;
			}
			if ( 'effective-deny' === $plugin_access_filter && 'deny' !== $effective ) {
				continue;
			}

			echo '<tr>';
			echo '<td><strong>' . esc_html( $name ) . '</strong></td>';
			echo '<td>' . ( $enabled ? '<span class="dashicons dashicons-yes"></span> ' . esc_html__( 'Active', 'ai-not' ) : esc_html__( 'Inactive', 'ai-not' ) ) . '</td>';
			echo '<td>';
			echo '<select name="ai_not_rule[' . esc_attr( $basename ) . ']">';
			$this->render_option( '', (string) $rule, __( 'Default', 'ai-not' ) );
			$this->render_option( 'allow', (string) $rule, __( 'Allow', 'ai-not' ) );
			$this->render_option( 'deny', (string) $rule, __( 'Deny', 'ai-not' ) );
			echo '</select>';
			echo '</td>';
			echo '<td><code>' . esc_html( $basename ) . '</code></td>';
			echo '</tr>';
		}

		echo '</tbody>';
		echo '</table>';

		submit_button( __( 'Save changes', 'ai-not' ) );
		echo '</form>';

		echo '<h2>' . esc_html__( 'Recent AI calls (best-effort)', 'ai-not' ) . '</h2>';
		echo '<table class="widefat striped">';
		echo '<thead><tr>';
		echo '<th>' . esc_html__( 'Time', 'ai-not' ) . '</th>';
		echo '<th>' . esc_html__( 'Decision', 'ai-not' ) . '</th>';
		echo '<th>' . esc_html__( 'Plugin', 'ai-not' ) . '</th>';
		echo '<th>' . esc_html__( 'Source file', 'ai-not' ) . '</th>';
		echo '<th>' . esc_html__( 'User', 'ai-not' ) . '</th>';
		echo '<th>' . esc_html__( 'URI', 'ai-not' ) . '</th>';
		echo '</tr></thead><tbody>';

		$log = array_reverse( $log );
		$shown = 0;
		foreach ( $log as $row ) {
			if ( $shown >= 50 ) {
				break;
			}
			$shown++;
			$ts       = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			$decision = isset( $row['decision'] ) ? (string) $row['decision'] : '';
			$plugin   = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			$file     = isset( $row['file'] ) ? (string) $row['file'] : '';
			$user_id  = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
			$uri      = isset( $row['uri'] ) ? (string) $row['uri'] : '';

			echo '<tr>';
			echo '<td>' . esc_html( $ts ? wp_date( 'Y-m-d H:i:s', $ts ) : '' ) . '</td>';
			echo '<td>' . esc_html( $decision ) . '</td>';
			echo '<td><code>' . esc_html( $plugin ?: 'unknown' ) . '</code></td>';
			echo '<td><code style="font-size:12px;">' . esc_html( $file ) . '</code></td>';
			echo '<td>' . esc_html( $user_id ? (string) $user_id : '' ) . '</td>';
			echo '<td><code style="font-size:12px;">' . esc_html( $uri ) . '</code></td>';
			echo '</tr>';
		}

		if ( 0 === $shown ) {
			echo '<tr><td colspan="6">' . esc_html__( 'No calls logged yet.', 'ai-not' ) . '</td></tr>';
		}

		echo '</tbody></table>';
		echo '</div>';
	}

	private function handle_save(): void {
		check_admin_referer( 'ai_not_save_policy', 'ai_not_nonce' );

		$policy = Policy::get_policy();

		$posted_default = filter_input( INPUT_POST, 'ai_not_default', FILTER_UNSAFE_RAW );
		$policy['default'] = ( 'deny' === sanitize_text_field( (string) $posted_default ) ) ? 'deny' : 'allow';

		$posted_log_enabled = filter_input( INPUT_POST, 'ai_not_log_enabled', FILTER_UNSAFE_RAW );
		$policy['log_enabled'] = ! empty( $posted_log_enabled );

		$rules = array();
		$posted_rules = filter_input( INPUT_POST, 'ai_not_rule', FILTER_UNSAFE_RAW, FILTER_REQUIRE_ARRAY );
		if ( is_array( $posted_rules ) ) {
			foreach ( $posted_rules as $basename => $rule ) {
				$basename = sanitize_text_field( (string) $basename );
				$rule     = sanitize_text_field( (string) $rule );
				if ( '' === $basename ) {
					continue;
				}
				if ( 'allow' === $rule || 'deny' === $rule ) {
					$rules[ $basename ] = $rule;
				}
			}
		}
		$policy['plugins'] = $rules;

		Policy::save_policy( $policy );
	}

	private function render_option( string $value, string $current, string $label ): void {
		echo '<option value="' . esc_attr( $value ) . '" ' . selected( $current, $value, false ) . '>' . esc_html( $label ) . '</option>';
	}
}

