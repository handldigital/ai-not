<?php
/**
 * Admin UI.
 *
 * @package HandL_AIGate
 */

namespace HandL\AIGate;

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
			__( 'HandL AI Gate', 'handl-ai-gate' ),
			__( 'HandL AI Gate', 'handl-ai-gate' ),
			'manage_options',
			'handl-ai-gate',
			array( $this, 'render_page' )
		);
	}

	public function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'handl-ai-gate' ) );
		}

		$plugin_status_filter = 'all';
		if ( isset( $_REQUEST['handl_aigate_status'] ) ) {
			$plugin_status_filter = sanitize_text_field( wp_unslash( (string) $_REQUEST['handl_aigate_status'] ) );
		}
		if ( 'active' !== $plugin_status_filter && 'inactive' !== $plugin_status_filter ) {
			$plugin_status_filter = 'all';
		}

		$plugin_access_filter = 'all';
		if ( isset( $_REQUEST['handl_aigate_access'] ) ) {
			$plugin_access_filter = sanitize_text_field( wp_unslash( (string) $_REQUEST['handl_aigate_access'] ) );
		}
		if ( 'effective-allow' !== $plugin_access_filter && 'effective-deny' !== $plugin_access_filter && 'default-only' !== $plugin_access_filter ) {
			$plugin_access_filter = 'all';
		}

		if ( isset( $_POST['handl_aigate_action'] ) && 'save' === $_POST['handl_aigate_action'] ) {
			check_admin_referer( 'handl_aigate_save_policy', 'handl_aigate_nonce' );
			$this->handle_save();
			echo '<div class="notice notice-success"><p>' . esc_html__( 'Saved.', 'handl-ai-gate' ) . '</p></div>';
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
		echo '<h1>' . esc_html__( 'HandL AI Gate', 'handl-ai-gate' ) . '</h1>';
		echo '<p>' . esc_html__( 'Allow/deny which plugins may execute prompts via the WordPress AI Client. Default policy is allow.', 'handl-ai-gate' ) . '</p>';

		echo '<form method="get" style="margin: 0 0 12px 0;">';
		echo '<input type="hidden" name="page" value="handl-ai-gate" />';
		echo '<p style="margin: 0;">';
		echo '<label for="handl-aigate-status-filter"><strong>' . esc_html__( 'Show', 'handl-ai-gate' ) . '</strong></label> ';
		echo '<select id="handl-aigate-status-filter" name="handl_aigate_status" onchange="if (this.form) { if (this.form.requestSubmit) { this.form.requestSubmit(); } else { HTMLFormElement.prototype.submit.call(this.form); } }">';
		$this->render_option( 'all', $plugin_status_filter, __( 'All plugins', 'handl-ai-gate' ) );
		$this->render_option( 'active', $plugin_status_filter, __( 'Active only', 'handl-ai-gate' ) );
		$this->render_option( 'inactive', $plugin_status_filter, __( 'Inactive only', 'handl-ai-gate' ) );
		echo '</select>';
		echo ' ';
		echo '<label for="handl-aigate-access-filter"><strong>' . esc_html__( 'AI access', 'handl-ai-gate' ) . '</strong></label> ';
		echo '<select id="handl-aigate-access-filter" name="handl_aigate_access" onchange="if (this.form) { if (this.form.requestSubmit) { this.form.requestSubmit(); } else { HTMLFormElement.prototype.submit.call(this.form); } }">';
		$this->render_option( 'all', $plugin_access_filter, __( 'All', 'handl-ai-gate' ) );
		$this->render_option( 'effective-allow', $plugin_access_filter, __( 'Effective allow', 'handl-ai-gate' ) );
		$this->render_option( 'effective-deny', $plugin_access_filter, __( 'Effective deny', 'handl-ai-gate' ) );
		$this->render_option( 'default-only', $plugin_access_filter, __( 'Default only', 'handl-ai-gate' ) );
		echo '</select>';
		echo '</p>';
		echo '</form>';

		echo '<form method="post">';
		wp_nonce_field( 'handl_aigate_save_policy', 'handl_aigate_nonce' );
		echo '<input type="hidden" name="handl_aigate_action" value="save" />';
		echo '<input type="hidden" name="handl_aigate_status" value="' . esc_attr( $plugin_status_filter ) . '" />';
		echo '<input type="hidden" name="handl_aigate_access" value="' . esc_attr( $plugin_access_filter ) . '" />';

		echo '<table class="form-table" role="presentation">';
		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Default policy', 'handl-ai-gate' ) . '</th>';
		echo '<td>';
		echo '<select name="handl_aigate_default">';
		$this->render_option( 'allow', $policy['default'] ?? 'allow', __( 'Allow', 'handl-ai-gate' ) );
		$this->render_option( 'deny', $policy['default'] ?? 'allow', __( 'Deny', 'handl-ai-gate' ) );
		echo '</select>';
		echo '<p class="description">' . esc_html__( 'Used when the calling plugin cannot be resolved or has no explicit rule.', 'handl-ai-gate' ) . '</p>';
		echo '</td>';
		echo '</tr>';

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Logging', 'handl-ai-gate' ) . '</th>';
		echo '<td>';
		echo '<label><input type="checkbox" name="handl_aigate_log_enabled" value="1" ' . checked( ! empty( $policy['log_enabled'] ), true, false ) . ' /> ' . esc_html__( 'Enable recent-call logging', 'handl-ai-gate' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'When enabled, this stores a local “recent calls” log (plugin attribution, decision, user id, and request URI). Nothing is sent off-site.', 'handl-ai-gate' ) . '</p>';
		echo '</td>';
		echo '</tr>';
		echo '</table>';

		echo '<h2>' . esc_html__( 'Plugin rules', 'handl-ai-gate' ) . '</h2>';
		echo '<table class="widefat striped">';
		echo '<thead><tr>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-gate' ) . '</th>';
		echo '<th>' . esc_html__( 'Status', 'handl-ai-gate' ) . '</th>';
		echo '<th>' . esc_html__( 'AI access', 'handl-ai-gate' ) . '</th>';
		echo '<th>' . esc_html__( 'Plugin file', 'handl-ai-gate' ) . '</th>';
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
			echo '<td>' . ( $enabled ? '<span class="dashicons dashicons-yes"></span> ' . esc_html__( 'Active', 'handl-ai-gate' ) : esc_html__( 'Inactive', 'handl-ai-gate' ) ) . '</td>';
			echo '<td>';
			echo '<select name="handl_aigate_rule[' . esc_attr( $basename ) . ']">';
			$this->render_option( '', (string) $rule, __( 'Default', 'handl-ai-gate' ) );
			$this->render_option( 'allow', (string) $rule, __( 'Allow', 'handl-ai-gate' ) );
			$this->render_option( 'deny', (string) $rule, __( 'Deny', 'handl-ai-gate' ) );
			echo '</select>';
			echo '</td>';
			echo '<td><code>' . esc_html( $basename ) . '</code></td>';
			echo '</tr>';
		}

		echo '</tbody>';
		echo '</table>';

		submit_button( __( 'Save changes', 'handl-ai-gate' ) );
		echo '</form>';

		echo '<h2>' . esc_html__( 'Recent AI calls (best-effort)', 'handl-ai-gate' ) . '</h2>';
		echo '<table class="widefat striped">';
		echo '<thead><tr>';
		echo '<th>' . esc_html__( 'Time', 'handl-ai-gate' ) . '</th>';
		echo '<th>' . esc_html__( 'Decision', 'handl-ai-gate' ) . '</th>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-gate' ) . '</th>';
		echo '<th>' . esc_html__( 'Source file', 'handl-ai-gate' ) . '</th>';
		echo '<th>' . esc_html__( 'User', 'handl-ai-gate' ) . '</th>';
		echo '<th>' . esc_html__( 'URI', 'handl-ai-gate' ) . '</th>';
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
			echo '<tr><td colspan="6">' . esc_html__( 'No calls logged yet.', 'handl-ai-gate' ) . '</td></tr>';
		}

		echo '</tbody></table>';
		echo '</div>';
	}

	private function handle_save(): void {
		check_admin_referer( 'handl_aigate_save_policy', 'handl_aigate_nonce' );

		$policy = Policy::get_policy();

		$posted_default = filter_input( INPUT_POST, 'handl_aigate_default', FILTER_UNSAFE_RAW );
		$policy['default'] = ( 'deny' === sanitize_text_field( (string) $posted_default ) ) ? 'deny' : 'allow';

		$posted_log_enabled = filter_input( INPUT_POST, 'handl_aigate_log_enabled', FILTER_UNSAFE_RAW );
		$policy['log_enabled'] = ! empty( $posted_log_enabled );

		$rules = array();
		$posted_rules = filter_input( INPUT_POST, 'handl_aigate_rule', FILTER_UNSAFE_RAW, FILTER_REQUIRE_ARRAY );
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
