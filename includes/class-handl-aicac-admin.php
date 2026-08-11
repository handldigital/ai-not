<?php
/**
 * Admin UI.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Admin {
	private const LOG_FILTER_UNKNOWN = Audit_Export::FILTER_UNKNOWN;

	/**
	 * @var array{decision:string,operation:string,provider:string,model:string,plugin:string}
	 */
	private array $log_filters = array(
		'decision'  => '',
		'operation' => '',
		'provider'  => '',
		'model'     => '',
		'plugin'    => '',
	);

	/** Set when Activity save rejects an invalid webhook URL (AC6). */
	private bool $webhook_url_rejected = false;

	/**
	 * AICAC-BULK result for Rules-tab inline notices.
	 *
	 * @var null|array{status:string,updated?:int}
	 */
	private ?array $bulk_result = null;

	/**
	 * AICAC-SIM dry-run result for Rules-tab panel (never persists policy).
	 *
	 * @var null|array<string,mixed>
	 */
	private ?array $sim_result = null;

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
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		// File downloads must run before admin-header HTML is buffered (render_page is too late).
		add_action( 'admin_init', array( $this, 'maybe_handle_file_downloads' ) );
	}

	/**
	 * Shared capability gate (single current_user_can for authz inventory).
	 */
	private function user_can_manage_options(): bool {
		return current_user_can( 'manage_options' );
	}

	public function enqueue_assets( string $hook_suffix ): void {
		if ( 'settings_page_handl-ai-connector-access-control' !== $hook_suffix ) {
			return;
		}

		wp_enqueue_style(
			'handl-aicac-admin',
			HANDL_AICAC_URL . 'assets/admin.css',
			array(),
			HANDL_AICAC_VERSION
		);
	}

	public function register_menu(): void {
		add_options_page(
			__( 'HandL AI Access', 'handl-ai-connector-access-control' ),
			__( 'HandL AI Access', 'handl-ai-connector-access-control' ),
			'manage_options',
			'handl-ai-connector-access-control',
			array( $this, 'render_page' )
		);
	}

	/**
	 * Stream export downloads on admin_init — before any admin HTML output.
	 *
	 * Handling these inside render_page() leaves the buffered admin chrome in the
	 * response body, so browsers save an HTML document with a .csv/.json filename.
	 */
	public function maybe_handle_file_downloads(): void {
		if ( ! isset( $_POST['handl_aicac_action'] ) ) {
			return;
		}

		$posted_action = sanitize_key( wp_unslash( (string) $_POST['handl_aicac_action'] ) );
		if ( 'export_log' !== $posted_action && 'export_rules' !== $posted_action && 'export_audit_report' !== $posted_action ) {
			return;
		}

		if ( ! $this->user_can_manage_options() ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'handl-ai-connector-access-control' ) );
		}

		if ( 'export_log' === $posted_action ) {
			check_admin_referer( 'handl_aicac_export_log', 'handl_aicac_nonce' );
			$this->log_filters = $this->parse_log_filters();
			$this->handle_export_log();
		}

		if ( 'export_rules' === $posted_action ) {
			check_admin_referer( 'handl_aicac_export_rules', 'handl_aicac_nonce' );
			$this->handle_export_rules();
		}

		if ( 'export_audit_report' === $posted_action ) {
			check_admin_referer( 'handl_aicac_export_audit_report', 'handl_aicac_nonce' );
			$this->handle_export_audit_report();
		}
	}

	/**
	 * AICAC-22 defense-in-depth: re-verify capability + CSRF inside private mutators.
	 *
	 * render_page already gates manage_options and checks the action nonce before
	 * dispatch. This aborts again if a future call site invokes a mutator without
	 * those checks (public refactor, REST/AJAX, admin-post).
	 *
	 * @param string $nonce_action Same action string as the dispatch check_admin_referer.
	 */
	private function require_admin_mutation( string $nonce_action ): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( $nonce_action, 'handl_aicac_nonce' );
	}

	public function render_page(): void {
		if ( ! $this->user_can_manage_options() ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'handl-ai-connector-access-control' ) );
		}

		// F5: Dashboard is default (board Q2). "log" aliases Activity for old bookmarks.
		$tab = 'dashboard';
		if ( isset( $_REQUEST['handl_aicac_tab'] ) ) {
			$tab = sanitize_key( wp_unslash( (string) $_REQUEST['handl_aicac_tab'] ) );
		}
		if ( 'log' === $tab ) {
			$tab = 'activity';
		}
		if ( ! in_array( $tab, array( 'dashboard', 'rules', 'activity', 'insights', 'profile', 'whats-new' ), true ) ) {
			$tab = 'dashboard';
		}

		$plugin_status_filter = 'all';
		if ( isset( $_REQUEST['handl_aicac_status'] ) ) {
			$plugin_status_filter = sanitize_text_field( wp_unslash( (string) $_REQUEST['handl_aicac_status'] ) );
		}
		if ( 'active' !== $plugin_status_filter && 'inactive' !== $plugin_status_filter ) {
			$plugin_status_filter = 'all';
		}

		$plugin_access_filter = 'all';
		if ( isset( $_REQUEST['handl_aicac_access'] ) ) {
			$plugin_access_filter = sanitize_text_field( wp_unslash( (string) $_REQUEST['handl_aicac_access'] ) );
		}
		if ( 'effective-allow' !== $plugin_access_filter && 'effective-deny' !== $plugin_access_filter && 'default-only' !== $plugin_access_filter ) {
			$plugin_access_filter = 'all';
		}

		$this->log_filters = $this->parse_log_filters();

		if ( isset( $_POST['handl_aicac_action'] ) ) {
			$posted_action = sanitize_key( wp_unslash( (string) $_POST['handl_aicac_action'] ) );
			if ( 'quick_rule' === $posted_action ) {
				check_admin_referer( 'handl_aicac_quick_rule', 'handl_aicac_nonce' );
				$this->handle_quick_rule_redirect( $this->log_filters );
			}
			if ( 'send_denial_digest' === $posted_action ) {
				check_admin_referer( 'handl_aicac_send_digest', 'handl_aicac_nonce' );
				Alerts::instance()->send_digest();
				$redirect = add_query_arg(
					array(
						'page'                    => 'handl-ai-connector-access-control',
						'handl_aicac_tab'         => 'activity',
						'handl_aicac_digest_sent' => '1',
					),
					admin_url( 'options-general.php' )
				);
				wp_safe_redirect( $redirect );
				exit;
			}
			if ( 'send_test_webhook' === $posted_action ) {
				check_admin_referer( 'handl_aicac_send_test_webhook', 'handl_aicac_nonce' );
				$ok = Alerts::send_test_webhook( Policy::get_policy() );
				$return_tab = 'activity';
				if ( isset( $_POST['handl_aicac_tab'] ) ) {
					$candidate = sanitize_key( wp_unslash( (string) $_POST['handl_aicac_tab'] ) );
					if ( in_array( $candidate, array( 'activity', 'dashboard' ), true ) ) {
						$return_tab = $candidate;
					}
				}
				$redirect = add_query_arg(
					array(
						'page'                       => 'handl-ai-connector-access-control',
						'handl_aicac_tab'            => $return_tab,
						'handl_aicac_webhook_tested' => $ok ? '1' : '0',
					),
					admin_url( 'options-general.php' )
				);
				wp_safe_redirect( $redirect );
				exit;
			}
			if ( 'send_test_email' === $posted_action ) {
				check_admin_referer( 'handl_aicac_send_test_email', 'handl_aicac_nonce' );
				$channel = Alerts::sanitize_test_email_channel(
					isset( $_POST['handl_aicac_test_email_channel'] )
						? wp_unslash( (string) $_POST['handl_aicac_test_email_channel'] )
						: 'denial_alert'
				);
				if ( '' === $channel ) {
					$channel = 'denial_alert';
				}
				$result = Alerts::send_test_email( Policy::get_policy(), $channel );
				$return_tab = 'activity';
				if ( isset( $_POST['handl_aicac_tab'] ) ) {
					$candidate = sanitize_key( wp_unslash( (string) $_POST['handl_aicac_tab'] ) );
					if ( in_array( $candidate, array( 'activity', 'dashboard' ), true ) ) {
						$return_tab = $candidate;
					}
				}
				$redirect = add_query_arg(
					array(
						'page'                      => 'handl-ai-connector-access-control',
						'handl_aicac_tab'           => $return_tab,
						'handl_aicac_test_email'    => (string) $result['status'],
						'handl_aicac_test_email_to' => Alerts::encode_email_query_arg( (string) $result['to'] ),
					),
					admin_url( 'options-general.php' )
				);
				wp_safe_redirect( $redirect );
				exit;
			}
			if ( 'undo_quick_rule' === $posted_action ) {
				check_admin_referer( 'handl_aicac_undo_quick_rule', 'handl_aicac_nonce' );
				$this->handle_undo_quick_rule();
			}
			// export_log / export_rules: handled on admin_init (maybe_handle_file_downloads).
			if ( 'import_rules_preview' === $posted_action ) {
				check_admin_referer( 'handl_aicac_import_rules', 'handl_aicac_nonce' );
				$this->handle_import_rules_preview();
			}
			if ( 'import_rules_confirm' === $posted_action ) {
				check_admin_referer( 'handl_aicac_import_rules_confirm', 'handl_aicac_nonce' );
				$this->handle_import_rules_confirm();
			}
			if ( 'preset_preview' === $posted_action ) {
				check_admin_referer( 'handl_aicac_preset_preview', 'handl_aicac_nonce' );
				$this->handle_preset_preview();
			}
			if ( 'preset_apply_confirm' === $posted_action ) {
				check_admin_referer( 'handl_aicac_preset_apply_confirm', 'handl_aicac_nonce' );
				$this->handle_preset_apply_confirm();
			}
			if ( 'bulk_plugin_rules' === $posted_action ) {
				check_admin_referer( 'handl_aicac_save_policy', 'handl_aicac_nonce' );
				$this->handle_bulk_plugin_rules();
			}
			if ( 'renew_temp_allow' === $posted_action ) {
				check_admin_referer( 'handl_aicac_renew_temp_allow', 'handl_aicac_nonce' );
				$this->handle_renew_temp_allow();
			}
			if ( 'simulate_policy' === $posted_action ) {
				check_admin_referer( 'handl_aicac_save_policy', 'handl_aicac_nonce' );
				$this->handle_simulate_policy();
			}
			if ( 'onboard_dismiss' === $posted_action ) {
				check_admin_referer( 'handl_aicac_onboard', 'handl_aicac_nonce' );
				$this->handle_onboard_dismiss();
			}
			if ( 'onboard_step' === $posted_action ) {
				check_admin_referer( 'handl_aicac_onboard', 'handl_aicac_nonce' );
				$this->handle_onboard_step();
			}
			if ( 'onboard_test_email' === $posted_action ) {
				check_admin_referer( 'handl_aicac_onboard', 'handl_aicac_nonce' );
				$this->handle_onboard_test_email();
			}
			if ( 'onboard_reopen' === $posted_action ) {
				check_admin_referer( 'handl_aicac_onboard', 'handl_aicac_nonce' );
				$this->handle_onboard_reopen();
			}
		}

		$saved       = false;
		$quick_saved = isset( $_GET['handl_aicac_quick_saved'] ) && '1' === (string) $_GET['handl_aicac_quick_saved'];
		$digest_sent = isset( $_GET['handl_aicac_digest_sent'] ) && '1' === (string) $_GET['handl_aicac_digest_sent'];
		$webhook_tested = isset( $_GET['handl_aicac_webhook_tested'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['handl_aicac_webhook_tested'] ) ) : '';
		$test_email_status = isset( $_GET['handl_aicac_test_email'] ) ? sanitize_key( wp_unslash( (string) $_GET['handl_aicac_test_email'] ) ) : '';
		$test_email_to     = isset( $_GET['handl_aicac_test_email_to'] )
			? Alerts::sanitize_email( wp_unslash( (string) $_GET['handl_aicac_test_email_to'] ) )
			: '';
		$blocked_ok  = isset( $_GET['handl_aicac_blocked'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['handl_aicac_blocked'] ) ) : '';
		$undo_rule   = isset( $_GET['handl_aicac_undo_rule'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['handl_aicac_undo_rule'] ) ) : '';
		$undone      = isset( $_GET['handl_aicac_undone'] ) && '1' === (string) $_GET['handl_aicac_undone'];
		$imported_ok = isset( $_GET['handl_aicac_imported'] ) && '1' === (string) $_GET['handl_aicac_imported'];
		$import_err  = isset( $_GET['handl_aicac_import_error'] ) ? sanitize_key( wp_unslash( (string) $_GET['handl_aicac_import_error'] ) ) : '';
		$import_ignored_q = isset( $_GET['handl_aicac_import_ignored'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['handl_aicac_import_ignored'] ) ) : '';
		$show_import_preview = isset( $_GET['handl_aicac_import_preview'] ) && '1' === (string) $_GET['handl_aicac_import_preview'];
		$renewed_ok = isset( $_GET['handl_aicac_renewed'] ) && '1' === (string) $_GET['handl_aicac_renewed'];
		$show_preset_preview = isset( $_GET['handl_aicac_preset_preview'] ) && '1' === (string) $_GET['handl_aicac_preset_preview'];
		$preset_status       = isset( $_GET['handl_aicac_preset'] ) ? sanitize_key( wp_unslash( (string) $_GET['handl_aicac_preset'] ) ) : '';
		$preset_id_q         = isset( $_GET['handl_aicac_preset_id'] ) ? sanitize_key( wp_unslash( (string) $_GET['handl_aicac_preset_id'] ) ) : '';

		if ( isset( $_POST['handl_aicac_action'] ) && 'save' === $_POST['handl_aicac_action'] ) {
			check_admin_referer( 'handl_aicac_save_policy', 'handl_aicac_nonce' );
			if ( 'activity' === $tab ) {
				$this->handle_save_log();
			} else {
				$this->handle_save_rules();
			}
			$saved = true;
		}

		$policy = Policy::get_policy();

		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$plugins = get_plugins();
		$active  = array_flip( (array) get_option( 'active_plugins', array() ) );

		// Read path applies TTL + entry-count retention and persists when rows drop.
		$log = Policy::get_retained_log();

		$icon_src = add_query_arg( 'ver', HANDL_AICAC_VERSION, HANDL_AICAC_URL . 'assets/icon-128x128.png' );

		echo '<div class="wrap">';
		echo '<h1 style="display:flex;align-items:center;gap:12px;">';
		echo '<img src="' . esc_url( $icon_src ) . '" alt="" width="40" height="40" style="border-radius:8px;" loading="lazy" decoding="async" />';
		echo esc_html__( 'HandL AI Access', 'handl-ai-connector-access-control' );
		echo '</h1>';
echo '<p>' . esc_html__( 'See which AI activity these rules control, what may be driving estimated spend, and block a plugin with one click. The default is Allow.', 'handl-ai-connector-access-control' );
		echo ' ' . esc_html( Differentiator_Messaging::page_subtitle_addition() ) . '</p>';

		$this->render_tabs( $tab, $plugin_status_filter, $plugin_access_filter, $this->log_filters );

		if ( $saved ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Saved.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( $renewed_ok ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Temporary allow renewed for 7 more days.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( $this->webhook_url_rejected ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Webhook URL not saved. Enter a valid http:// or https:// URL, or leave it blank to disable webhooks.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( is_array( $this->bulk_result ) ) {
			$status = (string) ( $this->bulk_result['status'] ?? '' );
			if ( 'empty' === $status ) {
				echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__( 'No plugins selected. No rules were changed.', 'handl-ai-connector-access-control' ) . '</p></div>';
			} elseif ( 'invalid' === $status ) {
				echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Choose Set to Allow or Set to Deny, then Apply.', 'handl-ai-connector-access-control' ) . '</p></div>';
			} elseif ( 'ok' === $status ) {
				$n = (int) ( $this->bulk_result['updated'] ?? 0 );
				echo '<div class="notice notice-success is-dismissible"><p>';
				echo esc_html(
					sprintf(
						/* translators: %d: number of plugins updated */
						_n(
							'Updated AI access for %d selected plugin.',
							'Updated AI access for %d selected plugins.',
							$n,
							'handl-ai-connector-access-control'
						),
						$n
					)
				);
				echo '</p></div>';
			}
		}
		if ( $quick_saved ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Plugin rule updated.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( $digest_sent ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Tried to send the blocked-call summary. Queued alerts are cleared only after a successful send.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( '1' === $webhook_tested ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Test webhook sent successfully (HTTP 2xx).', 'handl-ai-connector-access-control' ) . '</p></div>';
		} elseif ( '0' === $webhook_tested ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Test webhook failed. Check the URL and try again. The test does not count toward rate limits.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( 'sent' === $test_email_status ) {
			echo '<div class="notice notice-success is-dismissible"><p>';
			if ( '' !== $test_email_to ) {
				echo esc_html(
					sprintf(
						/* translators: %s: recipient email address */
						__( 'Test email sent to %s. WordPress accepted the message for sending, but inbox delivery is not guaranteed.', 'handl-ai-connector-access-control' ),
						$test_email_to
					)
				);
			} else {
				echo esc_html__( 'Test email sent to the configured recipient. WordPress accepted the message for sending, but inbox delivery is not guaranteed.', 'handl-ai-connector-access-control' );
			}
			echo '</p></div>';
		} elseif ( 'failed' === $test_email_status ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'WordPress could not send the test email. Check your site’s email or SMTP settings.', 'handl-ai-connector-access-control' ) . '</p></div>';
		} elseif ( 'rate_limited' === $test_email_status ) {
			echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__( 'Please wait one minute before sending another test email.', 'handl-ai-connector-access-control' ) . '</p></div>';
		} elseif ( 'no_recipient' === $test_email_status || 'invalid_channel' === $test_email_status ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Test email could not be sent because no valid recipient is available. Set a recipient for denial alerts or add a valid site admin email.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( $undone ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Plugin rule restored.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( $imported_ok ) {
			echo '<div class="notice notice-success is-dismissible"><p>';
			echo esc_html__( 'Rules imported. Your previous rule settings were replaced with the uploaded file.', 'handl-ai-connector-access-control' );
			echo ' <a href="' . esc_url(
				add_query_arg(
					array(
						'page'            => 'handl-ai-connector-access-control',
						'handl_aicac_tab' => 'rules',
					),
					admin_url( 'options-general.php' )
				)
			) . '">' . esc_html__( 'Back to Rules', 'handl-ai-connector-access-control' ) . '</a>';
			echo '</p></div>';
			if ( '' !== $import_ignored_q ) {
				$ignored_list = array_filter( array_map( 'trim', explode( ',', $import_ignored_q ) ) );
				if ( ! empty( $ignored_list ) ) {
					echo '<div class="notice notice-warning is-dismissible"><p>';
					echo esc_html__( 'Ignored unsupported fields from a newer export:', 'handl-ai-connector-access-control' );
					echo ' <code>' . esc_html( implode( ', ', $ignored_list ) ) . '</code>';
					echo '</p></div>';
				}
			}
		}
		if ( '' !== $import_err ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html( $this->import_error_message( $import_err ) ) . '</p></div>';
		}
		if ( 'applied' === $preset_status ) {
			$preset_label = $preset_id_q;
			$preset_def   = '' !== $preset_id_q ? Presets::get( $preset_id_q ) : null;
			if ( is_array( $preset_def ) ) {
				$preset_label = (string) $preset_def['label'];
			}
			echo '<div class="notice notice-success is-dismissible"><p>';
			echo esc_html(
				sprintf(
					/* translators: %s: preset name */
					__( 'Applied preset: %s.', 'handl-ai-connector-access-control' ),
					$preset_label
				)
			);
			echo '</p></div>';
		} elseif ( 'noop' === $preset_status ) {
			echo '<div class="notice notice-info is-dismissible"><p>' . esc_html__( 'That preset is already active. No settings were changed.', 'handl-ai-connector-access-control' ) . '</p></div>';
		} elseif ( 'error' === $preset_status ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Could not apply that preset. Your current settings were not changed.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( '' !== $blocked_ok ) {
			$blocked_label = isset( $plugins[ $blocked_ok ]['Name'] ) ? (string) $plugins[ $blocked_ok ]['Name'] : $blocked_ok;
			echo '<div class="notice notice-success is-dismissible"><p>';
			echo esc_html(
				sprintf(
					/* translators: %s: plugin display name */
					__( 'Blocked %s. New AI Client calls from this plugin will be blocked.', 'handl-ai-connector-access-control' ),
					$blocked_label
				)
			);
			// Board Q3: single-click block + undo notice (no confirm dialog).
			echo ' ';
			echo '<form method="post" class="handl-aicac-inline-undo" style="display:inline;">';
			wp_nonce_field( 'handl_aicac_undo_quick_rule', 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_action" value="undo_quick_rule" />';
			echo '<input type="hidden" name="handl_aicac_quick_plugin" value="' . esc_attr( $blocked_ok ) . '" />';
			echo '<input type="hidden" name="handl_aicac_undo_rule" value="' . esc_attr( $undo_rule ) . '" />';
			submit_button( __( 'Undo', 'handl-ai-connector-access-control' ), 'link', 'submit', false );
			echo '</form>';
			echo '</p></div>';
		}

		// Honesty banner: core skips our filter when AI is disabled site-wide.
		if ( function_exists( 'wp_supports_ai' ) && ! wp_supports_ai() ) {
			$why = defined( 'WP_AI_SUPPORT' ) && ! WP_AI_SUPPORT
				? __( 'WP_AI_SUPPORT is set to false.', 'handl-ai-connector-access-control' )
				: __( 'wp_supports_ai returned false.', 'handl-ai-connector-access-control' );
			echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'AI is turned off for the whole site.', 'handl-ai-connector-access-control' ) . '</strong> ';
			echo esc_html( $why ) . ' ';
			echo esc_html__( 'WordPress stops these prompts before HandL AI Access can inspect them. The activity log may be empty or incomplete, but the plugin is working as expected.', 'handl-ai-connector-access-control' );
			echo '</p></div>';
		}

		// Distinct empty-window honesty when TTL pruned everything (not the same as wp_supports_ai).
		$max_age_days = Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null );
		if ( null !== $max_age_days && 0 === count( $log ) && ( ! empty( $policy['log_enabled'] ) || ! empty( $policy['audit_only'] ) ) ) {
			echo '<div class="notice notice-info"><p><strong>' . esc_html__( 'No activity is stored for the current time window.', 'handl-ai-connector-access-control' ) . '</strong> ';
			echo esc_html(
				sprintf(
					/* translators: %d: maximum log age in days */
					__( 'Your %d-day time limit removed older log rows. This is different from site-wide AI being disabled, which prevents calls from being logged.', 'handl-ai-connector-access-control' ),
					$max_age_days
				)
			);
			echo '</p></div>';
		}

		if ( ! empty( $policy['audit_only'] ) ) {
			$audit_notice = esc_html__( 'Learn mode is on. Calls are logged but never blocked. Plugin rules show what would happen. Turn off Learn mode on the Activity tab when you are ready to enforce your rules.', 'handl-ai-connector-access-control' );
			if ( 'activity' !== $tab ) {
				$audit_notice .= ' <a href="' . esc_url( admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=activity' ) ) . '">' . esc_html__( 'Open Activity', 'handl-ai-connector-access-control' ) . '</a>';
			}
			echo '<div class="notice notice-info"><p>' . wp_kses_post( $audit_notice ) . '</p></div>';
		} elseif ( ! empty( $policy['kill_switch'] ) ) {
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'Emergency stop is on. All AI Client calls are blocked except listed plugins.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}

		// AICAC-FORECAST: mid-month projection vs configured spend thresholds.
		if ( 'dashboard' === $tab ) {
			foreach ( Spend_Forecast::active_warnings( $log, $policy ) as $warn ) {
				echo '<div class="notice notice-warning"><p>' . esc_html( Spend_Forecast::notice_text( $warn ) ) . '</p></div>';
			}
		}

		if ( 'dashboard' === $tab ) {
			$this->render_dashboard_tab( $log, $policy, $plugins );
			echo '</div>';
			return;
		}

		if ( 'profile' === $tab ) {
			$this->render_plugin_profile_tab( $log, $policy, $plugins, $active );
			echo '</div>';
			return;
		}

		if ( 'whats-new' === $tab ) {
			Whats_New::dismiss_for_user( get_current_user_id() );
			Whats_New::render_panel();
			echo '</div>';
			return;
		}

		if ( 'activity' === $tab ) {
			$this->render_log_tab( $log, $policy, $plugins );
			echo '</div>';
			return;
		}

		if ( 'insights' === $tab ) {
			$this->render_insights_tab( $log, $policy, $plugins );
			echo '</div>';
			return;
		}

		// --- Rules tab ---
		echo '<div class="handl-aicac-tab-panel">';

		$rules_form_id = 'handl-aicac-rules-save';
		$bulk_form_id  = 'handl-aicac-bulk-rules';

		// Bulk shell first — must not nest inside the rules form.
		echo '<form method="post" id="' . esc_attr( $bulk_form_id ) . '" class="handl-aicac-rules-save-form">';
		wp_nonce_field( 'handl_aicac_save_policy', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="bulk_plugin_rules" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="rules" />';
		echo '<input type="hidden" name="handl_aicac_status" value="' . esc_attr( $plugin_status_filter ) . '" />';
		echo '<input type="hidden" name="handl_aicac_access" value="' . esc_attr( $plugin_access_filter ) . '" />';
		echo '</form>';

		// Renew shell — associated via form= on Renew buttons (no nested forms).
		echo '<form method="post" id="handl-aicac-renew-form" class="handl-aicac-rules-save-form">';
		wp_nonce_field( 'handl_aicac_renew_temp_allow', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="renew_temp_allow" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="rules" />';
		echo '</form>';

		// Visible Rules form — do NOT use handl-aicac-rules-save-form (that class is
		// display:none for empty shells that only exist for form= association).
		echo '<form method="post" id="' . esc_attr( $rules_form_id ) . '">';
		wp_nonce_field( 'handl_aicac_save_policy', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_tab" value="rules" />';
		echo '<input type="hidden" name="handl_aicac_status" value="' . esc_attr( $plugin_status_filter ) . '" />';
		echo '<input type="hidden" name="handl_aicac_access" value="' . esc_attr( $plugin_access_filter ) . '" />';
		// Early action slot: Save is after the matrix and can be truncated by
		// max_input_vars. Click/submit handlers copy data-aicac-action here first.
		echo '<input type="hidden" name="handl_aicac_action" id="handl-aicac-action" value="" />';
		echo '<script>';
		echo '(function(){var form=document.getElementById(' . wp_json_encode( $rules_form_id ) . ');';
		echo 'var action=document.getElementById("handl-aicac-action");if(!form||!action)return;';
		echo 'form.addEventListener("click",function(e){var b=e.target.closest("[data-aicac-action]");if(b){action.value=b.getAttribute("data-aicac-action");}});';
		echo 'form.addEventListener("submit",function(e){var b=e.submitter;if(b&&b.getAttribute("data-aicac-action")){action.value=b.getAttribute("data-aicac-action");}});';
		echo '})();';
		echo '</script>';

		$this->render_presets_section( $policy, $show_preset_preview );

		// Settings demoted: collapsible panel, not the first thing you see (F5 IA).
		echo '<details class="handl-aicac-settings-panel">';
		echo '<summary><strong>' . esc_html__( 'Settings', 'handl-ai-connector-access-control' ) . '</strong> — ';
		echo esc_html__( 'site default, unknown operations, emergency stop, limit by role, blocked tools, model routing', 'handl-ai-connector-access-control' );
		echo '</summary>';
		echo '<table class="form-table" role="presentation">';
		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Default policy', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<select name="handl_aicac_default" form="' . esc_attr( $rules_form_id ) . '">';
		$this->render_option( 'allow', $policy['default'] ?? 'allow', __( 'Allow', 'handl-ai-connector-access-control' ) );
		$this->render_option( 'deny', $policy['default'] ?? 'allow', __( 'Deny', 'handl-ai-connector-access-control' ) );
		echo '</select>';
		echo '<p class="description">' . esc_html__( 'Used when we cannot identify the calling plugin or the plugin has no rule.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td>';
		echo '</tr>';
		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Unknown AI operations', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		$unknown = $policy['unknown_operation'] ?? 'inherit';
		echo '<select name="handl_aicac_unknown_operation" form="' . esc_attr( $rules_form_id ) . '">';
		$this->render_option( 'inherit', (string) $unknown, __( 'Follow plugin rule', 'handl-ai-connector-access-control' ) );
		$this->render_option( 'allow', (string) $unknown, __( 'Allow', 'handl-ai-connector-access-control' ) );
		$this->render_option( 'deny', (string) $unknown, __( 'Deny', 'handl-ai-connector-access-control' ) );
		echo '</select>';
		echo '<p class="description">' . esc_html__( 'Choose what happens when an AI Client operation does not fit Text, Image, Speech, Text to speech, or Video. This includes music, embeddings, and generic methods. Support checks follow the same rule as the matching generation method.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td>';
		echo '</tr>';
		$this->render_kill_switch_settings_rows( $policy, $rules_form_id, $plugins );
		$this->render_shadow_block_settings_rows( $policy, $rules_form_id, $plugins );
		$this->render_role_gate_settings_rows( $policy, $rules_form_id );
		echo '</table>';

		$this->render_ability_arming_settings( $policy, $rules_form_id );
		$this->render_model_force_settings( $policy, $rules_form_id, $log );
		echo '</details>';

		// Test this policy BEFORE the plugin matrix: sandbox has ~176 plugins × ~8
		// fields, which exceeds PHP max_input_vars (1000). Fields after the cutoff
		// are dropped — including a late simulate_policy submit — so Run test must
		// appear early enough that action + sim inputs always reach PHP.
		$this->render_policy_simulator_panel( $policy, $plugins, $log, $rules_form_id );

		$family_labels = Operations::family_labels();
		$force_map     = Model_Force::force_map( $policy );
		$unforced_n    = Model_Force::count_unforced_unattributed( $log );
		$graduate      = Graduate::proposal_from_request();

		if ( is_array( $graduate ) ) {
			$grad_label = $graduate['plugin'];
			if ( isset( $plugins[ $graduate['plugin'] ]['Name'] ) ) {
				$grad_label = (string) $plugins[ $graduate['plugin'] ]['Name'];
			}
			$grad_coverage = Graduate::coverage_for( $policy, $graduate );
			if ( null !== $grad_coverage ) {
				echo '<div class="notice notice-warning"><p>';
				echo esc_html( Graduate::coverage_label( $grad_coverage, $plugins ) );
				echo ' ';
				echo esc_html__( 'No second rule was created.', 'handl-ai-connector-access-control' );
				echo '</p></div>';
			} else {
				echo '<div class="notice notice-info"><p><strong>';
				echo esc_html__( 'Create a rule from observed activity', 'handl-ai-connector-access-control' );
				echo '</strong> ';
				echo esc_html(
					sprintf(
						/* translators: %s: plugin display name */
						__( 'Review the highlighted row for %s. Choose Allow or Deny, adjust the AI type, provider, or model if needed, then select Save changes.', 'handl-ai-connector-access-control' ),
						$grad_label
					)
				);
				$bits = array();
				if ( '' !== $graduate['family'] ) {
					$bits[] = sprintf(
						/* translators: %s: AI type label */
						__( 'AI type: %s', 'handl-ai-connector-access-control' ),
						$family_labels[ $graduate['family'] ] ?? $graduate['family']
					);
				}
				if ( '' !== $graduate['provider'] || '' !== $graduate['model'] ) {
					$bits[] = sprintf(
						/* translators: %s: provider/model path */
						__( 'Provider/model: %s', 'handl-ai-connector-access-control' ),
						trim( $graduate['provider'] . '/' . $graduate['model'], '/' )
					);
				}
				if ( ! empty( $bits ) ) {
					echo ' <span class="description">' . esc_html( implode( ' · ', $bits ) ) . '</span>';
				}
				echo '</p></div>';
			}
		}

		echo '<h2>' . esc_html__( 'Plugin rules', 'handl-ai-connector-access-control' ) . '</h2>';
echo '<p class="description">' . esc_html__( 'Plugin rules set the main access level. AI type columns can refine an allowed plugin, such as allowing text but blocking images. A plugin-level Deny blocks every AI type. Model routing is experimental, uses best-effort plugin detection, and does not guarantee spend. Leave both route fields blank to disable it.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p class="description handl-aicac-beyond-ca-rules">' . esc_html( Differentiator_Messaging::rules_note() ) . '</p>';
		if ( $unforced_n > 0 && ! empty( $force_map ) ) {
			echo '<div class="notice notice-warning inline"><p>';
			echo esc_html(
				sprintf(
					/* translators: %d: count of unattributed unforced calls in retained log */
					_n(
						'%d saved call could not be linked to a plugin and ran without model routing.',
						'%d saved calls could not be linked to a plugin and ran without model routing.',
						$unforced_n,
						'handl-ai-connector-access-control'
					),
					$unforced_n
				)
			);
			echo ' ' . esc_html__( 'Model routes follow the detected plugin. Calls with no detected plugin may run without a route, so model routing is not a spend guarantee.', 'handl-ai-connector-access-control' );
			echo '</p></div>';
		}
		$this->render_plugin_rules_filters( $plugin_status_filter, $plugin_access_filter );

		echo '<div class="tablenav top handl-aicac-bulk-nav">';
		echo '<div class="alignleft actions bulkactions">';
		echo '<label for="handl-aicac-bulk-action" class="screen-reader-text">' . esc_html__( 'Select bulk action', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<select name="handl_aicac_bulk_action" id="handl-aicac-bulk-action" form="' . esc_attr( $bulk_form_id ) . '">';
		echo '<option value="-1">' . esc_html__( 'Bulk actions', 'handl-ai-connector-access-control' ) . '</option>';
		echo '<option value="allow">' . esc_html__( 'Set to Allow', 'handl-ai-connector-access-control' ) . '</option>';
		echo '<option value="deny">' . esc_html__( 'Set to Deny', 'handl-ai-connector-access-control' ) . '</option>';
		echo '</select> ';
		echo '<input type="submit" class="button action" form="' . esc_attr( $bulk_form_id ) . '" value="' . esc_attr__( 'Apply', 'handl-ai-connector-access-control' ) . '" />';
		echo '</div>';
		echo '<br class="clear" />';
		echo '</div>';

		echo '<table class="widefat striped handl-aicac-rules-matrix">';
		echo '<thead><tr>';
		echo '<td id="cb" class="manage-column column-cb check-column"><label class="screen-reader-text" for="handl-aicac-bulk-select-all">' . esc_html__( 'Select all', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<input id="handl-aicac-bulk-select-all" type="checkbox" /></td>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Status', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'AI access', 'handl-ai-connector-access-control' ) . '</th>';
		foreach ( $family_labels as $family_id => $family_label ) {
			echo '<th class="handl-aicac-col-family">' . esc_html( $family_label ) . '</th>';
		}
		echo '<th class="handl-aicac-col-force">' . esc_html__( 'Provider route (experimental)', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="handl-aicac-col-force">' . esc_html__( 'Model route (experimental)', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Plugin file', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead>';
		echo '<tbody>';

		$operations = is_array( $policy['operations'] ?? null ) ? (array) $policy['operations'] : array();

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

			$plugin_ops = isset( $operations[ $basename ] ) && is_array( $operations[ $basename ] )
				? $operations[ $basename ]
				: array();

			$force_row = $force_map[ $basename ] ?? array( 'provider' => '', 'model' => '' );
			$force_p   = (string) ( $force_row['provider'] ?? '' );
			$force_m   = (string) ( $force_row['model'] ?? '' );
			// AICAC-GRADUATE: prefill empty model-route fields from the observed call.
			if ( is_array( $graduate ) && $basename === $graduate['plugin'] ) {
				if ( '' === $force_p && '' !== $graduate['provider'] ) {
					$force_p = $graduate['provider'];
				}
				if ( '' === $force_m && '' !== $graduate['model'] ) {
					$force_m = $graduate['model'];
				}
			}

			echo '<tr id="handl-aicac-rule-' . esc_attr( md5( $basename ) ) . '">';
			echo '<th scope="row" class="check-column">';
			echo '<label class="screen-reader-text" for="handl-aicac-bulk-cb-' . esc_attr( md5( $basename ) ) . '">';
			echo esc_html(
				sprintf(
					/* translators: %s: plugin name */
					__( 'Select %s', 'handl-ai-connector-access-control' ),
					$name
				)
			);
			echo '</label>';
			echo '<input type="checkbox" class="handl-aicac-bulk-cb" id="handl-aicac-bulk-cb-' . esc_attr( md5( $basename ) ) . '" name="handl_aicac_bulk_plugins[]" value="' . esc_attr( $basename ) . '" form="' . esc_attr( $bulk_form_id ) . '" />';
			echo '</th>';
			echo '<td><strong>' . esc_html( $name ) . '</strong>';
			if ( '' !== $force_p && '' !== $force_m && $unforced_n > 0 ) {
				echo '<br /><span class="description handl-aicac-unforced-hint" style="font-size:11px;">';
				echo esc_html(
					sprintf(
						/* translators: %d: unattributed unforced call count */
						_n(
							'%d call ran without model routing because no plugin was detected',
							'%d calls ran without model routing because no plugin was detected',
							$unforced_n,
							'handl-ai-connector-access-control'
						),
						$unforced_n
					)
				);
				echo '</span>';
			}
			echo '</td>';
			echo '<td>' . ( $enabled ? '<span class="dashicons dashicons-yes"></span> ' . esc_html__( 'Active', 'handl-ai-connector-access-control' ) : esc_html__( 'Inactive', 'handl-ai-connector-access-control' ) ) . '</td>';
			echo '<td>';
			echo '<select name="handl_aicac_rule[' . esc_attr( $basename ) . ']" form="' . esc_attr( $rules_form_id ) . '">';
			$this->render_option( '', (string) $rule, __( 'Default', 'handl-ai-connector-access-control' ) );
			$this->render_option( 'allow', (string) $rule, __( 'Allow', 'handl-ai-connector-access-control' ) );
			$this->render_option( 'deny', (string) $rule, __( 'Deny', 'handl-ai-connector-access-control' ) );
			echo '</select>';
			// AICAC-TEMP-ALLOW: optional expiry on Allow rules only.
			$expire_preset = Temp_Allow::preset_for_stored( $policy, (string) $basename );
			$expire_ts     = Temp_Allow::expires_at( $policy, (string) $basename );
			$expire_label  = Temp_Allow::remaining_label( $policy, (string) $basename );
			$expire_date   = ( null !== $expire_ts ) ? gmdate( 'Y-m-d', $expire_ts ) : '';
			echo '<div class="handl-aicac-temp-allow" style="margin-top:6px;">';
			echo '<label class="screen-reader-text" for="handl-aicac-expire-preset-' . esc_attr( md5( $basename ) ) . '">';
			echo esc_html(
				sprintf(
					/* translators: %s: plugin name */
					__( 'Temporary allow for %s', 'handl-ai-connector-access-control' ),
					$name
				)
			);
			echo '</label>';
			echo '<select class="handl-aicac-expire-preset" id="handl-aicac-expire-preset-' . esc_attr( md5( $basename ) ) . '" name="handl_aicac_expire_preset[' . esc_attr( $basename ) . ']" form="' . esc_attr( $rules_form_id ) . '">';
			$this->render_option( '', $expire_preset, __( 'No expiry', 'handl-ai-connector-access-control' ) );
			$this->render_option( '24h', $expire_preset, __( 'Expires in 24 hours', 'handl-ai-connector-access-control' ) );
			$this->render_option( '7d', $expire_preset, __( 'Expires in 7 days', 'handl-ai-connector-access-control' ) );
			$this->render_option( '30d', $expire_preset, __( 'Expires in 30 days', 'handl-ai-connector-access-control' ) );
			$this->render_option( 'custom', $expire_preset, __( 'Expires on date…', 'handl-ai-connector-access-control' ) );
			echo '</select> ';
			echo '<input type="date" class="handl-aicac-expire-date" name="handl_aicac_expire_date[' . esc_attr( $basename ) . ']" form="' . esc_attr( $rules_form_id ) . '" value="' . esc_attr( $expire_date ) . '" style="' . ( 'custom' === $expire_preset ? '' : 'display:none;' ) . '" aria-label="' . esc_attr(
				sprintf(
					/* translators: %s: plugin name */
					__( '%s expiry date', 'handl-ai-connector-access-control' ),
					$name
				)
			) . '" />';
			if ( '' !== $expire_label ) {
				echo '<p class="description" style="margin:4px 0 0;">' . esc_html( $expire_label ) . '</p>';
			}
			if ( Temp_Allow::is_expired( $policy, (string) $basename ) ) {
				echo '<p style="margin:4px 0 0;">';
				echo '<button type="submit" class="button button-small" form="handl-aicac-renew-form" name="handl_aicac_renew_plugin" value="' . esc_attr( $basename ) . '">';
				echo esc_html__( 'Renew 7 days', 'handl-ai-connector-access-control' );
				echo '</button>';
				echo '</p>';
			}
			echo '</div>';
			echo '</td>';
			foreach ( $family_labels as $family_id => $family_label ) {
				$family_rule = isset( $plugin_ops[ $family_id ] ) ? (string) $plugin_ops[ $family_id ] : '';
				$family_td_class = 'handl-aicac-col-family';
				if ( is_array( $graduate ) && $basename === $graduate['plugin'] && '' !== $graduate['family'] && $family_id === $graduate['family'] ) {
					$family_td_class .= ' handl-aicac-graduate-family';
				}
				echo '<td class="' . esc_attr( $family_td_class ) . '">';
				echo '<select name="handl_aicac_operation[' . esc_attr( $basename ) . '][' . esc_attr( $family_id ) . ']" form="' . esc_attr( $rules_form_id ) . '" aria-label="' . esc_attr( sprintf(
					/* translators: 1: plugin name, 2: capability family */
					__( '%1$s: %2$s', 'handl-ai-connector-access-control' ),
					$name,
					$family_label
				) ) . '">';
				$this->render_option( '', $family_rule, __( 'Follow plugin rule', 'handl-ai-connector-access-control' ) );
				$this->render_option( 'allow', $family_rule, __( 'Allow', 'handl-ai-connector-access-control' ) );
				$this->render_option( 'deny', $family_rule, __( 'Deny', 'handl-ai-connector-access-control' ) );
				echo '</select>';
				echo '</td>';
			}
			echo '<td class="handl-aicac-col-force">';
			echo '<input type="text" class="regular-text code" style="max-width:9em;" name="handl_aicac_model_force[' . esc_attr( $basename ) . '][provider]" form="' . esc_attr( $rules_form_id ) . '" value="' . esc_attr( $force_p ) . '" placeholder="openai" autocomplete="off" aria-label="' . esc_attr( sprintf(
				/* translators: %s: plugin name */
				__( '%s provider route', 'handl-ai-connector-access-control' ),
				$name
			) ) . '" />';
			echo '</td>';
			echo '<td class="handl-aicac-col-force">';
			echo '<input type="text" class="regular-text code" style="max-width:11em;" name="handl_aicac_model_force[' . esc_attr( $basename ) . '][model]" form="' . esc_attr( $rules_form_id ) . '" value="' . esc_attr( $force_m ) . '" placeholder="gpt-4o-mini" autocomplete="off" aria-label="' . esc_attr( sprintf(
				/* translators: %s: plugin name */
				__( '%s model route', 'handl-ai-connector-access-control' ),
				$name
			) ) . '" />';
			echo '</td>';
			echo '<td><code>' . esc_html( $basename ) . '</code></td>';
			echo '</tr>';
		}

		echo '</tbody>';
		echo '</table>';

		echo '<script>';
		echo '(function(){var all=document.getElementById("handl-aicac-bulk-select-all");if(!all)return;';
		echo 'all.addEventListener("change",function(){document.querySelectorAll(".handl-aicac-rules-matrix tbody input.handl-aicac-bulk-cb").forEach(function(cb){cb.checked=all.checked;});});';
		echo '})();';
		echo '(function(){document.querySelectorAll(".handl-aicac-expire-preset").forEach(function(sel){';
		echo 'sel.addEventListener("change",function(){var wrap=sel.closest(".handl-aicac-temp-allow");if(!wrap)return;var d=wrap.querySelector(".handl-aicac-expire-date");if(!d)return;d.style.display=(sel.value==="custom")?"":"none";});';
		echo '});})();';
		$focus_plugin = isset( $_REQUEST['handl_aicac_focus_plugin'] )
			? Plugin_Profile::sanitize_plugin( wp_unslash( (string) $_REQUEST['handl_aicac_focus_plugin'] ) )
			: '';
		if ( '' !== $focus_plugin ) {
			$focus_id = 'handl-aicac-rule-' . md5( $focus_plugin );
			echo '(function(){var r=document.getElementById(' . wp_json_encode( $focus_id ) . ');if(!r)return;';
			echo 'r.style.outline="2px solid #2271b1";r.style.outlineOffset="2px";';
			echo 'if(r.scrollIntoView){r.scrollIntoView({block:"center"});}';
			echo '})();';
		}
		echo '</script>';

		echo '<p class="submit">';
		echo '<button type="submit" name="handl_aicac_action" value="save" class="button button-primary" data-aicac-action="save">';
		echo esc_html__( 'Save changes', 'handl-ai-connector-access-control' );
		echo '</button>';
		echo '</p>';

		echo '</form>';

		$this->render_rules_transfer_section( $policy, $show_import_preview );

		echo '</div>'; // .handl-aicac-tab-panel
		echo '</div>'; // .wrap
	}

	private function render_plugin_rules_filters( string $plugin_status_filter, string $plugin_access_filter ): void {
		$base_url = add_query_arg(
			array(
				'page'            => 'handl-ai-connector-access-control',
				'handl_aicac_tab' => 'rules',
			),
			admin_url( 'options-general.php' )
		);

		$status_views = array(
			'all'      => __( 'All', 'handl-ai-connector-access-control' ),
			'active'   => __( 'Active', 'handl-ai-connector-access-control' ),
			'inactive' => __( 'Inactive', 'handl-ai-connector-access-control' ),
		);

		echo '<div class="handl-aicac-table-filters handl-aicac-rules-filters">';
		echo '<ul class="subsubsub">';
		$view_index = 0;
		foreach ( $status_views as $status_key => $status_label ) {
			if ( $view_index > 0 ) {
				echo ' | ';
			}
			++$view_index;

			$view_url = add_query_arg(
				array(
					'handl_aicac_status' => $status_key,
					'handl_aicac_access' => $plugin_access_filter,
				),
				$base_url
			);

			$is_current = $plugin_status_filter === $status_key;
			printf(
				'<li><a href="%1$s"%2$s>%3$s</a></li>',
				esc_url( $view_url ),
				$is_current ? ' class="current" aria-current="page"' : '',
				esc_html( $status_label )
			);
		}
		echo '</ul>';

		// No <form> here: this panel is rendered inside the Rules POST form. A nested
		// GET form would auto-close the outer form in browsers, leaving Run test with
		// button.form === null (AICAC-SIM QA fail on #93).
		$access_options = array(
			'all'             => __( 'All rules', 'handl-ai-connector-access-control' ),
			'effective-allow' => __( 'Explicit Allow', 'handl-ai-connector-access-control' ),
			'effective-deny'  => __( 'Explicit Deny', 'handl-ai-connector-access-control' ),
			'default-only'    => __( 'Uses default', 'handl-ai-connector-access-control' ),
		);
		echo '<div class="tablenav top">';
		echo '<div class="alignleft actions">';
		echo '<label for="handl-aicac-access-filter" class="screen-reader-text">' . esc_html__( 'Filter by AI access', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<select id="handl-aicac-access-filter" onchange="if (this.selectedOptions.length) { window.location = this.selectedOptions[0].getAttribute(\'data-url\'); }">';
		foreach ( $access_options as $access_key => $access_label ) {
			$access_url = add_query_arg(
				array(
					'handl_aicac_status' => $plugin_status_filter,
					'handl_aicac_access' => $access_key,
				),
				$base_url
			);
			printf(
				'<option value="%1$s" data-url="%2$s"%3$s>%4$s</option>',
				esc_attr( $access_key ),
				esc_url( $access_url ),
				selected( $plugin_access_filter, $access_key, false ),
				esc_html( $access_label )
			);
		}
		echo '</select>';
		echo '</div>';
		echo '<br class="clear" />';
		echo '</div>';
		echo '</div>';
	}

	/**
	 * @param 'dashboard'|'rules'|'activity'|'insights'|'profile' $active_tab
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $log_filters
	 */
	private function render_tabs( string $active_tab, string $plugin_status_filter, string $plugin_access_filter, array $log_filters ): void {
		$base_args = array(
			'page' => 'handl-ai-connector-access-control',
		);

		$dashboard_url = add_query_arg(
			array_merge( $base_args, array( 'handl_aicac_tab' => 'dashboard' ) ),
			admin_url( 'options-general.php' )
		);

		$rules_url = add_query_arg(
			array_merge(
				$base_args,
				array(
					'handl_aicac_tab'    => 'rules',
					'handl_aicac_status' => $plugin_status_filter,
					'handl_aicac_access' => $plugin_access_filter,
				)
			),
			admin_url( 'options-general.php' )
		);

		$activity_url = add_query_arg(
			array_merge( $base_args, array( 'handl_aicac_tab' => 'activity' ), $this->log_filters_to_query_args( $log_filters ) ),
			admin_url( 'options-general.php' )
		);

		$insights_url = add_query_arg(
			array_merge( $base_args, array( 'handl_aicac_tab' => 'insights' ) ),
			admin_url( 'options-general.php' )
		);

		echo '<nav class="nav-tab-wrapper wp-clearfix" aria-label="' . esc_attr__( 'Settings sections', 'handl-ai-connector-access-control' ) . '">';
		printf(
			'<a href="%1$s" class="nav-tab%2$s">%3$s</a>',
			esc_url( $dashboard_url ),
			'dashboard' === $active_tab ? ' nav-tab-active' : '',
			esc_html__( 'Dashboard', 'handl-ai-connector-access-control' )
		);
		printf(
			'<a href="%1$s" class="nav-tab%2$s">%3$s</a>',
			esc_url( $rules_url ),
			'rules' === $active_tab ? ' nav-tab-active' : '',
			esc_html__( 'Rules', 'handl-ai-connector-access-control' )
		);
		printf(
			'<a href="%1$s" class="nav-tab%2$s">%3$s</a>',
			esc_url( $activity_url ),
			( 'activity' === $active_tab || 'profile' === $active_tab ) ? ' nav-tab-active' : '',
			esc_html__( 'Activity', 'handl-ai-connector-access-control' )
		);
		printf(
			'<a href="%1$s" class="nav-tab%2$s handl-aicac-nav-tab--insights">%3$s</a>',
			esc_url( $insights_url ),
			'insights' === $active_tab ? ' nav-tab-active' : '',
			esc_html__( 'Insights', 'handl-ai-connector-access-control' )
		);
		echo '</nav>';
	}

	/**
	 * AICAC-11: Dashboard callout naming HandL differentiators vs Connector Approvals.
	 */
	private function render_beyond_connector_approvals_callout(): void {
		echo '<div class="handl-aicac-beyond-ca" role="note">';
		echo '<p class="handl-aicac-beyond-ca__title"><strong>' . esc_html( Differentiator_Messaging::headline() ) . '</strong></p>';
		echo '<p class="handl-aicac-beyond-ca__body">' . esc_html( Differentiator_Messaging::body() ) . '</p>';
		echo '<p class="handl-aicac-beyond-ca__coexist description">' . esc_html( Differentiator_Messaging::coexistence() ) . '</p>';
		echo '</div>';
	}

	/**
	 * AICAC-ONBOARD: Dashboard wizard, re-open link, and review reminder.
	 *
	 * @param array<string,mixed> $policy
	 */
	private function render_onboarding_dashboard_section( array $policy ): void {
		$state = Onboarding::ensure_initialized();
		$force = isset( $_GET['handl_aicac_onboard'] ) && '1' === (string) $_GET['handl_aicac_onboard'];

		if ( Onboarding::should_show_review_notice( $state ) ) {
			$activity_url = admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=activity' );
			$rules_url    = admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=rules' );
			echo '<div class="notice notice-info handl-aicac-onboard-review"><p>';
			echo esc_html__( 'Your watch period has ended. Review Activity to see which plugins used AI, then use Rules to allow or block them.', 'handl-ai-connector-access-control' );
			echo ' <a href="' . esc_url( $activity_url ) . '">' . esc_html__( 'Open Activity', 'handl-ai-connector-access-control' ) . '</a>';
			echo ' · <a href="' . esc_url( $rules_url ) . '">' . esc_html__( 'Open Rules', 'handl-ai-connector-access-control' ) . '</a>';
			echo '</p></div>';
		}

		if ( Onboarding::should_render_wizard( $state, $force ) ) {
			$this->render_onboarding_wizard( $policy, $state );
			return;
		}

		if ( Onboarding::should_show_reentry( $state ) ) {
			echo '<div class="handl-aicac-onboard-reentry" style="margin:0 0 1em;">';
			echo '<form method="post" style="display:inline;">';
			wp_nonce_field( 'handl_aicac_onboard', 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_action" value="onboard_reopen" />';
			echo '<input type="hidden" name="handl_aicac_tab" value="dashboard" />';
			submit_button(
				__( 'Run setup again', 'handl-ai-connector-access-control' ),
				'secondary',
				'submit',
				false
			);
			echo '</form>';
			echo '</div>';
		}

		// Soft link only — presets live on Rules; no hard dependency on onboarding.
		$presets_url = admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=rules#handl-aicac-presets' );
		echo '<p class="description handl-aicac-preset-link" style="margin:0 0 1em;">';
		echo '<a href="' . esc_url( $presets_url ) . '">' . esc_html__( 'Or start from a policy preset', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param array<string,mixed> $state
	 */
	private function render_onboarding_wizard( array $policy, array $state ): void {
		$step = Onboarding::sanitize_step( $state['step'] ?? 1 );
		echo '<div class="handl-aicac-onboard card" style="max-width:46em;padding:1em 1.25em;margin:0 0 1.5em;">';
		echo '<h2 style="margin-top:0;">' . esc_html__( 'Quick setup', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html(
			sprintf(
				/* translators: %d: current step number 1–3 */
				__( 'Step %d of 3: set up monitoring and alerts in about two minutes.', 'handl-ai-connector-access-control' ),
				$step
			)
		) . '</p>';

		echo '<form method="post" style="margin:0 0 0.75em;">';
		wp_nonce_field( 'handl_aicac_onboard', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="onboard_dismiss" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="dashboard" />';
		submit_button( __( 'Skip setup', 'handl-ai-connector-access-control' ), 'link', 'submit', false );
		echo '</form>';

		if ( 1 === $step ) {
			$this->render_onboarding_step_mode( $policy, $state );
		} elseif ( 2 === $step ) {
			$this->render_onboarding_step_alerts( $policy );
		} else {
			$this->render_onboarding_step_review( $state );
		}

		echo '</div>';
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param array<string,mixed> $state
	 */
	private function render_onboarding_step_mode( array $policy, array $state ): void {
		$network_locked = Onboarding::is_network_enforced();
		$mode           = Onboarding::sanitize_mode( $state['mode'] ?? Onboarding::MODE_OBSERVE );
		if ( '' === (string) ( $state['mode'] ?? '' ) ) {
			$mode = Onboarding::MODE_OBSERVE;
		}
		$days = Onboarding::sanitize_observe_days( $state['observe_days'] ?? Onboarding::DEFAULT_OBSERVE_DAYS );

		echo '<h3>' . esc_html__( '1. How do you want to start?', 'handl-ai-connector-access-control' ) . '</h3>';

		if ( $network_locked ) {
			echo '<p class="notice notice-warning inline" style="padding:8px 12px;">' . esc_html__( 'Your network admin controls the site-wide AI mode. You can still set alerts and a review reminder.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '<form method="post">';
			wp_nonce_field( 'handl_aicac_onboard', 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_action" value="onboard_step" />';
			echo '<input type="hidden" name="handl_aicac_tab" value="dashboard" />';
			echo '<input type="hidden" name="handl_aicac_onboard_step" value="1" />';
			echo '<input type="hidden" name="handl_aicac_onboard_mode" value="' . esc_attr( Onboarding::MODE_OBSERVE ) . '" />';
			submit_button( __( 'Continue', 'handl-ai-connector-access-control' ), 'primary', 'submit', false );
			echo '</form>';
			return;
		}

		echo '<form method="post">';
		wp_nonce_field( 'handl_aicac_onboard', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="onboard_step" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="dashboard" />';
		echo '<input type="hidden" name="handl_aicac_onboard_step" value="1" />';

		echo '<fieldset style="border:0;margin:0;padding:0;">';
		echo '<legend class="screen-reader-text">' . esc_html__( 'Starting mode', 'handl-ai-connector-access-control' ) . '</legend>';

		echo '<p><label><input type="radio" name="handl_aicac_onboard_mode" value="' . esc_attr( Onboarding::MODE_OBSERVE ) . '" ' . checked( $mode, Onboarding::MODE_OBSERVE, false ) . ' /> ';
		echo '<strong>' . esc_html__( 'Watch first (recommended)', 'handl-ai-connector-access-control' ) . '</strong></label><br />';
		echo '<span class="description" style="margin-left:1.75em;">' . esc_html__( 'Log AI activity without blocking it. Start here while you learn which plugins need access.', 'handl-ai-connector-access-control' ) . '</span></p>';

		echo '<p><label><input type="radio" name="handl_aicac_onboard_mode" value="' . esc_attr( Onboarding::MODE_ENFORCE ) . '" ' . checked( $mode, Onboarding::MODE_ENFORCE, false ) . ' /> ';
		echo '<strong>' . esc_html__( 'Enforce now', 'handl-ai-connector-access-control' ) . '</strong></label><br />';
		echo '<span class="description" style="margin-left:1.75em;">' . esc_html__( 'Apply your Rules immediately. Choose this only if your policy is already set.', 'handl-ai-connector-access-control' ) . '</span></p>';
		echo '</fieldset>';

		echo '<p><label for="handl-aicac-onboard-days">' . esc_html__( 'Watch window (days)', 'handl-ai-connector-access-control' ) . '</label><br />';
		echo '<input type="number" class="small-text" id="handl-aicac-onboard-days" name="handl_aicac_onboard_observe_days" min="' . esc_attr( (string) Onboarding::MIN_OBSERVE_DAYS ) . '" max="' . esc_attr( (string) Onboarding::MAX_OBSERVE_DAYS ) . '" step="1" value="' . esc_attr( (string) $days ) . '" /> ';
		echo '<span class="description">' . esc_html__( 'Watch first keeps 7–14 days of activity. Older entries are deleted.', 'handl-ai-connector-access-control' ) . '</span></p>';

		unset( $policy );
		submit_button( __( 'Continue', 'handl-ai-connector-access-control' ), 'primary', 'submit', false );
		echo '</form>';
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private function render_onboarding_step_alerts( array $policy ): void {
		$email = isset( $policy['alert_email'] ) ? (string) $policy['alert_email'] : '';
		if ( '' === $email ) {
			$email = (string) get_option( 'admin_email' );
		}
		$deny_on = ! empty( $policy['alert_on_deny'] );

		echo '<h3>' . esc_html__( '2. Where should we send alerts?', 'handl-ai-connector-access-control' ) . '</h3>';
		echo '<p class="description">' . esc_html__( 'Choose where to send blocked-call alerts. You can also send a test email.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<form method="post">';
		wp_nonce_field( 'handl_aicac_onboard', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_tab" value="dashboard" />';
		echo '<input type="hidden" name="handl_aicac_onboard_step" value="2" />';

		echo '<p><label for="handl-aicac-onboard-email">' . esc_html__( 'Alert email', 'handl-ai-connector-access-control' ) . '</label><br />';
		echo '<input type="email" class="regular-text" id="handl-aicac-onboard-email" name="handl_aicac_onboard_alert_email" value="' . esc_attr( $email ) . '" /></p>';

		echo '<p><label><input type="checkbox" name="handl_aicac_onboard_alert_on_deny" value="1" ' . checked( $deny_on, true, false ) . ' /> ';
		echo esc_html__( 'Email me when a call is blocked', 'handl-ai-connector-access-control' ) . '</label></p>';

		// AICAC-LEADS: opt-in only, unchecked by default (WP.org guideline 7).
		echo '<p><label><input type="checkbox" name="handl_aicac_onboard_leads_consent" value="1" /> ';
		echo esc_html__( 'I agree to send my alert email address and site URL to HandL Digital so it can email me product news and related offers. Optional. You can unsubscribe at any time by emailing support@handldigital.com.', 'handl-ai-connector-access-control' ) . '</label></p>';

		echo '<p>';
		echo '<button type="submit" name="handl_aicac_action" value="onboard_step" class="button button-primary">' . esc_html__( 'Continue', 'handl-ai-connector-access-control' ) . '</button>';
		echo ' ';
		echo '<button type="submit" name="handl_aicac_action" value="onboard_test_email" class="button">' . esc_html__( 'Send test email', 'handl-ai-connector-access-control' ) . '</button>';
		echo '</p>';
		echo '</form>';
	}

	/**
	 * @param array<string,mixed> $state
	 */
	private function render_onboarding_step_review( array $state ): void {
		$days = Onboarding::sanitize_observe_days( $state['observe_days'] ?? Onboarding::DEFAULT_OBSERVE_DAYS );
		echo '<h3>' . esc_html__( '3. Set a review reminder', 'handl-ai-connector-access-control' ) . '</h3>';
		echo '<p class="description">' . esc_html(
			sprintf(
				/* translators: %d: observe window in days */
				__( 'After %d days, show a Dashboard reminder to review Activity and update Rules.', 'handl-ai-connector-access-control' ),
				$days
			)
		) . '</p>';

		echo '<form method="post">';
		wp_nonce_field( 'handl_aicac_onboard', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="onboard_step" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="dashboard" />';
		echo '<input type="hidden" name="handl_aicac_onboard_step" value="3" />';

		echo '<p><label><input type="checkbox" name="handl_aicac_onboard_set_reminder" value="1" checked="checked" /> ';
		echo esc_html__( 'Remind me when the watch window ends', 'handl-ai-connector-access-control' ) . '</label></p>';

		submit_button( __( 'Finish setup', 'handl-ai-connector-access-control' ), 'primary', 'submit', false );
		echo '</form>';
	}

	/**
	 * Step 2: validate/save the entered alert address, send a denial-alert test, stay on step 2.
	 */
	private function handle_onboard_test_email(): void {
		$this->require_admin_mutation( 'handl_aicac_onboard' );
		$state = Onboarding::ensure_initialized();
		if ( empty( $state['eligible'] ) ) {
			$this->redirect_onboard_dashboard();
		}

		$email  = isset( $_POST['handl_aicac_onboard_alert_email'] )
			? wp_unslash( (string) $_POST['handl_aicac_onboard_alert_email'] )
			: '';
		$enable = isset( $_POST['handl_aicac_onboard_alert_on_deny'] );
		$policy = Onboarding::apply_alerts_to_policy( Policy::get_policy(), $email, $enable );
		Policy::save_policy( $policy );

		// Keep the wizard on alerts; do not advance the step.
		$state['step']   = 2;
		$state['status'] = Onboarding::STATUS_ACTIVE;
		Onboarding::save_state( $state );

		$result = Alerts::send_test_email( $policy, 'denial_alert' );
		$this->redirect_onboard_dashboard(
			array(
				'handl_aicac_test_email'    => (string) $result['status'],
				'handl_aicac_test_email_to' => Alerts::encode_email_query_arg( (string) $result['to'] ),
			)
		);
	}

	private function handle_onboard_dismiss(): void {
		$this->require_admin_mutation( 'handl_aicac_onboard' );
		$state           = Onboarding::ensure_initialized();
		$state['status'] = Onboarding::STATUS_DISMISSED;
		Onboarding::save_state( $state );
		$this->redirect_onboard_dashboard();
	}

	private function handle_onboard_reopen(): void {
		$this->require_admin_mutation( 'handl_aicac_onboard' );
		$state = Onboarding::ensure_initialized();
		if ( empty( $state['eligible'] ) ) {
			$this->redirect_onboard_dashboard();
		}
		$state['status'] = Onboarding::STATUS_ACTIVE;
		$state['step']   = 1;
		Onboarding::save_state( $state );
		$this->redirect_onboard_dashboard( array( 'handl_aicac_onboard' => '1' ) );
	}

	private function handle_onboard_step(): void {
		$this->require_admin_mutation( 'handl_aicac_onboard' );
		$state = Onboarding::ensure_initialized();
		if ( empty( $state['eligible'] ) ) {
			$this->redirect_onboard_dashboard();
		}

		$step = Onboarding::sanitize_step(
			isset( $_POST['handl_aicac_onboard_step'] )
				? wp_unslash( (string) $_POST['handl_aicac_onboard_step'] )
				: 1
		);

		if ( 1 === $step ) {
			$mode = Onboarding::sanitize_mode(
				isset( $_POST['handl_aicac_onboard_mode'] )
					? wp_unslash( (string) $_POST['handl_aicac_onboard_mode'] )
					: Onboarding::MODE_OBSERVE
			);
			$days = Onboarding::sanitize_observe_days(
				isset( $_POST['handl_aicac_onboard_observe_days'] )
					? wp_unslash( (string) $_POST['handl_aicac_onboard_observe_days'] )
					: Onboarding::DEFAULT_OBSERVE_DAYS
			);

			if ( ! Onboarding::is_network_enforced() ) {
				$policy = Onboarding::apply_mode_to_policy( Policy::get_policy(), $mode, $days );
				Policy::save_policy( $policy );
			}

			$state['mode']         = $mode;
			$state['observe_days'] = $days;
			$state['step']         = 2;
			$state['status']       = Onboarding::STATUS_ACTIVE;
			Onboarding::save_state( $state );
			$this->redirect_onboard_dashboard();
		}

		if ( 2 === $step ) {
			$email = isset( $_POST['handl_aicac_onboard_alert_email'] )
				? wp_unslash( (string) $_POST['handl_aicac_onboard_alert_email'] )
				: '';
			$enable = isset( $_POST['handl_aicac_onboard_alert_on_deny'] );
			// Unchecked by default — only true when the opt-in box is submitted checked.
			$leads_consent = isset( $_POST['handl_aicac_onboard_leads_consent'] );
			$policy        = Onboarding::apply_alerts_to_policy( Policy::get_policy(), $email, $enable );
			Policy::save_policy( $policy );
			$state['leads_consent'] = $leads_consent;
			$state['step']          = 3;
			$state['status']        = Onboarding::STATUS_ACTIVE;
			Onboarding::save_state( $state );
			$this->redirect_onboard_dashboard();
		}

		// Step 3 — finish. Opt-in lead POST only when consent was checked on step 2.
		$set_reminder = isset( $_POST['handl_aicac_onboard_set_reminder'] );
		$days         = Onboarding::sanitize_observe_days( $state['observe_days'] ?? Onboarding::DEFAULT_OBSERVE_DAYS );
		$state['review_due_ts'] = $set_reminder ? Onboarding::review_due_timestamp( $days ) : 0;
		$state['step']          = 3;
		$state['status']        = Onboarding::STATUS_COMPLETE;
		Onboarding::save_state( $state );

		// Failures are silent and never block wizard completion (no retry queue v1).
		if ( ! empty( $state['leads_consent'] ) ) {
			$policy = Policy::get_policy();
			$email  = Alerts::sanitize_email( $policy['alert_email'] ?? '' );
			Leads::maybe_register( $email, true );
		}

		$this->redirect_onboard_dashboard( array( 'handl_aicac_onboard_done' => '1' ) );
	}

	/**
	 * @param array<string,string> $extra
	 */
	private function redirect_onboard_dashboard( array $extra = array() ): void {
		$args = array_merge(
			array(
				'page'            => 'handl-ai-connector-access-control',
				'handl_aicac_tab' => 'dashboard',
			),
			$extra
		);
		wp_safe_redirect( add_query_arg( $args, admin_url( 'options-general.php' ) ) );
		exit;
	}

	/**
	 * AICAC-PROFILE: read-only per-plugin drill-down (usage, incidents, effective rules).
	 *
	 * @param array<int,mixed>                  $log
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $plugins
	 * @param array<string,bool>                $active
	 */
	private function render_plugin_profile_tab( array $log, array $policy, array $plugins, array $active ): void {
		$raw_plugin = isset( $_REQUEST['handl_aicac_plugin'] )
			? wp_unslash( (string) $_REQUEST['handl_aicac_plugin'] )
			: '';
		$plugin     = Plugin_Profile::sanitize_plugin( $raw_plugin );

		echo '<div class="handl-aicac-tab-panel handl-aicac-plugin-profile">';
		echo '<p><a href="' . esc_url( admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=activity' ) ) . '">&larr; ';
		echo esc_html__( 'Back to Activity', 'handl-ai-connector-access-control' );
		echo '</a></p>';

		if ( '' === $plugin ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'This plugin link is not valid. Open a plugin from Activity.', 'handl-ai-connector-access-control' ) . '</p></div>';
			echo '</div>';
			return;
		}

		$profile = Plugin_Profile::build( $plugin, $log, $policy, $plugins, $active );
		$eff     = $profile['effective'];
		$usage   = $profile['usage'];
		$inc     = $profile['incidents'];

		echo '<h2>' . esc_html( (string) $profile['label'] ) . '</h2>';
		echo '<p class="description"><code>' . esc_html( $plugin ) . '</code>';
		if ( ! $profile['installed'] ) {
			echo ' — ' . esc_html__( 'Not installed. Saved activity for this plugin is still available below.', 'handl-ai-connector-access-control' );
		} elseif ( ! $profile['active'] ) {
			echo ' — ' . esc_html__( 'Installed but inactive.', 'handl-ai-connector-access-control' );
		} else {
			echo ' — ' . esc_html__( 'Active', 'handl-ai-connector-access-control' );
		}
		echo '</p>';

		echo '<p>';
		echo esc_html__( 'First seen:', 'handl-ai-connector-access-control' ) . ' ';
		echo esc_html( $profile['first_ts'] ? wp_date( 'Y-m-d H:i:s', (int) $profile['first_ts'] ) : '—' );
		echo ' · ' . esc_html__( 'Last seen:', 'handl-ai-connector-access-control' ) . ' ';
		echo esc_html( $profile['last_ts'] ? wp_date( 'Y-m-d H:i:s', (int) $profile['last_ts'] ) : '—' );
		echo '</p>';

		if ( ! $profile['logging_enabled'] ) {
			echo '<div class="notice notice-warning inline"><p>';
			echo esc_html__( 'Activity logging and Learn mode are off. This page shows current rules, but it cannot show call history, estimated spend, or incidents until you turn on one of them.', 'handl-ai-connector-access-control' );
			echo '</p></div>';
		} elseif ( null !== $profile['retention_days'] ) {
			echo '<p class="description">';
			echo esc_html(
				sprintf(
					/* translators: %d: retention days */
					__( 'This page shows activity saved within the last %d days. Older activity was deleted based on your activity time limit.', 'handl-ai-connector-access-control' ),
					(int) $profile['retention_days']
				)
			);
			echo '</p>';
		}

		// --- Rules ---
		echo '<h3>' . esc_html__( 'Rules for this plugin', 'handl-ai-connector-access-control' ) . '</h3>';
		if ( ! empty( $eff['kill_switch'] ) ) {
			if ( ! empty( $eff['kill_switch_exception'] ) ) {
				echo '<p>' . esc_html__( 'Emergency stop is on, but this plugin is on the exception list. Its plugin and AI type rules still apply.', 'handl-ai-connector-access-control' ) . '</p>';
			} else {
				echo '<p><strong>' . esc_html__( 'Emergency stop is on. This plugin is not on the exception list, so its AI Client calls are blocked.', 'handl-ai-connector-access-control' ) . '</strong></p>';
			}
		}

		$plugin_chip = isset( $eff['plugin_verdict']['chip'] ) ? (string) $eff['plugin_verdict']['chip'] : '';
		$configured_plugin = isset( $eff['plugin_rule'] ) ? (string) $eff['plugin_rule'] : 'default';
		echo '<p><strong>' . esc_html__( 'Plugin rule result:', 'handl-ai-connector-access-control' ) . '</strong> ';
		echo esc_html( $plugin_chip );
		echo ' <span class="description">(';
		echo esc_html(
			sprintf(
				/* translators: %s: configured rule default|allow|deny */
				__( 'saved setting: %s', 'handl-ai-connector-access-control' ),
				$configured_plugin
			)
		);
		echo ')</span></p>';

		echo '<table class="widefat striped" style="max-width:48em;"><thead><tr>';
		echo '<th>' . esc_html__( 'AI type', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Saved setting', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Result', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( (array) ( $eff['families'] ?? array() ) as $fam ) {
			if ( ! is_array( $fam ) ) {
				continue;
			}
			$cfg = isset( $fam['configured'] ) ? (string) $fam['configured'] : 'inherit';
			$cfg_label = 'inherit' === $cfg
				? __( 'Follow plugin rule', 'handl-ai-connector-access-control' )
				: ( 'deny' === $cfg ? __( 'Deny', 'handl-ai-connector-access-control' ) : __( 'Allow', 'handl-ai-connector-access-control' ) );
			$chip = isset( $fam['verdict']['chip'] ) ? (string) $fam['verdict']['chip'] : '';
			echo '<tr>';
			echo '<td>' . esc_html( (string) ( $fam['label'] ?? '' ) ) . '</td>';
			echo '<td>' . esc_html( $cfg_label ) . '</td>';
			echo '<td>' . esc_html( $chip ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';

		// --- Usage ---
		echo '<h3>' . esc_html__( 'Usage', 'handl-ai-connector-access-control' ) . '</h3>';
		if ( $profile['logging_enabled'] ) {
			echo '<p>';
			echo esc_html(
				sprintf(
					/* translators: 1: call count, 2: estimated USD */
					__( '%1$s AI Client calls · Estimated spend: $%2$s', 'handl-ai-connector-access-control' ),
					number_format_i18n( (int) $usage['calls'] ),
					number_format_i18n( (float) $usage['estimated_usd'], 2 )
				)
			);
			echo '</p>';
			if ( ! empty( $usage['by_day'] ) ) {
				echo '<h4>' . esc_html__( 'By day', 'handl-ai-connector-access-control' ) . '</h4>';
				echo '<table class="widefat striped" style="max-width:36em;"><thead><tr>';
				echo '<th>' . esc_html__( 'Day', 'handl-ai-connector-access-control' ) . '</th>';
				echo '<th class="column-num">' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
				echo '<th class="column-num">' . esc_html__( 'Estimated spend', 'handl-ai-connector-access-control' ) . '</th>';
				echo '</tr></thead><tbody>';
				foreach ( (array) $usage['by_day'] as $day_row ) {
					if ( ! is_array( $day_row ) ) {
						continue;
					}
					echo '<tr>';
					echo '<td>' . esc_html( (string) ( $day_row['day'] ?? '' ) ) . '</td>';
					echo '<td class="column-num">' . esc_html( number_format_i18n( (int) ( $day_row['calls'] ?? 0 ) ) ) . '</td>';
					echo '<td class="column-num">$' . esc_html( number_format_i18n( (float) ( $day_row['usd'] ?? 0 ), 2 ) ) . '</td>';
					echo '</tr>';
				}
				echo '</tbody></table>';
			}
			if ( ! empty( $usage['by_operation'] ) ) {
				echo '<h4>' . esc_html__( 'By operation', 'handl-ai-connector-access-control' ) . '</h4>';
				$this->render_profile_bucket_table( (array) $usage['by_operation'] );
			}
			if ( ! empty( $usage['by_model'] ) ) {
				echo '<h4>' . esc_html__( 'By model', 'handl-ai-connector-access-control' ) . '</h4>';
				$this->render_profile_bucket_table( (array) $usage['by_model'] );
			}
			if ( 0 === (int) $usage['calls'] && 0 === (int) $profile['row_count'] ) {
				echo '<p class="description">' . esc_html__( 'No activity is saved for this plugin within the current time limit.', 'handl-ai-connector-access-control' ) . '</p>';
			}
		}

		// --- Incidents ---
		echo '<h3>' . esc_html__( 'Incidents', 'handl-ai-connector-access-control' ) . '</h3>';
		if ( $profile['logging_enabled'] ) {
			echo '<p>';
			echo esc_html(
				sprintf(
					/* translators: 1: denial count, 2: shadow call count, 3: spend alert count */
					__( 'Blocked calls: %1$s · Direct connections outside the AI Client: %2$s · Estimated spend alerts: %3$s', 'handl-ai-connector-access-control' ),
					number_format_i18n( (int) $inc['denial_count'] ),
					number_format_i18n( (int) $inc['shadow_call_count'] ),
					number_format_i18n( (int) $inc['spend_alert_count'] )
				)
			);
			echo '</p>';
			if ( ! empty( $inc['denials'] ) ) {
				echo '<h4>' . esc_html__( 'Recent blocked calls', 'handl-ai-connector-access-control' ) . '</h4>';
				echo '<ul>';
				foreach ( (array) $inc['denials'] as $d ) {
					if ( ! is_array( $d ) ) {
						continue;
					}
					$ts = isset( $d['ts'] ) ? (int) $d['ts'] : 0;
					echo '<li><code>' . esc_html( $ts ? wp_date( 'Y-m-d H:i:s', $ts ) : '—' ) . '</code> ';
					echo esc_html( (string) ( $d['operation'] ?: '—' ) );
					if ( ! empty( $d['denial_reason'] ) ) {
						echo ' — ' . esc_html( $this->format_denial_reason_label( (string) $d['denial_reason'] ) );
					}
					echo '</li>';
				}
				echo '</ul>';
			}
			if ( ! empty( $inc['shadow'] ) ) {
				echo '<h4>' . esc_html__( 'Direct connections outside the AI Client', 'handl-ai-connector-access-control' ) . '</h4>';
				echo '<ul>';
				foreach ( (array) $inc['shadow'] as $s ) {
					if ( ! is_array( $s ) ) {
						continue;
					}
					$ts = isset( $s['ts'] ) ? (int) $s['ts'] : 0;
					echo '<li><code>' . esc_html( $ts ? wp_date( 'Y-m-d H:i:s', $ts ) : '—' ) . '</code> ';
					echo esc_html( (string) ( $s['host'] ?: '—' ) );
					$count = isset( $s['count'] ) ? (int) $s['count'] : 1;
					if ( $count > 1 ) {
						echo ' · ' . esc_html(
							sprintf(
								/* translators: %d: call count */
								_n( '%d call', '%d calls', $count, 'handl-ai-connector-access-control' ),
								$count
							)
						);
					}
					echo '</li>';
				}
				echo '</ul>';
			}
			if ( ! empty( $inc['spend_alerts'] ) ) {
				echo '<h4>' . esc_html__( 'Estimated spend alerts', 'handl-ai-connector-access-control' ) . '</h4>';
				echo '<ul>';
				foreach ( (array) $inc['spend_alerts'] as $a ) {
					if ( ! is_array( $a ) ) {
						continue;
					}
					$ts = isset( $a['ts'] ) ? (int) $a['ts'] : 0;
					echo '<li><code>' . esc_html( $ts ? wp_date( 'Y-m-d H:i:s', $ts ) : '—' ) . '</code> ';
					echo esc_html(
						sprintf(
							/* translators: 1: threshold USD, 2: estimate USD */
							__( 'Alert threshold: $%1$s · Estimated spend: $%2$s', 'handl-ai-connector-access-control' ),
							number_format_i18n( (float) ( $a['threshold'] ?? 0 ), 2 ),
							number_format_i18n( (float) ( $a['est_usd'] ?? 0 ), 2 )
						)
					);
					echo '</li>';
				}
				echo '</ul>';
			}
		}

		// --- Actions (links / existing export surface only) ---
		// Activity uses a GET form (not <a class="button">): on the profile screen the
		// Activity nav-tab is already marked active, and an identical-looking href can
		// no-op in some browsers/automation. Submit always leaves profile → filtered Activity.
		echo '<h3>' . esc_html__( 'Actions', 'handl-ai-connector-access-control' ) . '</h3>';
		echo '<p class="handl-aicac-profile-actions">';
		echo '<a class="button button-secondary" href="' . esc_url( (string) $profile['actions']['rules_url'] ) . '">' . esc_html__( 'Edit rules for this plugin', 'handl-ai-connector-access-control' ) . '</a> ';

		echo '<form method="get" action="' . esc_url( admin_url( 'options-general.php' ) ) . '" style="display:inline;">';
		echo '<input type="hidden" name="page" value="handl-ai-connector-access-control" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="activity" />';
		echo '<input type="hidden" name="handl_aicac_log_plugin" value="' . esc_attr( $plugin ) . '" />';
		echo '<button type="submit" class="button button-secondary">' . esc_html__( 'View this plugin in Activity', 'handl-ai-connector-access-control' ) . '</button>';
		echo '</form> ';

		echo '<form method="post" style="display:inline;">';
		wp_nonce_field( 'handl_aicac_export_log', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="export_log" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="activity" />';
		echo '<input type="hidden" name="handl_aicac_log_plugin" value="' . esc_attr( $plugin ) . '" />';
		echo '<button type="submit" class="button">' . esc_html__( 'Download this plugin’s activity as CSV', 'handl-ai-connector-access-control' ) . '</button>';
		echo '</form>';
		echo '</p>';
		echo '<p class="description">' . esc_html__( 'The CSV uses the same Activity export. Rules can only be changed on the Rules tab.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '</div>';
	}

	/**
	 * @param list<array{key?:string,calls?:int,usd?:float}> $rows
	 */
	private function render_profile_bucket_table( array $rows ): void {
		echo '<table class="widefat striped" style="max-width:40em;"><thead><tr>';
		echo '<th>' . esc_html__( 'Name', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-num">' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-num">' . esc_html__( 'Estimated spend', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		$shown = 0;
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) || $shown >= 15 ) {
				break;
			}
			++$shown;
			$key = isset( $row['key'] ) ? (string) $row['key'] : '';
			if ( Analytics::UNKNOWN_KEY === $key ) {
				$key = __( 'Unknown', 'handl-ai-connector-access-control' );
			}
			echo '<tr>';
			echo '<td><code>' . esc_html( $key ) . '</code></td>';
			echo '<td class="column-num">' . esc_html( number_format_i18n( (int) ( $row['calls'] ?? 0 ) ) ) . '</td>';
			echo '<td class="column-num">$' . esc_html( number_format_i18n( (float) ( $row['usd'] ?? 0 ), 2 ) ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
	}

	/**
	 * F5 Dashboard — answers: Am I safe? What's spending? Block that one.
	 *
	 * @param array<int,mixed> $log
	 * @param array<string,mixed> $policy
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private function render_dashboard_tab( array $log, array $policy, array $plugins ): void {
		$coverage = $this->compute_coverage_buckets( $log, $policy );
		$pin      = Model_Force::pin_hold_stats( $log );
		$unforced = Model_Force::count_unforced_unattributed( $log );
		$has_pins = Model_Force::has_any_force_rules( $policy );

		// Spend over retained log (AI Client rows with tokens only; direct_http has none).
		$est_total   = 0.0;
		$est_any     = false;
		$deny_n      = 0;
		$plugin_spend = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$is_direct = isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'];
			if ( ! $is_direct && 'deny' === (string) ( $row['decision'] ?? '' ) ) {
				++$deny_n;
			}
			if ( $is_direct ) {
				continue;
			}
			$in  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
			$out = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
			$rates = Cost::rates_from_policy( $policy, isset( $row['provider'] ) ? (string) $row['provider'] : null );
			$usd   = Cost::estimate_usd( $in, $out, $rates );
			if ( null === $usd ) {
				continue;
			}
			$est_any    = true;
			$est_total += $usd;
			$p          = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			if ( '' === $p ) {
				$p = '__unknown__';
			}
			if ( ! isset( $plugin_spend[ $p ] ) ) {
				$plugin_spend[ $p ] = array( 'usd' => 0.0, 'calls' => 0 );
			}
			$plugin_spend[ $p ]['usd']   += $usd;
			$plugin_spend[ $p ]['calls'] += 1;
		}
		uasort(
			$plugin_spend,
			static function ( $a, $b ) {
				return $b['usd'] <=> $a['usd'];
			}
		);

		// Top attributed offenders for block-that-one (AI Client only; calls by plugin).
		$offenders = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'] ) {
				continue;
			}
			$p = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			if ( '' === $p ) {
				continue;
			}
			if ( ! isset( $offenders[ $p ] ) ) {
				$offenders[ $p ] = 0;
			}
			++$offenders[ $p ];
		}
		arsort( $offenders );

		// Shadow top callers (observe only — not governable here).
		$shadow_top = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( ! isset( $row['channel'] ) || 'direct_http' !== (string) $row['channel'] ) {
				continue;
			}
			$p = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			$c = isset( $row['count'] ) ? max( 1, (int) $row['count'] ) : 1;
			$key = '' !== $p ? $p : ( '__host__:' . (string) ( $row['host'] ?? '' ) );
			if ( ! isset( $shadow_top[ $key ] ) ) {
				$shadow_top[ $key ] = array(
					'calls'  => 0,
					'plugin' => $p,
					'host'   => (string) ( $row['host'] ?? '' ),
				);
			}
			$shadow_top[ $key ]['calls'] += $c;
		}
		uasort(
			$shadow_top,
			static function ( $a, $b ) {
				return $b['calls'] <=> $a['calls'];
			}
		);

		echo '<div class="handl-aicac-tab-panel handl-aicac-dashboard">';

		// AICAC-ONBOARD: first-run wizard + review reminder (Dashboard only).
		$this->render_onboarding_dashboard_section( $policy );

		// AICAC-11: name differentiators vs WordPress AI Connector Approvals (Dashboard-primary).
		$this->render_beyond_connector_approvals_callout();

		// --- Coverage tile (Δ1 + Δ5) ---
		echo '<div class="postbox handl-aicac-tile handl-aicac-tile--coverage">';
		echo '<div class="postbox-header"><h2 class="hndle">' . esc_html__( 'AI coverage', 'handl-ai-connector-access-control' ) . '</h2></div>';
		echo '<div class="inside">';
		if ( $coverage['D'] > 0 ) {
			// Q4 defaulted headline — one string, changeable at haktan F5 review.
			echo '<p class="handl-aicac-coverage-headline"><strong>';
			echo esc_html__( 'Some known AI activity is outside the AI Client and cannot be controlled by these rules', 'handl-ai-connector-access-control' );
			echo '</strong></p>';
		} elseif ( $coverage['M'] > 0 ) {
			echo '<p class="handl-aicac-coverage-headline"><strong>';
			echo esc_html__( 'All known AI activity in this log is using the AI Client', 'handl-ai-connector-access-control' );
			echo '</strong></p>';
		} else {
			echo '<p class="handl-aicac-coverage-headline"><strong>';
			echo esc_html__( 'No AI activity in the log yet', 'handl-ai-connector-access-control' );
			echo '</strong></p>';
		}

		echo '<p class="description handl-aicac-coverage-window">';
		echo esc_html(
			sprintf(
				/* translators: 1: log_limit (row slots), 2: human span or em dash */
				__( 'Last %1$s log entries, covering %2$s', 'handl-ai-connector-access-control' ),
				number_format_i18n( $coverage['log_limit'] ),
				$coverage['span_label']
			)
		);
		echo '</p>';

		echo '<p class="handl-aicac-coverage-buckets">';
		echo '<strong>' . esc_html__( 'Known AI activity:', 'handl-ai-connector-access-control' ) . '</strong> ';
		echo esc_html(
			sprintf(
				/* translators: %s: formatted call count M */
				__( '%s calls', 'handl-ai-connector-access-control' ),
				number_format_i18n( $coverage['M'] )
			)
		);
		echo '<br />';
		echo esc_html(
			sprintf(
				/* translators: 1: N through AI Client, 2: A attributed, 3: U unattributed */
				__( 'Through the AI Client: %1$s (identified: %2$s; unknown: %3$s)', 'handl-ai-connector-access-control' ),
				number_format_i18n( $coverage['N'] ),
				number_format_i18n( $coverage['A'] ),
				number_format_i18n( $coverage['U'] )
			)
		);
		echo '<br />';
		echo esc_html(
			sprintf(
				/* translators: %s: D outside AI Client call count */
				__( 'Outside the AI Client: %s (observed, not controlled)', 'handl-ai-connector-access-control' ),
				number_format_i18n( $coverage['D'] )
			)
		);
		echo '</p>';
		// Calls (M) can exceed log_limit entries when direct_http rows collapse multiple HTTP calls.
		echo '<p class="description">' . esc_html__( 'One log entry can represent many calls from the same plugin.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $coverage['saturated'] ) {
			echo '<div class="notice notice-warning inline"><p>';
			echo esc_html(
				sprintf(
					/* translators: %d: log_limit (row slots) */
					__( 'The log reached its %d-entry limit, so older entries were removed. Increase the limit under Activity settings to keep more history.', 'handl-ai-connector-access-control' ),
					$coverage['log_limit']
				)
			);
			echo '</p></div>';
		}

		echo '<p class="description">';
		echo esc_html__( 'Not counted: calls stopped before this plugin runs, direct cURL requests, and external workers that do not use WordPress HTTP or the AI Client.', 'handl-ai-connector-access-control' );
		echo '</p>';
		echo '</div></div>';

		// Secondary tiles: 2-col on wide viewports (CSS); coverage stays full-width above.
		echo '<div class="handl-aicac-dashboard-grid">';

		// --- Safety / control ---
		echo '<div class="postbox handl-aicac-tile handl-aicac-tile--safety">';
		echo '<div class="postbox-header"><h2 class="hndle">' . esc_html__( 'Safety and control', 'handl-ai-connector-access-control' ) . '</h2></div>';
		echo '<div class="inside">';
		$default = ( $policy['default'] ?? 'allow' ) === 'deny' ? __( 'Deny', 'handl-ai-connector-access-control' ) : __( 'Allow', 'handl-ai-connector-access-control' );
		$learn   = ! empty( $policy['audit_only'] )
			? __( 'Learn mode on (observing only; no blocking or model routing)', 'handl-ai-connector-access-control' )
			: __( 'Learn mode off (rules enforced)', 'handl-ai-connector-access-control' );
		echo '<p><strong>' . esc_html__( 'Default:', 'handl-ai-connector-access-control' ) . '</strong> ' . esc_html( $default );
		echo ' · <strong>' . esc_html( $learn ) . '</strong></p>';
		if ( ! empty( $policy['kill_switch'] ) ) {
			echo '<p class="handl-aicac-danger"><strong>' . esc_html__( 'Emergency stop is on.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		}
		echo '<p>' . esc_html(
			sprintf(
				/* translators: %d: deny count in retained log */
				_n( '%d blocked call in this log window.', '%d blocked calls in this log window.', $deny_n, 'handl-ai-connector-access-control' ),
				$deny_n
			)
		) . '</p>';
		echo '</div></div>';

		// --- Alert delivery health (AICAC-ALERT-HEALTH) ---
		$email_to     = Alerts::resolve_email( $policy );
		$webhook_url  = Alerts::resolve_webhook( $policy );
		$show_email   = '' !== $email_to;
		$show_webhook = '' !== $webhook_url;
		if ( $show_email || $show_webhook ) {
			$health = Alert_Health::get_state();
			echo '<div class="postbox handl-aicac-tile handl-aicac-tile--alert-health">';
			echo '<div class="postbox-header"><h2 class="hndle">' . esc_html__( 'Alert delivery', 'handl-ai-connector-access-control' ) . '</h2></div>';
			echo '<div class="inside">';
			echo '<p class="description">' . esc_html__( 'Shows whether recent email sends were accepted and whether webhook requests succeeded. Send a test using your saved settings.', 'handl-ai-connector-access-control' ) . '</p>';
			if ( $show_email ) {
				$email_row = $health[ Alert_Health::CHANNEL_EMAIL ];
				$line      = Alert_Health::format_status_line( Alert_Health::CHANNEL_EMAIL, $email_row );
				$failing   = (int) $email_row['consecutive_failures'] >= Alert_Health::FAILURE_THRESHOLD;
				echo $failing ? '<p class="handl-aicac-danger">' : '<p>';
				echo esc_html( $line );
				echo '</p>';
				echo '<form method="post" style="margin:0 0 1em;">';
				wp_nonce_field( 'handl_aicac_send_test_email', 'handl_aicac_nonce' );
				echo '<input type="hidden" name="handl_aicac_action" value="send_test_email" />';
				echo '<input type="hidden" name="handl_aicac_test_email_channel" value="denial_alert" />';
				echo '<input type="hidden" name="handl_aicac_tab" value="dashboard" />';
				submit_button( __( 'Send test email', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
				echo '</form>';
			}
			if ( $show_webhook ) {
				$hook_row = $health[ Alert_Health::CHANNEL_WEBHOOK ];
				$line     = Alert_Health::format_status_line( Alert_Health::CHANNEL_WEBHOOK, $hook_row );
				$failing  = (int) $hook_row['consecutive_failures'] >= Alert_Health::FAILURE_THRESHOLD;
				echo $failing ? '<p class="handl-aicac-danger">' : '<p>';
				echo esc_html( $line );
				echo '</p>';
				echo '<form method="post" style="margin:0;">';
				wp_nonce_field( 'handl_aicac_send_test_webhook', 'handl_aicac_nonce' );
				echo '<input type="hidden" name="handl_aicac_action" value="send_test_webhook" />';
				echo '<input type="hidden" name="handl_aicac_tab" value="dashboard" />';
				submit_button( __( 'Send test webhook', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
				echo '</form>';
			}
			echo '</div></div>';
		}

		// --- Spend ---
		echo '<div class="postbox handl-aicac-tile handl-aicac-tile--spend">';
		echo '<div class="postbox-header"><h2 class="hndle">' . esc_html__( 'Estimated spend', 'handl-ai-connector-access-control' ) . '</h2></div>';
		echo '<div class="inside">';
		if ( $est_any ) {
			echo '<p class="handl-aicac-spend-total"><strong>$' . esc_html( number_format_i18n( $est_total, 2 ) ) . '</strong> ';
			$rate_label = Cost::using_default_rates( $policy )
				? __( 'estimate using default rates', 'handl-ai-connector-access-control' )
				: __( 'estimate using custom rates', 'handl-ai-connector-access-control' );
			echo '<span class="description">' . esc_html( $rate_label ) . '</span></p>';

			$forecast = Spend_Forecast::compute( $log, $policy );
			if ( null !== $forecast ) {
				echo '<p class="handl-aicac-spend-forecast"><strong>';
				echo esc_html(
					sprintf(
						/* translators: %s: projected month-end USD amount */
						__( 'Estimated month-end: $%s', 'handl-ai-connector-access-control' ),
						number_format_i18n( (float) $forecast['projected_site'], 2 )
					)
				);
				echo '</strong> <span class="description">';
				echo esc_html(
					sprintf(
						/* translators: 1: days elapsed this month, 2: days in month, 3: month-to-date USD */
						__( 'Based on $%3$s so far across %1$d of %2$d days. Estimate only, not a bill.', 'handl-ai-connector-access-control' ),
						(int) $forecast['days_elapsed'],
						(int) $forecast['days_in_month'],
						number_format_i18n( (float) $forecast['mtd_site'], 2 )
					)
				);
				echo '</span></p>';
			}

			echo '<table class="widefat striped handl-aicac-tile-table"><thead><tr>';
			echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th class="column-num">' . esc_html__( 'Estimated $', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th class="column-num">' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			$i = 0;
			foreach ( $plugin_spend as $p => $row ) {
				if ( $i >= 8 ) {
					break;
				}
				++$i;
				$label = '__unknown__' === $p
					? __( 'unknown', 'handl-ai-connector-access-control' )
					: ( isset( $plugins[ $p ]['Name'] ) ? (string) $plugins[ $p ]['Name'] : $p );
				$profile_url = ( '__unknown__' !== $p ) ? Plugin_Profile::profile_url( (string) $p ) : '';
				echo '<tr><td>';
				if ( '' !== $profile_url ) {
					echo '<a href="' . esc_url( $profile_url ) . '">' . esc_html( $label ) . '</a>';
				} else {
					echo esc_html( $label );
				}
				echo '</td>';
				echo '<td class="column-num">$' . esc_html( number_format_i18n( $row['usd'], 2 ) ) . '</td>';
				echo '<td class="column-num">' . esc_html( number_format_i18n( $row['calls'] ) ) . '</td></tr>';
			}
			echo '</tbody></table>';
		} else {
			echo '<p class="description">' . esc_html__( 'No estimates yet. Token counts are required.', 'handl-ai-connector-access-control' ) . '</p>';
		}
		echo '</div></div>';

		// --- Pin-hold (Δ2): quiet when no force rules ---
		if ( $has_pins ) {
			echo '<div class="postbox handl-aicac-tile handl-aicac-tile--pins">';
			echo '<div class="postbox-header"><h2 class="hndle">' . esc_html__( 'Did model routes work?', 'handl-ai-connector-access-control' ) . '</h2></div>';
			echo '<div class="inside">';
			echo '<p><strong>';
			echo esc_html(
				sprintf(
					/* translators: 1: X held, 2: Y attempted */
					__( 'Model routes matched %1$s of %2$s attempts', 'handl-ai-connector-access-control' ),
					number_format_i18n( $pin['held'] ),
					number_format_i18n( $pin['attempted'] )
				)
			);
			echo '</strong></p>';
			if ( $unforced > 0 ) {
				echo '<p>';
				echo esc_html(
					sprintf(
						/* translators: %d: unattributed never-evaluated count */
						_n(
							'%d call had no detected plugin, so its model route was not checked.',
							'%d calls had no detected plugin, so their model routes were not checked.',
							$unforced,
							'handl-ai-connector-access-control'
						),
						$unforced
					)
				);
				echo '</p>';
			}
			if ( ! empty( $pin['by_skip'] ) ) {
				echo '<ul class="ul-disc">';
				foreach ( $pin['by_skip'] as $reason => $n ) {
					echo '<li><code>' . esc_html( $reason ) . '</code>: ' . esc_html( number_format_i18n( $n ) ) . '</li>';
				}
				echo '</ul>';
			}
			echo '</div></div>';
		}

		// --- Block that one ---
		echo '<div class="postbox handl-aicac-tile handl-aicac-tile--block">';
		echo '<div class="postbox-header"><h2 class="hndle">' . esc_html__( 'Block a plugin', 'handl-ai-connector-access-control' ) . '</h2></div>';
		echo '<div class="inside">';
		echo '<p class="description">' . esc_html__( 'These are the top AI Client callers that the plugin could identify in this log. Block one with a click. You can undo the change from the success notice.', 'handl-ai-connector-access-control' ) . '</p>';
		if ( empty( $offenders ) ) {
			echo '<p class="description">' . esc_html__( 'No identified AI Client callers in this log yet.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped handl-aicac-tile-table"><thead><tr>';
			echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th class="column-num">' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Rule', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Actions', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			$i = 0;
			foreach ( $offenders as $p => $calls ) {
				if ( $i >= 10 ) {
					break;
				}
				++$i;
				$label    = isset( $plugins[ $p ]['Name'] ) ? (string) $plugins[ $p ]['Name'] : $p;
				$explicit = isset( $policy['plugins'][ $p ] ) ? (string) $policy['plugins'][ $p ] : '';
				echo '<tr>';
				echo '<td><strong>' . esc_html( $label ) . '</strong><br /><code>' . esc_html( $p ) . '</code></td>';
				echo '<td class="column-num">' . esc_html( number_format_i18n( $calls ) ) . '</td>';
				echo '<td>' . esc_html( $this->format_explicit_rule_label( $explicit ) ) . '</td>';
				echo '<td class="handl-aicac-quick-actions">';
				// Single-click deny (board Q3); return to dashboard with undo notice.
				echo '<form method="post" class="handl-aicac-quick-rule-form">';
				wp_nonce_field( 'handl_aicac_quick_rule', 'handl_aicac_nonce' );
				echo '<input type="hidden" name="handl_aicac_action" value="quick_rule" />';
				echo '<input type="hidden" name="handl_aicac_quick_plugin" value="' . esc_attr( $p ) . '" />';
				echo '<input type="hidden" name="handl_aicac_quick_rule" value="deny" />';
				echo '<input type="hidden" name="handl_aicac_return_tab" value="dashboard" />';
				submit_button( __( 'Block', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false, array( 'class' => 'button button-small button-link-delete' ) );
				echo '</form>';
				$this->render_graduate_plugin_action( $p, $policy, $plugins );
				echo '</td></tr>';
			}
			echo '</tbody></table>';
		}

		// Shadow rows: explicit not-governable state (F5 item 5 / standing rule).
		if ( ! empty( $shadow_top ) ) {
			echo '<h3 style="margin-top:1.25em;">' . esc_html__( 'Outside AI Client (observe only)', 'handl-ai-connector-access-control' ) . '</h3>';
			echo '<p class="description">' . esc_html__( 'These calls bypass the AI Client, so Allow and Deny rules cannot control them.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '<table class="widefat striped handl-aicac-tile-table"><thead><tr>';
			echo '<th>' . esc_html__( 'Caller', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th class="column-num">' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Actions', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			$i = 0;
			foreach ( $shadow_top as $row ) {
				if ( $i >= 8 ) {
					break;
				}
				++$i;
				$p     = (string) ( $row['plugin'] ?? '' );
				$label = '' !== $p && isset( $plugins[ $p ]['Name'] )
					? (string) $plugins[ $p ]['Name']
					: ( '' !== $p ? $p : (string) ( $row['host'] ?? __( 'unknown', 'handl-ai-connector-access-control' ) ) );
				echo '<tr>';
				echo '<td><strong>' . esc_html( $label ) . '</strong>';
				if ( '' !== (string) ( $row['host'] ?? '' ) ) {
					echo '<br /><code>' . esc_html( (string) $row['host'] ) . '</code>';
				}
				echo '</td>';
				echo '<td class="column-num">' . esc_html( number_format_i18n( (int) $row['calls'] ) ) . '</td>';
				echo '<td><span class="description handl-aicac-not-governable">';
				echo esc_html__( 'observed, not controlled by these rules', 'handl-ai-connector-access-control' );
				echo '</span></td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div></div>';

		echo '</div>'; // .handl-aicac-dashboard-grid
		echo '</div>'; // .handl-aicac-dashboard
	}

	/**
	 * Coverage buckets — delegates to Analytics so Dashboard and weekly email share one implementation.
	 *
	 * @param array<int,mixed>    $log
	 * @param array<string,mixed> $policy
	 * @return array{A:int,U:int,N:int,D:int,M:int,log_limit:int,saturated:bool,span_label:string,min_ts:int,max_ts:int}
	 */
	private function compute_coverage_buckets( array $log, array $policy ): array {
		return Analytics::coverage_from_log( $log, $policy );
	}

	/**
	 * @param array<int,mixed> $log
	 * @param array<string,mixed> $policy
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private function render_insights_tab( array $log, array $policy, array $plugins ): void {
		$log_limit_policy = (int) ( $policy['log_limit'] ?? 200 );
		$stored_count     = count( $log );
		$aggregated       = Analytics::aggregate_from_log( $log, $plugins );
		$summary          = $aggregated['summary'];

		$dimension = 'plugin';
		if ( isset( $_REQUEST['handl_aicac_insights_dim'] ) ) {
			$dimension = sanitize_key( wp_unslash( (string) $_REQUEST['handl_aicac_insights_dim'] ) );
		}
		if ( ! isset( $aggregated['dimensions'][ $dimension ] ) ) {
			$dimension = 'plugin';
		}

		$metric = 'calls';
		if ( isset( $_REQUEST['handl_aicac_insights_metric'] ) ) {
			$metric = sanitize_key( wp_unslash( (string) $_REQUEST['handl_aicac_insights_metric'] ) );
		}
		if ( 'tokens' !== $metric ) {
			$metric = 'calls';
		}

		$rows = $aggregated['dimensions'][ $dimension ];
		$base_url = add_query_arg(
			array(
				'page'            => 'handl-ai-connector-access-control',
				'handl_aicac_tab' => 'insights',
			),
			admin_url( 'options-general.php' )
		);

		echo '<div class="handl-aicac-tab-panel handl-aicac-insights-wrap">';

		echo '<div class="handl-aicac-insights-hero">';
		echo '<div class="handl-aicac-insights-hero__copy">';
		echo '<h2 class="handl-aicac-insights-title">' . esc_html__( 'Usage insights', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="handl-aicac-insights-lead">';
		echo esc_html__( 'Totals and peaks from the saved log, grouped by plugin, provider, model, or operation.', 'handl-ai-connector-access-control' );
		echo '</p>';
		if ( 0 === $stored_count ) {
			echo '<p class="handl-aicac-insights-empty-note">';
			echo esc_html__( 'No data yet. Turn on Learn mode or logging in Activity, then run a few AI Client requests.', 'handl-ai-connector-access-control' );
			echo ' <a href="' . esc_url( admin_url( 'options-general.php?page=handl-ai-connector-access-control&handl_aicac_tab=activity' ) ) . '">';
			echo esc_html__( 'Open Activity', 'handl-ai-connector-access-control' );
			echo '</a></p>';
		} else {
			printf(
				'<p class="handl-aicac-insights-meta">%s</p>',
				esc_html(
					sprintf(
						/* translators: 1: stored entry count, 2: retention limit (entries), 3: retention mode phrase */
						__( 'Using %1$d of %2$d saved entries (%3$s).', 'handl-ai-connector-access-control' ),
						$stored_count,
						$log_limit_policy,
						$this->retention_mode_phrase( $policy )
					)
				)
			);
			// F6: one-line count only — not a second coverage %. Charts below are AI Client rows.
			// Sum of `count` on collapsed clusters (chatty-host collapse); missing count = 1.
			$direct_http_count = 0;
			foreach ( $log as $log_row ) {
				if ( is_array( $log_row ) && isset( $log_row['channel'] ) && 'direct_http' === (string) $log_row['channel'] ) {
					$cluster = isset( $log_row['count'] ) ? (int) $log_row['count'] : 1;
					$direct_http_count += $cluster > 0 ? $cluster : 1;
				}
			}
			if ( $direct_http_count > 0 ) {
				printf(
					'<p class="handl-aicac-insights-meta handl-aicac-insights-shadow">%s</p>',
					esc_html(
						sprintf(
							/* translators: %d: sum of direct_http row counts (HTTP calls) outside the AI Client */
							_n(
								'%d AI HTTP call was observed outside the AI Client and is not controlled by these rules.',
								'%d AI HTTP calls were observed outside the AI Client and are not controlled by these rules.',
								$direct_http_count,
								'handl-ai-connector-access-control'
							),
							$direct_http_count
						)
					)
				);
			}
		}
		echo '</div>';
		echo '</div>';

		if ( $stored_count > 0 ) {
			echo '<div class="handl-aicac-insights-summary" role="group" aria-label="' . esc_attr__( 'Overall totals', 'handl-ai-connector-access-control' ) . '">';
			$this->render_insights_stat_card(
				__( 'Total calls', 'handl-ai-connector-access-control' ),
				number_format_i18n( $summary['calls'] ),
				''
			);
			$this->render_insights_stat_card(
				__( 'Calls with token data', 'handl-ai-connector-access-control' ),
				number_format_i18n( $summary['calls_with_tokens'] ),
				$summary['calls'] > 0
					? sprintf(
						/* translators: %s: percentage */
						__( '%s%% of calls', 'handl-ai-connector-access-control' ),
						number_format_i18n( (int) round( 100 * $summary['calls_with_tokens'] / max( 1, $summary['calls'] ) ) )
					)
					: ''
			);
			$this->render_insights_stat_card(
				__( 'Total tokens (input + output)', 'handl-ai-connector-access-control' ),
				$this->format_insights_token_total( $summary['sum_input'], $summary['sum_output'] ),
				$summary['sum_total'] > 0
					? sprintf(
						/* translators: %s: formatted total token count */
						__( 'Reported total: %s', 'handl-ai-connector-access-control' ),
						number_format_i18n( $summary['sum_total'] )
					)
					: __( 'Filled after model responds', 'handl-ai-connector-access-control' )
			);
			$this->render_insights_stat_card(
				__( 'Largest single call', 'handl-ai-connector-access-control' ),
				$summary['max_total'] > 0 ? number_format_i18n( $summary['max_total'] ) : '—',
				$summary['max_total'] > 0
					? sprintf(
						/* translators: 1: input tokens, 2: output tokens */
						__( '%1$s input, %2$s output', 'handl-ai-connector-access-control' ),
						number_format_i18n( $summary['max_input'] ),
						number_format_i18n( $summary['max_output'] )
					)
					: ''
			);
			echo '</div>';
		}

		$forecast = Spend_Forecast::compute( $log, $policy );
		if ( null !== $forecast && ! empty( $forecast['plugins'] ) ) {
			echo '<div class="handl-aicac-insights-forecast" style="margin:1.25em 0;">';
			echo '<h3>' . esc_html__( 'Estimated month-end by plugin', 'handl-ai-connector-access-control' ) . '</h3>';
			echo '<p class="description">' . esc_html__( 'Projected from this month’s estimated spend so far. Estimate only, not a bill.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th class="column-num">' . esc_html__( 'Estimated so far this month', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th class="column-num">' . esc_html__( 'Estimated month-end', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			$i = 0;
			foreach ( $forecast['plugins'] as $basename => $row ) {
				if ( $i >= 12 ) {
					break;
				}
				++$i;
				$label = Analytics::UNKNOWN_KEY === $basename
					? __( '(unknown plugin)', 'handl-ai-connector-access-control' )
					: ( isset( $plugins[ $basename ]['Name'] ) ? (string) $plugins[ $basename ]['Name'] : (string) $basename );
				echo '<tr><td>' . esc_html( $label ) . '</td>';
				echo '<td class="column-num">$' . esc_html( number_format_i18n( (float) $row['mtd'], 2 ) ) . '</td>';
				echo '<td class="column-num">$' . esc_html( number_format_i18n( (float) $row['projected'], 2 ) ) . '</td></tr>';
			}
			echo '</tbody></table></div>';
		}

		$this->render_insights_trends( $log, $policy, $plugins );

		$dimensions = array(
			'plugin'    => __( 'Plugins', 'handl-ai-connector-access-control' ),
			'provider'  => __( 'Providers', 'handl-ai-connector-access-control' ),
			'model'     => __( 'Models', 'handl-ai-connector-access-control' ),
			'operation' => __( 'Operations', 'handl-ai-connector-access-control' ),
		);

		echo '<div class="handl-aicac-insights-toolbar">';
		echo '<nav class="handl-aicac-insights-pills" aria-label="' . esc_attr__( 'Group by', 'handl-ai-connector-access-control' ) . '">';
		foreach ( $dimensions as $dim_key => $dim_label ) {
			$pill_url = add_query_arg(
				array(
					'handl_aicac_insights_dim'    => $dim_key,
					'handl_aicac_insights_metric' => $metric,
				),
				$base_url
			);
			printf(
				'<a href="%1$s" class="handl-aicac-insights-pill%2$s">%3$s</a>',
				esc_url( $pill_url ),
				$dimension === $dim_key ? ' is-active' : '',
				esc_html( $dim_label )
			);
		}
		echo '</nav>';

		echo '<nav class="handl-aicac-insights-metric-toggle" aria-label="' . esc_attr__( 'Measure', 'handl-ai-connector-access-control' ) . '">';
		foreach ( array(
			'calls'  => __( 'Calls', 'handl-ai-connector-access-control' ),
			'tokens' => __( 'Total tokens', 'handl-ai-connector-access-control' ),
		) as $metric_key => $metric_label ) {
			$metric_url = add_query_arg(
				array(
					'handl_aicac_insights_dim'    => $dimension,
					'handl_aicac_insights_metric' => $metric_key,
				),
				$base_url
			);
			printf(
				'<a href="%1$s" class="handl-aicac-insights-metric%2$s">%3$s</a>',
				esc_url( $metric_url ),
				$metric === $metric_key ? ' is-active' : '',
				esc_html( $metric_label )
			);
		}
		echo '</nav>';
		echo '</div>';

		if ( empty( $rows ) ) {
			echo '<p class="handl-aicac-insights-table-empty">' . esc_html__( 'No data to chart for this group yet.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';
			return;
		}

		$chart_max = 0;
		foreach ( $rows as $row ) {
			$chart_max = max( $chart_max, $this->insights_row_metric_value( $row, $metric ) );
		}

		echo '<div class="handl-aicac-insights-panel">';
		echo '<table class="widefat handl-aicac-insights-table">';
		echo '<thead><tr>';
		echo '<th class="column-rank">' . esc_html__( '#', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-label">' . esc_html( $dimensions[ $dimension ] ) . '</th>';
		echo '<th class="column-chart">' . esc_html__( 'Share', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-num">' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-num">' . esc_html__( 'Total tokens', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-num">' . esc_html__( 'Largest call', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-num">' . esc_html__( 'Largest input', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-num">' . esc_html__( 'Largest output', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-time">' . esc_html__( 'Last seen', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';

		$rank = 0;
		foreach ( $rows as $row ) {
			++$rank;
			$this->render_insights_table_row( $row, $rank, $dimension, $metric, $chart_max );
		}

		echo '</tbody></table>';
		echo '</div>';
		echo '</div>';
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private function insights_row_metric_value( array $row, string $metric ): int {
		if ( 'tokens' === $metric ) {
			return (int) ( $row['sum_total'] ?? 0 );
		}

		return (int) ( $row['calls'] ?? 0 );
	}

	private function format_insights_token_total( int $input, int $output ): string {
		if ( 0 === $input && 0 === $output ) {
			return '—';
		}

		return number_format_i18n( $input + $output );
	}

	/**
	 * AICAC-TRENDS: weekly call/spend history (site + per plugin). Hidden when
	 * fewer than two weeks of retained activity exist.
	 *
	 * @param array<int,mixed>                  $log
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private function render_insights_trends( array $log, array $policy, array $plugins ): void {
		$trends = Usage_Trends::compute( $log, $policy, $plugins );
		if ( null === $trends ) {
			return;
		}

		echo '<div class="handl-aicac-insights-trends" style="margin:1.5em 0;">';
		echo '<h3>' . esc_html__( 'Weekly trends', 'handl-ai-connector-access-control' ) . '</h3>';
		echo '<p class="description">' . esc_html__( 'Calls and estimated spend by week from the saved log (last 8 weeks). Weeks with no saved data say “no data kept” — they are not shown as zero. Estimate only, not a bill.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<table class="widefat striped handl-aicac-trends-table">';
		echo '<thead><tr>';
		echo '<th>' . esc_html__( 'Scope', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Calls trend', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'This week vs last', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Estimated spend trend', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Spend vs last week', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';

		$this->render_insights_trend_row(
			__( 'Entire site', 'handl-ai-connector-access-control' ),
			$trends['site']['weeks'],
			$trends['site']['calls_delta_pct'],
			$trends['site']['spend_delta_pct']
		);

		$shown = 0;
		foreach ( $trends['plugins'] as $row ) {
			if ( $shown >= 12 ) {
				break;
			}
			++$shown;
			$this->render_insights_trend_row(
				(string) $row['label'],
				$row['weeks'],
				$row['calls_delta_pct'],
				$row['spend_delta_pct']
			);
		}

		echo '</tbody></table>';

		echo '<p class="description handl-aicac-trends-legend">';
		echo esc_html__( 'Week detail (newest last):', 'handl-ai-connector-access-control' );
		echo ' ';
		$parts = array();
		foreach ( $trends['site']['weeks'] as $i => $w ) {
			$label = isset( $trends['weeks'][ $i ]['label'] ) ? (string) $trends['weeks'][ $i ]['label'] : (string) $w['key'];
			if ( 'gap' === ( $w['status'] ?? '' ) ) {
				$parts[] = sprintf(
					/* translators: %s: week start label */
					__( '%s — no data kept', 'handl-ai-connector-access-control' ),
					$label
				);
			} else {
				$parts[] = sprintf(
					/* translators: 1: week start label, 2: call count, 3: dollar amount */
					__( '%1$s — %2$s calls, $%3$s', 'handl-ai-connector-access-control' ),
					$label,
					number_format_i18n( (int) ( $w['calls'] ?? 0 ) ),
					number_format_i18n( (float) ( $w['spend'] ?? 0 ), 2 )
				);
			}
		}
		echo esc_html( implode( '; ', $parts ) );
		echo '</p>';
		echo '</div>';
	}

	/**
	 * @param list<array{status:string,calls:int|null,spend:float|null}> $weeks
	 */
	private function render_insights_trend_row( string $label, array $weeks, ?float $calls_delta, ?float $spend_delta ): void {
		$calls_svg = Usage_Trends::sparkline_svg( $weeks, 'calls' );
		$spend_svg = Usage_Trends::sparkline_svg( $weeks, 'spend' );

		echo '<tr>';
		echo '<td>' . esc_html( $label ) . '</td>';
		echo '<td class="handl-aicac-trends-spark">';
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- sparkline_svg escapes attribute values.
		echo '' !== $calls_svg ? $calls_svg : '&mdash;';
		echo '</td>';
		echo '<td>' . esc_html( Usage_Trends::format_delta_label( $calls_delta ) ) . '</td>';
		echo '<td class="handl-aicac-trends-spark">';
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- sparkline_svg escapes attribute values.
		echo '' !== $spend_svg ? $spend_svg : '&mdash;';
		echo '</td>';
		echo '<td>' . esc_html( Usage_Trends::format_delta_label( $spend_delta ) ) . '</td>';
		echo '</tr>';
	}

	private function render_insights_stat_card( string $label, string $value, string $hint ): void {
		echo '<div class="handl-aicac-insights-stat">';
		echo '<span class="handl-aicac-insights-stat__label">' . esc_html( $label ) . '</span>';
		echo '<span class="handl-aicac-insights-stat__value">' . esc_html( $value ) . '</span>';
		if ( '' !== $hint ) {
			echo '<span class="handl-aicac-insights-stat__hint">' . esc_html( $hint ) . '</span>';
		}
		echo '</div>';
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private function render_insights_table_row( array $row, int $rank, string $dimension, string $metric, int $chart_max ): void {
		$key         = (string) ( $row['key'] ?? '' );
		$label       = (string) ( $row['label'] ?? $key );
		$calls       = (int) ( $row['calls'] ?? 0 );
		$sum_total   = (int) ( $row['sum_total'] ?? 0 );
		$max_total   = (int) ( $row['max_total'] ?? 0 );
		$max_input   = (int) ( $row['max_input'] ?? 0 );
		$max_output  = (int) ( $row['max_output'] ?? 0 );
		$last_ts     = (int) ( $row['last_ts'] ?? 0 );
		$bar_value   = $this->insights_row_metric_value( $row, $metric );
		$bar_percent = $chart_max > 0 ? (int) round( 100 * $bar_value / $chart_max ) : 0;
		if ( $bar_percent > 0 && $bar_value > 0 && $bar_percent < 4 ) {
			$bar_percent = 4;
		}

		$is_peak_row = 1 === $rank;

		echo '<tr' . ( $is_peak_row ? ' class="handl-aicac-insights-row--leader"' : '' ) . '>';
		echo '<td class="column-rank">';
		if ( $is_peak_row ) {
			echo '<span class="handl-aicac-insights-rank-badge" title="' . esc_attr__( 'Highest value in this view', 'handl-ai-connector-access-control' ) . '">★</span> ';
		}
		echo esc_html( (string) $rank );
		echo '</td>';
		echo '<td class="column-label">';
		echo '<strong>' . esc_html( $label ) . '</strong>';
		if ( Analytics::UNKNOWN_KEY !== $key && $key !== $label ) {
			echo '<br /><code class="handl-aicac-insights-key">' . esc_html( $key ) . '</code>';
		}
		echo '</td>';
		echo '<td class="column-chart">';
		echo '<div class="handl-aicac-insights-bar" role="img" aria-label="' . esc_attr(
			sprintf(
				/* translators: %d: percentage of chart maximum */
				__( '%d%% of the chart maximum', 'handl-ai-connector-access-control' ),
				$bar_percent
			)
		) . '">';
		printf(
			'<span class="handl-aicac-insights-bar__fill" style="width:%d%%;"></span>',
			(int) $bar_percent
		);
		echo '<span class="handl-aicac-insights-bar__value">' . esc_html( number_format_i18n( $bar_value ) ) . '</span>';
		echo '</div>';
		echo '</td>';
		echo '<td class="column-num">' . esc_html( number_format_i18n( $calls ) ) . '</td>';
		echo '<td class="column-num">' . esc_html( $sum_total > 0 ? number_format_i18n( $sum_total ) : '—' ) . '</td>';
		echo '<td class="column-num handl-aicac-insights-peak">' . esc_html( $max_total > 0 ? number_format_i18n( $max_total ) : '—' ) . '</td>';
		echo '<td class="column-num">' . esc_html( $max_input > 0 ? number_format_i18n( $max_input ) : '—' ) . '</td>';
		echo '<td class="column-num">' . esc_html( $max_output > 0 ? number_format_i18n( $max_output ) : '—' ) . '</td>';
		echo '<td class="column-time">' . esc_html( $last_ts ? wp_date( 'Y-m-d H:i', $last_ts ) : '—' ) . '</td>';
		echo '</tr>';
	}

	/**
	 * @param array<int,mixed> $log
	 * @param array<string,mixed> $policy
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private function render_log_tab( array $log, array $policy, array $plugins ): void {
		$log_limit_policy = (int) ( $policy['log_limit'] ?? 200 );
		$stored_count     = count( $log );
		$log_filters      = $this->log_filters;
		$filter_options   = $this->collect_log_filter_options( $log, $plugins );

		echo '<div id="handl-aicac-log-wrap" class="handl-aicac-tab-panel handl-aicac-log-wrap">';

		// Detached POST forms so "Send test email" can sit next to fields without nesting forms.
		echo '<form method="post" id="handl-aicac-test-email-denial" style="display:none;" hidden>';
		wp_nonce_field( 'handl_aicac_send_test_email', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="send_test_email" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="activity" />';
		echo '<input type="hidden" name="handl_aicac_test_email_channel" value="denial_alert" />';
		echo '</form>';
		echo '<form method="post" id="handl-aicac-test-email-weekly" style="display:none;" hidden>';
		wp_nonce_field( 'handl_aicac_send_test_email', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="send_test_email" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="activity" />';
		echo '<input type="hidden" name="handl_aicac_test_email_channel" value="weekly_report" />';
		echo '</form>';

		echo '<form method="post" style="margin-bottom:1.5em;">';
		wp_nonce_field( 'handl_aicac_save_policy', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="save" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="activity" />';
		$this->render_log_filter_hiddens( $log_filters );
		$this->render_logging_settings( $policy );
		submit_button( __( 'Save Activity settings', 'handl-ai-connector-access-control' ) );
		echo '</form>';

		$webhook_saved = Alerts::resolve_webhook( $policy );
		if ( '' !== $webhook_saved ) {
			echo '<form method="post" style="margin-bottom:1.5em;">';
			wp_nonce_field( 'handl_aicac_send_test_webhook', 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_action" value="send_test_webhook" />';
			echo '<input type="hidden" name="handl_aicac_tab" value="activity" />';
			submit_button(
				__( 'Send test webhook', 'handl-ai-connector-access-control' ),
				'secondary',
				'submit',
				false
			);
			echo '<p class="description" style="display:inline;margin-left:8px;">' . esc_html__( 'Immediately sends a sample JSON payload to the saved Webhook URL. The payload is marked as a test, does not represent a real blocked call, and does not count toward rate limits.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</form>';
		}

		$pending_digest = count( Alerts::pending_digest_rows() );
		$alerts_on      = ! empty( $policy['alert_on_deny'] ) || ! empty( $policy['alert_on_shadow'] );
		if ( $pending_digest > 0 && $alerts_on ) {
			echo '<form method="post" style="margin-bottom:1.5em;">';
			wp_nonce_field( 'handl_aicac_send_digest', 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_action" value="send_denial_digest" />';
			echo '<input type="hidden" name="handl_aicac_tab" value="activity" />';
			submit_button(
				sprintf(
/* translators: %d: queued alert count */
					__( 'Send alert summary now (%d queued)', 'handl-ai-connector-access-control' ),
					$pending_digest
				),
				'secondary',
				'submit',
				false
			);
			echo '</form>';
		}

		if ( ! empty( $policy['audit_only'] ) ) {
			$this->render_suggested_rules( $log, $policy, $plugins, $log_filters );
		}

		echo '<h2>' . esc_html__( 'Recent calls', 'handl-ai-connector-access-control' ) . '</h2>';
		$this->render_log_filters( $log_filters, $filter_options, $plugins );

		echo '<form method="post" style="margin:0 0 1em;display:inline-block;">';
		wp_nonce_field( 'handl_aicac_export_audit_report', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="export_audit_report" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="activity" />';
		echo '<label for="handl-aicac-report-window" class="screen-reader-text">' . esc_html__( 'Report window', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<select name="handl_aicac_report_window" id="handl-aicac-report-window">';
		foreach ( array(
			'7d'  => __( 'Last 7 days', 'handl-ai-connector-access-control' ),
			'1d'  => __( 'Last 24 hours', 'handl-ai-connector-access-control' ),
			'30d' => __( 'Last 30 days', 'handl-ai-connector-access-control' ),
			'all' => __( 'All saved activity', 'handl-ai-connector-access-control' ),
		) as $win => $win_label ) {
			printf(
				'<option value="%1$s"%2$s>%3$s</option>',
				esc_attr( $win ),
				'7d' === $win ? ' selected="selected"' : '',
				esc_html( $win_label )
			);
		}
		echo '</select> ';
		submit_button(
			__( 'Open audit report', 'handl-ai-connector-access-control' ),
			'secondary',
			'submit',
			false
		);
		echo ' <span class="description">' . esc_html__( 'Opens a printable report in your browser. Use Print → Save as PDF. Nothing is uploaded.', 'handl-ai-connector-access-control' ) . '</span>';
		echo '</form>';

		echo '<form method="post" style="margin:0 0 1em;">';
		wp_nonce_field( 'handl_aicac_export_log', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="export_log" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="activity" />';
		$this->render_log_filter_hiddens( $log_filters );
		submit_button(
			__( 'Download CSV', 'handl-ai-connector-access-control' ),
			'secondary',
			'submit',
			false
		);
		echo ' <span class="description">' . esc_html__( 'Downloads all saved activity matching your current filters, not just the rows shown here.', 'handl-ai-connector-access-control' ) . '</span>';
		echo '</form>';

		$log_newest_first = array_reverse( $log );
		$matching_count   = 0;
		$rows_to_show     = array();
		foreach ( $log_newest_first as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( ! $this->log_row_matches_filters( $row, $log_filters ) ) {
				continue;
			}
			++$matching_count;
			if ( count( $rows_to_show ) < 50 ) {
				$rows_to_show[] = $row;
			}
		}

		$retention_phrase = $this->retention_mode_phrase( $policy );
		echo '<p class="handl-aicac-log-meta">';
		if ( $this->log_filters_active( $log_filters ) ) {
			printf(
				/* translators: 1: entries shown, 2: matching-entry count, 3: stored entry count, 4: retention limit, 5: retention mode phrase */
				esc_html__( 'Showing %1$d of %2$d matching entries, newest first. The log currently keeps %3$d of %4$d entries (%5$s).', 'handl-ai-connector-access-control' ),
				count( $rows_to_show ),
				$matching_count,
				(int) $stored_count,
				(int) $log_limit_policy,
				$retention_phrase
			);
		} else {
			printf(
				/* translators: 1: stored entry count, 2: retention limit, 3: rows shown in table, 4: retention mode phrase */
				esc_html__( 'Showing the newest %3$d rows. The log currently keeps %1$d of %2$d entries (%4$s).', 'handl-ai-connector-access-control' ),
				(int) $stored_count,
				(int) $log_limit_policy,
				count( $rows_to_show ),
				$retention_phrase
			);
		}
		echo '</p>';
		echo '<table class="widefat striped handl-aicac-log-table">';
		echo '<thead><tr>';
		echo '<th class="column-time">' . esc_html__( 'Time', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Decision', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-operation">' . esc_html__( 'Operation / AI type', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-provider">' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-model">' . esc_html__( 'Model', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-tokens">' . esc_html__( 'Input tokens', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-tokens">' . esc_html__( 'Output tokens', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-tokens">' . esc_html__( 'Estimated $', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Prompt', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'User', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Request URL', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th class="column-actions">' . esc_html__( 'Actions', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';

		foreach ( $rows_to_show as $row ) {
			$this->render_log_row( $row, $plugins, $policy, $log_filters );
		}

		if ( 0 === count( $rows_to_show ) ) {
			if ( 0 === $stored_count ) {
				$empty_message = ! empty( $policy['audit_only'] )
					? __( 'No calls logged yet. Make an AI Client request while Learn mode is on.', 'handl-ai-connector-access-control' )
					: __( 'No calls logged yet. Turn on logging above, then make an AI Client request.', 'handl-ai-connector-access-control' );
			} elseif ( $this->log_filters_active( $log_filters ) ) {
				$empty_message = __( 'No calls match the current filters.', 'handl-ai-connector-access-control' );
			} else {
				$empty_message = __( 'No calls to display.', 'handl-ai-connector-access-control' );
			}
			echo '<tr><td colspan="13">' . esc_html( $empty_message ) . '</td></tr>';
		}

		echo '</tbody></table>';
		echo '</div>';
	}

	/**
	 * @return array{decision:string,operation:string,provider:string,model:string,plugin:string}
	 */
	private function parse_log_filters(): array {
		$filters = array(
			'decision'  => '',
			'operation' => '',
			'provider'  => '',
			'model'     => '',
			'plugin'    => '',
		);

		if ( isset( $_REQUEST['handl_aicac_log_decision'] ) ) {
			$decision = sanitize_key( wp_unslash( (string) $_REQUEST['handl_aicac_log_decision'] ) );
			if ( 'allow' === $decision || 'deny' === $decision || 'observe' === $decision ) {
				$filters['decision'] = $decision;
			}
		}

		$text_fields = array(
			'operation' => 'handl_aicac_log_operation',
			'provider'  => 'handl_aicac_log_provider',
			'model'     => 'handl_aicac_log_model',
			'plugin'    => 'handl_aicac_log_plugin',
		);

		foreach ( $text_fields as $key => $request_key ) {
			if ( ! isset( $_REQUEST[ $request_key ] ) ) {
				continue;
			}
			$value = sanitize_text_field( wp_unslash( (string) $_REQUEST[ $request_key ] ) );
			if ( '' === $value ) {
				continue;
			}
			if ( self::LOG_FILTER_UNKNOWN === $value ) {
				$filters[ $key ] = self::LOG_FILTER_UNKNOWN;
				continue;
			}
			$filters[ $key ] = $value;
		}

		return $filters;
	}

	/**
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $filters
	 * @return array<string,string>
	 */
	private function log_filters_to_query_args( array $filters ): array {
		$args = array();
		foreach ( $filters as $key => $value ) {
			if ( '' === $value ) {
				continue;
			}
			$args[ 'handl_aicac_log_' . $key ] = $value;
		}
		return $args;
	}

	/**
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $filters
	 */
	private function log_filters_active( array $filters ): bool {
		foreach ( $filters as $value ) {
			if ( '' !== $value ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param array<int,mixed> $log
	 * @param array<string,array<string,mixed>> $plugins
	 * @return array{decision:array<string,string>,operation:array<string,string>,provider:array<string,string>,model:array<string,string>,plugin:array<string,string>}
	 */
	private function collect_log_filter_options( array $log, array $plugins ): array {
		$options = array(
			'decision'  => array(),
			'operation' => array(),
			'provider'  => array(),
			'model'     => array(),
			'plugin'    => array(),
		);

		$has_unknown = array(
			'operation' => false,
			'provider'  => false,
			'model'     => false,
			'plugin'    => false,
		);

		foreach ( $log as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}

			$decision = $this->get_log_row_field( $row, 'decision' );
			if ( 'allow' === $decision || 'deny' === $decision || 'observe' === $decision ) {
				$options['decision'][ $decision ] = $decision;
			}

			foreach ( array( 'operation', 'provider' ) as $field ) {
				$value = $this->get_log_row_field( $row, $field );
				if ( '' === $value ) {
					$has_unknown[ $field ] = true;
					continue;
				}
				$options[ $field ][ $value ] = $value;
			}

			$model = $this->get_log_row_model( $row );
			if ( '' === $model ) {
				$has_unknown['model'] = true;
			} else {
				$options['model'][ $model ] = $model;
			}

			$plugin = $this->get_log_row_field( $row, 'plugin' );
			if ( '' === $plugin ) {
				$has_unknown['plugin'] = true;
				continue;
			}
			$label = $plugin;
			if ( isset( $plugins[ $plugin ]['Name'] ) ) {
				$label = (string) $plugins[ $plugin ]['Name'];
			}
			$options['plugin'][ $plugin ] = $label;
		}

		foreach ( array( 'operation', 'provider', 'model', 'plugin' ) as $field ) {
			if ( $has_unknown[ $field ] ) {
				$options[ $field ][ self::LOG_FILTER_UNKNOWN ] = __( '(unknown)', 'handl-ai-connector-access-control' );
			}
			natcasesort( $options[ $field ] );
			if ( isset( $options[ $field ][ self::LOG_FILTER_UNKNOWN ] ) ) {
				$unknown_label = $options[ $field ][ self::LOG_FILTER_UNKNOWN ];
				unset( $options[ $field ][ self::LOG_FILTER_UNKNOWN ] );
				$options[ $field ] = array( self::LOG_FILTER_UNKNOWN => $unknown_label ) + $options[ $field ];
			}
		}

		return $options;
	}

	/**
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $filters
	 * @param array{decision:array<string,string>,operation:array<string,string>,provider:array<string,string>,model:array<string,string>,plugin:array<string,string>} $filter_options
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private function render_log_filters( array $filters, array $filter_options, array $plugins ): void {
		unset( $plugins );

		$base_url = add_query_arg(
			array(
				'page'            => 'handl-ai-connector-access-control',
				'handl_aicac_tab' => 'activity',
			),
			admin_url( 'options-general.php' )
		);

		$decision_views = array(
			''         => __( 'All', 'handl-ai-connector-access-control' ),
			'allow'    => __( 'Allow', 'handl-ai-connector-access-control' ),
			'deny'     => __( 'Deny', 'handl-ai-connector-access-control' ),
			'observe'  => __( 'Outside AI Client', 'handl-ai-connector-access-control' ),
		);

		$other_filters = $filters;
		$other_filters['decision'] = '';

		echo '<div class="handl-aicac-table-filters handl-aicac-log-filters">';
		echo '<ul class="subsubsub">';
		$view_index = 0;
		foreach ( $decision_views as $decision_key => $decision_label ) {
			if ( $view_index > 0 ) {
				echo ' | ';
			}
			++$view_index;

			$view_filters           = $other_filters;
			$view_filters['decision'] = $decision_key;
			$view_url               = add_query_arg( $this->log_filters_to_query_args( $view_filters ), $base_url );

			$is_current = $filters['decision'] === $decision_key;
			printf(
				'<li><a href="%1$s"%2$s>%3$s</a></li>',
				esc_url( $view_url ),
				$is_current ? ' class="current" aria-current="page"' : '',
				esc_html( $decision_label )
			);
		}
		echo '</ul>';

		echo '<form method="get">';
		echo '<input type="hidden" name="page" value="handl-ai-connector-access-control" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="activity" />';
		if ( '' !== $filters['decision'] ) {
			echo '<input type="hidden" name="handl_aicac_log_decision" value="' . esc_attr( $filters['decision'] ) . '" />';
		}
		echo '<div class="tablenav top">';
		echo '<div class="alignleft actions">';
		$this->render_log_filter_select(
			'handl-aicac-log-operation-filter',
			'handl_aicac_log_operation',
			__( 'All operations', 'handl-ai-connector-access-control' ),
			__( 'Filter by operation', 'handl-ai-connector-access-control' ),
			$filters['operation'],
			$filter_options['operation']
		);
		$this->render_log_filter_select(
			'handl-aicac-log-provider-filter',
			'handl_aicac_log_provider',
			__( 'All providers', 'handl-ai-connector-access-control' ),
			__( 'Filter by provider', 'handl-ai-connector-access-control' ),
			$filters['provider'],
			$filter_options['provider']
		);
		$this->render_log_filter_select(
			'handl-aicac-log-model-filter',
			'handl_aicac_log_model',
			__( 'All models', 'handl-ai-connector-access-control' ),
			__( 'Filter by model', 'handl-ai-connector-access-control' ),
			$filters['model'],
			$filter_options['model']
		);
		$this->render_log_filter_select(
			'handl-aicac-log-plugin-filter',
			'handl_aicac_log_plugin',
			__( 'All plugins', 'handl-ai-connector-access-control' ),
			__( 'Filter by plugin', 'handl-ai-connector-access-control' ),
			$filters['plugin'],
			$filter_options['plugin']
		);
		submit_button( __( 'Filter', 'handl-ai-connector-access-control' ), '', 'filter_action', false );
		if ( $this->log_filters_active( $filters ) ) {
			echo ' <a class="button" href="' . esc_url( $base_url ) . '">' . esc_html__( 'Clear filters', 'handl-ai-connector-access-control' ) . '</a>';
		}
		echo '</div>';
		echo '<br class="clear" />';
		echo '</div>';
		echo '</form>';
		echo '</div>';
	}

	/**
	 * @param array<string,string> $options
	 */
	private function render_log_filter_select(
		string $id,
		string $name,
		string $all_label,
		string $screen_reader_label,
		string $current,
		array $options
	): void {
		echo '<label for="' . esc_attr( $id ) . '" class="screen-reader-text">' . esc_html( $screen_reader_label ) . '</label>';
		echo '<select id="' . esc_attr( $id ) . '" name="' . esc_attr( $name ) . '">';
		$this->render_option( '', $current, $all_label );
		foreach ( $options as $value => $label ) {
			$this->render_option( (string) $value, $current, (string) $label );
		}
		echo '</select> ';
	}

	/**
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $filters
	 */
	private function render_log_filter_hiddens( array $filters ): void {
		foreach ( $this->log_filters_to_query_args( $filters ) as $key => $value ) {
			echo '<input type="hidden" name="' . esc_attr( $key ) . '" value="' . esc_attr( $value ) . '" />';
		}
	}

	/**
	 * @param array<string,mixed> $row
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $filters
	 */
	private function log_row_matches_filters( array $row, array $filters ): bool {
		return Audit_Export::row_matches_filters( $row, $filters );
	}

	/**
	 * Human phrase for retention mode used in Insights / Activity meta lines.
	 *
	 * @param array<string,mixed> $policy
	 */
	private function retention_mode_phrase( array $policy ): string {
		$max_age = Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null );
		if ( null === $max_age ) {
			return __( 'entry limit; no time limit', 'handl-ai-connector-access-control' );
		}

		return sprintf(
			/* translators: %d: maximum log age in days */
			__( 'entry limit plus %d-day time limit; stricter limit wins', 'handl-ai-connector-access-control' ),
			$max_age
		);
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private function get_log_row_field( array $row, string $field ): string {
		return Audit_Export::row_field( $row, $field );
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private function get_log_row_model( array $row ): string {
		return Audit_Export::row_model( $row );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private function render_logging_settings( array $policy ): void {
		$audit_only  = ! empty( $policy['audit_only'] );
		$log_enabled = ! empty( $policy['log_enabled'] );
		$log_limit   = (int) ( $policy['log_limit'] ?? 200 );
		$max_age     = Policy::sanitize_log_max_age_days( $policy['log_max_age_days'] ?? null );
		$max_age_val = null === $max_age ? '' : (string) $max_age;

		echo '<p class="description" style="max-width:52em;margin-bottom:1em;">';
		echo esc_html__( 'Use this tab to see AI Client and direct AI HTTP activity. Learn mode logs every call without blocking it. Manage enforcement on the Rules tab.', 'handl-ai-connector-access-control' );
		echo '</p>';

		echo '<table class="form-table" role="presentation">';
		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Learn mode', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<label><input type="checkbox" name="handl_aicac_audit_only" value="1" ' . checked( $audit_only, true, false ) . ' /> ';
		echo esc_html__( 'Log every call without blocking it (recommended while you identify plugins)', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'See which plugins use the AI Client and what your rules would do. Set Allow or Deny here or on the Rules tab, then turn off Learn mode to enforce the rules.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td>';
		echo '</tr>';

		if ( ! $audit_only ) {
			echo '<tr>';
			echo '<th scope="row">' . esc_html__( 'Log calls', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<td>';
			echo '<label><input type="checkbox" name="handl_aicac_log_enabled" value="1" ' . checked( $log_enabled, true, false ) . ' /> ';
			echo esc_html__( 'Log calls while enforcing rules', 'handl-ai-connector-access-control' ) . '</label>';
			echo '<p class="description">' . esc_html__( 'Keep an activity trail while rules are enforced. The log is stored in your WordPress database. Optional emails and webhooks are controlled separately below.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td>';
			echo '</tr>';
		} else {
			echo '<tr class="handl-aicac-log-implied">';
			echo '<th scope="row">' . esc_html__( 'Log calls', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<td><p class="description" style="margin:0;">' . esc_html__( 'On automatically while learn mode is active.', 'handl-ai-connector-access-control' ) . '</p></td>';
			echo '</tr>';
		}

		echo '<tr>';
		echo '<th scope="row"><label for="handl-aicac-log-limit">' . esc_html__( 'Keep this many log entries', 'handl-ai-connector-access-control' ) . '</label></th>';
		echo '<td>';
		echo '<input type="number" id="handl-aicac-log-limit" name="handl_aicac_log_limit" value="' . esc_attr( (string) $log_limit ) . '" min="20" max="1000" step="1" class="small-text" />';
		echo ' <span class="description">' . esc_html__( 'Choose 20 to 1,000. Oldest entries are removed when the limit is reached.', 'handl-ai-connector-access-control' ) . '</span>';
		echo '</td>';
		echo '</tr>';

		echo '<tr>';
		echo '<th scope="row"><label for="handl-aicac-log-max-age-days">' . esc_html__( 'Delete log entries older than (days)', 'handl-ai-connector-access-control' ) . '</label></th>';
		echo '<td>';
		echo '<input type="number" id="handl-aicac-log-max-age-days" name="handl_aicac_log_max_age_days" value="' . esc_attr( $max_age_val ) . '" min="1" max="3650" step="1" class="small-text" placeholder="" />';
		echo ' <span class="description">' . esc_html__( 'Optional. Leave blank for no time limit. When set, older entries are removed the next time the log is read or updated. The entry limit still applies, and the stricter limit wins.', 'handl-ai-connector-access-control' ) . '</span>';
		echo '</td>';
		echo '</tr>';

		// F3: denial alerts + AICAC-SHADOW-ALERT shadow-AI observe emails.
		$alert_on      = ! empty( $policy['alert_on_deny'] );
		$alert_shadow  = ! empty( $policy['alert_on_shadow'] );
		$alert_mode    = Alerts::sanitize_mode( $policy['alert_mode'] ?? 'immediate' );
		$alert_email   = Alerts::sanitize_email( $policy['alert_email'] ?? '' );
		$alert_hook    = Alerts::sanitize_webhook_url( $policy['alert_webhook_url'] ?? '' );
		$pending       = count( Alerts::pending_digest_rows() );

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Blocked-call email alerts', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<label><input type="checkbox" name="handl_aicac_alert_on_deny" value="1" ' . checked( $alert_on, true, false ) . ' /> ';
		echo esc_html__( 'Email me when a prompt is blocked. Alerts are sent only while rules are enforced, not in Learn mode.', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'Emails identify HandL AI Access as the sender, so you can distinguish a blocked call from a plugin error.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p style="margin-top:8px;"><label for="handl-aicac-alert-email">' . esc_html__( 'Recipient email', 'handl-ai-connector-access-control' ) . '</label><br />';
		echo '<input type="email" class="regular-text" id="handl-aicac-alert-email" name="handl_aicac_alert_email" value="' . esc_attr( $alert_email ) . '" placeholder="' . esc_attr( (string) get_option( 'admin_email' ) ) . '" />';
		echo ' ';
		submit_button(
			__( 'Send test email', 'handl-ai-connector-access-control' ),
			'secondary',
			'submit',
			false,
			array(
				'form'  => 'handl-aicac-test-email-denial',
				'id'    => 'handl-aicac-send-test-denial-email',
			)
		);
		echo '<br /><span class="description">' . esc_html__( 'Leave empty to use the site admin email. Test emails use the saved address, so save changes before testing.', 'handl-ai-connector-access-control' ) . '</span></p>';
		echo '<p style="margin-top:8px;"><label for="handl-aicac-alert-webhook">' . esc_html__( 'Webhook URL', 'handl-ai-connector-access-control' ) . '</label><br />';
		echo '<input type="url" class="regular-text" id="handl-aicac-alert-webhook" name="handl_aicac_alert_webhook_url" value="' . esc_attr( $alert_hook ) . '" placeholder="https://" pattern="https?://.*" inputmode="url" autocomplete="off" />';
echo '<br /><span class="description">' . esc_html__( 'Optional. Send the same blocked-call alert as JSON to an http:// or https:// webhook, such as Slack or Teams. It follows the email schedule and rate limit. It includes request paths, but not prompt text or user identity. Direct AI connection alerts are email-only and are not sent to this webhook. Leave blank to disable the webhook.', 'handl-ai-connector-access-control' ) . '</span></p>';
		echo '<p style="margin-top:8px;">';
		echo '<label><input type="radio" name="handl_aicac_alert_mode" value="immediate" ' . checked( $alert_mode, 'immediate', false ) . ' /> ';
		echo esc_html__( 'Send immediately (maximum 20 per hour; extra alerts retry later)', 'handl-ai-connector-access-control' ) . '</label><br />';
		echo '<label><input type="radio" name="handl_aicac_alert_mode" value="digest" ' . checked( $alert_mode, 'digest', false ) . ' /> ';
		echo esc_html__( 'Send an hourly summary', 'handl-ai-connector-access-control' ) . '</label>';
		echo '</p>';
		if ( $pending > 0 ) {
			echo '<p class="description"><strong>' . esc_html(
				sprintf(
					/* translators: %d: queued alert count */
					__( 'Queued for the next summary: %d', 'handl-ai-connector-access-control' ),
					$pending
				)
			) . '</strong></p>';
		}
		echo '</td>';
		echo '</tr>';

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Direct AI connection alerts', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<label><input type="checkbox" name="handl_aicac_alert_on_shadow" value="1" ' . checked( $alert_shadow, true, false ) . ' /> ';
		echo esc_html__( 'Send an email when a plugin connects directly to an AI provider outside the AI Client', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'Off by default. Requires logging or learn mode. Sends one alert for each plugin and AI provider domain while that activity remains in the log. These alerts do not block requests. Uses the same email address and delivery schedule as blocked-request alerts.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td>';
		echo '</tr>';

		// F7: weekly aggregate report email (Dashboard mailed).
		// Checked-but-inactive when no explicit preference: always render checked; delivery is
		// gated by logging/learn (is_active). Provenance field records what the operator saw.
		$weekly_on = ! empty( $policy['weekly_report_enabled'] );
		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Weekly activity summary', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		// Hidden provenance: "what the UI presented as the untouched state" (board re-tip).
		echo '<input type="hidden" name="handl_aicac_weekly_report_rendered" value="' . ( $weekly_on ? '1' : '0' ) . '" />';
		echo '<label><input type="checkbox" name="handl_aicac_weekly_report_enabled" value="1" ' . checked( $weekly_on, true, false ) . ' /> ';
		echo esc_html__( 'Email a weekly summary of AI coverage, blocked calls, estimated spend, and model-routing activity', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'Selected by default. It sends only while logging or Learn mode is on. Clear the checkbox and save to turn it off.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p class="description">' . esc_html__( 'Uses the blocked-call alert recipient, or the site admin email. Includes totals and plugin names only. It does not include prompt text, user names, or request paths. The email shows the date range it covers.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p style="margin-top:8px;">';
		submit_button(
			__( 'Send test email', 'handl-ai-connector-access-control' ),
			'secondary',
			'submit',
			false,
			array(
				'form' => 'handl-aicac-test-email-weekly',
				'id'   => 'handl-aicac-send-test-weekly-email',
			)
		);
		echo ' <span class="description">' . esc_html__( 'Sends a labeled test weekly report to the saved recipient, or the site admin email. Limited to one test email per minute.', 'handl-ai-connector-access-control' ) . '</span>';
		echo '</p>';
		echo '</td>';
		echo '</tr>';

		// F3 / AICAC-24: estimated $ rates (observability only).
		$rates          = Cost::fallback_rates_from_policy( $policy );
		$provider_rates = Cost::sanitize_provider_rates( $policy['est_usd_provider_rates'] ?? array() );
		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Estimated spend rates', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<p class="description" style="margin-top:0;">' . esc_html__( 'Enter approximate USD prices per 1 million tokens to calculate the Estimated $ column. These values are for estimates only, not billing or enforcement.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p><strong>' . esc_html__( 'Default rates', 'handl-ai-connector-access-control' ) . '</strong></p>';
		echo '<label for="handl-aicac-est-in">' . esc_html__( 'Input tokens ($ per 1M)', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<input type="number" step="0.01" min="0" max="10000" class="small-text" id="handl-aicac-est-in" name="handl_aicac_est_usd_input_per_m" value="' . esc_attr( (string) $rates['input_per_m'] ) . '" /> ';
		echo '<label for="handl-aicac-est-out" style="margin-left:12px;">' . esc_html__( 'Output tokens ($ per 1M)', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<input type="number" step="0.01" min="0" max="10000" class="small-text" id="handl-aicac-est-out" name="handl_aicac_est_usd_output_per_m" value="' . esc_attr( (string) $rates['output_per_m'] ) . '" />';
		echo '<p class="description">' . esc_html__( 'Used when the provider is missing or unknown, or has no custom rates below.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p style="margin-top:12px;"><strong>' . esc_html__( 'Rates by provider (optional)', 'handl-ai-connector-access-control' ) . '</strong></p>';
		echo '<p class="description">' . esc_html__( 'Leave both fields blank to use the default rates for that provider. Estimates only, not billing.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<table class="widefat striped" style="max-width:36em;"><thead><tr>';
		echo '<th>' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Input $ per 1M tokens', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Output $ per 1M tokens', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';
		foreach ( Cost::KNOWN_PROVIDERS as $provider_id ) {
			$row_in  = isset( $provider_rates[ $provider_id ] ) ? (string) $provider_rates[ $provider_id ]['input_per_m'] : '';
			$row_out = isset( $provider_rates[ $provider_id ] ) ? (string) $provider_rates[ $provider_id ]['output_per_m'] : '';
			$in_id   = 'handl-aicac-est-prov-' . $provider_id . '-in';
			$out_id  = 'handl-aicac-est-prov-' . $provider_id . '-out';
			echo '<tr>';
			echo '<td><code>' . esc_html( $provider_id ) . '</code></td>';
			echo '<td><label class="screen-reader-text" for="' . esc_attr( $in_id ) . '">' . esc_html(
				sprintf(
					/* translators: %s: provider id */
					__( '%s input $ per 1M tokens', 'handl-ai-connector-access-control' ),
					$provider_id
				)
			) . '</label>';
			echo '<input type="number" step="0.01" min="0" max="10000" class="small-text" id="' . esc_attr( $in_id ) . '" name="handl_aicac_est_usd_provider[' . esc_attr( $provider_id ) . '][input]" value="' . esc_attr( $row_in ) . '" placeholder="' . esc_attr__( 'uses default rates', 'handl-ai-connector-access-control' ) . '" /></td>';
			echo '<td><label class="screen-reader-text" for="' . esc_attr( $out_id ) . '">' . esc_html(
				sprintf(
					/* translators: %s: provider id */
					__( '%s output $ per 1M tokens', 'handl-ai-connector-access-control' ),
					$provider_id
				)
			) . '</label>';
			echo '<input type="number" step="0.01" min="0" max="10000" class="small-text" id="' . esc_attr( $out_id ) . '" name="handl_aicac_est_usd_provider[' . esc_attr( $provider_id ) . '][output]" value="' . esc_attr( $row_out ) . '" placeholder="' . esc_attr__( 'uses default rates', 'handl-ai-connector-access-control' ) . '" /></td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
		echo '</td>';
		echo '</tr>';

		// S-103: estimated-spend threshold alerts (opt-in, empty = off).
		$site_threshold    = Spend_Threshold::sanitize_threshold( $policy['spend_threshold_site'] ?? null );
		$plugin_thresholds = Spend_Threshold::sanitize_plugin_thresholds( $policy['spend_threshold_plugins'] ?? array() );
		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Estimated spend alerts', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<p class="description" style="margin-top:0;">' . esc_html__( 'Sends an email when estimated spend in the saved activity log crosses a threshold. After the estimate drops below that threshold, another crossing can trigger a new alert. Each threshold can alert at most once every 24 hours. Leave a field blank to turn that alert off. Uses the same email address as blocked-call alerts. Amounts are estimates, not billing, and alerts do not block calls.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p><label for="handl-aicac-spend-threshold-site">' . esc_html__( 'Site-wide threshold (USD)', 'handl-ai-connector-access-control' ) . '</label><br />';
		echo '<input type="number" step="0.01" min="0" max="1000000" class="small-text" id="handl-aicac-spend-threshold-site" name="handl_aicac_spend_threshold_site" value="' . esc_attr( null === $site_threshold ? '' : (string) $site_threshold ) . '" placeholder="' . esc_attr__( 'Off', 'handl-ai-connector-access-control' ) . '" /></p>';

		echo '<p style="margin-top:12px;"><strong>' . esc_html__( 'Plugin thresholds (optional)', 'handl-ai-connector-access-control' ) . '</strong></p>';
		echo '<p class="description">' . esc_html__( 'Leave a field blank to turn that plugin’s alert off. Each plugin sends a separate email when its estimate crosses the threshold.', 'handl-ai-connector-access-control' ) . '</p>';
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins_for_threshold = get_plugins();
		echo '<div class="handl-aicac-spend-threshold-plugins" style="max-height:220px;overflow:auto;border:1px solid #c3c4c7;padding:8px;max-width:36em;background:#fff;">';
		if ( empty( $plugins_for_threshold ) ) {
			echo '<p class="description">' . esc_html__( 'No installed plugins found.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped" style="margin:0;"><thead><tr>';
			echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Threshold (USD)', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $plugins_for_threshold as $basename => $meta ) {
				$name  = isset( $meta['Name'] ) ? (string) $meta['Name'] : (string) $basename;
				$val   = isset( $plugin_thresholds[ $basename ] ) ? (string) $plugin_thresholds[ $basename ] : '';
				$field = 'handl-aicac-spend-th-' . md5( (string) $basename );
				echo '<tr>';
				echo '<td><label for="' . esc_attr( $field ) . '">' . esc_html( $name ) . '</label><br /><code style="font-size:11px;">' . esc_html( (string) $basename ) . '</code></td>';
				echo '<td><input type="number" step="0.01" min="0" max="1000000" class="small-text" id="' . esc_attr( $field ) . '" name="handl_aicac_spend_threshold_plugins[' . esc_attr( (string) $basename ) . ']" value="' . esc_attr( $val ) . '" placeholder="' . esc_attr__( 'Off', 'handl-ai-connector-access-control' ) . '" /></td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';
		echo '</td>';
		echo '</tr>';

		// AICAC-ANOMALY: usage spike alerts (opt-in, default off).
		$anomaly_on       = ! empty( $policy['anomaly_alert_enabled'] );
		$anomaly_mult     = Anomaly::sanitize_multiplier( $policy['anomaly_multiplier'] ?? Anomaly::DEFAULT_MULTIPLIER );
		$anomaly_floor_c  = Anomaly::sanitize_floor_calls( $policy['anomaly_floor_calls'] ?? Anomaly::DEFAULT_FLOOR_CALLS );
		$anomaly_floor_s  = Anomaly::sanitize_floor_spend( $policy['anomaly_floor_spend'] ?? Anomaly::DEFAULT_FLOOR_SPEND );
		$anomaly_notice   = Anomaly::degradation_notice( $policy );
		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Usage spike alerts', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<label><input type="checkbox" name="handl_aicac_anomaly_alert_enabled" value="1" ' . checked( $anomaly_on, true, false ) . ' /> ';
		echo esc_html__( 'Email me when a plugin’s AI usage spikes', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'Off by default. Compares each plugin’s AI Client calls and estimated spend today with its daily average over the previous 7 days. Uses the blocked-call alert email address and optional webhook. Alerts do not block calls.', 'handl-ai-connector-access-control' ) . '</p>';
		if ( '' !== $anomaly_notice ) {
			echo '<p class="description notice notice-warning inline" style="padding:8px;"><strong>' . esc_html( $anomaly_notice ) . '</strong></p>';
		}
		echo '<p><label for="handl-aicac-anomaly-multiplier">' . esc_html__( 'Alert multiplier', 'handl-ai-connector-access-control' ) . '</label><br />';
		echo '<input type="number" step="0.1" min="1.5" max="50" class="small-text" id="handl-aicac-anomaly-multiplier" name="handl_aicac_anomaly_multiplier" value="' . esc_attr( (string) $anomaly_mult ) . '" /> ';
		echo '<span class="description">' . esc_html__( 'Default: 3. An alert can fire when today’s usage reaches three times the recent daily average.', 'handl-ai-connector-access-control' ) . '</span></p>';
		echo '<p><label for="handl-aicac-anomaly-floor-calls">' . esc_html__( 'Minimum calls before an alert', 'handl-ai-connector-access-control' ) . '</label><br />';
		echo '<input type="number" step="1" min="1" max="100000" class="small-text" id="handl-aicac-anomaly-floor-calls" name="handl_aicac_anomaly_floor_calls" value="' . esc_attr( (string) $anomaly_floor_c ) . '" /> ';
		echo '<span class="description">' . esc_html__( 'Default: 20. Call-volume alerts do not fire until a plugin reaches this many calls today.', 'handl-ai-connector-access-control' ) . '</span></p>';
		echo '<p><label for="handl-aicac-anomaly-floor-spend">' . esc_html__( 'Minimum estimated spend before an alert (USD)', 'handl-ai-connector-access-control' ) . '</label><br />';
		echo '<input type="number" step="0.01" min="0.01" max="1000000" class="small-text" id="handl-aicac-anomaly-floor-spend" name="handl_aicac_anomaly_floor_spend" value="' . esc_attr( (string) $anomaly_floor_s ) . '" /> ';
		echo '<span class="description">' . esc_html__( 'Default: $1.00. Spend alerts do not fire until a plugin reaches this estimated amount today.', 'handl-ai-connector-access-control' ) . '</span></p>';
		echo '</td>';
		echo '</tr>';

		echo '</table>';
	}

	private function handle_save_rules(): void {
		$this->require_admin_mutation( 'handl_aicac_save_policy' );

		$policy = $this->build_rules_policy_from_post( Policy::get_policy() );
		Policy::save_policy( $policy );
	}

	/**
	 * AICAC-TEMP-ALLOW: one-click renew of an expired temporary allow (+7 days).
	 */
	private function handle_renew_temp_allow(): void {
		$this->require_admin_mutation( 'handl_aicac_renew_temp_allow' );

		$plugin = isset( $_POST['handl_aicac_renew_plugin'] )
			? sanitize_text_field( wp_unslash( (string) $_POST['handl_aicac_renew_plugin'] ) )
			: '';
		if ( '' === $plugin ) {
			return;
		}

		$updated = Temp_Allow::renew_allow_on_policy( Policy::get_policy(), $plugin );
		if ( false === $updated ) {
			return;
		}
		Policy::save_policy( $updated );

		$redirect = add_query_arg(
			array(
				'page'                => 'handl-ai-connector-access-control',
				'handl_aicac_tab'     => 'rules',
				'handl_aicac_renewed' => '1',
			),
			admin_url( 'options-general.php' )
		);
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Build a rules-tab policy from POST without saving (used by save + AICAC-SIM).
	 *
	 * @param array<string,mixed> $base Starting policy (usually saved).
	 * @return array<string,mixed>
	 */
	/**
	 * Build a policy array from Rules-tab POST fields.
	 *
	 * @param array<string,mixed> $base          Saved policy used as the starting point.
	 * @param bool                $merge_missing When true (simulator), keep base plugin /
	 *                                           operation / force rules for keys absent from
	 *                                           POST. Needed when max_input_vars truncates the
	 *                                           matrix so a partial POST does not wipe rules.
	 *                                           Save keeps false: empty selects mean "Default".
	 * @return array<string,mixed>
	 */
	private function build_rules_policy_from_post( array $base, bool $merge_missing = false ): array {
		$policy = $base;

		$posted_default = filter_input( INPUT_POST, 'handl_aicac_default', FILTER_UNSAFE_RAW );
		if ( null !== $posted_default && false !== $posted_default ) {
			$policy['default'] = ( 'deny' === sanitize_text_field( (string) $posted_default ) ) ? 'deny' : 'allow';
		}

		$posted_unknown = filter_input( INPUT_POST, 'handl_aicac_unknown_operation', FILTER_UNSAFE_RAW );
		if ( null !== $posted_unknown && false !== $posted_unknown ) {
			$policy['unknown_operation'] = Policy::sanitize_unknown_operation( $posted_unknown );
		}

		$rules        = $merge_missing && isset( $base['plugins'] ) && is_array( $base['plugins'] )
			? $base['plugins']
			: array();
		$posted_rules = filter_input( INPUT_POST, 'handl_aicac_rule', FILTER_UNSAFE_RAW, FILTER_REQUIRE_ARRAY );
		if ( is_array( $posted_rules ) ) {
			if ( $merge_missing ) {
				foreach ( $posted_rules as $basename => $rule ) {
					$basename = sanitize_text_field( (string) $basename );
					$rule     = sanitize_text_field( (string) $rule );
					if ( '' === $basename ) {
						continue;
					}
					if ( 'allow' === $rule || 'deny' === $rule ) {
						$rules[ $basename ] = $rule;
					} else {
						unset( $rules[ $basename ] );
					}
				}
			} else {
				$rules = array();
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
		} elseif ( ! $merge_missing ) {
			$rules = array();
		}
		$policy['plugins'] = $rules;

		// AICAC-TEMP-ALLOW: optional expiry presets for Allow rules.
		$expires        = $merge_missing && isset( $base['plugin_expires'] ) && is_array( $base['plugin_expires'] )
			? Temp_Allow::sanitize_plugin_expires( $base['plugin_expires'] )
			: array();
		$posted_presets = filter_input( INPUT_POST, 'handl_aicac_expire_preset', FILTER_UNSAFE_RAW, FILTER_REQUIRE_ARRAY );
		$posted_dates   = filter_input( INPUT_POST, 'handl_aicac_expire_date', FILTER_UNSAFE_RAW, FILTER_REQUIRE_ARRAY );
		if ( ! is_array( $posted_presets ) ) {
			$posted_presets = array();
		}
		if ( ! is_array( $posted_dates ) ) {
			$posted_dates = array();
		}
		if ( ! $merge_missing ) {
			$expires = array();
		}
		$now = time();
		foreach ( $rules as $basename => $rule ) {
			if ( 'allow' !== (string) $rule ) {
				unset( $expires[ $basename ] );
				continue;
			}
			if ( ! array_key_exists( $basename, $posted_presets ) ) {
				if ( ! $merge_missing ) {
					unset( $expires[ $basename ] );
				}
				continue;
			}
			$ts = Temp_Allow::resolve_posted_expiry(
				$posted_presets[ $basename ] ?? '',
				$posted_dates[ $basename ] ?? '',
				$now
			);
			if ( null === $ts ) {
				unset( $expires[ $basename ] );
			} else {
				$expires[ $basename ] = $ts;
			}
		}
		$policy['plugin_expires'] = $expires;

		$posted_ops = filter_input( INPUT_POST, 'handl_aicac_operation', FILTER_UNSAFE_RAW, FILTER_REQUIRE_ARRAY );
		if ( is_array( $posted_ops ) ) {
			$sanitized_ops = Policy::sanitize_operations( $posted_ops );
			if ( $merge_missing ) {
				$base_ops = isset( $base['operations'] ) && is_array( $base['operations'] ) ? $base['operations'] : array();
				$policy['operations'] = array_replace_recursive( $base_ops, $sanitized_ops );
			} else {
				$policy['operations'] = $sanitized_ops;
			}
		} elseif ( ! $merge_missing ) {
			$policy['operations'] = array();
		}

		// Accept new field name; also read legacy POST key during transition.
		$posted_tools = filter_input( INPUT_POST, 'handl_aicac_denied_tools', FILTER_UNSAFE_RAW );
		if ( null === $posted_tools || false === $posted_tools || '' === $posted_tools ) {
			$posted_tools = filter_input( INPUT_POST, 'handl_aicac_denied_abilities', FILTER_UNSAFE_RAW );
		}
		if ( null !== $posted_tools && false !== $posted_tools ) {
			$policy['denied_tools'] = Policy::sanitize_denied_tools( (string) $posted_tools );
		}

		$this->apply_kill_switch_settings_from_post( $policy );
		$this->apply_shadow_block_settings_from_post( $policy );
		$this->apply_role_gate_settings_from_post( $policy );
		$this->apply_model_force_settings_from_post( $policy );

		return $policy;
	}

	/**
	 * AICAC-SIM: dry-run draft Rules-tab settings against Policy::evaluate (no save, no outbound).
	 */
	private function handle_simulate_policy(): void {
		$this->require_admin_mutation( 'handl_aicac_save_policy' );

		$saved = Policy::get_policy();
		$draft = $this->build_rules_policy_from_post( $saved, true );

		$mode = isset( $_POST['handl_aicac_sim_mode'] )
			? sanitize_key( wp_unslash( (string) $_POST['handl_aicac_sim_mode'] ) )
			: 'hypothetical';
		if ( 'replay' !== $mode ) {
			$mode = 'hypothetical';
		}

		$result = array(
			'mode'  => $mode,
			'draft' => true,
		);

		if ( 'hypothetical' === $mode ) {
			$plugin = isset( $_POST['handl_aicac_sim_plugin'] )
				? sanitize_text_field( wp_unslash( (string) $_POST['handl_aicac_sim_plugin'] ) )
				: '';
			$operation = isset( $_POST['handl_aicac_sim_operation'] )
				? sanitize_text_field( wp_unslash( (string) $_POST['handl_aicac_sim_operation'] ) )
				: '';
			$armed_raw = isset( $_POST['handl_aicac_sim_tools'] )
				? wp_unslash( (string) $_POST['handl_aicac_sim_tools'] )
				: '';
			$armed_raw = str_replace( array( ',', ';' ), "\n", $armed_raw );
			$armed     = Policy::sanitize_denied_tools( $armed_raw );

			$family = '' !== $operation ? Operations::family_from_operation( $operation ) : null;
			$eval   = Policy_Simulator::evaluate_call(
				$draft,
				'' !== $plugin ? $plugin : null,
				'' !== $operation ? $operation : null,
				$armed,
				$family
			);
			$verdict = Policy_Simulator::verdict_from_eval( $eval );

			$result['plugin']    = $plugin;
			$result['operation'] = $operation;
			$result['family']    = is_string( $family ) ? $family : '';
			$result['eval']      = $eval;
			$result['verdict']   = $verdict;
		} else {
			$limit = Policy_Simulator::sanitize_replay_limit(
				isset( $_POST['handl_aicac_sim_limit'] )
					? wp_unslash( (string) $_POST['handl_aicac_sim_limit'] )
					: Policy_Simulator::DEFAULT_REPLAY_LIMIT
			);
			$log = Policy::get_retained_log();
			$diff = Policy_Simulator::replay_diff(
				$saved,
				$draft,
				$log,
				$limit,
				array(
					'log_enabled'      => ! empty( $saved['log_enabled'] ),
					'audit_only'       => ! empty( $saved['audit_only'] ),
					'log_max_age_days' => $saved['log_max_age_days'] ?? null,
					'log_limit'        => $saved['log_limit'] ?? null,
				)
			);
			$result['limit'] = $limit;
			$result['diff']  = $diff;
		}

		$this->sim_result = $result;
	}

	/**
	 * Rules-tab "Test this policy" panel (AICAC-SIM).
	 *
	 * @param array<string,mixed>      $policy
	 * @param array<string,array|mixed> $plugins
	 * @param array<int,mixed>         $log
	 */
	private function render_policy_simulator_panel( array $policy, array $plugins, array $log, string $form_id ): void {
		$mode = is_array( $this->sim_result ) ? (string) ( $this->sim_result['mode'] ?? 'hypothetical' ) : 'hypothetical';
		if ( 'replay' !== $mode ) {
			$mode = 'hypothetical';
		}

		$sel_plugin = is_array( $this->sim_result ) ? (string) ( $this->sim_result['plugin'] ?? '' ) : '';
		$sel_op     = is_array( $this->sim_result ) ? (string) ( $this->sim_result['operation'] ?? '' ) : 'generate_text';
		$sel_limit  = is_array( $this->sim_result ) && isset( $this->sim_result['limit'] )
			? (int) $this->sim_result['limit']
			: Policy_Simulator::DEFAULT_REPLAY_LIMIT;

		$ops = array(
			'generate_text'                     => __( 'Text generation (generate_text)', 'handl-ai-connector-access-control' ),
			'generate_image'                    => __( 'Image generation (generate_image)', 'handl-ai-connector-access-control' ),
			'generate_speech'                   => __( 'Speech generation (generate_speech)', 'handl-ai-connector-access-control' ),
			'convert_text_to_speech'            => __( 'Text to speech (convert_text_to_speech)', 'handl-ai-connector-access-control' ),
			'generate_video'                    => __( 'Video generation (generate_video)', 'handl-ai-connector-access-control' ),
			'is_supported_for_music_generation' => __( 'Other or unknown operation (for example, music)', 'handl-ai-connector-access-control' ),
		);

		echo '<div class="handl-aicac-sim-panel" id="handl-aicac-sim-panel" data-rules-form="' . esc_attr( $form_id ) . '">';
		echo '<h2>' . esc_html__( 'Test this policy', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Preview how the rules on this screen would handle AI Client calls before you save. No AI call is sent, and the test uses the same decision process as live traffic.', 'handl-ai-connector-access-control' ) . '</p>';

		// Panel is rendered inside the rules <form> ($form_id); controls are native
		// descendants (no form=) so Run test includes handl_aicac_action=simulate_policy
		// under both native clicks and shared Chrome automation.

		echo '<fieldset class="handl-aicac-sim-mode">';
		echo '<legend class="screen-reader-text">' . esc_html__( 'Test mode', 'handl-ai-connector-access-control' ) . '</legend>';
		echo '<label><input type="radio" name="handl_aicac_sim_mode" value="hypothetical" ' . checked( $mode, 'hypothetical', false ) . ' /> ';
		echo esc_html__( 'Test a sample call', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<label><input type="radio" name="handl_aicac_sim_mode" value="replay" ' . checked( $mode, 'replay', false ) . ' /> ';
		echo esc_html__( 'Replay saved activity', 'handl-ai-connector-access-control' ) . '</label>';
		echo '</fieldset>';

		echo '<table class="form-table handl-aicac-sim-fields" role="presentation">';
		echo '<tr class="handl-aicac-sim-hyp">';
		echo '<th scope="row"><label for="handl-aicac-sim-plugin">' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</label></th>';
		echo '<td><select name="handl_aicac_sim_plugin" id="handl-aicac-sim-plugin">';
		echo '<option value="">' . esc_html__( 'Unknown or no plugin', 'handl-ai-connector-access-control' ) . '</option>';
		foreach ( $plugins as $basename => $meta ) {
			$basename = (string) $basename;
			$label    = is_array( $meta ) && isset( $meta['Name'] ) ? (string) $meta['Name'] : $basename;
			echo '<option value="' . esc_attr( $basename ) . '" ' . selected( $sel_plugin, $basename, false ) . '>' . esc_html( $label ) . '</option>';
		}
		echo '</select></td></tr>';

		echo '<tr class="handl-aicac-sim-hyp">';
		echo '<th scope="row"><label for="handl-aicac-sim-operation">' . esc_html__( 'Operation', 'handl-ai-connector-access-control' ) . '</label></th>';
		echo '<td><select name="handl_aicac_sim_operation" id="handl-aicac-sim-operation">';
		foreach ( $ops as $op_id => $op_label ) {
			echo '<option value="' . esc_attr( $op_id ) . '" ' . selected( $sel_op, $op_id, false ) . '>' . esc_html( $op_label ) . '</option>';
		}
		echo '</select>';
		echo '<p class="description">' . esc_html__( 'AI type rules use the operation family, such as Text or Image.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td></tr>';

		echo '<tr class="handl-aicac-sim-hyp">';
		echo '<th scope="row"><label for="handl-aicac-sim-tools">' . esc_html__( 'Tools offered to the AI (optional)', 'handl-ai-connector-access-control' ) . '</label></th>';
		echo '<td><input type="text" class="regular-text code" name="handl_aicac_sim_tools" id="handl-aicac-sim-tools" value="" placeholder="namespace/tool" />';
		echo '<p class="description">' . esc_html__( 'Enter tool names separated by commas or new lines. Use this to test rules that block specific tools.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td></tr>';

		echo '<tr class="handl-aicac-sim-replay">';
		echo '<th scope="row"><label for="handl-aicac-sim-limit">' . esc_html__( 'Calls to replay', 'handl-ai-connector-access-control' ) . '</label></th>';
		echo '<td><input type="number" class="small-text" min="1" max="1000" name="handl_aicac_sim_limit" id="handl-aicac-sim-limit" value="' . esc_attr( (string) $sel_limit ) . '" />';
		echo '<p class="description">' . esc_html__( 'Replays the newest saved AI Client calls. Direct connections outside the AI Client are skipped because these rules do not control them.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td></tr>';
		echo '</table>';

		echo '<p>';
		echo '<button type="submit" class="button button-secondary" name="handl_aicac_action" value="simulate_policy" id="handl-aicac-sim-run" data-aicac-action="simulate_policy">';
		echo esc_html__( 'Run test', 'handl-ai-connector-access-control' );
		echo '</button>';
		echo ' <span class="description">' . esc_html__( 'Your rules will not be saved.', 'handl-ai-connector-access-control' ) . '</span>';
		echo '</p>';

		if ( is_array( $this->sim_result ) ) {
			$this->render_policy_simulator_result( $this->sim_result, $plugins );
		}

		echo '</div>';
	}

	/**
	 * @param array<string,mixed>       $result
	 * @param array<string,array|mixed> $plugins
	 */
	private function render_policy_simulator_result( array $result, array $plugins ): void {
		$mode = (string) ( $result['mode'] ?? '' );
		echo '<div class="handl-aicac-sim-result notice notice-info inline" role="status">';

		if ( 'hypothetical' === $mode ) {
			$verdict = is_array( $result['verdict'] ?? null ) ? $result['verdict'] : array();
			$chip    = (string) ( $verdict['chip'] ?? '' );
			$allowed = ! empty( $verdict['allowed'] );
			$class   = $allowed ? 'handl-aicac-badge--allow' : 'handl-aicac-badge--deny';
			echo '<p><strong>' . esc_html__( 'Sample call result', 'handl-ai-connector-access-control' ) . ':</strong> ';
			echo '<span class="handl-aicac-badge ' . esc_attr( $class ) . '">' . esc_html( $chip ) . '</span></p>';
			$plugin = (string) ( $result['plugin'] ?? '' );
			$op     = (string) ( $result['operation'] ?? '' );
			$pname  = $plugin;
			if ( $plugin && isset( $plugins[ $plugin ]['Name'] ) ) {
				$pname = (string) $plugins[ $plugin ]['Name'];
			}
			echo '<p class="description">' . esc_html(
				sprintf(
					/* translators: 1: plugin label, 2: operation name */
					__( 'Plugin: %1$s · Operation: %2$s', 'handl-ai-connector-access-control' ),
					'' !== $pname ? $pname : __( 'Unknown', 'handl-ai-connector-access-control' ),
					'' !== $op ? $op : __( 'None', 'handl-ai-connector-access-control' )
				)
			) . '</p>';
			echo '</div>';
			return;
		}

		$diff = is_array( $result['diff'] ?? null ) ? $result['diff'] : array();
		if ( ! empty( $diff['empty'] ) ) {
			$why = (string) ( $diff['empty_reason'] ?? '' );
			echo '<p>' . esc_html( $why !== '' ? $why : __( 'No saved activity to replay.', 'handl-ai-connector-access-control' ) ) . '</p>';
			echo '</div>';
			return;
		}

		$blocked_n = (int) ( $diff['now_blocked_count'] ?? 0 );
		$allowed_n = (int) ( $diff['now_allowed_count'] ?? 0 );
		$scanned   = (int) ( $diff['scanned'] ?? 0 );
		$unchanged = (int) ( $diff['unchanged'] ?? 0 );

		echo '<p><strong>' . esc_html__( 'Replay summary', 'handl-ai-connector-access-control' ) . '</strong></p>';
		echo '<ul>';
		echo '<li>' . esc_html(
			sprintf(
				/* translators: %d: call count */
				__( 'Allowed before, blocked now: %d', 'handl-ai-connector-access-control' ),
				$blocked_n
			)
		) . '</li>';
		echo '<li>' . esc_html(
			sprintf(
				/* translators: %d: call count */
				__( 'Blocked before, allowed now: %d', 'handl-ai-connector-access-control' ),
				$allowed_n
			)
		) . '</li>';
		echo '<li>' . esc_html(
			sprintf(
				/* translators: 1: scanned count, 2: unchanged count */
				__( 'Saved calls compared: %1$d. Unchanged: %2$d.', 'handl-ai-connector-access-control' ),
				$scanned,
				$unchanged
			)
		) . '</li>';
		echo '</ul>';

		$blocked_rows = is_array( $diff['now_blocked'] ?? null ) ? $diff['now_blocked'] : array();
		$allowed_rows = is_array( $diff['now_allowed'] ?? null ) ? $diff['now_allowed'] : array();
		if ( ! empty( $blocked_rows ) ) {
			echo '<p><strong>' . esc_html__( 'Allowed before, blocked now', 'handl-ai-connector-access-control' ) . '</strong></p>';
			$this->render_sim_delta_list( $blocked_rows, $plugins );
		}
		if ( ! empty( $allowed_rows ) ) {
			echo '<p><strong>' . esc_html__( 'Blocked before, allowed now', 'handl-ai-connector-access-control' ) . '</strong></p>';
			$this->render_sim_delta_list( $allowed_rows, $plugins );
		}

		echo '</div>';
	}

	/**
	 * @param list<array{plugin?:string,operation?:string,reason?:string}> $rows
	 * @param array<string,array|mixed>                                    $plugins
	 */
	private function render_sim_delta_list( array $rows, array $plugins ): void {
		echo '<ul class="handl-aicac-sim-delta-list">';
		foreach ( $rows as $row ) {
			$plugin = (string) ( $row['plugin'] ?? '' );
			$op     = (string) ( $row['operation'] ?? '' );
			$reason = (string) ( $row['reason'] ?? '' );
			$label  = $plugin;
			if ( $plugin && isset( $plugins[ $plugin ]['Name'] ) ) {
				$label = (string) $plugins[ $plugin ]['Name'];
			}
			if ( '' === $label ) {
				$label = __( 'Unknown plugin', 'handl-ai-connector-access-control' );
			}
			$line = $label;
			if ( '' !== $op ) {
				$line .= ' · ' . $op;
			}
			if ( '' !== $reason ) {
				$line .= ' — ' . Policy_Simulator::reason_label( $reason );
			}
			echo '<li><code>' . esc_html( $line ) . '</code></li>';
		}
		echo '</ul>';
	}

	/**
	 * AICAC-BULK: set allow/deny for checked plugin rows only.
	 *
	 * Reuses handl_aicac_save_policy nonce + manage_options page gate.
	 * Does not rewrite capability-family or model-force maps.
	 */
	private function handle_bulk_plugin_rules(): void {
		$this->require_admin_mutation( 'handl_aicac_save_policy' );

		$posted_action = filter_input( INPUT_POST, 'handl_aicac_bulk_action', FILTER_UNSAFE_RAW );
		$rule          = sanitize_text_field( (string) $posted_action );
		if ( 'allow' !== $rule && 'deny' !== $rule ) {
			$this->bulk_result = array( 'status' => 'invalid' );
			return;
		}

		$posted = filter_input( INPUT_POST, 'handl_aicac_bulk_plugins', FILTER_UNSAFE_RAW, FILTER_REQUIRE_ARRAY );
		$selected = is_array( $posted ) ? $posted : array();
		if ( empty( $selected ) ) {
			$this->bulk_result = array( 'status' => 'empty' );
			return;
		}

		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$installed = function_exists( 'get_plugins' ) ? get_plugins() : array();
		if ( ! is_array( $installed ) ) {
			$installed = array();
		}

		$policy = Policy::get_policy();
		$result = Policy::apply_bulk_plugin_rules( $policy, $selected, $rule, $installed );
		if ( false === $result ) {
			$this->bulk_result = array( 'status' => 'invalid' );
			return;
		}

		if ( 0 === (int) $result['updated'] ) {
			// All selections invalid/removed — treat as no-op notice, no save.
			$this->bulk_result = array( 'status' => 'empty' );
			return;
		}

		Policy::save_policy( $result['policy'] );
		$this->bulk_result = array(
			'status'  => 'ok',
			'updated' => (int) $result['updated'],
		);
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private function apply_model_force_settings_from_post( array &$policy ): void {
		$this->require_admin_mutation( 'handl_aicac_save_policy' );

		$posted_map = filter_input( INPUT_POST, 'handl_aicac_model_force', FILTER_UNSAFE_RAW, FILTER_REQUIRE_ARRAY );
		$policy['model_force_plugins'] = Model_Force::sanitize_force_map( is_array( $posted_map ) ? $posted_map : array() );

		$posted_ua = filter_input( INPUT_POST, 'handl_aicac_model_force_unattributed', FILTER_UNSAFE_RAW );
		$policy['model_force_unattributed']          = Model_Force::sanitize_unattributed_mode( $posted_ua );
		$policy['model_force_unattributed_provider'] = Model_Force::sanitize_id( filter_input( INPUT_POST, 'handl_aicac_model_force_unattributed_provider', FILTER_UNSAFE_RAW ) );
		$policy['model_force_unattributed_model']    = Model_Force::sanitize_id( filter_input( INPUT_POST, 'handl_aicac_model_force_unattributed_model', FILTER_UNSAFE_RAW ) );

		// Legacy site-wide fields must not reappear.
		unset( $policy['model_force_enabled'], $policy['model_force_provider'], $policy['model_force_model'] );
	}

	/**
	 * EXPERIMENTAL per-plugin model force / downgrade (F4).
	 *
	 * Labeled experimental in words (not fine print). Relies on unsupported
	 * clone-sharing; final-route verification fail-closes on mismatch.
	 * Pins follow the detected caller (best-effort) — not a spend guarantee.
	 *
	 * @param array<string,mixed> $policy
	 * @param array<int,mixed>    $log
	 */
	private function render_model_force_settings( array $policy, string $form_id, array $log = array() ): void {
		$ua_mode  = Model_Force::sanitize_unattributed_mode( $policy['model_force_unattributed'] ?? 'none' );
		$ua_prov  = (string) ( $policy['model_force_unattributed_provider'] ?? '' );
		$ua_model = (string) ( $policy['model_force_unattributed_model'] ?? '' );
		$compat   = Model_Force::clone_compat_status();
		$health   = Model_Force::get_health();
		$force_n  = count( Model_Force::force_map( $policy ) );
		$unforced = Model_Force::count_unforced_unattributed( $log );

		echo '<h2>' . esc_html__( 'Model routing by plugin (experimental)', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<div class="notice notice-warning inline"><p>';
		echo '<strong>' . esc_html__( 'Experimental. Do not rely on this as a production control.', 'handl-ai-connector-access-control' ) . '</strong> ';
		echo esc_html__( 'Choose a provider and model in a plugin row to route allowed AI Client calls. Leave both fields blank for no routing. Plugin detection is best-effort and may be wrong or unavailable for cron, REST, shared libraries, and must-use plugins. A wrong match can apply the wrong route. This feature is experimental and not a spend guarantee.', 'handl-ai-connector-access-control' );
		echo '</p></div>';

		if ( $force_n > 0 || 'force' === $ua_mode ) {
			echo '<div class="notice notice-info inline"><p>';
			echo esc_html(
				sprintf(
					/* translators: %d: number of plugins with a force row */
					_n( '%d plugin has model routing configured.', '%d plugins have model routing configured.', $force_n, 'handl-ai-connector-access-control' ),
					$force_n
				)
			);
			if ( $unforced > 0 ) {
				echo ' <strong>' . esc_html(
					sprintf(
						/* translators: %d: unattributed unforced count */
						_n(
							'%d saved call ran without model routing because no plugin was detected.',
							'%d saved calls ran without model routing because no plugin was detected.',
							$unforced,
							'handl-ai-connector-access-control'
						),
						$unforced
					)
				) . '</strong>';
			} else {
				echo ' ' . esc_html__( 'No saved calls have run without model routing because no plugin was detected.', 'handl-ai-connector-access-control' );
			}
			echo '</p></div>';
		}

		echo '<table class="form-table" role="presentation">';
		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Calls with no detected plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<select name="handl_aicac_model_force_unattributed" id="handl-aicac-model-force-unattributed" form="' . esc_attr( $form_id ) . '">';
		$this->render_option( 'none', $ua_mode, __( 'Do not route (recommended)', 'handl-ai-connector-access-control' ) );
		$this->render_option( 'force', $ua_mode, __( 'Route to the provider and model below', 'handl-ai-connector-access-control' ) );
		echo '</select>';
		echo '<p class="description">' . esc_html__( 'Choose what happens when no plugin can be identified. The default is not to route these calls. The optional provider and model apply only to unidentified calls, not as a site-wide default.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<p style="margin-top:8px;">';
		echo '<label for="handl-aicac-model-force-ua-provider">' . esc_html__( 'Provider', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<input type="text" class="regular-text code" id="handl-aicac-model-force-ua-provider" name="handl_aicac_model_force_unattributed_provider" form="' . esc_attr( $form_id ) . '" value="' . esc_attr( $ua_prov ) . '" placeholder="openai" autocomplete="off" /> ';
		echo '<label for="handl-aicac-model-force-ua-model">' . esc_html__( 'Model', 'handl-ai-connector-access-control' ) . '</label> ';
		echo '<input type="text" class="regular-text code" id="handl-aicac-model-force-ua-model" name="handl_aicac_model_force_unattributed_model" form="' . esc_attr( $form_id ) . '" value="' . esc_attr( $ua_model ) . '" placeholder="gpt-4o-mini" autocomplete="off" />';
		echo '</p>';
		echo '<p class="description">' . esc_html__( 'Required only when routing unidentified calls. If either field is missing, no model route is applied.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '</td>';
		echo '</tr>';

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Model-routing health', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		if ( $compat['compatible'] ) {
			echo '<p style="margin:0;"><span class="dashicons dashicons-yes-alt" style="color:#00a32a;"></span> ';
			echo esc_html__( 'Compatibility check passed. This quick check does not prove that model routing will work. The final route is checked again before the provider call.', 'handl-ai-connector-access-control' );
			echo '</p>';
		} else {
			echo '<p style="margin:0;"><span class="dashicons dashicons-warning" style="color:#d63638;"></span> ';
			echo esc_html(
				sprintf(
					/* translators: %s: reason code */
					__( 'Compatibility check failed: %s. Model routing will not be applied.', 'handl-ai-connector-access-control' ),
					$compat['reason']
				)
			);
			echo '</p>';
		}
		$status = isset( $health['status'] ) ? (string) $health['status'] : '';
		if ( '' !== $status ) {
			echo '<p class="description" style="margin-top:6px;">';
			echo esc_html(
				sprintf(
					/* translators: %s: health status code */
					__( 'Last routing status: %s', 'handl-ai-connector-access-control' ),
					$status
				)
			);
			echo '</p>';
		}
		echo '</td>';
		echo '</tr>';
		echo '</table>';
	}

	/**
	 * Caller-intent tool deny-at-arming (F2). Distinct from MCP visibility.
	 *
	 * Matches any armed tool name — WordPress abilities (wpab__) and custom
	 * FunctionDeclarations. The registered-abilities checklist is a helper subset.
	 *
	 * @param array<string,mixed> $policy
	 */
	private function render_ability_arming_settings( array $policy, string $form_id ): void {
		$denied      = Policy::get_denied_tools( $policy );
		$denied_text = implode( "\n", $denied );
		$registered  = $this->list_registered_ability_names();

		echo '<h2>' . esc_html__( 'Blocked AI tools', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<div class="notice notice-info inline handl-aicac-ability-axis-notice"><p>';
		echo esc_html__( 'Choose which tools plugins may offer to an AI model. If a prompt includes a blocked WordPress ability or custom tool, the entire prompt is blocked before the model runs. This does not hide or unregister the tool elsewhere on your site. Matching is not case-sensitive.', 'handl-ai-connector-access-control' );
		echo '</p></div>';

		echo '<table class="form-table" role="presentation">';
		echo '<tr>';
		echo '<th scope="row"><label for="handl-aicac-denied-tools">' . esc_html__( 'Blocked tools', 'handl-ai-connector-access-control' ) . '</label></th>';
		echo '<td>';
		echo '<textarea name="handl_aicac_denied_tools" id="handl-aicac-denied-tools" form="' . esc_attr( $form_id ) . '" rows="6" cols="50" class="large-text code" placeholder="namespace/tool-name">' . esc_textarea( $denied_text ) . '</textarea>';
		echo '<p class="description">' . esc_html__( 'Enter one tool name per line, such as mainwp/add-site-v1. If a prompt offers any listed tool, the prompt is blocked before the model runs. Leave this empty to allow all tools. You may list custom tool names too.', 'handl-ai-connector-access-control' ) . '</p>';

		// Flag deny-list entries that match nothing currently registered (helper only).
		if ( ! empty( $denied ) ) {
			$inert = array();
			foreach ( $denied as $entry ) {
				if ( ! Policy::deny_entry_matches_registered( $entry, $registered ) ) {
					$inert[] = $entry;
				}
			}
			if ( ! empty( $inert ) ) {
				echo '<div class="notice notice-warning inline handl-aicac-inert-tools"><p>';
				echo esc_html__( 'Not registered now. The rule will apply if this ability or custom tool is added later:', 'handl-ai-connector-access-control' );
				echo ' <code>' . esc_html( implode( ', ', $inert ) ) . '</code>';
				echo '</p></div>';
			}
		}

		if ( ! empty( $registered ) ) {
			echo '<p class="description"><strong>' . esc_html__( 'Registered WordPress abilities you can add:', 'handl-ai-connector-access-control' ) . '</strong></p>';
			echo '<ul class="handl-aicac-registered-abilities">';
			foreach ( $registered as $name ) {
				// Case-insensitive check so checkbox reflects normalized matching.
				$checked = Policy::deny_entry_matches_registered( $name, $denied ) ? ' checked="checked"' : '';
				echo '<li><label>';
				echo '<input type="checkbox" class="handl-aicac-tool-quick-add" data-tool="' . esc_attr( $name ) . '"' . $checked . ' /> ';
				echo '<code>' . esc_html( $name ) . '</code>';
				echo '</label></li>';
			}
			echo '</ul>';
			echo '<p class="description">' . esc_html__( 'Use the checkboxes to add or remove names from the list above, then save your changes. This is not a complete list of tools you can block.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '<script>';
			echo '(function(){var ta=document.getElementById("handl-aicac-denied-tools");if(!ta)return;';
			echo 'function lines(){return ta.value.split(/\\r\\n|\\r|\\n/).map(function(s){return s.trim();}).filter(Boolean);}';
			echo 'function write(arr){ta.value=arr.join("\\n");}';
			echo 'function idx(cur,n){var nl=n.toLowerCase();for(var i=0;i<cur.length;i++){if(cur[i].toLowerCase()===nl)return i;}return -1;}';
			echo 'document.querySelectorAll(".handl-aicac-tool-quick-add").forEach(function(cb){cb.addEventListener("change",function(){var n=cb.getAttribute("data-tool");var cur=lines();var i=idx(cur,n);if(cb.checked&&i<0)cur.push(n);if(!cb.checked&&i>=0)cur.splice(i,1);write(cur);});});';
			echo '})();';
			echo '</script>';
		} else {
			echo '<p class="description">' . esc_html__( 'No WordPress abilities are registered right now. You can still enter ability or custom tool names above to block them if they are added later.', 'handl-ai-connector-access-control' ) . '</p>';
		}

		echo '</td>';
		echo '</tr>';
		echo '</table>';
	}

	/**
	 * @return list<string>
	 */
	private function list_registered_ability_names(): array {
		if ( ! function_exists( 'wp_get_abilities' ) ) {
			return array();
		}

		try {
			$abilities = wp_get_abilities();
		} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			return array();
		}

		if ( ! is_array( $abilities ) ) {
			return array();
		}

		$names = array();
		foreach ( $abilities as $ability ) {
			if ( is_object( $ability ) && method_exists( $ability, 'get_name' ) ) {
				$name = (string) $ability->get_name();
			} elseif ( is_string( $ability ) ) {
				$name = $ability;
			} else {
				continue;
			}
			if ( '' !== $name ) {
				$names[] = $name;
			}
		}

		$names = array_values( array_unique( $names ) );
		sort( $names, SORT_STRING );
		return $names;
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private function apply_kill_switch_settings_from_post( array &$policy ): void {
		$this->require_admin_mutation( 'handl_aicac_save_policy' );

		$posted_kill = filter_input( INPUT_POST, 'handl_aicac_kill_switch', FILTER_UNSAFE_RAW );
		$policy['kill_switch'] = ! empty( $posted_kill );

		$exceptions = array();
		$posted_exceptions = filter_input( INPUT_POST, 'handl_aicac_kill_exceptions', FILTER_UNSAFE_RAW, FILTER_REQUIRE_ARRAY );
		if ( is_array( $posted_exceptions ) ) {
			foreach ( $posted_exceptions as $basename ) {
				$basename = sanitize_text_field( (string) $basename );
				if ( '' !== $basename ) {
					$exceptions[] = $basename;
				}
			}
		}
		$policy['kill_switch_exceptions'] = array_values( array_unique( $exceptions ) );
	}

	/**
	 * AICAC-23: opt-in block of direct AI provider HTTP (Rules tab).
	 *
	 * @param array<string,mixed> $policy
	 */
	private function apply_shadow_block_settings_from_post( array &$policy ): void {
		$this->require_admin_mutation( 'handl_aicac_save_policy' );

		$posted = filter_input( INPUT_POST, 'handl_aicac_shadow_block_enabled', FILTER_UNSAFE_RAW );
		$policy['shadow_block_enabled'] = ! empty( $posted );

		$exceptions = array();
		$posted_exceptions = filter_input( INPUT_POST, 'handl_aicac_shadow_block_exceptions', FILTER_UNSAFE_RAW, FILTER_REQUIRE_ARRAY );
		if ( is_array( $posted_exceptions ) ) {
			foreach ( $posted_exceptions as $basename ) {
				$basename = sanitize_text_field( (string) $basename );
				if ( '' !== $basename ) {
					$exceptions[] = $basename;
				}
			}
		}
		$policy['shadow_block_exceptions'] = array_values( array_unique( $exceptions ) );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private function apply_role_gate_settings_from_post( array &$policy ): void {
		$this->require_admin_mutation( 'handl_aicac_save_policy' );

		$posted_enabled = filter_input( INPUT_POST, 'handl_aicac_role_gate_enabled', FILTER_UNSAFE_RAW );
		$policy['role_gate_enabled'] = ! empty( $posted_enabled );

		$roles = array();
		$posted_roles = filter_input( INPUT_POST, 'handl_aicac_allowed_roles', FILTER_UNSAFE_RAW, FILTER_REQUIRE_ARRAY );
		if ( is_array( $posted_roles ) ) {
			foreach ( $posted_roles as $role ) {
				$role = sanitize_key( (string) $role );
				if ( '' !== $role ) {
					$roles[] = $role;
				}
			}
		}
		$policy['allowed_roles'] = Policy::sanitize_allowed_roles( $roles );
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	private function apply_log_settings_from_post( array &$policy ): void {
		$this->require_admin_mutation( 'handl_aicac_save_policy' );

		$posted_audit = filter_input( INPUT_POST, 'handl_aicac_audit_only', FILTER_UNSAFE_RAW );
		$policy['audit_only'] = ! empty( $posted_audit );

		if ( $policy['audit_only'] ) {
			$policy['log_enabled'] = true;
		} else {
			$posted_log_enabled = filter_input( INPUT_POST, 'handl_aicac_log_enabled', FILTER_UNSAFE_RAW );
			$policy['log_enabled'] = ! empty( $posted_log_enabled );
		}

		$posted_log_limit = filter_input( INPUT_POST, 'handl_aicac_log_limit', FILTER_VALIDATE_INT );
		if ( false !== $posted_log_limit && null !== $posted_log_limit ) {
			$policy['log_limit'] = (int) $posted_log_limit;
		}

		// Empty field = TTL off. Invalid values also coerce to off via sanitize.
		$posted_max_age = filter_input( INPUT_POST, 'handl_aicac_log_max_age_days', FILTER_UNSAFE_RAW );
		if ( null === $posted_max_age || false === $posted_max_age || '' === trim( (string) $posted_max_age ) ) {
			$policy['log_max_age_days'] = null;
		} else {
			$policy['log_max_age_days'] = Policy::sanitize_log_max_age_days( $posted_max_age );
		}

		$posted_alert = filter_input( INPUT_POST, 'handl_aicac_alert_on_deny', FILTER_UNSAFE_RAW );
		$policy['alert_on_deny'] = ! empty( $posted_alert );
		$posted_shadow = filter_input( INPUT_POST, 'handl_aicac_alert_on_shadow', FILTER_UNSAFE_RAW );
		$policy['alert_on_shadow'] = ! empty( $posted_shadow );
		$policy['alert_mode']    = Alerts::sanitize_mode( filter_input( INPUT_POST, 'handl_aicac_alert_mode', FILTER_UNSAFE_RAW ) );
		$policy['alert_email']   = Alerts::sanitize_email( filter_input( INPUT_POST, 'handl_aicac_alert_email', FILTER_UNSAFE_RAW ) );

		$webhook_check = Alerts::validate_webhook_url_input(
			filter_input( INPUT_POST, 'handl_aicac_alert_webhook_url', FILTER_UNSAFE_RAW )
		);
		if ( $webhook_check['ok'] ) {
			$policy['alert_webhook_url'] = $webhook_check['url'];
		} else {
			// AC6: reject invalid values inline — do not store; keep prior sanitized URL.
			$this->webhook_url_rejected  = true;
			$policy['alert_webhook_url'] = Alerts::sanitize_webhook_url( $policy['alert_webhook_url'] ?? '' );
		}

		// F7: persist weekly preference only on divergence from the rendered state.
		// Provenance = what the checkbox showed; unchecked checkbox posts absence.
		$posted_weekly    = ! empty( filter_input( INPUT_POST, 'handl_aicac_weekly_report_enabled', FILTER_UNSAFE_RAW ) );
		$rendered_weekly  = ! empty( filter_input( INPUT_POST, 'handl_aicac_weekly_report_rendered', FILTER_UNSAFE_RAW ) );
		$raw_opt          = get_option( Plugin::OPTION_KEY );
		$had_weekly_key   = is_array( $raw_opt ) && array_key_exists( 'weekly_report_enabled', $raw_opt );

		if ( $posted_weekly !== $rendered_weekly ) {
			// Operator diverged from what was shown → store explicit choice.
			$policy['weekly_report_enabled']  = $posted_weekly;
			$policy['_weekly_report_write']   = 'set';
		} elseif ( $had_weekly_key ) {
			// No divergence; keep the already-stored explicit choice.
			$policy['weekly_report_enabled']  = ! empty( $raw_opt['weekly_report_enabled'] );
			$policy['_weekly_report_write']   = 'set';
		} else {
			// No divergence and never stored → leave key absent (staged default re-derives).
			// In-memory true so maybe_schedule sees preference selected after logging turns on.
			$policy['weekly_report_enabled']  = true;
			$policy['_weekly_report_write']   = 'omit';
		}

		$policy['est_usd_input_per_m']  = Cost::sanitize_rate(
			filter_input( INPUT_POST, 'handl_aicac_est_usd_input_per_m', FILTER_UNSAFE_RAW ),
			Cost::DEFAULT_INPUT_PER_M
		);
		$policy['est_usd_output_per_m'] = Cost::sanitize_rate(
			filter_input( INPUT_POST, 'handl_aicac_est_usd_output_per_m', FILTER_UNSAFE_RAW ),
			Cost::DEFAULT_OUTPUT_PER_M
		);
		$posted_provider_rates = filter_input( INPUT_POST, 'handl_aicac_est_usd_provider', FILTER_UNSAFE_RAW, FILTER_REQUIRE_ARRAY );
		$policy['est_usd_provider_rates'] = Cost::sanitize_provider_rates( is_array( $posted_provider_rates ) ? $posted_provider_rates : array() );

		// S-103: estimated-spend thresholds (empty = off).
		$policy['spend_threshold_site'] = Spend_Threshold::sanitize_threshold(
			filter_input( INPUT_POST, 'handl_aicac_spend_threshold_site', FILTER_UNSAFE_RAW )
		);
		$posted_plugin_th = filter_input( INPUT_POST, 'handl_aicac_spend_threshold_plugins', FILTER_UNSAFE_RAW, FILTER_REQUIRE_ARRAY );
		$policy['spend_threshold_plugins'] = Spend_Threshold::sanitize_plugin_thresholds(
			is_array( $posted_plugin_th ) ? $posted_plugin_th : array()
		);

		// AICAC-ANOMALY: usage spike alerts (default off).
		$policy['anomaly_alert_enabled'] = ! empty( filter_input( INPUT_POST, 'handl_aicac_anomaly_alert_enabled', FILTER_UNSAFE_RAW ) );
		$policy['anomaly_multiplier']    = Anomaly::sanitize_multiplier(
			filter_input( INPUT_POST, 'handl_aicac_anomaly_multiplier', FILTER_UNSAFE_RAW )
		);
		$policy['anomaly_floor_calls'] = Anomaly::sanitize_floor_calls(
			filter_input( INPUT_POST, 'handl_aicac_anomaly_floor_calls', FILTER_UNSAFE_RAW )
		);
		$policy['anomaly_floor_spend'] = Anomaly::sanitize_floor_spend(
			filter_input( INPUT_POST, 'handl_aicac_anomaly_floor_spend', FILTER_UNSAFE_RAW )
		);
	}

	/**
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $log_filters
	 */
	private function handle_quick_rule_redirect( array $log_filters ): void {
		$this->require_admin_mutation( 'handl_aicac_quick_rule' );

		$plugin = filter_input( INPUT_POST, 'handl_aicac_quick_plugin', FILTER_UNSAFE_RAW );
		$rule   = filter_input( INPUT_POST, 'handl_aicac_quick_rule', FILTER_UNSAFE_RAW );
		$return = filter_input( INPUT_POST, 'handl_aicac_return_tab', FILTER_UNSAFE_RAW );

		$plugin = sanitize_text_field( (string) $plugin );
		$rule   = sanitize_text_field( (string) $rule );
		$return = sanitize_key( (string) $return );
		if ( ! in_array( $return, array( 'dashboard', 'activity', 'rules' ), true ) ) {
			$return = 'activity';
		}

		// set_plugin_rule() also accepts '' (clear) for undo — this caller must not.
		// Widening the shared validator for undo must not relax Allow/Deny posts into
		// silent rule-deletes (Lisa F5 should-fix).
		if ( 'allow' !== $rule && 'deny' !== $rule ) {
			return;
		}

		// Capture previous explicit rule for undo (empty string = Default).
		$policy   = Policy::get_policy();
		$prev     = '';
		if ( isset( $policy['plugins'][ $plugin ] ) && is_string( $policy['plugins'][ $plugin ] ) ) {
			$prev = (string) $policy['plugins'][ $plugin ];
			if ( 'allow' !== $prev && 'deny' !== $prev ) {
				$prev = '';
			}
		}

		if ( Policy::set_plugin_rule( $plugin, $rule ) ) {
			$args = array(
				'page'            => 'handl-ai-connector-access-control',
				'handl_aicac_tab' => $return,
			);
			if ( 'dashboard' === $return && 'deny' === $rule ) {
				$args['handl_aicac_blocked']   = $plugin;
				$args['handl_aicac_undo_rule'] = $prev;
			} else {
				$args['handl_aicac_quick_saved'] = '1';
				$args                           = array_merge( $args, $this->log_filters_to_query_args( $log_filters ) );
			}
			wp_safe_redirect( add_query_arg( $args, admin_url( 'options-general.php' ) ) );
			exit;
		}
	}

	/**
	 * Restore a previous plugin rule after dashboard single-click block (board Q3 undo).
	 */
	private function handle_undo_quick_rule(): void {
		$this->require_admin_mutation( 'handl_aicac_undo_quick_rule' );

		$plugin = sanitize_text_field( (string) filter_input( INPUT_POST, 'handl_aicac_quick_plugin', FILTER_UNSAFE_RAW ) );
		$prev   = sanitize_text_field( (string) filter_input( INPUT_POST, 'handl_aicac_undo_rule', FILTER_UNSAFE_RAW ) );
		if ( 'allow' !== $prev && 'deny' !== $prev ) {
			$prev = '';
		}
		if ( '' !== $plugin && Policy::set_plugin_rule( $plugin, $prev ) ) {
			wp_safe_redirect(
				add_query_arg(
					array(
						'page'               => 'handl-ai-connector-access-control',
						'handl_aicac_tab'    => 'dashboard',
						'handl_aicac_undone' => '1',
					),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private function render_kill_switch_settings_rows( array $policy, string $form_id, array $plugins ): void {
		$kill_switch = ! empty( $policy['kill_switch'] );
		$exceptions  = Policy::get_kill_switch_exceptions( $policy );
		// Dimmed + state note when kill is off; list stays fully operable (no pointer-events
		// block, no disabled checkboxes) so staging exceptions before enabling kill still POSTs.
		$ex_class = 'handl-aicac-kill-exceptions' . ( $kill_switch ? '' : ' is-muted' );
		// S-104: advisory only — kill on with an empty Exceptions list.
		$show_zero_warn = $kill_switch && array() === $exceptions;
		if ( $show_zero_warn ) {
			$ex_described_by = 'handl-aicac-kill-exceptions-zero-warn';
		} elseif ( ! $kill_switch ) {
			$ex_described_by = 'handl-aicac-kill-exceptions-state';
		} else {
			$ex_described_by = '';
		}

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Emergency stop', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<label><input type="checkbox" name="handl_aicac_kill_switch" value="1" form="' . esc_attr( $form_id ) . '" ' . checked( $kill_switch, true, false ) . ' id="handl-aicac-kill-switch" /> ';
		echo esc_html__( 'Block all AI Client calls', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'Blocks every AI Client call except listed exceptions. Calls from unknown plugins are blocked too.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<div class="' . esc_attr( $ex_class ) . '" id="handl-aicac-kill-exceptions-wrap">';
		echo '<p class="handl-aicac-kill-exceptions__heading" id="handl-aicac-kill-exceptions-heading"><strong>' . esc_html__( 'Exceptions', 'handl-ai-connector-access-control' ) . '</strong></p>';
		// Load-bearing: "exception" ≠ unconditionally allowed.
		echo '<p class="description">' . esc_html__( 'Exceptions still follow their normal plugin and AI type rules.', 'handl-ai-connector-access-control' ) . '</p>';
		// Visible only while kill is off; same listener toggles hidden with is-muted.
		echo '<p class="description handl-aicac-kill-exceptions__state" id="handl-aicac-kill-exceptions-state"' . ( $kill_switch ? ' hidden' : '' ) . '>' . esc_html__( 'Exceptions apply only while the Emergency stop is on.', 'handl-ai-connector-access-control' ) . '</p>';
		// S-104: distinct inline warning when kill is on and no exceptions are selected (server + JS).
		echo '<p class="description notice notice-warning inline handl-aicac-kill-exceptions__zero-warn" id="handl-aicac-kill-exceptions-zero-warn" aria-live="polite"' . ( $show_zero_warn ? '' : ' hidden' ) . '>';
		echo esc_html__( 'No exceptions selected. Emergency stop will block all AI Client calls from every installed plugin.', 'handl-ai-connector-access-control' );
		echo '</p>';
		// #16: announce state / zero-exceptions warning on group focus (sibling of aria-labelledby).
		echo '<div class="handl-aicac-kill-exceptions__list" role="group" aria-labelledby="handl-aicac-kill-exceptions-heading"';
		if ( '' !== $ex_described_by ) {
			echo ' aria-describedby="' . esc_attr( $ex_described_by ) . '"';
		}
		echo '>';
		$i = 0;
		foreach ( $plugins as $basename => $data ) {
			++$i;
			$name = isset( $data['Name'] ) ? (string) $data['Name'] : $basename;
			$id   = 'handl-aicac-kill-ex-' . (string) $i;
			$on   = in_array( $basename, $exceptions, true );
			echo '<label class="handl-aicac-kill-exceptions__item" for="' . esc_attr( $id ) . '">';
			echo '<input type="checkbox" id="' . esc_attr( $id ) . '" name="handl_aicac_kill_exceptions[]" value="' . esc_attr( $basename ) . '" form="' . esc_attr( $form_id ) . '" ' . checked( $on, true, false ) . ' />';
			echo '<span class="handl-aicac-kill-exceptions__text">';
			echo '<span class="handl-aicac-kill-exceptions__name">' . esc_html( $name ) . '</span>';
			echo '<code class="handl-aicac-kill-exceptions__slug">' . esc_html( $basename ) . '</code>';
			echo '</span>';
			echo '</label>';
		}
		echo '</div>';
		echo '</div>';
		// Live mute, state-note, and zero-exceptions warning (does not change policy until form submit).
		echo '<script>';
		echo '(function(){var k=document.getElementById("handl-aicac-kill-switch"),w=document.getElementById("handl-aicac-kill-exceptions-wrap"),n=document.getElementById("handl-aicac-kill-exceptions-state"),z=document.getElementById("handl-aicac-kill-exceptions-zero-warn"),g=w&&w.querySelector(".handl-aicac-kill-exceptions__list"),xs=w?w.querySelectorAll(\'input[name="handl_aicac_kill_exceptions[]"]\'):[];';
		echo 'if(!k||!w)return;function anyEx(){for(var i=0;i<xs.length;i++){if(xs[i].checked)return true;}return false;}';
		echo 'function s(){var on=k.checked,zero=on&&!anyEx();w.classList.toggle("is-muted",!on);if(n)n.hidden=on;if(z)z.hidden=!zero;if(g){if(zero){g.setAttribute("aria-describedby","handl-aicac-kill-exceptions-zero-warn");}else if(!on){g.setAttribute("aria-describedby","handl-aicac-kill-exceptions-state");}else{g.removeAttribute("aria-describedby");}}}';
		echo 'k.addEventListener("change",s);for(var i=0;i<xs.length;i++){xs[i].addEventListener("change",s);}s();})();';
		echo '</script>';
		echo '</td>';
		echo '</tr>';
	}

	/**
	 * AICAC-23: opt-in block of direct AI provider HTTP outside the AI Client.
	 *
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private function render_shadow_block_settings_rows( array $policy, string $form_id, array $plugins ): void {
		$enabled    = ! empty( $policy['shadow_block_enabled'] );
		$exceptions = Shadow_AI::get_block_exceptions( $policy );
		$ex_class   = 'handl-aicac-shadow-block-exceptions' . ( $enabled ? '' : ' is-muted' );

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Direct AI connections', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<label><input type="checkbox" name="handl_aicac_shadow_block_enabled" value="1" form="' . esc_attr( $form_id ) . '" ' . checked( $enabled, true, false ) . ' id="handl-aicac-shadow-block-enabled" /> ';
		echo esc_html__( 'Block direct calls to known AI providers', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'Off by default. Blocks WordPress HTTP requests to known AI provider hosts, except for the plugins allowed below. Calls made through the WordPress AI Client are not affected. Turn on Learn mode or activity logging first to see which direct connections would be blocked.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<div class="' . esc_attr( $ex_class ) . '" id="handl-aicac-shadow-block-exceptions-wrap">';
		echo '<p class="handl-aicac-shadow-block-exceptions__heading" id="handl-aicac-shadow-block-exceptions-heading"><strong>' . esc_html__( 'Allow selected plugins to connect directly', 'handl-ai-connector-access-control' ) . '</strong></p>';
		echo '<p class="description handl-aicac-shadow-block-exceptions__state" id="handl-aicac-shadow-block-exceptions-state"' . ( $enabled ? ' hidden' : '' ) . '>' . esc_html__( 'Exceptions apply only when blocking is on. Allowed direct connections are logged when Learn mode or activity logging is on.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<div class="handl-aicac-kill-exceptions__list" role="group" aria-labelledby="handl-aicac-shadow-block-exceptions-heading">';
		$i = 0;
		foreach ( $plugins as $basename => $data ) {
			++$i;
			$name = isset( $data['Name'] ) ? (string) $data['Name'] : $basename;
			$id   = 'handl-aicac-shadow-ex-' . (string) $i;
			$on   = in_array( $basename, $exceptions, true );
			echo '<label class="handl-aicac-kill-exceptions__item" for="' . esc_attr( $id ) . '">';
			echo '<input type="checkbox" id="' . esc_attr( $id ) . '" name="handl_aicac_shadow_block_exceptions[]" value="' . esc_attr( $basename ) . '" form="' . esc_attr( $form_id ) . '" ' . checked( $on, true, false ) . ' />';
			echo '<span class="handl-aicac-kill-exceptions__text">';
			echo '<span class="handl-aicac-kill-exceptions__name">' . esc_html( $name ) . '</span>';
			echo '<code class="handl-aicac-kill-exceptions__slug">' . esc_html( $basename ) . '</code>';
			echo '</span>';
			echo '</label>';
		}
		echo '</div>';
		echo '</div>';
		echo '<script>';
		echo '(function(){var k=document.getElementById("handl-aicac-shadow-block-enabled"),w=document.getElementById("handl-aicac-shadow-block-exceptions-wrap"),n=document.getElementById("handl-aicac-shadow-block-exceptions-state");';
		echo 'if(!k||!w)return;function s(){var on=k.checked;w.classList.toggle("is-muted",!on);if(n)n.hidden=on;}k.addEventListener("change",s);s();})();';
		echo '</script>';
		echo '</td>';
		echo '</tr>';
	}

	/**
	 * Optional per-role gate: which WP roles may initiate AI Client operations.
	 *
	 * @param array<string,mixed> $policy
	 */
	private function render_role_gate_settings_rows( array $policy, string $form_id ): void {
		$enabled  = ! empty( $policy['role_gate_enabled'] );
		$available = Policy::available_roles_for_gate();
		$allowed  = Policy::sanitize_allowed_roles( $policy['allowed_roles'] ?? array() );
		// Gate ON: mirror stored list exactly (empty = none checked). Gate OFF + empty: all checked default.
		$checked  = Policy::role_gate_checked_roles( $enabled, $allowed, $available );
		$list_class = 'handl-aicac-role-gate-list' . ( $enabled ? '' : ' is-muted' );

		echo '<tr>';
		echo '<th scope="row">' . esc_html__( 'Limit by role', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<label><input type="checkbox" name="handl_aicac_role_gate_enabled" value="1" form="' . esc_attr( $form_id ) . '" ' . checked( $enabled, true, false ) . ' id="handl-aicac-role-gate-enabled" /> ';
		echo esc_html__( 'Only selected WordPress roles may start AI Client calls', 'handl-ai-connector-access-control' ) . '</label>';
		echo '<p class="description">' . esc_html__( 'Off by default, so every role is allowed. When enabled, users with an unselected role are blocked. Blocks appear in the log and alerts as “role not allowed.” Cron, WP-CLI, and requests without a signed-in user are not limited.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<div class="' . esc_attr( $list_class ) . '" id="handl-aicac-role-gate-wrap" style="margin-top:10px;max-width:28em;">';
		echo '<p class="handl-aicac-role-gate__heading" id="handl-aicac-role-gate-heading"><strong>' . esc_html__( 'Allowed roles', 'handl-ai-connector-access-control' ) . '</strong></p>';
		echo '<p class="description handl-aicac-role-gate__state" id="handl-aicac-role-gate-state"' . ( $enabled ? ' hidden' : '' ) . '>' . esc_html__( 'This list applies only while Limit by role is on.', 'handl-ai-connector-access-control' ) . '</p>';
		if ( $enabled && empty( $allowed ) ) {
			echo '<p class="description" style="color:#b32d2e;"><strong>' . esc_html__( 'No roles selected. Every signed-in user will be blocked.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		}
		if ( empty( $available ) ) {
			echo '<p class="description">' . esc_html__( 'No WordPress roles are available on this site.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<div class="handl-aicac-role-gate__list" role="group" aria-labelledby="handl-aicac-role-gate-heading" aria-describedby="handl-aicac-role-gate-state">';
			$i = 0;
			foreach ( $available as $slug => $label ) {
				++$i;
				$id  = 'handl-aicac-role-' . (string) $i;
				$on  = in_array( $slug, $checked, true );
				echo '<label class="handl-aicac-role-gate__item" for="' . esc_attr( $id ) . '" style="display:block;margin:2px 0;">';
				echo '<input type="checkbox" id="' . esc_attr( $id ) . '" name="handl_aicac_allowed_roles[]" value="' . esc_attr( $slug ) . '" form="' . esc_attr( $form_id ) . '" ' . checked( $on, true, false ) . ' /> ';
				echo '<span>' . esc_html( $label ) . '</span> <code style="font-size:11px;">' . esc_html( $slug ) . '</code>';
				echo '</label>';
			}
			echo '</div>';
		}
		echo '</div>';
		echo '<script>';
		echo '(function(){var k=document.getElementById("handl-aicac-role-gate-enabled"),w=document.getElementById("handl-aicac-role-gate-wrap"),n=document.getElementById("handl-aicac-role-gate-state");';
		echo 'if(!k||!w)return;function s(){w.classList.toggle("is-muted",!k.checked);if(n)n.hidden=k.checked;}k.addEventListener("change",s);s();})();';
		echo '</script>';
		echo '</td>';
		echo '</tr>';
	}

	private function render_suggested_rules( array $log, array $policy, array $plugins, array $log_filters ): void {
		$suggested = Policy::suggested_rules_from_log( $log, $policy, $plugins );

		echo '<h2>' . esc_html__( 'Suggested rules', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description handl-aicac-log-meta" style="margin-top:0;">';
		echo esc_html__( 'Plugins found while Learn mode was on. “Would block at plugin level” reflects only the Emergency stop and plugin rule. AI type rules are evaluated separately.', 'handl-ai-connector-access-control' );
		echo '</p>';

		if ( empty( $suggested ) ) {
			echo '<p>' . esc_html__( 'No identified plugin calls in the log yet.', 'handl-ai-connector-access-control' ) . '</p>';
			return;
		}

		echo '<table class="widefat striped handl-aicac-suggested-rules">';
		echo '<thead><tr>';
		echo '<th>' . esc_html__( 'Plugin', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Calls', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Last seen', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Rule', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Would block at plugin level', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<th>' . esc_html__( 'Actions', 'handl-ai-connector-access-control' ) . '</th>';
		echo '</tr></thead><tbody>';

		foreach ( array_slice( $suggested, 0, 30 ) as $row ) {
			echo '<tr>';
			echo '<td><strong>' . esc_html( $row['label'] ) . '</strong><br /><code>' . esc_html( $row['plugin'] ) . '</code></td>';
			echo '<td>' . esc_html( number_format_i18n( (int) $row['calls'] ) ) . '</td>';
			echo '<td>' . esc_html( ! empty( $row['last_ts'] ) ? wp_date( 'Y-m-d H:i:s', (int) $row['last_ts'] ) : '—' ) . '</td>';
			echo '<td>' . esc_html( $this->format_explicit_rule_label( (string) $row['explicit'] ) ) . '</td>';
			echo '<td>' . $this->render_decision_badge( (string) $row['effective'] ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '<td class="handl-aicac-quick-actions">';
			$this->render_quick_rule_buttons( (string) $row['plugin'], $log_filters );
			$this->render_graduate_plugin_action( (string) $row['plugin'], $policy, $plugins );
			echo '</td>';
			echo '</tr>';
		}

		echo '</tbody></table>';
	}

	private function format_explicit_rule_label( string $explicit ): string {
		if ( 'allow' === $explicit ) {
			return __( 'Allow', 'handl-ai-connector-access-control' );
		}
		if ( 'deny' === $explicit ) {
			return __( 'Deny', 'handl-ai-connector-access-control' );
		}
		return __( 'Default', 'handl-ai-connector-access-control' );
	}

	/**
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $log_filters
	 */
	private function render_quick_rule_buttons( string $plugin_basename, array $log_filters ): void {
		if ( '' === $plugin_basename ) {
			return;
		}

		foreach ( array( 'allow', 'deny' ) as $rule ) {
			echo '<form method="post" class="handl-aicac-quick-rule-form">';
			wp_nonce_field( 'handl_aicac_quick_rule', 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_action" value="quick_rule" />';
			echo '<input type="hidden" name="handl_aicac_quick_plugin" value="' . esc_attr( $plugin_basename ) . '" />';
			echo '<input type="hidden" name="handl_aicac_quick_rule" value="' . esc_attr( $rule ) . '" />';
			$this->render_log_filter_hiddens( $log_filters );
			$label = 'allow' === $rule
				? __( 'Allow', 'handl-ai-connector-access-control' )
				: __( 'Deny', 'handl-ai-connector-access-control' );
			$attrs = array( 'class' => 'button button-small' );
			if ( 'deny' === $rule ) {
				$attrs['class'] .= ' button-link-delete';
			}
			submit_button( $label, 'secondary', 'submit', false, $attrs );
			echo '</form>';
		}
	}

	private function handle_save_log(): void {
		$this->require_admin_mutation( 'handl_aicac_save_policy' );

		$policy = Policy::get_policy();

		$this->apply_log_settings_from_post( $policy );

		Policy::save_policy( $policy );
		// Apply a newly saved TTL immediately so the Activity table matches settings.
		Policy::prune_stored_log();
	}

	private function render_option( string $value, string $current, string $label ): void {
		echo '<option value="' . esc_attr( $value ) . '" ' . selected( $current, $value, false ) . '>' . esc_html( $label ) . '</option>';
	}

	/**
	 * @param array<string,mixed> $row
	 * @param array<string,array<string,mixed>> $plugins
	 * @param array<string,mixed> $policy
	 * @param array{decision:string,operation:string,provider:string,model:string,plugin:string} $log_filters
	 */
	private function render_log_row( array $row, array $plugins, array $policy, array $log_filters ): void {
		$ts        = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		$decision  = isset( $row['decision'] ) ? (string) $row['decision'] : '';
		$operation = isset( $row['operation'] ) ? (string) $row['operation'] : '';
		$provider  = isset( $row['provider'] ) ? (string) $row['provider'] : '';
		$plugin    = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
		$file      = isset( $row['file'] ) ? (string) $row['file'] : '';
		$user_id   = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
		$uri       = isset( $row['uri'] ) ? (string) $row['uri'] : '';
		$prompt        = isset( $row['prompt_preview'] ) ? (string) $row['prompt_preview'] : '';
		$input_tokens  = array_key_exists( 'input_tokens', $row ) ? (int) $row['input_tokens'] : null;
		$output_tokens = array_key_exists( 'output_tokens', $row ) ? (int) $row['output_tokens'] : null;
		$thought_tokens = array_key_exists( 'thought_tokens', $row ) ? (int) $row['thought_tokens'] : null;
		$is_direct_http = isset( $row['channel'] ) && 'direct_http' === (string) $row['channel'];
		$host           = isset( $row['host'] ) ? (string) $row['host'] : '';
		if ( $is_direct_http && '' === $provider && ! empty( $row['shadow_provider'] ) ) {
			$provider = (string) $row['shadow_provider'];
		}

		$model          = $this->get_log_row_model( $row );
		$model_inferred = ! empty( $row['model_inferred'] );

		$plugin_label = $plugin;
		if ( $plugin && isset( $plugins[ $plugin ]['Name'] ) ) {
			$plugin_label = (string) $plugins[ $plugin ]['Name'];
		}

		echo '<tr>';
		echo '<td class="column-time">' . esc_html( $ts ? wp_date( 'Y-m-d H:i:s', $ts ) : '—' ) . '</td>';
		echo '<td>';
		echo $this->render_decision_badge( $decision ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		if ( $is_direct_http ) {
			echo '<br /><span class="description handl-aicac-shadow-label" style="font-size:11px;">';
			if ( 'deny' === $decision ) {
				echo esc_html__( 'outside AI Client; blocked', 'handl-ai-connector-access-control' );
			} elseif ( 'allow' === $decision && ! empty( $row['shadow_exception'] ) ) {
				echo esc_html__( 'outside AI Client; allowed by exception', 'handl-ai-connector-access-control' );
			} else {
				echo esc_html__( 'outside AI Client; observed, not blocked', 'handl-ai-connector-access-control' );
			}
			echo '</span>';
			$cluster_count = isset( $row['count'] ) ? (int) $row['count'] : 1;
			if ( $cluster_count > 1 ) {
				echo '<br /><span class="description handl-aicac-shadow-count" style="font-size:11px;">';
				// count = HTTP calls (not page loads). Span from first_ts..ts when collapsed.
				$first_ts = isset( $row['first_ts'] ) ? (int) $row['first_ts'] : 0;
				$last_ts  = $ts > 0 ? $ts : ( isset( $row['ts'] ) ? (int) $row['ts'] : 0 );
				if ( $first_ts > 0 && $last_ts > 0 && $last_ts !== $first_ts ) {
					echo esc_html(
						sprintf(
							/* translators: 1: call count, 2: first time, 3: last time */
							_n(
								'observed %1$d call between %2$s and %3$s',
								'observed %1$d calls between %2$s and %3$s',
								$cluster_count,
								'handl-ai-connector-access-control'
							),
							$cluster_count,
							wp_date( 'Y-m-d H:i:s', $first_ts ),
							wp_date( 'Y-m-d H:i:s', $last_ts )
						)
					);
				} else {
					echo esc_html(
						sprintf(
							/* translators: %d: number of HTTP calls in this cluster */
							_n(
								'observed %d call',
								'observed %d calls',
								$cluster_count,
								'handl-ai-connector-access-control'
							),
							$cluster_count
						)
					);
				}
				echo '</span>';
			}
		}
		// Learn-mode "would" is AI Client only — direct_http is observe-only (no would-enforce).
		if ( ! $is_direct_http && ! empty( $policy['audit_only'] ) ) {
			$would = isset( $row['would_decision'] ) ? (string) $row['would_decision'] : '';
			if ( '' === $would && $plugin ) {
				$would = Policy::effective_decision_label( $policy, $plugin );
			}
			if ( '' !== $would && $would !== $decision ) {
				echo '<br /><span class="description" style="font-size:11px;">';
				echo esc_html__( 'would', 'handl-ai-connector-access-control' ) . ' ';
				echo wp_kses_post( $this->render_decision_badge( $would ) );
				echo '</span>';
			}
		}
		$reason = isset( $row['denial_reason'] ) ? (string) $row['denial_reason'] : '';
		if ( '' !== $reason && ( 'deny' === $decision || ( ! empty( $policy['audit_only'] ) && 'deny' === ( $row['would_decision'] ?? '' ) ) ) ) {
			echo '<br /><span class="description handl-aicac-denial-reason">' . esc_html( $this->format_denial_reason_label( $reason ) ) . '</span>';
		}
		$user_role = isset( $row['user_role'] ) ? (string) $row['user_role'] : '';
		if ( '' !== $user_role ) {
			echo '<br /><span class="description handl-aicac-user-role" style="font-size:11px;">' . esc_html__( 'Role:', 'handl-ai-connector-access-control' ) . ' <code>' . esc_html( $user_role ) . '</code></span>';
		}
		$matched = array();
		if ( isset( $row['matched_tools'] ) && is_array( $row['matched_tools'] ) ) {
			$matched = $row['matched_tools'];
		} elseif ( isset( $row['matched_abilities'] ) && is_array( $row['matched_abilities'] ) ) {
			$matched = $row['matched_abilities'];
		}
		if ( ! empty( $matched ) ) {
			echo '<br /><span class="description handl-aicac-matched-tools"><code>' . esc_html( implode( ', ', array_map( 'strval', $matched ) ) ) . '</code></span>';
		}
		$armed = array();
		if ( isset( $row['armed_tools'] ) && is_array( $row['armed_tools'] ) ) {
			$armed = $row['armed_tools'];
		} elseif ( isset( $row['armed_abilities'] ) && is_array( $row['armed_abilities'] ) ) {
			$armed = $row['armed_abilities'];
		}
		if ( ! empty( $armed ) && empty( $matched ) ) {
			echo '<br /><span class="description handl-aicac-armed-tools">' . esc_html__( 'tools offered:', 'handl-ai-connector-access-control' ) . ' <code>' . esc_html( implode( ', ', array_map( 'strval', $armed ) ) ) . '</code></span>';
		}
		echo '</td>';
		$family = isset( $row['capability_family'] ) ? (string) $row['capability_family'] : '';
		if ( '' === $family && '' !== $operation && ! $is_direct_http ) {
			$family = Operations::family_from_operation( $operation );
		}
		$family_labels = Operations::family_labels();
		$family_label  = $family_labels[ $family ] ?? ( Operations::FAMILY_UNKNOWN === $family ? __( 'Unknown', 'handl-ai-connector-access-control' ) : $family );
		echo '<td class="column-operation"><code>' . esc_html( $operation ?: '—' ) . '</code>';
		if ( $is_direct_http && '' !== $host ) {
			echo '<br /><span class="description handl-aicac-shadow-host" style="font-size:11px;"><code>' . esc_html( $host ) . '</code></span>';
		} elseif ( '' !== $family ) {
			echo '<br /><span class="description handl-aicac-family-label">' . esc_html( $family_label ) . '</span>';
		}
		echo '</td>';
		echo '<td class="column-provider"><code>' . esc_html( $provider ?: '—' ) . '</code>';
		if ( $is_direct_http ) {
			echo '<br /><span class="description" style="font-size:11px;">' . esc_html__( 'direct HTTP', 'handl-ai-connector-access-control' ) . '</span>';
		}
		if ( ! empty( $row['pin_matched'] ) ) {
			$pp = isset( $row['pin_provider'] ) ? (string) $row['pin_provider'] : '';
			$pm = isset( $row['pin_model'] ) ? (string) $row['pin_model'] : '';
			echo '<br /><span class="description handl-aicac-pin-matched" style="font-size:11px;">';
			echo esc_html__( 'model route matched', 'handl-ai-connector-access-control' );
			if ( '' !== $pp || '' !== $pm ) {
				echo ' → <code>' . esc_html( $pp . ( '' !== $pp && '' !== $pm ? '/' : '' ) . $pm ) . '</code>';
			}
			echo '</span>';
		}
		if ( ! empty( $row['model_forced'] ) ) {
			$fp = isset( $row['forced_provider'] ) ? (string) $row['forced_provider'] : '';
			$fm = isset( $row['forced_model'] ) ? (string) $row['forced_model'] : '';
			echo '<br /><span class="description handl-aicac-forced-label" style="font-size:11px;">' . esc_html__( 'model routed', 'handl-ai-connector-access-control' );
			if ( '' !== $fp || '' !== $fm ) {
				echo ' → <code>' . esc_html( trim( $fp . '/' . $fm, '/' ) ) . '</code>';
			}
			$src = isset( $row['forced_source'] ) ? (string) $row['forced_source'] : '';
			if ( 'unattributed' === $src ) {
				echo ' <em>' . esc_html__( '(rule for unknown plugins)', 'handl-ai-connector-access-control' ) . '</em>';
			}
			echo '</span>';
		} elseif ( ! empty( $row['model_force_unforced'] ) || ( isset( $row['model_force_skipped'] ) && 'unattributed' === (string) $row['model_force_skipped'] ) ) {
			echo '<br /><span class="description handl-aicac-unforced-label" style="font-size:11px;">' . esc_html__( 'not routed (plugin unknown)', 'handl-ai-connector-access-control' ) . '</span>';
		}
		// Observability honesty: inferred provider/model must not look like builder-set facts.
		if ( $model_inferred && $provider ) {
			echo '<br /><span class="description handl-aicac-inferred-label" style="font-size:11px;">' . esc_html__( 'inferred', 'handl-ai-connector-access-control' ) . '</span>';
		}
		echo '</td>';
		echo '<td class="column-model"><code>' . esc_html( $model ?: '—' ) . '</code>';
		if ( $model_inferred && $model ) {
			echo '<br /><span class="description handl-aicac-inferred-label" style="font-size:11px;">' . esc_html__( 'inferred', 'handl-ai-connector-access-control' ) . '</span>';
		}
		echo '</td>';
		echo '<td class="column-tokens">' . $this->render_token_count( $input_tokens ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<td class="column-tokens">' . $this->render_token_count( $output_tokens, $thought_tokens ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<td class="column-tokens">' . $this->render_est_cost_cell( $input_tokens, $output_tokens, $policy, $provider ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<td>';
		if ( $plugin ) {
			$profile_url = Plugin_Profile::profile_url( $plugin );
			if ( '' !== $profile_url ) {
				echo '<strong><a href="' . esc_url( $profile_url ) . '">' . esc_html( $plugin_label ) . '</a></strong>';
			} else {
				echo '<strong>' . esc_html( $plugin_label ) . '</strong>';
			}
			echo '<br /><code>' . esc_html( $plugin ) . '</code>';
			if ( $file ) {
				echo '<br /><span class="description" style="font-size:11px;">' . esc_html( wp_basename( $file ) ) . '</span>';
			}
		} else {
			echo '<span class="handl-aicac-muted">' . esc_html__( 'unknown', 'handl-ai-connector-access-control' ) . '</span>';
		}
		echo '</td>';
		echo '<td>' . $this->render_prompt_cell( $prompt, $row ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '</td>';
		echo '<td>';
		if ( $user_id > 0 ) {
			$user      = get_userdata( $user_id );
			$edit_link = get_edit_user_link( $user_id );
			if ( $user && is_string( $edit_link ) && '' !== $edit_link ) {
				echo '<a href="' . esc_url( $edit_link ) . '">' . esc_html( $user->display_name ) . '</a>';
			} elseif ( $user ) {
				echo esc_html( $user->display_name );
			} else {
				echo esc_html( sprintf( '#%d', $user_id ) );
			}
			// M4 keeps first user_id on collapse; same "first of N" honesty as path (F6 known limit).
			$user_cluster = $is_direct_http && isset( $row['count'] ) ? (int) $row['count'] : 1;
			if ( $is_direct_http && $user_cluster > 1 ) {
				echo '<br /><span class="description" style="font-size:11px;">';
				echo esc_html(
					sprintf(
						/* translators: %d: total HTTP calls in this cluster */
						_n( 'first of %d', 'first of %d', $user_cluster, 'handl-ai-connector-access-control' ),
						$user_cluster
					)
				);
				echo '</span>';
			}
		} else {
			echo '<span class="handl-aicac-muted">—</span>';
		}
		echo '</td>';
		echo '<td><code>' . esc_html( $uri ?: '—' ) . '</code>';
		// M4 keeps the first path on collapse; label it when the cluster has multiple calls.
		if ( $is_direct_http && '' !== $uri ) {
			$uri_cluster = isset( $row['count'] ) ? (int) $row['count'] : 1;
			if ( $uri_cluster > 1 ) {
				echo '<br /><span class="description" style="font-size:11px;">';
				echo esc_html(
					sprintf(
						/* translators: %d: total HTTP calls in this cluster */
						_n( 'first of %d', 'first of %d', $uri_cluster, 'handl-ai-connector-access-control' ),
						$uri_cluster
					)
				);
				echo '</span>';
			}
		}
		echo '</td>';
		echo '<td class="column-actions handl-aicac-quick-actions">';
		// direct_http is not governed by plugin Allow/Deny rules (AI Client only).
		// Opt-in Direct AI connections block is separate (Rules → Direct AI connections).
		if ( $is_direct_http ) {
			echo '<span class="description handl-aicac-not-governable" style="font-size:11px;">';
			if ( 'deny' === $decision ) {
				echo esc_html__( 'outside AI Client; blocked', 'handl-ai-connector-access-control' );
			} elseif ( 'allow' === $decision && ! empty( $row['shadow_exception'] ) ) {
				echo esc_html__( 'outside AI Client; allowed by exception', 'handl-ai-connector-access-control' );
			} else {
				echo esc_html__( 'outside AI Client; observed, not blocked', 'handl-ai-connector-access-control' );
			}
			echo '</span>';
		} elseif ( $plugin ) {
			$this->render_quick_rule_buttons( $plugin, $log_filters );
			$this->render_graduate_action( $row, $policy, $plugins );
		} else {
			echo '<span class="handl-aicac-muted">—</span>';
		}
		echo '</td>';
		echo '</tr>';
	}

	/**
	 * AICAC-GRADUATE: Create rule from this call (or already-covered status).
	 *
	 * @param array<string,mixed>               $row
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private function render_graduate_action( array $row, array $policy, array $plugins ): void {
		$proposal = Graduate::proposal_from_log_row( $row );
		if ( null === $proposal ) {
			return;
		}

		$coverage = Graduate::coverage_for( $policy, $proposal );
		echo '<div class="handl-aicac-graduate-action" style="margin-top:4px;">';
		if ( null !== $coverage ) {
			echo '<span class="description" style="font-size:11px;">';
			echo esc_html( Graduate::coverage_label( $coverage, $plugins ) );
			echo '</span>';
		} else {
			echo '<a class="button button-small" href="' . esc_url( Graduate::rules_url( $proposal ) ) . '">';
			echo esc_html__( 'Create rule from this call', 'handl-ai-connector-access-control' );
			echo '</a>';
		}
		echo '</div>';
	}

	/**
	 * Plugin-level graduate link (Dashboard / Suggested rules).
	 *
	 * @param array<string,mixed>               $policy
	 * @param array<string,array<string,mixed>> $plugins
	 */
	private function render_graduate_plugin_action( string $plugin_basename, array $policy, array $plugins ): void {
		$proposal = Graduate::proposal_from_plugin( $plugin_basename );
		if ( null === $proposal ) {
			return;
		}

		$coverage = Graduate::coverage_for( $policy, $proposal );
		echo '<div class="handl-aicac-graduate-action" style="margin-top:4px;">';
		if ( null !== $coverage ) {
			echo '<span class="description" style="font-size:11px;">';
			echo esc_html( Graduate::coverage_label( $coverage, $plugins ) );
			echo '</span>';
		} else {
			echo '<a class="button button-small" href="' . esc_url( Graduate::rules_url( $proposal ) ) . '">';
			echo esc_html__( 'Create rule for this plugin', 'handl-ai-connector-access-control' );
			echo '</a>';
		}
		echo '</div>';
	}

	private function render_token_count( ?int $count, ?int $thought_tokens = null ): string {
		if ( null === $count ) {
			return '<span class="handl-aicac-muted">—</span>';
		}

		$html = '<span class="handl-aicac-token-count">' . esc_html( number_format_i18n( $count ) ) . '</span>';

		if ( null !== $thought_tokens && $thought_tokens > 0 ) {
			$html .= '<br /><span class="description" style="font-size:11px;">' . esc_html(
				sprintf(
					/* translators: %s: formatted thought token count */
					__( 'Reasoning: %s', 'handl-ai-connector-access-control' ),
					number_format_i18n( $thought_tokens )
				)
			) . '</span>';
		}

		return $html;
	}

	/**
	 * Estimated USD cell — observability only; never enforcement.
	 *
	 * @param array<string,mixed> $policy
	 * @param string              $provider Log-row provider id (may be empty).
	 */
	private function render_est_cost_cell( ?int $input_tokens, ?int $output_tokens, array $policy, string $provider = '' ): string {
		if ( null === $input_tokens && null === $output_tokens ) {
			return '<span class="handl-aicac-muted">—</span>';
		}

		$usd = Cost::estimate_usd( $input_tokens, $output_tokens, Cost::rates_from_policy( $policy, $provider ) );
		if ( null === $usd ) {
			return '<span class="handl-aicac-muted">—</span>';
		}

		$using_defaults = Cost::using_default_rates( $policy );
		$title          = $using_defaults
			? __( 'Estimate based on tokens and built-in placeholder rates. Not a bill. Set your own rates under Estimated spend rates.', 'handl-ai-connector-access-control' )
			: __( 'Estimate based on tokens and your saved rates. Not a bill.', 'handl-ai-connector-access-control' );
		$label          = $using_defaults
			? __( 'estimate using default rates', 'handl-ai-connector-access-control' )
			: __( 'estimate using custom rates', 'handl-ai-connector-access-control' );

		return '<span class="handl-aicac-est-cost" title="' . esc_attr( $title ) . '">'
			. esc_html( Cost::format_usd( $usd ) )
			. '<br /><span class="description" style="font-size:11px;">' . esc_html( $label ) . '</span>'
			. '</span>';
	}

	/**
	 * Human label for denial_reason codes (loud denials — admin blames this plugin).
	 */
	private function format_denial_reason_label( string $reason ): string {
		$map = array(
			'kill_switch'         => __( 'Blocked by HandL: emergency stop', 'handl-ai-connector-access-control' ),
			'role'                => __( 'Blocked by HandL: role not allowed', 'handl-ai-connector-access-control' ),
			'plugin'              => __( 'Blocked by HandL: plugin rule', 'handl-ai-connector-access-control' ),
			'capability_family'   => __( 'Blocked by HandL: AI type rule', 'handl-ai-connector-access-control' ),
			'unknown_operation'   => __( 'Blocked by HandL: unknown operation rule', 'handl-ai-connector-access-control' ),
			'tool_armed'          => __( 'Blocked by HandL: prompt offered a blocked tool', 'handl-ai-connector-access-control' ),
			// Legacy reason code from pre-rename log rows.
			'ability_armed'       => __( 'Blocked by HandL: prompt offered a blocked tool', 'handl-ai-connector-access-control' ),
		);
		return $map[ $reason ] ?? sprintf(
			/* translators: %s: internal denial reason code */
			__( 'Blocked by HandL: %s', 'handl-ai-connector-access-control' ),
			$reason
		);
	}

	private function render_decision_badge( string $decision ): string {
		if ( 'allow' === $decision ) {
			return '<span class="handl-aicac-badge handl-aicac-badge--allow">' . esc_html__( 'allow', 'handl-ai-connector-access-control' ) . '</span>';
		}
		if ( 'deny' === $decision ) {
			return '<span class="handl-aicac-badge handl-aicac-badge--deny">' . esc_html__( 'deny', 'handl-ai-connector-access-control' ) . '</span>';
		}
		if ( 'observe' === $decision ) {
			return '<span class="handl-aicac-badge handl-aicac-badge--observe">' . esc_html__( 'observe', 'handl-ai-connector-access-control' ) . '</span>';
		}
		return '<span class="handl-aicac-muted">' . esc_html( $decision ?: '—' ) . '</span>';
	}

	/**
	 * @param array<string,mixed> $row
	 */
	private function render_prompt_cell( string $prompt, array $row ): string {
		if ( '' === $prompt ) {
			return '<span class="handl-aicac-muted">—</span>';
		}

		$config_note = '';
		if ( ! empty( $row['config'] ) && is_array( $row['config'] ) ) {
			$parts = array();
			foreach ( $row['config'] as $key => $value ) {
				if ( 'systemInstruction' === $key ) {
					continue;
				}
				$parts[] = $key . '=' . ( is_scalar( $value ) ? (string) $value : wp_json_encode( $value ) );
			}
			if ( ! empty( $parts ) ) {
				$config_note = '<p class="description" style="margin:4px 0 0;font-size:11px;">' . esc_html( implode( ', ', $parts ) ) . '</p>';
			}
		}

		$html  = '<details class="handl-aicac-prompt-details">';
		$html .= '<summary>' . esc_html__( 'View preview', 'handl-ai-connector-access-control' ) . '</summary>';
		$html .= '<pre>' . esc_html( $prompt ) . '</pre>';
		$html .= $config_note;
		$html .= '</details>';

		return $html;
	}

	/**
	 * One-click policy presets (AICAC-PRESET / #106).
	 *
	 * @param array<string,mixed> $policy
	 */
	private function render_presets_section( array $policy, bool $show_preview ): void {
		echo '<div id="handl-aicac-presets" class="handl-aicac-presets" style="margin:0 0 1.5em;">';
		echo '<h2>' . esc_html__( 'Policy presets', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Start from a curated template. You will see every setting that would change before anything is saved. Your custom plugin rules are not cleared unless a preset says it will change them.', 'handl-ai-connector-access-control' ) . '</p>';

		$defs = Presets::definitions();
		echo '<div class="handl-aicac-preset-cards" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(14em,1fr));gap:12px;max-width:56em;">';
		foreach ( $defs as $def ) {
			$id    = (string) $def['id'];
			$active = Presets::is_active( $id, $policy );
			echo '<div class="handl-aicac-preset-card" style="border:1px solid #c3c4c7;padding:12px;background:#fff;">';
			echo '<p style="margin:0 0 6px;"><strong>' . esc_html( (string) $def['label'] ) . '</strong>';
			if ( $active ) {
				echo ' <span class="description">(' . esc_html__( 'Active', 'handl-ai-connector-access-control' ) . ')</span>';
			}
			echo '</p>';
			echo '<p class="description" style="margin:0 0 10px;">' . esc_html( (string) $def['description'] ) . '</p>';
			echo '<form method="post" style="margin:0;">';
			wp_nonce_field( 'handl_aicac_preset_preview', 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_action" value="preset_preview" />';
			echo '<input type="hidden" name="handl_aicac_tab" value="rules" />';
			echo '<input type="hidden" name="handl_aicac_preset_id" value="' . esc_attr( $id ) . '" />';
			submit_button(
				$active ? __( 'Review (already active)', 'handl-ai-connector-access-control' ) : __( 'Preview changes', 'handl-ai-connector-access-control' ),
				'secondary',
				'submit',
				false
			);
			echo '</form>';
			echo '</div>';
		}
		echo '</div>';

		if ( ! $show_preview ) {
			echo '</div>';
			return;
		}

		$user_id = get_current_user_id();
		$pending = get_transient( Presets::preview_transient_key( $user_id ) );
		if ( ! is_array( $pending ) || empty( $pending['preset_id'] ) ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'Preset preview expired or was not found. Choose a preset again.', 'handl-ai-connector-access-control' ) . '</p></div>';
			echo '</div>';
			return;
		}

		$preset_id = sanitize_key( (string) $pending['preset_id'] );
		$def       = Presets::get( $preset_id );
		$diff      = Presets::diff( $preset_id, $policy );

		echo '<div class="handl-aicac-preset-preview" style="border:1px solid #c3c4c7;padding:12px 16px;background:#fff;max-width:52em;margin-top:1em;">';
		echo '<h3>' . esc_html__( 'Preset preview', 'handl-ai-connector-access-control' ) . '</h3>';
		if ( is_array( $def ) ) {
			echo '<p><strong>' . esc_html( (string) $def['label'] ) . '</strong> — ' . esc_html( (string) $def['description'] ) . '</p>';
		}

		if ( ! empty( $diff['active'] ) ) {
			echo '<div class="notice notice-info inline"><p>' . esc_html__( 'That preset is already active. Applying it again will not change any settings.', 'handl-ai-connector-access-control' ) . '</p></div>';
			echo '<form method="post">';
			wp_nonce_field( 'handl_aicac_preset_apply_confirm', 'handl_aicac_nonce' );
			echo '<input type="hidden" name="handl_aicac_action" value="preset_apply_confirm" />';
			echo '<input type="hidden" name="handl_aicac_tab" value="rules" />';
			submit_button( __( 'Dismiss', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
			echo '</form>';
			echo '</div></div>';
			return;
		}

		if ( empty( $diff['ok'] ) ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html__( 'Could not build a preview for that preset.', 'handl-ai-connector-access-control' ) . '</p></div>';
			echo '</div></div>';
			return;
		}

		if ( ! empty( $diff['overwrites'] ) ) {
			echo '<div class="notice notice-warning inline"><p><strong>' . esc_html__( 'This preset will overwrite custom rules.', 'handl-ai-connector-access-control' ) . '</strong> ';
			echo esc_html__( 'Rows marked overwrite replace existing plugin or AI-type rules.', 'handl-ai-connector-access-control' );
			echo '</p></div>';
		}

		$rows = isset( $diff['rows'] ) && is_array( $diff['rows'] ) ? $diff['rows'] : array();
		if ( empty( $rows ) ) {
			echo '<p class="description">' . esc_html__( 'No settings would change.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped" style="margin:0.5em 0 1em;">';
			echo '<thead><tr>';
			echo '<th>' . esc_html__( 'Setting', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Current', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'New', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $rows as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				echo '<tr>';
				echo '<td>' . esc_html( (string) ( $row['label'] ?? '' ) );
				if ( ! empty( $row['overwrite'] ) ) {
					echo ' <span class="description">(' . esc_html__( 'overwrite', 'handl-ai-connector-access-control' ) . ')</span>';
				}
				echo '</td>';
				echo '<td>' . esc_html( (string) ( $row['current'] ?? '' ) ) . '</td>';
				echo '<td>' . esc_html( (string) ( $row['new'] ?? '' ) ) . '</td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '<form method="post">';
		wp_nonce_field( 'handl_aicac_preset_apply_confirm', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="preset_apply_confirm" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="rules" />';
		submit_button( __( 'Apply preset', 'handl-ai-connector-access-control' ), 'primary', 'submit', false );
		echo '</form>';
		echo '</div>';
		echo '</div>';
	}

	/**
	 * Rules-tab export / import (AICAC-102).
	 *
	 * @param array<string,mixed> $policy
	 */
	private function render_rules_transfer_section( array $policy, bool $show_preview ): void {
		echo '<hr />';
		echo '<h2>' . esc_html__( 'Export or import rules', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Download your current rules as a JSON file, or upload a previous export. Importing replaces all current access-control settings. The activity log is not included.', 'handl-ai-connector-access-control' ) . '</p>';

		echo '<form method="post" style="margin-bottom:1em;">';
		wp_nonce_field( 'handl_aicac_export_rules', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="export_rules" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="rules" />';
		submit_button( __( 'Download rules (JSON)', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
		echo '</form>';

		echo '<form method="post" enctype="multipart/form-data" style="margin-bottom:1em;">';
		wp_nonce_field( 'handl_aicac_import_rules', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="import_rules_preview" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="rules" />';
		echo '<p>';
		echo '<label for="handl-aicac-import-file"><strong>' . esc_html__( 'Import rules (JSON)', 'handl-ai-connector-access-control' ) . '</strong></label><br />';
		echo '<input type="file" id="handl-aicac-import-file" name="handl_aicac_import_file" accept="application/json,.json" required />';
		echo '</p>';
		echo '<p class="description">' . esc_html__( 'Choose a JSON file up to 1 MB. You can preview added, changed, and removed rules before anything changes.', 'handl-ai-connector-access-control' ) . '</p>';
		submit_button( __( 'Upload and preview', 'handl-ai-connector-access-control' ), 'secondary', 'submit', false );
		echo '</form>';

		if ( ! $show_preview ) {
			return;
		}

		$user_id = get_current_user_id();
		$pending = get_transient( Policy_Transfer::preview_transient_key( $user_id ) );
		if ( ! is_array( $pending ) || ! isset( $pending['policy'] ) || ! is_array( $pending['policy'] ) ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'Import preview expired or was not found. Upload the file again.', 'handl-ai-connector-access-control' ) . '</p></div>';
			return;
		}

		$incoming = $pending['policy'];
		$ignored  = isset( $pending['ignored'] ) && is_array( $pending['ignored'] ) ? $pending['ignored'] : array();
		$diff     = Policy_Transfer::diff_policies( $policy, $incoming );
		$lines    = Policy_Transfer::format_diff_lines( $diff );

		echo '<div class="handl-aicac-import-preview" style="border:1px solid #c3c4c7;padding:12px 16px;background:#fff;max-width:52em;">';
		echo '<h3>' . esc_html__( 'Import preview', 'handl-ai-connector-access-control' ) . '</h3>';
		echo '<p><strong>' . esc_html__( 'Mode: replace all rules', 'handl-ai-connector-access-control' ) . '</strong> — ';
		echo esc_html__( 'Confirming this import replaces all current rules with the uploaded settings. The same safety checks used when saving Rules will run first.', 'handl-ai-connector-access-control' );
		echo '</p>';

		if ( ! empty( $ignored ) ) {
			echo '<div class="notice notice-warning inline"><p>';
			echo esc_html__( 'These fields from a newer export will be ignored:', 'handl-ai-connector-access-control' );
			echo ' <code>' . esc_html( implode( ', ', array_map( 'strval', $ignored ) ) ) . '</code>';
			echo '</p></div>';
		}

		echo '<ul style="margin-left:1.2em;list-style:disc;">';
		foreach ( $lines as $line ) {
			echo '<li>' . esc_html( $line ) . '</li>';
		}
		echo '</ul>';

		$empty_ruleset = empty( $incoming['plugins'] )
			&& empty( $incoming['operations'] )
			&& empty( $incoming['denied_tools'] )
			&& empty( $incoming['denied_abilities'] )
			&& empty( $incoming['model_force_plugins'] )
			&& empty( $incoming['kill_switch'] );
		if ( $empty_ruleset ) {
			echo '<div class="notice notice-info inline"><p>' . esc_html__( 'This file contains no saved plugin rules, AI type settings, blocked tools, model routes, or Emergency stop settings. Importing it is a valid way to reset these settings.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}

		echo '<form method="post">';
		wp_nonce_field( 'handl_aicac_import_rules_confirm', 'handl_aicac_nonce' );
		echo '<input type="hidden" name="handl_aicac_action" value="import_rules_confirm" />';
		echo '<input type="hidden" name="handl_aicac_tab" value="rules" />';
		submit_button( __( 'Confirm and replace rules', 'handl-ai-connector-access-control' ), 'primary', 'submit', false );
		echo '</form>';
		echo '</div>';
	}

	/**
	 * Stream current policy as a JSON download (AC1).
	 */
	private function handle_export_rules(): void {
		$this->require_admin_mutation( 'handl_aicac_export_rules' );

		$policy  = Policy::get_policy();
		$export  = Policy_Transfer::build_export(
			$policy,
			defined( 'HANDL_AICAC_VERSION' ) ? (string) HANDL_AICAC_VERSION : '',
			gmdate( 'c' )
		);
		$payload = Policy_Transfer::encode_export( $export );
		$filename = 'handl-aicac-rules-' . gmdate( 'Ymd-His' ) . '.json';

		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Content-Length: ' . (string) strlen( $payload ) );
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- raw JSON download body.
		echo $payload;
		exit;
	}

	/**
	 * Stream the currently filtered retained audit log as CSV (AICAC-26).
	 *
	 * Capability + nonce are enforced by maybe_handle_file_downloads() on admin_init
	 * (before admin HTML is buffered). Exports every matching retained row
	 * (≤ log_limit / 1000), not the 50-row UI page.
	 */
	private function handle_export_log(): void {
		$policy  = Policy::get_policy();
		$log     = get_option( Plugin::LOG_OPTION_KEY );
		$log     = is_array( $log ) ? $log : array();
		$plugins = function_exists( 'get_plugins' ) ? get_plugins() : array();
		if ( ! is_array( $plugins ) ) {
			$plugins = array();
		}

		$user_labels = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) || empty( $row['user_id'] ) ) {
				continue;
			}
			$uid = (int) $row['user_id'];
			if ( $uid < 1 || isset( $user_labels[ $uid ] ) ) {
				continue;
			}
			$user = get_userdata( $uid );
			$user_labels[ $uid ] = ( $user && isset( $user->display_name ) )
				? (string) $user->display_name
				: '';
		}

		$payload  = Audit_Export::build_csv( $log, $this->log_filters, $plugins, $policy, $user_labels );
		$filename = 'handl-aicac-audit-' . gmdate( 'Ymd-His' ) . '.csv';

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Content-Length: ' . (string) strlen( $payload ) );
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- raw CSV download body.
		echo $payload;
		exit;
	}

/**
	 * Stream a printable audit evidence report (AICAC-EVIDENCE / #118).
	 *
	 * Capability + nonce enforced by maybe_handle_file_downloads() on admin_init.
	 */
	private function handle_export_audit_report(): void {
		$window = isset( $_POST['handl_aicac_report_window'] )
			? Rest::sanitize_window( wp_unslash( (string) $_POST['handl_aicac_report_window'] ) )
			: Rest::DEFAULT_WINDOW;

		$policy  = Policy::get_policy();
		$log     = Policy::get_retained_log();
		$plugins = function_exists( 'get_plugins' ) ? get_plugins() : array();
		if ( ! is_array( $plugins ) ) {
			$plugins = array();
		}

		$data    = Audit_Evidence::build_report_data( $policy, $log, $window, time(), $plugins );
		$payload = Audit_Evidence::build_html( $data );
		$filename = 'handl-aicac-audit-report-' . gmdate( 'Ymd-His' ) . '.html';

		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		header( 'Content-Disposition: inline; filename="' . $filename . '"' );
		header( 'Content-Length: ' . (string) strlen( $payload ) );
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped HTML document body.
		echo $payload;
		exit;
	}

/**
	 * Stash preset id for confirmation screen (no policy write).
	 */
	private function handle_preset_preview(): void {
		$this->require_admin_mutation( 'handl_aicac_preset_preview' );

		$redirect_base = array(
			'page'            => 'handl-ai-connector-access-control',
			'handl_aicac_tab' => 'rules',
		);

		$preset_id = isset( $_POST['handl_aicac_preset_id'] )
			? sanitize_key( wp_unslash( (string) $_POST['handl_aicac_preset_id'] ) )
			: '';
		if ( null === Presets::get( $preset_id ) ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_preset' => 'error' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}

		set_transient(
			Presets::preview_transient_key( get_current_user_id() ),
			array( 'preset_id' => $preset_id ),
			Presets::PREVIEW_TTL
		);

		wp_safe_redirect(
			add_query_arg(
				array_merge( $redirect_base, array( 'handl_aicac_preset_preview' => '1' ) ),
				admin_url( 'options-general.php' )
			)
		);
		exit;
	}

/**
	 * Apply pending preset (or no-op when already active) via Policy::save_policy.
	 */
	private function handle_preset_apply_confirm(): void {
		$this->require_admin_mutation( 'handl_aicac_preset_apply_confirm' );

		$redirect_base = array(
			'page'            => 'handl-ai-connector-access-control',
			'handl_aicac_tab' => 'rules',
		);

		$key     = Presets::preview_transient_key( get_current_user_id() );
		$pending = get_transient( $key );
		delete_transient( $key );

		if ( ! is_array( $pending ) || empty( $pending['preset_id'] ) ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_preset' => 'error' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}

		$preset_id = sanitize_key( (string) $pending['preset_id'] );
		$result    = Presets::apply( $preset_id, Policy::get_policy() );
		$status    = ! empty( $result['ok'] ) ? (string) ( $result['status'] ?? 'applied' ) : 'error';

		wp_safe_redirect(
			add_query_arg(
				array_merge(
					$redirect_base,
					array(
						'handl_aicac_preset'    => $status,
						'handl_aicac_preset_id' => $preset_id,
					)
				),
				admin_url( 'options-general.php' )
			)
		);
		exit;
	}

	/**
	 * Validate upload and stash preview; no policy write (AC2/AC4).
	 */
	private function handle_import_rules_preview(): void {
		$this->require_admin_mutation( 'handl_aicac_import_rules' );

		$redirect_base = array(
			'page'            => 'handl-ai-connector-access-control',
			'handl_aicac_tab' => 'rules',
		);

		if ( empty( $_FILES['handl_aicac_import_file'] ) || ! is_array( $_FILES['handl_aicac_import_file'] ) ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => 'no_file' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}

		$file = $_FILES['handl_aicac_import_file'];
		$err  = isset( $file['error'] ) ? (int) $file['error'] : UPLOAD_ERR_NO_FILE;
		if ( UPLOAD_ERR_NO_FILE === $err ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => 'empty' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}
		if ( UPLOAD_ERR_OK !== $err ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => 'upload_failed' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}

		$size = isset( $file['size'] ) ? (int) $file['size'] : 0;
		if ( $size <= 0 ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => 'empty' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}
		if ( $size > Policy_Transfer::MAX_UPLOAD_BYTES ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => 'too_large' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}

		$tmp = isset( $file['tmp_name'] ) ? (string) $file['tmp_name'] : '';
		if ( '' === $tmp || ! is_uploaded_file( $tmp ) ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => 'upload_failed' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local upload tmp only.
		$raw = file_get_contents( $tmp );
		if ( ! is_string( $raw ) ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => 'upload_failed' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}

		$parsed = Policy_Transfer::parse_import( $raw );
		if ( empty( $parsed['ok'] ) ) {
			$code = isset( $parsed['error'] ) ? (string) $parsed['error'] : 'invalid_json';
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => $code ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}

		$user_id = get_current_user_id();
		set_transient(
			Policy_Transfer::preview_transient_key( $user_id ),
			array(
				'policy'         => $parsed['policy'],
				'ignored'        => $parsed['ignored'],
				'plugin_version' => $parsed['plugin_version'],
				'exported_at'    => $parsed['exported_at'],
			),
			Policy_Transfer::PREVIEW_TTL
		);

		wp_safe_redirect(
			add_query_arg(
				array_merge( $redirect_base, array( 'handl_aicac_import_preview' => '1' ) ),
				admin_url( 'options-general.php' )
			)
		);
		exit;
	}

	/**
	 * Confirm pending import: full replace via Policy::save_policy (AC3).
	 */
	private function handle_import_rules_confirm(): void {
		$this->require_admin_mutation( 'handl_aicac_import_rules_confirm' );

		$redirect_base = array(
			'page'            => 'handl-ai-connector-access-control',
			'handl_aicac_tab' => 'rules',
		);

		$user_id = get_current_user_id();
		$key     = Policy_Transfer::preview_transient_key( $user_id );
		$pending = get_transient( $key );
		if ( ! is_array( $pending ) || ! isset( $pending['policy'] ) || ! is_array( $pending['policy'] ) ) {
			wp_safe_redirect(
				add_query_arg(
					array_merge( $redirect_base, array( 'handl_aicac_import_error' => 'preview_expired' ) ),
					admin_url( 'options-general.php' )
				)
			);
			exit;
		}

		$for_save = Policy_Transfer::policy_for_save( $pending['policy'] );
		Policy::save_policy( $for_save );
		delete_transient( $key );

		$args = array( 'handl_aicac_imported' => '1' );
		$ignored = isset( $pending['ignored'] ) && is_array( $pending['ignored'] ) ? $pending['ignored'] : array();
		if ( ! empty( $ignored ) ) {
			$args['handl_aicac_import_ignored'] = implode( ',', array_map( 'strval', $ignored ) );
		}

		wp_safe_redirect(
			add_query_arg(
				array_merge( $redirect_base, $args ),
				admin_url( 'options-general.php' )
			)
		);
		exit;
	}

	/**
	 * Map import error codes to admin-facing messages (AC4).
	 */
	private function import_error_message( string $code ): string {
		$messages = array(
			'empty'                => __( 'Import failed: the file was empty. Your current rules were not changed.', 'handl-ai-connector-access-control' ),
			'no_file'              => __( 'Import failed: no file was selected. Your current rules were not changed.', 'handl-ai-connector-access-control' ),
			'upload_failed'        => __( 'Import failed: the file could not be uploaded. Your current rules were not changed.', 'handl-ai-connector-access-control' ),
			'too_large'            => __( 'Import failed: the file is larger than 1 MB. Your current rules were not changed.', 'handl-ai-connector-access-control' ),
			'invalid_json'         => __( 'Import failed: the file is not valid JSON. Your current rules were not changed.', 'handl-ai-connector-access-control' ),
			'missing_required_keys'=> __( 'Import failed: the file is missing plugin_version or exported_at. Your current rules were not changed.', 'handl-ai-connector-access-control' ),
			'preview_expired'      => __( 'Import failed: the preview expired. Upload the file again. Your current rules were not changed.', 'handl-ai-connector-access-control' ),
		);

		return $messages[ $code ] ?? __( 'Import failed. Your current rules were not changed.', 'handl-ai-connector-access-control' );
	}
}

