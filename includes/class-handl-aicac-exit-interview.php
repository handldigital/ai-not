<?php
/**
 * AICAC-EXIT-INTERVIEW (#328): opt-in deactivation feedback modal.
 *
 * Plugins-screen only. Skip sends nothing. Send stores locally + emails
 * site admin and the HandL feedback inbox. Never blocks deactivation.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Opt-in exit interview on deactivate (this plugin only).
 */
final class Exit_Interview {

	public const OPTION_KEY = 'handl_aicac_exit_interview';

	public const AJAX_ACTION = 'handl_aicac_exit_interview';

	public const NONCE_ACTION = 'handl_aicac_exit_interview';

	/** HandL product-feedback copy recipient (not remote telemetry). */
	public const FEEDBACK_INBOX = 'support@handldigital.com';

	public const OTHER_MAX = 500;

	public const HISTORY_MAX = 50;

	/**
	 * Reason slug => default English label.
	 *
	 * @var array<string,string>
	 */
	public const REASONS = array(
		'testing'   => 'Just testing',
		'complex'   => 'Too complex',
		'conflict'  => 'Broke something or conflict',
		'missing'   => 'Missing a feature I need',
		'switching' => 'Switching to another tool',
		'other'     => 'Other',
	);

	/** @var self|null */
	private static $instance = null;

	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	public static function reset_for_tests(): void {
		self::$instance = null;
		delete_option( self::OPTION_KEY );
	}

	public function init(): void {
		add_action( 'wp_ajax_' . self::AJAX_ACTION, array( $this, 'handle_ajax' ) );
		if ( is_admin() ) {
			add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		}
	}

	/**
	 * Assets only on plugins.php for users who can deactivate plugins.
	 *
	 * @param string $hook_suffix Current admin page hook.
	 */
	public function enqueue( string $hook_suffix ): void {
		if ( 'plugins.php' !== $hook_suffix ) {
			return;
		}
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}
		if ( ! defined( 'HANDL_AICAC_URL' ) || ! defined( 'HANDL_AICAC_FILE' ) ) {
			return;
		}

		$basename = plugin_basename( HANDL_AICAC_FILE );
		$version  = defined( 'HANDL_AICAC_VERSION' ) ? HANDL_AICAC_VERSION : null;

		wp_enqueue_style(
			'handl-aicac-exit-interview',
			HANDL_AICAC_URL . 'assets/exit-interview.css',
			array(),
			$version
		);
		wp_enqueue_script(
			'handl-aicac-exit-interview',
			HANDL_AICAC_URL . 'assets/exit-interview.js',
			array(),
			$version,
			true
		);
		wp_localize_script(
			'handl-aicac-exit-interview',
			'handlAicacExitInterview',
			array(
				'pluginBasename' => $basename,
				'ajaxUrl'        => admin_url( 'admin-ajax.php' ),
				'action'         => self::AJAX_ACTION,
				'nonce'          => wp_create_nonce( self::NONCE_ACTION ),
				'i18n'           => array(
					'title'       => __( 'Before you go — what made you deactivate?', 'handl-ai-connector-access-control' ),
					'skip'        => __( 'Skip & deactivate', 'handl-ai-connector-access-control' ),
					'send'        => __( 'Send feedback & deactivate', 'handl-ai-connector-access-control' ),
					'otherLabel'  => __( 'Short details (optional)', 'handl-ai-connector-access-control' ),
					'otherHint'   => __( 'Required when Other is selected.', 'handl-ai-connector-access-control' ),
					'closeLabel'  => __( 'Close', 'handl-ai-connector-access-control' ),
					'reasons'     => self::reason_labels(),
				),
			)
		);
	}

	/**
	 * @return array<string,string>
	 */
	public static function reason_labels(): array {
		return array(
			'testing'   => __( 'Just testing', 'handl-ai-connector-access-control' ),
			'complex'   => __( 'Too complex', 'handl-ai-connector-access-control' ),
			'conflict'  => __( 'Broke something or conflict', 'handl-ai-connector-access-control' ),
			'missing'   => __( 'Missing a feature I need', 'handl-ai-connector-access-control' ),
			'switching' => __( 'Switching to another tool', 'handl-ai-connector-access-control' ),
			'other'     => __( 'Other', 'handl-ai-connector-access-control' ),
		);
	}

	/**
	 * Build a sanitized submission payload (unit-tested).
	 *
	 * @param mixed                $reason Raw reason slug.
	 * @param mixed                $other  Raw other text.
	 * @param array<string,mixed>  $ctx    Optional context (user_login, site_url, now).
	 * @return array{reason:string,other:string,user:string,site:string,ts:int}|null
	 */
	public static function build_payload( $reason, $other = '', array $ctx = array() ): ?array {
		$slug = sanitize_key( (string) $reason );
		if ( ! isset( self::REASONS[ $slug ] ) ) {
			return null;
		}

		$detail = '';
		if ( 'other' === $slug || '' !== trim( (string) $other ) ) {
			$detail = sanitize_textarea_field( (string) $other );
			if ( strlen( $detail ) > self::OTHER_MAX ) {
				$detail = substr( $detail, 0, self::OTHER_MAX );
			}
		}
		if ( 'other' === $slug && '' === $detail ) {
			return null;
		}

		$now  = isset( $ctx['now'] ) ? max( 0, (int) $ctx['now'] ) : time();
		$user = isset( $ctx['user_login'] )
			? sanitize_user( (string) $ctx['user_login'], true )
			: '';
		if ( '' === $user && function_exists( 'wp_get_current_user' ) ) {
			$current = wp_get_current_user();
			$user    = $current instanceof \WP_User ? (string) $current->user_login : '';
		}
		$site = isset( $ctx['site_url'] )
			? esc_url_raw( (string) $ctx['site_url'] )
			: ( function_exists( 'home_url' ) ? home_url( '/' ) : '' );

		return array(
			'reason' => $slug,
			'other'  => $detail,
			'user'   => $user,
			'site'   => $site,
			'ts'     => $now,
		);
	}

	/**
	 * Persist a submission locally (transparency; not remote telemetry).
	 *
	 * @param array{reason:string,other:string,user:string,site:string,ts:int} $payload
	 * @return list<array{reason:string,other:string,user:string,site:string,ts:int}>
	 */
	public static function store_submission( array $payload ): array {
		$state = self::sanitize_state( get_option( self::OPTION_KEY, array() ) );
		$state['submissions'][] = array(
			'reason' => $payload['reason'],
			'other'  => $payload['other'],
			'user'   => $payload['user'],
			'site'   => $payload['site'],
			'ts'     => $payload['ts'],
		);
		if ( count( $state['submissions'] ) > self::HISTORY_MAX ) {
			$state['submissions'] = array_slice( $state['submissions'], -self::HISTORY_MAX );
		}
		$state['last'] = end( $state['submissions'] ) ?: null;
		update_option( self::OPTION_KEY, $state, false );

		return $state['submissions'];
	}

	/**
	 * @param mixed $raw
	 * @return array{submissions:list<array{reason:string,other:string,user:string,site:string,ts:int}>,last:?array{reason:string,other:string,user:string,site:string,ts:int}}
	 */
	public static function sanitize_state( $raw ): array {
		$empty = array(
			'submissions' => array(),
			'last'        => null,
		);
		if ( ! is_array( $raw ) ) {
			return $empty;
		}
		$out = array();
		$rows = isset( $raw['submissions'] ) && is_array( $raw['submissions'] ) ? $raw['submissions'] : array();
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$built = self::build_payload(
				$row['reason'] ?? '',
				$row['other'] ?? '',
				array(
					'user_login' => $row['user'] ?? '',
					'site_url'   => $row['site'] ?? '',
					'now'        => isset( $row['ts'] ) ? (int) $row['ts'] : time(),
				)
			);
			if ( null !== $built ) {
				$out[] = $built;
			}
		}
		if ( count( $out ) > self::HISTORY_MAX ) {
			$out = array_slice( $out, -self::HISTORY_MAX );
		}
		$last = null;
		if ( ! empty( $out ) ) {
			$last = $out[ count( $out ) - 1 ];
		}

		return array(
			'submissions' => $out,
			'last'        => $last,
		);
	}

	/**
	 * Email site admin + HandL feedback inbox. Failures never block deactivate.
	 *
	 * @param array{reason:string,other:string,user:string,site:string,ts:int} $payload
	 */
	public static function email_submission( array $payload ): void {
		$labels = self::reason_labels();
		$label  = $labels[ $payload['reason'] ] ?? $payload['reason'];
		$when   = gmdate( 'Y-m-d H:i:s', $payload['ts'] ) . ' UTC';

		$lines = array(
			__( 'HandL AI Connector Access Control — deactivation feedback', 'handl-ai-connector-access-control' ),
			'',
			sprintf(
				/* translators: %s: reason label */
				__( 'Reason: %s', 'handl-ai-connector-access-control' ),
				$label
			),
		);
		if ( '' !== $payload['other'] ) {
			$lines[] = sprintf(
				/* translators: %s: free-text detail */
				__( 'Details: %s', 'handl-ai-connector-access-control' ),
				$payload['other']
			);
		}
		$lines[] = sprintf(
			/* translators: %s: WordPress login */
			__( 'User: %s', 'handl-ai-connector-access-control' ),
			'' !== $payload['user'] ? $payload['user'] : __( '(unknown)', 'handl-ai-connector-access-control' )
		);
		$lines[] = sprintf(
			/* translators: %s: site URL */
			__( 'Site: %s', 'handl-ai-connector-access-control' ),
			'' !== $payload['site'] ? $payload['site'] : __( '(unknown)', 'handl-ai-connector-access-control' )
		);
		$lines[] = sprintf(
			/* translators: %s: UTC timestamp */
			__( 'When: %s', 'handl-ai-connector-access-control' ),
			$when
		);
		$lines[] = '';
		$lines[] = __( 'Sent only because Send feedback & deactivate was clicked. Skip transmits nothing.', 'handl-ai-connector-access-control' );

		$body    = implode( "\n", $lines );
		$subject = sprintf(
			/* translators: %s: site host or name */
			__( '[%s] HandL AI Access deactivation feedback', 'handl-ai-connector-access-control' ),
			wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
		);

		$admin = sanitize_email( (string) get_option( 'admin_email', '' ) );
		$inbox = sanitize_email( self::FEEDBACK_INBOX );

		if ( '' !== $admin && is_email( $admin ) ) {
			Alerts::safe_wp_mail( $admin, $subject, $body );
		}
		if ( '' !== $inbox && is_email( $inbox ) && strtolower( $inbox ) !== strtolower( $admin ) ) {
			Alerts::safe_wp_mail( $inbox, $subject, $body );
		}
	}

	/**
	 * Opt-in AJAX: store + email. Always JSON-success so the UI can deactivate.
	 */
	public function handle_ajax(): void {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
		}
		check_ajax_referer( self::NONCE_ACTION, 'nonce' );

		$payload = self::build_payload(
			isset( $_POST['reason'] ) ? wp_unslash( (string) $_POST['reason'] ) : '',
			isset( $_POST['other'] ) ? wp_unslash( (string) $_POST['other'] ) : ''
		);
		if ( null === $payload ) {
			wp_send_json_error( array( 'message' => 'invalid' ), 400 );
		}

		self::store_submission( $payload );
		self::email_submission( $payload );

		wp_send_json_success(
			array(
				'stored' => true,
			)
		);
	}
}
