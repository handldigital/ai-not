<?php
/**
 * AICAC-POSTCARD (#427): outbound-exhaust audit (suggestion-only).
 *
 * The suite screens AI payloads for PII and redacts prompt previews in exports,
 * but its own alert emails and webhooks still leave the box with deny reasons,
 * spend figures, site URLs, and more. POSTCARD inventories every bundled outbound
 * sender, pairs each live destination with the content categories that sender
 * carries by design, and surfaces plain-language findings — never intercepting
 * or sampling live mail.
 *
 * Design rules:
 * - Suggestion only. Zero edits to Alerts, Policy, digests, reports, or senders.
 * - Writes confined to two own options (settings + state).
 * - Inventory runs on a throttled admin_init (and on demand from WP-CLI), never cron.
 * - Static sender → categories table is the source of truth (+ filter).
 * - Findings re-arm only on a NEW destination or NEW category pairing.
 * - Exactly one re-arming [POSTCARD] alert; body names categories only, never
 *   sample content or full addresses (destinations redacted to domain/host).
 * - Own two options. OFF by default. README-FREE.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Outbound-exhaust audit.
 */
final class Postcard {

	public const SETTINGS_OPTION = 'handl_aicac_postcard';

	public const STATE_OPTION = 'handl_aicac_postcard_state';

	public const PAGE_SLUG = 'handl-aicac-postcard';

	public const ALERT_KIND = 'postcard';

	public const FRAMING = 'report_only_never_edits_senders';

	public const POST_PRESENT  = 'handl_aicac_postcard_present';
	public const POST_ENABLED  = 'handl_aicac_postcard_enabled';
	public const POST_OUTBOUND = 'handl_aicac_postcard_outbound';

	public const ACTION_SAVE = 'handl_aicac_postcard_save';
	public const ACTION_ACK  = 'handl_aicac_postcard_ack';

	/** Admin check throttle in seconds (5 minutes). */
	public const CHECK_THROTTLE_SECONDS = 300;

	public const CHANNEL_NOTICE   = 'notice';
	public const CHANNEL_OUTBOUND = 'notice+outbound';

	public const CAT_USERNAMES         = 'usernames';
	public const CAT_DENY_REASONS      = 'deny_reasons';
	public const CAT_PROMPT_FRAGMENTS  = 'prompt_fragments';
	public const CAT_SPEND_AMOUNTS     = 'spend_amounts';
	public const CAT_KEY_FINGERPRINTS  = 'key_fingerprints';
	public const CAT_SITE_URLS         = 'site_urls';

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	/** @var list<string> */
	private static $test_notices = array();

	/** @var int|null */
	private static $test_now = null;

	/** @var array<string,mixed>|null Injected policy for tests. */
	private static $test_policy = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_print' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_ACK, array( self::class, 'handle_ack' ) );

		if ( self::is_enabled() ) {
			add_action( 'admin_init', array( self::class, 'maybe_check' ), 30 );
			add_action( 'admin_notices', array( self::class, 'maybe_render_notice' ) );
			add_action( 'network_admin_notices', array( self::class, 'maybe_render_notice' ) );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered   = false;
		self::$test_mails   = array();
		self::$test_notices = array();
		self::$test_now     = null;
		self::$test_policy  = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATE_OPTION );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	/**
	 * @return list<string>
	 */
	public static function test_notices(): array {
		return self::$test_notices;
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	/**
	 * @param array<string,mixed>|null $policy Policy or null to read live.
	 */
	public static function set_test_policy( ?array $policy ): void {
		self::$test_policy = $policy;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{enabled:bool,outbound_alert:bool}
	 */
	public static function defaults(): array {
		return array(
			'enabled'        => false,
			'outbound_alert' => false,
		);
	}

	/**
	 * @return array{enabled:bool,outbound_alert:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,outbound_alert:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return self::defaults();
		}

		return array(
			'enabled'        => ! empty( $raw['enabled'] ),
			'outbound_alert' => ! empty( $raw['outbound_alert'] ),
		);
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

	public static function is_outbound_enabled(): bool {
		$settings = self::get_settings();

		return ! empty( $settings['outbound_alert'] );
	}

	/* ---------------------------------------------------------------------
	 * State
	 * ------------------------------------------------------------------ */

	/**
	 * @return array<string,mixed>
	 */
	public static function defaults_state(): array {
		return array(
			'alerted'            => false,
			'last_check_ts'      => 0,
			'last_alert_ts'      => 0,
			'last_alert_channel' => '',
			'acknowledged'       => array(),
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw state.
	 * @return array<string,mixed>
	 */
	public static function sanitize_state( $raw ): array {
		$out = self::defaults_state();
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$out['alerted']            = ! empty( $raw['alerted'] );
		$out['last_check_ts']      = isset( $raw['last_check_ts'] ) ? max( 0, (int) $raw['last_check_ts'] ) : 0;
		$out['last_alert_ts']      = isset( $raw['last_alert_ts'] ) ? max( 0, (int) $raw['last_alert_ts'] ) : 0;
		$out['last_alert_channel'] = isset( $raw['last_alert_channel'] ) ? sanitize_key( (string) $raw['last_alert_channel'] ) : '';
		$ack                       = array();
		if ( isset( $raw['acknowledged'] ) && is_array( $raw['acknowledged'] ) ) {
			foreach ( $raw['acknowledged'] as $key ) {
				$key = sanitize_text_field( (string) $key );
				if ( '' !== $key ) {
					$ack[ $key ] = true;
				}
			}
		}
		$out['acknowledged'] = array_keys( $ack );

		return $out;
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

	public static function is_alerted(): bool {
		$state = self::get_state();

		return ! empty( $state['alerted'] );
	}

	/* ---------------------------------------------------------------------
	 * Bundled sender → content-categories table
	 * ------------------------------------------------------------------ */

	/**
	 * Category keys this audit knows about.
	 *
	 * @return list<string>
	 */
	public static function category_keys(): array {
		return array(
			self::CAT_USERNAMES,
			self::CAT_DENY_REASONS,
			self::CAT_PROMPT_FRAGMENTS,
			self::CAT_SPEND_AMOUNTS,
			self::CAT_KEY_FINGERPRINTS,
			self::CAT_SITE_URLS,
		);
	}

	public static function category_label( string $key ): string {
		$map = array(
			self::CAT_USERNAMES        => __( 'usernames', 'handl-ai-connector-access-control' ),
			self::CAT_DENY_REASONS     => __( 'deny reasons', 'handl-ai-connector-access-control' ),
			self::CAT_PROMPT_FRAGMENTS => __( 'prompt fragments', 'handl-ai-connector-access-control' ),
			self::CAT_SPEND_AMOUNTS    => __( 'spend amounts', 'handl-ai-connector-access-control' ),
			self::CAT_KEY_FINGERPRINTS => __( 'key fingerprints', 'handl-ai-connector-access-control' ),
			self::CAT_SITE_URLS        => __( 'site URLs', 'handl-ai-connector-access-control' ),
		);

		return $map[ $key ] ?? $key;
	}

	/**
	 * Bundled static inventory. Filter: handl_aicac_postcard_senders.
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function bundled_senders(): array {
		$alerts = self::page_link( 'handl-aicac' );
		if ( class_exists( Admin::class, false ) && method_exists( Admin::class, 'screen_url' ) ) {
			$alerts = (string) Admin::screen_url( 'activity' );
		}

		$rows = array(
			array(
				'id'               => 'deny_alert_email',
				'label'            => __( 'Deny alert email', 'handl-ai-connector-access-control' ),
				'channel'          => 'email',
				'cadence'          => 'immediate',
				'policy_flag'      => 'alert_on_deny',
				'categories'       => array( self::CAT_DENY_REASONS, self::CAT_SITE_URLS ),
				'has_redacted'     => false,
				'deep_link'        => $alerts,
				'suggestion'       => __( 'Review the alert recipient, or turn deny alerts off if this inbox should not see deny reasons.', 'handl-ai-connector-access-control' ),
			),
			array(
				'id'               => 'deny_alert_webhook',
				'label'            => __( 'Deny alert webhook', 'handl-ai-connector-access-control' ),
				'channel'          => 'webhook',
				'cadence'          => 'immediate',
				'policy_flag'      => 'alert_on_deny',
				'categories'       => array( self::CAT_DENY_REASONS, self::CAT_SITE_URLS ),
				'has_redacted'     => false,
				'deep_link'        => $alerts,
				'suggestion'       => __( 'Point the webhook at a host you trust for deny reasons, or clear it.', 'handl-ai-connector-access-control' ),
			),
			array(
				'id'               => 'shadow_alert_email',
				'label'            => __( 'Shadow-AI alert email', 'handl-ai-connector-access-control' ),
				'channel'          => 'email',
				'cadence'          => 'immediate',
				'policy_flag'      => 'alert_on_shadow',
				'categories'       => array( self::CAT_SITE_URLS ),
				'has_redacted'     => false,
				'deep_link'        => $alerts,
				'suggestion'       => __( 'Review the shadow-alert recipient if this mailbox should not see site URLs from observe events.', 'handl-ai-connector-access-control' ),
			),
			array(
				'id'               => 'denial_digest_email',
				'label'            => __( 'Denial digest email', 'handl-ai-connector-access-control' ),
				'channel'          => 'email',
				'cadence'          => 'digest',
				'policy_flag'      => 'alert_on_deny',
				'categories'       => array( self::CAT_DENY_REASONS, self::CAT_SITE_URLS ),
				'has_redacted'     => false,
				'deep_link'        => $alerts,
				'suggestion'       => __( 'Review the digest recipient for deny-reason exposure.', 'handl-ai-connector-access-control' ),
			),
			array(
				'id'               => 'denial_digest_webhook',
				'label'            => __( 'Denial digest webhook', 'handl-ai-connector-access-control' ),
				'channel'          => 'webhook',
				'cadence'          => 'digest',
				'policy_flag'      => 'alert_on_deny',
				'categories'       => array( self::CAT_DENY_REASONS, self::CAT_SITE_URLS ),
				'has_redacted'     => false,
				'deep_link'        => $alerts,
				'suggestion'       => __( 'Review the webhook host for batched deny-reason posts.', 'handl-ai-connector-access-control' ),
			),
			array(
				'id'               => 'governance_digest',
				'label'            => __( 'Governance digest email', 'handl-ai-connector-access-control' ),
				'channel'          => 'email',
				'cadence'          => 'weekly',
				'policy_flag'      => 'governance_digest_enabled',
				'categories'       => array( self::CAT_SPEND_AMOUNTS, self::CAT_SITE_URLS ),
				'has_redacted'     => false,
				'deep_link'        => $alerts,
				'suggestion'       => __( 'Review the digest recipient for weekly spend and site URL exposure.', 'handl-ai-connector-access-control' ),
			),
			array(
				'id'               => 'weekly_report',
				'label'            => __( 'Weekly report email', 'handl-ai-connector-access-control' ),
				'channel'          => 'email',
				'cadence'          => 'weekly',
				'policy_flag'      => 'weekly_report_enabled',
				'categories'       => array( self::CAT_SPEND_AMOUNTS, self::CAT_DENY_REASONS ),
				'has_redacted'     => false,
				'deep_link'        => $alerts,
				'suggestion'       => __( 'Review the weekly-report recipient for spend and block totals.', 'handl-ai-connector-access-control' ),
			),
			array(
				'id'               => 'monthly_report',
				'label'            => __( 'Monthly report email', 'handl-ai-connector-access-control' ),
				'channel'          => 'email',
				'cadence'          => 'monthly',
				'policy_flag'      => 'monthly_report_enabled',
				'categories'       => array( self::CAT_SPEND_AMOUNTS, self::CAT_SITE_URLS ),
				'has_redacted'     => false,
				'deep_link'        => $alerts,
				'suggestion'       => __( 'Review the monthly-report recipient for spend figures in the attached audit report.', 'handl-ai-connector-access-control' ),
			),
			array(
				'id'               => 'policy_backup',
				'label'            => __( 'Policy backup email', 'handl-ai-connector-access-control' ),
				'channel'          => 'email',
				'cadence'          => 'weekly',
				'policy_flag'      => 'policy_backup_email_enabled',
				'categories'       => array( self::CAT_KEY_FINGERPRINTS, self::CAT_SITE_URLS ),
				'has_redacted'     => false,
				'deep_link'        => $alerts,
				'suggestion'       => __( 'Review the policy-backup recipient — the JSON backup can include key material fingerprints and site identity.', 'handl-ai-connector-access-control' ),
			),
			array(
				'id'               => 'spend_threshold',
				'label'            => __( 'Spend-threshold alert email', 'handl-ai-connector-access-control' ),
				'channel'          => 'email',
				'cadence'          => 'on_threshold',
				'policy_flag'      => 'spend_threshold',
				'categories'       => array( self::CAT_SPEND_AMOUNTS, self::CAT_SITE_URLS ),
				'has_redacted'     => false,
				'deep_link'        => $alerts,
				'suggestion'       => __( 'Review the alert recipient for spend-amount exposure.', 'handl-ai-connector-access-control' ),
			),
			array(
				'id'               => 'anomaly_alert',
				'label'            => __( 'Anomaly alert email / webhook', 'handl-ai-connector-access-control' ),
				'channel'          => 'both',
				'cadence'          => 'on_anomaly',
				'policy_flag'      => 'anomaly_alert_enabled',
				'categories'       => array( self::CAT_SPEND_AMOUNTS, self::CAT_SITE_URLS ),
				'has_redacted'     => false,
				'deep_link'        => $alerts,
				'suggestion'       => __( 'Review anomaly alert recipients and the webhook host for spend and site URL exposure.', 'handl-ai-connector-access-control' ),
			),
			array(
				'id'               => 'pii_warn',
				'label'            => __( 'PII-WARN alert email / webhook', 'handl-ai-connector-access-control' ),
				'channel'          => 'both',
				'cadence'          => 'on_hit',
				'policy_flag'      => 'pii_warn',
				'categories'       => array( self::CAT_PROMPT_FRAGMENTS, self::CAT_SITE_URLS ),
				'has_redacted'     => true,
				'deep_link'        => $alerts,
				'suggestion'       => __( 'Prefer that sender\'s redacted mode where available, or review who receives PII category alerts.', 'handl-ai-connector-access-control' ),
			),
			array(
				'id'               => 'latency_alert',
				'label'            => __( 'Latency p95 alert email / webhook', 'handl-ai-connector-access-control' ),
				'channel'          => 'both',
				'cadence'          => 'on_threshold',
				'policy_flag'      => 'latency',
				'categories'       => array( self::CAT_SITE_URLS ),
				'has_redacted'     => false,
				'deep_link'        => $alerts,
				'suggestion'       => __( 'Review latency alert recipients for site URL exposure.', 'handl-ai-connector-access-control' ),
			),
		);

		/**
		 * Filter the POSTCARD outbound-sender inventory.
		 *
		 * @param list<array<string,mixed>> $rows Sender rows.
		 */
		$filtered = apply_filters( 'handl_aicac_postcard_senders', $rows );
		if ( ! is_array( $filtered ) ) {
			return $rows;
		}

		$out = array();
		foreach ( $filtered as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$id = isset( $row['id'] ) ? sanitize_key( (string) $row['id'] ) : '';
			if ( '' === $id ) {
				continue;
			}
			$cats = array();
			if ( isset( $row['categories'] ) && is_array( $row['categories'] ) ) {
				foreach ( $row['categories'] as $cat ) {
					$cat = sanitize_key( (string) $cat );
					if ( in_array( $cat, self::category_keys(), true ) ) {
						$cats[] = $cat;
					}
				}
			}
			$out[] = array(
				'id'           => $id,
				'label'        => isset( $row['label'] ) ? sanitize_text_field( (string) $row['label'] ) : $id,
				'channel'      => isset( $row['channel'] ) ? sanitize_key( (string) $row['channel'] ) : 'email',
				'cadence'      => isset( $row['cadence'] ) ? sanitize_key( (string) $row['cadence'] ) : '',
				'policy_flag'  => isset( $row['policy_flag'] ) ? sanitize_key( (string) $row['policy_flag'] ) : '',
				'categories'   => array_values( array_unique( $cats ) ),
				'has_redacted' => ! empty( $row['has_redacted'] ),
				'deep_link'    => isset( $row['deep_link'] ) ? esc_url_raw( (string) $row['deep_link'] ) : '',
				'suggestion'   => isset( $row['suggestion'] ) ? sanitize_text_field( (string) $row['suggestion'] ) : '',
			);
		}

		return $out;
	}

	/* ---------------------------------------------------------------------
	 * Destination resolution (guarded reads only)
	 * ------------------------------------------------------------------ */

	/**
	 * @return array<string,mixed>
	 */
	public static function resolve_policy(): array {
		if ( null !== self::$test_policy ) {
			return self::$test_policy;
		}
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' ) ) {
			$policy = Policy::get_policy();
			return is_array( $policy ) ? $policy : array();
		}

		return array();
	}

	/**
	 * @param array<string,mixed> $policy Policy.
	 */
	public static function resolve_email( array $policy ): string {
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
			return (string) Alerts::resolve_email( $policy );
		}
		$email = isset( $policy['alert_email'] ) ? sanitize_email( (string) $policy['alert_email'] ) : '';
		if ( '' === $email ) {
			$email = sanitize_email( (string) get_option( 'admin_email' ) );
		}

		return $email;
	}

	/**
	 * @param array<string,mixed> $policy Policy.
	 */
	public static function resolve_webhook( array $policy ): string {
		if ( class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			return (string) Alerts::resolve_webhook( $policy );
		}

		return '';
	}

	/**
	 * @param array<string,mixed> $policy Policy.
	 * @param array<string,mixed> $sender Sender row.
	 */
	public static function sender_is_live( array $policy, array $sender ): bool {
		$flag = (string) ( $sender['policy_flag'] ?? '' );
		switch ( $flag ) {
			case 'alert_on_deny':
				return ! empty( $policy['alert_on_deny'] );
			case 'alert_on_shadow':
				return ! empty( $policy['alert_on_shadow'] );
			case 'governance_digest_enabled':
				if ( class_exists( Governance_Digest::class, false ) && method_exists( Governance_Digest::class, 'is_active' ) ) {
					return (bool) Governance_Digest::is_active( $policy );
				}
				return ! empty( $policy['governance_digest_enabled'] );
			case 'weekly_report_enabled':
				if ( class_exists( Weekly_Report::class, false ) && method_exists( Weekly_Report::class, 'is_active' ) ) {
					return (bool) Weekly_Report::is_active( $policy );
				}
				return ! empty( $policy['weekly_report_enabled'] );
			case 'monthly_report_enabled':
				if ( class_exists( Monthly_Report::class, false ) && method_exists( Monthly_Report::class, 'is_active' ) ) {
					return (bool) Monthly_Report::is_active( $policy );
				}
				return ! empty( $policy['monthly_report_enabled'] );
			case 'policy_backup_email_enabled':
				if ( class_exists( Policy_Backup::class, false ) && method_exists( Policy_Backup::class, 'is_enabled' ) ) {
					return (bool) Policy_Backup::is_enabled( $policy );
				}
				return ! empty( $policy['policy_backup_email_enabled'] );
			case 'spend_threshold':
				if ( class_exists( Spend_Threshold::class, false ) && method_exists( Spend_Threshold::class, 'has_any_threshold' ) ) {
					return (bool) Spend_Threshold::has_any_threshold( $policy );
				}
				return false;
			case 'anomaly_alert_enabled':
				return ! empty( $policy['anomaly_alert_enabled'] );
			case 'pii_warn':
				if ( class_exists( Pii_Warn::class, false ) && method_exists( Pii_Warn::class, 'sanitize_plugin_modes' ) ) {
					$map = Pii_Warn::sanitize_plugin_modes( $policy['pii_screen'] ?? array() );
					foreach ( $map as $mode ) {
						if ( Pii_Warn::MODE_OFF !== $mode ) {
							return true;
						}
					}
				}
				return false;
			case 'latency':
				if ( class_exists( Latency::class, false ) && method_exists( Latency::class, 'is_alert_enabled' ) ) {
					return (bool) Latency::is_alert_enabled( $policy );
				}
				return ! empty( $policy['latency_alert_enabled'] );
			default:
				return false;
		}
	}

	public static function email_domain( string $email ): string {
		$at = strrpos( $email, '@' );
		if ( false === $at || $at < 1 ) {
			return '';
		}

		return strtolower( substr( $email, $at + 1 ) );
	}

	public static function url_host( string $url ): string {
		$parts = parse_url( trim( $url ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- host only.
		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			return '';
		}

		return strtolower( (string) $parts['host'] ) . ( ! empty( $parts['port'] ) ? ':' . (int) $parts['port'] : '' );
	}

	public static function page_link( string $slug ): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) admin_url( 'admin.php?page=' . $slug );
	}

	/**
	 * Live destinations for a sender (empty when not configured / not live).
	 *
	 * @param array<string,mixed> $policy Policy.
	 * @param array<string,mixed> $sender Sender row.
	 * @return list<array{kind:string,key:string,display:string}>
	 */
	public static function destinations_for( array $policy, array $sender ): array {
		if ( ! self::sender_is_live( $policy, $sender ) ) {
			return array();
		}
		$channel = (string) ( $sender['channel'] ?? 'email' );
		$out     = array();

		if ( 'email' === $channel || 'both' === $channel ) {
			$email = self::resolve_email( $policy );
			if ( 'governance_digest' === (string) ( $sender['id'] ?? '' )
				&& class_exists( Governance_Digest::class, false )
				&& method_exists( Governance_Digest::class, 'resolve_email' ) ) {
				$email = (string) Governance_Digest::resolve_email( $policy );
			}
			$domain = self::email_domain( $email );
			if ( '' !== $domain ) {
				$out[] = array(
					'kind'    => 'email',
					'key'     => $domain,
					'display' => '@' . $domain,
				);
			}
		}

		if ( 'webhook' === $channel || 'both' === $channel ) {
			$webhook = self::resolve_webhook( $policy );
			$host    = self::url_host( $webhook );
			if ( '' !== $host ) {
				$out[] = array(
					'kind'    => 'webhook',
					'key'     => $host,
					'display' => $host,
				);
			}
		}

		return $out;
	}

	/* ---------------------------------------------------------------------
	 * Inventory + findings
	 * ------------------------------------------------------------------ */

	/**
	 * Pairing key for acknowledge / re-arm.
	 */
	public static function pairing_key( string $sender_id, string $dest_kind, string $dest_key, string $category ): string {
		return sanitize_key( $sender_id ) . '|' . sanitize_key( $dest_kind ) . '|' . strtolower( $dest_key ) . '|' . sanitize_key( $category );
	}

	/**
	 * Full exhaust inventory (live senders with destinations). Always includes
	 * dormant rows when $include_dormant is true (CSV / print).
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function inventory( bool $include_dormant = true ): array {
		$policy  = self::resolve_policy();
		$senders = self::bundled_senders();
		$out     = array();

		foreach ( $senders as $sender ) {
			$live = self::sender_is_live( $policy, $sender );
			$dests = self::destinations_for( $policy, $sender );
			if ( ! $include_dormant && ( ! $live || empty( $dests ) ) ) {
				continue;
			}
			$out[] = array(
				'id'           => (string) $sender['id'],
				'label'        => (string) $sender['label'],
				'channel'      => (string) $sender['channel'],
				'cadence'      => (string) $sender['cadence'],
				'live'         => $live,
				'destinations' => $dests,
				'categories'   => (array) $sender['categories'],
				'has_redacted' => ! empty( $sender['has_redacted'] ),
				'deep_link'    => (string) $sender['deep_link'],
				'suggestion'   => (string) $sender['suggestion'],
			);
		}

		return $out;
	}

	/**
	 * Build plain-language finding for one destination × category pairing.
	 *
	 * @param array<string,mixed>               $sender Sender.
	 * @param array{kind:string,key:string,display:string} $dest Destination.
	 * @param string                            $category Category key.
	 * @return array<string,mixed>
	 */
	public static function build_finding( array $sender, array $dest, string $category ): array {
		$sender_id = (string) $sender['id'];
		$key       = self::pairing_key( $sender_id, (string) $dest['kind'], (string) $dest['key'], $category );
		$cat_label = self::category_label( $category );
		$label     = (string) $sender['label'];
		$display   = (string) $dest['display'];
		$cadence   = (string) ( $sender['cadence'] ?? '' );

		if ( 'webhook' === (string) $dest['kind'] ) {
			$summary = sprintf(
				/* translators: 1: sender label, 2: category label, 3: webhook host */
				__( '%1$s POST %2$s to webhook host %3$s.', 'handl-ai-connector-access-control' ),
				$label,
				$cat_label,
				$display
			);
		} else {
			$when = '';
			if ( 'weekly' === $cadence ) {
				$when = ' ' . __( 'weekly', 'handl-ai-connector-access-control' );
			} elseif ( 'monthly' === $cadence ) {
				$when = ' ' . __( 'monthly', 'handl-ai-connector-access-control' );
			}
			$summary = sprintf(
				/* translators: 1: sender label, 2: category label, 3: @domain, 4: optional cadence adverb */
				__( '%1$s emails %2$s to a %3$s inbox%4$s.', 'handl-ai-connector-access-control' ),
				$label,
				$cat_label,
				$display,
				$when
			);
		}

		$suggestion = (string) ( $sender['suggestion'] ?? '' );
		if ( ! empty( $sender['has_redacted'] ) ) {
			$suggestion = __( 'Enable that sender\'s redacted mode where one exists, or review the recipient.', 'handl-ai-connector-access-control' );
		}

		return array(
			'key'        => $key,
			'sender_id'  => $sender_id,
			'sender'     => $label,
			'category'   => $category,
			'dest_kind'  => (string) $dest['kind'],
			'dest_key'   => (string) $dest['key'],
			'dest_display' => $display,
			'summary'    => $summary,
			'suggestion' => $suggestion,
			'deep_link'  => (string) ( $sender['deep_link'] ?? '' ),
		);
	}

	/**
	 * All live destination × category pairings (before acknowledge filter).
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function all_pairings(): array {
		$policy   = self::resolve_policy();
		$findings = array();
		foreach ( self::bundled_senders() as $sender ) {
			$dests = self::destinations_for( $policy, $sender );
			if ( empty( $dests ) ) {
				continue;
			}
			foreach ( $dests as $dest ) {
				foreach ( (array) $sender['categories'] as $category ) {
					$findings[] = self::build_finding( $sender, $dest, (string) $category );
				}
			}
		}

		return $findings;
	}

	/**
	 * Unacknowledged pairings only.
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function findings(): array {
		$ack = array_fill_keys( (array) self::get_state()['acknowledged'], true );
		$out = array();
		foreach ( self::all_pairings() as $row ) {
			$key = (string) ( $row['key'] ?? '' );
			if ( '' === $key || isset( $ack[ $key ] ) ) {
				continue;
			}
			$out[] = $row;
		}

		return $out;
	}

	/**
	 * Acknowledge one or more pairing keys.
	 *
	 * @param list<string> $keys Pairing keys.
	 * @return int How many newly acknowledged.
	 */
	public static function acknowledge( array $keys ): int {
		$state = self::get_state();
		$ack   = array_fill_keys( (array) $state['acknowledged'], true );
		$added = 0;
		foreach ( $keys as $key ) {
			$key = sanitize_text_field( (string) $key );
			if ( '' === $key || isset( $ack[ $key ] ) ) {
				continue;
			}
			$ack[ $key ] = true;
			++$added;
		}
		if ( $added <= 0 ) {
			return 0;
		}
		$state['acknowledged'] = array_keys( $ack );
		// Re-arm alert latch so a later NEW pairing can fire again.
		$state['alerted']            = false;
		$state['last_alert_ts']      = 0;
		$state['last_alert_channel'] = '';
		self::put_state( $state );

		return $added;
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function snapshot( ?int $now = null ): array {
		$now      = self::resolve_now( $now );
		$findings = self::findings();
		$state    = self::get_state();

		return array(
			'enabled'              => self::is_enabled(),
			'outbound_alert'       => self::is_outbound_enabled(),
			'now'                  => $now,
			'inventory'            => self::inventory( true ),
			'findings'             => $findings,
			'unacknowledged_count' => count( $findings ),
			'alerted'              => ! empty( $state['alerted'] ),
			'last_alert_ts'        => (int) $state['last_alert_ts'],
			'last_alert_channel'   => (string) $state['last_alert_channel'],
			'last_check_ts'        => (int) $state['last_check_ts'],
			'acknowledged_count'   => count( (array) $state['acknowledged'] ),
			'framing'              => self::FRAMING,
		);
	}

	/* ---------------------------------------------------------------------
	 * Throttled admin_init check
	 * ------------------------------------------------------------------ */

	private static function resolve_now( ?int $now ): int {
		if ( null !== $now ) {
			return $now;
		}
		if ( null !== self::$test_now ) {
			return (int) self::$test_now;
		}
		if ( class_exists( Clock::class, false ) && method_exists( Clock::class, 'now' ) ) {
			return (int) Clock::now();
		}

		return time();
	}

	/**
	 * @param int|null $now   Optional timestamp.
	 * @param bool     $force Skip throttle.
	 * @return bool True when a check ran.
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

		$state['last_check_ts'] = $now;
		self::put_state( $state );
		self::maybe_fire_alerts( $now );

		return true;
	}

	/**
	 * Exactly one re-arming alert while unacknowledged exposures exist.
	 *
	 * @return bool True when a new alert was raised.
	 */
	public static function maybe_fire_alerts( ?int $now = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now      = self::resolve_now( $now );
		$findings = self::findings();
		$state    = self::get_state();

		if ( empty( $findings ) ) {
			if ( ! empty( $state['alerted'] ) ) {
				$state['alerted']            = false;
				$state['last_alert_ts']      = 0;
				$state['last_alert_channel'] = '';
				self::put_state( $state );
			}

			return false;
		}

		if ( ! empty( $state['alerted'] ) ) {
			return false;
		}

		$channel = self::CHANNEL_NOTICE;
		if ( self::is_outbound_enabled() ) {
			if ( ! self::fire_outbound( $findings, $now ) ) {
				return false;
			}
			$channel = self::CHANNEL_OUTBOUND;
		}

		$state['alerted']            = true;
		$state['last_alert_ts']      = $now;
		$state['last_alert_channel'] = $channel;
		self::put_state( $state );

		return true;
	}

	/**
	 * Alert body names categories only — never sample content or full addresses.
	 *
	 * @param list<array<string,mixed>> $findings Findings.
	 */
	private static function fire_outbound( array $findings, int $now ): bool {
		$policy = self::resolve_policy();
		$email  = self::resolve_email( $policy );
		if ( '' === $email ) {
			$email = sanitize_email( (string) get_option( 'admin_email' ) );
		}

		$categories = array();
		foreach ( $findings as $row ) {
			$cat = (string) ( $row['category'] ?? '' );
			if ( '' !== $cat ) {
				$categories[ $cat ] = true;
			}
		}
		$cat_labels = array();
		foreach ( array_keys( $categories ) as $cat ) {
			$cat_labels[] = self::category_label( (string) $cat );
		}

		$ok = false;
		if ( '' !== $email ) {
			$subject = self::build_subject( count( $findings ), $cat_labels );
			$body    = self::build_body( $findings, $cat_labels );
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
		}

		$hook_url = self::resolve_webhook( $policy );
		if ( '' !== $hook_url && class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
			$posted = (bool) Alerts::safe_wp_remote_post(
				$hook_url,
				array(
					'type'                 => 'handl_aicac_postcard',
					'unacknowledged_count' => count( $findings ),
					'categories'           => array_keys( $categories ),
					'ts'                   => $now,
				)
			);
			$ok = $ok || $posted;
		}

		return $ok;
	}

	/**
	 * @param list<string> $cat_labels Category labels.
	 */
	public static function build_subject( int $count, array $cat_labels ): string {
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$cats = implode( ', ', $cat_labels );

		return sprintf(
			/* translators: 1: site name, 2: finding count, 3: category list */
			__( '[%1$s] [POSTCARD] New outbound exposure: %2$d pairing(s) (%3$s)', 'handl-ai-connector-access-control' ),
			$site,
			$count,
			$cats
		);
	}

	/**
	 * @param list<array<string,mixed>> $findings Findings.
	 * @param list<string>              $cat_labels Category labels.
	 */
	public static function build_body( array $findings, array $cat_labels ): string {
		$lines   = array();
		$lines[] = __( 'AI Access Control found outbound senders that can leave this site with sensitive content categories. Destinations are shown as domains/hosts only — no sample content is included.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %s: comma-separated category labels */
			__( 'Categories involved: %s', 'handl-ai-connector-access-control' ),
			implode( ', ', $cat_labels )
		);
		$lines[] = '';
		foreach ( $findings as $row ) {
			$lines[] = '- ' . (string) ( $row['summary'] ?? '' );
		}
		$lines[] = '';
		$lines[] = __( 'Suggestion only: Postcard never edits a sender, recipient, or webhook. Acknowledge pairings you accept, or change the owning control.', 'handl-ai-connector-access-control' );
		$url     = self::admin_url();
		if ( '' !== $url ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Open postcard: %s', 'handl-ai-connector-access-control' ),
				$url
			);
		}

		return implode( "\n", $lines );
	}

	public static function admin_url(): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg( 'page', self::PAGE_SLUG, admin_url( 'admin.php' ) );
	}

	/* ---------------------------------------------------------------------
	 * Admin notice
	 * ------------------------------------------------------------------ */

	public static function maybe_render_notice(): void {
		if ( ! self::is_enabled() || ! Caps::user_can_view() ) {
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG === $page ) {
			return;
		}
		$findings = self::findings();
		if ( empty( $findings ) ) {
			return;
		}

		$cats = array();
		foreach ( $findings as $row ) {
			$cats[ (string) $row['category'] ] = true;
		}
		$labels = array();
		foreach ( array_keys( $cats ) as $cat ) {
			$labels[] = self::category_label( (string) $cat );
		}

		$html  = '<div class="notice notice-warning"><p><strong>' . esc_html__( 'AI Access Control — Postcard:', 'handl-ai-connector-access-control' ) . '</strong> ';
		$html .= esc_html(
			sprintf(
				/* translators: 1: finding count, 2: category list */
				_n( '%1$d unacknowledged outbound exposure (%2$s).', '%1$d unacknowledged outbound exposures (%2$s).', count( $findings ), 'handl-ai-connector-access-control' ),
				count( $findings ),
				implode( ', ', $labels )
			)
		);
		$url = self::admin_url();
		if ( '' !== $url ) {
			$html .= ' <a href="' . esc_url( $url ) . '">' . esc_html__( 'Review', 'handl-ai-connector-access-control' ) . '</a>';
		}
		$html .= '</p></div>';

		self::$test_notices[] = $html;
		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped above.
	}

	/* ---------------------------------------------------------------------
	 * CSV + print
	 * ------------------------------------------------------------------ */

	/**
	 * @param array<string,mixed>|null $snap Optional snapshot.
	 */
	public static function csv_for_snapshot( ?array $snap = null ): string {
		if ( null === $snap ) {
			$snap = self::snapshot();
		}
		$lines   = array();
		$lines[] = self::csv_line( array( 'section', 'sender', 'channel', 'destination', 'category', 'live', 'summary', 'suggestion', 'framing' ) );
		$lines[] = self::csv_line(
			array(
				'summary',
				'',
				'',
				'',
				'',
				'',
				'checked=' . gmdate( 'Y-m-d H:i:s', (int) ( $snap['now'] ?? 0 ) ) . ' UTC'
					. ' unacknowledged=' . (string) (int) ( $snap['unacknowledged_count'] ?? 0 )
					. ' delivery=' . ( ! empty( $snap['outbound_alert'] ) ? self::CHANNEL_OUTBOUND : self::CHANNEL_NOTICE ),
				'',
				self::FRAMING,
			)
		);
		foreach ( (array) ( $snap['inventory'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$dests = (array) ( $row['destinations'] ?? array() );
			if ( empty( $dests ) ) {
				$lines[] = self::csv_line(
					array(
						'inventory',
						(string) $row['id'],
						(string) $row['channel'],
						'',
						implode( '|', (array) $row['categories'] ),
						! empty( $row['live'] ) ? 'live' : 'off',
						(string) $row['label'],
						(string) $row['suggestion'],
						self::FRAMING,
					)
				);
				continue;
			}
			foreach ( $dests as $dest ) {
				if ( ! is_array( $dest ) ) {
					continue;
				}
				foreach ( (array) $row['categories'] as $cat ) {
					$lines[] = self::csv_line(
						array(
							'inventory',
							(string) $row['id'],
							(string) ( $dest['kind'] ?? '' ),
							(string) ( $dest['display'] ?? '' ),
							(string) $cat,
							! empty( $row['live'] ) ? 'live' : 'off',
							(string) $row['label'],
							(string) $row['suggestion'],
							self::FRAMING,
						)
					);
				}
			}
		}
		foreach ( (array) ( $snap['findings'] ?? array() ) as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$lines[] = self::csv_line(
				array(
					'finding',
					(string) $row['sender_id'],
					(string) $row['dest_kind'],
					(string) $row['dest_display'],
					(string) $row['category'],
					'unacked',
					(string) $row['summary'],
					(string) $row['suggestion'],
					self::FRAMING,
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
			$col = (string) $col;
			if ( '' !== $col && in_array( $col[0], array( '=', '+', '-', '@', "\t", "\r" ), true ) ) {
				$col = "'" . $col;
			}
			$needs = str_contains( $col, ',' ) || str_contains( $col, '"' ) || str_contains( $col, "\n" );
			$col   = str_replace( '"', '""', $col );
			$out[] = $needs ? '"' . $col . '"' : $col;
		}

		return implode( ',', $out );
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_print_html( array $snap ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8" /><title>POSTCARD</title>';
		$html .= '<style>body{font-family:sans-serif;margin:2rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:.4rem;text-align:left}h1,h2{margin-top:1.5rem}</style>';
		$html .= '</head><body>';
		$html .= '<h1>' . esc_html__( 'Postcard — outbound exhaust', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Report only — never edits a sender. Destinations shown as domains/hosts only.', 'handl-ai-connector-access-control' ) . '</p>';
		$html .= '<p>' . esc_html( sprintf( 'Unacknowledged: %d', (int) ( $snap['unacknowledged_count'] ?? 0 ) ) ) . '</p>';
		$html .= '<h2>' . esc_html__( 'Findings', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= self::findings_table_html( (array) ( $snap['findings'] ?? array() ), false );
		$html .= '<h2>' . esc_html__( 'Inventory', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= self::inventory_table_html( (array) ( $snap['inventory'] ?? array() ), false );
		$html .= '</body></html>';

		return $html;
	}

	/**
	 * @param list<array<string,mixed>> $rows Findings.
	 */
	private static function findings_table_html( array $rows, bool $links ): string {
		$html  = '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Finding', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Suggestion', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		$shown = 0;
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			++$shown;
			$summary = esc_html( (string) ( $row['summary'] ?? '' ) );
			if ( $links && ! empty( $row['deep_link'] ) ) {
				$summary .= ' <a href="' . esc_url( (string) $row['deep_link'] ) . '">' . esc_html__( 'Open control', 'handl-ai-connector-access-control' ) . '</a>';
			}
			$html .= '<tr><td>' . $summary . '</td><td>' . esc_html( (string) ( $row['suggestion'] ?? '' ) ) . '</td></tr>';
		}
		if ( 0 === $shown ) {
			$html .= '<tr><td colspan="2">' . esc_html__( 'No unacknowledged outbound exposures.', 'handl-ai-connector-access-control' ) . '</td></tr>';
		}
		$html .= '</tbody></table>';

		return $html;
	}

	/**
	 * @param list<array<string,mixed>> $rows Inventory.
	 */
	private static function inventory_table_html( array $rows, bool $links ): string {
		$html  = '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Sender', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Live', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Destinations', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Categories', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$label = esc_html( (string) ( $row['label'] ?? '' ) );
			if ( $links && ! empty( $row['deep_link'] ) ) {
				$label = '<a href="' . esc_url( (string) $row['deep_link'] ) . '">' . $label . '</a>';
			}
			$dest_bits = array();
			foreach ( (array) ( $row['destinations'] ?? array() ) as $dest ) {
				if ( is_array( $dest ) ) {
					$dest_bits[] = (string) ( $dest['display'] ?? '' );
				}
			}
			$cats = array();
			foreach ( (array) ( $row['categories'] ?? array() ) as $cat ) {
				$cats[] = self::category_label( (string) $cat );
			}
			$html .= '<tr>';
			$html .= '<td>' . $label . '</td>';
			$html .= '<td>' . esc_html( ! empty( $row['live'] ) ? 'live' : 'off' ) . '</td>';
			$html .= '<td>' . esc_html( implode( ', ', $dest_bits ) ) . '</td>';
			$html .= '<td>' . esc_html( implode( ', ', $cats ) ) . '</td>';
			$html .= '</tr>';
		}
		$html .= '</tbody></table>';

		return $html;
	}

	/* ---------------------------------------------------------------------
	 * Admin UI
	 * ------------------------------------------------------------------ */

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) || ! class_exists( Admin::class, false ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Postcard', 'handl-ai-connector-access-control' ),
			__( 'Postcard', 'handl-ai-connector-access-control' ),
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
		$enabled    = self::is_enabled();
		$snap       = $enabled ? self::snapshot() : null;
		$csv        = add_query_arg(
			array(
				'page'                       => self::PAGE_SLUG,
				'handl_aicac_postcard_csv'   => '1',
				'_wpnonce'                   => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_postcard_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print      = add_query_arg(
			array(
				'page'                         => self::PAGE_SLUG,
				'handl_aicac_postcard_print'   => '1',
				'_wpnonce'                     => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_postcard_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Postcard', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Inventories every outbound email and webhook this suite can send, pairs each live destination with the content categories that sender carries by design, and flags new exposures. Suggestion only — it never edits a sender. Checks run on admin page loads, not on cron. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable postcard', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Audit outbound exhaust on admin page loads', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row">' . esc_html__( 'Outbound alert', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_OUTBOUND ) . '" value="1" ' . checked( ! empty( $settings['outbound_alert'] ), true, false ) . ' /> ';
			echo esc_html__( 'Also send a [POSTCARD] alert by email / webhook when a new exposure appears (off by default)', 'handl-ai-connector-access-control' );
			echo '</label></td></tr></tbody></table>';
			submit_button( __( 'Save postcard settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled || ! is_array( $snap ) ) {
			echo '<p>' . esc_html__( 'Postcard is off. Enable it to inventory outbound exhaust.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Report only — never edits a sender, recipient, or webhook.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		if ( (int) $snap['unacknowledged_count'] > 0 ) {
			echo '<div class="notice notice-warning inline"><p><strong>' . esc_html__( 'Unacknowledged outbound exposures.', 'handl-ai-connector-access-control' ) . '</strong> ';
			echo esc_html__( 'Acknowledge pairings you accept, or change the owning control.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		echo '<ul>';
		echo '<li>' . esc_html( sprintf( 'Unacknowledged exposures: %d', (int) $snap['unacknowledged_count'] ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( 'Acknowledged pairings: %d', (int) $snap['acknowledged_count'] ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( 'Alert delivery: %s', ! empty( $snap['outbound_alert'] ) ? 'admin notice + this screen + email/webhook' : 'admin notice + this screen' ) ) . '</li>';
		echo '</ul>';

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Findings', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( $can_manage && (int) $snap['unacknowledged_count'] > 0 ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_ACK ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_ACK );
			}
			echo str_replace( '<table>', '<table class="widefat striped">', self::findings_ack_table_html( (array) $snap['findings'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			submit_button( __( 'Acknowledge selected', 'handl-ai-connector-access-control' ), 'secondary' );
			echo '</form>';
		} else {
			echo str_replace( '<table>', '<table class="widefat striped">', self::findings_table_html( (array) $snap['findings'], true ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}

		echo '<h2>' . esc_html__( 'Exhaust inventory', 'handl-ai-connector-access-control' ) . '</h2>';
		echo str_replace( '<table>', '<table class="widefat striped">', self::inventory_table_html( (array) $snap['inventory'], true ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		echo '</div>';
	}

	/**
	 * @param list<array<string,mixed>> $rows Findings.
	 */
	private static function findings_ack_table_html( array $rows ): string {
		$html  = '<table><thead><tr>';
		$html .= '<th>' . esc_html__( 'Ack', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Finding', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '<th>' . esc_html__( 'Suggestion', 'handl-ai-connector-access-control' ) . '</th>';
		$html .= '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$key = (string) ( $row['key'] ?? '' );
			$html .= '<tr>';
			$html .= '<td><input type="checkbox" name="ack_keys[]" value="' . esc_attr( $key ) . '" /></td>';
			$summary = esc_html( (string) ( $row['summary'] ?? '' ) );
			if ( ! empty( $row['deep_link'] ) ) {
				$summary .= ' <a href="' . esc_url( (string) $row['deep_link'] ) . '">' . esc_html__( 'Open control', 'handl-ai-connector-access-control' ) . '</a>';
			}
			$html .= '<td>' . $summary . '</td>';
			$html .= '<td>' . esc_html( (string) ( $row['suggestion'] ?? '' ) ) . '</td>';
			$html .= '</tr>';
		}
		$html .= '</tbody></table>';

		return $html;
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_postcard_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
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
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_postcard_csv' ) ) {
			return;
		}
		$csv = self::csv_for_snapshot();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=handl-aicac-postcard.csv' );
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		if ( empty( $_GET['handl_aicac_postcard_print'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
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
		if ( ! function_exists( 'wp_verify_nonce' ) || ! wp_verify_nonce( $nonce, 'handl_aicac_postcard_print' ) ) {
			return;
		}
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		echo self::build_print_html( self::snapshot() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in builder.
		exit;
	}

	private static function redirect_to_page(): void {
		$redirect = self::admin_url();
		if ( '' === $redirect && function_exists( 'admin_url' ) ) {
			$redirect = admin_url( 'admin.php?page=' . self::PAGE_SLUG );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save postcard settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Invalid form', 'handl-ai-connector-access-control' ) );
		}
		self::save_settings(
			array(
				'enabled'        => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
				'outbound_alert' => ! empty( $_POST[ self::POST_OUTBOUND ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
			)
		);
		self::redirect_to_page();
	}

	public static function handle_ack(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to acknowledge postcard findings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_ACK );
		$keys = isset( $_POST['ack_keys'] ) && is_array( $_POST['ack_keys'] ) ? wp_unslash( $_POST['ack_keys'] ) : array(); // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$clean = array();
		foreach ( $keys as $key ) {
			$clean[] = sanitize_text_field( (string) $key );
		}
		self::acknowledge( $clean );
		self::redirect_to_page();
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac postcard', CLI_Postcard::class );
	}
}

/**
 * WP-CLI: wp handl-aicac postcard status|export
 */
final class CLI_Postcard {

	/**
	 * Run an outbound-exhaust check and show unacknowledged exposures.
	 * Exits non-zero while any unacknowledged exposure is present (while enabled).
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
		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';

		if ( ! Postcard::is_enabled() ) {
			\WP_CLI::log( 'enabled=no framing=' . Postcard::FRAMING );
			\WP_CLI::log( 'Postcard is disabled.' );

			return;
		}

		Postcard::maybe_check( null, true );
		$snap = Postcard::snapshot();

		\WP_CLI::log(
			sprintf(
				'enabled=yes unacknowledged=%d alerted=%s outbound=%s framing=%s',
				(int) $snap['unacknowledged_count'],
				! empty( $snap['alerted'] ) ? 'yes' : 'no',
				! empty( $snap['outbound_alert'] ) ? 'on' : 'off',
				Postcard::FRAMING
			)
		);

		$display = array();
		foreach ( (array) $snap['findings'] as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$display[] = array(
				'sender'     => (string) $row['sender_id'],
				'destination'=> (string) $row['dest_display'],
				'category'   => (string) $row['category'],
				'summary'    => (string) $row['summary'],
			);
		}
		if ( ! empty( $display ) ) {
			if ( 'json' === $format ) {
				\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			} elseif ( class_exists( '\\WP_CLI\\Utils' ) ) {
				\WP_CLI\Utils\format_items( 'table', $display, array( 'sender', 'destination', 'category', 'summary' ) );
			} else {
				foreach ( $display as $row ) {
					\WP_CLI::log( implode( "\t", $row ) );
				}
			}
		}

		if ( (int) $snap['unacknowledged_count'] > 0 ) {
			\WP_CLI::error( 'Unacknowledged outbound exposure present.' );
		}
	}

	/**
	 * Export the exhaust inventory and findings as CSV.
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
		$csv = Postcard::csv_for_snapshot();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
