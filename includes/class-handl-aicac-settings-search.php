<?php
/**
 * AICAC-FIND (#198): admin settings type-ahead jump index.
 *
 * Builds a searchable index from registered labels (screens, sections, and
 * setting controls). No external calls. The index is localized into the admin
 * script at enqueue time; the search box is rendered in the screen header.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registry + markup + script payload for Find a setting.
 */
final class Settings_Search {

	public const SCRIPT_HANDLE = 'handl-aicac-settings-search';

	/**
	 * @var array<string, array{
	 *   key:string,
	 *   label:string,
	 *   screen:string,
	 *   selector:string,
	 *   keywords:list<string>,
	 *   type:string
	 * }>
	 */
	private static array $entries = array();

	private static bool $defaults_loaded = false;

	/**
	 * Reset registry (unit tests).
	 */
	public static function reset_for_tests(): void {
		self::$entries         = array();
		self::$defaults_loaded = false;
	}

	/**
	 * Register one searchable entry. Later calls with the same key replace.
	 *
	 * @param array{
	 *   key:string,
	 *   label:string,
	 *   screen:string,
	 *   selector?:string,
	 *   keywords?:list<string>|string,
	 *   type?:string
	 * } $entry
	 */
	public static function register( array $entry ): void {
		$key = isset( $entry['key'] ) ? sanitize_key( (string) $entry['key'] ) : '';
		if ( '' === $key ) {
			return;
		}

		$label = isset( $entry['label'] ) ? trim( (string) $entry['label'] ) : '';
		if ( '' === $label ) {
			return;
		}

		$screen = isset( $entry['screen'] ) ? sanitize_key( (string) $entry['screen'] ) : 'dashboard';
		if ( class_exists( Admin::class ) ) {
			$screen = Admin::normalize_screen( $screen );
		}

		$selector = isset( $entry['selector'] ) ? trim( (string) $entry['selector'] ) : '';
		$type     = isset( $entry['type'] ) ? sanitize_key( (string) $entry['type'] ) : 'setting';
		if ( ! in_array( $type, array( 'setting', 'section', 'screen' ), true ) ) {
			$type = 'setting';
		}

		$keywords = array();
		if ( isset( $entry['keywords'] ) ) {
			$raw = $entry['keywords'];
			if ( is_string( $raw ) ) {
				$raw = preg_split( '/\s+/', $raw ) ?: array();
			}
			if ( is_array( $raw ) ) {
				foreach ( $raw as $word ) {
					$word = strtolower( trim( (string) $word ) );
					if ( '' !== $word ) {
						$keywords[] = $word;
					}
				}
			}
		}
		$keywords = array_values( array_unique( $keywords ) );

		self::$entries[ $key ] = array(
			'key'      => $key,
			'label'    => $label,
			'screen'   => $screen,
			'selector' => $selector,
			'keywords' => $keywords,
			'type'     => $type,
		);
	}

	/**
	 * @return array<string, array{
	 *   key:string,
	 *   label:string,
	 *   screen:string,
	 *   selector:string,
	 *   keywords:list<string>,
	 *   type:string
	 * }>
	 */
	public static function registered(): array {
		self::ensure_defaults();
		return self::$entries;
	}

	/**
	 * Index payload for the type-ahead script (and tests).
	 *
	 * @return list<array{
	 *   key:string,
	 *   label:string,
	 *   screen:string,
	 *   url:string,
	 *   selector:string,
	 *   type:string,
	 *   haystack:string
	 * }>
	 */
	public static function build_index(): array {
		self::ensure_defaults();
		$out = array();
		foreach ( self::$entries as $entry ) {
			$url = class_exists( Admin::class )
				? Admin::screen_url( $entry['screen'] )
				: admin_url( 'admin.php?page=handl-aicac' );

			$parts = array( strtolower( $entry['label'] ), $entry['key'] );
			foreach ( $entry['keywords'] as $word ) {
				$parts[] = $word;
			}
			$haystack = preg_replace( '/\s+/', ' ', implode( ' ', $parts ) );
			$haystack = is_string( $haystack ) ? trim( $haystack ) : '';

			$out[] = array(
				'key'      => $entry['key'],
				'label'    => $entry['label'],
				'screen'   => $entry['screen'],
				'url'      => $url,
				'selector' => $entry['selector'],
				'type'     => $entry['type'],
				'haystack' => $haystack,
			);
		}
		return $out;
	}

	/**
	 * Filter the index by a query string (case-insensitive substring match).
	 *
	 * @return list<array<string,string>>
	 */
	public static function match( string $query, ?array $index = null ): array {
		$index = null === $index ? self::build_index() : $index;
		$q     = strtolower( trim( $query ) );
		if ( '' === $q ) {
			return array();
		}

		$hits = array();
		foreach ( $index as $row ) {
			$hay = isset( $row['haystack'] ) ? (string) $row['haystack'] : '';
			if ( '' !== $hay && false !== strpos( $hay, $q ) ) {
				$hits[] = $row;
			}
		}
		return $hits;
	}

	/**
	 * Search box markup for the screen header.
	 */
	public static function render_box(): void {
		echo '<div class="handl-aicac-settings-search" data-aicac-settings-search>';
		echo '<label class="screen-reader-text" for="handl-aicac-settings-search-input">';
		echo esc_html__( 'Find a setting', 'handl-ai-connector-access-control' );
		echo '</label>';
		echo '<input type="search" id="handl-aicac-settings-search-input" class="handl-aicac-settings-search__input" autocomplete="off" spellcheck="false" placeholder="' . esc_attr__( 'Find a setting…', 'handl-ai-connector-access-control' ) . '" aria-autocomplete="list" aria-controls="handl-aicac-settings-search-list" aria-expanded="false" aria-haspopup="listbox" role="combobox" />';
		echo '<ul id="handl-aicac-settings-search-list" class="handl-aicac-settings-search__list" role="listbox" hidden></ul>';
		echo '<div id="handl-aicac-settings-search-status" class="screen-reader-text" role="status" aria-live="polite" aria-atomic="true"></div>';
		echo '</div>';
	}

	/**
	 * Enqueue the type-ahead script and localize the index.
	 */
	public static function enqueue( string $current_screen = 'dashboard' ): void {
		if ( ! defined( 'HANDL_AICAC_URL' ) || ! defined( 'HANDL_AICAC_VERSION' ) ) {
			return;
		}

		$current_screen = class_exists( Admin::class )
			? Admin::normalize_screen( $current_screen )
			: sanitize_key( $current_screen );

		wp_enqueue_script(
			self::SCRIPT_HANDLE,
			HANDL_AICAC_URL . 'assets/settings-search.js',
			array(),
			HANDL_AICAC_VERSION,
			true
		);

		wp_add_inline_script(
			self::SCRIPT_HANDLE,
			'window.handlAicacSettingsSearch=' . wp_json_encode(
				array(
					'currentScreen' => $current_screen,
					'index'         => self::build_index(),
					'i18n'          => array(
						'noResults'   => __( 'No matching settings', 'handl-ai-connector-access-control' ),
						/* translators: %d: number of matches */
						'nResults'    => __( '%d matches', 'handl-ai-connector-access-control' ),
						/* translators: %s: setting label */
						'jumpingTo'   => __( 'Opening %s', 'handl-ai-connector-access-control' ),
						'oneResult'   => __( '1 match', 'handl-ai-connector-access-control' ),
					),
				)
			) . ';',
			'before'
		);
	}

	/**
	 * Built-in catalog of screens, sections, and setting controls.
	 */
	public static function ensure_defaults(): void {
		if ( self::$defaults_loaded ) {
			return;
		}
		self::$defaults_loaded = true;
		self::register_defaults();
	}

	/**
	 * Register the shipped catalog. Safe to call after reset_for_tests().
	 */
	public static function register_defaults(): void {
		// Screens.
		self::register(
			array(
				'key'      => 'screen-dashboard',
				'label'    => __( 'Dashboard', 'handl-ai-connector-access-control' ),
				'screen'   => 'dashboard',
				'selector' => '.handl-aicac-screen-title',
				'type'     => 'screen',
				'keywords' => array( 'home', 'overview' ),
			)
		);
		self::register(
			array(
				'key'      => 'screen-rules',
				'label'    => __( 'Rules', 'handl-ai-connector-access-control' ),
				'screen'   => 'rules',
				'selector' => '.handl-aicac-screen-title',
				'type'     => 'screen',
				'keywords' => array( 'plugins', 'allow', 'deny', 'matrix' ),
			)
		);
		self::register(
			array(
				'key'      => 'screen-protections',
				'label'    => __( 'Protections', 'handl-ai-connector-access-control' ),
				'screen'   => 'protections',
				'selector' => '.handl-aicac-screen-title',
				'type'     => 'screen',
				'keywords' => array( 'safeguards', 'defaults' ),
			)
		);
		self::register(
			array(
				'key'      => 'screen-activity',
				'label'    => __( 'Activity', 'handl-ai-connector-access-control' ),
				'screen'   => 'activity',
				'selector' => '#handl-aicac-recent-calls',
				'type'     => 'screen',
				'keywords' => array( 'log', 'calls', 'history' ),
			)
		);
		self::register(
			array(
				'key'      => 'screen-insights',
				'label'    => __( 'Insights', 'handl-ai-connector-access-control' ),
				'screen'   => 'insights',
				'selector' => '.handl-aicac-screen-title',
				'type'     => 'screen',
				'keywords' => array( 'trends', 'spend', 'usage' ),
			)
		);
		self::register(
			array(
				'key'      => 'screen-policy-tools',
				'label'    => __( 'Policy Tools', 'handl-ai-connector-access-control' ),
				'screen'   => 'policy-tools',
				'selector' => '#handl-aicac-sim-panel',
				'type'     => 'screen',
				'keywords' => array( 'simulator', 'backup', 'restore', 'import', 'export', 'template' ),
			)
		);
		self::register(
			array(
				'key'      => 'screen-alerts',
				'label'    => __( 'Alerts & Settings', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '#handl-aicac-alerts-save',
				'type'     => 'screen',
				'keywords' => array( 'settings', 'email', 'reports', 'retention' ),
			)
		);

		// Protections settings.
		self::register(
			array(
				'key'      => 'default-policy',
				'label'    => __( 'Default policy', 'handl-ai-connector-access-control' ),
				'screen'   => 'protections',
				'selector' => '#handl-aicac-default',
				'keywords' => array( 'default', 'allow', 'deny', 'fallback' ),
			)
		);
		self::register(
			array(
				'key'      => 'unknown-operation',
				'label'    => __( 'Unknown AI operations', 'handl-ai-connector-access-control' ),
				'screen'   => 'protections',
				'selector' => '#handl-aicac-unknown-operation',
				'keywords' => array( 'unknown', 'operation', 'embeddings', 'music' ),
			)
		);
		self::register(
			array(
				'key'      => 'kill-switch',
				'label'    => __( 'Emergency stop', 'handl-ai-connector-access-control' ),
				'screen'   => 'protections',
				'selector' => '#handl-aicac-kill-switch',
				'keywords' => array( 'kill', 'switch', 'emergency', 'stop', 'block all' ),
			)
		);
		self::register(
			array(
				'key'      => 'shadow-block',
				'label'    => __( 'Block direct AI connections', 'handl-ai-connector-access-control' ),
				'screen'   => 'protections',
				'selector' => '#handl-aicac-shadow-block-enabled',
				'keywords' => array( 'shadow', 'direct', 'outside', 'bypass' ),
			)
		);
		self::register(
			array(
				'key'      => 'role-gate',
				'label'    => __( 'Limit by role', 'handl-ai-connector-access-control' ),
				'screen'   => 'protections',
				'selector' => '#handl-aicac-role-gate-enabled',
				'keywords' => array( 'role', 'roles', 'capability', 'who can' ),
			)
		);
		self::register(
			array(
				'key'      => 'new-plugin-interim',
				'label'    => __( 'New plugins', 'handl-ai-connector-access-control' ),
				'screen'   => 'protections',
				'selector' => '#handl-aicac-new-plugin-interim',
				'keywords' => array( 'new', 'plugin', 'interim', 'hold' ),
			)
		);
		self::register(
			array(
				'key'      => 'quiet-hours',
				'label'    => __( 'Quiet hours', 'handl-ai-connector-access-control' ),
				'screen'   => 'protections',
				'selector' => '#handl-aicac-qh-name-0',
				'keywords' => array( 'quiet', 'hours', 'schedule', 'overnight', 'night' ),
			)
		);
		self::register(
			array(
				'key'      => 'residency-region',
				'label'    => __( 'Data residency', 'handl-ai-connector-access-control' ),
				'screen'   => 'protections',
				'selector' => '#handl-aicac-residency-region',
				'keywords' => array( 'residency', 'region', 'eu', 'us', 'geo' ),
			)
		);
		self::register(
			array(
				'key'      => 'residency-map',
				'label'    => __( 'Provider residency map', 'handl-ai-connector-access-control' ),
				'screen'   => 'protections',
				'selector' => '#handl-aicac-residency-map',
				'keywords' => array( 'residency', 'map', 'provider region' ),
			)
		);
		self::register(
			array(
				'key'      => 'model-force',
				'label'    => __( 'Model routing for unknown plugins', 'handl-ai-connector-access-control' ),
				'screen'   => 'protections',
				'selector' => '#handl-aicac-model-force-unattributed',
				'keywords' => array( 'model', 'routing', 'force', 'unattributed' ),
			)
		);
		self::register(
			array(
				'key'      => 'denied-tools',
				'label'    => __( 'Denied tools', 'handl-ai-connector-access-control' ),
				'screen'   => 'protections',
				'selector' => '#handl-aicac-denied-tools',
				'keywords' => array( 'tools', 'mcp', 'abilities', 'arming' ),
			)
		);
		self::register(
			array(
				'key'      => 'disclosure-privacy',
				'label'    => __( 'Public AI disclosure', 'handl-ai-connector-access-control' ),
				'screen'   => 'protections',
				'selector' => '#handl-aicac-disclosure-privacy',
				'keywords' => array( 'disclosure', 'privacy', 'transparency' ),
			)
		);
		self::register(
			array(
				'key'      => 'disclosure-json',
				'label'    => __( 'Machine-readable AI disclosure', 'handl-ai-connector-access-control' ),
				'screen'   => 'protections',
				'selector' => '#handl-aicac-disclosure-json',
				'keywords' => array( 'ai.json', 'well-known', 'json', 'machine' ),
			)
		);
		self::register(
			array(
				'key'      => 'badge-embed',
				'label'    => __( 'Badge embed code', 'handl-ai-connector-access-control' ),
				'screen'   => 'protections',
				'selector' => '#handl-aicac-badge-embed',
				'keywords' => array( 'badge', 'embed', 'snippet', 'html' ),
			)
		);
		self::register(
			array(
				'key'      => 'freeze',
				'label'    => __( 'Freeze rules', 'handl-ai-connector-access-control' ),
				'screen'   => 'protections',
				'selector' => '#handl-aicac-freeze-start-minutes',
				'keywords' => array( 'freeze', 'lock', 'pause changes' ),
			)
		);
		self::register(
			array(
				'key'      => 'protections-advanced',
				'label'    => __( 'Advanced controls', 'handl-ai-connector-access-control' ),
				'screen'   => 'protections',
				'selector' => '#handl-aicac-protections-advanced',
				'type'     => 'section',
				'keywords' => array( 'advanced', 'model', 'tools' ),
			)
		);

		// Alerts & Settings.
		self::register(
			array(
				'key'      => 'learn-mode',
				'label'    => __( 'Learn mode', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '[name="handl_aicac_audit_only"]',
				'keywords' => array( 'audit', 'observe', 'log only', 'learning' ),
			)
		);
		self::register(
			array(
				'key'      => 'log-enabled',
				'label'    => __( 'Log calls', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '[name="handl_aicac_log_enabled"]',
				'keywords' => array( 'logging', 'activity trail' ),
			)
		);
		self::register(
			array(
				'key'      => 'log-limit',
				'label'    => __( 'Keep this many log entries', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '#handl-aicac-log-limit',
				'keywords' => array( 'limit', 'entries', 'size' ),
			)
		);
		self::register(
			array(
				'key'      => 'log-retention',
				'label'    => __( 'How long to keep activity', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '#handl-aicac-log-max-age-days',
				'keywords' => array( 'retention', 'days', 'keep', 'purge', 'age' ),
			)
		);
		self::register(
			array(
				'key'      => 'alert-email',
				'label'    => __( 'Recipient email', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '#handl-aicac-alert-email',
				'keywords' => array( 'email', 'alert', 'recipient', 'notify' ),
			)
		);
		self::register(
			array(
				'key'      => 'alert-webhook',
				'label'    => __( 'Webhook URL', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '#handl-aicac-alert-webhook',
				'keywords' => array( 'webhook', 'slack', 'teams', 'hook', 'json' ),
			)
		);
		self::register(
			array(
				'key'      => 'alert-on-deny',
				'label'    => __( 'Blocked-call email alerts', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '[name="handl_aicac_alert_on_deny"]',
				'keywords' => array( 'deny', 'blocked', 'email alerts' ),
			)
		);
		self::register(
			array(
				'key'      => 'alert-on-shadow',
				'label'    => __( 'Direct AI connection alerts', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '[name="handl_aicac_alert_on_shadow"]',
				'keywords' => array( 'shadow', 'direct', 'connection alerts' ),
			)
		);
		self::register(
			array(
				'key'      => 'drift-alert',
				'label'    => __( 'Provider or model change alerts', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '#handl-aicac-drift-alert-mode',
				'keywords' => array( 'drift', 'provider', 'model', 'change' ),
			)
		);
		self::register(
			array(
				'key'      => 'weekly-report',
				'label'    => __( 'Weekly activity summary', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '[name="handl_aicac_weekly_report_enabled"]',
				'keywords' => array( 'weekly', 'report', 'summary' ),
			)
		);
		self::register(
			array(
				'key'      => 'governance-digest',
				'label'    => __( 'Weekly governance digest', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '#handl-aicac-governance-digest',
				'keywords' => array( 'digest', 'governance', 'weekly' ),
			)
		);
		self::register(
			array(
				'key'      => 'monthly-report',
				'label'    => __( 'Monthly audit report', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '[name="handl_aicac_monthly_report_enabled"]',
				'keywords' => array( 'monthly', 'audit', 'report' ),
			)
		);
		self::register(
			array(
				'key'      => 'est-spend-rates',
				'label'    => __( 'Estimated spend rates', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '#handl-aicac-est-in',
				'keywords' => array( 'spend', 'cost', 'rates', 'pricing', 'tokens' ),
			)
		);
		self::register(
			array(
				'key'      => 'spend-threshold',
				'label'    => __( 'Site-wide threshold (USD)', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '#handl-aicac-spend-threshold-site',
				'keywords' => array( 'threshold', 'budget', 'spend alert', 'estimated spend alerts' ),
			)
		);
		self::register(
			array(
				'key'      => 'anomaly',
				'label'    => __( 'Usage spike alerts', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '#handl-aicac-anomaly-multiplier',
				'keywords' => array( 'anomaly', 'spike', 'unusual', 'multiplier' ),
			)
		);
		self::register(
			array(
				'key'      => 'share-status',
				'label'    => __( 'Share status', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '#handl-aicac-share-ttl',
				'keywords' => array( 'share', 'status link', 'consultant', 'readonly' ),
			)
		);
		self::register(
			array(
				'key'      => 'role-access',
				'label'    => __( 'Role access', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '.handl-aicac-auditor-matrix',
				'type'     => 'section',
				'keywords' => array( 'auditor', 'roles', 'view only', 'permissions' ),
			)
		);
		self::register(
			array(
				'key'      => 'alerts-reports',
				'label'    => __( 'Scheduled reports', 'handl-ai-connector-access-control' ),
				'screen'   => 'alerts',
				'selector' => '#handl-aicac-alerts-reports',
				'type'     => 'section',
				'keywords' => array( 'reports', 'schedule', 'email' ),
			)
		);

		// Rules: mute/snooze (plain-language synonym gate — "mute" finds snooze).
		self::register(
			array(
				'key'      => 'alert-snooze',
				'label'    => __( 'Mute alerts for a plugin', 'handl-ai-connector-access-control' ),
				'screen'   => 'rules',
				'selector' => '.handl-aicac-alert-snooze',
				'keywords' => array( 'mute', 'snooze', 'silence', 'pause alerts', 'quiet alerts' ),
			)
		);
		self::register(
			array(
				'key'      => 'review-due',
				'label'    => __( 'Review due window', 'handl-ai-connector-access-control' ),
				'screen'   => 'rules',
				'selector' => '#handl-aicac-review-due-days',
				'keywords' => array( 'review', 'due', 'stale', 'confirm' ),
			)
		);
		self::register(
			array(
				'key'      => 'suggested-rules',
				'label'    => __( 'Suggested rules', 'handl-ai-connector-access-control' ),
				'screen'   => 'rules',
				'selector' => '#handl-aicac-suggested-rules',
				'type'     => 'section',
				'keywords' => array( 'suggest', 'recommend' ),
			)
		);

		// Activity.
		self::register(
			array(
				'key'      => 'recent-calls',
				'label'    => __( 'Recent calls', 'handl-ai-connector-access-control' ),
				'screen'   => 'activity',
				'selector' => '#handl-aicac-recent-calls',
				'type'     => 'section',
				'keywords' => array( 'log', 'activity', 'calls' ),
			)
		);
		self::register(
			array(
				'key'      => 'webhook-delivery-log',
				'label'    => __( 'Webhook delivery log', 'handl-ai-connector-access-control' ),
				'screen'   => 'activity',
				'selector' => '#handl-aicac-webhook-log',
				'type'     => 'section',
				'keywords' => array( 'webhook', 'delivery', 'failures' ),
			)
		);

		// Policy Tools.
		self::register(
			array(
				'key'      => 'policy-simulator',
				'label'    => __( 'Policy simulator', 'handl-ai-connector-access-control' ),
				'screen'   => 'policy-tools',
				'selector' => '#handl-aicac-sim-panel',
				'keywords' => array( 'simulate', 'dry run', 'what if', 'test policy' ),
			)
		);
		self::register(
			array(
				'key'      => 'scan-all',
				'label'    => __( 'Scan installed plugins and themes', 'handl-ai-connector-access-control' ),
				'screen'   => 'policy-tools',
				'selector' => '#handl-aicac-tools-scan-all',
				'type'     => 'section',
				'keywords' => array( 'scan', 'preflight', 'themes', 'plugins' ),
			)
		);
		self::register(
			array(
				'key'      => 'policy-template',
				'label'    => __( 'Start from a template', 'handl-ai-connector-access-control' ),
				'screen'   => 'policy-tools',
				'selector' => '#handl-aicac-tools-template',
				'type'     => 'section',
				'keywords' => array( 'template', 'preset', 'pack' ),
			)
		);
		self::register(
			array(
				'key'      => 'policy-backup',
				'label'    => __( 'Backup and recovery', 'handl-ai-connector-access-control' ),
				'screen'   => 'policy-tools',
				'selector' => '#handl-aicac-tools-backup',
				'type'     => 'section',
				'keywords' => array( 'backup', 'restore', 'import', 'export', 'history' ),
			)
		);
		self::register(
			array(
				'key'      => 'policy-checks',
				'label'    => __( 'Policy checks', 'handl-ai-connector-access-control' ),
				'screen'   => 'policy-tools',
				'selector' => '#handl-aicac-tools-checks',
				'type'     => 'section',
				'keywords' => array( 'checks', 'assertions', 'tests' ),
			)
		);

		// Dashboard.
		self::register(
			array(
				'key'      => 'needs-attention',
				'label'    => __( 'Needs attention', 'handl-ai-connector-access-control' ),
				'screen'   => 'dashboard',
				'selector' => '#handl-aicac-needs-attention',
				'type'     => 'section',
				'keywords' => array( 'attention', 'alerts', 'warnings' ),
			)
		);
		self::register(
			array(
				'key'      => 'keyscan',
				'label'    => __( 'API key scan', 'handl-ai-connector-access-control' ),
				'screen'   => 'dashboard',
				'selector' => '#handl-aicac-keyscan',
				'keywords' => array( 'keyscan', 'api key', 'secrets' ),
			)
		);

		// Insights sections (read-only targets; Kent owns Insights render methods).
		self::register(
			array(
				'key'      => 'insights-daily',
				'label'    => __( 'Daily trends', 'handl-ai-connector-access-control' ),
				'screen'   => 'insights',
				'selector' => '#handl-aicac-insights-daily',
				'type'     => 'section',
				'keywords' => array( 'daily', 'trends', 'chart' ),
			)
		);
		self::register(
			array(
				'key'      => 'insights-weekly',
				'label'    => __( 'Weekly trends', 'handl-ai-connector-access-control' ),
				'screen'   => 'insights',
				'selector' => '#handl-aicac-insights-weekly',
				'type'     => 'section',
				'keywords' => array( 'weekly', 'trends' ),
			)
		);
		self::register(
			array(
				'key'      => 'insights-forecast',
				'label'    => __( 'Estimated month-end by plugin', 'handl-ai-connector-access-control' ),
				'screen'   => 'insights',
				'selector' => '#handl-aicac-insights-forecast',
				'type'     => 'section',
				'keywords' => array( 'forecast', 'month-end', 'projection' ),
			)
		);
	}
}
