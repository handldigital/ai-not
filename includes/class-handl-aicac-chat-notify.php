<?php
/**
 * AICAC-CHAT-NOTIFY (#298): Slack Block Kit / Teams Adaptive Card alerts.
 *
 * Option + filter + WP-CLI. No admin UI (follow-up). Reuses Alert_Routing
 * types; does not add a second routing table. Chat POST failure never
 * blocks or delays the email path.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Native Slack / Teams delivery for selected security events.
 */
final class Chat_Notify {

	public const OPTION_KEY = 'handl_aicac_chat_notify';

	public const TARGET_SLACK = 'slack';

	public const TARGET_TEAMS = 'teams';

	public const CLASS_DENY_STORM = 'deny_storm';

	public const CLASS_BUDGET = 'budget';

	public const CLASS_TAMPER = 'tamper';

	public const CLASS_POLICY = 'policy';

	public const CLASS_INCIDENT = 'incident';

	public const CLASS_TEST = 'test';

	public const CLASS_DRIFT = 'drift';

	public const CLASS_ANOMALY = 'anomaly';

	public const CLASS_SHADOW = 'shadow';

	public const CLASS_CANARY = 'canary';

	public const FILTER_CONFIG = 'handl_aicac_chat_notify_config';

	public const FILTER_SHOULD_SEND = 'handl_aicac_chat_notify_should_send';

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( '\WP_CLI' ) ) {
			\WP_CLI::add_command( 'handl-aicac chat-notify status', array( self::class, 'cmd_status' ) );
			\WP_CLI::add_command( 'handl-aicac chat-notify set', array( self::class, 'cmd_set' ) );
			\WP_CLI::add_command( 'handl-aicac chat-notify test', array( self::class, 'cmd_test' ) );
		}
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		delete_option( self::OPTION_KEY );
	}

	/**
	 * @return list<string>
	 */
	public static function targets(): array {
		return array( self::TARGET_SLACK, self::TARGET_TEAMS );
	}

	/**
	 * Event classes this channel can format. Alert_Routing types that overlap
	 * are consumed from that table; classes with no routing type still send
	 * when a webhook URL is configured (deny storm, tamper, policy, test).
	 *
	 * @return list<string>
	 */
	public static function event_classes(): array {
		return array(
			self::CLASS_DENY_STORM,
			self::CLASS_BUDGET,
			self::CLASS_TAMPER,
			self::CLASS_POLICY,
			self::CLASS_INCIDENT,
			self::CLASS_TEST,
			self::CLASS_DRIFT,
			self::CLASS_ANOMALY,
			self::CLASS_SHADOW,
			self::CLASS_CANARY,
		);
	}

	/**
	 * Map a chat event class onto Alert_Routing::TYPES, or empty when none.
	 */
	public static function routing_type_for_class( string $class ): string {
		$map = array(
			self::CLASS_BUDGET  => 'budget',
			self::CLASS_DRIFT   => 'drift',
			self::CLASS_ANOMALY => 'anomaly',
			self::CLASS_SHADOW  => 'shadow',
			self::CLASS_CANARY  => 'canary',
		);
		return isset( $map[ $class ] ) ? $map[ $class ] : '';
	}

	/**
	 * @param mixed $raw
	 * @return array{slack_url:string,teams_url:string,min_severity:int}
	 */
	public static function sanitize_config( $raw ): array {
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}
		$slack = Alerts::sanitize_webhook_url( $raw['slack_url'] ?? '' );
		$teams = Alerts::sanitize_webhook_url( $raw['teams_url'] ?? '' );
		$min   = isset( $raw['min_severity'] ) && is_numeric( $raw['min_severity'] )
			? (int) $raw['min_severity']
			: 0;
		if ( $min < 0 ) {
			$min = 0;
		}
		if ( $min > 10 ) {
			$min = 10;
		}

		return array(
			'slack_url'    => $slack,
			'teams_url'    => $teams,
			'min_severity' => $min,
		);
	}

	/**
	 * @return array{slack_url:string,teams_url:string,min_severity:int}
	 */
	public static function get_config(): array {
		$stored = self::sanitize_config( get_option( self::OPTION_KEY, array() ) );
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( self::FILTER_CONFIG, $stored );
			$stored   = self::sanitize_config( $filtered );
		}

		return $stored;
	}

	/**
	 * @param array<string,mixed> $config
	 */
	public static function save_config( array $config ): array {
		$clean = self::sanitize_config( $config );
		update_option( self::OPTION_KEY, $clean, false );

		return $clean;
	}

	/**
	 * Mask a webhook URL for CLI / logs. Never echoes the full secret.
	 *
	 * @param mixed $url
	 */
	public static function mask_url( $url ): string {
		$url = trim( (string) $url );
		if ( '' === $url ) {
			return '';
		}
		$parts = function_exists( 'wp_parse_url' ) ? wp_parse_url( $url ) : parse_url( $url );
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return '(configured)';
		}
		$tail = substr( $url, -4 );
		if ( ! is_string( $tail ) || strlen( $tail ) < 4 ) {
			$tail = '****';
		}

		return strtolower( (string) $parts['scheme'] ) . '://' . (string) $parts['host'] . '/…****' . $tail;
	}

	/**
	 * Classify a log event, or null to skip.
	 *
	 * @param array<string,mixed> $event
	 */
	public static function classify( array $event ): ?string {
		if ( ! empty( $event['chat_test'] ) || self::CLASS_TEST === ( $event['channel'] ?? '' ) ) {
			return self::CLASS_TEST;
		}
		if ( ! empty( $event['retry_storm'] ) ) {
			return self::CLASS_DENY_STORM;
		}

		$channel = isset( $event['channel'] ) ? sanitize_key( (string) $event['channel'] ) : '';
		if ( 'tamper' === $channel ) {
			return self::CLASS_TAMPER;
		}
		if ( 'budget' === $channel || 'spend_threshold' === $channel ) {
			return self::CLASS_BUDGET;
		}
		if ( in_array( $channel, array( 'policy_restore', 'policy_save', 'policy_import' ), true ) ) {
			return self::CLASS_POLICY;
		}
		if ( 'incident' === $channel ) {
			return self::CLASS_INCIDENT;
		}
		if ( 'drift' === $channel ) {
			return self::CLASS_DRIFT;
		}
		if ( 'anomaly' === $channel ) {
			return self::CLASS_ANOMALY;
		}
		if ( 'canary' === $channel ) {
			return self::CLASS_CANARY;
		}
		if ( 'direct_http' === $channel ) {
			return self::CLASS_SHADOW;
		}

		return null;
	}

	/**
	 * SIEM-aligned 0–10 severity so routing stays one model.
	 */
	public static function severity_for_class( string $class ): int {
		switch ( $class ) {
			case self::CLASS_TAMPER:
				return 8;
			case self::CLASS_DENY_STORM:
			case self::CLASS_INCIDENT:
				return 7;
			case self::CLASS_BUDGET:
			case self::CLASS_ANOMALY:
				return 5;
			case self::CLASS_SHADOW:
			case self::CLASS_DRIFT:
			case self::CLASS_CANARY:
				return 4;
			case self::CLASS_POLICY:
				return 3;
			case self::CLASS_TEST:
				return 1;
			default:
				return 4;
		}
	}

	/**
	 * @param array<string,mixed> $policy
	 */
	public static function routing_allows( array $policy, string $class ): bool {
		$type = self::routing_type_for_class( $class );
		if ( '' === $type ) {
			return true;
		}
		$routing = isset( $policy['alert_routing'] ) ? Alert_Routing::sanitize_routing( $policy['alert_routing'] ) : array();
		if ( array() === $routing ) {
			return true;
		}

		return isset( $routing[ $type ] ) && '' !== trim( (string) $routing[ $type ] );
	}

	/**
	 * @param array<string,mixed> $policy
	 * @param array<string,mixed> $event
	 */
	public static function should_send( array $policy, array $event, string $target, string $class ): bool {
		$config = self::get_config();
		$url    = self::TARGET_TEAMS === $target ? $config['teams_url'] : $config['slack_url'];
		$allow  = '' !== $url
			&& in_array( $class, self::event_classes(), true )
			&& self::severity_for_class( $class ) >= $config['min_severity']
			&& self::routing_allows( $policy, $class );

		if ( function_exists( 'apply_filters' ) ) {
			$allow = (bool) apply_filters( self::FILTER_SHOULD_SEND, $allow, $event, $target, $class, $policy );
		}

		return $allow;
	}

	/**
	 * Funnel entry from Policy::append_log_event. Never throws.
	 *
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 */
	public static function observe( array $event, array $policy ): void {
		try {
			$class = self::classify( $event );
			if ( null === $class || self::CLASS_TEST === $class ) {
				return;
			}
			self::notify( $event, $policy, $class );
		} catch ( \Throwable $e ) {
			unset( $e );
		}
	}

	/**
	 * @param array<string,mixed> $event
	 * @param array<string,mixed> $policy
	 * @return array{slack:array{ok:bool,http_status:?int,error:string},teams:array{ok:bool,http_status:?int,error:string}}
	 */
	public static function notify( array $event, array $policy, string $class ): array {
		$empty = array(
			'ok'          => false,
			'http_status' => null,
			'error'       => '',
		);
		$out   = array(
			'slack' => $empty,
			'teams' => $empty,
		);

		foreach ( self::targets() as $target ) {
			if ( ! self::should_send( $policy, $event, $target, $class ) ) {
				continue;
			}
			$out[ $target ] = self::deliver_target( $target, $event, $class );
		}

		return $out;
	}

	/**
	 * Sample payload for the CLI test command. Logged as event=test.
	 *
	 * @return array{ok:bool,http_status:?int,error:string,target:string}
	 */
	public static function send_test( string $target ): array {
		$target = sanitize_key( $target );
		if ( ! in_array( $target, self::targets(), true ) ) {
			return array(
				'ok'          => false,
				'http_status' => null,
				'error'       => 'Unknown target. Use slack or teams.',
				'target'      => $target,
			);
		}

		$event = array(
			'chat_test' => true,
			'channel'   => self::CLASS_TEST,
			'plugin'    => 'handl-ai-connector-access-control/handl-ai-connector-access-control.php',
			'provider'  => 'test',
			'count'     => 1,
			'decision'  => 'test',
		);
		$result = self::deliver_target( $target, $event, self::CLASS_TEST );
		$result['target'] = $target;

		return $result;
	}

	/**
	 * @param array<string,mixed> $event
	 * @return array{ok:bool,http_status:?int,error:string}
	 */
	public static function deliver_target( string $target, array $event, string $class ): array {
		$config = self::get_config();
		$url    = self::TARGET_TEAMS === $target ? $config['teams_url'] : $config['slack_url'];
		if ( '' === $url ) {
			return array(
				'ok'          => false,
				'http_status' => null,
				'error'       => 'Webhook URL missing or invalid',
			);
		}

		$payload = self::TARGET_TEAMS === $target
			? self::build_teams_card( $event, $class )
			: self::build_slack_blocks( $event, $class );

		$log_event = self::CLASS_TEST === $class ? 'test' : 'chat_' . $target;

		try {
			return Alerts::deliver_webhook( $url, $payload, $log_event );
		} catch ( \Throwable $e ) {
			unset( $e );
			Alert_Health::record_result( Alert_Health::CHANNEL_WEBHOOK, false, 'Chat request error' );
			Webhook_Delivery_Log::push(
				array(
					'ts'          => time(),
					'event'       => $log_event,
					'http_status' => null,
					'retries'     => 0,
					'ok'          => false,
					'error'       => 'Chat request error',
				)
			);

			return array(
				'ok'          => false,
				'http_status' => null,
				'error'       => 'Chat request error',
			);
		}
	}

	/**
	 * @param array<string,mixed> $event
	 * @return array<string,mixed>
	 */
	public static function build_slack_blocks( array $event, string $class ): array {
		$fields = self::card_fields( $event, $class );
		$link   = self::deep_link( $class );
		$title  = self::class_title( $class );

		$block_fields = array();
		foreach ( $fields as $field ) {
			$block_fields[] = array(
				'type' => 'mrkdwn',
				'text' => '*' . $field['name'] . "*\n" . $field['value'],
			);
		}

		$blocks = array(
			array(
				'type' => 'header',
				'text' => array(
					'type'  => 'plain_text',
					'text'  => $title,
					'emoji' => false,
				),
			),
			array(
				'type'   => 'section',
				'fields' => $block_fields,
			),
		);
		if ( '' !== $link ) {
			$blocks[] = array(
				'type'     => 'actions',
				'elements' => array(
					array(
						'type' => 'button',
						'text' => array(
							'type'  => 'plain_text',
							'text'  => self::deep_link_label( $class ),
							'emoji' => false,
						),
						'url'  => $link,
					),
				),
			);
		}

		return array(
			'text'   => $title,
			'blocks' => $blocks,
			'event'  => self::CLASS_TEST === $class ? 'test' : 'chat_slack',
			'type'   => 'handl_aicac_chat_slack',
		);
	}

	/**
	 * @param array<string,mixed> $event
	 * @return array<string,mixed>
	 */
	public static function build_teams_card( array $event, string $class ): array {
		$fields = self::card_fields( $event, $class );
		$link   = self::deep_link( $class );
		$title  = self::class_title( $class );
		$facts  = array();
		foreach ( $fields as $field ) {
			$facts[] = array(
				'name'  => $field['name'],
				'value' => $field['value'],
			);
		}

		$card = array(
			'@type'      => 'MessageCard',
			'@context'   => 'https://schema.org/extensions',
			'summary'    => $title,
			'themeColor' => 'D32F2F',
			'title'      => $title,
			'sections'   => array(
				array(
					'facts' => $facts,
				),
			),
			'event'      => self::CLASS_TEST === $class ? 'test' : 'chat_teams',
			'type'       => 'handl_aicac_chat_teams',
		);
		if ( '' !== $link ) {
			$card['potentialAction'] = array(
				array(
					'@type'   => 'OpenUri',
					'name'    => self::deep_link_label( $class ),
					'targets' => array(
						array(
							'os'  => 'default',
							'uri' => $link,
						),
					),
				),
			);
		}

		return $card;
	}

	/**
	 * @param array<string,mixed> $event
	 * @return list<array{name:string,value:string}>
	 */
	public static function card_fields( array $event, string $class ): array {
		$plugin   = isset( $event['plugin'] ) ? (string) $event['plugin'] : '';
		$provider = isset( $event['provider'] ) ? (string) $event['provider'] : '';
		if ( '' === $provider && isset( $event['shadow_provider'] ) ) {
			$provider = (string) $event['shadow_provider'];
		}
		$count = isset( $event['count'] ) ? (int) $event['count'] : 0;
		if ( $count < 1 ) {
			$count = 1;
		}

		$fields   = array();
		$fields[] = array(
			'name'  => __( 'Event', 'handl-ai-connector-access-control' ),
			'value' => self::class_title( $class ),
		);
		$fields[] = array(
			'name'  => __( 'Plugin', 'handl-ai-connector-access-control' ),
			'value' => '' !== $plugin ? $plugin : __( '(none)', 'handl-ai-connector-access-control' ),
		);
		$fields[] = array(
			'name'  => __( 'Provider', 'handl-ai-connector-access-control' ),
			'value' => '' !== $provider ? $provider : __( '(none)', 'handl-ai-connector-access-control' ),
		);
		$fields[] = array(
			'name'  => __( 'Count', 'handl-ai-connector-access-control' ),
			'value' => (string) $count,
		);

		return $fields;
	}

	public static function class_title( string $class ): string {
		switch ( $class ) {
			case self::CLASS_DENY_STORM:
				return __( 'Deny storm', 'handl-ai-connector-access-control' );
			case self::CLASS_BUDGET:
				return __( 'Budget breach', 'handl-ai-connector-access-control' );
			case self::CLASS_TAMPER:
				return __( 'Tamper', 'handl-ai-connector-access-control' );
			case self::CLASS_POLICY:
				return __( 'Policy change', 'handl-ai-connector-access-control' );
			case self::CLASS_INCIDENT:
				return __( 'Incident', 'handl-ai-connector-access-control' );
			case self::CLASS_TEST:
				return __( 'Test message', 'handl-ai-connector-access-control' );
			case self::CLASS_DRIFT:
				return __( 'Usage change', 'handl-ai-connector-access-control' );
			case self::CLASS_ANOMALY:
				return __( 'Usage spike', 'handl-ai-connector-access-control' );
			case self::CLASS_SHADOW:
				return __( 'Direct AI call', 'handl-ai-connector-access-control' );
			case self::CLASS_CANARY:
				return __( 'Canary', 'handl-ai-connector-access-control' );
			default:
				return __( 'Alert', 'handl-ai-connector-access-control' );
		}
	}

	public static function deep_link( string $class ): string {
		if ( ! class_exists( Admin::class ) ) {
			return '';
		}
		$screen = 'activity';
		if ( self::CLASS_BUDGET === $class ) {
			$screen = 'insights';
		} elseif ( self::CLASS_POLICY === $class ) {
			$screen = 'rules';
		} elseif ( self::CLASS_TEST === $class ) {
			$screen = 'alerts';
		}

		return Admin::screen_url( $screen );
	}

	public static function deep_link_label( string $class ): string {
		if ( self::CLASS_BUDGET === $class ) {
			return __( 'Open Insights', 'handl-ai-connector-access-control' );
		}
		if ( self::CLASS_POLICY === $class ) {
			return __( 'Open Rules', 'handl-ai-connector-access-control' );
		}
		if ( self::CLASS_TEST === $class ) {
			return __( 'Open Alerts', 'handl-ai-connector-access-control' );
		}

		return __( 'Open Activity', 'handl-ai-connector-access-control' );
	}

	/**
	 * @return array{slack_configured:bool,teams_configured:bool,slack_url_masked:string,teams_url_masked:string,min_severity:int}
	 */
	public static function status(): array {
		$config = self::get_config();

		return array(
			'slack_configured'   => '' !== $config['slack_url'],
			'teams_configured'   => '' !== $config['teams_url'],
			'slack_url_masked'   => self::mask_url( $config['slack_url'] ),
			'teams_url_masked'   => self::mask_url( $config['teams_url'] ),
			'min_severity'       => $config['min_severity'],
		);
	}

	/**
	 * WP-CLI: `wp handl-aicac chat-notify status`.
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public static function cmd_status( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		$st = self::status();
		\WP_CLI::log(
			sprintf(
				'Chat notify: slack=%s %s | teams=%s %s | min_severity=%d',
				$st['slack_configured'] ? 'on' : 'off',
				$st['slack_url_masked'],
				$st['teams_configured'] ? 'on' : 'off',
				$st['teams_url_masked'],
				(int) $st['min_severity']
			)
		);
	}

	/**
	 * WP-CLI: `wp handl-aicac chat-notify set --slack= --teams= --min-severity=`.
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public static function cmd_set( $args, $assoc_args ): void {
		unset( $args );
		$current = self::get_config();
		if ( array_key_exists( 'slack', $assoc_args ) ) {
			$check = Alerts::validate_webhook_url_input( $assoc_args['slack'] );
			if ( ! $check['ok'] ) {
				\WP_CLI::error( 'Slack webhook URL is not a valid http(s) URL.' );
				return;
			}
			$current['slack_url'] = $check['url'];
		}
		if ( array_key_exists( 'teams', $assoc_args ) ) {
			$check = Alerts::validate_webhook_url_input( $assoc_args['teams'] );
			if ( ! $check['ok'] ) {
				\WP_CLI::error( 'Teams webhook URL is not a valid http(s) URL.' );
				return;
			}
			$current['teams_url'] = $check['url'];
		}
		if ( array_key_exists( 'min-severity', $assoc_args ) ) {
			$current['min_severity'] = $assoc_args['min-severity'];
		}
		$saved = self::save_config( $current );
		\WP_CLI::success(
			sprintf(
				'Saved. slack=%s teams=%s min_severity=%d',
				self::mask_url( $saved['slack_url'] ),
				self::mask_url( $saved['teams_url'] ),
				(int) $saved['min_severity']
			)
		);
	}

	/**
	 * WP-CLI: `wp handl-aicac chat-notify test --target=slack|teams`.
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public static function cmd_test( $args, $assoc_args ): void {
		unset( $args );
		$target = isset( $assoc_args['target'] ) ? sanitize_key( (string) $assoc_args['target'] ) : self::TARGET_SLACK;
		$result = self::send_test( $target );
		if ( ! empty( $result['ok'] ) ) {
			\WP_CLI::success( sprintf( 'Test delivered to %s.', $target ) );
			return;
		}
		\WP_CLI::error(
			sprintf(
				'Test to %s failed: %s',
				$target,
				'' !== $result['error'] ? $result['error'] : 'request failed'
			)
		);
	}
}
