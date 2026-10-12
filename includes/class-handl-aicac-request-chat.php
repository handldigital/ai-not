<?php
/**
 * AICAC-REQUEST-CHAT (#321): Slack/Teams cards for access requests.
 *
 * Listens to Access_Request creation; reuses Chat_Notify webhook URLs /
 * masking / health isolation. Approval stays in wp-admin (deep link only).
 * Chat failure never blocks the request or email path.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Deliver pending access-request cards to configured chat webhooks.
 */
final class Request_Chat {

	public const OPTION_KEY = 'handl_aicac_request_chat';

	/** Per-request delivery ledger: id => {created:int, reminder:int}. */
	public const SENT_OPTION_KEY = 'handl_aicac_request_chat_sent';

	public const CRON_HOOK = 'handl_aicac_request_chat_remind';

	public const REMINDER_WINDOW = DAY_IN_SECONDS;

	public const TITLE = 'AI access request';

	public const TITLE_REMINDER = 'AI access request still pending';

	public const REVIEW_LABEL = 'Review request';

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		self::ensure_cron();
		add_action( self::CRON_HOOK, array( self::class, 'cron_remind' ) );

		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( '\WP_CLI' ) ) {
			\WP_CLI::add_command( 'handl-aicac request-chat status', array( self::class, 'cmd_status' ) );
			\WP_CLI::add_command( 'handl-aicac request-chat set', array( self::class, 'cmd_set' ) );
		}
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		delete_option( self::OPTION_KEY );
		delete_option( self::SENT_OPTION_KEY );
	}

	/**
	 * @param mixed $raw
	 * @return array{enabled:bool}
	 */
	public static function sanitize_config( $raw ): array {
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}

		return array(
			'enabled' => ! empty( $raw['enabled'] ),
		);
	}

	/**
	 * @return array{enabled:bool}
	 */
	public static function get_config(): array {
		return self::sanitize_config( get_option( self::OPTION_KEY, array() ) );
	}

	/**
	 * @param array<string,mixed> $config
	 * @return array{enabled:bool}
	 */
	public static function save_config( array $config ): array {
		$clean = self::sanitize_config( $config );
		if ( ! $clean['enabled'] ) {
			delete_option( self::OPTION_KEY );
			return $clean;
		}
		update_option( self::OPTION_KEY, $clean, false );

		return $clean;
	}

	public static function is_enabled(): bool {
		return ! empty( self::get_config()['enabled'] );
	}

	/**
	 * Called from Access_Request after a NEW pending row is stored.
	 * Collapse / same-id updates must not call this.
	 *
	 * @param array<string,mixed> $row Request row.
	 */
	public static function on_created( array $row, ?int $now = null ): void {
		$now = null !== $now ? (int) $now : time();
		try {
			self::deliver_for_row( $row, 'created', $now );
		} catch ( \Throwable $e ) {
			unset( $e );
		}
	}

	/**
	 * Cron: remind once per still-pending request after the email collapse window.
	 */
	public static function cron_remind(): void {
		try {
			self::remind_pending( time() );
		} catch ( \Throwable $e ) {
			unset( $e );
		}
	}

	/**
	 * @param array<string,mixed> $row
	 * @param 'created'|'reminder' $kind
	 * @return array{slack:array{ok:bool,http_status:?int,error:string},teams:array{ok:bool,http_status:?int,error:string},skipped:string}
	 */
	public static function deliver_for_row( array $row, string $kind, ?int $now = null ): array {
		$now   = null !== $now ? (int) $now : time();
		$empty = array(
			'ok'          => false,
			'http_status' => null,
			'error'       => '',
		);
		$out   = array(
			'slack'   => $empty,
			'teams'   => $empty,
			'skipped' => '',
		);

		if ( 'created' !== $kind && 'reminder' !== $kind ) {
			$out['skipped'] = 'bad_kind';
			return $out;
		}

		if ( ! self::is_enabled() ) {
			$out['skipped'] = 'disabled';
			return $out;
		}

		$id = self::sanitize_request_id( (string) ( $row['id'] ?? '' ) );
		if ( '' === $id ) {
			$out['skipped'] = 'no_id';
			return $out;
		}

		$status = sanitize_key( (string) ( $row['status'] ?? '' ) );
		if ( Access_Request::STATUS_PENDING !== $status ) {
			$out['skipped'] = 'not_pending';
			return $out;
		}

		$sent = self::get_sent_map();
		$prior = isset( $sent[ $id ] ) && is_array( $sent[ $id ] ) ? $sent[ $id ] : array();
		if ( 'created' === $kind && ! empty( $prior['created'] ) ) {
			$out['skipped'] = 'deduped';
			return $out;
		}
		if ( 'reminder' === $kind && ! empty( $prior['reminder'] ) ) {
			$out['skipped'] = 'deduped';
			return $out;
		}
		if ( 'reminder' === $kind && empty( $prior['created'] ) ) {
			// Reminder only after an initial card (or treat create-miss as allow).
		}

		if ( ! class_exists( Chat_Notify::class, false ) ) {
			$out['skipped'] = 'no_chat';
			return $out;
		}

		$config = Chat_Notify::get_config();
		$has_slack = '' !== (string) ( $config['slack_url'] ?? '' );
		$has_teams = '' !== (string) ( $config['teams_url'] ?? '' );
		if ( ! $has_slack && ! $has_teams ) {
			$out['skipped'] = 'no_webhooks';
			return $out;
		}

		$event = self::row_to_event( $row, $kind );
		foreach ( Chat_Notify::targets() as $target ) {
			$url = Chat_Notify::TARGET_TEAMS === $target
				? (string) ( $config['teams_url'] ?? '' )
				: (string) ( $config['slack_url'] ?? '' );
			if ( '' === $url ) {
				continue;
			}
			$payload = Chat_Notify::TARGET_TEAMS === $target
				? self::build_teams_card( $event, $kind )
				: self::build_slack_blocks( $event, $kind );
			$log_event = 'chat_' . $target;
			try {
				$out[ $target ] = Alerts::deliver_webhook( $url, $payload, $log_event );
			} catch ( \Throwable $e ) {
				unset( $e );
				if ( class_exists( Alert_Health::class, false ) ) {
					Alert_Health::record_result( Alert_Health::CHANNEL_WEBHOOK, false, 'Chat request error' );
				}
				if ( class_exists( Webhook_Delivery_Log::class, false ) ) {
					Webhook_Delivery_Log::push(
						array(
							'ts'          => $now,
							'event'       => $log_event,
							'http_status' => null,
							'retries'     => 0,
							'ok'          => false,
							'error'       => 'Chat request error',
						)
					);
				}
				$out[ $target ] = array(
					'ok'          => false,
					'http_status' => null,
					'error'       => 'Chat request error',
				);
			}
		}

		if ( ! isset( $sent[ $id ] ) || ! is_array( $sent[ $id ] ) ) {
			$sent[ $id ] = array(
				'created'  => 0,
				'reminder' => 0,
			);
		}
		$sent[ $id ][ $kind ] = $now;
		self::save_sent_map( $sent );

		return $out;
	}

	/**
	 * Scan pending requests; remind once after REMINDER_WINDOW from first email/create.
	 *
	 * @return int Number of reminder attempts.
	 */
	public static function remind_pending( ?int $now = null ): int {
		$now = null !== $now ? (int) $now : time();
		if ( ! self::is_enabled() ) {
			return 0;
		}
		if ( ! class_exists( Access_Request::class, false ) ) {
			return 0;
		}

		$map  = get_option( Access_Request::OPTION_KEY, array() );
		if ( ! is_array( $map ) ) {
			return 0;
		}

		$sent  = self::get_sent_map();
		$count = 0;
		foreach ( $map as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( Access_Request::STATUS_PENDING !== sanitize_key( (string) ( $row['status'] ?? '' ) ) ) {
				continue;
			}
			$id = self::sanitize_request_id( (string) ( $row['id'] ?? '' ) );
			if ( '' === $id ) {
				continue;
			}
			$prior = isset( $sent[ $id ] ) && is_array( $sent[ $id ] ) ? $sent[ $id ] : array();
			if ( ! empty( $prior['reminder'] ) ) {
				continue;
			}
			$anchor = isset( $row['emailed_ts'] ) ? (int) $row['emailed_ts'] : 0;
			if ( $anchor <= 0 ) {
				$anchor = isset( $prior['created'] ) ? (int) $prior['created'] : 0;
			}
			if ( $anchor <= 0 ) {
				$anchor = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			}
			if ( $anchor <= 0 || ( $anchor + self::REMINDER_WINDOW ) > $now ) {
				continue;
			}
			self::deliver_for_row( $row, 'reminder', $now );
			++$count;
		}

		return $count;
	}

	/**
	 * @param array<string,mixed> $row
	 * @param 'created'|'reminder' $kind
	 * @return array<string,mixed>
	 */
	public static function row_to_event( array $row, string $kind ): array {
		$plugin = Plugin_Profile::sanitize_plugin( (string) ( $row['plugin'] ?? '' ) );
		$reason = sanitize_text_field( (string) ( $row['reason'] ?? '' ) );
		$login  = sanitize_text_field( (string) ( $row['user_login'] ?? '' ) );

		return array(
			'plugin'           => $plugin,
			'provider'         => '',
			'scope'            => '' !== $reason ? $reason : __( 'AI Client access', 'handl-ai-connector-access-control' ),
			'requester'        => $login,
			'request_id'       => self::sanitize_request_id( (string) ( $row['id'] ?? '' ) ),
			'request_chat'     => true,
			'request_reminder' => 'reminder' === $kind,
		);
	}

	/**
	 * @param array<string,mixed> $event
	 * @return list<array{name:string,value:string}>
	 */
	public static function card_fields( array $event ): array {
		$plugin   = (string) ( $event['plugin'] ?? '' );
		$provider = (string) ( $event['provider'] ?? '' );
		$scope    = (string) ( $event['scope'] ?? '' );
		$who      = (string) ( $event['requester'] ?? '' );

		return array(
			array(
				'name'  => __( 'Plugin', 'handl-ai-connector-access-control' ),
				'value' => '' !== $plugin ? $plugin : __( 'Not recorded', 'handl-ai-connector-access-control' ),
			),
			array(
				'name'  => __( 'Provider', 'handl-ai-connector-access-control' ),
				'value' => '' !== $provider ? $provider : __( 'Not recorded', 'handl-ai-connector-access-control' ),
			),
			array(
				'name'  => __( 'Requested', 'handl-ai-connector-access-control' ),
				'value' => '' !== $scope ? $scope : __( 'AI Client access', 'handl-ai-connector-access-control' ),
			),
			array(
				'name'  => __( 'Requester', 'handl-ai-connector-access-control' ),
				'value' => '' !== $who ? $who : __( 'Not recorded', 'handl-ai-connector-access-control' ),
			),
		);
	}

	public static function review_url(): string {
		if ( class_exists( Admin::class, false ) ) {
			return Admin::screen_url( 'protections' );
		}

		return '';
	}

	/**
	 * @param array<string,mixed> $event
	 * @param 'created'|'reminder' $kind
	 * @return array<string,mixed>
	 */
	public static function build_slack_blocks( array $event, string $kind ): array {
		$title  = 'reminder' === $kind ? self::TITLE_REMINDER : self::TITLE;
		$fields = self::card_fields( $event );
		$link   = self::review_url();

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
							'text'  => self::REVIEW_LABEL,
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
			'event'  => 'chat_slack',
			'type'   => 'handl_aicac_chat_slack',
		);
	}

	/**
	 * @param array<string,mixed> $event
	 * @param 'created'|'reminder' $kind
	 * @return array<string,mixed>
	 */
	public static function build_teams_card( array $event, string $kind ): array {
		$title  = 'reminder' === $kind ? self::TITLE_REMINDER : self::TITLE;
		$fields = self::card_fields( $event );
		$link   = self::review_url();
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
			'themeColor' => '1565C0',
			'title'      => $title,
			'sections'   => array(
				array(
					'facts' => $facts,
				),
			),
			'event'      => 'chat_teams',
			'type'       => 'handl_aicac_chat_teams',
		);
		if ( '' !== $link ) {
			$card['potentialAction'] = array(
				array(
					'@type'   => 'OpenUri',
					'name'    => self::REVIEW_LABEL,
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
	 * @return array{enabled:bool,slack_configured:bool,teams_configured:bool,slack_url_masked:string,teams_url_masked:string}
	 */
	public static function status(): array {
		$config = self::get_config();
		$chat   = class_exists( Chat_Notify::class, false )
			? Chat_Notify::get_config()
			: array(
				'slack_url' => '',
				'teams_url' => '',
			);

		return array(
			'enabled'          => ! empty( $config['enabled'] ),
			'slack_configured' => '' !== (string) ( $chat['slack_url'] ?? '' ),
			'teams_configured' => '' !== (string) ( $chat['teams_url'] ?? '' ),
			'slack_url_masked' => class_exists( Chat_Notify::class, false )
				? Chat_Notify::mask_url( $chat['slack_url'] ?? '' )
				: '',
			'teams_url_masked' => class_exists( Chat_Notify::class, false )
				? Chat_Notify::mask_url( $chat['teams_url'] ?? '' )
				: '',
		);
	}

	/**
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public static function cmd_status( $args, $assoc_args ): void {
		unset( $args, $assoc_args );
		$st = self::status();
		\WP_CLI::log(
			sprintf(
				'Request chat: enabled=%s | slack=%s %s | teams=%s %s',
				$st['enabled'] ? 'on' : 'off',
				$st['slack_configured'] ? 'on' : 'off',
				$st['slack_url_masked'],
				$st['teams_configured'] ? 'on' : 'off',
				$st['teams_url_masked']
			)
		);
	}

	/**
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public static function cmd_set( $args, $assoc_args ): void {
		unset( $args );
		$current = self::get_config();
		if ( array_key_exists( 'enabled', $assoc_args ) ) {
			$current['enabled'] = Chat_Notify::flag( $assoc_args['enabled'] );
		}
		$saved = self::save_config( $current );
		\WP_CLI::success(
			sprintf(
				'Saved. request-chat enabled=%s',
				! empty( $saved['enabled'] ) ? 'on' : 'off'
			)
		);
	}

	private static function ensure_cron(): void {
		if ( ! function_exists( 'wp_next_scheduled' ) || ! function_exists( 'wp_schedule_event' ) ) {
			return;
		}
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::CRON_HOOK );
		}
	}

	/**
	 * @return array<string,array{created:int,reminder:int}>
	 */
	private static function get_sent_map(): array {
		$raw = get_option( self::SENT_OPTION_KEY, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $id => $row ) {
			$id = self::sanitize_request_id( (string) $id );
			if ( '' === $id || ! is_array( $row ) ) {
				continue;
			}
			$out[ $id ] = array(
				'created'  => isset( $row['created'] ) ? (int) $row['created'] : 0,
				'reminder' => isset( $row['reminder'] ) ? (int) $row['reminder'] : 0,
			);
		}

		return $out;
	}

	/**
	 * @param array<string,array{created:int,reminder:int}> $map
	 */
	private static function save_sent_map( array $map ): void {
		if ( empty( $map ) ) {
			delete_option( self::SENT_OPTION_KEY );
			return;
		}
		// Cap ledger size — drop resolved ids older than 14 days when map grows.
		if ( count( $map ) > 200 ) {
			$cutoff = time() - ( 14 * DAY_IN_SECONDS );
			foreach ( $map as $id => $row ) {
				$last = max( (int) ( $row['created'] ?? 0 ), (int) ( $row['reminder'] ?? 0 ) );
				if ( $last > 0 && $last < $cutoff ) {
					unset( $map[ $id ] );
				}
			}
		}
		update_option( self::SENT_OPTION_KEY, $map, false );
	}

	private static function sanitize_request_id( string $id ): string {
		$id = strtolower( preg_replace( '/[^a-f0-9]/', '', $id ) ?? '' );

		return ( 32 === strlen( $id ) ) ? $id : '';
	}
}
