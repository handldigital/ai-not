<?php
/**
 * AICAC-PRIVACY-HOOKS (#294): WordPress personal-data export/erase.
 *
 * Tools → Export/Erase Personal Data callbacks for Activity rows (including
 * prompt snapshots) and, when present, incident groups that name a user.
 * Erasure clears identifying fields and keeps aggregate counters.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Core privacy exporter/eraser + WP-CLI parity.
 */
final class Privacy_Hooks {

	public const EXPORTER_ID = 'handl-aicac';

	public const ERASER_ID = 'handl-aicac';

	public const PAGE_SIZE = 50;

	public const CHANNEL = 'privacy_erase';

	public const GROUP_ACTIVITY = 'handl-aicac-activity';

	public const GROUP_PROMPT = 'handl-aicac-prompt';

	public const GROUP_INCIDENT = 'handl-aicac-incident';

	public const FRIENDLY_NAME = 'AI activity (HandL)';

	public const GROUP_LABEL_ACTIVITY = 'AI activity';

	public const GROUP_LABEL_PROMPT = 'Prompt snapshots';

	public const GROUP_LABEL_INCIDENT = 'AI incidents';

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_filter( 'wp_privacy_personal_data_exporters', array( self::class, 'register_exporter' ) );
		add_filter( 'wp_privacy_personal_data_erasers', array( self::class, 'register_eraser' ) );

		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( '\WP_CLI' ) ) {
			\WP_CLI::add_command( 'handl-aicac privacy export', array( self::class, 'cmd_export' ) );
			\WP_CLI::add_command( 'handl-aicac privacy erase', array( self::class, 'cmd_erase' ) );
		}
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
	}

	/**
	 * @param mixed $exporters
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_exporter( $exporters ): array {
		if ( ! is_array( $exporters ) ) {
			$exporters = array();
		}
		$exporters[ self::EXPORTER_ID ] = array(
			'exporter_friendly_name' => self::FRIENDLY_NAME,
			'callback'               => array( self::class, 'export' ),
		);

		return $exporters;
	}

	/**
	 * @param mixed $erasers
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_eraser( $erasers ): array {
		if ( ! is_array( $erasers ) ) {
			$erasers = array();
		}
		$erasers[ self::ERASER_ID ] = array(
			'eraser_friendly_name' => self::FRIENDLY_NAME,
			'callback'             => array( self::class, 'erase' ),
		);

		return $erasers;
	}

	/**
	 * @param string $email_address Requested email.
	 * @param int    $page          1-based page.
	 * @return array{data:list<array<string,mixed>>,done:bool}
	 */
	public static function export( $email_address, $page = 1 ): array {
		$page  = max( 1, (int) $page );
		$items = self::collect_export_items( (string) $email_address );
		$offset = ( $page - 1 ) * self::PAGE_SIZE;
		$slice  = array_slice( $items, $offset, self::PAGE_SIZE );

		return array(
			'data' => array_values( $slice ),
			'done' => ( $offset + count( $slice ) ) >= count( $items ),
		);
	}

	/**
	 * @param string $email_address Requested email.
	 * @param int    $page          1-based page.
	 * @return array{items_removed:bool,items_retained:bool,messages:list<string>,done:bool}
	 */
	public static function erase( $email_address, $page = 1 ): array {
		$email   = self::normalize_email( (string) $email_address );
		$page    = max( 1, (int) $page );
		$user_id = self::resolve_user_id( $email );
		$log     = Policy::get_retained_log();

		$match_indexes = array();
		foreach ( $log as $i => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( ! self::row_matches( $row, $email, $user_id ) ) {
				continue;
			}
			if ( ! self::row_has_personal_data( $row ) ) {
				continue;
			}
			$match_indexes[] = (int) $i;
		}

		$offset = ( $page - 1 ) * self::PAGE_SIZE;
		$slice  = array_slice( $match_indexes, $offset, self::PAGE_SIZE );
		$done   = ( $offset + count( $slice ) ) >= count( $match_indexes );

		$removed = 0;
		foreach ( $slice as $i ) {
			if ( ! isset( $log[ $i ] ) || ! is_array( $log[ $i ] ) ) {
				continue;
			}
			$log[ $i ] = self::anonymize_row( $log[ $i ] );
			++$removed;
		}

		if ( $removed > 0 ) {
			update_option( Plugin::LOG_OPTION_KEY, $log, false );
			self::write_evidence( $removed, $email );
		}

		$messages = array();
		if ( $removed > 0 ) {
			$messages[] = sprintf(
				/* translators: %d: number of activity records anonymized */
				_n(
					'Removed personal details from %d AI activity record. Counts and decisions were kept.',
					'Removed personal details from %d AI activity records. Counts and decisions were kept.',
					$removed,
					'handl-ai-connector-access-control'
				),
				$removed
			);
		}

		return array(
			'items_removed'  => $removed > 0,
			'items_retained' => false,
			'messages'       => $messages,
			'done'           => $done,
		);
	}

	/**
	 * WP-CLI: `wp handl-aicac privacy export --email=`.
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public static function cmd_export( $args, $assoc_args ): void {
		unset( $args );
		$email = isset( $assoc_args['email'] ) ? (string) $assoc_args['email'] : '';
		if ( '' === self::normalize_email( $email ) ) {
			\WP_CLI::error( 'Provide --email.' );
			return;
		}
		$all  = array();
		$page = 1;
		do {
			$result = self::export( $email, $page );
			$data   = isset( $result['data'] ) && is_array( $result['data'] ) ? $result['data'] : array();
			foreach ( $data as $item ) {
				$all[] = $item;
			}
			$done = ! empty( $result['done'] );
			++$page;
		} while ( ! $done );

		\WP_CLI::print_value( $all, array( 'format' => 'json' ) );
	}

	/**
	 * WP-CLI: `wp handl-aicac privacy erase --email=`.
	 *
	 * @param array<int,string>    $args
	 * @param array<string,string> $assoc_args
	 */
	public static function cmd_erase( $args, $assoc_args ): void {
		unset( $args );
		$email = isset( $assoc_args['email'] ) ? (string) $assoc_args['email'] : '';
		if ( '' === self::normalize_email( $email ) ) {
			\WP_CLI::error( 'Provide --email.' );
			return;
		}
		$page    = 1;
		$removed = false;
		do {
			$result  = self::erase( $email, $page );
			$removed = $removed || ! empty( $result['items_removed'] );
			$done    = ! empty( $result['done'] );
			++$page;
		} while ( ! $done );

		if ( $removed ) {
			\WP_CLI::success( 'Removed personal details from matching AI activity records. Counts and decisions were kept.' );
			return;
		}
		\WP_CLI::success( 'No matching AI activity records.' );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function collect_export_items( string $email_address ): array {
		$email   = self::normalize_email( $email_address );
		$user_id = self::resolve_user_id( $email );
		if ( '' === $email && $user_id <= 0 ) {
			return array();
		}

		$log   = Policy::get_retained_log();
		$items = array();
		foreach ( $log as $i => $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			if ( ! self::row_matches( $row, $email, $user_id ) ) {
				continue;
			}
			$items[] = self::activity_item( (int) $i, $row );
			$preview = isset( $row['prompt_preview'] ) ? (string) $row['prompt_preview'] : '';
			if ( '' !== $preview ) {
				$items[] = self::prompt_item( (int) $i, $row, $preview );
			}
		}

		if ( class_exists( Incident::class, false ) ) {
			foreach ( Incident::group( $log ) as $incident ) {
				if ( ! is_array( $incident ) ) {
					continue;
				}
				$events = isset( $incident['events'] ) && is_array( $incident['events'] ) ? $incident['events'] : array();
				$hit    = false;
				foreach ( $events as $event ) {
					if ( is_array( $event ) && self::row_matches( $event, $email, $user_id ) ) {
						$hit = true;
						break;
					}
				}
				if ( $hit ) {
					$items[] = self::incident_item( $incident );
				}
			}
		}

		return $items;
	}

	/**
	 * @param array<string,mixed> $row
	 */
	public static function row_matches( array $row, string $email, int $user_id ): bool {
		if ( $user_id > 0 && isset( $row['user_id'] ) && (int) $row['user_id'] === $user_id ) {
			return true;
		}
		if ( '' === $email ) {
			return false;
		}
		$preview = isset( $row['prompt_preview'] ) ? (string) $row['prompt_preview'] : '';
		if ( '' !== $preview && false !== stripos( $preview, $email ) ) {
			return true;
		}

		return false;
	}

	/**
	 * @param array<string,mixed> $row
	 */
	public static function row_has_personal_data( array $row ): bool {
		if ( (int) ( $row['user_id'] ?? 0 ) > 0 ) {
			return true;
		}
		if ( '' !== trim( (string) ( $row['user_role'] ?? '' ) ) ) {
			return true;
		}
		if ( '' !== trim( (string) ( $row['prompt_preview'] ?? '' ) ) ) {
			return true;
		}
		if ( '' !== trim( (string) ( $row['uri'] ?? '' ) ) ) {
			return true;
		}

		return false;
	}

	/**
	 * @param array<string,mixed> $row
	 * @return array<string,mixed>
	 */
	public static function anonymize_row( array $row ): array {
		$row['user_id']         = 0;
		$row['user_role']       = '';
		$row['prompt_preview']  = '';
		$row['uri']             = '';

		return $row;
	}

	public static function resolve_user_id( string $email ): int {
		$email = self::normalize_email( $email );
		if ( '' === $email || ! function_exists( 'get_user_by' ) ) {
			return 0;
		}
		$user = get_user_by( 'email', $email );
		if ( is_object( $user ) && isset( $user->ID ) ) {
			return (int) $user->ID;
		}

		return 0;
	}

	public static function normalize_email( string $email ): string {
		$email = strtolower( trim( $email ) );
		if ( '' === $email ) {
			return '';
		}
		if ( function_exists( 'sanitize_email' ) ) {
			$email = strtolower( (string) sanitize_email( $email ) );
		}
		if ( function_exists( 'is_email' ) && ! is_email( $email ) ) {
			return '';
		}

		return $email;
	}

	/**
	 * @param array<string,mixed> $row
	 * @return array<string,mixed>
	 */
	private static function activity_item( int $index, array $row ): array {
		$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		$data = array();
		self::push_pair( $data, 'Time', self::format_ts( $ts ) );
		self::push_pair( $data, 'Plugin', isset( $row['plugin'] ) ? (string) $row['plugin'] : '' );
		self::push_pair( $data, 'Decision', isset( $row['decision'] ) ? (string) $row['decision'] : '' );
		self::push_pair( $data, 'Provider', isset( $row['provider'] ) ? (string) $row['provider'] : '' );
		self::push_pair( $data, 'Model', isset( $row['model'] ) ? (string) $row['model'] : '' );
		self::push_pair( $data, 'Prompt snapshot', isset( $row['prompt_preview'] ) ? (string) $row['prompt_preview'] : '' );
		self::push_pair( $data, 'Request path', isset( $row['uri'] ) ? (string) $row['uri'] : '' );
		$uid = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
		if ( $uid > 0 ) {
			self::push_pair( $data, 'User ID', (string) $uid );
		}

		return array(
			'group_id'    => self::GROUP_ACTIVITY,
			'group_label' => self::GROUP_LABEL_ACTIVITY,
			'item_id'     => 'handl-aicac-activity-' . $index,
			'data'        => $data,
		);
	}

	/**
	 * @param array<string,mixed> $row
	 * @return array<string,mixed>
	 */
	private static function prompt_item( int $index, array $row, string $preview ): array {
		$data = array();
		self::push_pair( $data, 'Time', self::format_ts( isset( $row['ts'] ) ? (int) $row['ts'] : 0 ) );
		self::push_pair( $data, 'Plugin', isset( $row['plugin'] ) ? (string) $row['plugin'] : '' );
		self::push_pair( $data, 'Prompt snapshot', $preview );

		return array(
			'group_id'    => self::GROUP_PROMPT,
			'group_label' => self::GROUP_LABEL_PROMPT,
			'item_id'     => 'handl-aicac-prompt-' . $index,
			'data'        => $data,
		);
	}

	/**
	 * @param array<string,mixed> $incident
	 * @return array<string,mixed>
	 */
	private static function incident_item( array $incident ): array {
		$id   = isset( $incident['id'] ) ? (string) $incident['id'] : '';
		$data = array();
		self::push_pair( $data, 'Incident', $id );
		self::push_pair( $data, 'Started', self::format_ts( isset( $incident['started_ts'] ) ? (int) $incident['started_ts'] : 0 ) );
		self::push_pair( $data, 'Ended', self::format_ts( isset( $incident['ended_ts'] ) ? (int) $incident['ended_ts'] : 0 ) );

		return array(
			'group_id'    => self::GROUP_INCIDENT,
			'group_label' => self::GROUP_LABEL_INCIDENT,
			'item_id'     => 'handl-aicac-incident-' . $id,
			'data'        => $data,
		);
	}

	/**
	 * @param list<array{name:string,value:string}> $data
	 */
	private static function push_pair( array &$data, string $name, string $value ): void {
		if ( '' === $value ) {
			return;
		}
		$data[] = array(
			'name'  => $name,
			'value' => $value,
		);
	}

	private static function format_ts( int $ts ): string {
		if ( $ts <= 0 ) {
			return '';
		}
		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( 'c', $ts );
		}

		return gmdate( 'c', $ts );
	}

	private static function write_evidence( int $erased_count, string $email ): void {
		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) ) {
			$log = array();
		}
		$log[] = array(
			'ts'             => Clock::now(),
			'channel'        => self::CHANNEL,
			'decision'       => 'erased',
			'plugin'         => '',
			'user_id'        => 0,
			'user_role'      => '',
			'prompt_preview' => '',
			'uri'            => '',
			'erased_count'   => $erased_count,
			'email_sha1'     => sha1( strtolower( $email ) ),
		);
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
	}
}

Privacy_Hooks::init();
