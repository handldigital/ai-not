<?php
/**
 * AICAC-COACH (#437): repeat-deny outreach (admin-initiated only).
 *
 * Spots users hitting the same deny rule repeatedly in a trailing window and
 * lets an admin preview + send a plain-language explainer email. Never
 * auto-sends. Zero edits to Alerts, FRICTION, WHY, FIRST-DENY, or SOFT-DENY.
 *
 * Design rules:
 * - Own two options (settings + state). OFF by default.
 * - Throttled admin_init scan over the activity log (guarded reads).
 * - Email via wp_mail directly — never touches the Alerts class.
 * - Sent state stays quiet; re-arms after 14 quiet days.
 * - README-FREE.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Repeat-deny coaching outreach.
 */
final class Coach {

	public const SETTINGS_OPTION = 'handl_aicac_coach';

	public const STATE_OPTION = 'handl_aicac_coach_state';

	public const PAGE_SLUG = 'handl-aicac-coach';

	public const FRAMING = 'admin_initiated_never_auto_sends';

	public const WINDOW_DAYS = 14;

	public const QUIET_DAYS = 14;

	public const DEFAULT_THRESHOLD = 5;

	public const CHECK_THROTTLE_SECONDS = 300;

	public const ACTION_SAVE    = 'handl_aicac_coach_save';
	public const ACTION_PREVIEW = 'handl_aicac_coach_preview';
	public const ACTION_SEND    = 'handl_aicac_coach_send';

	public const POST_PRESENT   = 'handl_aicac_coach_present';
	public const POST_ENABLED   = 'handl_aicac_coach_enabled';
	public const POST_THRESHOLD = 'handl_aicac_coach_threshold';

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	/** @var int|null */
	private static $test_now = null;

	/** @var list<array<string,mixed>>|null Injected activity log for tests. */
	private static $test_log = null;

	/** @var array<string,mixed>|null Injected policy for tests. */
	private static $test_policy = null;

	/** @var bool|null Force access-request availability in tests. */
	private static $test_access_request = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );
		add_action( 'admin_post_' . self::ACTION_PREVIEW, array( self::class, 'handle_preview' ) );
		add_action( 'admin_post_' . self::ACTION_SEND, array( self::class, 'handle_send' ) );

		if ( self::is_enabled() ) {
			add_action( 'admin_init', array( self::class, 'maybe_scan' ), 30 );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered          = false;
		self::$test_mails          = array();
		self::$test_now            = null;
		self::$test_log            = null;
		self::$test_policy         = null;
		self::$test_access_request = null;
		delete_option( self::SETTINGS_OPTION );
		delete_option( self::STATE_OPTION );
	}

	/**
	 * @return list<array<string,mixed>>
	 */
	public static function test_mails(): array {
		return self::$test_mails;
	}

	public static function set_test_now( ?int $now ): void {
		self::$test_now = $now;
	}

	/**
	 * @param list<array<string,mixed>>|null $log Log or null to read live.
	 */
	public static function set_test_log( ?array $log ): void {
		self::$test_log = $log;
	}

	/**
	 * @param array<string,mixed>|null $policy Policy or null to read live.
	 */
	public static function set_test_policy( ?array $policy ): void {
		self::$test_policy = $policy;
	}

	public static function set_test_access_request( ?bool $enabled ): void {
		self::$test_access_request = $enabled;
	}

	/* ---------------------------------------------------------------------
	 * Settings
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{enabled:bool,threshold:int}
	 */
	public static function defaults(): array {
		return array(
			'enabled'   => false,
			'threshold' => self::DEFAULT_THRESHOLD,
		);
	}

	/**
	 * @return array{enabled:bool,threshold:int}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool,threshold:int}
	 */
	public static function sanitize_settings( $raw ): array {
		$out = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$out['enabled'] = ! empty( $raw['enabled'] );
		$threshold      = isset( $raw['threshold'] ) ? (int) $raw['threshold'] : self::DEFAULT_THRESHOLD;
		if ( $threshold < 2 ) {
			$threshold = 2;
		}
		if ( $threshold > 100 ) {
			$threshold = 100;
		}
		$out['threshold'] = $threshold;

		return $out;
	}

	/**
	 * @param array<string,mixed> $settings Settings.
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
		return ! empty( self::get_settings()['enabled'] );
	}

	public static function threshold(): int {
		return (int) self::get_settings()['threshold'];
	}

	/* ---------------------------------------------------------------------
	 * State
	 * ------------------------------------------------------------------ */

	/**
	 * @return array{last_scan_ts:int,sent:array<string,array{sent_ts:int,streak:int}>}
	 */
	public static function defaults_state(): array {
		return array(
			'last_scan_ts' => 0,
			'sent'         => array(),
		);
	}

	/**
	 * @return array{last_scan_ts:int,sent:array<string,array{sent_ts:int,streak:int}>}
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw state.
	 * @return array{last_scan_ts:int,sent:array<string,array{sent_ts:int,streak:int}>}
	 */
	public static function sanitize_state( $raw ): array {
		$out = self::defaults_state();
		if ( ! is_array( $raw ) ) {
			return $out;
		}
		$out['last_scan_ts'] = isset( $raw['last_scan_ts'] ) ? max( 0, (int) $raw['last_scan_ts'] ) : 0;
		$sent                = array();
		if ( isset( $raw['sent'] ) && is_array( $raw['sent'] ) ) {
			foreach ( $raw['sent'] as $key => $row ) {
				$key = self::sanitize_key_string( (string) $key );
				if ( '' === $key || ! is_array( $row ) ) {
					continue;
				}
				$sent[ $key ] = array(
					'sent_ts' => isset( $row['sent_ts'] ) ? max( 0, (int) $row['sent_ts'] ) : 0,
					'streak'  => isset( $row['streak'] ) ? max( 0, (int) $row['streak'] ) : 0,
				);
			}
		}
		$out['sent'] = $sent;

		return $out;
	}

	/**
	 * @param array{last_scan_ts:int,sent:array<string,array{sent_ts:int,streak:int}>} $state State.
	 */
	public static function put_state( array $state ): void {
		$clean = self::sanitize_state( $state );
		if ( $clean === self::defaults_state() ) {
			delete_option( self::STATE_OPTION );
		} else {
			update_option( self::STATE_OPTION, $clean, false );
		}
	}

	private static function sanitize_key_string( string $key ): string {
		$key = strtolower( trim( $key ) );
		$key = preg_replace( '/[^a-z0-9_|.:\-]+/', '', $key );

		return is_string( $key ) ? $key : '';
	}

	/* ---------------------------------------------------------------------
	 * Time + log
	 * ------------------------------------------------------------------ */

	public static function resolve_now( ?int $now = null ): int {
		if ( null !== self::$test_now ) {
			return (int) self::$test_now;
		}
		if ( null !== $now ) {
			return $now;
		}
		if ( class_exists( Clock::class, false ) && method_exists( Clock::class, 'now' ) ) {
			return (int) Clock::now();
		}

		return time();
	}

	/**
	 * Guarded activity-log read. Empty + notice when the store is absent.
	 *
	 * @return array{rows:list<array<string,mixed>>,available:bool,notice:string}
	 */
	public static function read_activity_log(): array {
		if ( null !== self::$test_log ) {
			return array(
				'rows'      => array_values( self::$test_log ),
				'available' => true,
				'notice'    => '',
			);
		}
		if ( ! class_exists( Plugin::class, false ) ) {
			return array(
				'rows'      => array(),
				'available' => false,
				'notice'    => 'Activity log source unavailable.',
			);
		}
		$raw = get_option( Plugin::LOG_OPTION_KEY, null );
		if ( null === $raw || false === $raw ) {
			return array(
				'rows'      => array(),
				'available' => false,
				'notice'    => 'Activity log source unavailable.',
			);
		}
		if ( ! is_array( $raw ) ) {
			return array(
				'rows'      => array(),
				'available' => true,
				'notice'    => '',
			);
		}
		$rows = array();
		foreach ( $raw as $row ) {
			if ( is_array( $row ) ) {
				$rows[] = $row;
			}
		}

		return array(
			'rows'      => $rows,
			'available' => true,
			'notice'    => '',
		);
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function resolve_policy(): array {
		if ( null !== self::$test_policy ) {
			return self::$test_policy;
		}
		if ( class_exists( Policy::class, false ) && method_exists( Policy::class, 'get_policy' ) ) {
			$policy = Policy::get_policy();
			if ( is_array( $policy ) ) {
				return $policy;
			}
		}

		return array();
	}

	public static function access_request_enabled(): bool {
		if ( null !== self::$test_access_request ) {
			return (bool) self::$test_access_request;
		}

		return class_exists( Access_Request::class, false );
	}

	/* ---------------------------------------------------------------------
	 * Streak detection
	 * ------------------------------------------------------------------ */

	/**
	 * Build a stable user+rule key.
	 */
	public static function candidate_key( int $user_id, string $rule ): string {
		$user_id = max( 0, $user_id );
		$rule    = self::sanitize_key_string( $rule );
		if ( '' === $rule ) {
			$rule = 'unknown';
		}

		return $user_id . '|' . $rule;
	}

	/**
	 * Rule identity for a deny row: denial_reason, else plugin basename.
	 *
	 * @param array<string,mixed> $row Activity row.
	 */
	public static function rule_from_row( array $row ): string {
		$reason = isset( $row['denial_reason'] ) ? sanitize_key( (string) $row['denial_reason'] ) : '';
		if ( '' !== $reason ) {
			return $reason;
		}
		$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
		$plugin = strtolower( trim( $plugin ) );
		if ( '' !== $plugin ) {
			return 'plugin:' . self::sanitize_key_string( str_replace( '/', '.', $plugin ) );
		}

		return 'unknown';
	}

	/**
	 * Aggregate deny streaks in the trailing window.
	 *
	 * @return list<array{key:string,user_id:int,rule:string,streak:int,last_deny_ts:int,first_deny_ts:int,plugin:string,rule_note:string}>
	 */
	public static function detect_streaks( ?int $now = null, ?int $threshold = null ): array {
		$now       = self::resolve_now( $now );
		$threshold = null === $threshold ? self::threshold() : max( 2, (int) $threshold );
		$window    = self::WINDOW_DAYS * DAY_IN_SECONDS;
		if ( ! defined( 'DAY_IN_SECONDS' ) ) {
			$window = self::WINDOW_DAYS * 86400;
		}
		$cutoff = $now - $window;

		$pack = self::read_activity_log();
		if ( ! $pack['available'] ) {
			return array();
		}

		/** @var array<string,array{user_id:int,rule:string,streak:int,last_deny_ts:int,first_deny_ts:int,plugin:string,rule_note:string}> $agg */
		$agg = array();
		foreach ( $pack['rows'] as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$decision = isset( $row['decision'] ) ? (string) $row['decision'] : '';
			if ( 'deny' !== $decision ) {
				continue;
			}
			$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts < $cutoff || $ts > $now ) {
				continue;
			}
			$user_id = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
			if ( $user_id <= 0 ) {
				continue;
			}
			$rule = self::rule_from_row( $row );
			$key  = self::candidate_key( $user_id, $rule );
			$plugin = isset( $row['plugin'] ) ? (string) $row['plugin'] : '';
			$note   = '';
			if ( class_exists( Rule_Notes::class, false ) && method_exists( Rule_Notes::class, 'from_activity_row' ) ) {
				$note = (string) Rule_Notes::from_activity_row( $row );
			}
			if ( ! isset( $agg[ $key ] ) ) {
				$agg[ $key ] = array(
					'user_id'       => $user_id,
					'rule'          => $rule,
					'streak'        => 0,
					'last_deny_ts'  => $ts,
					'first_deny_ts' => $ts,
					'plugin'        => $plugin,
					'rule_note'     => $note,
				);
			}
			$agg[ $key ]['streak']++;
			if ( $ts > $agg[ $key ]['last_deny_ts'] ) {
				$agg[ $key ]['last_deny_ts'] = $ts;
				if ( '' !== $plugin ) {
					$agg[ $key ]['plugin'] = $plugin;
				}
				if ( '' !== $note ) {
					$agg[ $key ]['rule_note'] = $note;
				}
			}
			if ( $ts < $agg[ $key ]['first_deny_ts'] ) {
				$agg[ $key ]['first_deny_ts'] = $ts;
			}
		}

		$out = array();
		foreach ( $agg as $key => $row ) {
			if ( (int) $row['streak'] < $threshold ) {
				continue;
			}
			$out[] = array_merge( array( 'key' => $key ), $row );
		}
		usort(
			$out,
			static function ( array $a, array $b ): int {
				return ( (int) $b['streak'] ) <=> ( (int) $a['streak'] );
			}
		);

		return $out;
	}

	/**
	 * Candidates that still need outreach (threshold met, not quiet-sent).
	 *
	 * @return list<array{key:string,user_id:int,rule:string,streak:int,last_deny_ts:int,first_deny_ts:int,plugin:string,rule_note:string,status:string}>
	 */
	public static function candidates( ?int $now = null ): array {
		$now      = self::resolve_now( $now );
		$state    = self::get_state();
		$quiet    = self::QUIET_DAYS * ( defined( 'DAY_IN_SECONDS' ) ? DAY_IN_SECONDS : 86400 );
		$streaks  = self::detect_streaks( $now );
		$out      = array();

		foreach ( $streaks as $row ) {
			$key  = (string) $row['key'];
			$sent = isset( $state['sent'][ $key ] ) && is_array( $state['sent'][ $key ] )
				? $state['sent'][ $key ]
				: null;

			if ( null !== $sent ) {
				$sent_ts = (int) $sent['sent_ts'];
				$last    = (int) $row['last_deny_ts'];
				// Quiet while no new denies after send, until quiet period elapses past last deny.
				if ( $last <= $sent_ts ) {
					// No denies after send — still quiet.
					continue;
				}
				// Denies resumed after send: re-arm only after quiet_days with no contact window
				// measured from sent_ts — if last deny is within quiet of sent, stay quiet;
				// if gap between sent and first post-send deny exceeds quiet, treat as re-armed.
				// Spec: re-arms if streak resumes after 14 quiet days.
				// Interpret: after send, if there are 14 days with no denies, clear sent;
				// then a new streak can appear. If denies continue without a quiet gap, stay quiet.
				$gap_after_send = $last - $sent_ts;
				if ( $gap_after_send < $quiet ) {
					// Streak continued without a quiet period — stay quiet (already coached).
					continue;
				}
				// Quiet gap satisfied between send and resumed activity — eligible again.
			}

			$row['status'] = 'ready';
			$out[]         = $row;
		}

		return $out;
	}

	/**
	 * Drop sent entries whose last deny is older than quiet days (re-arm housekeeping).
	 */
	public static function prune_sent_state( ?int $now = null ): int {
		$now   = self::resolve_now( $now );
		$quiet = self::QUIET_DAYS * ( defined( 'DAY_IN_SECONDS' ) ? DAY_IN_SECONDS : 86400 );
		$state = self::get_state();
		$pack  = self::read_activity_log();
		$last_by_key = array();
		foreach ( $pack['rows'] as $row ) {
			if ( ! is_array( $row ) || 'deny' !== (string) ( $row['decision'] ?? '' ) ) {
				continue;
			}
			$user_id = isset( $row['user_id'] ) ? (int) $row['user_id'] : 0;
			if ( $user_id <= 0 ) {
				continue;
			}
			$key = self::candidate_key( $user_id, self::rule_from_row( $row ) );
			$ts  = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts > ( $last_by_key[ $key ] ?? 0 ) ) {
				$last_by_key[ $key ] = $ts;
			}
		}
		$removed = 0;
		foreach ( array_keys( $state['sent'] ) as $key ) {
			$last = $last_by_key[ $key ] ?? 0;
			if ( $last <= 0 || ( $now - $last ) >= $quiet ) {
				unset( $state['sent'][ $key ] );
				++$removed;
			}
		}
		if ( $removed > 0 ) {
			self::put_state( $state );
		}

		return $removed;
	}

	/**
	 * Mark a candidate as sent (admin action only).
	 */
	public static function mark_sent( string $key, int $streak, ?int $now = null ): void {
		$now   = self::resolve_now( $now );
		$key   = self::sanitize_key_string( $key );
		$state = self::get_state();
		$state['sent'][ $key ] = array(
			'sent_ts' => $now,
			'streak'  => max( 0, $streak ),
		);
		self::put_state( $state );
	}

	/* ---------------------------------------------------------------------
	 * Email compose (never auto-sends)
	 * ------------------------------------------------------------------ */

	/**
	 * @param array<string,mixed> $candidate Candidate row.
	 * @return array{to:string,subject:string,body:string,ok:bool,error:string}
	 */
	public static function compose_explainer( array $candidate ): array {
		$user_id = isset( $candidate['user_id'] ) ? (int) $candidate['user_id'] : 0;
		$rule    = isset( $candidate['rule'] ) ? (string) $candidate['rule'] : 'unknown';
		$note    = isset( $candidate['rule_note'] ) ? (string) $candidate['rule_note'] : '';
		$plugin  = isset( $candidate['plugin'] ) ? (string) $candidate['plugin'] : '';
		$streak  = isset( $candidate['streak'] ) ? (int) $candidate['streak'] : 0;

		$to = '';
		$user = function_exists( 'get_userdata' ) ? get_userdata( $user_id ) : false;
		if ( is_object( $user ) && ! empty( $user->user_email ) ) {
			$to = sanitize_email( (string) $user->user_email );
		}
		$login = is_object( $user ) && ! empty( $user->user_login )
			? (string) $user->user_login
			: ( 'user#' . $user_id );

		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';

		$rule_label = self::rule_label( $rule, $plugin );
		$subject    = sprintf(
			/* translators: 1: site name, 2: rule label */
			__( '[%1$s] About your blocked AI requests (%2$s)', 'handl-ai-connector-access-control' ),
			$site,
			$rule_label
		);

		$lines   = array();
		$lines[] = sprintf(
			/* translators: %s: user login */
			__( 'Hi %s,', 'handl-ai-connector-access-control' ),
			$login
		);
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: 1: streak count, 2: rule label */
			__( 'AI Not noticed %1$d recent blocked AI attempts matching: %2$s.', 'handl-ai-connector-access-control' ),
			$streak,
			$rule_label
		);
		$lines[] = '';
		$lines[] = __( 'What was blocked', 'handl-ai-connector-access-control' );
		$lines[] = '- ' . $rule_label;
		if ( '' !== $plugin ) {
			$lines[] = '- ' . sprintf(
				/* translators: %s: plugin basename */
				__( 'Plugin: %s', 'handl-ai-connector-access-control' ),
				$plugin
			);
		}
		$lines[] = '';
		$lines[] = __( 'Why', 'handl-ai-connector-access-control' );
		$lines[] = '- ' . sprintf(
			/* translators: %s: rule name */
			__( 'Rule: %s', 'handl-ai-connector-access-control' ),
			$rule_label
		);
		if ( '' !== $note ) {
			$lines[] = '- ' . $note;
		} else {
			$lines[] = '- ' . __( 'This site blocks that AI action under its current policy.', 'handl-ai-connector-access-control' );
		}
		$lines[] = '';
		$lines[] = __( 'What to do next', 'handl-ai-connector-access-control' );
		if ( self::access_request_enabled() ) {
			$lines[] = '- ' . __( 'When AI is blocked, use the on-screen access request so an admin can review it.', 'handl-ai-connector-access-control' );
			$home    = function_exists( 'home_url' ) ? home_url( '/' ) : '';
			if ( '' !== $home ) {
				$lines[] = '- ' . sprintf(
					/* translators: %s: site URL */
					__( 'Site: %s', 'handl-ai-connector-access-control' ),
					$home
				);
			}
		} else {
			$lines[] = '- ' . __( 'Ask a site admin if you need this AI action allowed.', 'handl-ai-connector-access-control' );
		}
		$lines[] = '';
		$lines[] = __( 'This message was sent by a site admin. AI Not never emails you automatically about denials.', 'handl-ai-connector-access-control' );

		$body = implode( "\n", $lines );
		$ok   = '' !== $to;
		$err  = $ok ? '' : __( 'User has no email address.', 'handl-ai-connector-access-control' );

		return array(
			'to'      => $to,
			'subject' => $subject,
			'body'    => $body,
			'ok'      => $ok,
			'error'   => $err,
		);
	}

	public static function rule_label( string $rule, string $plugin = '' ): string {
		$rule = sanitize_key( $rule );
		$map  = array(
			'plugin'             => __( 'Plugin rule', 'handl-ai-connector-access-control' ),
			'role'               => __( 'Role rule', 'handl-ai-connector-access-control' ),
			'budget'             => __( 'Budget rule', 'handl-ai-connector-access-control' ),
			'kill_switch'        => __( 'Kill switch', 'handl-ai-connector-access-control' ),
			'quiet_hours'        => __( 'Quiet hours', 'handl-ai-connector-access-control' ),
			'pii'                => __( 'PII rule', 'handl-ai-connector-access-control' ),
			'tool_armed'         => __( 'Tool rule', 'handl-ai-connector-access-control' ),
			'capability_family'  => __( 'Capability family', 'handl-ai-connector-access-control' ),
			'unknown_operation'  => __( 'Unknown operation', 'handl-ai-connector-access-control' ),
			'break_glass'        => __( 'Break-glass hold', 'handl-ai-connector-access-control' ),
			'unknown'            => __( 'Unknown rule', 'handl-ai-connector-access-control' ),
		);
		if ( isset( $map[ $rule ] ) ) {
			$label = $map[ $rule ];
			if ( 'plugin' === $rule && '' !== $plugin ) {
				return $label . ' (' . $plugin . ')';
			}

			return $label;
		}
		if ( 0 === strpos( $rule, 'plugin:' ) ) {
			return __( 'Plugin rule', 'handl-ai-connector-access-control' ) . ' (' . substr( $rule, 7 ) . ')';
		}

		return $rule;
	}

	/**
	 * Send explainer — explicit admin action only. Never called from maybe_scan.
	 *
	 * @param array<string,mixed> $candidate Candidate.
	 * @return array{sent:bool,error:string,mail:array{to:string,subject:string,body:string}}
	 */
	public static function send_explainer( array $candidate, ?int $now = null ): array {
		$now      = self::resolve_now( $now );
		$composed = self::compose_explainer( $candidate );
		$mail     = array(
			'to'      => $composed['to'],
			'subject' => $composed['subject'],
			'body'    => $composed['body'],
		);
		if ( ! $composed['ok'] ) {
			return array(
				'sent'  => false,
				'error' => $composed['error'],
				'mail'  => $mail,
			);
		}

		$ok = false;
		if ( function_exists( 'wp_mail' ) ) {
			$ok = (bool) wp_mail( $composed['to'], $composed['subject'], $composed['body'] );
		}
		self::$test_mails[] = $mail;

		if ( ! $ok ) {
			return array(
				'sent'  => false,
				'error' => __( 'wp_mail failed. Explainer was not sent.', 'handl-ai-connector-access-control' ),
				'mail'  => $mail,
			);
		}

		$key    = isset( $candidate['key'] ) ? (string) $candidate['key'] : self::candidate_key( (int) $candidate['user_id'], (string) $candidate['rule'] );
		$streak = isset( $candidate['streak'] ) ? (int) $candidate['streak'] : 0;
		self::mark_sent( $key, $streak, $now );

		return array(
			'sent'  => true,
			'error' => '',
			'mail'  => $mail,
		);
	}

	/* ---------------------------------------------------------------------
	 * Throttled scan (never sends mail)
	 * ------------------------------------------------------------------ */

	public static function maybe_scan( ?int $now = null, bool $force = false ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now   = self::resolve_now( is_int( $now ) ? $now : null );
		$state = self::get_state();
		$last  = (int) $state['last_scan_ts'];
		if ( ! $force && $last > 0 && $now >= $last && ( $now - $last ) < self::CHECK_THROTTLE_SECONDS ) {
			return false;
		}
		self::prune_sent_state( $now );
		$state                  = self::get_state();
		$state['last_scan_ts']  = $now;
		self::put_state( $state );
		// Detection only — never auto-send.
		self::candidates( $now );

		return true;
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function snapshot( ?int $now = null ): array {
		$now = self::resolve_now( $now );
		self::prune_sent_state( $now );
		$pack       = self::read_activity_log();
		$candidates = self::is_enabled() ? self::candidates( $now ) : array();
		$state      = self::get_state();

		return array(
			'enabled'           => self::is_enabled(),
			'threshold'         => self::threshold(),
			'window_days'       => self::WINDOW_DAYS,
			'quiet_days'        => self::QUIET_DAYS,
			'now'               => $now,
			'log_available'     => $pack['available'],
			'log_notice'        => $pack['notice'],
			'candidates'        => $candidates,
			'candidate_count'   => count( $candidates ),
			'sent_count'        => count( $state['sent'] ),
			'last_scan_ts'      => (int) $state['last_scan_ts'],
			'access_request'    => self::access_request_enabled(),
			'framing'           => self::FRAMING,
		);
	}

	/**
	 * WP-CLI / CSV census rows.
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function census( ?int $now = null ): array {
		$now  = self::resolve_now( $now );
		$rows = array();
		foreach ( self::detect_streaks( $now ) as $row ) {
			$key    = (string) $row['key'];
			$state  = self::get_state();
			$status = 'ready';
			if ( isset( $state['sent'][ $key ] ) ) {
				$status = 'sent_quiet';
			}
			foreach ( self::candidates( $now ) as $c ) {
				if ( (string) $c['key'] === $key ) {
					$status = 'ready';
					break;
				}
			}
			if ( isset( $state['sent'][ $key ] ) && 'ready' !== $status ) {
				$status = 'sent_quiet';
			}
			$rows[] = array(
				'key'          => $key,
				'user_id'      => (int) $row['user_id'],
				'rule'         => (string) $row['rule'],
				'streak'       => (int) $row['streak'],
				'last_deny_ts' => (int) $row['last_deny_ts'],
				'plugin'       => (string) $row['plugin'],
				'status'       => $status,
			);
		}

		return $rows;
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
			__( 'Coach', 'handl-ai-connector-access-control' ),
			__( 'Coach', 'handl-ai-connector-access-control' ),
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
		$preview    = null;
		if ( isset( $_GET['coach_preview'] ) && is_string( $_GET['coach_preview'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$preview = self::find_candidate_by_key( sanitize_text_field( wp_unslash( $_GET['coach_preview'] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}
		$notice = isset( $_GET['coach_notice'] ) ? sanitize_key( (string) wp_unslash( $_GET['coach_notice'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$csv = add_query_arg(
			array(
				'page'                   => self::PAGE_SLUG,
				'handl_aicac_coach_csv'  => '1',
				'_wpnonce'               => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_coach_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Coach', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Finds users who hit the same deny rule repeatedly and lets you send a plain-language explainer. Never emails anyone unless you click Send. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( 'sent' === $notice ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Explainer email sent.', 'handl-ai-connector-access-control' ) . '</p></div>';
		} elseif ( 'mail_failed' === $notice ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'wp_mail failed. Explainer was not sent.', 'handl-ai-connector-access-control' ) . '</p></div>';
		} elseif ( 'no_email' === $notice ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'User has no email address.', 'handl-ai-connector-access-control' ) . '</p></div>';
		} elseif ( 'saved' === $notice ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Coach settings saved.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}

		if ( $can_manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable coach', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Scan for repeat-deny coaching candidates on admin page loads', 'handl-ai-connector-access-control' );
			echo '</label></td></tr>';
			echo '<tr><th scope="row">' . esc_html__( 'Streak threshold', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<input type="number" min="2" max="100" name="' . esc_attr( self::POST_THRESHOLD ) . '" value="' . esc_attr( (string) (int) $settings['threshold'] ) . '" /> ';
			echo '<p class="description">' . esc_html__( 'Denies per user+rule in the last 14 days before a row appears. Default 5.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</td></tr></tbody></table>';
			submit_button( __( 'Save coach settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled || ! is_array( $snap ) ) {
			echo '<p>' . esc_html__( 'Coach is off. Enable it to list repeat-deny candidates.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Admin-initiated only — never auto-sends.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		if ( empty( $snap['log_available'] ) ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html( (string) $snap['log_notice'] ) . '</p></div>';
		}
		echo '<ul>';
		echo '<li>' . esc_html( sprintf( 'Ready candidates: %d', (int) $snap['candidate_count'] ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( 'Quiet (already sent): %d', (int) $snap['sent_count'] ) ) . '</li>';
		echo '<li>' . esc_html( sprintf( 'Threshold: %d denies / 14 days', (int) $snap['threshold'] ) ) . '</li>';
		echo '</ul>';
		echo '<p><a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a></p>';

		if ( is_array( $preview ) ) {
			$composed = self::compose_explainer( $preview );
			echo '<h2>' . esc_html__( 'Preview explainer', 'handl-ai-connector-access-control' ) . '</h2>';
			echo '<p><strong>' . esc_html__( 'To', 'handl-ai-connector-access-control' ) . ':</strong> ' . esc_html( $composed['to'] !== '' ? $composed['to'] : '—' ) . '</p>';
			echo '<p><strong>' . esc_html__( 'Subject', 'handl-ai-connector-access-control' ) . ':</strong> ' . esc_html( $composed['subject'] ) . '</p>';
			echo '<pre style="white-space:pre-wrap;background:#fff;border:1px solid #c3c4c7;padding:12px;max-width:720px;">' . esc_html( $composed['body'] ) . '</pre>';
			if ( $can_manage ) {
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="margin:1em 0;">';
				echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SEND ) . '" />';
				echo '<input type="hidden" name="coach_key" value="' . esc_attr( (string) $preview['key'] ) . '" />';
				if ( function_exists( 'wp_nonce_field' ) ) {
					wp_nonce_field( self::ACTION_SEND );
				}
				submit_button( __( 'Send explainer', 'handl-ai-connector-access-control' ), 'primary', 'submit', false );
				echo ' <a class="button" href="' . esc_url( admin_url( 'admin.php?page=' . self::PAGE_SLUG ) ) . '">' . esc_html__( 'Cancel', 'handl-ai-connector-access-control' ) . '</a>';
				echo '</form>';
			}
		}

		echo '<h2>' . esc_html__( 'Coaching candidates', 'handl-ai-connector-access-control' ) . '</h2>';
		$candidates = (array) $snap['candidates'];
		if ( empty( $candidates ) ) {
			echo '<p>' . esc_html__( 'No candidates at the current threshold.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'User', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Rule', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Streak', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Last deny', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Action', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $candidates as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$user_id = (int) $row['user_id'];
				$user    = function_exists( 'get_userdata' ) ? get_userdata( $user_id ) : false;
				$login   = is_object( $user ) && ! empty( $user->user_login ) ? (string) $user->user_login : ( '#' . $user_id );
				$preview_url = add_query_arg(
					array(
						'page'          => self::PAGE_SLUG,
						'coach_preview' => (string) $row['key'],
					),
					admin_url( 'admin.php' )
				);
				echo '<tr>';
				echo '<td>' . esc_html( $login ) . '</td>';
				echo '<td>' . esc_html( self::rule_label( (string) $row['rule'], (string) ( $row['plugin'] ?? '' ) ) ) . '</td>';
				echo '<td>' . esc_html( (string) (int) $row['streak'] ) . '</td>';
				echo '<td>' . esc_html( self::format_ts( (int) $row['last_deny_ts'] ) ) . '</td>';
				echo '<td>';
				if ( $can_manage ) {
					echo '<a class="button button-small" href="' . esc_url( $preview_url ) . '">' . esc_html__( 'Preview &amp; send', 'handl-ai-connector-access-control' ) . '</a>';
				} else {
					echo '—';
				}
				echo '</td></tr>';
			}
			echo '</tbody></table>';
		}

		echo '</div>';
	}

	/**
	 * @return array<string,mixed>|null
	 */
	public static function find_candidate_by_key( string $key ): ?array {
		$key = self::sanitize_key_string( $key );
		foreach ( self::candidates() as $row ) {
			if ( (string) $row['key'] === $key ) {
				return $row;
			}
		}
		// Allow preview of threshold-met rows even if currently quiet, for diagnostics.
		foreach ( self::detect_streaks() as $row ) {
			if ( (string) $row['key'] === $key ) {
				$row['status'] = 'streak';

				return $row;
			}
		}

		return null;
	}

	public static function format_ts( int $ts ): string {
		if ( $ts <= 0 ) {
			return '—';
		}
		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( 'Y-m-d H:i', $ts );
		}

		return gmdate( 'Y-m-d H:i', $ts ) . ' UTC';
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'Forbidden.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		$enabled   = isset( $_POST[ self::POST_ENABLED ] );
		$threshold = isset( $_POST[ self::POST_THRESHOLD ] ) ? (int) wp_unslash( $_POST[ self::POST_THRESHOLD ] ) : self::DEFAULT_THRESHOLD;
		self::save_settings(
			array(
				'enabled'   => $enabled,
				'threshold' => $threshold,
			)
		);
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'         => self::PAGE_SLUG,
					'coach_notice' => 'saved',
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	public static function handle_preview(): void {
		// Preview is GET-driven on the page; this post action is unused reserved.
		wp_safe_redirect( admin_url( 'admin.php?page=' . self::PAGE_SLUG ) );
		exit;
	}

	public static function handle_send(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'Forbidden.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SEND );
		$key = isset( $_POST['coach_key'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['coach_key'] ) ) : '';
		$row = self::find_candidate_by_key( $key );
		$notice = 'no_email';
		if ( is_array( $row ) ) {
			$result = self::send_explainer( $row );
			if ( $result['sent'] ) {
				$notice = 'sent';
			} elseif ( false !== strpos( (string) $result['error'], 'wp_mail' ) ) {
				$notice = 'mail_failed';
			} else {
				$notice = 'no_email';
			}
		}
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'         => self::PAGE_SLUG,
					'coach_notice' => $notice,
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	/**
	 * @param list<array<string,mixed>>|null $rows Census rows.
	 */
	public static function csv_for_census( ?array $rows = null ): string {
		$rows = null !== $rows ? $rows : self::census();
		$fh   = fopen( 'php://temp', 'r+' );
		if ( false === $fh ) {
			return '';
		}
		fputcsv( $fh, array( 'key', 'user_id', 'rule', 'streak', 'last_deny_ts', 'plugin', 'status' ), ',', '"', '' );
		foreach ( $rows as $row ) {
			fputcsv(
				$fh,
				array(
					(string) ( $row['key'] ?? '' ),
					(int) ( $row['user_id'] ?? 0 ),
					(string) ( $row['rule'] ?? '' ),
					(int) ( $row['streak'] ?? 0 ),
					(int) ( $row['last_deny_ts'] ?? 0 ),
					(string) ( $row['plugin'] ?? '' ),
					(string) ( $row['status'] ?? '' ),
				),
				',',
				'"',
				''
			);
		}
		rewind( $fh );
		$csv = stream_get_contents( $fh );
		fclose( $fh );

		return is_string( $csv ) ? $csv : '';
	}

	public static function maybe_handle_csv(): void {
		if ( empty( $_GET['handl_aicac_coach_csv'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		if ( ! Caps::user_can_view() ) {
			return;
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		check_admin_referer( 'handl_aicac_coach_csv' );
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=handl-aicac-coach.csv' );
		echo self::csv_for_census(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	/* ---------------------------------------------------------------------
	 * WP-CLI
	 * ------------------------------------------------------------------ */

	public static function register_cli(): void {
		if ( ! class_exists( '\\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command(
			'handl-aicac coach',
			static function ( $args, $assoc_args ) {
				$snap = self::snapshot();
				\WP_CLI::log( 'enabled=' . ( $snap['enabled'] ? '1' : '0' ) );
				\WP_CLI::log( 'threshold=' . (int) $snap['threshold'] );
				\WP_CLI::log( 'candidates=' . (int) $snap['candidate_count'] );
				\WP_CLI::log( 'sent_quiet=' . (int) $snap['sent_count'] );
				foreach ( self::census() as $row ) {
					\WP_CLI::log(
						sprintf(
							'%s user=%d rule=%s streak=%d status=%s',
							(string) $row['key'],
							(int) $row['user_id'],
							(string) $row['rule'],
							(int) $row['streak'],
							(string) $row['status']
						)
					);
				}
			}
		);
	}
}
