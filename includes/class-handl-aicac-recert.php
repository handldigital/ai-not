<?php
/**
 * AICAC-RECERT (#359): periodic access recertification of AI grants.
 *
 * Inventories standing grants (explicit plugin Allow rules, role-gate roles,
 * plus anything registered through the `handl_aicac_recert_grant_sources`
 * filter), emails the owner a digest each cycle with signed confirm / revoke
 * links, flags grants nobody attested within the grace window, and can
 * optionally auto-suspend them. OFF by default.
 *
 * Self-contained: own screen, own options, own signed-token subsystem (modelled
 * on Inbox_Actions, which is not modified). Reads and writes Policy / Temp_Allow
 * only through their existing public methods.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Recertification cycle, inventory, tokens and admin screen.
 */
final class Recert {

	/** Settings only: enabled, cycle_days, grace_days, auto_suspend. */
	public const OPTION_KEY = 'handl_aicac_recert';

	/** Cycle id / start + per-grant attestation state. */
	public const STATE_OPTION_KEY = 'handl_aicac_recert_state';

	/** Signed-link tokens. */
	public const TOKENS_OPTION_KEY = 'handl_aicac_recert_tokens';

	public const CRON_HOOK = 'handl_aicac_recert_cycle';

	public const PAGE_SLUG = 'handl-aicac-recert';

	public const OPEN_HOOK  = 'handl_aicac_recert_open';
	public const APPLY_HOOK = 'handl_aicac_recert_apply';
	public const NONCE_KEY  = 'handl_aicac_recert_apply';

	public const ACT_CONFIRM = 'recert_confirm';
	public const ACT_REVOKE  = 'recert_revoke';

	public const CHANNEL = 'recert';

	public const SOURCE_TEMP_ALLOW = 'temp_allow';
	public const SOURCE_ROLE_GATE  = 'role_gate';

	public const DEFAULT_CYCLE_DAYS = 90;
	public const DEFAULT_GRACE_DAYS = 14;

	/** Token lifetime. */
	public const TOKEN_TTL = 172800;

	/** Max grants listed (and token-minted) in one digest email. */
	public const DIGEST_MAX_GRANTS = 50;

	/** @var bool */
	private static $registered = false;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 21 );
		add_action( 'admin_init', array( self::class, 'maybe_save_settings' ), 6 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_grant_action' ), 7 );
		add_action( 'admin_post_' . self::OPEN_HOOK, array( self::class, 'handle_open' ) );
		add_action( 'admin_post_nopriv_' . self::OPEN_HOOK, array( self::class, 'handle_open' ) );
		add_action( 'admin_post_' . self::APPLY_HOOK, array( self::class, 'handle_apply' ) );
		// No nopriv apply — unauthenticated POST must not change state.
		add_action( self::CRON_HOOK, array( self::class, 'cron_run' ) );
		add_action( 'init', array( self::class, 'maybe_self_heal_schedule' ), 24 );
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		delete_option( self::OPTION_KEY );
		delete_option( self::STATE_OPTION_KEY );
		delete_option( self::TOKENS_OPTION_KEY );
		$ts = wp_next_scheduled( self::CRON_HOOK );
		if ( $ts ) {
			wp_unschedule_event( $ts, self::CRON_HOOK );
		}
	}

	// -------------------------------------------------------------------------
	// Settings.
	// -------------------------------------------------------------------------

	/**
	 * @return array{enabled:bool,cycle_days:int,grace_days:int,auto_suspend:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::OPTION_KEY, array() ) );
	}

	/**
	 * @param mixed $raw
	 * @return array{enabled:bool,cycle_days:int,grace_days:int,auto_suspend:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		$raw = is_array( $raw ) ? $raw : array();

		$cycle = self::DEFAULT_CYCLE_DAYS;
		if ( isset( $raw['cycle_days'] ) && is_numeric( $raw['cycle_days'] ) ) {
			$cycle = (int) $raw['cycle_days'];
		}
		$cycle = max( 7, min( 365, $cycle ) );

		$grace = self::DEFAULT_GRACE_DAYS;
		if ( isset( $raw['grace_days'] ) && is_numeric( $raw['grace_days'] ) ) {
			$grace = (int) $raw['grace_days'];
		}
		$grace = max( 0, min( 90, $grace ) );

		return array(
			'enabled'      => ! empty( $raw['enabled'] ),
			'cycle_days'   => $cycle,
			'grace_days'   => $grace,
			'auto_suspend' => ! empty( $raw['auto_suspend'] ),
		);
	}

	/**
	 * Persist settings. No-op (returns false, no write) when nothing changed.
	 *
	 * @param array<string,mixed> $settings
	 */
	public static function save_settings( array $settings ): bool {
		$clean  = self::sanitize_settings( $settings );
		$before = self::get_settings();
		if ( $clean === $before ) {
			return false;
		}

		update_option( self::OPTION_KEY, $clean, false );
		self::maybe_schedule();

		return true;
	}

	// -------------------------------------------------------------------------
	// State (cycle + attestations).
	// -------------------------------------------------------------------------

	/**
	 * @return array{cycle_id:string,cycle_started_ts:int,digest_sent_ts:int,grants:array<string,array{confirmed_ts:int,next_due_ts:int,flagged:bool,flagged_ts:int}>}
	 */
	public static function get_state(): array {
		$raw = get_option( self::STATE_OPTION_KEY, array() );
		$raw = is_array( $raw ) ? $raw : array();

		$grants = array();
		if ( isset( $raw['grants'] ) && is_array( $raw['grants'] ) ) {
			foreach ( $raw['grants'] as $gid => $row ) {
				$gid = self::sanitize_grant_id( (string) $gid );
				if ( '' === $gid || ! is_array( $row ) ) {
					continue;
				}
				$grants[ $gid ] = array(
					'confirmed_ts' => isset( $row['confirmed_ts'] ) ? max( 0, (int) $row['confirmed_ts'] ) : 0,
					'next_due_ts'  => isset( $row['next_due_ts'] ) ? max( 0, (int) $row['next_due_ts'] ) : 0,
					'flagged'      => ! empty( $row['flagged'] ),
					'flagged_ts'   => isset( $row['flagged_ts'] ) ? max( 0, (int) $row['flagged_ts'] ) : 0,
				);
			}
		}

		return array(
			'cycle_id'         => isset( $raw['cycle_id'] ) ? preg_replace( '/[^a-f0-9]/', '', strtolower( (string) $raw['cycle_id'] ) ) : '',
			'cycle_started_ts' => isset( $raw['cycle_started_ts'] ) ? max( 0, (int) $raw['cycle_started_ts'] ) : 0,
			'digest_sent_ts'   => isset( $raw['digest_sent_ts'] ) ? max( 0, (int) $raw['digest_sent_ts'] ) : 0,
			'grants'           => $grants,
		);
	}

	/**
	 * @param array<string,mixed> $state
	 */
	private static function save_state( array $state ): void {
		update_option( self::STATE_OPTION_KEY, $state, false );
	}

	// -------------------------------------------------------------------------
	// Inventory.
	// -------------------------------------------------------------------------

	/**
	 * Standing grants, flattened, with last-used and attestation state attached.
	 *
	 * @param array<string,mixed>|null $policy
	 * @return list<array<string,mixed>>
	 */
	public static function build_inventory( ?array $policy = null, ?int $now = null ): array {
		$policy = null !== $policy ? $policy : Policy::get_policy();
		$now    = null !== $now ? $now : Clock::now();

		$sources = array(
			self::SOURCE_TEMP_ALLOW => self::temp_allow_grants( $policy, $now ),
			self::SOURCE_ROLE_GATE  => self::role_gate_grants( $policy ),
		);

		$sources = apply_filters( 'handl_aicac_recert_grant_sources', $sources, $policy, $now );
		if ( ! is_array( $sources ) ) {
			$sources = array();
		}

		$flat = array();
		foreach ( $sources as $source_name => $list ) {
			if ( ! is_array( $list ) ) {
				continue;
			}
			foreach ( $list as $grant ) {
				if ( ! is_array( $grant ) ) {
					continue;
				}
				$gid = self::sanitize_grant_id( (string) ( $grant['grant_id'] ?? '' ) );
				if ( '' === $gid || isset( $flat[ $gid ] ) ) {
					continue;
				}
				$source = sanitize_key( (string) ( $grant['source'] ?? '' ) );
				if ( '' === $source ) {
					$source = sanitize_key( (string) $source_name );
				}
				$grant['grant_id'] = $gid;
				$grant['source']   = $source;
				$grant['label']    = isset( $grant['label'] ) && '' !== (string) $grant['label'] ? (string) $grant['label'] : $gid;
				$flat[ $gid ]      = $grant;
			}
		}

		$used  = self::last_used_by_plugin();
		$state = self::get_state();

		$out = array();
		foreach ( $flat as $gid => $grant ) {
			if ( ! array_key_exists( 'last_used_ts', $grant ) ) {
				$plugin               = isset( $grant['plugin'] ) ? (string) $grant['plugin'] : '';
				$grant['last_used_ts'] = ( '' !== $plugin && isset( $used[ $plugin ] ) ) ? $used[ $plugin ] : null;
			}
			$row                    = $state['grants'][ $gid ] ?? null;
			$grant['confirmed_ts']  = null !== $row ? $row['confirmed_ts'] : 0;
			$grant['next_due_ts']   = null !== $row ? $row['next_due_ts'] : 0;
			$grant['flagged']       = null !== $row && $row['flagged'];
			$grant['unattested']    = ( null === $row || $row['confirmed_ts'] <= 0 );
			$grant['status']        = self::status_for( $row, $now );
			$out[]                  = $grant;
		}

		return $out;
	}

	/**
	 * @param array{confirmed_ts:int,next_due_ts:int,flagged:bool,flagged_ts:int}|null $row
	 */
	public static function status_for( ?array $row, int $now ): string {
		if ( null === $row || $row['confirmed_ts'] <= 0 ) {
			return $row && $row['flagged'] ? 'flagged' : 'unattested';
		}
		if ( $row['flagged'] ) {
			return 'flagged';
		}
		if ( $row['next_due_ts'] <= $now ) {
			return 'due';
		}

		return 'ok';
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return list<array<string,mixed>>
	 */
	private static function temp_allow_grants( array $policy, int $now ): array {
		$plugins = isset( $policy['plugins'] ) && is_array( $policy['plugins'] ) ? $policy['plugins'] : array();
		$out     = array();
		foreach ( $plugins as $plugin => $rule ) {
			$plugin = (string) $plugin;
			if ( 'allow' !== (string) $rule || '' === $plugin ) {
				continue;
			}
			$gid = self::sanitize_grant_id( self::SOURCE_TEMP_ALLOW . ':' . $plugin );
			if ( '' === $gid ) {
				continue;
			}
			if ( Temp_Allow::is_expired( $policy, $plugin, $now ) ) {
				continue;
			}
			$out[] = array(
				'grant_id'   => $gid,
				'source'     => self::SOURCE_TEMP_ALLOW,
				'label'      => $plugin,
				'plugin'     => $plugin,
				'expires_at' => Temp_Allow::expires_at( $policy, $plugin ),
			);
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return list<array<string,mixed>>
	 */
	private static function role_gate_grants( array $policy ): array {
		if ( empty( $policy['role_gate_enabled'] ) ) {
			return array();
		}
		$labels = Policy::available_roles_for_gate();
		$out    = array();
		foreach ( Policy::sanitize_allowed_roles( $policy['allowed_roles'] ?? array() ) as $role ) {
			$gid = self::sanitize_grant_id( self::SOURCE_ROLE_GATE . ':' . $role );
			if ( '' === $gid ) {
				continue;
			}
			$out[] = array(
				'grant_id' => $gid,
				'source'   => self::SOURCE_ROLE_GATE,
				'label'    => isset( $labels[ $role ] ) ? (string) $labels[ $role ] : $role,
				'role'     => $role,
			);
		}

		return $out;
	}

	/**
	 * Most recent real activity timestamp per plugin (read-only on the log).
	 *
	 * @return array<string,int>
	 */
	private static function last_used_by_plugin(): array {
		$log = get_option( Plugin::LOG_OPTION_KEY, array() );
		if ( ! is_array( $log ) ) {
			return array();
		}
		$out = array();
		foreach ( $log as $row ) {
			if ( ! is_array( $row ) || empty( $row['plugin'] ) ) {
				continue;
			}
			if ( self::CHANNEL === ( isset( $row['channel'] ) ? (string) $row['channel'] : '' ) ) {
				continue;
			}
			if ( class_exists( Usage_Trends::class ) && ! Usage_Trends::is_activity_row( $row ) ) {
				continue;
			}
			$plugin = (string) $row['plugin'];
			$ts     = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
			if ( $ts > 0 && ( ! isset( $out[ $plugin ] ) || $ts > $out[ $plugin ] ) ) {
				$out[ $plugin ] = $ts;
			}
		}

		return $out;
	}

	private static function sanitize_grant_id( string $id ): string {
		$id = trim( $id );
		if ( '' === $id || strlen( $id ) > 191 ) {
			return '';
		}
		if ( 1 !== preg_match( '/^[a-z0-9_\-]+:[A-Za-z0-9_\-\.\/@]+$/', $id ) || false !== strpos( $id, '..' ) ) {
			return '';
		}

		return $id;
	}

	/**
	 * @return array<string,mixed>|null
	 */
	private static function find_grant( string $grant_id, ?array $policy = null, ?int $now = null ): ?array {
		$grant_id = self::sanitize_grant_id( $grant_id );
		if ( '' === $grant_id ) {
			return null;
		}
		foreach ( self::build_inventory( $policy, $now ) as $grant ) {
			if ( $grant['grant_id'] === $grant_id ) {
				return $grant;
			}
		}

		return null;
	}

	// -------------------------------------------------------------------------
	// Confirm / revoke.
	// -------------------------------------------------------------------------

	/**
	 * Attest that a grant is still needed. False when the grant no longer exists.
	 */
	public static function confirm_grant( string $grant_id, int $actor_id = 0, ?int $now = null ): bool {
		$now   = null !== $now ? $now : Clock::now();
		$grant = self::find_grant( $grant_id, null, $now );
		if ( null === $grant ) {
			return false;
		}

		$settings = self::get_settings();
		$state    = self::get_state();

		$state['grants'][ $grant['grant_id'] ] = array(
			'confirmed_ts' => $now,
			'next_due_ts'  => $now + $settings['cycle_days'] * self::day(),
			'flagged'      => false,
			'flagged_ts'   => 0,
		);
		self::save_state( $state );
		self::audit( $grant, 'recert_confirm', $actor_id, $now );

		return true;
	}

	/**
	 * Revoke a grant through the public Policy API. False when the grant is
	 * unknown or cannot be revoked.
	 *
	 * @param string $decision Audit decision (recert_revoke | recert_auto_suspend).
	 */
	public static function revoke_grant( string $grant_id, int $actor_id = 0, ?int $now = null, string $decision = 'recert_revoke' ): bool {
		$now   = null !== $now ? $now : Clock::now();
		$grant = self::find_grant( $grant_id, null, $now );
		if ( null === $grant ) {
			return false;
		}

		$ok = false;
		if ( self::SOURCE_TEMP_ALLOW === $grant['source'] && ! empty( $grant['plugin'] ) ) {
			$ok = Policy::set_plugin_rule( (string) $grant['plugin'], '' );
		} elseif ( self::SOURCE_ROLE_GATE === $grant['source'] && ! empty( $grant['role'] ) ) {
			$policy = Policy::get_policy();
			$roles  = Policy::sanitize_allowed_roles( $policy['allowed_roles'] ?? array() );
			$roles  = array_values( array_diff( $roles, array( (string) $grant['role'] ) ) );

			$policy['allowed_roles'] = Policy::sanitize_allowed_roles( $roles );
			Policy::save_policy( $policy );
			$ok = true;
		} else {
			// Future sources: a registering class performs the revoke.
			$ok = (bool) apply_filters( 'handl_aicac_recert_revoke_grant', false, $grant, $actor_id, $now );
		}

		if ( ! $ok ) {
			return false;
		}

		$state = self::get_state();
		unset( $state['grants'][ $grant['grant_id'] ] );
		self::save_state( $state );

		self::audit( $grant, $decision, $actor_id, $now );

		return true;
	}

	/**
	 * @param array<string,mixed> $grant
	 */
	private static function audit( array $grant, string $decision, int $actor_id, int $now ): void {
		Policy::append_log_event(
			array(
				'ts'        => $now,
				'plugin'    => isset( $grant['plugin'] ) ? (string) $grant['plugin'] : '',
				'decision'  => $decision,
				'channel'   => self::CHANNEL,
				'source'    => self::CHANNEL,
				'actor_id'  => $actor_id,
				'grant_id'  => (string) $grant['grant_id'],
				'operation' => '',
				'provider'  => '',
			)
		);
	}

	private static function day(): int {
		return defined( 'DAY_IN_SECONDS' ) ? (int) DAY_IN_SECONDS : 86400;
	}

	// -------------------------------------------------------------------------
	// Cycle / cron.
	// -------------------------------------------------------------------------

	public static function maybe_self_heal_schedule(): void {
		self::maybe_schedule();
	}

	public static function maybe_schedule(): void {
		$want = ! empty( self::get_settings()['enabled'] );
		if ( $want ) {
			if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
				wp_schedule_event( Clock::now() + self::day(), 'daily', self::CRON_HOOK );
			}
			return;
		}
		$ts = wp_next_scheduled( self::CRON_HOOK );
		if ( $ts ) {
			wp_unschedule_event( $ts, self::CRON_HOOK );
		}
	}

	public static function cron_run(): void {
		self::process_cycle( Policy::get_policy(), Clock::now() );
	}

	/**
	 * Start a cycle when due (and email the digest), then sweep for grants that
	 * outlasted the grace window.
	 *
	 * @param array<string,mixed> $policy
	 * @return array{started:bool,sent:bool,status:string,flagged:int,suspended:int}
	 */
	public static function process_cycle( array $policy, ?int $now = null ): array {
		$now  = null !== $now ? $now : Clock::now();
		$base = array(
			'started'   => false,
			'sent'      => false,
			'status'    => 'skipped',
			'flagged'   => 0,
			'suspended' => 0,
		);

		$settings = self::get_settings();
		if ( empty( $settings['enabled'] ) ) {
			$base['status'] = 'inactive';
			return $base;
		}

		$state = self::get_state();
		$due   = $state['cycle_started_ts'] <= 0
			|| $state['cycle_started_ts'] + $settings['cycle_days'] * self::day() <= $now;

		if ( $due ) {
			$state = self::start_cycle( $policy, $now );
			$base['started'] = true;
			$base['status']  = 'started';
		}

		if ( $state['digest_sent_ts'] <= 0 ) {
			$sent         = self::send_digest( $policy, $now );
			$base['sent'] = $sent['sent'];
			if ( ! $base['started'] ) {
				$base['status'] = 'digest_' . $sent['status'];
			} elseif ( ! $sent['sent'] ) {
				$base['status'] = 'started_' . $sent['status'];
			}
		}

		$sweep             = self::grace_sweep( $policy, $now );
		$base['flagged']   = $sweep['flagged'];
		$base['suspended'] = $sweep['suspended'];

		return $base;
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array{cycle_id:string,cycle_started_ts:int,digest_sent_ts:int,grants:array<string,array{confirmed_ts:int,next_due_ts:int,flagged:bool,flagged_ts:int}>}
	 */
	private static function start_cycle( array $policy, int $now ): array {
		$state                     = self::get_state();
		$state['cycle_id']         = bin2hex( random_bytes( 8 ) );
		$state['cycle_started_ts'] = $now;
		$state['digest_sent_ts']   = 0;

		$grants = array();
		foreach ( self::build_inventory( $policy, $now ) as $grant ) {
			$prev                        = $state['grants'][ $grant['grant_id'] ] ?? null;
			$grants[ $grant['grant_id'] ] = array(
				'confirmed_ts' => null !== $prev ? $prev['confirmed_ts'] : 0,
				'next_due_ts'  => $now,
				'flagged'      => false,
				'flagged_ts'   => 0,
			);
		}
		$state['grants'] = $grants;
		self::save_state( $state );

		return self::get_state();
	}

	/**
	 * Digest email with one confirm + one revoke link per grant due this cycle.
	 *
	 * @param array<string,mixed> $policy
	 * @return array{sent:bool,status:string}
	 */
	public static function send_digest( array $policy, ?int $now = null ): array {
		$now   = null !== $now ? $now : Clock::now();
		$state = self::get_state();

		$pending = array();
		foreach ( self::build_inventory( $policy, $now ) as $grant ) {
			$row = $state['grants'][ $grant['grant_id'] ] ?? null;
			if ( null !== $row && $row['confirmed_ts'] >= $state['cycle_started_ts'] ) {
				continue;
			}
			$pending[] = $grant;
		}

		if ( empty( $pending ) ) {
			$state['digest_sent_ts'] = $now;
			self::save_state( $state );
			return array(
				'sent'   => false,
				'status' => 'no_grants',
			);
		}

		$to = Alerts::resolve_email( $policy );
		if ( '' === $to ) {
			return array(
				'sent'   => false,
				'status' => 'no_email',
			);
		}

		$shown = array_slice( $pending, 0, self::DIGEST_MAX_GRANTS );
		$urls  = self::mint_urls( $shown, $to, $now );
		$body  = self::format_digest_body( $shown, $urls, count( $pending ) - count( $shown ), self::get_settings() );

		$subject = __( '[AI Access Control] Access recertification: confirm or revoke standing AI grants', 'handl-ai-connector-access-control' );
		if ( ! Alerts::safe_wp_mail( $to, $subject, $body ) ) {
			return array(
				'sent'   => false,
				'status' => 'mail_failed',
			);
		}

		$state                   = self::get_state();
		$state['digest_sent_ts'] = $now;
		self::save_state( $state );

		return array(
			'sent'   => true,
			'status' => 'sent',
		);
	}

	/**
	 * @param list<array<string,mixed>>                          $grants
	 * @param array<string,array{confirm:string,revoke:string}> $urls
	 * @param array{enabled:bool,cycle_days:int,grace_days:int,auto_suspend:bool} $settings
	 */
	public static function format_digest_body( array $grants, array $urls, int $omitted, array $settings ): string {
		$lines   = array();
		$lines[] = sprintf(
			/* translators: %d: number of grants */
			_n( '%d standing AI access grant needs recertification.', '%d standing AI access grants need recertification.', count( $grants ) + $omitted, 'handl-ai-connector-access-control' ),
			count( $grants ) + $omitted
		);
		$lines[] = sprintf(
			/* translators: %d: grace days */
			__( 'Confirm each grant is still needed, or revoke it. Grants left unattested for %d days after this email are flagged.', 'handl-ai-connector-access-control' ),
			(int) $settings['grace_days']
		);
		if ( ! empty( $settings['auto_suspend'] ) ) {
			$lines[] = __( 'Auto-suspend is ON: flagged grants will be revoked automatically.', 'handl-ai-connector-access-control' );
		}
		$lines[] = __( 'Links require you to be logged in as an administrator, are single-use, and expire in 48 hours. Opening a link changes nothing until you confirm on the next screen.', 'handl-ai-connector-access-control' );
		$lines[] = '';

		foreach ( $grants as $grant ) {
			$gid = (string) $grant['grant_id'];
			if ( ! isset( $urls[ $gid ] ) ) {
				continue;
			}
			$expires = ( isset( $grant['expires_at'] ) && null !== $grant['expires_at'] )
				? self::format_ts( (int) $grant['expires_at'] )
				: __( 'no expiry', 'handl-ai-connector-access-control' );
			$used    = ! empty( $grant['last_used_ts'] )
				? self::format_ts( (int) $grant['last_used_ts'] )
				: __( 'no recent activity', 'handl-ai-connector-access-control' );
			$lines[] = sprintf( '- [%s] %s', (string) $grant['source'], (string) $grant['label'] );
			$lines[] = sprintf(
				/* translators: 1: expiry, 2: last used */
				__( '  Expires: %1$s | Last used: %2$s', 'handl-ai-connector-access-control' ),
				$expires,
				$used
			);
			$lines[] = '  ' . __( 'Confirm still needed:', 'handl-ai-connector-access-control' ) . ' ' . $urls[ $gid ]['confirm'];
			$lines[] = '  ' . __( 'Revoke:', 'handl-ai-connector-access-control' ) . ' ' . $urls[ $gid ]['revoke'];
			$lines[] = '';
		}

		if ( $omitted > 0 ) {
			$lines[] = sprintf(
				/* translators: %d: number of additional grants */
				_n( '…and %d more grant. Review it on the Access recertification screen.', '…and %d more grants. Review them on the Access recertification screen.', $omitted, 'handl-ai-connector-access-control' ),
				$omitted
			);
		}

		return implode( "\n", $lines );
	}

	/**
	 * Flag (and optionally auto-suspend) grants unattested past the grace window.
	 *
	 * @param array<string,mixed> $policy
	 * @return array{flagged:int,suspended:int}
	 */
	public static function grace_sweep( array $policy, ?int $now = null ): array {
		$now      = null !== $now ? $now : Clock::now();
		$settings = self::get_settings();
		$result   = array(
			'flagged'   => 0,
			'suspended' => 0,
		);
		if ( empty( $settings['enabled'] ) ) {
			return $result;
		}

		$state = self::get_state();
		if ( $state['cycle_started_ts'] <= 0 ) {
			return $result;
		}

		$inventory = self::build_inventory( $policy, $now );
		$live      = array();
		foreach ( $inventory as $grant ) {
			$live[ $grant['grant_id'] ] = $grant;
		}

		$changed = false;
		// Drop attestation rows for grants that no longer exist.
		foreach ( array_keys( $state['grants'] ) as $gid ) {
			if ( ! isset( $live[ $gid ] ) ) {
				unset( $state['grants'][ $gid ] );
				$changed = true;
			}
		}
		// Seed grants created mid-cycle: due now, grace runs from first sight.
		foreach ( $live as $gid => $grant ) {
			if ( ! isset( $state['grants'][ $gid ] ) ) {
				$state['grants'][ $gid ] = array(
					'confirmed_ts' => 0,
					'next_due_ts'  => $now,
					'flagged'      => false,
					'flagged_ts'   => 0,
				);
				$changed                 = true;
			}
		}

		$grace_secs = $settings['grace_days'] * self::day();
		$to_flag    = array();
		foreach ( $state['grants'] as $gid => $row ) {
			if ( $row['flagged'] || $row['confirmed_ts'] >= $state['cycle_started_ts'] ) {
				continue;
			}
			if ( $now > $row['next_due_ts'] + $grace_secs ) {
				$to_flag[] = $gid;
			}
		}

		foreach ( $to_flag as $gid ) {
			$state['grants'][ $gid ]['flagged']    = true;
			$state['grants'][ $gid ]['flagged_ts'] = $now;
			$changed                               = true;
		}
		if ( $changed ) {
			self::save_state( $state );
		}

		foreach ( $to_flag as $gid ) {
			++$result['flagged'];
			self::audit( $live[ $gid ], 'recert_flagged', 0, $now );
			if ( ! empty( $settings['auto_suspend'] ) && self::revoke_grant( $gid, 0, $now, 'recert_auto_suspend' ) ) {
				++$result['suspended'];
			}
		}

		return $result;
	}

	// -------------------------------------------------------------------------
	// Signed tokens (parallel to Inbox_Actions; that class is untouched).
	// -------------------------------------------------------------------------

	/**
	 * Mint one confirm + one revoke URL per grant (single token-store write).
	 *
	 * @param list<array<string,mixed>> $grants
	 * @return array<string,array{confirm:string,revoke:string}>
	 */
	public static function mint_urls( array $grants, string $recipient, ?int $now = null ): array {
		$now       = null !== $now ? $now : Clock::now();
		$recipient = self::sanitize_recipient( $recipient );
		$out       = array();
		if ( '' === $recipient ) {
			return $out;
		}

		$map = self::purge_expired( self::get_map(), $now );
		foreach ( $grants as $grant ) {
			$gid = self::sanitize_grant_id( (string) ( $grant['grant_id'] ?? '' ) );
			if ( '' === $gid ) {
				continue;
			}
			$out[ $gid ] = array(
				'confirm' => self::mint_into( $map, self::ACT_CONFIRM, $gid, $recipient, $now ),
				'revoke'  => self::mint_into( $map, self::ACT_REVOKE, $gid, $recipient, $now ),
			);
		}
		self::save_map( $map );

		return $out;
	}

	public static function mint_url( string $action, string $grant_id, string $recipient, ?int $now = null ): string {
		$now       = null !== $now ? $now : Clock::now();
		$action    = self::sanitize_action( $action );
		$grant_id  = self::sanitize_grant_id( $grant_id );
		$recipient = self::sanitize_recipient( $recipient );
		if ( '' === $action || '' === $grant_id || '' === $recipient ) {
			return '';
		}
		$map = self::purge_expired( self::get_map(), $now );
		$url = self::mint_into( $map, $action, $grant_id, $recipient, $now );
		self::save_map( $map );

		return $url;
	}

	/**
	 * @param array<string,array<string,mixed>> $map
	 */
	private static function mint_into( array &$map, string $action, string $grant_id, string $recipient, int $now ): string {
		$id  = self::new_id();
		$exp = $now + self::TOKEN_TTL;
		$sig = self::signature_for( $id, $action, $grant_id, $recipient, $exp );

		$map[ $id ] = array(
			'action'    => $action,
			'grant_id'  => $grant_id,
			'recipient' => $recipient,
			'exp'       => $exp,
			'used'      => false,
		);

		return add_query_arg(
			array(
				'action' => self::OPEN_HOOK,
				't'      => $id,
				's'      => $sig,
			),
			admin_url( 'admin-post.php' )
		);
	}

	/**
	 * @return array{ok:bool,error:string,row:?array<string,mixed>}
	 */
	public static function inspect( string $id, string $sig, ?int $now = null ): array {
		$empty = array(
			'ok'    => false,
			'error' => 'invalid',
			'row'   => null,
		);
		$id    = self::sanitize_id( $id );
		$sig   = self::sanitize_sig( $sig );
		if ( '' === $id || '' === $sig ) {
			return $empty;
		}

		$now = null !== $now ? $now : Clock::now();
		$map = self::get_map();
		if ( ! isset( $map[ $id ] ) ) {
			return $empty;
		}

		$row      = $map[ $id ];
		$expected = self::signature_for( $id, $row['action'], $row['grant_id'], $row['recipient'], $row['exp'] );
		if ( ! hash_equals( $expected, $sig ) ) {
			return $empty;
		}
		if ( ! empty( $row['used'] ) ) {
			return array(
				'ok'    => false,
				'error' => 'used',
				'row'   => $row,
			);
		}
		if ( (int) $row['exp'] <= $now ) {
			return array(
				'ok'    => false,
				'error' => 'expired',
				'row'   => $row,
			);
		}

		return array(
			'ok'    => true,
			'error' => '',
			'row'   => $row,
		);
	}

	/**
	 * Apply a verified token row. Consumes the token only on success.
	 *
	 * @param array<string,mixed> $row
	 * @return array{ok:bool,error:string,message:string}
	 */
	public static function apply_verified( array $row, string $id, int $user_id, ?int $now = null ): array {
		$id       = self::sanitize_id( $id );
		$action   = self::sanitize_action( (string) ( $row['action'] ?? '' ) );
		$grant_id = self::sanitize_grant_id( (string) ( $row['grant_id'] ?? '' ) );
		$now      = null !== $now ? $now : Clock::now();

		$ok = false;
		if ( '' !== $id && '' !== $grant_id ) {
			if ( self::ACT_CONFIRM === $action ) {
				$ok = self::confirm_grant( $grant_id, $user_id, $now );
			} elseif ( self::ACT_REVOKE === $action ) {
				$ok = self::revoke_grant( $grant_id, $user_id, $now );
			}
		}

		if ( ! $ok ) {
			return array(
				'ok'      => false,
				'error'   => 'gone',
				'message' => self::error_message( 'gone' ),
			);
		}

		self::mark_used( $id );

		return array(
			'ok'      => true,
			'error'   => '',
			'message' => self::ACT_CONFIRM === $action
				? __( 'Thanks. This grant is recertified until the next cycle.', 'handl-ai-connector-access-control' )
				: __( 'This grant has been revoked.', 'handl-ai-connector-access-control' ),
		);
	}

	public static function error_message( string $code ): string {
		if ( 'expired' === $code ) {
			return __( 'This link has expired. Nothing was changed.', 'handl-ai-connector-access-control' );
		}
		if ( 'used' === $code ) {
			return __( 'This link was already used. Nothing was changed.', 'handl-ai-connector-access-control' );
		}
		if ( 'cap' === $code ) {
			return __( 'You need permission to manage these settings.', 'handl-ai-connector-access-control' );
		}
		if ( 'gone' === $code ) {
			return __( 'This grant no longer exists. Nothing was changed.', 'handl-ai-connector-access-control' );
		}

		return __( 'This link is not valid. Nothing was changed.', 'handl-ai-connector-access-control' );
	}

	public static function handle_open(): void {
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}

		if ( function_exists( 'is_user_logged_in' ) && ! is_user_logged_in() ) {
			if ( function_exists( 'auth_redirect' ) ) {
				auth_redirect();
			}
			self::halt( self::error_message( 'cap' ) );
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			self::halt( self::error_message( 'cap' ) );
			return;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- signed token, read-only GET.
		$id  = isset( $_GET['t'] ) ? self::sanitize_id( wp_unslash( (string) $_GET['t'] ) ) : '';
		$sig = isset( $_GET['s'] ) ? self::sanitize_sig( wp_unslash( (string) $_GET['s'] ) ) : '';
		// phpcs:enable
		$got = self::inspect( $id, $sig );
		if ( ! $got['ok'] || ! is_array( $got['row'] ) ) {
			self::halt( self::error_message( (string) $got['error'] ) );
			return;
		}

		$grant = self::find_grant( (string) $got['row']['grant_id'] );
		if ( null === $grant ) {
			self::halt( self::error_message( 'gone' ) );
			return;
		}

		self::render_confirm( $id, $sig, $got['row'], $grant );
	}

	public static function handle_apply(): void {
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}

		if ( function_exists( 'is_user_logged_in' ) && ! is_user_logged_in() ) {
			self::halt( self::error_message( 'cap' ) );
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			self::halt( self::error_message( 'cap' ) );
			return;
		}

		check_admin_referer( self::NONCE_KEY );

		$id  = isset( $_POST['t'] ) ? self::sanitize_id( wp_unslash( (string) $_POST['t'] ) ) : '';
		$sig = isset( $_POST['s'] ) ? self::sanitize_sig( wp_unslash( (string) $_POST['s'] ) ) : '';
		$got = self::inspect( $id, $sig );
		if ( ! $got['ok'] || ! is_array( $got['row'] ) ) {
			self::halt( self::error_message( (string) $got['error'] ) );
			return;
		}

		$result = self::apply_verified( $got['row'], $id, (int) get_current_user_id() );
		self::halt( $result['message'] );
	}

	/**
	 * @param array<string,mixed> $row
	 * @param array<string,mixed> $grant
	 */
	private static function render_confirm( string $id, string $sig, array $row, array $grant ): void {
		$revoke = self::ACT_REVOKE === $row['action'];
		$nonce  = function_exists( 'wp_create_nonce' ) ? wp_create_nonce( self::NONCE_KEY ) : '';

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Access recertification', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p>' . esc_html(
			$revoke
				? __( 'Revoke this standing AI access grant', 'handl-ai-connector-access-control' )
				: __( 'Confirm this standing AI access grant is still needed', 'handl-ai-connector-access-control' )
		) . '</p>';
		echo '<p><code>' . esc_html( (string) $grant['label'] ) . '</code> (' . esc_html( (string) $grant['source'] ) . ')</p>';
		echo '<p>' . esc_html__( 'This does not change anything until you confirm.', 'handl-ai-connector-access-control' ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="' . esc_attr( self::APPLY_HOOK ) . '" />';
		echo '<input type="hidden" name="t" value="' . esc_attr( $id ) . '" />';
		echo '<input type="hidden" name="s" value="' . esc_attr( $sig ) . '" />';
		echo '<input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '" />';
		echo '<p><button type="submit" class="button button-primary">' . esc_html( $revoke ? __( 'Revoke', 'handl-ai-connector-access-control' ) : __( 'Confirm', 'handl-ai-connector-access-control' ) ) . '</button></p>';
		echo '</form>';
		echo '</div>';
		exit;
	}

	private static function halt( string $message ): void {
		if ( function_exists( 'wp_die' ) ) {
			wp_die( esc_html( $message ) );
		}
		echo esc_html( $message );
		exit;
	}

	private static function sanitize_recipient( string $raw ): string {
		return Alerts::sanitize_email( $raw );
	}

	private static function sanitize_id( string $id ): string {
		$id = strtolower( preg_replace( '/[^a-f0-9]/', '', $id ) ?? '' );
		return ( 32 === strlen( $id ) ) ? $id : '';
	}

	private static function sanitize_sig( string $sig ): string {
		$sig = strtolower( preg_replace( '/[^a-f0-9]/', '', $sig ) ?? '' );
		return ( 64 === strlen( $sig ) ) ? $sig : '';
	}

	private static function sanitize_action( string $action ): string {
		$action = sanitize_key( $action );
		return in_array( $action, array( self::ACT_CONFIRM, self::ACT_REVOKE ), true ) ? $action : '';
	}

	private static function new_id(): string {
		if ( function_exists( 'wp_generate_password' ) ) {
			$raw = wp_generate_password( 32, false, false );
			$hex = strtolower( preg_replace( '/[^a-f0-9]/', '', $raw ) ?? '' );
			if ( strlen( $hex ) >= 32 ) {
				return substr( $hex, 0, 32 );
			}
		}

		return bin2hex( random_bytes( 16 ) );
	}

	private static function signature_for( string $id, string $action, string $grant_id, string $recipient, int $exp ): string {
		$payload = $id . '|' . $action . '|' . $grant_id . '|' . $recipient . '|' . (string) $exp;
		return hash_hmac( 'sha256', $payload, self::secret() );
	}

	private static function secret(): string {
		if ( function_exists( 'wp_salt' ) ) {
			return (string) wp_salt( 'auth' );
		}

		return 'handl-aicac-recert';
	}

	/**
	 * @return array<string,array{action:string,grant_id:string,recipient:string,exp:int,used:bool}>
	 */
	private static function get_map(): array {
		$raw = get_option( self::TOKENS_OPTION_KEY, array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $id => $row ) {
			$id = self::sanitize_id( (string) $id );
			if ( '' === $id || ! is_array( $row ) ) {
				continue;
			}
			$action    = self::sanitize_action( (string) ( $row['action'] ?? '' ) );
			$grant_id  = self::sanitize_grant_id( (string) ( $row['grant_id'] ?? '' ) );
			$recipient = self::sanitize_recipient( (string) ( $row['recipient'] ?? '' ) );
			$exp       = isset( $row['exp'] ) ? (int) $row['exp'] : 0;
			if ( '' === $action || '' === $grant_id || '' === $recipient || $exp <= 0 ) {
				continue;
			}
			$out[ $id ] = array(
				'action'    => $action,
				'grant_id'  => $grant_id,
				'recipient' => $recipient,
				'exp'       => $exp,
				'used'      => ! empty( $row['used'] ),
			);
		}

		return $out;
	}

	/**
	 * @param array<string,array<string,mixed>> $map
	 */
	private static function save_map( array $map ): void {
		if ( empty( $map ) ) {
			delete_option( self::TOKENS_OPTION_KEY );
			return;
		}
		update_option( self::TOKENS_OPTION_KEY, $map, false );
	}

	/**
	 * @param array<string,array<string,mixed>> $map
	 * @return array<string,array<string,mixed>>
	 */
	private static function purge_expired( array $map, int $now ): array {
		foreach ( $map as $id => $row ) {
			if ( (int) ( $row['exp'] ?? 0 ) <= $now ) {
				unset( $map[ $id ] );
			}
		}

		return $map;
	}

	private static function mark_used( string $id ): void {
		$map = self::get_map();
		if ( ! isset( $map[ $id ] ) ) {
			return;
		}
		$map[ $id ]['used'] = true;
		self::save_map( $map );
	}

	// -------------------------------------------------------------------------
	// Admin screen.
	// -------------------------------------------------------------------------

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}

		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Access recertification', 'handl-ai-connector-access-control' ),
			__( 'Access recertification', 'handl-ai-connector-access-control' ),
			Caps::VIEW,
			self::PAGE_SLUG,
			array( self::class, 'render_page' )
		);
	}

	public static function maybe_save_settings(): void {
		if ( ! is_admin() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified below.
		if ( empty( $_POST['handl_aicac_recert_save'] ) ) {
			return;
		}
		if ( ! Caps::user_can_manage() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_recert_settings', 'handl_aicac_recert_nonce' );

		self::save_settings(
			array(
				'enabled'      => ! empty( $_POST['handl_aicac_recert_enabled'] ),
				'cycle_days'   => isset( $_POST['handl_aicac_recert_cycle_days'] ) ? absint( wp_unslash( (string) $_POST['handl_aicac_recert_cycle_days'] ) ) : self::DEFAULT_CYCLE_DAYS,
				'grace_days'   => isset( $_POST['handl_aicac_recert_grace_days'] ) ? absint( wp_unslash( (string) $_POST['handl_aicac_recert_grace_days'] ) ) : self::DEFAULT_GRACE_DAYS,
				'auto_suspend' => ! empty( $_POST['handl_aicac_recert_auto_suspend'] ),
			)
		);
		self::redirect_back( 'updated' );
	}

	/**
	 * Per-row Confirm / Revoke buttons on the screen.
	 */
	public static function maybe_handle_grant_action(): void {
		if ( ! is_admin() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified below.
		if ( empty( $_POST['handl_aicac_recert_grant_action'] ) ) {
			return;
		}
		if ( ! Caps::user_can_manage() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_recert_grant', 'handl_aicac_recert_grant_nonce' );

		$action   = sanitize_key( wp_unslash( (string) $_POST['handl_aicac_recert_grant_action'] ) );
		$grant_id = isset( $_POST['handl_aicac_recert_grant_id'] ) ? self::sanitize_grant_id( wp_unslash( (string) $_POST['handl_aicac_recert_grant_id'] ) ) : '';
		$user_id  = (int) get_current_user_id();
		$ok       = false;
		if ( '' !== $grant_id ) {
			if ( self::ACT_CONFIRM === $action ) {
				$ok = self::confirm_grant( $grant_id, $user_id );
			} elseif ( self::ACT_REVOKE === $action ) {
				$ok = self::revoke_grant( $grant_id, $user_id );
			}
		}
		self::redirect_back( $ok ? 'updated' : 'error' );
	}

	private static function redirect_back( string $flag ): void {
		wp_safe_redirect(
			add_query_arg(
				array(
					'page'  => self::PAGE_SLUG,
					$flag   => '1',
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	private static function format_ts( int $ts ): string {
		if ( function_exists( 'wp_date' ) ) {
			return (string) wp_date( 'Y-m-d H:i', $ts );
		}

		return gmdate( 'Y-m-d H:i', $ts ) . ' UTC';
	}

	public static function render_page(): void {
		if ( ! Caps::user_can_view() ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'handl-ai-connector-access-control' ) );
		}

		$settings  = self::get_settings();
		$can_manage = Caps::user_can_manage();
		$now       = Clock::now();
		$inventory = self::build_inventory( null, $now );

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Access recertification', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Standing AI access grants that should be re-confirmed periodically. Off by default; when on, the site owner gets an emailed digest each cycle with confirm and revoke links.', 'handl-ai-connector-access-control' ) . '</p>';

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- display-only flags.
		if ( ! empty( $_GET['updated'] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Saved.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		if ( ! empty( $_GET['error'] ) ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'That grant no longer exists.', 'handl-ai-connector-access-control' ) . '</p></div>';
		}
		// phpcs:enable

		if ( empty( $inventory ) ) {
			echo '<p>' . esc_html__( 'No standing grants to recertify.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			foreach ( array( __( 'Grant', 'handl-ai-connector-access-control' ), __( 'Source', 'handl-ai-connector-access-control' ), __( 'Expires', 'handl-ai-connector-access-control' ), __( 'Last used', 'handl-ai-connector-access-control' ), __( 'Status', 'handl-ai-connector-access-control' ), __( 'Next due', 'handl-ai-connector-access-control' ) ) as $head ) {
				echo '<th>' . esc_html( $head ) . '</th>';
			}
			if ( $can_manage ) {
				echo '<th>' . esc_html__( 'Actions', 'handl-ai-connector-access-control' ) . '</th>';
			}
			echo '</tr></thead><tbody>';
			foreach ( $inventory as $grant ) {
				$status_labels = array(
					'ok'         => __( 'OK', 'handl-ai-connector-access-control' ),
					'due'        => __( 'Due', 'handl-ai-connector-access-control' ),
					'unattested' => __( 'Unattested', 'handl-ai-connector-access-control' ),
					'flagged'    => __( 'Flagged', 'handl-ai-connector-access-control' ),
				);
				echo '<tr>';
				echo '<td><code>' . esc_html( (string) $grant['label'] ) . '</code></td>';
				echo '<td>' . esc_html( (string) $grant['source'] ) . '</td>';
				echo '<td>' . esc_html( ! empty( $grant['expires_at'] ) ? self::format_ts( (int) $grant['expires_at'] ) : __( 'Never', 'handl-ai-connector-access-control' ) ) . '</td>';
				echo '<td>' . esc_html( ! empty( $grant['last_used_ts'] ) ? self::format_ts( (int) $grant['last_used_ts'] ) : __( 'No recent activity', 'handl-ai-connector-access-control' ) ) . '</td>';
				echo '<td>' . esc_html( $status_labels[ $grant['status'] ] ?? (string) $grant['status'] ) . '</td>';
				echo '<td>' . esc_html( ! empty( $grant['next_due_ts'] ) ? self::format_ts( (int) $grant['next_due_ts'] ) : '—' ) . '</td>';
				if ( $can_manage ) {
					echo '<td>';
					foreach ( array(
						self::ACT_CONFIRM => __( 'Confirm', 'handl-ai-connector-access-control' ),
						self::ACT_REVOKE  => __( 'Revoke', 'handl-ai-connector-access-control' ),
					) as $act => $text ) {
						echo '<form method="post" action="' . esc_url( admin_url( 'admin.php?page=' . self::PAGE_SLUG ) ) . '" style="display:inline-block;margin-right:4px;">';
						wp_nonce_field( 'handl_aicac_recert_grant', 'handl_aicac_recert_grant_nonce' );
						echo '<input type="hidden" name="handl_aicac_recert_grant_id" value="' . esc_attr( (string) $grant['grant_id'] ) . '" />';
						echo '<button type="submit" class="button" name="handl_aicac_recert_grant_action" value="' . esc_attr( $act ) . '">' . esc_html( $text ) . '</button>';
						echo '</form>';
					}
					echo '</td>';
				}
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		if ( $can_manage ) {
			echo '<h2>' . esc_html__( 'Settings', 'handl-ai-connector-access-control' ) . '</h2>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin.php?page=' . self::PAGE_SLUG ) ) . '">';
			wp_nonce_field( 'handl_aicac_recert_settings', 'handl_aicac_recert_nonce' );
			echo '<input type="hidden" name="handl_aicac_recert_save" value="1" />';
			echo '<p><label><input type="checkbox" name="handl_aicac_recert_enabled" value="1"' . ( $settings['enabled'] ? ' checked="checked"' : '' ) . ' /> ' . esc_html__( 'Enable periodic recertification (email digest each cycle). Off by default.', 'handl-ai-connector-access-control' ) . '</label></p>';
			echo '<p><label>' . esc_html__( 'Cycle length (days)', 'handl-ai-connector-access-control' ) . ' <input type="number" min="7" max="365" name="handl_aicac_recert_cycle_days" value="' . esc_attr( (string) $settings['cycle_days'] ) . '" /></label></p>';
			echo '<p><label>' . esc_html__( 'Grace period (days)', 'handl-ai-connector-access-control' ) . ' <input type="number" min="0" max="90" name="handl_aicac_recert_grace_days" value="' . esc_attr( (string) $settings['grace_days'] ) . '" /></label></p>';
			echo '<p><label><input type="checkbox" name="handl_aicac_recert_auto_suspend" value="1"' . ( $settings['auto_suspend'] ? ' checked="checked"' : '' ) . ' /> ' . esc_html__( 'Auto-suspend: revoke grants still unattested after the grace period. Off by default.', 'handl-ai-connector-access-control' ) . '</label></p>';
			submit_button( __( 'Save settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		echo '</div>';
	}
}
