<?php
/**
 * AICAC-SUCCESSION (#407): alert-audience bus factor (read-only).
 *
 * Recipient census across alerting controls from a bundled static
 * option-to-recipient table (+ admin_email fallback). Distinct-humans count,
 * single-point-of-failure flag, dead-recipient findings (deleted user, lost
 * manage_options, never-logged-in via Unattended ledger when present).
 * Suggestion-only deep links. Exactly one re-arming [SUCCESSION] alert sent
 * to every census destination. Print + CSV + WP-CLI. Never rewrites recipients.
 * OFF by default. Own two options.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Alert-audience bus-factor census.
 */
final class Succession {

	public const SETTINGS_OPTION = 'handl_aicac_succession';

	public const STATE_OPTION = 'handl_aicac_succession_state';

	public const PAGE_SLUG = 'handl-aicac-succession';

	public const ALERT_KIND = 'succession';

	public const FRAMING = 'report_only_never_rewrites_recipients';

	public const FILTER_SOURCES = 'handl_aicac_succession_recipient_sources';

	public const POST_PRESENT = 'handl_aicac_succession_present';

	public const POST_ENABLED = 'handl_aicac_succession_enabled';

	public const ACTION_SAVE = 'handl_aicac_succession_save';

	public const HISTORY_CAP = 40;

	/** @var bool */
	private static $registered = false;

	/** @var list<array<string,mixed>> */
	private static $test_mails = array();

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		add_action( 'admin_menu', array( self::class, 'register_menu' ), 20 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_csv' ), 5 );
		add_action( 'admin_init', array( self::class, 'maybe_handle_print' ), 5 );
		add_action( 'admin_post_' . self::ACTION_SAVE, array( self::class, 'handle_save' ) );

		if ( self::is_enabled() ) {
			add_action( 'init', array( self::class, 'maybe_fire_alerts' ), 30 );
		}

		self::register_cli();
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$test_mails = array();
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
	 * @return array{enabled:bool}
	 */
	public static function defaults(): array {
		return array(
			'enabled' => false,
		);
	}

	/**
	 * @return array{enabled:bool}
	 */
	public static function get_settings(): array {
		return self::sanitize_settings( get_option( self::SETTINGS_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw settings.
	 * @return array{enabled:bool}
	 */
	public static function sanitize_settings( $raw ): array {
		$defaults = self::defaults();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}

		return array(
			'enabled' => ! empty( $raw['enabled'] ),
		);
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

			return true;
		}
		update_option( self::SETTINGS_OPTION, $clean, false );

		return true;
	}

	public static function is_enabled(): bool {
		$settings = self::get_settings();

		return ! empty( $settings['enabled'] );
	}

	/**
	 * @return array{alerted:bool,known_users:array<string,int>,history:list<array<string,mixed>>}
	 */
	public static function defaults_state(): array {
		return array(
			'alerted'      => false,
			'known_users'  => array(),
			'history'      => array(),
		);
	}

	/**
	 * @return array{alerted:bool,known_users:array<string,int>,history:list<array<string,mixed>>}
	 */
	public static function get_state(): array {
		return self::sanitize_state( get_option( self::STATE_OPTION, array() ) );
	}

	/**
	 * @param mixed $raw Raw state.
	 * @return array{alerted:bool,known_users:array<string,int>,history:list<array<string,mixed>>}
	 */
	public static function sanitize_state( $raw ): array {
		$defaults = self::defaults_state();
		if ( ! is_array( $raw ) ) {
			return $defaults;
		}
		$known = array();
		if ( isset( $raw['known_users'] ) && is_array( $raw['known_users'] ) ) {
			foreach ( $raw['known_users'] as $email => $uid ) {
				$email = self::normalize_email( (string) $email );
				$uid   = (int) $uid;
				if ( '' === $email || $uid <= 0 ) {
					continue;
				}
				$known[ $email ] = $uid;
			}
		}
		$history = array();
		if ( isset( $raw['history'] ) && is_array( $raw['history'] ) ) {
			foreach ( $raw['history'] as $row ) {
				$clean = self::sanitize_history_entry( $row );
				if ( null !== $clean ) {
					$history[] = $clean;
				}
			}
		}
		if ( count( $history ) > self::HISTORY_CAP ) {
			$history = array_slice( $history, -self::HISTORY_CAP );
		}

		return array(
			'alerted'     => ! empty( $raw['alerted'] ),
			'known_users' => $known,
			'history'     => $history,
		);
	}

	/**
	 * @param mixed $row Raw history row.
	 * @return array{ts:int,distinct:int,spof:bool,dead:int}|null
	 */
	public static function sanitize_history_entry( $row ): ?array {
		if ( ! is_array( $row ) ) {
			return null;
		}
		$ts = isset( $row['ts'] ) ? (int) $row['ts'] : 0;
		if ( $ts <= 0 ) {
			return null;
		}

		return array(
			'ts'       => $ts,
			'distinct' => max( 0, (int) ( $row['distinct'] ?? 0 ) ),
			'spof'     => ! empty( $row['spof'] ),
			'dead'     => max( 0, (int) ( $row['dead'] ?? 0 ) ),
		);
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

	public static function set_alerted( bool $alerted ): void {
		$state            = self::get_state();
		$state['alerted'] = $alerted;
		self::put_state( $state );
	}

	public static function normalize_email( string $email ): string {
		$email = trim( $email );
		if ( function_exists( 'sanitize_email' ) ) {
			$email = sanitize_email( $email );
		}
		if ( '' === $email ) {
			return '';
		}
		if ( function_exists( 'is_email' ) && ! is_email( $email ) ) {
			return '';
		}

		return strtolower( $email );
	}

	/**
	 * Bundled static option-to-recipient table.
	 *
	 * @return list<array{control:string,option:string,field:string,kind:string,page:string,fallback_admin:bool,label:string}>
	 */
	public static function bundled_recipient_sources(): array {
		$policy = class_exists( Plugin::class, false ) ? Plugin::OPTION_KEY : 'handl_aicac_policy';
		$out    = array(
			array(
				'control'         => 'denial',
				'option'          => $policy,
				'field'           => 'alert_email',
				'kind'            => 'policy_field',
				'page'            => 'handl-aicac',
				'fallback_admin'  => true,
				'label'           => 'Denial / default alerts',
			),
		);

		$routing_types = array(
			'budget',
			'drift',
			'anomaly',
			'latency',
			'shadow',
			'expiry',
			'digest',
			'webhook-failure',
			'canary',
		);
		if ( class_exists( Alert_Routing::class, false ) && defined( Alert_Routing::class . '::TYPES' ) ) {
			$routing_types = Alert_Routing::TYPES;
		}
		foreach ( $routing_types as $type ) {
			$out[] = array(
				'control'         => 'routing_' . str_replace( '-', '_', (string) $type ),
				'option'          => $policy,
				'field'           => (string) $type,
				'kind'            => 'routing_type',
				'page'            => 'handl-aicac',
				'fallback_admin'  => true,
				'label'           => sprintf( 'Alert routing: %s', (string) $type ),
			);
		}

		// Own-option destinations (class may be absent on older installs — still listed).
		$out[] = array(
			'control'         => 'unattended',
			'option'          => 'handl_aicac_unattended',
			'field'           => 'backup_email',
			'kind'            => 'option_field',
			'page'            => 'handl-aicac-unattended',
			'fallback_admin'  => true,
			'label'           => 'Unattended backup',
		);

		// Single-fire controls that reuse the default alert_email path (deep-link only).
		$defaults = array(
			'drill'      => 'handl-aicac-drill',
			'key_age'    => 'handl-aicac-key-age',
			'footprint'  => 'handl-aicac-footprint',
			'noise'      => 'handl-aicac-noise',
			'friction'   => 'handl-aicac-friction',
			'dormant'    => 'handl-aicac-dormant',
			'chargeback' => 'handl-aicac-chargeback',
			'recert'     => 'handl-aicac-recert',
			'went_ai'    => 'handl-aicac',
			'temp_allow' => 'handl-aicac',
		);
		foreach ( $defaults as $control => $page ) {
			$out[] = array(
				'control'         => (string) $control,
				'option'          => $policy,
				'field'           => 'alert_email',
				'kind'            => 'policy_default',
				'page'            => (string) $page,
				'fallback_admin'  => true,
				'label'           => sprintf( 'Default alert path: %s', (string) $control ),
			);
		}

		return $out;
	}

	/**
	 * @return list<array{control:string,option:string,field:string,kind:string,page:string,fallback_admin:bool,label:string}>
	 */
	public static function recipient_sources(): array {
		$sources = self::bundled_recipient_sources();
		if ( function_exists( 'apply_filters' ) ) {
			$filtered = apply_filters( self::FILTER_SOURCES, $sources );
			if ( is_array( $filtered ) ) {
				$sources = $filtered;
			}
		}
		$out = array();
		foreach ( $sources as $row ) {
			if ( ! is_array( $row ) ) {
				continue;
			}
			$control = isset( $row['control'] ) ? sanitize_key( (string) $row['control'] ) : '';
			$option  = isset( $row['option'] ) ? sanitize_key( (string) $row['option'] ) : '';
			$field   = isset( $row['field'] ) ? (string) $row['field'] : '';
			$kind    = isset( $row['kind'] ) ? sanitize_key( (string) $row['kind'] ) : '';
			$page    = isset( $row['page'] ) ? sanitize_key( (string) $row['page'] ) : 'handl-aicac';
			$label   = isset( $row['label'] ) ? sanitize_text_field( (string) $row['label'] ) : $control;
			if ( '' === $control || '' === $option || '' === $field || '' === $kind ) {
				continue;
			}
			// routing types may contain hyphens.
			if ( 'routing_type' === $kind ) {
				$field = sanitize_text_field( $field );
			} else {
				$field = sanitize_key( $field );
			}
			if ( '' === $field ) {
				continue;
			}
			$out[] = array(
				'control'        => $control,
				'option'         => $option,
				'field'          => $field,
				'kind'           => $kind,
				'page'           => '' !== $page ? $page : 'handl-aicac',
				'fallback_admin' => ! empty( $row['fallback_admin'] ),
				'label'          => '' !== $label ? $label : $control,
			);
		}

		return $out;
	}

	public static function admin_email(): string {
		$admin = function_exists( 'sanitize_email' )
			? sanitize_email( (string) get_option( 'admin_email' ) )
			: (string) get_option( 'admin_email' );
		$admin = self::normalize_email( $admin );

		return $admin;
	}

	public static function control_admin_url( string $page ): string {
		$page = sanitize_key( $page );
		if ( '' === $page ) {
			$page = 'handl-aicac';
		}
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg( 'page', $page, admin_url( 'admin.php' ) );
	}

	/**
	 * Resolve configured emails for one source row (read-only).
	 *
	 * @param array<string,mixed> $source Source.
	 * @return array{emails:list<string>,used_fallback:bool,configured:bool}
	 */
	public static function resolve_source_emails( array $source ): array {
		$kind     = (string) ( $source['kind'] ?? '' );
		$option   = (string) ( $source['option'] ?? '' );
		$field    = (string) ( $source['field'] ?? '' );
		$fallback = ! empty( $source['fallback_admin'] );
		$emails   = array();
		$configured = false;

		if ( 'routing_type' === $kind ) {
			$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : get_option( $option, array() );
			if ( ! is_array( $policy ) ) {
				$policy = array();
			}
			if ( class_exists( Alert_Routing::class, false ) && method_exists( Alert_Routing::class, 'resolve_recipients' ) ) {
				$list = Alert_Routing::resolve_recipients( $policy, $field );
				foreach ( $list as $email ) {
					$n = self::normalize_email( (string) $email );
					if ( '' !== $n ) {
						$emails[]     = $n;
						$configured = true;
					}
				}
			}
			// If routing fell through to default, still count the default destination.
			if ( empty( $emails ) && class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
				$n = self::normalize_email( (string) Alerts::resolve_email( $policy ) );
				if ( '' !== $n ) {
					$emails[] = $n;
				}
			}
		} elseif ( 'option_field' === $kind ) {
			$raw = get_option( $option, array() );
			if ( is_array( $raw ) && isset( $raw[ $field ] ) ) {
				$n = self::normalize_email( (string) $raw[ $field ] );
				if ( '' !== $n ) {
					$emails[]     = $n;
					$configured = true;
				}
			}
		} else {
			// policy_field / policy_default
			$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : get_option( $option, array() );
			if ( ! is_array( $policy ) ) {
				$policy = array();
			}
			if ( isset( $policy[ $field ] ) ) {
				$n = self::normalize_email( (string) $policy[ $field ] );
				if ( '' !== $n ) {
					$emails[]     = $n;
					$configured = true;
				}
			}
			if ( empty( $emails ) && class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_email' ) ) {
				$n = self::normalize_email( (string) Alerts::resolve_email( $policy ) );
				if ( '' !== $n ) {
					$emails[] = $n;
				}
			}
		}

		$used_fallback = false;
		if ( empty( $emails ) && $fallback ) {
			$admin = self::admin_email();
			if ( '' !== $admin ) {
				$emails[]      = $admin;
				$used_fallback = true;
			}
		}

		$emails = array_values( array_unique( $emails ) );

		return array(
			'emails'        => $emails,
			'used_fallback' => $used_fallback,
			'configured'    => $configured,
		);
	}

	/**
	 * @param object|false $user User.
	 * @return bool|null true/false, or null when unknown.
	 */
	public static function user_has_manage( $user ): ?bool {
		if ( ! is_object( $user ) ) {
			return null;
		}
		if ( isset( $user->allcaps ) && is_array( $user->allcaps ) ) {
			return ! empty( $user->allcaps['manage_options'] );
		}
		if ( method_exists( $user, 'has_cap' ) ) {
			return (bool) $user->has_cap( Caps::MANAGE );
		}
		if ( function_exists( 'user_can' ) ) {
			return (bool) user_can( $user, Caps::MANAGE );
		}

		return null;
	}

	/**
	 * class_exists-guarded Unattended ledger lookup.
	 */
	public static function unattended_has_login( int $user_id ): ?bool {
		if ( $user_id <= 0 ) {
			return null;
		}
		if ( ! class_exists( Unattended::class, false ) || ! method_exists( Unattended::class, 'get_state' ) ) {
			return null;
		}
		if ( method_exists( Unattended::class, 'is_enabled' ) && ! Unattended::is_enabled() ) {
			return null;
		}
		$state = Unattended::get_state();
		if ( ! is_array( $state ) ) {
			return null;
		}
		// Only enrich when Unattended is actively watching.
		$watching = (int) ( $state['watching_since'] ?? 0 );
		$ledger   = isset( $state['ledger'] ) && is_array( $state['ledger'] ) ? $state['ledger'] : array();
		if ( $watching <= 0 && empty( $ledger ) ) {
			return null;
		}
		$key = (string) $user_id;

		return isset( $ledger[ $key ] );
	}

	/**
	 * Full recipient census rows.
	 *
	 * @return list<array<string,mixed>>
	 */
	public static function census(): array {
		$state = self::get_state();
		$known = $state['known_users'];
		$rows  = array();

		foreach ( self::recipient_sources() as $source ) {
			$resolved = self::resolve_source_emails( $source );
			$url      = self::control_admin_url( (string) $source['page'] );
			if ( empty( $resolved['emails'] ) ) {
				$rows[] = array(
					'control'        => (string) $source['control'],
					'label'          => (string) $source['label'],
					'email'          => '',
					'user_id'        => 0,
					'user_login'     => '',
					'match'          => 'none',
					'dead'           => array(),
					'used_fallback'  => false,
					'url'            => $url,
				);
				continue;
			}
			foreach ( $resolved['emails'] as $email ) {
				$user_id    = 0;
				$user_login = '';
				$match      = 'unmatched';
				$dead       = array();

				$user = function_exists( 'get_user_by' ) ? get_user_by( 'email', $email ) : false;
				if ( is_object( $user ) && isset( $user->ID ) ) {
					$user_id    = (int) $user->ID;
					$user_login = isset( $user->user_login ) ? (string) $user->user_login : '';
					$match      = 'user';
					$has_manage = self::user_has_manage( $user );
					if ( false === $has_manage ) {
						$dead[] = 'lost_manage_options';
					}
					$logged = self::unattended_has_login( $user_id );
					if ( false === $logged ) {
						$dead[] = 'never_logged_in';
					}
					$known[ $email ] = $user_id;
				} else {
					// Previously matched user_id no longer resolves → deleted.
					if ( isset( $known[ $email ] ) ) {
						$prev = (int) $known[ $email ];
						if ( $prev > 0 && function_exists( 'get_userdata' ) && false === get_userdata( $prev ) ) {
							$dead[]  = 'deleted_user';
							$match   = 'deleted';
							$user_id = $prev;
						}
					}
				}

				$rows[] = array(
					'control'       => (string) $source['control'],
					'label'         => (string) $source['label'],
					'email'         => $email,
					'user_id'       => $user_id,
					'user_login'    => $user_login,
					'match'         => $match,
					'dead'          => $dead,
					'used_fallback' => ! empty( $resolved['used_fallback'] ),
					'url'           => $url,
				);
			}
		}

		// Persist known_users map for deleted-user detection on later runs.
		$state['known_users'] = $known;
		self::put_state( $state );

		return $rows;
	}

	/**
	 * Distinct destination emails with human match metadata.
	 *
	 * @param list<array<string,mixed>>|null $census Census override.
	 * @return list<array{email:string,user_id:int,user_login:string,match:string,controls:list<string>,dead:list<string>,url:string}>
	 */
	public static function distinct_humans( ?array $census = null ): array {
		$census = null !== $census ? $census : self::census();
		$by     = array();
		foreach ( $census as $row ) {
			$email = self::normalize_email( (string) ( $row['email'] ?? '' ) );
			if ( '' === $email ) {
				continue;
			}
			if ( ! isset( $by[ $email ] ) ) {
				$by[ $email ] = array(
					'email'      => $email,
					'user_id'    => (int) ( $row['user_id'] ?? 0 ),
					'user_login' => (string) ( $row['user_login'] ?? '' ),
					'match'      => (string) ( $row['match'] ?? 'unmatched' ),
					'controls'   => array(),
					'dead'       => array(),
					'url'        => (string) ( $row['url'] ?? '' ),
				);
			}
			$control = sanitize_key( (string) ( $row['control'] ?? '' ) );
			if ( '' !== $control && ! in_array( $control, $by[ $email ]['controls'], true ) ) {
				$by[ $email ]['controls'][] = $control;
			}
			foreach ( (array) ( $row['dead'] ?? array() ) as $reason ) {
				$reason = sanitize_key( (string) $reason );
				if ( '' !== $reason && ! in_array( $reason, $by[ $email ]['dead'], true ) ) {
					$by[ $email ]['dead'][] = $reason;
				}
			}
			if ( (int) ( $row['user_id'] ?? 0 ) > 0 ) {
				$by[ $email ]['user_id'] = (int) $row['user_id'];
			}
			if ( '' !== (string) ( $row['user_login'] ?? '' ) ) {
				$by[ $email ]['user_login'] = (string) $row['user_login'];
			}
			if ( 'user' === (string) ( $row['match'] ?? '' ) ) {
				$by[ $email ]['match'] = 'user';
			} elseif ( 'deleted' === (string) ( $row['match'] ?? '' ) && 'user' !== $by[ $email ]['match'] ) {
				$by[ $email ]['match'] = 'deleted';
			}
			if ( '' === $by[ $email ]['url'] && '' !== (string) ( $row['url'] ?? '' ) ) {
				$by[ $email ]['url'] = (string) $row['url'];
			}
		}
		$out = array_values( $by );
		usort(
			$out,
			static function ( array $a, array $b ): int {
				return strcmp( $a['email'], $b['email'] );
			}
		);

		return $out;
	}

	/**
	 * @param list<array<string,mixed>>|null $humans Humans override.
	 */
	public static function is_spof( ?array $humans = null ): bool {
		$humans = null !== $humans ? $humans : self::distinct_humans();

		return 1 === count( $humans );
	}

	/**
	 * @param list<array<string,mixed>>|null $humans Humans override.
	 * @return list<array{email:string,user_id:int,reason:string,url:string}>
	 */
	public static function dead_findings( ?array $humans = null ): array {
		$humans = null !== $humans ? $humans : self::distinct_humans();
		$out    = array();
		foreach ( $humans as $row ) {
			foreach ( (array) ( $row['dead'] ?? array() ) as $reason ) {
				$out[] = array(
					'email'   => (string) ( $row['email'] ?? '' ),
					'user_id' => (int) ( $row['user_id'] ?? 0 ),
					'reason'  => sanitize_key( (string) $reason ),
					'url'     => (string) ( $row['url'] ?? '' ),
				);
			}
		}

		return $out;
	}

	/**
	 * Unique destination list for the [SUCCESSION] alert fan-out.
	 *
	 * @param list<array<string,mixed>>|null $humans Humans override.
	 * @return list<string>
	 */
	public static function census_destinations( ?array $humans = null ): array {
		$humans = null !== $humans ? $humans : self::distinct_humans();
		$out    = array();
		foreach ( $humans as $row ) {
			$email = self::normalize_email( (string) ( $row['email'] ?? '' ) );
			if ( '' !== $email ) {
				$out[] = $email;
			}
		}
		$admin = self::admin_email();
		if ( '' !== $admin ) {
			$out[] = $admin;
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function snapshot( ?int $now = null ): array {
		$now     = null !== $now ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$census  = self::census();
		$humans  = self::distinct_humans( $census );
		$dead    = self::dead_findings( $humans );
		$spof    = self::is_spof( $humans );
		self::record_history( $now, count( $humans ), $spof, count( $dead ) );
		$state = self::get_state();

		return array(
			'enabled'           => self::is_enabled(),
			'distinct_humans'   => count( $humans ),
			'spof'              => $spof,
			'humans'            => $humans,
			'dead'              => $dead,
			'dead_count'        => count( $dead ),
			'census'            => $census,
			'destinations'      => self::census_destinations( $humans ),
			'alerted'           => ! empty( $state['alerted'] ),
			'history'           => $state['history'],
			'framing'           => self::FRAMING,
		);
	}

	public static function record_history( int $now, int $distinct, bool $spof, int $dead ): void {
		$state              = self::get_state();
		$state['history'][] = array(
			'ts'       => $now,
			'distinct' => $distinct,
			'spof'     => $spof,
			'dead'     => $dead,
		);
		if ( count( $state['history'] ) > self::HISTORY_CAP ) {
			$state['history'] = array_slice( $state['history'], -self::HISTORY_CAP );
		}
		self::put_state( $state );
	}

	/**
	 * @return bool True when a new alert was sent.
	 */
	public static function maybe_fire_alerts( ?int $now = null ): bool {
		if ( ! self::is_enabled() ) {
			return false;
		}
		$now    = null !== $now ? $now : ( class_exists( Clock::class, false ) ? Clock::now() : time() );
		$snap   = self::snapshot( $now );
		$hot    = ! empty( $snap['spof'] ) || ! empty( $snap['dead'] );

		if ( ! $hot ) {
			if ( self::is_alerted() ) {
				self::set_alerted( false );
			}

			return false;
		}

		if ( self::is_alerted() ) {
			return false;
		}

		if ( ! self::fire_alert( $snap, $now ) ) {
			return false;
		}
		self::set_alerted( true );

		return true;
	}

	/**
	 * @param array<string,mixed> $payload Payload / snapshot.
	 */
	private static function fire_alert( array $payload, int $now ): bool {
		$destinations = self::census_destinations( isset( $payload['humans'] ) && is_array( $payload['humans'] ) ? $payload['humans'] : null );
		if ( empty( $destinations ) ) {
			return false;
		}

		$subject = self::build_subject( $payload );
		$body    = self::build_body( $payload );
		$any_ok  = false;

		foreach ( $destinations as $email ) {
			$ok = false;
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
			if ( $ok ) {
				$any_ok = true;
			}
		}

		$policy = class_exists( Policy::class, false ) ? Policy::get_policy() : array();
		if ( ! is_array( $policy ) ) {
			$policy = array();
		}
		if ( $any_ok && class_exists( Alerts::class, false ) && method_exists( Alerts::class, 'resolve_webhook' ) ) {
			$hook_url = (string) Alerts::resolve_webhook( $policy );
			if ( '' !== $hook_url && method_exists( Alerts::class, 'safe_wp_remote_post' ) ) {
				Alerts::safe_wp_remote_post(
					$hook_url,
					array(
						'type'            => 'handl_aicac_succession',
						'distinct_humans' => (int) ( $payload['distinct_humans'] ?? 0 ),
						'spof'            => ! empty( $payload['spof'] ),
						'dead_count'      => (int) ( $payload['dead_count'] ?? 0 ),
						'site'            => function_exists( 'home_url' ) ? home_url( '/' ) : '',
						'ts'              => $now,
					)
				);
			}
		}

		return $any_ok;
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	public static function build_subject( array $payload ): string {
		$site = function_exists( 'get_bloginfo' )
			? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			: 'WordPress';
		$distinct = (int) ( $payload['distinct_humans'] ?? 0 );

		return sprintf(
			/* translators: 1: site name, 2: distinct human count */
			__( '[%1$s] [SUCCESSION] Alert audience bus factor is %2$d', 'handl-ai-connector-access-control' ),
			$site,
			$distinct
		);
	}

	/**
	 * @param array<string,mixed> $payload Payload.
	 */
	public static function build_body( array $payload ): string {
		$lines   = array();
		$lines[] = __( 'This site\'s AI Connector governance alerts resolve to too few humans, or include a dead recipient.', 'handl-ai-connector-access-control' );
		$lines[] = '';
		$lines[] = sprintf(
			/* translators: %d: distinct humans */
			__( 'Distinct humans in the recipient census: %d', 'handl-ai-connector-access-control' ),
			(int) ( $payload['distinct_humans'] ?? 0 )
		);
		if ( ! empty( $payload['spof'] ) ) {
			$lines[] = __( 'Single point of failure: the entire suite routes to one human.', 'handl-ai-connector-access-control' );
		}
		$dead = is_array( $payload['dead'] ?? null ) ? $payload['dead'] : array();
		if ( ! empty( $dead ) ) {
			$lines[] = '';
			$lines[] = __( 'Dead recipients (suggestion only — open the linked settings to add another destination):', 'handl-ai-connector-access-control' );
			foreach ( $dead as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}
				$lines[] = sprintf(
					'- %s (%s) — %s',
					(string) ( $row['email'] ?? '' ),
					(string) ( $row['reason'] ?? '' ),
					(string) ( $row['url'] ?? '' )
				);
			}
		}
		$lines[] = '';
		$lines[] = __( 'Report only — never rewrites recipients on other controls.', 'handl-ai-connector-access-control' );
		$url     = self::admin_url();
		if ( '' !== $url ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %s: admin URL */
				__( 'Open succession census: %s', 'handl-ai-connector-access-control' ),
				$url
			);
		}

		return implode( "\n", $lines ) . "\n";
	}

	public static function admin_url(): string {
		if ( ! function_exists( 'admin_url' ) ) {
			return '';
		}

		return (string) add_query_arg( 'page', self::PAGE_SLUG, admin_url( 'admin.php' ) );
	}

	/**
	 * @param array<string,mixed>|null $snap Snapshot override.
	 */
	public static function csv_for_snapshot( ?array $snap = null ): string {
		$snap  = null !== $snap ? $snap : self::snapshot();
		$lines = array();
		$lines[] = self::csv_line( array( 'section', 'email', 'user_id', 'match', 'controls_or_reason', 'url', 'framing' ) );
		foreach ( (array) ( $snap['humans'] ?? array() ) as $row ) {
			$lines[] = self::csv_line(
				array(
					'human',
					(string) ( $row['email'] ?? '' ),
					(string) (int) ( $row['user_id'] ?? 0 ),
					(string) ( $row['match'] ?? '' ),
					implode( '|', (array) ( $row['controls'] ?? array() ) ),
					(string) ( $row['url'] ?? '' ),
					self::FRAMING,
				)
			);
		}
		foreach ( (array) ( $snap['dead'] ?? array() ) as $row ) {
			$lines[] = self::csv_line(
				array(
					'dead',
					(string) ( $row['email'] ?? '' ),
					(string) (int) ( $row['user_id'] ?? 0 ),
					'',
					(string) ( $row['reason'] ?? '' ),
					(string) ( $row['url'] ?? '' ),
					self::FRAMING,
				)
			);
		}
		$lines[] = self::csv_line(
			array(
				'summary',
				'',
				(string) (int) ( $snap['distinct_humans'] ?? 0 ),
				! empty( $snap['spof'] ) ? 'spof' : 'ok',
				(string) (int) ( $snap['dead_count'] ?? 0 ),
				'',
				self::FRAMING,
			)
		);

		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * @param list<string> $cols Columns.
	 */
	public static function csv_line( array $cols ): string {
		$out = array();
		foreach ( $cols as $col ) {
			$col = (string) $col;
			if ( str_contains( $col, ',' ) || str_contains( $col, '"' ) || str_contains( $col, "\n" ) ) {
				$col = '"' . str_replace( '"', '""', $col ) . '"';
			}
			$out[] = $col;
		}

		return implode( ',', $out );
	}

	/**
	 * @param array<string,mixed> $snap Snapshot.
	 */
	public static function build_print_html( array $snap ): string {
		$html  = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>';
		$html .= esc_html__( 'AI Connector succession report', 'handl-ai-connector-access-control' );
		$html .= '</title><style>body{font-family:sans-serif;margin:24px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px;text-align:left}</style></head><body>';
		$html .= '<h1>' . esc_html__( 'AI Connector succession report', 'handl-ai-connector-access-control' ) . '</h1>';
		$html .= '<p>' . esc_html(
			sprintf(
				/* translators: %d: distinct humans */
				__( 'Distinct humans: %d', 'handl-ai-connector-access-control' ),
				(int) ( $snap['distinct_humans'] ?? 0 )
			)
		) . '</p>';
		if ( ! empty( $snap['spof'] ) ) {
			$html .= '<p><strong>' . esc_html__( 'Single point of failure.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		}
		$html .= '<p><strong>' . esc_html__( 'Report only — never rewrites recipients.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		$html .= '<h2>' . esc_html__( 'Humans', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= '<table><thead><tr><th>' . esc_html__( 'Email', 'handl-ai-connector-access-control' ) . '</th><th>' . esc_html__( 'Match', 'handl-ai-connector-access-control' ) . '</th><th>' . esc_html__( 'Controls', 'handl-ai-connector-access-control' ) . '</th></tr></thead><tbody>';
		foreach ( (array) ( $snap['humans'] ?? array() ) as $row ) {
			$html .= '<tr><td>' . esc_html( (string) ( $row['email'] ?? '' ) ) . '</td><td>' . esc_html( (string) ( $row['match'] ?? '' ) ) . '</td><td><code>' . esc_html( implode( ', ', (array) ( $row['controls'] ?? array() ) ) ) . '</code></td></tr>';
		}
		$html .= '</tbody></table>';
		$html .= '<h2>' . esc_html__( 'Dead recipients', 'handl-ai-connector-access-control' ) . '</h2>';
		$html .= '<table><thead><tr><th>' . esc_html__( 'Email', 'handl-ai-connector-access-control' ) . '</th><th>' . esc_html__( 'Reason', 'handl-ai-connector-access-control' ) . '</th><th>' . esc_html__( 'Link', 'handl-ai-connector-access-control' ) . '</th></tr></thead><tbody>';
		foreach ( (array) ( $snap['dead'] ?? array() ) as $row ) {
			$html .= '<tr><td>' . esc_html( (string) ( $row['email'] ?? '' ) ) . '</td><td>' . esc_html( (string) ( $row['reason'] ?? '' ) ) . '</td><td>' . esc_html( (string) ( $row['url'] ?? '' ) ) . '</td></tr>';
		}
		$html .= '</tbody></table></body></html>';

		return $html;
	}

	public static function register_menu(): void {
		if ( ! Caps::user_can_view() ) {
			return;
		}
		if ( ! function_exists( 'add_submenu_page' ) ) {
			return;
		}
		add_submenu_page(
			Admin::MENU_SLUG,
			__( 'Alert succession', 'handl-ai-connector-access-control' ),
			__( 'Succession', 'handl-ai-connector-access-control' ),
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
				'page'                        => self::PAGE_SLUG,
				'handl_aicac_succession_csv'  => '1',
				'_wpnonce'                    => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_succession_csv' ) : '',
			),
			admin_url( 'admin.php' )
		);
		$print = add_query_arg(
			array(
				'page'                         => self::PAGE_SLUG,
				'handl_aicac_succession_print' => '1',
				'_wpnonce'                     => function_exists( 'wp_create_nonce' ) ? wp_create_nonce( 'handl_aicac_succession_print' ) : '',
			),
			admin_url( 'admin.php' )
		);

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Alert succession', 'handl-ai-connector-access-control' ) . '</h1>';
		echo '<p class="description">' . esc_html__( 'Count how many distinct humans receive AI Connector governance alerts. Report only — never rewrites recipients. Off by default.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( $can_manage ) {
			$action = admin_url( 'admin-post.php' );
			echo '<form method="post" action="' . esc_url( $action ) . '">';
			echo '<input type="hidden" name="action" value="' . esc_attr( self::ACTION_SAVE ) . '" />';
			if ( function_exists( 'wp_nonce_field' ) ) {
				wp_nonce_field( self::ACTION_SAVE );
			}
			echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
			echo '<table class="form-table" role="presentation"><tbody>';
			echo '<tr><th scope="row">' . esc_html__( 'Enable succession census', 'handl-ai-connector-access-control' ) . '</th><td>';
			echo '<label><input type="checkbox" name="' . esc_attr( self::POST_ENABLED ) . '" value="1" ' . checked( ! empty( $settings['enabled'] ), true, false ) . ' /> ';
			echo esc_html__( 'Census alert recipients, flag a single point of failure, and alert on dead destinations', 'handl-ai-connector-access-control' );
			echo '</label></td></tr></tbody></table>';
			submit_button( __( 'Save succession settings', 'handl-ai-connector-access-control' ) );
			echo '</form>';
		}

		if ( ! $enabled || ! is_array( $snap ) ) {
			echo '<p>' . esc_html__( 'Succession census is off. Enable it to count who receives governance alerts.', 'handl-ai-connector-access-control' ) . '</p>';
			echo '</div>';

			return;
		}

		echo '<p><strong>' . esc_html__( 'Report only — never rewrites recipients on other controls.', 'handl-ai-connector-access-control' ) . '</strong></p>';
		echo '<ul>';
		echo '<li>' . esc_html(
			sprintf(
				/* translators: %d: distinct humans */
				__( 'Distinct humans: %d', 'handl-ai-connector-access-control' ),
				(int) $snap['distinct_humans']
			)
		) . '</li>';
		if ( ! empty( $snap['spof'] ) ) {
			echo '<li><strong>' . esc_html__( 'Single point of failure — add a second destination on at least one control.', 'handl-ai-connector-access-control' ) . '</strong></li>';
		}
		echo '</ul>';

		echo '<p>';
		echo '<a class="button" href="' . esc_url( $csv ) . '">' . esc_html__( 'Download CSV', 'handl-ai-connector-access-control' ) . '</a> ';
		echo '<a class="button" href="' . esc_url( $print ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Print / PDF view', 'handl-ai-connector-access-control' ) . '</a>';
		echo '</p>';

		echo '<h2>' . esc_html__( 'Audience', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $snap['humans'] ) ) {
			echo '<p>' . esc_html__( 'No recipients resolved yet.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Email', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Match', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Controls', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Review', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $snap['humans'] as $row ) {
				echo '<tr>';
				echo '<td>' . esc_html( (string) $row['email'] ) . '</td>';
				echo '<td>' . esc_html( (string) $row['match'] ) . '</td>';
				echo '<td><code>' . esc_html( implode( ', ', (array) $row['controls'] ) ) . '</code></td>';
				echo '<td><a href="' . esc_url( (string) $row['url'] ) . '">' . esc_html__( 'Open settings', 'handl-ai-connector-access-control' ) . '</a></td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '<h2>' . esc_html__( 'Dead recipients', 'handl-ai-connector-access-control' ) . '</h2>';
		if ( empty( $snap['dead'] ) ) {
			echo '<p>' . esc_html__( 'No dead recipients detected.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr>';
			echo '<th>' . esc_html__( 'Email', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Reason', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th>' . esc_html__( 'Review', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $snap['dead'] as $row ) {
				echo '<tr>';
				echo '<td>' . esc_html( (string) $row['email'] ) . '</td>';
				echo '<td><code>' . esc_html( (string) $row['reason'] ) . '</code></td>';
				echo '<td><a href="' . esc_url( (string) $row['url'] ) . '">' . esc_html__( 'Open settings', 'handl-ai-connector-access-control' ) . '</a></td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '</div>';
	}

	public static function maybe_handle_csv(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_succession_csv'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_succession_csv' );
		$csv = self::csv_for_snapshot();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/csv; charset=utf-8' );
			header( 'Content-Disposition: attachment; filename=handl-aicac-succession.csv' );
		}
		echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV download.
		exit;
	}

	public static function maybe_handle_print(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['handl_aicac_succession_print'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( (string) $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! Caps::user_can_view() || ! self::is_enabled() ) {
			return;
		}
		check_admin_referer( 'handl_aicac_succession_print' );
		$snap = self::snapshot();
		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=utf-8' );
		}
		echo self::build_print_html( $snap ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside builder.
		exit;
	}

	public static function handle_save(): void {
		if ( ! Caps::user_can_manage() ) {
			wp_die( esc_html__( 'You do not have permission to save succession settings.', 'handl-ai-connector-access-control' ) );
		}
		check_admin_referer( self::ACTION_SAVE );
		if ( empty( $_POST[ self::POST_PRESENT ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			wp_die( esc_html__( 'Security check failed. Go back, reload the page, and try again.', 'handl-ai-connector-access-control' ) );
		}
		self::save_settings(
			array(
				'enabled' => ! empty( $_POST[ self::POST_ENABLED ] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
			)
		);
		$redirect = add_query_arg(
			array(
				'page'    => self::PAGE_SLUG,
				'updated' => '1',
			),
			admin_url( 'admin.php' )
		);
		if ( function_exists( 'wp_safe_redirect' ) ) {
			wp_safe_redirect( $redirect );
			exit;
		}
	}

	public static function register_cli(): void {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return;
		}
		if ( ! class_exists( '\\WP_CLI' ) ) {
			return;
		}
		\WP_CLI::add_command( 'handl-aicac succession', CLI_Succession::class );
	}
}

/**
 * WP-CLI: wp handl-aicac succession status|export
 */
final class CLI_Succession {

	/**
	 * Show succession status. Exits non-zero on SPOF or dead recipient.
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

		if ( ! Succession::is_enabled() ) {
			\WP_CLI::log(
				sprintf(
					'enabled=no framing=%s',
					Succession::FRAMING
				)
			);
			\WP_CLI::log( 'Succession census is disabled.' );

			return;
		}

		$snap = Succession::snapshot();
		$spof = ! empty( $snap['spof'] );
		$dead = (array) $snap['dead'];

		\WP_CLI::log(
			sprintf(
				'enabled=yes distinct_humans=%d spof=%s dead=%d framing=%s',
				(int) $snap['distinct_humans'],
				$spof ? 'yes' : 'no',
				count( $dead ),
				Succession::FRAMING
			)
		);

		$display = array();
		foreach ( (array) $snap['humans'] as $row ) {
			$display[] = array(
				'email'    => (string) $row['email'],
				'match'    => (string) $row['match'],
				'controls' => implode( ',', (array) $row['controls'] ),
			);
		}
		if ( ! empty( $display ) ) {
			if ( 'json' === $format ) {
				\WP_CLI::print_value( $display, array( 'format' => 'json' ) );
			} elseif ( class_exists( '\\WP_CLI\\Utils' ) ) {
				\WP_CLI\Utils\format_items( 'table', $display, array( 'email', 'match', 'controls' ) );
			} else {
				foreach ( $display as $row ) {
					\WP_CLI::log( implode( "\t", $row ) );
				}
			}
		}

		if ( $spof || ! empty( $dead ) ) {
			\WP_CLI::error( 'Succession SPOF and/or dead recipients present.', false );
		}
	}

	/**
	 * Export the succession report as CSV.
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
		$csv = Succession::csv_for_snapshot();
		if ( ! empty( $assoc_args['porcelain'] ) ) {
			echo $csv; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI CSV.
			return;
		}
		\WP_CLI::print_value( $csv, array( 'format' => 'csv' ) );
	}
}
