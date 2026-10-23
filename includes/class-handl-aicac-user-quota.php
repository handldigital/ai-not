<?php
/**
 * AICAC-USER-QUOTA (#339): per-role / per-user AI call quotas (rolling 24h).
 *
 * Subdivides the site AI allowance — does not extend site-wide rate caps or
 * budgets. Enforcement hooks `wp_ai_client_prevent_prompt` after Policy so
 * Cost, Rate_Cap, and Policy stay untouched this wave.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Fair-share call ceilings per WP role (defaults) with per-user overrides.
 */
final class User_Quota {

	public const REASON = 'user_quota';

	/** Durable hourly buckets: "{user_id}|{YmdH}" => int. */
	public const COUNTS_OPTION_KEY = 'handl_aicac_user_quota_counts';

	/** User meta: positive int override; absent / empty = inherit role. */
	public const USER_META_LIMIT = 'handl_aicac_user_quota_limit';

	/** User meta mirror of rolling usage (for Users-list sort). */
	public const USER_META_USAGE = 'handl_aicac_user_quota_usage';

	public const POLICY_ROLE_LIMITS = 'user_quota_role_limits';

	public const POST_PRESENT = 'handl_aicac_user_quota_present';

	public const POST_ROLE_LIMITS = 'handl_aicac_user_quota_role_limits';

	public const WINDOW_SECONDS = 86400;

	public const MAX_CAP = 1000000;

	public const FILTER_PRIORITY = 2;

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
		delete_option( self::COUNTS_OPTION_KEY );
	}

	public function init(): void {
		add_filter( 'wp_ai_client_prevent_prompt', array( $this, 'maybe_prevent_prompt' ), self::FILTER_PRIORITY, 2 );
		add_action( 'handl_aicac_protections_settings', array( $this, 'render_settings' ) );
		add_filter( 'pre_update_option_' . Plugin::OPTION_KEY, array( self::class, 'merge_on_policy_save' ), 10, 2 );

		add_action( 'show_user_profile', array( $this, 'render_profile_field' ) );
		add_action( 'edit_user_profile', array( $this, 'render_profile_field' ) );
		add_action( 'personal_options_update', array( $this, 'save_profile_field' ) );
		add_action( 'edit_user_profile_update', array( $this, 'save_profile_field' ) );

		add_filter( 'manage_users_columns', array( $this, 'users_column' ) );
		add_filter( 'manage_users_custom_column', array( $this, 'users_column_content' ), 10, 3 );
		add_filter( 'manage_users_sortable_columns', array( $this, 'users_sortable_column' ) );
		add_action( 'pre_get_users', array( $this, 'users_orderby_usage' ) );
	}

	/**
	 * Empty / non-positive → unlimited (omit). Positive int capped.
	 *
	 * @param mixed $raw Raw limit.
	 */
	public static function sanitize_limit( $raw ): ?int {
		if ( null === $raw || false === $raw ) {
			return null;
		}
		if ( is_string( $raw ) ) {
			$raw = trim( $raw );
			if ( '' === $raw ) {
				return null;
			}
		}
		if ( ! is_numeric( $raw ) ) {
			return null;
		}
		$v = (int) $raw;
		if ( $v <= 0 ) {
			return null;
		}
		if ( $v > self::MAX_CAP ) {
			$v = self::MAX_CAP;
		}

		return $v;
	}

	/**
	 * @param mixed $raw role => limit map
	 * @return array<string,int>
	 */
	public static function sanitize_role_limits( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $role => $limit ) {
			$role = sanitize_key( (string) $role );
			if ( '' === $role ) {
				continue;
			}
			$clean = self::sanitize_limit( $limit );
			if ( null === $clean ) {
				continue;
			}
			$out[ $role ] = $clean;
		}
		ksort( $out );

		return $out;
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array<string,int>
	 */
	public static function role_limits( array $policy ): array {
		return self::sanitize_role_limits( $policy[ self::POLICY_ROLE_LIMITS ] ?? array() );
	}

	/**
	 * Per-user override from user meta (null = inherit role).
	 */
	public static function user_override( int $user_id ): ?int {
		if ( $user_id <= 0 ) {
			return null;
		}
		$raw = get_user_meta( $user_id, self::USER_META_LIMIT, true );

		return self::sanitize_limit( $raw );
	}

	/**
	 * Effective rolling-24h limit for a user, or null when unlimited.
	 * Precedence: user override > max among the user's roles that have a quota.
	 *
	 * @param array<string,mixed> $policy
	 * @param list<string>|null   $roles  Injectable roles (tests).
	 */
	public static function effective_limit( array $policy, int $user_id, ?array $roles = null ): ?int {
		$override = self::user_override( $user_id );
		if ( null !== $override ) {
			return $override;
		}

		$role_limits = self::role_limits( $policy );
		if ( empty( $role_limits ) ) {
			return null;
		}

		if ( null === $roles ) {
			$roles = self::roles_for_user( $user_id );
		}
		$max = null;
		foreach ( $roles as $role ) {
			$role = sanitize_key( (string) $role );
			if ( isset( $role_limits[ $role ] ) ) {
				$v = (int) $role_limits[ $role ];
				if ( null === $max || $v > $max ) {
					$max = $v;
				}
			}
		}

		return $max;
	}

	/**
	 * @return list<string>
	 */
	public static function roles_for_user( int $user_id ): array {
		if ( $user_id <= 0 ) {
			return array();
		}
		if ( array_key_exists( 'handl_aicac_test_user_roles', $GLOBALS ) && (int) ( $GLOBALS['handl_aicac_test_user_id'] ?? 0 ) === $user_id ) {
			$raw = $GLOBALS['handl_aicac_test_user_roles'];
			if ( is_array( $raw ) ) {
				return array_values( array_map( 'strval', $raw ) );
			}
		}
		if ( ! function_exists( 'get_userdata' ) ) {
			return array();
		}
		$user = get_userdata( $user_id );
		if ( ! $user || ! isset( $user->roles ) || ! is_array( $user->roles ) ) {
			return array();
		}

		return array_values( array_map( 'strval', $user->roles ) );
	}

	/**
	 * Local hour bucket key in site timezone.
	 */
	public static function hour_key( ?int $now = null, ?\DateTimeZone $tz = null ): string {
		$now = null !== $now ? (int) $now : Clock::now();
		$tz  = Quiet_Hours::timezone( $tz );
		$dt  = ( new \DateTimeImmutable( '@' . $now ) )->setTimezone( $tz );

		return $dt->format( 'YmdH' );
	}

	/**
	 * @return array<string,int>
	 */
	public static function get_counts_map(): array {
		return self::sanitize_counts_map( get_option( self::COUNTS_OPTION_KEY, array() ) );
	}

	/**
	 * @param mixed $raw Raw map.
	 * @return array<string,int>
	 */
	public static function sanitize_counts_map( $raw ): array {
		if ( ! is_array( $raw ) ) {
			return array();
		}
		$out = array();
		foreach ( $raw as $key => $n ) {
			$key = sanitize_text_field( (string) $key );
			if ( '' === $key || ! is_numeric( $n ) ) {
				continue;
			}
			$v = (int) $n;
			if ( $v < 0 ) {
				$v = 0;
			}
			$out[ $key ] = $v;
		}

		return $out;
	}

	/**
	 * @param array<string,int> $map Counts map.
	 */
	public static function save_counts_map( array $map ): void {
		$map = self::sanitize_counts_map( $map );
		$map = self::prune_counts_map( $map );
		if ( empty( $map ) ) {
			delete_option( self::COUNTS_OPTION_KEY );
			return;
		}
		update_option( self::COUNTS_OPTION_KEY, $map, false );
	}

	/**
	 * Drop buckets older than the rolling window when the map grows.
	 *
	 * @param array<string,int> $map Counts map.
	 * @return array<string,int>
	 */
	public static function prune_counts_map( array $map, ?int $now = null, ?\DateTimeZone $tz = null ): array {
		if ( count( $map ) <= 500 ) {
			return $map;
		}
		$now    = null !== $now ? (int) $now : Clock::now();
		$tz     = Quiet_Hours::timezone( $tz );
		$keep   = array();
		$cutoff = $now - self::WINDOW_SECONDS;
		foreach ( $map as $key => $n ) {
			$parts = explode( '|', $key, 2 );
			if ( count( $parts ) < 2 ) {
				continue;
			}
			$suffix = $parts[1];
			if ( ! preg_match( '/^\d{10}$/', $suffix ) ) {
				continue;
			}
			$y  = (int) substr( $suffix, 0, 4 );
			$m  = (int) substr( $suffix, 4, 2 );
			$d  = (int) substr( $suffix, 6, 2 );
			$h  = (int) substr( $suffix, 8, 2 );
			$dt = \DateTimeImmutable::createFromFormat( 'Y-m-d H:i:s', sprintf( '%04d-%02d-%02d %02d:00:00', $y, $m, $d, $h ), $tz );
			if ( ! $dt ) {
				continue;
			}
			if ( $dt->getTimestamp() >= $cutoff ) {
				$keep[ $key ] = $n;
			}
		}

		return $keep;
	}

	public static function count_key( int $user_id, string $hour_key ): string {
		return (string) (int) $user_id . '|' . sanitize_text_field( $hour_key );
	}

	/**
	 * Sum of hourly buckets for this user in the rolling 24h window.
	 */
	public static function rolling_count( int $user_id, ?int $now = null, ?\DateTimeZone $tz = null, ?array $map = null ): int {
		if ( $user_id <= 0 ) {
			return 0;
		}
		$now  = null !== $now ? (int) $now : Clock::now();
		$tz   = Quiet_Hours::timezone( $tz );
		$map  = null !== $map ? self::sanitize_counts_map( $map ) : self::get_counts_map();
		$total = 0;
		$prefix = (string) (int) $user_id . '|';
		$cutoff = $now - self::WINDOW_SECONDS;
		foreach ( $map as $key => $n ) {
			if ( 0 !== strpos( $key, $prefix ) ) {
				continue;
			}
			$suffix = substr( $key, strlen( $prefix ) );
			if ( ! is_string( $suffix ) || ! preg_match( '/^\d{10}$/', $suffix ) ) {
				continue;
			}
			$y  = (int) substr( $suffix, 0, 4 );
			$m  = (int) substr( $suffix, 4, 2 );
			$d  = (int) substr( $suffix, 6, 2 );
			$h  = (int) substr( $suffix, 8, 2 );
			$dt = \DateTimeImmutable::createFromFormat( 'Y-m-d H:i:s', sprintf( '%04d-%02d-%02d %02d:00:00', $y, $m, $d, $h ), $tz );
			if ( ! $dt ) {
				continue;
			}
			if ( $dt->getTimestamp() >= $cutoff ) {
				$total += (int) $n;
			}
		}

		return $total;
	}

	/**
	 * Increment the current hour bucket; mirror usage onto user meta.
	 */
	public static function record_attempt( int $user_id, ?int $now = null, ?\DateTimeZone $tz = null ): int {
		if ( $user_id <= 0 ) {
			return 0;
		}
		$now      = null !== $now ? (int) $now : Clock::now();
		$tz       = Quiet_Hours::timezone( $tz );
		$hour_key = self::hour_key( $now, $tz );
		$map      = self::get_counts_map();
		$key      = self::count_key( $user_id, $hour_key );
		$map[ $key ] = isset( $map[ $key ] ) ? ( (int) $map[ $key ] + 1 ) : 1;
		self::save_counts_map( $map );
		$count = self::rolling_count( $user_id, $now, $tz, $map );
		update_user_meta( $user_id, self::USER_META_USAGE, $count );

		return $count;
	}

	/**
	 * Test helper: set a bucket count directly.
	 */
	public static function set_window_count( int $user_id, string $hour_key, int $count ): void {
		$map = self::get_counts_map();
		$key = self::count_key( $user_id, $hour_key );
		if ( $count <= 0 ) {
			unset( $map[ $key ] );
		} else {
			$map[ $key ] = $count;
		}
		self::save_counts_map( $map );
		update_user_meta( $user_id, self::USER_META_USAGE, self::rolling_count( $user_id ) );
	}

	/**
	 * @param array<string,mixed> $policy
	 * @return array{prevent:bool,reason:string,limit:?int,count:int,source:string}
	 */
	public static function evaluate( array $policy, int $user_id, ?array $roles = null, ?int $now = null, ?\DateTimeZone $tz = null ): array {
		$out = array(
			'prevent' => false,
			'reason'  => '',
			'limit'   => null,
			'count'   => 0,
			'source'  => '',
		);
		if ( $user_id <= 0 ) {
			return $out;
		}

		$override = self::user_override( $user_id );
		$limit    = self::effective_limit( $policy, $user_id, $roles );
		$out['limit']  = $limit;
		$out['source'] = null !== $override ? 'user' : ( null !== $limit ? 'role' : '' );
		if ( null === $limit ) {
			return $out;
		}

		$now           = null !== $now ? (int) $now : Clock::now();
		$count         = self::rolling_count( $user_id, $now, $tz );
		$out['count']  = $count;
		if ( $count >= $limit ) {
			$out['prevent'] = true;
			$out['reason']  = self::REASON;
		}

		return $out;
	}

	/**
	 * Tag an Activity event; report whether to block.
	 *
	 * @param array<string,mixed>      $event  Mutated.
	 * @param array<string,mixed>|null $policy Policy.
	 * @return array{active:bool,prevent:bool,reason:string,soft:bool}
	 */
	public static function apply_to_event( array &$event, $policy = null, ?int $now = null ): array {
		$policy = is_array( $policy ) ? $policy : Policy::get_policy();
		$now    = null !== $now ? (int) $now : ( isset( $event['ts'] ) ? (int) $event['ts'] : Clock::now() );
		$user_id = isset( $event['user_id'] ) ? (int) $event['user_id'] : Policy::current_user_id_for_gate();

		$eval = self::evaluate( $policy, $user_id, null, $now );
		$event['user_quota_limit']  = $eval['limit'];
		$event['user_quota_count']  = $eval['count'];
		$event['user_quota_source'] = $eval['source'];

		if ( empty( $eval['prevent'] ) ) {
			if ( null !== $eval['limit'] && $user_id > 0 ) {
				$after                       = self::record_attempt( $user_id, $now );
				$event['user_quota_count']   = $after;
			}

			return array(
				'active'  => null !== $eval['limit'],
				'prevent' => false,
				'reason'  => '',
				'soft'    => false,
			);
		}

		$event['denial_reason']   = self::REASON;
		$event['decision_source'] = self::REASON;
		$event['user_quota']      = true;

		return array(
			'active'  => true,
			'prevent' => true,
			'reason'  => self::REASON,
			'soft'    => false,
		);
	}

	/**
	 * Gate filter after Policy (priority 2). Site-wide rate cap already ran.
	 *
	 * @param mixed $prevent Prior filter result.
	 * @param mixed $builder Prompt builder.
	 */
	public function maybe_prevent_prompt( $prevent, $builder ): bool {
		if ( $prevent ) {
			return true;
		}

		$policy = Policy::get_policy();
		if ( ! empty( $policy['audit_only'] ) ) {
			return false;
		}
		if ( class_exists( Break_Glass::class, false ) && Break_Glass::is_active() ) {
			return false;
		}

		$user_id = Policy::current_user_id_for_gate();
		if ( $user_id <= 0 ) {
			return false;
		}

		$now  = Clock::now();
		$eval = self::evaluate( $policy, $user_id, null, $now );
		if ( null === $eval['limit'] ) {
			return false;
		}

		if ( empty( $eval['prevent'] ) ) {
			self::record_attempt( $user_id, $now );

			return false;
		}

		$attrib    = Attribution::resolve_from_backtrace();
		$plugin    = is_string( $attrib['plugin'] ?? null ) ? (string) $attrib['plugin'] : null;
		$snapshot  = class_exists( Prompt_Snapshot::class, false ) ? Prompt_Snapshot::from_builder( $builder ) : array();
		$operation = isset( $snapshot['operation'] ) ? (string) $snapshot['operation'] : '';
		$family    = isset( $snapshot['capability_family'] ) && is_string( $snapshot['capability_family'] )
			? (string) $snapshot['capability_family']
			: ( class_exists( Operations::class, false ) ? Operations::family_from_operation( $operation ) : '' );

		$event = array_merge(
			array(
				'ts'                => $now,
				'plugin'            => $plugin,
				'file'              => $attrib['file'] ?? null,
				'caller'            => $attrib['method'] ?? null,
				'decision'          => 'deny',
				'would_decision'    => 'deny',
				'capability_family' => $family,
				'denial_reason'     => self::REASON,
				'decision_source'   => self::REASON,
				'user_id'           => $user_id,
				'user_role'         => Policy::current_user_role_for_log(),
				'user_quota'        => true,
				'user_quota_limit'  => $eval['limit'],
				'user_quota_count'  => $eval['count'],
				'user_quota_source' => $eval['source'],
				'uri'               => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) ) : null,
			),
			is_array( $snapshot ) ? $snapshot : array()
		);

		self::reclassify_latest_allow( $event );

		$soft = false;
		if ( class_exists( Soft_Deny::class, false ) ) {
			$soft = Soft_Deny::maybe_arm_from_deny(
				true,
				$event,
				$policy,
				is_string( $plugin ) ? $plugin : null,
				$operation,
				$family
			);
		}

		Policy::append_log_event( $event );

		$suppress = class_exists( Retry_Storm::class, false ) && Retry_Storm::should_suppress_deny_alert( $event, $policy );
		if ( class_exists( Alerts::class, false ) && ! $suppress ) {
			Alerts::maybe_notify_denial( $event, $policy );
		}
		if ( class_exists( Access_Request::class, false ) ) {
			Access_Request::note_deny( $event );
		}

		return $soft ? false : true;
	}

	/**
	 * When Policy already logged an allow for this call, flip it to our deny
	 * so Activity shows one row with reason user_quota.
	 *
	 * @param array<string,mixed> $event Deny event (merged into the row).
	 */
	public static function reclassify_latest_allow( array $event ): void {
		$policy = Policy::get_policy();
		if ( empty( $policy['log_enabled'] ) && empty( $policy['audit_only'] ) ) {
			return;
		}
		$log = get_option( Plugin::LOG_OPTION_KEY );
		if ( ! is_array( $log ) || empty( $log ) ) {
			return;
		}
		$i    = count( $log ) - 1;
		$last = $log[ $i ];
		if ( ! is_array( $last ) ) {
			return;
		}
		if ( 'allow' !== (string) ( $last['decision'] ?? '' ) ) {
			return;
		}
		if ( (int) ( $last['user_id'] ?? 0 ) !== (int) ( $event['user_id'] ?? 0 ) ) {
			return;
		}
		$last_ts  = (int) ( $last['ts'] ?? 0 );
		$event_ts = (int) ( $event['ts'] ?? 0 );
		if ( $last_ts > 0 && $event_ts > 0 && abs( $last_ts - $event_ts ) > 5 ) {
			return;
		}

		// Drop the allow; caller appends the deny so SIEM/Why/alerts see one row.
		unset( $last, $event );
		array_pop( $log );
		update_option( Plugin::LOG_OPTION_KEY, $log, false );
	}

	/**
	 * @param mixed $value New option value.
	 * @param mixed $old   Previous option value.
	 * @return mixed
	 */
	public static function merge_on_policy_save( $value, $old ) {
		if ( ! is_array( $value ) ) {
			return $value;
		}

		$posted = isset( $_POST[ self::POST_PRESENT ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Admin save already verified the form nonce.
		if ( $posted ) {
			$raw = isset( $_POST[ self::POST_ROLE_LIMITS ] ) ? wp_unslash( $_POST[ self::POST_ROLE_LIMITS ] ) : array(); // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			$value[ self::POLICY_ROLE_LIMITS ] = self::sanitize_role_limits( is_array( $raw ) ? $raw : array() );

			return $value;
		}

		if ( is_array( $old ) && array_key_exists( self::POLICY_ROLE_LIMITS, $old ) ) {
			$value[ self::POLICY_ROLE_LIMITS ] = self::sanitize_role_limits( $old[ self::POLICY_ROLE_LIMITS ] );
		}

		return $value;
	}

	/**
	 * Protections settings: per-role rolling-24h call limits.
	 *
	 * @param array<string,mixed> $policy Policy.
	 */
	public function render_settings( $policy ): void {
		$policy = is_array( $policy ) ? $policy : array();
		$limits = self::role_limits( $policy );
		$roles  = Policy::available_roles_for_gate();

		echo '<tr id="handl-aicac-user-quota">';
		echo '<th scope="row">' . esc_html__( 'Per-user AI call quotas', 'handl-ai-connector-access-control' ) . '</th>';
		echo '<td>';
		echo '<input type="hidden" name="' . esc_attr( self::POST_PRESENT ) . '" value="1" />';
		echo '<p class="description">' . esc_html__( 'Optional rolling 24-hour call limits per WordPress role. Leave blank for unlimited. Per-user overrides are on each user profile. Quotas subdivide the site allowance — they do not raise site-wide rate caps or budgets. Cron and WP-CLI (no signed-in user) are not limited.', 'handl-ai-connector-access-control' ) . '</p>';

		if ( empty( $roles ) ) {
			echo '<p class="description">' . esc_html__( 'No WordPress roles are available on this site.', 'handl-ai-connector-access-control' ) . '</p>';
		} else {
			echo '<table class="widefat striped" style="max-width:36em;margin-top:8px;"><thead><tr>';
			echo '<th scope="col">' . esc_html__( 'Role', 'handl-ai-connector-access-control' ) . '</th>';
			echo '<th scope="col">' . esc_html__( 'Calls / 24h', 'handl-ai-connector-access-control' ) . '</th>';
			echo '</tr></thead><tbody>';
			foreach ( $roles as $slug => $label ) {
				$slug  = (string) $slug;
				$value = isset( $limits[ $slug ] ) ? (string) (int) $limits[ $slug ] : '';
				$id    = 'handl-aicac-user-quota-' . sanitize_html_class( $slug );
				echo '<tr>';
				echo '<td><label for="' . esc_attr( $id ) . '">' . esc_html( (string) $label ) . ' <code style="font-size:11px;">' . esc_html( $slug ) . '</code></label></td>';
				echo '<td><input type="number" min="0" max="' . esc_attr( (string) self::MAX_CAP ) . '" class="small-text" id="' . esc_attr( $id ) . '" name="' . esc_attr( self::POST_ROLE_LIMITS ) . '[' . esc_attr( $slug ) . ']" value="' . esc_attr( $value ) . '" placeholder="' . esc_attr__( 'unlimited', 'handl-ai-connector-access-control' ) . '" /></td>';
				echo '</tr>';
			}
			echo '</tbody></table>';
		}

		echo '</td>';
		echo '</tr>';
	}

	/**
	 * @param \WP_User $user User being edited.
	 */
	public function render_profile_field( $user ): void {
		if ( ! $user || ! isset( $user->ID ) ) {
			return;
		}
		if ( ! current_user_can( Caps::MANAGE ) ) {
			return;
		}
		$user_id  = (int) $user->ID;
		$policy   = Policy::get_policy();
		$override = self::user_override( $user_id );
		$role_lim = self::effective_limit( $policy, $user_id );
		$usage    = self::rolling_count( $user_id );
		$value    = null !== $override ? (string) $override : '';

		echo '<h2>' . esc_html__( 'AI call quota', 'handl-ai-connector-access-control' ) . '</h2>';
		echo '<table class="form-table" role="presentation"><tr>';
		echo '<th><label for="handl-aicac-user-quota-limit">' . esc_html__( 'Calls / 24h override', 'handl-ai-connector-access-control' ) . '</label></th>';
		echo '<td>';
		echo '<input type="number" min="0" max="' . esc_attr( (string) self::MAX_CAP ) . '" class="small-text" name="handl_aicac_user_quota_limit" id="handl-aicac-user-quota-limit" value="' . esc_attr( $value ) . '" />';
		echo '<p class="description">';
		if ( null !== $role_lim && null === $override ) {
			echo esc_html(
				sprintf(
					/* translators: 1: usage count, 2: role quota */
					__( 'Leave blank to use the role default. Current usage: %1$s / %2$s (role default).', 'handl-ai-connector-access-control' ),
					(string) $usage,
					(string) $role_lim
				)
			);
		} elseif ( null !== $override ) {
			echo esc_html(
				sprintf(
					/* translators: 1: usage count, 2: override quota */
					__( 'Current usage: %1$s / %2$s (user override). Empty clears the override.', 'handl-ai-connector-access-control' ),
					(string) $usage,
					(string) $override
				)
			);
		} else {
			echo esc_html__( 'Leave blank for unlimited (no role quota applies to this user).', 'handl-ai-connector-access-control' );
		}
		echo '</p></td></tr></table>';
	}

	/**
	 * @param int $user_id User ID.
	 */
	public function save_profile_field( $user_id ): void {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 || ! current_user_can( Caps::MANAGE ) ) {
			return;
		}
		if ( ! isset( $_POST['handl_aicac_user_quota_limit'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Profile save verifies nonce upstream.
			return;
		}
		$raw   = wp_unslash( $_POST['handl_aicac_user_quota_limit'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$limit = self::sanitize_limit( $raw );
		if ( null === $limit ) {
			delete_user_meta( $user_id, self::USER_META_LIMIT );
			return;
		}
		update_user_meta( $user_id, self::USER_META_LIMIT, $limit );
	}

	/**
	 * @param array<string,string> $columns Users columns.
	 * @return array<string,string>
	 */
	public function users_column( $columns ) {
		if ( ! is_array( $columns ) ) {
			$columns = array();
		}
		if ( ! current_user_can( Caps::MANAGE ) && ! Caps::user_can_view() ) {
			return $columns;
		}
		$policy = Policy::get_policy();
		if ( empty( self::role_limits( $policy ) ) ) {
			// Still show when any user overrides exist — cheap check omitted; column stays hidden until role quotas are set.
			return $columns;
		}
		$columns['handl_aicac_quota'] = __( 'AI quota (24h)', 'handl-ai-connector-access-control' );

		return $columns;
	}

	/**
	 * @param string $output      Column HTML.
	 * @param string $column_name Column key.
	 * @param int    $user_id     User ID.
	 */
	public function users_column_content( $output, $column_name, $user_id ) {
		if ( 'handl_aicac_quota' !== $column_name ) {
			return $output;
		}
		$user_id = (int) $user_id;
		$policy  = Policy::get_policy();
		$limit   = self::effective_limit( $policy, $user_id );
		if ( null === $limit ) {
			return '—';
		}
		$usage = self::rolling_count( $user_id );

		return esc_html( (string) $usage . ' / ' . (string) $limit );
	}

	/**
	 * @param array<string,string> $columns Sortable columns.
	 * @return array<string,string>
	 */
	public function users_sortable_column( $columns ) {
		if ( ! is_array( $columns ) ) {
			$columns = array();
		}
		$columns['handl_aicac_quota'] = 'handl_aicac_quota_usage';

		return $columns;
	}

	/**
	 * @param \WP_User_Query $query User query.
	 */
	public function users_orderby_usage( $query ): void {
		if ( ! $query instanceof \WP_User_Query ) {
			return;
		}
		$orderby = $query->get( 'orderby' );
		if ( 'handl_aicac_quota_usage' !== $orderby ) {
			return;
		}
		$query->set( 'meta_key', self::USER_META_USAGE );
		$query->set( 'orderby', 'meta_value_num' );
	}
}
