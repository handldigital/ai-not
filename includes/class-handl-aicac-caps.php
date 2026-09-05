<?php
/**
 * Admin access capabilities: manage vs read-only auditor view (AICAC-AUDITOR-ROLE).
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Capability helpers and role matrix for AI Access Control screens.
 */
final class Caps {

	/** Read-only access to Rules, Activity, Insights, and related surfaces. */
	public const VIEW = 'handl_aicac_view';

	/** Full manage (WordPress administrators already hold this). */
	public const MANAGE = 'manage_options';

	/** Core Site Health screen capability — granted with VIEW for auditors. */
	public const SITE_HEALTH = 'view_site_health_tests';

	/**
	 * POST actions that only stream downloads (no policy mutation).
	 *
	 * @var list<string>
	 */
	public const READ_EXPORT_ACTIONS = array(
		'export_log',
		'export_rules',
		'export_audit_report',
		'export_prune_candidates',
		'pack_export_backup',
		'download_latest_backup',
	);

	/**
	 * Whether the current user may open AI Access Control screens.
	 */
	public static function user_can_view(): bool {
		return self::user_can_manage() || current_user_can( self::VIEW );
	}

	/**
	 * Whether the current user may mutate policy / settings.
	 */
	public static function user_can_manage(): bool {
		return current_user_can( self::MANAGE );
	}

	/**
	 * View without manage — hide mutating controls; deny mutating POSTs.
	 */
	public static function is_read_only(): bool {
		return self::user_can_view() && ! self::user_can_manage();
	}

	/**
	 * True when the action only downloads read data.
	 */
	public static function is_read_export_action( string $action ): bool {
		return in_array( $action, self::READ_EXPORT_ACTIONS, true );
	}

	/**
	 * Ensure every role that can manage_options also has VIEW (admin default unchanged).
	 * Safe to call on activate and on admin_init for upgrades.
	 */
	public static function ensure_registered(): void {
		foreach ( self::editable_role_keys() as $role_key ) {
			$role = self::get_role_object( $role_key );
			if ( null === $role ) {
				continue;
			}
			if ( self::role_has_cap( $role, self::MANAGE ) && ! self::role_has_cap( $role, self::VIEW ) ) {
				self::role_add_cap( $role, self::VIEW );
			}
		}
	}

	/**
	 * Role × view/manage matrix for the settings screen.
	 *
	 * @return list<array{key:string,name:string,view:bool,manage:bool}>
	 */
	public static function role_access_matrix(): array {
		$out = array();
		foreach ( self::editable_role_keys() as $role_key ) {
			$role = self::get_role_object( $role_key );
			if ( null === $role ) {
				continue;
			}
			$out[] = array(
				'key'    => $role_key,
				'name'   => self::role_display_name( $role_key ),
				'view'   => self::role_has_cap( $role, self::VIEW ) || self::role_has_cap( $role, self::MANAGE ),
				'manage' => self::role_has_cap( $role, self::MANAGE ),
			);
		}
		return $out;
	}

	/**
	 * Apply view checkboxes from settings (manage-only caller).
	 * Does not grant or revoke manage_options. Administrator keeps VIEW.
	 *
	 * @param list<string> $view_role_keys Role keys that should hold VIEW.
	 */
	public static function apply_view_roles( array $view_role_keys ): void {
		$wanted = array();
		foreach ( $view_role_keys as $key ) {
			$key = sanitize_key( (string) $key );
			if ( '' !== $key ) {
				$wanted[ $key ] = true;
			}
		}

		foreach ( self::editable_role_keys() as $role_key ) {
			$role = self::get_role_object( $role_key );
			if ( null === $role ) {
				continue;
			}

			$must_view = isset( $wanted[ $role_key ] ) || self::role_has_cap( $role, self::MANAGE );
			$has_view  = self::role_has_cap( $role, self::VIEW );

			if ( $must_view && ! $has_view ) {
				self::role_add_cap( $role, self::VIEW );
				if ( ! self::role_has_cap( $role, self::MANAGE ) ) {
					self::role_add_cap( $role, self::SITE_HEALTH );
				}
			} elseif ( ! $must_view && $has_view && ! self::role_has_cap( $role, self::MANAGE ) ) {
				self::role_remove_cap( $role, self::VIEW );
				self::role_remove_cap( $role, self::SITE_HEALTH );
			}
		}
	}

	/**
	 * @return list<string>
	 */
	private static function editable_role_keys(): array {
		if ( isset( $GLOBALS['handl_aicac_test_roles'] ) && is_array( $GLOBALS['handl_aicac_test_roles'] ) ) {
			return array_map( 'strval', array_keys( $GLOBALS['handl_aicac_test_roles'] ) );
		}
		if ( ! function_exists( 'wp_roles' ) ) {
			return array();
		}
		$roles = wp_roles();
		if ( ! is_object( $roles ) || ! isset( $roles->roles ) || ! is_array( $roles->roles ) ) {
			return array();
		}
		return array_map( 'strval', array_keys( $roles->roles ) );
	}

	/**
	 * @return object|null Role-like object with has_cap / add_cap / remove_cap.
	 */
	private static function get_role_object( string $role_key ) {
		if ( isset( $GLOBALS['handl_aicac_test_roles'][ $role_key ] ) ) {
			return $GLOBALS['handl_aicac_test_roles'][ $role_key ];
		}
		if ( ! function_exists( 'get_role' ) ) {
			return null;
		}
		$role = get_role( $role_key );
		return is_object( $role ) ? $role : null;
	}

	private static function role_display_name( string $role_key ): string {
		if ( isset( $GLOBALS['handl_aicac_test_roles'][ $role_key ]->name ) ) {
			return (string) $GLOBALS['handl_aicac_test_roles'][ $role_key ]->name;
		}
		if ( function_exists( 'wp_roles' ) ) {
			$roles = wp_roles();
			if ( is_object( $roles ) && isset( $roles->role_names[ $role_key ] ) ) {
				return translate_user_role( (string) $roles->role_names[ $role_key ] );
			}
		}
		return $role_key;
	}

	/**
	 * @param object $role Role object.
	 */
	private static function role_has_cap( $role, string $cap ): bool {
		if ( is_object( $role ) && method_exists( $role, 'has_cap' ) ) {
			return (bool) $role->has_cap( $cap );
		}
		if ( is_object( $role ) && isset( $role->capabilities ) && is_array( $role->capabilities ) ) {
			return ! empty( $role->capabilities[ $cap ] );
		}
		return false;
	}

	/**
	 * @param object $role Role object.
	 */
	private static function role_add_cap( $role, string $cap ): void {
		if ( is_object( $role ) && method_exists( $role, 'add_cap' ) ) {
			$role->add_cap( $cap );
			return;
		}
		if ( is_object( $role ) ) {
			if ( ! isset( $role->capabilities ) || ! is_array( $role->capabilities ) ) {
				$role->capabilities = array();
			}
			$role->capabilities[ $cap ] = true;
		}
	}

	/**
	 * @param object $role Role object.
	 */
	private static function role_remove_cap( $role, string $cap ): void {
		if ( is_object( $role ) && method_exists( $role, 'remove_cap' ) ) {
			$role->remove_cap( $cap );
			return;
		}
		if ( is_object( $role ) && isset( $role->capabilities ) && is_array( $role->capabilities ) ) {
			unset( $role->capabilities[ $cap ] );
		}
	}
}
