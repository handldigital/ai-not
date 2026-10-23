<?php
/**
 * AICAC-SAVE-CONFLICT (#217): revision token so concurrent rule edits detect-and-refuse.
 *
 * Last-write-wins becomes refuse-with-notice. Revision meta lives outside the
 * policy option so no-op settings writes stay byte-identical.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Issue/verify opaque save tokens; stamp revision on real policy writes.
 */
final class Save_Guard {

	public const META_OPTION = 'handl_aicac_policy_rev';

	public const FIELD = 'handl_aicac_save_token';

	/** @var bool */
	private static $registered = false;

	/**
	 * Conflict payload for the current request (admin notice).
	 *
	 * @var null|array{
	 *   who:string,
	 *   when:int,
	 *   changes:list<string>,
	 *   from_rev:int,
	 *   to_rev:int
	 * }
	 */
	private static $conflict = null;

	public static function init(): void {
		if ( self::$registered ) {
			return;
		}
		self::$registered = true;

		self::ensure_meta();
		add_action( 'updated_option', array( self::class, 'on_updated_option' ), 20, 3 );
		add_action( 'add_option', array( self::class, 'on_add_option' ), 20, 2 );
	}

	public static function reset_for_tests(): void {
		self::$registered = false;
		self::$conflict   = null;
		delete_option( self::META_OPTION );
	}

	/**
	 * @return array{
	 *   rev:int,
	 *   token:string,
	 *   saved_at:int,
	 *   actor:array{type:string,user_id:int,login:string},
	 *   changes:list<string>,
	 *   from_rev:int,
	 *   to_rev:int
	 * }
	 */
	public static function get_meta(): array {
		return self::sanitize_meta( get_option( self::META_OPTION, null ) );
	}

	/**
	 * Opaque token for the form the page was rendered from. Never show the raw rev.
	 */
	public static function current_token(): string {
		$meta = self::ensure_meta();
		return (string) $meta['token'];
	}

	/**
	 * Emit the hidden revision-token field (Rules / settings save forms).
	 */
	public static function render_token_field(): void {
		$token = self::current_token();
		echo '<input type="hidden" name="' . esc_attr( self::FIELD ) . '" id="handl-aicac-save-token" value="' . esc_attr( $token ) . '" />';
	}

	/**
	 * Early save-handler check. True when the posted token matches live state.
	 */
	public static function check_posted_token(): bool {
		$posted = '';
		if ( isset( $_POST[ self::FIELD ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- caller verified nonce.
			$posted = sanitize_text_field( wp_unslash( (string) $_POST[ self::FIELD ] ) );
		}

		return self::accept_token( $posted );
	}

	/**
	 * @param string $posted Opaque token from the form / CLI --base-token.
	 * @param bool   $force  When true, skip the mismatch refuse (CLI --force).
	 */
	public static function accept_token( string $posted, bool $force = false ): bool {
		self::$conflict = null;
		$meta           = self::ensure_meta();

		if ( $force ) {
			return true;
		}

		if ( hash_equals( (string) $meta['token'], $posted ) ) {
			return true;
		}

		self::$conflict = array(
			'who'      => Policy_Snapshots::actor_display( $meta['actor'] ),
			'when'     => (int) $meta['saved_at'],
			'changes'  => array_values( array_map( 'strval', $meta['changes'] ) ),
			'from_rev' => (int) $meta['from_rev'],
			'to_rev'   => (int) $meta['to_rev'],
		);

		return false;
	}

	/**
	 * CLI / import helper: refuse a stale base unless forced.
	 *
	 * @return array{ok:bool,error?:string,conflict?:array<string,mixed>}
	 */
	public static function assert_base_token( string $base_token, bool $force = false ): array {
		if ( self::accept_token( $base_token, $force ) ) {
			return array( 'ok' => true );
		}

		$conflict = self::conflict();
		$who      = is_array( $conflict ) ? (string) $conflict['who'] : '';
		$when     = is_array( $conflict ) ? (int) $conflict['when'] : 0;
		$when_h   = $when > 0 ? gmdate( 'Y-m-d H:i:s', $when ) . ' UTC' : '';

		$msg = 'Policy not applied: someone else saved after this base was taken.';
		if ( '' !== $who && '' !== $when_h ) {
			$msg = sprintf(
				'Policy not applied: %1$s saved at %2$s after this base was taken. Re-export, review, and retry — or pass --force.',
				$who,
				$when_h
			);
		} elseif ( '' !== $who ) {
			$msg = sprintf(
				'Policy not applied: %s saved after this base was taken. Re-export, review, and retry — or pass --force.',
				$who
			);
		}

		return array(
			'ok'       => false,
			'error'    => $msg,
			'conflict' => is_array( $conflict ) ? $conflict : array(),
		);
	}

	/**
	 * @return null|array{
	 *   who:string,
	 *   when:int,
	 *   changes:list<string>,
	 *   from_rev:int,
	 *   to_rev:int
	 * }
	 */
	public static function conflict(): ?array {
		return self::$conflict;
	}

	/**
	 * Admin notice when a Rules save was refused for a stale token.
	 */
	public static function maybe_render_conflict_notice(): void {
		$conflict = self::$conflict;
		if ( ! is_array( $conflict ) ) {
			return;
		}

		$who  = (string) ( $conflict['who'] ?? '' );
		$when = (int) ( $conflict['when'] ?? 0 );
		$when_h = '';
		if ( $when > 0 ) {
			if ( function_exists( 'wp_date' ) ) {
				$when_h = (string) wp_date( 'Y-m-d H:i', $when );
			} else {
				$when_h = gmdate( 'Y-m-d H:i', $when ) . ' UTC';
			}
		}

		echo '<div class="notice notice-error is-dismissible"><p>';
		if ( '' !== $who && '' !== $when_h ) {
			echo esc_html(
				sprintf(
					/* translators: 1: user display name, 2: local date/time */
					__( 'Rules were not saved because %1$s saved first (%2$s). Review their changes below, then save again.', 'handl-ai-connector-access-control' ),
					$who,
					$when_h
				)
			);
		} elseif ( '' !== $who ) {
			echo esc_html(
				sprintf(
					/* translators: %s: user display name */
					__( 'Rules were not saved because %s saved first. Review their changes below, then save again.', 'handl-ai-connector-access-control' ),
					$who
				)
			);
		} else {
			echo esc_html__( 'Rules were not saved because someone else saved first. Review the current rules below, then save again.', 'handl-ai-connector-access-control' );
		}
		echo '</p>';

		$changes = isset( $conflict['changes'] ) && is_array( $conflict['changes'] ) ? $conflict['changes'] : array();
		if ( ! empty( $changes ) ) {
			echo '<ul style="list-style:disc;margin-left:1.5em;">';
			$shown = 0;
			foreach ( $changes as $line ) {
				$line = (string) $line;
				if ( '' === $line ) {
					continue;
				}
				echo '<li>' . esc_html( $line ) . '</li>';
				++$shown;
				if ( $shown >= 8 ) {
					$more = count( $changes ) - $shown;
					if ( $more > 0 ) {
						echo '<li>' . esc_html(
							sprintf(
								/* translators: %d: number of additional change lines */
								_n( '+%d more change', '+%d more changes', $more, 'handl-ai-connector-access-control' ),
								$more
							)
						) . '</li>';
					}
					break;
				}
			}
			echo '</ul>';
		}
		echo '</div>';
	}

	/**
	 * @param string $option
	 * @param mixed  $old_value
	 * @param mixed  $value
	 */
	public static function on_updated_option( $option, $old_value, $value ): void {
		if ( Plugin::OPTION_KEY !== (string) $option ) {
			return;
		}
		if ( ! is_array( $value ) ) {
			return;
		}
		$before = is_array( $old_value ) ? $old_value : array();
		self::bump_from_write( $before, $value );
	}

	/**
	 * @param string $option
	 * @param mixed  $value
	 */
	public static function on_add_option( $option, $value ): void {
		if ( Plugin::OPTION_KEY !== (string) $option ) {
			return;
		}
		if ( ! is_array( $value ) ) {
			return;
		}
		self::bump_from_write( array(), $value );
	}

	/**
	 * @param array<string,mixed> $before
	 * @param array<string,mixed> $after
	 */
	public static function bump_from_write( array $before, array $after ): void {
		$changes = Policy_Snapshots::change_lines( $before, $after );
		// updated_option only fires when WP sees a value change; still skip empty diffs.
		if ( empty( $changes ) ) {
			// Structural / non-diff-key write still needs a new token so concurrent
			// editors cannot overwrite silently after any persisted mutation.
			$changes = array(
				__( 'Policy updated.', 'handl-ai-connector-access-control' ),
			);
		}

		$prev = self::ensure_meta();
		$from = (int) $prev['rev'];
		$to   = $from + 1;
		$now  = class_exists( Clock::class, false ) ? Clock::now() : time();

		$meta = array(
			'rev'      => $to,
			'token'    => self::mint_token( $to ),
			'saved_at' => (int) $now,
			'actor'    => Policy_Snapshots::detect_actor(),
			'changes'  => array_values( array_slice( $changes, 0, 40 ) ),
			'from_rev' => $from,
			'to_rev'   => $to,
		);

		update_option( self::META_OPTION, $meta, false );
	}

	/**
	 * @return array{
	 *   rev:int,
	 *   token:string,
	 *   saved_at:int,
	 *   actor:array{type:string,user_id:int,login:string},
	 *   changes:list<string>,
	 *   from_rev:int,
	 *   to_rev:int
	 * }
	 */
	public static function ensure_meta(): array {
		$raw = get_option( self::META_OPTION, null );
		if ( is_array( $raw ) && isset( $raw['token'] ) && is_string( $raw['token'] ) && '' !== $raw['token'] ) {
			return self::sanitize_meta( $raw );
		}

		$meta = array(
			'rev'      => 1,
			'token'    => self::mint_token( 1 ),
			'saved_at' => 0,
			'actor'    => array(
				'type'    => 'system',
				'user_id' => 0,
				'login'   => '',
			),
			'changes'  => array(),
			'from_rev' => 0,
			'to_rev'   => 1,
		);
		update_option( self::META_OPTION, $meta, false );

		return $meta;
	}

	/**
	 * @param mixed $raw
	 * @return array{
	 *   rev:int,
	 *   token:string,
	 *   saved_at:int,
	 *   actor:array{type:string,user_id:int,login:string},
	 *   changes:list<string>,
	 *   from_rev:int,
	 *   to_rev:int
	 * }
	 */
	public static function sanitize_meta( $raw ): array {
		if ( ! is_array( $raw ) ) {
			$raw = array();
		}

		$rev = isset( $raw['rev'] ) ? max( 1, (int) $raw['rev'] ) : 1;
		$token = isset( $raw['token'] ) ? sanitize_text_field( (string) $raw['token'] ) : '';
		if ( '' === $token ) {
			$token = self::mint_token( $rev );
		}

		$actor = isset( $raw['actor'] ) && is_array( $raw['actor'] ) ? $raw['actor'] : array();
		$changes = array();
		if ( isset( $raw['changes'] ) && is_array( $raw['changes'] ) ) {
			foreach ( $raw['changes'] as $line ) {
				$line = sanitize_text_field( (string) $line );
				if ( '' !== $line ) {
					$changes[] = $line;
				}
				if ( count( $changes ) >= 40 ) {
					break;
				}
			}
		}

		return array(
			'rev'      => $rev,
			'token'    => $token,
			'saved_at' => isset( $raw['saved_at'] ) ? max( 0, (int) $raw['saved_at'] ) : 0,
			'actor'    => array(
				'type'    => isset( $actor['type'] ) ? sanitize_key( (string) $actor['type'] ) : 'system',
				'user_id' => isset( $actor['user_id'] ) ? max( 0, (int) $actor['user_id'] ) : 0,
				'login'   => isset( $actor['login'] ) ? sanitize_text_field( (string) $actor['login'] ) : '',
			),
			'changes'  => $changes,
			'from_rev' => isset( $raw['from_rev'] ) ? max( 0, (int) $raw['from_rev'] ) : 0,
			'to_rev'   => isset( $raw['to_rev'] ) ? max( 0, (int) $raw['to_rev'] ) : $rev,
		);
	}

	private static function mint_token( int $rev ): string {
		$rev = max( 1, $rev );
		$seed = 'handl-aicac-save-guard|' . $rev . '|' . wp_generate_password( 12, false, false );
		if ( function_exists( 'wp_hash' ) ) {
			return substr( (string) wp_hash( $seed ), 0, 32 );
		}

		return substr( hash( 'sha256', $seed ), 0, 32 );
	}
}
