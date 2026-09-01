<?php
/**
 * Wall-clock helper — production uses real time(); PHPUnit may override via bootstrap.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Clock {

	public static function now(): int {
		if ( function_exists( 'handl_aicac_now' ) ) {
			return handl_aicac_now();
		}

		return time();
	}
}
