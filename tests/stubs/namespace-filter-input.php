<?php
/**
 * Test-only override: Admin calls unqualified filter_input() from this namespace.
 *
 * @package HandL_AICAC
 */

namespace HandL\AICAC;

/**
 * @param int              $type     INPUT_* constant.
 * @param string           $var_name Field name.
 * @param int              $filter   Filter id.
 * @param int|array<mixed> $options  Filter options.
 * @return mixed
 */
function filter_input( $type, $var_name, $filter = FILTER_DEFAULT, $options = 0 ) {
	if ( \INPUT_POST === $type
		&& isset( $GLOBALS['handl_aicac_test_post'] )
		&& is_array( $GLOBALS['handl_aicac_test_post'] ) ) {
		$flags = is_array( $options ) ? (int) ( $options['flags'] ?? 0 ) : (int) $options;
		if ( ! array_key_exists( (string) $var_name, $GLOBALS['handl_aicac_test_post'] ) ) {
			return ( $flags & \FILTER_REQUIRE_ARRAY ) ? false : null;
		}
		$value = $GLOBALS['handl_aicac_test_post'][ (string) $var_name ];
		if ( $flags & \FILTER_REQUIRE_ARRAY ) {
			return is_array( $value ) ? $value : false;
		}
		if ( \FILTER_VALIDATE_INT === $filter ) {
			return filter_var( $value, \FILTER_VALIDATE_INT );
		}
		return $value;
	}
	return \filter_input( $type, $var_name, $filter, $options );
}
