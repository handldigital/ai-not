<?php
/**
 * AICAC-NEIGHBORS (#492) bundled anonymized peer distribution.
 *
 * Versioned local table. Phase 1 never fetches. Refresh later can replace
 * this file or overlay a rates-feed-style payload with the same format.
 *
 * @package HandL_AICAC
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

return array(
	'version' => 1,
	'format'  => 'handl_aicac_neighbors_v1',
	'as_of'   => '2026-11-04',
	'site_size_buckets' => array(
		'xs' => array( 'max_posts' => 19 ),
		's'  => array( 'max_posts' => 199 ),
		'm'  => array( 'max_posts' => 1999 ),
		'l'  => array( 'max_posts' => 19999 ),
		'xl' => array( 'max_posts' => null ),
	),
	'weekly_call_bands' => array(
		'quiet'  => array( 'max' => 9 ),
		'light'  => array( 'max' => 49 ),
		'steady' => array( 'max' => 199 ),
		'busy'   => array( 'max' => 999 ),
		'heavy'  => array( 'max' => null ),
	),
	'deny_rate_bands' => array(
		'rare'     => array( 'max' => 0.01 ),
		'typical'  => array( 'max' => 0.05 ),
		'elevated' => array( 'max' => 0.10 ),
		'high'     => array( 'max' => 0.25 ),
		'severe'   => array( 'max' => null ),
	),
	'spend_bands' => array(
		'low'   => array( 'max' => 10.0 ),
		'mid'   => array( 'max' => 50.0 ),
		'high'  => array( 'max' => 200.0 ),
		'heavy' => array( 'max' => null ),
	),
	'distributions' => array(
		'xs' => array(
			'weekly_calls' => array(
				'p10' => 2.0,
				'p25' => 4.0,
				'p50' => 8.0,
				'p75' => 16.0,
				'p90' => 28.0,
			),
			'deny_rate'    => array(
				'p10' => 0.01,
				'p25' => 0.02,
				'p50' => 0.04,
				'p75' => 0.06,
				'p90' => 0.10,
			),
			'spend_usd'    => array(
				'p10' => 1.0,
				'p25' => 2.0,
				'p50' => 5.0,
				'p75' => 10.0,
				'p90' => 18.0,
			),
		),
		's'  => array(
			'weekly_calls' => array(
				'p10' => 6.0,
				'p25' => 12.0,
				'p50' => 22.0,
				'p75' => 30.0,
				'p90' => 55.0,
			),
			'deny_rate'    => array(
				'p10' => 0.01,
				'p25' => 0.02,
				'p50' => 0.035,
				'p75' => 0.05,
				'p90' => 0.08,
			),
			'spend_usd'    => array(
				'p10' => 2.0,
				'p25' => 3.0,
				'p50' => 8.0,
				'p75' => 18.0,
				'p90' => 36.0,
			),
		),
		'm'  => array(
			'weekly_calls' => array(
				'p10' => 20.0,
				'p25' => 40.0,
				'p50' => 80.0,
				'p75' => 140.0,
				'p90' => 240.0,
			),
			'deny_rate'    => array(
				'p10' => 0.015,
				'p25' => 0.03,
				'p50' => 0.05,
				'p75' => 0.08,
				'p90' => 0.12,
			),
			'spend_usd'    => array(
				'p10' => 8.0,
				'p25' => 15.0,
				'p50' => 35.0,
				'p75' => 70.0,
				'p90' => 140.0,
			),
		),
		'l'  => array(
			'weekly_calls' => array(
				'p10' => 80.0,
				'p25' => 160.0,
				'p50' => 320.0,
				'p75' => 600.0,
				'p90' => 1100.0,
			),
			'deny_rate'    => array(
				'p10' => 0.02,
				'p25' => 0.04,
				'p50' => 0.06,
				'p75' => 0.10,
				'p90' => 0.16,
			),
			'spend_usd'    => array(
				'p10' => 25.0,
				'p25' => 50.0,
				'p50' => 120.0,
				'p75' => 250.0,
				'p90' => 480.0,
			),
		),
		'xl' => array(
			'weekly_calls' => array(
				'p10' => 200.0,
				'p25' => 400.0,
				'p50' => 800.0,
				'p75' => 1500.0,
				'p90' => 2800.0,
			),
			'deny_rate'    => array(
				'p10' => 0.02,
				'p25' => 0.045,
				'p50' => 0.07,
				'p75' => 0.11,
				'p90' => 0.18,
			),
			'spend_usd'    => array(
				'p10' => 80.0,
				'p25' => 160.0,
				'p50' => 350.0,
				'p75' => 700.0,
				'p90' => 1400.0,
			),
		),
	),
);
