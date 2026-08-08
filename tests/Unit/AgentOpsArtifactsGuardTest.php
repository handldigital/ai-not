<?php
/**
 * Guard: AgentOps working artifacts must never be tracked in git (#60).
 *
 * @package HandL_AICAC
 */

declare(strict_types=1);

namespace HandL\AICAC\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * Fails CI if handoff md/json (or other AgentOps workspace files) are committed.
 */
final class AgentOpsArtifactsGuardTest extends TestCase {

	/**
	 * Exact paths that must stay local / gitignored.
	 *
	 * @return list<string>
	 */
	private static function forbidden_paths(): array {
		return array(
			'.agentops-meta.json',
			'.agentops-result.json',
			'.agentops-runner-log.json',
			'implementation-plan.md',
			'decisions.md',
			'developer-handoff.md',
			'test-results.md',
			'product-handoff.md',
			'research.md',
			'backlog.yaml',
			'aicac-3-authz-coverage.md',
		);
	}

	/**
	 * AC: never track AgentOps internal md/json (or related working files).
	 */
	public function test_agentops_internal_artifacts_are_not_tracked(): void {
		$repo_root = dirname( __DIR__, 2 );
		$git       = trim( (string) shell_exec( 'command -v git' ) );
		if ( '' === $git ) {
			$this->markTestSkipped( 'git binary not available' );
		}

		$tracked = array();

		foreach ( self::forbidden_paths() as $path ) {
			$cmd    = 'cd ' . escapeshellarg( $repo_root ) . ' && git ls-files --error-unmatch '
				. escapeshellarg( $path ) . ' 2>/dev/null';
			$output = shell_exec( $cmd );
			if ( is_string( $output ) && '' !== trim( $output ) ) {
				$tracked[] = $path;
			}
		}

		$glob_cmd = 'cd ' . escapeshellarg( $repo_root ) . " && git ls-files '.agentops*' 2>/dev/null";
		$glob_out = shell_exec( $glob_cmd );
		if ( is_string( $glob_out ) && '' !== trim( $glob_out ) ) {
			foreach ( preg_split( '/\s+/', trim( $glob_out ) ) ?: array() as $path ) {
				if ( '' !== $path && ! in_array( $path, $tracked, true ) ) {
					$tracked[] = $path;
				}
			}
		}

		$this->assertSame(
			array(),
			$tracked,
			'AgentOps working files must stay local/gitignored. Remove from the commit: '
				. implode( ', ', $tracked )
		);
	}
}
