# Decisions — AICAC-2

## D-1 — 2026-08-07 — Block AICAC-2; do not implement without AICAC-1

**Decision:** Stop implementation and return the work item to Product. Do not add a CI workflow, `.gitignore`, or release documentation under this job while AICAC-1 is absent.

**Why:**

- Backlog precondition: “AICAC-1 test suite exists and is runnable via a single command.”
- AC3 requires running that PHPUnit suite in CI and failing on test failure.
- Repo inspection on `main` @ `3c36f1f` found no Composer/PHPUnit harness, test directory, or test references.
- Operating rules forbid expanding into unapproved product scope (AICAC-1) and forbid guessing when requirements/preconditions conflict.

**Impact:** Issue #20 remains open pending AICAC-1 delivery (or an explicit Product decision to combine/resequence). No code changes were made for AICAC-2 in this job.

## D-2 — 2026-08-07 — Branch protection remains human-owned

**Decision:** When AICAC-2 is unblocked, document required CI status checks in `decisions.md` / workflow comments only; do not attempt to configure GitHub branch protection from this credential-free AgentOps workspace.

**Why:** Developer agents here cannot use GitHub credentials or push remotes; branch protection is a repo-admin action outside the codebase.

**Impact:** Edge case from backlog remains: a tag can still be pushed on a commit that never passed CI until a human enables required checks / protection on `main`.
