# Adversarial Security Review — vps-control-mcp

**Review performed:** 2026-04-16 (Claude Opus deep audit + Sonnet follow-up fixes)
**Status at submission:** All findings closed. Shipped as v1.3.0 (`3d33cf3`) with two follow-up fixes (`f751409`, `862c732`).
**Test suite:** `src/__tests__/security.test.ts` — 181 cases passing (`npm test` exits 0 on VPS post-deploy).

The review was scoped to every customer-reachable attack surface: the OAuth flow, the path allowlist, the regex-based command allow/deny lists used by `run_approved_command`, the background-job lifecycle, session handling, and the `search_file` regex surface. Findings are numbered F-VM-1 through F-VM-8 by severity and order of discovery.

---

## Findings

### F-VM-1 — CRITICAL — Loopback redirect URIs accepted by default in OAuth
**Impact:** An attacker who can run a process on the same host as the MCP server can register a localhost redirect URI and intercept the authorization code during the OAuth handshake.
**Fix:** Loopback redirects stripped from the default-allowed list. Gated behind an explicit opt-in environment variable `ALLOW_LOOPBACK_REDIRECTS=true` so deploys that need loopback for local development can still have it, but marketplace deployments do not ship it.
**Verification:** OAuth unit tests assert that `http://127.0.0.1/*` is rejected unless the env var is set.

### F-VM-2 — HIGH — Symlink path-allowlist bypass
**Impact:** `validatePath` compared the raw input path against the allowlist. A symlink in an allowed directory pointing at `/etc/shadow` or `/root/.ssh/id_rsa` would pass the check, then resolve to a sensitive file on read.
**Fix:** `validatePath` now calls `fs.realpathSync` on the input before the allowlist check and before the sensitive-pattern match. Symlinks are followed first, then the canonical path is validated.
**Verification:** Tests include symlink-to-sensitive and symlink-out-of-allowlist cases.

### F-VM-3 — HIGH — Pathological regex inputs (ReDoS + denial-of-service)
**Impact:** Unbounded `command`, `justification`, `path`, `pattern`, and `process_name` inputs could be crafted to trigger catastrophic backtracking in the allow/deny regexes, pinning the event loop.
**Fix:** `INPUT_LIMITS` caps every user-supplied string before any regex runs:
- `command`: 4096
- `justification`: 1000
- `description`: 500
- `path`: 512
- `pattern`: 256
- `process_name`: 64

Inputs exceeding the cap are rejected with a `400` before the pattern check.
**Verification:** Tests exercise each cap boundary and assert a clean rejection, not a hang.

### F-VM-4 — MEDIUM — Session table unbounded growth
**Impact:** The StreamableHTTP transport keeps a per-session EventStore. Without a cap, a malicious or buggy client could spin up sessions until memory is exhausted.
**Fix:** `MAX_SESSIONS=200` cap. When exceeded, the server returns `503` with a `Retry-After: 30` header instead of accepting the session.
**Verification:** Load test creates 201 sessions and asserts the 201st is rejected with `503`.

### F-VM-5 — MEDIUM — Background jobs could run forever
**Impact:** `run_approved_command` with `background=true` forks a child process. Without a timeout, a stuck or malicious command could run indefinitely, consuming CPU/memory and filling logs.
**Fix:** `BG_COMMAND_TIMEOUT_MS=600000` (10 minutes) with escalation: `SIGTERM` → wait 5s → `SIGKILL`. Timeout applies to all background jobs uniformly.
**Verification:** Tests spawn a sleep-longer-than-timeout job and assert the process is killed by the deadline.

### F-VM-6 — MEDIUM — OAuth codes and refresh tokens used `Math.random`
**Impact:** `Math.random()` is not cryptographically secure. An attacker observing several tokens could predict future ones.
**Fix:** All OAuth codes and refresh tokens now use `crypto.randomBytes(32).toString('base64url')`. 256 bits of entropy, URL-safe encoding.
**Verification:** Grep for `Math.random` in `src/` yields zero results in security-sensitive paths. Audit log samples confirm the new format.

### F-VM-7 — MEDIUM — Pathological regex in `search_file`
**Impact:** The `search_file` tool accepts a user-supplied regex. Even with input length caps, structurally pathological patterns (e.g. `(a+)+b`) can still cause backtracking storms on real file contents.
**Fix:** `CATASTROPHIC_PATTERN_SHAPES` guard rejects known pathological shapes before compiling the regex. Rejected patterns return a `400` explaining why.
**Verification:** Tests include the classic `(a+)+`, `(x*)*`, nested-alternation bombs; all rejected with the guard message.

### F-VM-8 — LOW — Deploy job log growth
**Impact:** A long-running deploy with verbose output could produce a multi-megabyte log attached to a single job record.
**Fix:** `capLog` truncates deploy job logs at 500 lines with a `[... truncated, N lines]` marker.
**Verification:** Test runs a loop that emits 1000 lines and asserts the stored log is exactly 500 + the truncation marker.

---

## Follow-up fixes (Sonnet continuation)

Two additional test-suite fixes landed after the main v1.3.0 commit, both closing small gaps discovered when running the full suite against the hardened code:

**`f751409` — Dot-source env-manip pattern.** The original deny-pattern for `. /etc/profile` and similar dot-source invocations relied on `\b` word boundaries. `\b` does not fire before `.` at the start of a string, so a command beginning with `. /etc/profile` evaded detection. Fix: command-position anchor `(?:^|[;&|])\s*\.\s+/`.

**`862c732` — AWS config sensitive-pattern.** The sensitive-file allowlist matched `.aws/credentials` but not `aws/config` without the leading dot. Added `/\/aws\/(config|credentials)/i` so both forms are caught.

---

## What was out of scope

This review deliberately did **not** cover:
- The Claude Code SessionStart hook behavior (v1.4.0 added these; any behavioral regressions belong in a follow-up behavioral review, not a security review).
- The marketplace listing copy.
- Third-party dependency vulnerabilities (tracked separately via upcoming Snyk + CodeQL + SonarCloud automation).
- The Telegram connector (separate product, separate repo, separate review).

---

## How to reproduce the test suite

```bash
git clone https://github.com/claudedussy/vps-control-mcp
cd vps-control-mcp
npm install
npm test
```

Expected: 181 tests pass, exit code 0.

If any test fails, treat it as a security regression and open a GitHub issue.
