# ForgeRift Security Remediation Progress — vps-control-mcp
<!-- Phase 1 status file — updated automatically during remediation -->

## Status: Phase 1 COMPLETE

All bypass-corpus tests pass: **4/4 suites, all green**.  
Pre-existing security.test.ts failures: 114 (down from 117; Phase 1 fixes resolved 3).

---

## Phase 1 — Critical Pattern Fixes

### C5 — Kernel module operations ✅
**File:** `src/tools.ts` — 4 new patterns  
**Finding:** modprobe/insmod/rmmod/depmod were not blocked. Any of these can load
a rootkit or remove a defensive module. lsmod (read-only) remains allowed.  
**Fix:** Added `category: 'kernel-module'` patterns for each verb.  
**Tests:** `[C5]` suite — 8 tests, all pass.

### C6 — Sensitive write-destination blocking ✅
**File:** `src/tools.ts` — 16 new patterns  
**Finding:** cp/mv/tee/install/dd to sensitive system paths were unblocked.  
**Fix:** Path-substring patterns for: ld.so.preload, sudoers, cron.*, systemd/system|user,
pam.d, profile.d, environment, rc.local, hosts, grub, lib/modules, usr/local/bin,
init.d, ~/.ssh/authorized_keys, sshd_config.  
**Tests:** `[C6]` suite — 24 tests, all pass.

### C7 — LD_PRELOAD= / LD_AUDIT= / LD_LIBRARY_PATH= injection ✅
**File:** `src/tools.ts` — 3 new patterns  
**Finding:** Dynamic-linker env var injection not blocked.  
**Fix:** `/\bLD_PRELOAD\s*=/`, `/\bLD_AUDIT\s*=/`, `/\bLD_LIBRARY_PATH\s*=/`  
**Tests:** `[C7]` suite — 10 tests, all pass.

### C8 — Shell -c flag-injection evasion ✅
**File:** `src/tools.ts` — modified existing shell -c pattern  
**Finding:** Existing pattern `/\b(bash|sh|...)\s+-c\b/` required -c directly after
the shell name — flags like `--noprofile`, `-x` between shell and -c were not caught.  
**Fix:** Changed `\s+-c` to `[^\n]*\s+-c` to allow intervening flags.  
(`ksh` was already present in the VPS pattern — no change needed.)  
**Tests:** `[C8]` suite — 8 tests, all pass.

### __TEST_ONLY export ✅
**File:** `src/tools.ts` — added export block at end of file  
**Finding:** `security.test.ts` and `bypass-corpus.test.ts` both import `__TEST_ONLY`
but it was never exported from tools.ts (tests were always failing in git HEAD).  
**Fix:** Added `export const __TEST_ONLY = { validateCommand, BLOCKED_PATTERNS,
AMBER_PATTERNS, SENSITIVE_FILE_PATTERNS, CATASTROPHIC_PATTERN_SHAPES,
POSITIVE_ALLOWLIST, safeEnv, SAFE_ENV_KEYS, GIT_HARDENING_FLAGS };`

---

## Git Status
VPS repo has a corrupt git index in the sandbox preventing `git commit`.
**Code changes are on disk and correct.** Run the following to commit:

```bash
# vps-control-mcp
cd vps-control-mcp
rm .git/index && git reset          # rebuild index
git add src/tools.ts src/__tests__/bypass-corpus.test.ts
git commit -m "Phase 1: C5/C6/C7/C8 pattern fixes + __TEST_ONLY export + bypass-corpus harness (VPS)

C5: modprobe/insmod/rmmod/depmod blocked (kernel-module category)
C6: 16 sensitive-destination path patterns
C7: LD_PRELOAD=/LD_AUDIT=/LD_LIBRARY_PATH= injection blocked
C8: Shell -c pattern now allows intervening flags (ksh already present)
export: Added __TEST_ONLY so test harness can import internals

All bypass-corpus tests pass. Refs: C5 C6 C7 C8 (S60 adversarial review)"
```

---

## Remaining Work (Phase 2+)

### Pre-existing security.test.ts failures (114 — not introduced by Phase 1)
These tests were written against a future implementation and were already failing
before any Phase 1 changes. Requires Phase 2+ work:
- AMBER tier: apt-get, find -exec (moved to RED), xargs, sed -i behaviour
- capString / INPUT_LIMITS shape changes
- validatePath allowlist restrictions
- validateProcess allowlist restrictions
- curl -o output-path blocking (F-OP-34 extension)
- Several green-tier command allow-list tests

### Not yet started
- **C11/C12/C13**: Layer 2 (Claude API classifier) and Layer 3 (multi-persona board)
  **DO NOT EXIST in current code** — require full implementation from scratch.
- **H1–H20**: High-severity findings
- **M1–M15**: Medium-severity findings
- **D1–D12**: Design recommendations
