# CVSS-Based Patch SLA — ForgeRift Internal Process

**Applies to:** vps-control-mcp, local-terminal-mcp  
**Required by:** ToS §A.3  
**Owner:** Dustin (ForgeRift LLC sole member)  
**Last updated:** 2026-04-21

---

## SLA Commitments (ToS §A.3)

| CVSS Score | Target Patch Release |
|---|---|
| 9.0 – 10.0 (Critical) | Within **72 hours** of ForgeRift becoming aware |
| 7.0 – 8.9 (High) | Within **30 days** of ForgeRift becoming aware |
| Below 7.0 | Best-effort, next scheduled release |

The 72-hour clock starts when ForgeRift first becomes aware of the vulnerability — whether via npm audit output, GitHub Dependabot alert, direct CVE disclosure, or user report.

---

## Monitoring — How CVEs Are Detected

### Automated
- **npm audit** — run on every deploy via CI or manually: `npm audit` / `pnpm audit`
- **GitHub Dependabot** — enabled on both repos (`ForgeRift/local-terminal-mcp`, `ForgeRift/vps-control-mcp`). Alerts appear in the Security tab and are sent to the repo owner email.
- **GitHub Advisory Database** — Dependabot pulls from this automatically.

### Manual checks (run at least monthly)
```bash
# In each plugin directory:
npm audit --audit-level=high
```

---

## Response Process

### Step 1 — Triage (within 2 hours of awareness)
1. Read the CVE / Dependabot alert.
2. Determine if the vulnerable package is a direct or transitive dependency.
3. Determine if the vulnerable code path is reachable in the plugin's use of the package.
4. Assign CVSS score. If the CVE has no published score, use the NVD calculator or estimate conservatively.
5. Note the **awareness timestamp** — this starts the SLA clock.

### Step 2 — Patch (within SLA window)
1. Update the vulnerable dependency: `npm update <package>` or pin to patched version in `package.json`.
2. Re-run `npm audit` to confirm the finding is resolved.
3. Run the full test suite: `npm test` (both plugins have `__tests__/` directories).
4. Build: `npm run build` — confirm clean TypeScript compile.

### Step 3 — Release (before SLA deadline)
1. Bump `patch` version in `package.json` (e.g. 1.9.0 → 1.9.1).
2. Add CHANGELOG entry: `## [x.y.z] — YYYY-MM-DD` with `### Security` section describing the CVE, affected package, and resolution.
3. Commit: `git commit -am "security: patch CVE-YYYY-XXXXX in <package> (CVSS <score>)"`
4. Push to GitHub: `git push origin main`
5. Deploy to VPS via `deploy_vps_mcp` (vps-control-mcp) and/or publish updated marketplace listing (local-terminal-mcp).

### Step 4 — Document
Record the following in a private log (e.g. a secure note or internal Notion doc):
- CVE identifier
- Affected package and version range
- CVSS score
- Awareness timestamp (when ForgeRift first knew)
- Patch release timestamp
- Time elapsed (must be within SLA)

This log is the evidence if a breach-of-contract claim is ever made on the patch SLA.

---

## Escalation

If a CVSS 9.0+ vulnerability cannot be patched within 72 hours (e.g. no upstream fix available):
1. Assess whether a workaround (disable affected feature, add input validation) reduces exposure.
2. If no workaround: notify affected users via the email on file with a timeline estimate.
3. Document the delay and reason in the internal log.

---

## Package Dependency Map (as of v1.9.0)

### local-terminal-mcp
| Package | Purpose | Notes |
|---|---|---|
| `@modelcontextprotocol/sdk` | MCP protocol | Core dependency |
| `@anthropic-ai/sdk` | AI classification (BLOCKED tier) | New in 1.9.0 |
| `express` | HTTP server | |
| `dotenv` | Env config | |

### vps-control-mcp
| Package | Purpose | Notes |
|---|---|---|
| `@modelcontextprotocol/sdk` | MCP protocol | Core dependency |
| `@anthropic-ai/sdk` | AI classification (BLOCKED tier) | New in 1.9.0 |
| `express` | HTTP server | |
| `dotenv` | Env config | |
| `tsx` | Dev TypeScript runner | devDependency |

---

*This document is an internal process record. Publishing the ToS without this process in place creates the liability the ToS was written to avoid.*
