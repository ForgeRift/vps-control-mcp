#!/usr/bin/env bash
# verify-S68.sh — S68 Fifteenth-Pass closure verifier
# Run from the directory containing both plugin dirs (local-terminal-mcp/ and vps-control-mcp/).
# After remediation, every finding should print MISS:.  CONFIRMED: lines mean fix didn't land.
set -u
LT=local-terminal-mcp
VPS=vps-control-mcp

CONFIRMED=0; MISS=0
confirm() { echo "CONFIRMED: $1 -- $2"; CONFIRMED=$((CONFIRMED+1)); }
miss()    { echo "MISS: $1 -- $2 (fixed)"; MISS=$((MISS+1)); }

# -- F-S68-1: v1.13.1 tag exists in both repos (we target v1.13.1 since 1.13.0 was untagged) --
( cd $LT && git rev-parse --verify v1.13.1 >/dev/null 2>&1 ) && \
( cd $VPS && git rev-parse --verify v1.13.1 >/dev/null 2>&1 ) && \
  miss F-S68-1 "v1.13.1 tag exists on both repos" || \
  confirm F-S68-1 "v1.13.1 tag missing on at least one repo"

# -- F-S68-2: git --upload-pack/--receive-pack/--exec/--server-option blocked --
node -e "
  const src = require('fs').readFileSync('$LT/src/tools.ts','utf8');
  const ok = ['--upload-pack','--receive-pack','--exec','--server-option']
    .every(f => src.includes(\"'\" + f + \"'\"));
  process.exit(ok ? 0 : 1);
" 2>/dev/null && \
  miss F-S68-2 "git RCE flags now in FORBIDDEN_GIT_FLAGS" || \
  confirm F-S68-2 "git --upload-pack/etc still missing from FORBIDDEN_GIT_FLAGS"

# -- F-S68-3: LT git execs include core.hooksPath=/dev/null --
grep -q "core\.hooksPath" $LT/src/tools.ts && \
  miss F-S68-3 "LT now hardens git with core.hooksPath" || \
  confirm F-S68-3 "LT git lacks core.hooksPath hardening"

# -- F-S68-4: VPS audit caps every string arg, not just command/justification --
node -e "
  const src = require('fs').readFileSync('$VPS/src/audit.ts','utf8');
  const hasGeneric = /capField\(v,\s*512\)/.test(src) &&
                     !/\}\s*else\s*\{\s*cappedArgs\[k\]\s*=\s*v;/.test(src);
  process.exit(hasGeneric ? 0 : 1);
" 2>/dev/null && \
  miss F-S68-4 "VPS audit applies a per-field cap to every arg" || \
  confirm F-S68-4 "VPS audit still allows uncapped non-command/justification args"

# -- F-S68-5: VPS node validator blocks --env-file and --conditions --
grep -E "'(--env-file|--conditions)'" $VPS/src/tools.ts >/dev/null && \
  miss F-S68-5 "VPS node validator blocks --env-file and --conditions" || \
  confirm F-S68-5 "VPS node validator missing --env-file/--conditions"

# -- F-S68-6: VPS npm audit fix rejected --
node -e "
  const src = require('fs').readFileSync('$VPS/src/tools.ts','utf8');
  const m = src.match(/validateNpmArgs[\s\S]+?return null;\s*\}/);
  if (!m) process.exit(1);
  process.exit(/'fix'/.test(m[0]) ? 0 : 1);
" 2>/dev/null && \
  miss F-S68-6 "VPS validateNpmArgs rejects 'fix' second positional" || \
  confirm F-S68-6 "VPS validateNpmArgs accepts npm audit fix"

# -- F-S68-7: VPS deploy/job IDs include random suffix --
grep -qE "deploy-\\\$\{Date\.now\(\)\}-\\\$\{crypto" $VPS/src/tools.ts && \
  miss F-S68-7 "VPS deploy IDs include randomness" || \
  confirm F-S68-7 "VPS deploy IDs still use Date.now() alone"

# -- F-S68-8: VPS validatePath uses O_NOFOLLOW --
grep -qE "O_NOFOLLOW" $VPS/src/tools.ts && \
  miss F-S68-8 "VPS validatePath now opens with O_NOFOLLOW" || \
  confirm F-S68-8 "VPS validatePath returns string only — TOCTOU window"

# -- F-S68-9 / F-S68-10: doc category counts match source --
LT_CATS=$(node -e "
  const src = require('fs').readFileSync('$LT/src/tools.ts','utf8');
  const cats = (start, end) => {
    const s = src.indexOf(start), e = src.indexOf(end, s);
    const slice = src.slice(s, e);
    return new Set((slice.match(/category:\s*'([^']+)'/g)||[]).map(x=>x.match(/'([^']+)'/)[1]));
  };
  const b = cats('export const BLOCKED_PATTERNS:', 'export function checkBlocked');
  const h = cats('const HARD_BLOCKED_PATTERNS:', 'function tokenizeCommand');
  console.log(new Set([...b,...h]).size);
")
LT_DOCS=$(grep -hE "[0-9]+ categor" $LT/SECURITY.md $LT/MARKETPLACE_LISTING.md $LT/CLAUDE_CONTEXT.md \
  $LT/.claude-plugin/CLAUDE.md $LT/README.md $LT/TROUBLESHOOTING.md 2>/dev/null \
  | grep -oE "[0-9]+ categor" | grep -oE "^[0-9]+" | sort -u)
[ "$(echo "$LT_DOCS" | wc -l)" = "1" ] && [ "$LT_DOCS" = "$LT_CATS" ] && \
  miss F-S68-9 "LT doc category counts agree and match source ($LT_CATS)" || \
  confirm F-S68-9 "LT doc category counts disagree (docs say {$(echo $LT_DOCS | tr '\n' ' ')}, source says $LT_CATS)"

VP_CATS=$(node -e "
  const src = require('fs').readFileSync('$VPS/src/tools.ts','utf8');
  const cats = (start, end) => {
    const s = src.indexOf(start), e = src.indexOf(end, s);
    const slice = src.slice(s, e);
    return new Set((slice.match(/category:\s*'([^']+)'/g)||[]).map(x=>x.match(/'([^']+)'/)[1]));
  };
  const b = cats('const BLOCKED_PATTERNS:', 'const AMBER_PATTERNS:');
  const h = cats('const HARD_BLOCKED_PATTERNS:', 'function tokenizeCommand');
  console.log(new Set([...b,...h]).size);
")
VP_DOCS=$(grep -hE "[0-9]+ categor" $VPS/SECURITY.md $VPS/MARKETPLACE_LISTING.md $VPS/CLAUDE_CONTEXT.md \
  $VPS/.claude-plugin/CLAUDE.md $VPS/README.md $VPS/TROUBLESHOOTING.md 2>/dev/null \
  | grep -oE "[0-9]+ categor" | grep -oE "^[0-9]+" | sort -u)
[ "$(echo "$VP_DOCS" | wc -l)" = "1" ] && [ "$VP_DOCS" = "$VP_CATS" ] && \
  miss F-S68-10 "VPS doc category counts agree and match source ($VP_CATS)" || \
  confirm F-S68-10 "VPS doc category counts disagree (docs say {$(echo $VP_DOCS | tr '\n' ' ')}, source says $VP_CATS)"

# -- F-S68-15: pm2 BLOCKED_SUBS present --
grep -qE "BLOCKED_SUBS" $VPS/src/tools.ts && \
  miss F-S68-15 "VPS pm2 validator now has BLOCKED_SUBS" || \
  confirm F-S68-15 "VPS pm2 validator missing BLOCKED_SUBS"

# -- F-S68-17: Layer 2/3 calls pass a timeout/AbortSignal --
grep -qE "AbortSignal\.timeout" $LT/src/tools.ts && \
  miss F-S68-17 "LT Layer 2/3 calls have an AbortSignal" || \
  confirm F-S68-17 "LT Layer 2/3 calls have no client-side timeout"
grep -qE "AbortSignal\.timeout" $VPS/src/tools.ts && \
  miss F-S68-17b "VPS Layer 2/3 calls have an AbortSignal" || \
  confirm F-S68-17b "VPS Layer 2/3 calls have no client-side timeout"

# -- F-S68-19: VPS audit caps tool field --
grep -qE "cappedTool" $VPS/src/audit.ts && \
  miss F-S68-19 "VPS audit tool field is capped" || \
  confirm F-S68-19 "VPS audit tool field uncapped"

# -- F-S68-20: dist freshness checked in CI --
grep -rqE "git diff.*dist" $LT/.github/workflows/ $VPS/.github/workflows/ 2>/dev/null && \
  miss F-S68-20 "CI now asserts dist freshness" || \
  confirm F-S68-20 "CI lacks dist-freshness assertion"

# -- F-S68-21: typescript moved to devDependencies --
node -e "
  const p = require('./$VPS/package.json');
  process.exit((p.devDependencies||{}).typescript ? 0 : 1);
" && \
  miss F-S68-21 "VPS typescript in devDependencies" || \
  confirm F-S68-21 "VPS typescript still in dependencies"

# -- Test-suite freshness ---------------------------------------------------
echo
echo "Running LT test suite..."
( cd $LT && node --experimental-transform-types --loader ./ts-loader.mjs --no-warnings \
    --test src/__tests__/security.test.ts src/__tests__/bypass-corpus.test.ts > /tmp/lt68.out 2>&1 )
grep "# pass\|# fail" /tmp/lt68.out | tail -2

echo "Running VPS test suite..."
( cd $VPS && node --env-file=.env.test --experimental-transform-types --loader ./ts-loader.mjs \
    --no-warnings --test src/__tests__/security.test.ts src/__tests__/bypass-corpus.test.ts > /tmp/vps68.out 2>&1 )
grep "# pass\|# fail" /tmp/vps68.out | tail -2

echo
echo "===================="
echo "S68 closure check: $MISS fixed (MISS), $CONFIRMED still open (CONFIRMED)"
[ "$CONFIRMED" = "0" ] && \
  echo "ALL S68 FINDINGS CLOSED -- v1.14.0 ready to tag." || \
  echo "$CONFIRMED FINDING(S) NOT CLOSED -- investigate before tagging."
