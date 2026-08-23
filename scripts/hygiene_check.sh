#!/usr/bin/env bash
set -euo pipefail

# hygiene_check.sh — Repo hygiene scan for tracked-eligible files.
#
# Enforces the project git-hygiene rules (documented in the project AGENTS.md contract):
#   - no full system paths (/Users/..., /home/...) in tracked-eligible files
#   - no references to ../data.md or sibling data inventory paths in src/, tests/, configs/
#   - git diff --check passes
#
# Warns (does not fail) on:
#   - AI tool name mentions in tracked-eligible files (deferred pre-public scrub)
#
# Usage:
#   scripts/hygiene_check.sh              # scan the whole repo
#   scripts/hygiene_check.sh --staged     # scan only staged paths (pre-commit)
#   scripts/hygiene_check.sh --controls   # control-file integrity only (private do/ surface)
#
# Exit codes:
#   0 = pass (possibly with warnings)
#   1 = hygiene violation found
#   2 = invocation error
#
# Project-specific tuning (optional):
#   Set HYGIENE_SCAN_ROOTS to override the default tracked-eligible source roots.
#   Set HYGIENE_SIBLING_PROJECTS to scan additional repo roots for cache leaks.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="repo"
if [[ "${1:-}" == "--staged" ]]; then
  MODE="staged"
elif [[ "${1:-}" == "--controls" ]]; then
  # Control-file integrity. These files are gitignored, so the staged scan below
  # can never see them — this is the only path that checks them.
  if [[ -f scripts/control_check.py ]]; then
    exec python3 scripts/control_check.py "$ROOT"
  fi
  echo "hygiene_check: scripts/control_check.py missing; control gate cannot run." >&2
  exit 1
elif [[ -n "${1:-}" ]]; then
  echo "hygiene_check: unknown argument: $1" >&2
  exit 2
fi

# Tracked-eligible source roots. Override via HYGIENE_SCAN_ROOTS env var
# if your project uses a different layout.
SCAN_ROOTS=(${HYGIENE_SCAN_ROOTS:-src scripts config configs tests})
TOP_LEVEL_FILES=(README.md CITATION.cff pyproject.toml setup.py setup.cfg)

# Sibling project roots to also scan for cache leaks (space-separated).
SIBLING_PROJECTS=(${HYGIENE_SIBLING_PROJECTS:-})

# Scan glob extensions
SCAN_GLOBS=("*.py" "*.md" "*.yml" "*.yaml" "*.toml" "*.sh" "*.ps1" "*.cfg" "*.ini")

violations=0
warnings=0

is_self_referential() {
  case "$1" in
    scripts/hygiene_check.sh) return 0 ;;
  esac
  return 1
}

gather_files() {
  if [[ "$MODE" == "staged" ]]; then
    git diff --cached --name-only --diff-filter=ACMR 2>/dev/null \
      | while read -r f; do
          [[ -z "$f" ]] && continue
          case "$f" in
            do/*|docs/*|var/*|data/*|outputs/*|dist/*|.git/*) continue ;;
          esac
          is_self_referential "$f" && continue
          for pat in "${SCAN_GLOBS[@]}"; do
            # shellcheck disable=SC2053
            if [[ "$f" == $pat ]]; then echo "$f"; break; fi
          done
        done
  else
    local roots=()
    for r in "${SCAN_ROOTS[@]}"; do [[ -e "$r" ]] && roots+=("$r"); done
    for f in "${TOP_LEVEL_FILES[@]}"; do [[ -f "$f" ]] && roots+=("$f"); done
    [[ ${#roots[@]} -eq 0 ]] && return 0
    find "${roots[@]}" -type f 2>/dev/null \
      | while read -r f; do
          is_self_referential "$f" && continue
          for pat in "${SCAN_GLOBS[@]}"; do
            # shellcheck disable=SC2053
            if [[ "$f" == $pat ]]; then echo "$f"; break; fi
          done
        done
  fi
}

# Read into array; uses while-read to stay Bash 3.2 compatible.
FILES=()
while IFS= read -r line; do FILES+=("$line"); done < <(gather_files)

# --- Check 1: full system paths (FAIL) ---
fail_paths=""
for f in ${FILES[@]+"${FILES[@]}"}; do
  [[ -f "$f" ]] || continue
  if hits="$(grep -nE '(/Users/[A-Za-z0-9._-]+|/home/[A-Za-z0-9._-]+|[A-Za-z]:[\\/]Users)' "$f" 2>/dev/null)"; then
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      fail_paths+="${f}:${line}"$'\n'
    done <<< "$hits"
  fi
done

if [[ -n "$fail_paths" ]]; then
  echo "hygiene_check: FAIL — absolute system paths in tracked-eligible files:" >&2
  printf '%s' "$fail_paths" >&2
  echo "  Fix: replace with \$HOME, ~, or repo-relative paths." >&2
  violations=$((violations + 1))
fi

# --- Check 2: ../data.md or sibling-inventory references in source code (FAIL) ---
fail_datamd=""
for f in ${FILES[@]+"${FILES[@]}"}; do
  [[ -f "$f" ]] || continue
  case "$f" in
    src/*|tests/*|configs/*)
      if hits="$(grep -nE '(/|\.\./)data\.md\b' "$f" 2>/dev/null)"; then
        while IFS= read -r line; do
          [[ -z "$line" ]] && continue
          fail_datamd+="${f}:${line}"$'\n'
        done <<< "$hits"
      fi
      ;;
  esac
done

if [[ -n "$fail_datamd" ]]; then
  echo "hygiene_check: FAIL — sibling data inventory (data.md) referenced in source/tests/configs:" >&2
  printf '%s' "$fail_datamd" >&2
  echo "  Fix: drop the data.md reference; the inventory is a coordination doc, not a code input." >&2
  violations=$((violations + 1))
fi

# --- Check 3: AI tool name mentions in tracked-eligible files (WARN) ---
warn_ai=""
for f in ${FILES[@]+"${FILES[@]}"}; do
  [[ -f "$f" ]] || continue
  if hits="$(grep -niE '\b(codex|claude|gpt[- ]?pro|gpt-?5|openai|anthropic|\borca\b|\bmako\b|\bdairy\b|\btandy\b)\b' "$f" 2>/dev/null)"; then
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      warn_ai+="${f}:${line}"$'\n'
    done <<< "$hits"
  fi
done

if [[ -n "$warn_ai" ]]; then
  ai_count="$(printf '%s' "$warn_ai" | grep -c .)"
  echo "hygiene_check: WARN — ${ai_count} AI/tool-name mention(s) in tracked-eligible files (deferred pre-public scrub):" >&2
  printf '%s' "$warn_ai" | head -20 >&2
  if [[ "$ai_count" -gt 20 ]]; then
    echo "  ... and $((ai_count - 20)) more." >&2
  fi
  warnings=$((warnings + 1))
fi

# --- Check 4: git diff --check (FAIL); staged mode checks the index (--cached) ---
if [[ "$MODE" == "staged" ]]; then
  if ! git diff --cached --check 2>/dev/null; then
    echo "hygiene_check: FAIL — git diff --cached --check reported whitespace/conflict markers in staged content." >&2
    violations=$((violations + 1))
  fi
else
  if ! git diff --check 2>/dev/null; then
    echo "hygiene_check: FAIL — git diff --check reported whitespace/conflict markers." >&2
    violations=$((violations + 1))
  fi
fi

# (Repo-local .venv/cache directories are no longer policed — they're ignored by
# git, Syncthing, rclone, and remrun, so they never propagate.)

if [[ "$violations" -gt 0 ]]; then
  echo "hygiene_check: FAIL ($violations violation(s), $warnings warning(s))" >&2
  exit 1
fi

if [[ "$warnings" -gt 0 ]]; then
  echo "hygiene_check: pass with $warnings warning(s)"
else
  echo "hygiene_check: pass"
fi
