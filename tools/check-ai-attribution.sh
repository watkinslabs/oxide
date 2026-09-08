#!/usr/bin/env bash
# Refuse any AI attribution in commit messages or pull-request text.
#
# Authorship is created by the client, so no server setting can prevent this;
# what a repository can do is refuse to carry it. This script is the single
# owner of that decision, called by the commit-msg hook for fast local
# feedback and by the pull-request workflow as the check that cannot be
# bypassed — a local hook is skipped by --no-verify or a redirected
# core.hooksPath, which is exactly how the trailers this guards against
# reached main.
set -uo pipefail

# One pattern per line, extended regular expressions, matched case-insensitively.
patterns='^[[:space:]]*co-authored-by:
^[[:space:]]*co-developed-with
^[[:space:]]*assisted-by:
^[[:space:]]*claude-session:
generated (with|by) \[?(claude|copilot|codex|chatgpt|an? ai)
written by .*(ai|assistant|bot)
noreply@(anthropic|openai)
(anthropic|openai)\.com
claude\.ai
claude (code|opus|sonnet|haiku)
github copilot
copilot(\[bot\])?
codex
chatgpt
gpt-[0-9]
🤖'

fail=0
report() { printf '%s\n' "$1" >&2; fail=1; }

check_text() {
    local origin="$1" text="$2" line
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        if printf '%s' "$text" | grep -qiE "$line"; then
            report "ai-attribution: $origin carries a forbidden attribution matching /$line/"
        fi
    done <<< "$patterns"
}

case "${1:-}" in
    --message-file)
        check_text "commit message" "$(cat "$2")"
        ;;
    --range)
        # Every commit message in a revision range.
        while IFS= read -r sha; do
            [ -n "$sha" ] || continue
            check_text "commit $sha" "$(git log -1 --format=%B "$sha")"
        done < <(git rev-list "$2")
        ;;
    --text)
        check_text "${3:-text}" "$2"
        ;;
    *)
        echo "usage: $0 --message-file <path> | --range <rev-range> | --text <text> [origin]" >&2
        exit 2
        ;;
esac

if [ "$fail" -ne 0 ]; then
    cat >&2 <<'MSG'
ai-attribution: REFUSED — this project carries no AI attribution, ever.
        No Co-Authored-By naming an assistant, no session link, no generated-with
        footer, in commit messages, pull request titles or bodies.
        Remove it and amend; do not bypass this check.
MSG
    exit 1
fi
echo "ai-attribution: clean"
