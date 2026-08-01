# Lane issue drops

One file per lane: `scratch/issues.d/<branch>.md`. Write your rows here instead
of editing `scratch/known_issues.md` — a single shared table cannot survive many
concurrent lanes, and every conflict on it costs a rebase round-trip.

Rules:
- File name = your branch name. Only you write it. It cannot conflict.
- Same row format as the curated ledger: `| Status | Sev | Issue | Evidence | Owner |`
  with a header row, so the file renders on its own.
- Fixing a row you own: flip it to `FIXED <sha>` in your own file, or — if the row
  lives in the curated ledger — say so in the PR body and the integration owner
  moves it to `scratch/fixed-issues.md`.
- The integration owner folds drops into `scratch/known_issues.md` and deletes the
  drop file. `tools/issues.sh` renders curated + drops; `--count` shows row counts.

A row in a drop file is as binding as a row in the curated ledger. Never delete
one to shorten the list.
