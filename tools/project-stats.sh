#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

top_n="${1:-10}"
if ! [[ "$top_n" =~ ^[0-9]+$ ]] || [ "$top_n" -le 0 ]; then
  echo "usage: tools/project-stats.sh [top_n]" >&2
  exit 2
fi

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is required" >&2
  exit 2
fi

rs_file_count="$(git ls-files '*.rs' | wc -l | tr -d ' ')"
rs_loc_total="$(git ls-files '*.rs' | xargs -r wc -l | awk 'END{print $1+0}')"

code_file_count="$(git ls-files '*.[ch]' '*.cc' '*.cpp' '*.h' '*.hpp' '*.rs' '*.py' '*.sh' '*.S' '*.asm' '*.go' '*.js' '*.ts' '*.tsx' '*.cxx' '*.hh' | wc -l | tr -d ' ')"
code_loc_total="$(git ls-files '*.[ch]' '*.cc' '*.cpp' '*.h' '*.hpp' '*.rs' '*.py' '*.sh' '*.S' '*.asm' '*.go' '*.js' '*.ts' '*.tsx' '*.cxx' '*.hh' | xargs -r wc -l | awk 'END{print $1+0}')"

workspace_members="$(
  awk '
    /\[workspace\]/ { in_ws=1; next }
    /^\[/ && in_ws { in_ws=0 }
    in_ws && /members[[:space:]]*=/ {
      line=$0
      while (line !~ /\]/ && getline > 0) {
        line = line " " $0
      }
      print line
      exit
    }
  ' Cargo.toml | grep -o '"[^"]\+"' | tr -d '"'
)"

workspace_member_count="$(printf "%s\n" "$workspace_members" | sed '/^$/d' | wc -l | tr -d ' ')"
crates_dir_count="$(find crates -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"

tmp_stats="$(mktemp)"
tmp_lang_stats="$(mktemp)"
tmp_rust_files="$(mktemp)"
trap 'rm -f "$tmp_stats" "$tmp_lang_stats" "$tmp_rust_files"' EXIT

while IFS= read -r member; do
  [ -z "$member" ] && continue
  if [ -d "$member" ]; then
    files="$(git ls-files "$member/**/*.rs" "$member/*.rs" | wc -l | tr -d ' ')"
    loc="$(git ls-files "$member/**/*.rs" "$member/*.rs" | xargs -r wc -l | awk 'END{print $1+0}')"
    printf "%s\t%s\t%s\n" "$loc" "$files" "$member" >> "$tmp_stats"
  fi
done <<EOF
$workspace_members
EOF

generated_utc="$(date -u +"%Y-%m-%d %H:%M:%S UTC")"
repo_name="$(basename "$repo_root")"
largest_path="$(awk -F '\t' 'BEGIN{max=-1; name="-"} {if ($1+0>max){max=$1+0; name=$3}} END{print name}' "$tmp_stats")"
largest_loc="$(awk -F '\t' 'BEGIN{max=0} {if ($1+0>max){max=$1+0}} END{print max+0}' "$tmp_stats")"
top_n_loc="$(awk -F '\t' 'NF==3 {print $1+0}' "$tmp_stats" | sort -nr | head -n "$top_n" | awk '{s+=$1} END{print s+0}')"
top_n_share="$(awk -v t="$top_n_loc" -v total="$rs_loc_total" 'BEGIN{if (total>0) printf("%.1f%%", (100.0*t)/total); else print "0.0%"}')"
avg_loc_per_rs_file="$(awk -v total="$rs_loc_total" -v files="$rs_file_count" 'BEGIN{if (files>0) printf("%.1f", total/files); else print "0.0"}')"

read -r median_crate_loc p90_crate_loc <<EOF
$(awk -F '\t' 'NF==3 {print $1+0}' "$tmp_stats" | sort -n | awk '
{
  a[++n]=$1
}
END{
  if (n==0) { print "0 0"; exit }
  mid=(n%2)?a[(n+1)/2]:((a[n/2]+a[n/2+1])/2)
  p90_idx=int((n*90+99)/100)
  if (p90_idx < 1) p90_idx=1
  if (p90_idx > n) p90_idx=n
  printf("%.1f %.0f\n", mid, a[p90_idx])
}')
EOF

while IFS= read -r rsf; do
  [ -z "$rsf" ] && continue
  printf "%s\t%s\n" "$(wc -l < "$rsf" | tr -d ' ')" "$rsf" >> "$tmp_rust_files"
done <<EOF
$(git ls-files '*.rs')
EOF

largest_rs_file="$(awk -F '\t' 'BEGIN{max=-1; name="-"} {if ($1+0>max){max=$1+0; name=$2}} END{print name}' "$tmp_rust_files")"
largest_rs_file_loc="$(awk -F '\t' 'BEGIN{max=0} {if ($1+0>max){max=$1+0}} END{print max+0}' "$tmp_rust_files")"

while IFS= read -r f; do
  [ -z "$f" ] && continue
  ext="${f##*.}"
  case "$ext" in
    rs) lang="Rust" ;;
    c|h|cc|cpp|hpp|cxx|hh) lang="C/C++" ;;
    py) lang="Python" ;;
    sh) lang="Shell" ;;
    S|asm) lang="Assembly" ;;
    go) lang="Go" ;;
    js|ts|tsx) lang="JS/TS" ;;
    *) lang="Other" ;;
  esac
  printf "%s\t1\t%s\n" "$lang" "$(wc -l < "$f" | tr -d ' ')" >> "$tmp_lang_stats"
done <<EOF
$(git ls-files '*.[ch]' '*.cc' '*.cpp' '*.h' '*.hpp' '*.rs' '*.py' '*.sh' '*.S' '*.asm' '*.go' '*.js' '*.ts' '*.tsx' '*.cxx' '*.hh')
EOF

docs_md_count="$(git ls-files 'docs/**/*.md' 'docs/*.md' | wc -l | tr -d ' ')"
docs_draft_count=0
docs_frozen_count=0
while IFS= read -r doc; do
  [ -z "$doc" ] && continue
  status_token="$(awk 'NR<=6 && /^(DRAFT|FROZEN) / {print $1; exit}' "$doc")"
  case "$status_token" in
    DRAFT) docs_draft_count=$((docs_draft_count+1)) ;;
    FROZEN) docs_frozen_count=$((docs_frozen_count+1)) ;;
  esac
done <<EOF
$(git ls-files 'docs/**/*.md' 'docs/*.md')
EOF

echo "# ${repo_name} project stats"
echo
echo "_Generated: ${generated_utc}_"
echo
echo "| Metric | Value |"
echo "|---|---:|"
echo "| Workspace members | ${workspace_member_count} |"
echo "| Crates under \`crates/\` | ${crates_dir_count} |"
echo "| Rust files tracked | ${rs_file_count} |"
echo "| Rust LOC (tracked \`.rs\`) | ${rs_loc_total} |"
echo "| Avg LOC per Rust file | ${avg_loc_per_rs_file} |"
echo "| Code files tracked (multi-language) | ${code_file_count} |"
echo "| Code LOC (multi-language) | ${code_loc_total} |"
echo "| Largest workspace crate by Rust LOC | \`${largest_path}\` (${largest_loc}) |"
echo "| Top ${top_n} crates share of Rust LOC | ${top_n_share} |"
echo "| Median crate Rust LOC | ${median_crate_loc} |"
echo "| P90 crate Rust LOC | ${p90_crate_loc} |"
echo "| Largest Rust file | \`${largest_rs_file}\` (${largest_rs_file_loc}) |"
echo "| Docs markdown files | ${docs_md_count} |"
echo "| Docs status count | DRAFT ${docs_draft_count} / FROZEN ${docs_frozen_count} |"
echo
echo "## Top ${top_n} workspace crates by Rust LOC"
echo
echo "| Rank | Crate path | Rust files | Rust LOC |"
echo "|---:|---|---:|---:|"
awk -F '\t' 'NF==3 {print $0}' "$tmp_stats" | sort -t$'\t' -k1,1nr -k3,3 | head -n "$top_n" | awk -F '\t' '{printf("| %d | `%s` | %d | %d |\n", NR, $3, $2, $1)}'
echo
echo "## Language mix (by LOC)"
echo
echo "| Rank | Language | Files | LOC | LOC share |"
echo "|---:|---|---:|---:|---:|"
awk -F '\t' '
{
  files[$1]+=$2
  loc[$1]+=$3
  total+=$3
}
END{
  for (k in loc) {
    pct=(total>0)?(100.0*loc[k]/total):0
    printf("%s\t%d\t%d\t%.1f%%\n", k, files[k], loc[k], pct)
  }
}' "$tmp_lang_stats" | sort -t$'\t' -k3,3nr -k1,1 | head -n 8 | awk -F '\t' '{printf("| %d | %s | %d | %d | %s |\n", NR, $1, $2, $3, $4)}'
