"""Self-contained HTML chart for the syscall-cost report.

Kept beside the report rather than inside it because the page is a document in
its own right: it is what someone opens months later to ask whether this kernel
got closer to the host or further away.
"""
import html as _html
import math

BANDS = ((2, "ok"), (5, "slow"), (20, "bad"))


def band(ratio: float) -> str:
    for limit, name in BANDS:
        if ratio < limit:
            return name
    return "severe"


def width(ratio: float) -> float:
    """Log scale. The ratios span one to four orders of magnitude, so a linear
    bar flattens every row below the worst one into nothing."""
    return max(1.5, min(100.0, 100.0 * math.log10(max(ratio, 1.0)) / 4.0))


STYLE = """
:root {
  --ground:#f4f7f8; --panel:#ffffff; --line:#d2dcdf; --ink:#0f1a1e; --dim:#5a6b70;
  --accent:#127d8c; --ok:#2f7d54; --slow:#a8761a; --bad:#c05621; --severe:#b02a41;
  --grid:#e3ebed;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --ground:#0c1316; --panel:#121c20; --line:#243237; --ink:#e6eef0; --dim:#8ea3a9;
    --accent:#4fc3d4; --ok:#5cbf8a; --slow:#d8a53f; --bad:#e8834e; --severe:#f0637f;
    --grid:#1b272c;
  }
}
:root[data-theme="dark"] {
  --ground:#0c1316; --panel:#121c20; --line:#243237; --ink:#e6eef0; --dim:#8ea3a9;
  --accent:#4fc3d4; --ok:#5cbf8a; --slow:#d8a53f; --bad:#e8834e; --severe:#f0637f;
  --grid:#1b272c;
}
* { box-sizing:border-box; }
body {
  margin:0; background:var(--ground); color:var(--ink);
  font:400 16px/1.6 "IBM Plex Sans", system-ui, sans-serif;
  padding:clamp(20px,4vw,56px);
}
.wrap { max-width:1000px; margin:0 auto; display:flex; flex-direction:column; gap:28px; }
header h1 {
  font:600 clamp(24px,3.4vw,36px)/1.15 "IBM Plex Sans", system-ui, sans-serif;
  margin:0 0 8px; letter-spacing:-.02em; text-wrap:balance;
}
header p { margin:0; color:var(--dim); max-width:66ch; }
.eyebrow {
  font:500 11px/1 "IBM Plex Mono", ui-monospace, monospace; letter-spacing:.16em;
  text-transform:uppercase; color:var(--accent); margin:0 0 12px;
}
ul.stats { list-style:none; margin:0; padding:0; display:flex; flex-wrap:wrap; gap:10px; }
ul.stats li {
  flex:1 1 190px; background:var(--panel); border:1px solid var(--line);
  border-radius:3px; padding:14px 16px; display:flex; flex-direction:column; gap:2px;
}
ul.stats b {
  font:600 21px/1.2 "IBM Plex Mono", ui-monospace, monospace;
  font-variant-numeric:tabular-nums;
}
ul.stats span { color:var(--dim); font-size:13px; }
.panel { background:var(--panel); border:1px solid var(--line); border-radius:3px; overflow-x:auto; }
table { width:100%; border-collapse:collapse; font-variant-numeric:tabular-nums; }
caption {
  text-align:left; padding:16px 18px 2px;
  font:500 12px/1 "IBM Plex Mono", ui-monospace, monospace;
  letter-spacing:.12em; text-transform:uppercase; color:var(--dim);
}
th, td { padding:9px 12px; text-align:left; border-bottom:1px solid var(--grid); }
thead th {
  font:500 11px/1 "IBM Plex Mono", ui-monospace, monospace; letter-spacing:.1em;
  text-transform:uppercase; color:var(--dim); border-bottom:1px solid var(--line);
}
tbody tr:last-child th, tbody tr:last-child td { border-bottom:none; }
.r th { font-weight:500; white-space:nowrap; }
.n { font-family:"IBM Plex Mono", ui-monospace, monospace; text-align:right; white-space:nowrap; }
.base { color:var(--dim); }
.track { width:42%; min-width:150px; }
.bar { display:block; height:9px; border-radius:1px; }
.ratio { font-weight:600; }
.bar.ok { background:var(--ok); }
.bar.slow { background:var(--slow); }
.bar.bad { background:var(--bad); }
.bar.severe { background:var(--severe); }
.ratio.ok { color:var(--ok); }
.ratio.slow { color:var(--slow); }
.ratio.bad { color:var(--bad); }
.ratio.severe { color:var(--severe); }
footer { color:var(--dim); font-size:14px; max-width:72ch; }
footer p { margin:0 0 10px; }
code { font-family:"IBM Plex Mono", ui-monospace, monospace; font-size:.92em; }
"""


def render(rows, blk, totals, logpath) -> str:
    bar_rows = []
    for ratio, name, ours, theirs in rows:
        cls = band(ratio)
        bar_rows.append(
            '<tr class="r"><th scope="row">' + _html.escape(name) + "</th>"
            + '<td class="n">' + format(ours, ",") + "</td>"
            + '<td class="n base">' + format(theirs, ",") + "</td>"
            + '<td class="track"><span class="bar ' + cls
            + '" style="width:' + format(width(ratio), ".1f") + '%"></span></td>'
            + '<td class="n ratio ' + cls + '">' + format(ratio, ".0f") + "&times;</td></tr>")

    blk_rows = []
    for op in ("read", "write", "flush", "other"):
        if op in blk:
            cnt, ms, avg = blk[op]
            blk_rows.append(
                '<tr><th scope="row">' + op + "</th>"
                + '<td class="n">' + format(cnt, ",") + "</td>"
                + '<td class="n">' + format(ms, ",") + " ms</td>"
                + '<td class="n">' + format(avg / 1000.0, ",.1f") + " &micro;s</td></tr>")

    stats = ""
    if totals:
        stats = ("<li><b>" + format(totals["calls"], ",") + "</b><span>syscalls in the boot</span></li>"
                 + "<li><b>" + format(totals["total_ms"], ",") + " ms</b><span>on CPU in the kernel</span></li>"
                 + "<li><b>" + format(totals["avg_ns"], ",") + " ns</b><span>average per call</span></li>")

    return (
        "<title>Syscall Cost Against Linux</title>\n"
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?'
        'family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap">\n'
        "<style>" + STYLE + "</style>\n"
        '<div class="wrap">\n'
        "  <header>\n"
        '    <p class="eyebrow">oxide kernel &middot; measured against the host</p>\n'
        "    <h1>How much more does a syscall cost here than on Linux?</h1>\n"
        "    <p>Both sides are measured on the same machine. The Linux figure is a tight loop "
        "over one shape of the call on the host kernel; the oxide figure is the average over "
        "every such call a real desktop boot made. Bars are log-scaled &mdash; the range runs "
        "from single digits to four figures.</p>\n"
        "  </header>\n"
        '  <ul class="stats">' + stats + "</ul>\n"
        '  <div class="panel"><table>\n'
        "    <caption>Cost per call, worst first</caption>\n"
        '    <thead><tr><th>operation</th><th class="n">oxide ns</th><th class="n">linux ns</th>'
        '<th>ratio</th><th class="n">&nbsp;</th></tr></thead>\n'
        "    <tbody>" + "".join(bar_rows) + "</tbody>\n"
        "  </table></div>\n"
        '  <div class="panel"><table>\n'
        "    <caption>Block device, same boot</caption>\n"
        '    <thead><tr><th>operation</th><th class="n">requests</th><th class="n">total</th>'
        '<th class="n">average</th></tr></thead>\n'
        "    <tbody>" + "".join(blk_rows) + "</tbody>\n"
        "  </table></div>\n"
        "  <footer>\n"
        "    <p>Run-to-run variance on the oxide side is large &mdash; the boot does not make the "
        "same mix of calls twice. A change is demonstrated here when it moves a row by more than "
        "about half, or across a colour band. Anything smaller needs repeated runs or a hosted "
        "microbenchmark.</p>\n"
        "    <p>Regenerate with <code>make perf-report</code>. Source: <code>"
        + _html.escape(str(logpath)) + "</code></p>\n"
        "  </footer>\n"
        "</div>\n")
