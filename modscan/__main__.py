"""Command line: modscan scan FILE [FILE...]

Exit codes: 0 no known malicious patterns, 1 suspicious, 2 likely malicious, 3 a file couldn't
be scanned. That makes it usable as a gate in scripts and CI pipelines.
"""

import argparse
import json
import os
import sys
import textwrap
from pathlib import Path

from modscan import __version__
from modscan.rules import printable
from modscan.scanner import Report, ScanError, scan_bytes

MAX_FILE_BYTES = 256 * 1024 * 1024
EXIT_CODES = {"no_known_threats": 0, "suspicious": 1, "likely_malicious": 2}
EXIT_ERROR = 3

STYLES = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2",
          "likely_malicious": "1;41;97", "suspicious": "1;43;30", "no_known_threats": "1;42;30", "dim": "2"}


class Printer:
    def __init__(self, color: bool) -> None:
        self.color = color

    def style(self, text: str, key: str) -> str:
        return f"\033[{STYLES[key]}m{text}\033[0m" if self.color else text


def _size(n: int) -> str:
    return f"{n / 2**20:.1f} MB" if n >= 2**20 else f"{n / 1024:.0f} KB"


def render(report: Report, p: Printer) -> str:
    """Everything that came from the file goes through printable(): a hostile jar could otherwise
    put terminal control codes in a mod name or string and rewrite what you see."""
    lines = [f"{p.style(printable(report.file_name), 'dim')}  ({report.file_type}, {_size(report.file_size)})",
             f"SHA-256  {report.sha256}"]
    for mod in report.mods:
        details = " ".join(printable(x) for x in (mod.name or mod.id or "unnamed", mod.version or "") if x)
        authors = f" by {printable(', '.join(mod.authors))}" if mod.authors else ""
        lines.append(f"Mod      {mod.loader} · {details}{authors}")
    lines.append(f"Contents {report.stats['files']:,} files, {report.stats['classes']:,} classes")
    lines += ["", f"  {p.style(f' {report.verdict_label.upper()} ', report.verdict)}  risk score {report.score}/100", ""]

    for f in report.findings:
        attack = f"  [{f.attack_id} {f.attack_name}]" if f.attack_id else ""
        lines.append(f"  {p.style(f'{f.severity.upper():8}', f.severity)} {f.title}{p.style(attack, 'dim')}")
        lines += textwrap.wrap(f.description, 88, initial_indent="           ", subsequent_indent="           ")
        for e in f.evidence:
            where = f"  ({printable(e.location)})" if e.location else ""
            lines.append(f"           - {e.text}{p.style(where, 'dim')}")
        if f.evidence_total > len(f.evidence):
            lines.append(f"           … and {f.evidence_total - len(f.evidence)} more")
        lines.append("")

    if report.urls or report.ips:
        lines.append("Addresses found in the file:")
        lines += [f"  {printable(u['url'])}" for u in report.urls] + [f"  {i['ip']}" for i in report.ips]
        lines.append("")
    for note in report.notes:
        lines.append(p.style(f"Note: {printable(note)}", "dim"))
    lines.append(p.style("Static analysis shows what code could do, not what it did. No scanner can prove a file is "
                         "safe.", "dim"))
    return "\n".join(lines)


def explain(report: Report) -> str:
    from modscan.summary import SummaryError, summarise  # the Anthropic SDK is only needed for --explain

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return "(--explain needs your own Anthropic API key in the ANTHROPIC_API_KEY environment variable.)"
    try:
        return summarise(report.to_dict(), api_key)
    except SummaryError as exc:
        return f"(Couldn't get a summary: {exc})"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="modscan", description="Check Minecraft mods and other .jar files for "
                                     "malicious behaviour without running them.")
    parser.add_argument("--version", action="version", version=f"modscan {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan one or more .jar or .class files")
    scan.add_argument("files", nargs="+", type=Path)
    scan.add_argument("--json", action="store_true", help="print the full reports as JSON")
    scan.add_argument("--explain", action="store_true",
                      help="add a plain-English summary by Claude, using your API key from ANTHROPIC_API_KEY")
    args = parser.parse_args(argv)

    printer = Printer(color=sys.stdout.isatty() and "NO_COLOR" not in os.environ and not args.json)
    reports, worst, failed = [], 0, False
    for path in args.files:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                raise ScanError(f"larger than {MAX_FILE_BYTES // 2**20} MB")
            report = scan_bytes(path.read_bytes(), path.name)
        except (OSError, ScanError) as exc:
            print(f"{printable(str(path))}: {exc}", file=sys.stderr)
            failed = True
            continue
        worst = max(worst, EXIT_CODES[report.verdict])
        summary = explain(report) if args.explain else None
        if args.json:
            reports.append(report.to_dict() | ({"ai_summary": summary} if summary else {}))
        else:
            print(render(report, printer))
            if summary:
                print("\n" + printer.style("Claude's explanation (AI-generated; the verdict above comes from the "
                                           "scanner's rules):", "dim"))
                print(textwrap.fill(summary, 88, replace_whitespace=False))
            print()

    if args.json:
        print(json.dumps(reports, indent=2))
    return EXIT_ERROR if failed else worst


if __name__ == "__main__":
    sys.exit(main())
