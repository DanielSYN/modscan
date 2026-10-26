"""Scan a file and produce a report. The file is only ever read, never executed."""

import hashlib
import time
from dataclasses import asdict, dataclass, field
from pathlib import PurePath

from modscan import __version__
from modscan.archive import ArchiveError, is_zip
from modscan.jar import JarAnalysis, ModInfo, analyse_class, analyse_jar, sniff_kind
from modscan.rules import SEVERITY_WEIGHTS, Context, Finding, run_rules

VERDICT_LABELS = {
    "likely_malicious": "Likely malicious",
    "suspicious": "Suspicious",
    "no_known_threats": "No known malicious patterns",
}
LIKELY_MALICIOUS_SCORE = 60
SUSPICIOUS_SCORE = 20


class ScanError(ValueError):
    """The file can't be scanned (wrong type, corrupt)."""


@dataclass
class Report:
    file_name: str
    file_size: int
    sha256: str
    file_type: str
    verdict: str
    verdict_label: str
    score: int
    mods: list[ModInfo]
    stats: dict[str, int]
    findings: list[Finding]
    urls: list[dict[str, str]]
    ips: list[dict[str, str]]
    notes: list[str] = field(default_factory=list)
    scanner_version: str = __version__
    elapsed_ms: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def verdict_for(findings: list[Finding]) -> tuple[str, int]:
    score = min(100, sum(SEVERITY_WEIGHTS[f.severity] for f in findings))
    if score >= LIKELY_MALICIOUS_SCORE or any(f.severity == "critical" for f in findings):
        return "likely_malicious", score
    if score >= SUSPICIOUS_SCORE:
        return "suspicious", score
    return "no_known_threats", score


def scan_bytes(data: bytes, file_name: str) -> Report:
    started = time.monotonic()
    name = PurePath(file_name.replace("\\", "/")).name[:200] or "upload"
    sha256 = hashlib.sha256(data).hexdigest()

    analysis: JarAnalysis
    if is_zip(data):
        try:
            analysis = analyse_jar(data)
        except ArchiveError as exc:
            raise ScanError(f"This doesn't look like a valid .jar file: {exc}") from exc
        file_type = "Java archive (.jar)"
    elif sniff_kind(data) == "class":
        analysis = analyse_class(data, name)
        file_type = "Java class file (.class)"
    else:
        raise ScanError("ModScan reads .jar and .class files, and this file is neither.")

    findings = run_rules(ctx := Context(analysis, sha256))
    verdict, score = verdict_for(findings)
    return Report(
        file_name=name,
        file_size=len(data),
        sha256=sha256,
        file_type=file_type,
        verdict=verdict,
        verdict_label=VERDICT_LABELS[verdict],
        score=score,
        mods=analysis.mods,
        stats={
            "files": analysis.entry_count,
            "classes": len(analysis.classes),
            "unreadable_classes": len(analysis.unparseable),
            "nested_jars": len(analysis.nested_jars),
            "strings": sum(len(c.info.strings) for c in analysis.classes),
        },
        findings=findings,
        urls=[{"url": url, "location": location} for url, location in ctx.urls],
        ips=[{"ip": ip, "location": location} for ip, location in ctx.ips],
        notes=analysis.notes,
        elapsed_ms=round((time.monotonic() - started) * 1000),
    )
