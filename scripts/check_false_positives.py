"""Scans popular, legitimate Java libraries from Maven Central and prints a table.

    python scripts/check_false_positives.py [download-folder]

Mods often bundle libraries like these, so anything flagged here is a likely false alarm in
real mods. Rerun it after changing a rule.
"""

import sys
import urllib.request
from pathlib import Path

from modscan.scanner import scan_bytes

MAVEN = "https://repo1.maven.org/maven2/"
LIBRARIES = [
    "com/google/code/gson/gson/2.11.0/gson-2.11.0.jar",
    "com/google/guava/guava/33.3.1-jre/guava-33.3.1-jre.jar",
    "org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.jar",
    "commons-io/commons-io/2.17.0/commons-io-2.17.0.jar",
    "com/fasterxml/jackson/core/jackson-databind/2.18.0/jackson-databind-2.18.0.jar",
    "com/squareup/okhttp3/okhttp/4.12.0/okhttp-4.12.0.jar",
    "org/jetbrains/kotlin/kotlin-stdlib/2.0.21/kotlin-stdlib-2.0.21.jar",
    "org/lwjgl/lwjgl/3.3.4/lwjgl-3.3.4.jar",
    "org/lwjgl/lwjgl/3.3.4/lwjgl-3.3.4-natives-windows.jar",
    "net/java/dev/jna/jna/5.15.0/jna-5.15.0.jar",
    "org/apache/logging/log4j/log4j-core/2.24.1/log4j-core-2.24.1.jar",
    "it/unimi/dsi/fastutil/8.5.15/fastutil-8.5.15.jar",
    "org/joml/joml/1.10.8/joml-1.10.8.jar",
    "com/github/ben-manes/caffeine/caffeine/3.1.8/caffeine-3.1.8.jar",
    "net/bytebuddy/byte-buddy/1.15.5/byte-buddy-1.15.5.jar",
]


def main() -> None:
    folder = Path(sys.argv[1] if len(sys.argv) > 1 else "samples/maven")
    folder.mkdir(parents=True, exist_ok=True)
    flagged = 0
    for path in LIBRARIES:
        target = folder / path.rsplit("/", 1)[-1]
        if not target.exists():
            urllib.request.urlretrieve(MAVEN + path, target)
        report = scan_bytes(target.read_bytes(), target.name)
        flagged += report.verdict != "no_known_threats"
        findings = ", ".join(f"{f.id} ({f.severity})" for f in report.findings) or "-"
        print(f"{target.name:40} {report.verdict_label:28} {report.score:3}  {findings}")
    print(f"\n{flagged} of {len(LIBRARIES)} flagged as suspicious or worse")


if __name__ == "__main__":
    main()
