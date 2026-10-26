"""Reads entries out of a zip/jar entirely in memory, with hard limits.

Uploaded archives are hostile by assumption: nothing is extracted to disk, nothing is
executed, and every read is capped so a zip bomb (a tiny file that inflates to
gigabytes) or an archive with millions of entries can't exhaust memory or CPU.
"""

import io
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field

MAX_ENTRIES = 50_000
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
# Real jars compress 3-10x. A large entry compressing far better than that is a bomb.
MAX_COMPRESSION_RATIO = 200
MAX_NESTING_DEPTH = 2


class ArchiveError(ValueError):
    """Not a readable zip/jar at all."""


@dataclass
class Budget:
    """Shared across an archive and the jars nested inside it."""
    bytes_left: int = MAX_TOTAL_BYTES
    entries_left: int = MAX_ENTRIES
    notes: list[str] = field(default_factory=list)


@dataclass
class Entry:
    name: str
    data: bytes
    compressed_size: int


def is_zip(data: bytes) -> bool:
    return data[:4] in (b"PK\x03\x04", b"PK\x05\x06")


def iter_entries(data: bytes, budget: Budget, label: str = "") -> Iterator[Entry]:
    """Yield each file in the archive. Entries that break a limit are skipped and noted."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, EOFError) as exc:
        raise ArchiveError(f"not a valid jar/zip archive ({exc})") from exc

    for info in infos:
        name = f"{label}{info.filename}"
        if info.is_dir():
            continue
        if budget.entries_left <= 0:
            budget.notes.append(f"Stopped after {MAX_ENTRIES:,} files: the archive has more than the scan limit.")
            return
        budget.entries_left -= 1

        if info.file_size > MAX_ENTRY_BYTES:
            budget.notes.append(f"Skipped {name}: larger than {MAX_ENTRY_BYTES // 2**20} MB uncompressed.")
            continue
        if info.file_size > 2**20 and info.file_size > MAX_COMPRESSION_RATIO * max(info.compress_size, 1):
            budget.notes.append(f"Skipped {name}: compresses {info.file_size // max(info.compress_size, 1):,}x, "
                                "a sign of a zip bomb.")
            continue

        # The sizes in the zip header can lie, so the real limit is how much we actually read.
        limit = min(MAX_ENTRY_BYTES, budget.bytes_left)
        try:
            with archive.open(info) as stream:
                content = stream.read(limit + 1)
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError, ValueError, EOFError, OSError) as exc:
            budget.notes.append(f"Couldn't read {name}: {exc}.")
            continue
        if len(content) > limit:
            budget.notes.append(f"Stopped at {name}: the scan's {MAX_TOTAL_BYTES // 2**20} MB read limit was reached."
                                if limit == budget.bytes_left else f"Skipped {name}: too large.")
            if limit == budget.bytes_left:
                return
            continue
        budget.bytes_left -= len(content)
        yield Entry(name=name, data=content, compressed_size=info.compress_size)
