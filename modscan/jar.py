"""Turns a jar into the facts the rules look at: parsed classes, resources, metadata."""

import json
import math
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from modscan.archive import MAX_NESTING_DEPTH, Budget, iter_entries, is_zip
from modscan.classfile import MAGIC as CLASS_MAGIC
from modscan.classfile import ClassFormatError, ClassInfo, parse_class

# Folders where mod loaders legitimately bundle library jars ("jar-in-jar").
NESTED_JAR_DIRS = ("META-INF/jars/", "META-INF/jarjar/", "META-INF/libraries/", "META-INF/libs/")
NATIVE_EXTENSIONS = {".dll", ".so", ".dylib", ".jnilib"}
TEXT_EXTENSIONS = {".json", ".txt", ".properties", ".cfg", ".conf", ".yml", ".yaml", ".toml", ".ini", ".mcmeta", ""}
MAX_TEXT_RESOURCE_BYTES = 512 * 1024
MAX_LINES_PER_RESOURCE = 5_000
ENTROPY_SAMPLE_BYTES = 1024 * 1024
MAX_FIELD_LENGTH = 200


@dataclass
class ParsedClass:
    path: str
    info: ClassInfo


@dataclass
class Resource:
    path: str
    size: int
    kind: str | None  # what the content really is: class, windows-exe, linux-elf, macos-macho, zip, or None
    entropy: float | None
    text_lines: list[str] = field(default_factory=list)

    @property
    def extension(self) -> str:
        return PurePosixPath(self.path.rsplit("!/", 1)[-1]).suffix.lower()


@dataclass
class ModInfo:
    loader: str
    id: str | None = None
    name: str | None = None
    version: str | None = None
    description: str | None = None
    authors: list[str] = field(default_factory=list)


@dataclass
class JarAnalysis:
    classes: list[ParsedClass] = field(default_factory=list)
    unparseable: list[tuple[str, str]] = field(default_factory=list)
    resources: list[Resource] = field(default_factory=list)
    nested_jars: list[str] = field(default_factory=list)
    manifest: dict[str, str] = field(default_factory=dict)
    mods: list[ModInfo] = field(default_factory=list)
    odd_entry_names: list[str] = field(default_factory=list)
    entry_count: int = 0
    notes: list[str] = field(default_factory=list)


def sniff_kind(data: bytes) -> str | None:
    """What a file really is, judged by its first bytes rather than its name."""
    head = data[:8]
    if head[:4] == CLASS_MAGIC and len(data) >= 8:
        # Mach-O universal binaries share the CAFEBABE magic; class files have a major version >= 45.
        return "class" if int.from_bytes(head[6:8], "big") >= 45 else "macos-macho"
    if head[:2] == b"MZ":
        return "windows-exe"
    if head[:4] == b"\x7fELF":
        return "linux-elf"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macos-macho"
    if is_zip(data):
        return "zip"
    return None


def shannon_entropy(data: bytes) -> float:
    """Bits per byte, 0-8. Encrypted or compressed data is close to 8."""
    sample = data[:ENTROPY_SAMPLE_BYTES]
    if not sample:
        return 0.0
    total = len(sample)
    return -sum(c / total * math.log2(c / total) for c in Counter(sample).values())


def _clip(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:MAX_FIELD_LENGTH] if text else None


def _authors(value) -> list[str]:
    if isinstance(value, str):
        value = [a.strip() for a in value.split(",")]
    if isinstance(value, dict):
        value = list(value.keys())
    if not isinstance(value, list):
        return []
    names = [a.get("name") if isinstance(a, dict) else a for a in value]
    return [_clip(n) for n in names if _clip(n)][:10]


def _simple_yaml(text: str) -> dict[str, str]:
    """Top-level 'key: value' pairs only; enough for plugin.yml metadata without a YAML library."""
    result = {}
    for line in text.splitlines():
        if line and not line[0].isspace() and ":" in line and not line.startswith("#"):
            key, _, value = line.partition(":")
            result[key.strip()] = value.strip().strip("'\"")
    return result


def parse_mod_metadata(path: str, data: bytes, manifest: dict[str, str]) -> ModInfo | None:
    """Read the mod's description of itself. Values are untrusted and only displayed."""
    try:
        text = data.decode("utf-8-sig")
        if path == "fabric.mod.json":
            d = json.loads(text)
            return ModInfo("Fabric", _clip(d.get("id")), _clip(d.get("name")), _clip(d.get("version")),
                           _clip(d.get("description")), _authors(d.get("authors")))
        if path == "quilt.mod.json":
            q = json.loads(text).get("quilt_loader", {})
            meta = q.get("metadata", {})
            return ModInfo("Quilt", _clip(q.get("id")), _clip(meta.get("name")), _clip(q.get("version")),
                           _clip(meta.get("description")), _authors(meta.get("contributors")))
        if path in ("META-INF/mods.toml", "META-INF/neoforge.mods.toml"):
            d = tomllib.loads(text)
            mod = (d.get("mods") or [{}])[0]
            version = mod.get("version")
            if isinstance(version, str) and "${" in version:
                version = manifest.get("Implementation-Version", version)
            return ModInfo("NeoForge" if "neoforge" in path else "Forge", _clip(mod.get("modId")),
                           _clip(mod.get("displayName")), _clip(version), _clip(mod.get("description")),
                           _authors(mod.get("authors") or d.get("authors")))
        if path == "mcmod.info":
            d = json.loads(text)
            mod = (d.get("modList") if isinstance(d, dict) else d)[0]
            return ModInfo("Forge (legacy)", _clip(mod.get("modid")), _clip(mod.get("name")),
                           _clip(mod.get("version")), _clip(mod.get("description")), _authors(mod.get("authorList")))
        if path == "velocity-plugin.json":
            d = json.loads(text)
            return ModInfo("Velocity", _clip(d.get("id")), _clip(d.get("name")), _clip(d.get("version")),
                           _clip(d.get("description")), _authors(d.get("authors")))
        if path in ("plugin.yml", "paper-plugin.yml", "bungee.yml"):
            d = _simple_yaml(text)
            loader = {"plugin.yml": "Bukkit/Spigot", "paper-plugin.yml": "Paper", "bungee.yml": "BungeeCord"}[path]
            return ModInfo(loader, None, _clip(d.get("name")), _clip(d.get("version")),
                           _clip(d.get("description")), _authors(d.get("authors") or d.get("author")))
    except (ValueError, TypeError, AttributeError, IndexError, KeyError, tomllib.TOMLDecodeError):
        return None
    return None


METADATA_FILES = {"fabric.mod.json", "quilt.mod.json", "META-INF/mods.toml", "META-INF/neoforge.mods.toml",
                  "mcmod.info", "velocity-plugin.json", "plugin.yml", "paper-plugin.yml", "bungee.yml"}


def parse_manifest(data: bytes) -> dict[str, str]:
    """Main section of META-INF/MANIFEST.MF. Lines starting with a space continue the previous one."""
    result: dict[str, str] = {}
    last = None
    for line in data.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            break  # end of the main section
        if line.startswith(" ") and last:
            result[last] += line[1:]
        elif ":" in line:
            key, _, value = line.partition(":")
            last = key.strip()
            result[last] = value.strip()
    return {k: v[:500] for k, v in result.items()}


def _text_lines(data: bytes) -> list[str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return []
    return [line.strip() for line in text.splitlines()[:MAX_LINES_PER_RESOURCE] if line.strip()]


def analyse_jar(data: bytes, budget: Budget | None = None) -> JarAnalysis:
    budget = budget or Budget()
    analysis = JarAnalysis()
    _walk(data, analysis, budget, label="", depth=0)
    analysis.notes = budget.notes
    return analysis


def analyse_class(data: bytes, name: str) -> JarAnalysis:
    analysis = JarAnalysis(entry_count=1)
    try:
        analysis.classes.append(ParsedClass(name, parse_class(data)))
    except ClassFormatError as exc:
        analysis.unparseable.append((name, str(exc)))
    return analysis


def _walk(data: bytes, analysis: JarAnalysis, budget: Budget, label: str, depth: int) -> None:
    seen: set[str] = set()
    pending_metadata: list[tuple[str, bytes]] = []
    for entry in iter_entries(data, budget, label):
        analysis.entry_count += 1
        inner = entry.name[len(label):]
        if inner in seen or ".." in inner.split("/") or inner.startswith("/") or "\\" in inner:
            analysis.odd_entry_names.append(entry.name)
        seen.add(inner)

        if inner.endswith(".class"):
            try:
                analysis.classes.append(ParsedClass(entry.name, parse_class(entry.data)))
            except ClassFormatError as exc:
                analysis.unparseable.append((entry.name, str(exc)))
            continue

        if depth == 0 and inner == "META-INF/MANIFEST.MF":
            analysis.manifest = parse_manifest(entry.data)
        if depth == 0 and inner in METADATA_FILES:
            pending_metadata.append((inner, entry.data))

        kind = sniff_kind(entry.data)
        resource = Resource(entry.name, len(entry.data), kind, None)
        if kind == "zip" and PurePosixPath(inner).suffix.lower() in (".jar", ".zip"):
            analysis.nested_jars.append(entry.name)
            if depth + 1 <= MAX_NESTING_DEPTH:
                try:
                    _walk(entry.data, analysis, budget, label=f"{entry.name}!/", depth=depth + 1)
                except ValueError as exc:
                    budget.notes.append(f"Couldn't open nested archive {entry.name}: {exc}")
            else:
                budget.notes.append(f"Didn't open {entry.name}: archives nested more than "
                                    f"{MAX_NESTING_DEPTH} deep aren't scanned.")
            continue
        if kind is None and len(entry.data) >= 4096:
            resource.entropy = round(shannon_entropy(entry.data), 2)
        if (kind is None and resource.extension in TEXT_EXTENSIONS
                and len(entry.data) <= MAX_TEXT_RESOURCE_BYTES):
            resource.text_lines = _text_lines(entry.data)
        analysis.resources.append(resource)

    for path, raw in pending_metadata:  # after the manifest, which mods.toml versions can refer to
        mod = parse_mod_metadata(path, raw, analysis.manifest)
        if mod:
            analysis.mods.append(mod)
