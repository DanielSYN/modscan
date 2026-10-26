"""Detection rules: what the jar's code and contents suggest it would do if run.

Every rule explains itself in plain English, carries a MITRE ATT&CK technique ID (the
shared vocabulary security teams use), and returns the exact evidence that triggered it.
Severity reflects how rarely legitimate mods do the thing, not how bad it sounds.
"""

import base64
import binascii
import ipaddress
import json
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from urllib.parse import urlsplit

from modscan.jar import NATIVE_EXTENSIONS, NESTED_JAR_DIRS, JarAnalysis, sniff_kind

SEVERITY_WEIGHTS = {"critical": 40, "high": 25, "medium": 12, "low": 4, "info": 0}
SEVERITY_ORDER = list(SEVERITY_WEIGHTS)
MAX_EVIDENCE = 10
MAX_EVIDENCE_CHARS = 200
MAX_IOCS = 50


@dataclass
class Evidence:
    text: str
    location: str


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    description: str
    attack_id: str | None
    attack_name: str | None
    evidence: list[Evidence]
    evidence_total: int


@dataclass
class StringHit:
    text: str      # as found (or as decoded from base64)
    norm: str      # lowercase, backslashes turned into slashes, for matching
    location: str
    in_code: bool  # a string literal in a class, as opposed to a line of a text resource


@dataclass
class RefHit:
    owner: str
    name: str
    location: str

    def __str__(self) -> str:
        return f"{self.owner.replace('/', '.')}.{self.name}"


def printable(text: str) -> str:
    """Show invisible and control characters as \\uXXXX so evidence is readable and safe to display."""
    shown = "".join(f"\\u{ord(ch):04x}" if unicodedata.category(ch).startswith("C") and ch != " " else ch
                    for ch in text[:MAX_EVIDENCE_CHARS])
    return shown + ("…" if len(text) > MAX_EVIDENCE_CHARS else "")


def _normalise(text: str) -> str:
    return text.replace("\\", "/").lower()


BASE64_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")


def _b64decode(text: str) -> bytes | None:
    if not BASE64_RE.fullmatch(text) or len(text.rstrip("=")) % 4 == 1:
        return None
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_" if "-" in text or "_" in text else None)
    except (binascii.Error, ValueError):
        return None


def _mostly_printable(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    readable = sum(ch.isprintable() or ch in "\t\n\r" for ch in text)
    return text if text and readable / len(text) >= 0.9 else None


# --- Indicators of compromise (URLs and IP addresses) ------------------------------

URL_RE = re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>\\^`{|}]+", re.I)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# Namespace URLs that appear in ordinary XML/JSON libraries; listing them is just noise.
NOISE_HOSTS = {"www.w3.org", "w3.org", "xml.org", "java.sun.com", "xml.apache.org", "apache.org", "www.apache.org",
               "purl.org", "json-schema.org", "ns.adobe.com", "xmlpull.org", "textures.minecraft.net"}


def _public_ip(text: str) -> str | None:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


def extract_iocs(strings: list[StringHit]) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    urls: dict[str, str] = {}
    ips: dict[str, str] = {}
    for hit in strings:
        if "://" in hit.text:
            for url in URL_RE.findall(hit.text):
                url = url.rstrip(".,;:)]}")
                host = urlsplit(url).hostname or ""
                if host and host not in NOISE_HOSTS and len(urls) < MAX_IOCS:
                    urls.setdefault(url, hit.location)
        if any(ch.isdigit() for ch in hit.text):
            for candidate in IPV4_RE.findall(hit.text):
                ip = _public_ip(candidate)
                if ip and len(ips) < MAX_IOCS:
                    ips.setdefault(ip, hit.location)
    return list(urls.items()), list(ips.items())


@cache
def known_iocs() -> dict:
    return json.loads((Path(__file__).parent / "data" / "known_iocs.json").read_text())


# --- What the rules look at ----------------------------------------------------------

class Context:
    def __init__(self, analysis: JarAnalysis, sha256: str = "") -> None:
        self.analysis = analysis
        self.sha256 = sha256
        self.strings: list[StringHit] = []
        self.refs: list[RefHit] = []
        self.referenced_classes: list[tuple[str, str]] = []
        for parsed in analysis.classes:
            for text in parsed.info.strings:
                self.strings.append(StringHit(text, _normalise(text), parsed.path, True))
                decoded = _b64decode(text)
                plain = _mostly_printable(decoded) if decoded else None
                if plain and len(plain) >= 8:
                    self.strings.append(StringHit(f"{plain} (decoded from base64 {text[:40]}…)",
                                                  _normalise(plain), parsed.path, True))
            for ref in parsed.info.method_refs:
                self.refs.append(RefHit(ref.owner, ref.name, parsed.path))
            for name in parsed.info.referenced_classes:
                self.referenced_classes.append((name, parsed.path))
        for resource in analysis.resources:
            for line in resource.text_lines:
                self.strings.append(StringHit(line, _normalise(line), resource.path, False))
        self.urls, self.ips = extract_iocs(self.strings)

    def has_ref(self, predicate: Callable[[RefHit], bool]) -> bool:
        return any(predicate(ref) for ref in self.refs)


Check = Callable[[Context, set[str]], list[Evidence]]


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    description: str
    attack: tuple[str, str] | None
    check: Check


def _dedupe(evidence: list[Evidence]) -> list[Evidence]:
    seen, unique = set(), []
    for item in evidence:
        key = (item.text, item.location)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def strings_matching(pattern: str, code_only: bool = False) -> Check:
    regex = re.compile(pattern)

    def check(ctx: Context, _: set[str]) -> list[Evidence]:
        return [Evidence(printable(s.text), s.location) for s in ctx.strings
                if (s.in_code or not code_only) and regex.search(s.norm)]
    return check


def refs_matching(predicate: Callable[[RefHit], bool]) -> Check:
    def check(ctx: Context, _: set[str]) -> list[Evidence]:
        return [Evidence(f"calls {ref}", ref.location) for ref in ctx.refs if predicate(ref)]
    return check


def any_of(*checks: Check) -> Check:
    def check(ctx: Context, triggered: set[str]) -> list[Evidence]:
        return [e for c in checks for e in c(ctx, triggered)]
    return check


def combination(requires_all: list[set[str]]) -> Check:
    """Triggers when, for every group, at least one rule in that group already triggered."""
    def check(ctx: Context, triggered: set[str]) -> list[Evidence]:
        if all(group & triggered for group in requires_all):
            parts = sorted(set().union(*requires_all) & triggered)
            return [Evidence("Combination of: " + ", ".join(RULES_BY_ID[p].title for p in parts), "")]
        return []
    return check


def _alternation(*words: str) -> str:
    return "|".join(re.escape(w) for w in words)


# --- Individual checks ----------------------------------------------------------------

def check_known_iocs(ctx: Context, _: set[str]) -> list[Evidence]:
    iocs = known_iocs()
    evidence = []
    if ctx.sha256 in iocs["sha256"]:
        evidence.append(Evidence(f"File hash matches known malware: {iocs['sha256'][ctx.sha256]}", "whole file"))
    for ip, location in ctx.ips:
        if ip in iocs["ips"]:
            evidence.append(Evidence(f"{ip}: {iocs['ips'][ip]}", location))
    for url, location in ctx.urls:
        host = urlsplit(url).hostname or ""
        if host in iocs["ips"] or host in iocs["domains"]:
            evidence.append(Evidence(f"{url}: {iocs['ips'].get(host) or iocs['domains'][host]}", location))
    return evidence


STAGING_DOMAINS = ("pastebin.com", "hastebin.com", "paste.ee", "rentry.co", "rentry.org", "controlc.com",
                   "transfer.sh", "file.io", "gofile.io", "anonfiles.com", "catbox.moe", "temp.sh", "ngrok.io",
                   "ngrok-free.app", "ngrok.app", "trycloudflare.com", "duckdns.org", "ddns.net", "hopto.org",
                   "zapto.org", "no-ip.com", "serveo.net", "webhook.site", "pipedream.net")


def check_suspicious_hosts(ctx: Context, _: set[str]) -> list[Evidence]:
    evidence = []
    for url, location in ctx.urls:
        host = (urlsplit(url).hostname or "").lower()
        if _public_ip(host):
            evidence.append(Evidence(f"{printable(url)} (a raw IP address instead of a domain name)", location))
        elif any(host == d or host.endswith("." + d) for d in STAGING_DOMAINS):
            evidence.append(Evidence(f"{printable(url)} (a paste, file-sharing, tunnel or dynamic-DNS service)",
                                     location))
        elif re.search(r"(cdn|media)\.discordapp\.(com|net)/attachments/", url.lower()):
            evidence.append(Evidence(f"{printable(url)} (a file uploaded to Discord)", location))
    return evidence


def _looks_obfuscated(segment: str) -> bool:
    if not segment or segment.isdigit():
        return False  # anonymous inner classes are numbered: Foo$1
    if len(segment) <= 2 or segment in JAVA_KEYWORDS:
        return True
    if not all(ch.isascii() and (ch.isalnum() or ch in "_") for ch in segment):
        return True  # invisible, Unicode look-alike or otherwise unusual characters
    return len(segment) >= 4 and (set(segment) <= set("Il1") or set(segment) <= set("O0"))


JAVA_KEYWORDS = set("abstract assert boolean break byte case catch char class const continue default do double else "
                    "enum extends final finally float for goto if implements import instanceof int interface long "
                    "native new package private protected public return short static strictfp super switch "
                    "synchronized this throw throws transient try void volatile while".split())


def check_obfuscated_names(ctx: Context, _: set[str]) -> list[Evidence]:
    names = [p.info.name for p in ctx.analysis.classes
             if not p.info.name.endswith(("package-info", "module-info"))]
    if len(names) < 5:
        return []
    odd = []
    for name in names:
        segments = name.rsplit("/", 1)[-1].split("$")
        last = segments[-1] if len(segments) > 1 else ""
        if _looks_obfuscated(segments[0]) or (last and not last.isdigit() and _looks_obfuscated(last)):
            odd.append(name)
    ratio = len(odd) / len(names)
    if ratio < 0.4:
        return []
    summary = Evidence(f"{len(odd)} of {len(names)} classes ({ratio:.0%}) have meaningless names", "")
    return [summary] + [Evidence(printable(n.replace("/", ".")), "") for n in odd[:MAX_EVIDENCE - 1]]


def _string_looks_encrypted(text: str) -> bool:
    if len(text) < 6:
        return False
    weird = sum(1 for ch in text
                if ch == "�" or (unicodedata.category(ch) in ("Cc", "Co", "Cn", "Cs") and ch not in "\t\n\r"))
    if weird / len(text) >= 0.2:
        return True
    # Real base64 of this length almost always contains a digit; long identifiers often don't.
    if len(text) >= 40 and " " not in text and any(ch.isdigit() for ch in text):
        decoded = _b64decode(text)
        return decoded is not None and len(decoded) >= 24 and _mostly_printable(decoded) is None
    return False


def check_encrypted_strings(ctx: Context, _: set[str]) -> list[Evidence]:
    candidates = [s for s in ctx.strings if s.in_code and len(s.text) >= 6 and "decoded from base64" not in s.text]
    hidden = [s for s in candidates if _string_looks_encrypted(s.text)]
    if len(hidden) < 5 or (len(hidden) / len(candidates) < 0.15 and len(hidden) < 25):
        return []
    summary = Evidence(f"{len(hidden)} of {len(candidates)} text strings ({len(hidden) / len(candidates):.0%}) "
                       "are unreadable or encoded", "")
    return [summary] + [Evidence(printable(s.text), s.location) for s in hidden[:MAX_EVIDENCE - 1]]


EXECUTABLE_KINDS = {"class": "a compiled Java class", "windows-exe": "a Windows program or DLL",
                    "linux-elf": "a Linux program or library", "macos-macho": "a macOS program or library",
                    "zip": "an archive (possibly another jar)"}
EXPECTED_EXTENSIONS = {"class": {".class"}, "windows-exe": {".dll", ".exe", ".sys"},
                       "linux-elf": {".so"}, "macos-macho": {".dylib", ".jnilib"}}
DISGUISE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ogg", ".wav", ".mp3", ".txt", ".json", ".lang",
                       ".properties", ".cfg", ".yml", ".yaml", ".toml", ".nbt", ".dat", ".bin", ".mcmeta", ""}
SCRIPT_EXTENSIONS = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".jse", ".wsf", ".hta", ".scr", ".lnk", ".msi",
                     ".sh", ".command"}


def _is_versioned_shared_lib(path: str) -> bool:
    return bool(re.search(r"\.so(\.\d+)+$", path))


def check_embedded_payloads(ctx: Context, _: set[str]) -> list[Evidence]:
    evidence = []
    for res in ctx.analysis.resources:
        if res.kind in EXPECTED_EXTENSIONS and res.extension not in EXPECTED_EXTENSIONS[res.kind] \
                and not (res.kind == "linux-elf" and _is_versioned_shared_lib(res.path)):
            evidence.append(Evidence(f"{res.path} is really {EXECUTABLE_KINDS[res.kind]}", res.path))
        elif res.kind == "zip" and res.extension in DISGUISE_EXTENSIONS:
            evidence.append(Evidence(f"{res.path} is really {EXECUTABLE_KINDS['zip']}", res.path))
        elif res.extension in SCRIPT_EXTENSIONS:
            evidence.append(Evidence(f"{res.path}: a {res.extension} file has no reason to be inside a mod", res.path))
    for s in ctx.strings:
        if s.in_code and len(s.text) >= 100:
            decoded = _b64decode(s.text)
            kind = sniff_kind(decoded) if decoded else None
            if kind:
                evidence.append(Evidence(f"A base64 string decodes to {EXECUTABLE_KINDS[kind]}: "
                                         f"{printable(s.text[:60])}…", s.location))
    return evidence


def check_native_code(ctx: Context, triggered: set[str]) -> list[Evidence]:
    evidence = refs_matching(lambda r: r.owner in ("java/lang/System", "java/lang/Runtime")
                             and r.name in ("load", "loadLibrary"))(ctx, triggered)
    evidence += [Evidence(f"bundles native library {res.path}", res.path) for res in ctx.analysis.resources
                 if res.extension in NATIVE_EXTENSIONS or _is_versioned_shared_lib(res.path)]
    return evidence


def check_encrypted_resources(ctx: Context, _: set[str]) -> list[Evidence]:
    return [Evidence(f"{res.path}: {res.size:,} bytes, entropy {res.entropy} bits/byte", res.path)
            for res in ctx.analysis.resources
            if res.entropy is not None and res.entropy >= 7.5 and res.extension not in COMPRESSED_EXTENSIONS]


COMPRESSED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ogg", ".mp3", ".zip", ".jar", ".gz", ".xz",
                         ".zst", ".bz2", ".7z", ".woff", ".woff2", ".nbt", ".mca", ".schem", ".schematic", ".litematic",
                         ".ttf", ".otf", ".jks", ".p12", ".der", ".cer", ".crt", ".dat", ".bin", ".pack", ".lzma"}


def check_odd_nested_jars(ctx: Context, _: set[str]) -> list[Evidence]:
    return [Evidence(f"{path} is a jar stored outside the folders mod loaders use for bundled libraries", path)
            for path in ctx.analysis.nested_jars
            if not path.rsplit("!/", 1)[-1].startswith(NESTED_JAR_DIRS)]


def check_malformed_classes(ctx: Context, _: set[str]) -> list[Evidence]:
    return [Evidence(reason, path) for path, reason in ctx.analysis.unparseable]


def check_archive_anomalies(ctx: Context, _: set[str]) -> list[Evidence]:
    return [Evidence(f"unusual entry name: {printable(name)}", name) for name in ctx.analysis.odd_entry_names]


def check_java_agent(ctx: Context, triggered: set[str]) -> list[Evidence]:
    evidence = [Evidence(f"MANIFEST.MF declares {key}: {printable(value)}", "META-INF/MANIFEST.MF")
                for key, value in ctx.analysis.manifest.items()
                if key in ("Premain-Class", "Agent-Class", "Launcher-Agent-Class")]
    return evidence + refs_matching(lambda r: r.owner == "java/lang/instrument/Instrumentation"
                                    and r.name in ("addTransformer", "redefineClasses", "retransformClasses"))(
        ctx, triggered)


NETWORK_REFS = {
    "java/net/URL": {"openConnection", "openStream"},
    "java/net/URLConnection": {"getInputStream", "getOutputStream", "connect"},
    "java/net/HttpURLConnection": {"getInputStream", "getOutputStream", "connect", "setRequestMethod"},
    "java/net/http/HttpClient": {"send", "sendAsync", "newHttpClient", "newBuilder"},
    "java/net/Socket": {"<init>", "connect"},
    "java/net/DatagramSocket": {"<init>", "send"},
    "okhttp3/OkHttpClient": {"newCall"},
    "org/apache/http/impl/client/HttpClients": {"createDefault", "custom"},
}
PROCESS_REFS = {("java/lang/Runtime", "exec"), ("java/lang/ProcessBuilder", "start"),
                ("java/lang/ProcessBuilder", "<init>")}
SESSION_STRINGS = ("method_1674", "func_148254_d")  # getAccessToken in Fabric and Forge runtime names
SESSION_CLASSES = ("net/minecraft/client/User", "net/minecraft/client/util/Session", "net/minecraft/util/Session")
REFLECTION_REFS = {("java/lang/Class", "forName"), ("java/lang/ClassLoader", "loadClass"),
                   ("java/lang/reflect/Method", "invoke"), ("java/lang/invoke/MethodHandles$Lookup", "findStatic"),
                   ("java/lang/invoke/MethodHandles$Lookup", "findVirtual"), ("java/lang/Class", "getMethod"),
                   ("java/lang/Class", "getDeclaredMethod")}
HIDDEN_CLASS_NAMES = {"java.lang.runtime", "java/lang/runtime", "java.lang.processbuilder", "java/lang/processbuilder",
                      "java.net.urlclassloader", "java/net/urlclassloader", "getruntime"}


def check_reflection_hiding(ctx: Context, _: set[str]) -> list[Evidence]:
    if not ctx.has_ref(lambda r: (r.owner, r.name) in REFLECTION_REFS):
        return []
    return [Evidence(f"looks up {printable(s.text)} by name", s.location)
            for s in ctx.strings if s.in_code and s.norm.strip() in HIDDEN_CLASS_NAMES]


def check_downloader(ctx: Context, triggered: set[str]) -> list[Evidence]:
    """Network access and code loading in the same class. Big libraries often do both in unrelated
    places; loaders like fractureiser's fetch bytes and run them in one spot."""
    evidence = []
    for parsed in ctx.analysis.classes:
        info = parsed.info
        loader = next((r for r in info.method_refs if _loads_code(r.owner, r.name)), None)
        if loader is None:
            continue
        network = next((r for r in info.method_refs if _uses_network(r.owner, r.name)), None)
        address = next((s for s in info.strings if "://" in s or s.lower() in ("http", "https")
                        or any(_public_ip(ip) for ip in IPV4_RE.findall(s))), None)
        if network or address:
            dotted = lambda ref: f"{ref.owner.replace('/', '.')}.{ref.name}"  # noqa: E731
            source = f"calls {dotted(network)}" if network else f"uses the address {printable(address)!r}"
            evidence.append(Evidence(f"loads code with {dotted(loader)} and {source}", parsed.path))
    if {"embedded_payload", "network"} <= triggered:
        evidence.append(Evidence("carries a hidden payload and connects to the internet", ""))
    return evidence


def check_session_token(ctx: Context, _: set[str]) -> list[Evidence]:
    evidence = [Evidence(f"calls {ref} (returns your Minecraft login token)", ref.location) for ref in ctx.refs
                if ref.name in SESSION_STRINGS
                or (ref.owner in SESSION_CLASSES and ref.name in ("getAccessToken", "getSessionId"))]
    evidence += [Evidence(f"looks up {s.text} by name (your Minecraft login token)", s.location)
                 for s in ctx.strings if s.in_code and s.text in SESSION_STRINGS]
    return evidence


def _loads_code(owner: str, name: str) -> bool:
    return (name in ("defineClass", "defineHiddenClass", "defineAnonymousClass")
            or (owner == "java/net/URLClassLoader" and name in ("<init>", "newInstance"))
            or (owner == "javax/script/ScriptEngine" and name == "eval"))


def _uses_network(owner: str, name: str) -> bool:
    return name in NETWORK_REFS.get(owner, ())


def check_dynamic_code(ctx: Context, triggered: set[str]) -> list[Evidence]:
    evidence = refs_matching(lambda r: _loads_code(r.owner, r.name))(ctx, triggered)
    if ctx.has_ref(lambda r: (r.owner, r.name) in REFLECTION_REFS):
        evidence += [Evidence(f"looks up {s.text} by name", s.location)
                     for s in ctx.strings if s.in_code and s.norm in ("defineclass", "definehiddenclass")]
    return evidence


# --- The rule list ----------------------------------------------------------------------
# Combination rules come after the rules they depend on.

CREDENTIAL_PATTERN = "|".join([
    r"(?:^|/)login data\b", r"(?:^|/)web data\b", r"(?:^|/)local state\b", r"network/cookies", r"default/cookies",
    _alternation("encrypted_key", "os_crypt", "logins.json", "key4.db", "cookies.sqlite", "signons.sqlite",
                 "google/chrome/user data", "bravesoftware/brave-browser", "microsoft/edge/user data",
                 "opera software/opera", "mozilla/firefox/profiles", "yandex/yandexbrowser",
                 "discord/local storage", "discordcanary", "discordptb", "lightcord", "dqw4w9wgxcq:",
                 "local storage/leveldb", "wallet.dat", "exodus.wallet", "electrum/wallets", "atomic/local storage",
                 "metamask", "nkbihfbeogaeaoehlefnkodbefgpgknn", "ethereum/keystore", "coinomi", "bitcoin/wallets",
                 "telegram desktop/tdata", "steam/config/loginusers.vdf", "filezilla/recentservers.xml",
                 "filezilla/sitemanager.xml", ".ssh/id_rsa", ".aws/credentials"),
])
LAUNCHER_ACCOUNTS_PATTERN = _alternation(
    "launcher_accounts.json", "launcher_accounts_microsoft_store.json", "essential/microsoft_accounts.json",
    "lunarclient/settings/game/accounts.json", "feather/accounts.json", "prismlauncher/accounts.json",
    "polymc/accounts.json", "multimc/accounts.json")
WEBHOOK_PATTERN = (r"discord(?:app)?\.com/api/(?:v\d+/)?webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/"
                   r"|webhook\.site/|\.m\.pipedream\.net")
PERSISTENCE_PATTERN = (r"programs/startup|shell:startup|currentversion/run(?:once|services)?\b|\bschtasks\b"
                       r"|\breg(?:\.exe)?\s+add\b|/library/launch(?:agents|daemons)|\blaunchctl\s+load\b"
                       r"|\.config/autostart|systemctl\s+(?:--user\s+)?enable|/etc/systemd/system|\bcrontab\b"
                       r"|/etc/rc\.local|winlogon/(?:shell|userinit)|/etc/init\.d/")
SHELL_PATTERN = (r"\b(?:powershell|pwsh)\b|\bcmd(?:\.exe)?\s*/[ck]\b|\bcmd\.exe\b"
                 r"|\b(?:wscript|cscript|mshta|regsvr32|certutil|bitsadmin)\b|\brundll32\b(?!.*url\.dll)"
                 r"|/bin/(?:ba)?sh\b|\b(?:ba)?sh\s+-c\b|(?:^|\s)-e(?:nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}"
                 r"|-windowstyle\s+hidden"
                 r"|invoke-webrequest|invoke-expression|\biex\s*\(|downloadstring|downloadfile|start-process"
                 r"|chmod\s+\+x|\bcurl\s+-[a-z]|\bwget\s+https?:")
ANTI_ANALYSIS_PATTERN = (r"\b(?:virtualbox|vbox(?:service|tray|guest)?|vmware|qemu|sandboxie|sbiedll|wireshark"
                         r"|fiddler|httpdebugger|procmon|processhacker|x64dbg|x32dbg|ollydbg|ida64|idaq|dnspy"
                         r"|ghidra|recaf|jd-gui|bytecode-?viewer)\b|agentlib:jdwp")
RECON_PATTERN = (_alternation("api.ipify.org", "ipinfo.io", "ip-api.com", "checkip.amazonaws.com", "icanhazip.com",
                              "ifconfig.me", "myexternalip.com", "wtfismyip.com", "geolocation-db.com", "ipapi.co",
                              "freegeoip") + r"|\bwhoami\b|\bsysteminfo\b|\bipconfig\b|\bwmic\b|\bnet\s+user\b")

RULES = [
    Rule("known_ioc", "Matches known malware", "critical",
         "The file's hash, or an address inside it, matches indicators published for real malware campaigns.",
         ("T1071", "Application Layer Protocol"), check_known_iocs),
    Rule("credential_theft", "Looks for saved passwords, cookies, tokens or crypto wallets", "critical",
         "Contains the file paths where browsers keep saved passwords and cookies, where Discord keeps its login "
         "token, or where crypto wallets are stored. No game mod has a reason to read these; information "
         "stealers do.", ("T1555.003", "Credentials from Web Browsers"),
         strings_matching(CREDENTIAL_PATTERN)),
    Rule("launcher_accounts", "Reads Minecraft launcher account files", "high",
         "Reads the files where Minecraft launchers store your logged-in accounts. Account-switcher mods (and "
         "Essential, for its own file) do this legitimately; account stealers do it too.",
         ("T1552.001", "Credentials In Files"), strings_matching(LAUNCHER_ACCOUNTS_PATTERN)),
    Rule("session_token", "Accesses your Minecraft login token", "medium",
         "Reads the session token that proves to servers you're logged in as you. Whoever has it can join "
         "servers as you until it expires. A few mods use it legitimately (account switchers, some server "
         "integrations); token stealers always do.", ("T1528", "Steal Application Access Token"),
         check_session_token),
    Rule("webhook_exfil", "Can send data to a Discord or Telegram webhook", "high",
         "Contains a webhook address: a URL that lets anyone who has it post messages into a chat channel. "
         "Malware uses them to send stolen data to the attacker. Mods almost never need one.",
         ("T1567.004", "Exfiltration Over Webhook"), strings_matching(WEBHOOK_PATTERN)),
    Rule("persistence", "Tries to run itself automatically at startup", "high",
         "Refers to the Windows Startup folder, the registry's Run keys, scheduled tasks, or their macOS and Linux "
         "equivalents. That's how malware keeps running after you close the game or restart the computer.",
         ("T1547.001", "Registry Run Keys / Startup Folder"), strings_matching(PERSISTENCE_PATTERN)),
    Rule("shell_commands", "Contains system shell commands", "high",
         "Contains commands for PowerShell, the Windows command prompt or Unix shells, including tools attackers "
         "use to download and run files. Game mods don't need a command line.",
         ("T1059", "Command and Scripting Interpreter"), strings_matching(SHELL_PATTERN)),
    Rule("reflection_hiding", "Hides which system functions it uses", "high",
         "Looks up powerful Java classes (running programs, loading code) by their name as text instead of calling "
         "them directly, a common trick to get past scanners that look for direct calls.",
         ("T1027", "Obfuscated Files or Information"), check_reflection_hiding),
    Rule("embedded_payload", "Contains a hidden program or script", "high",
         "A file inside the jar is disguised as something else (for example a program saved as .png), the jar "
         "contains scripts or Windows executables, or a long text string decodes to a program. Malware hides "
         "its next stage this way.", ("T1027.009", "Embedded Payloads"), check_embedded_payloads),
    Rule("keylogger", "Can record keystrokes outside the game", "high",
         "Uses JNativeHook, a library that captures keyboard and mouse input system-wide, not just in Minecraft.",
         ("T1056.001", "Keylogging"),
         lambda ctx, _: [Evidence(f"uses {c.replace('/', '.')}", loc) for c, loc in ctx.referenced_classes
                         if c.startswith(("com/github/kwhat/jnativehook/", "org/jnativehook/"))]),
    Rule("process_exec", "Can start other programs", "medium",
         "Can launch other programs on your computer. Some mods do this to open a folder or a web page; "
         "malware does it to run its payload.", ("T1059", "Command and Scripting Interpreter"),
         refs_matching(lambda r: (r.owner, r.name) in PROCESS_REFS)),
    Rule("dynamic_code", "Can load and run code that isn't in the jar", "medium",
         "Can turn raw bytes into running code at runtime, so what it finally does can't be seen by scanning the "
         "jar. Some libraries do this legitimately; malicious loaders (like fractureiser's) use it to run code "
         "downloaded from the internet.", ("T1620", "Reflective Code Loading"), check_dynamic_code),
    Rule("anti_analysis", "Checks whether it's being watched", "medium",
         "Looks for virtual machines, debuggers or analysis tools. Malware does this to behave innocently when a "
         "researcher is looking.", ("T1497", "Virtualization/Sandbox Evasion"),
         strings_matching(ANTI_ANALYSIS_PATTERN, code_only=True)),
    Rule("recon", "Collects information about your computer or network", "medium",
         "Looks up your public IP address or runs system information commands. Information stealers send this "
         "along with stolen data.", ("T1016", "System Network Configuration Discovery"),
         strings_matching(RECON_PATTERN)),
    Rule("screen_capture", "Can take screenshots of your whole screen", "medium",
         "Uses Java's desktop screenshot function, which captures everything on screen, not just the game.",
         ("T1113", "Screen Capture"),
         refs_matching(lambda r: r.owner == "java/awt/Robot" and "ScreenCapture" in r.name)),
    Rule("suspicious_host", "Connects to a suspicious address", "medium",
         "Contains web addresses that use a raw IP address, or services popular for hosting malware (paste "
         "sites, anonymous file sharing, tunnels, dynamic DNS, files uploaded to Discord).",
         ("T1071.001", "Web Protocols"), check_suspicious_hosts),
    Rule("obfuscated_names", "Code is obfuscated", "medium",
         "Most class names are meaningless (a, b, IlIlI...), which makes the code hard to read. Some legitimate "
         "paid or anti-cheat mods do this to protect their code; malware does it to hide.",
         ("T1027", "Obfuscated Files or Information"), check_obfuscated_names),
    Rule("encrypted_strings", "Text inside the code is encrypted", "medium",
         "Many text strings are scrambled or encoded and only decrypted when the code runs, which hides "
         "addresses, file paths and commands from scanners like this one.",
         ("T1027.013", "Encrypted/Encoded File"), check_encrypted_strings),
    Rule("java_agent", "Can modify other code as it loads", "medium",
         "Declares itself a Java agent or uses the instrumentation API, which lets it change other classes, "
         "including Minecraft's, while they load.", ("T1574", "Hijack Execution Flow"), check_java_agent),
    Rule("clipboard", "Reads or changes your clipboard", "low",
         "Accesses the system clipboard. Crypto 'clippers' swap wallet addresses you copy for the attacker's.",
         ("T1115", "Clipboard Data"),
         refs_matching(lambda r: (r.owner, r.name) in {("java/awt/Toolkit", "getSystemClipboard"),
                                                        ("java/awt/datatransfer/Clipboard", "getContents"),
                                                        ("java/awt/datatransfer/Clipboard", "setContents")})),
    Rule("native_code", "Includes native code", "low",
         "Bundles or loads native libraries (.dll, .so, .dylib). Performance and graphics mods do this; native "
         "code can't be inspected by this scanner.", ("T1106", "Native API"), check_native_code),
    Rule("encrypted_resource", "Contains encrypted-looking data files", "low",
         "Some files have the randomness of encrypted data but aren't a known compressed format.",
         ("T1027.013", "Encrypted/Encoded File"), check_encrypted_resources),
    Rule("odd_nested_jar", "Contains a jar in an unusual place", "low",
         "Mod loaders bundle libraries in META-INF/jars. A jar stored elsewhere may be a hidden second stage.",
         ("T1027.009", "Embedded Payloads"), check_odd_nested_jars),
    Rule("malformed_classes", "Some classes are deliberately broken", "low",
         "Some class files couldn't be read. Obfuscators corrupt classes on purpose to crash decompilers; it can "
         "also be a quirk this scanner doesn't understand.", ("T1027", "Obfuscated Files or Information"),
         check_malformed_classes),
    Rule("archive_anomaly", "The archive has unusual file names", "low",
         "Duplicate names, '..' path segments or absolute paths: tricks that make some tools see different files "
         "than Java does.", None, check_archive_anomalies),
    Rule("network", "Connects to the internet", "info",
         "Uses Java networking. Many mods do this (update checks, cosmetics, server lists). On its own it's not "
         "suspicious, but it matters in combination with other findings.",
         ("T1071.001", "Web Protocols"),
         refs_matching(lambda r: _uses_network(r.owner, r.name))),

    Rule("stealer_pattern", "Behaves like an information stealer", "critical",
         "Reads credentials or your login token and has a way to send them out (a webhook or a suspicious "
         "server). That's the defining pattern of an information stealer.",
         ("T1041", "Exfiltration Over C2 Channel"),
         combination([{"credential_theft", "launcher_accounts", "session_token"},
                      {"webhook_exfil", "suspicious_host", "known_ioc"}])),
    Rule("downloader", "Downloads and runs code", "high",
         "Connects to the internet and can run code that isn't in the jar, or carries a hidden payload. Fractureiser "
         "worked exactly like this: a small loader that fetched the real malware. Some server plugins legitimately "
         "download their libraries this way at startup, so check where the code comes from.",
         ("T1105", "Ingress Tool Transfer"), check_downloader),
    Rule("persistent_payload", "Installs something to run at startup", "critical",
         "Refers to startup locations and can run programs or carries a hidden payload: the pattern of malware "
         "installing itself permanently.", ("T1547", "Boot or Logon Autostart Execution"),
         combination([{"persistence"}, {"process_exec", "shell_commands", "downloader", "embedded_payload"}])),
]
RULES_BY_ID = {rule.id: rule for rule in RULES}


def run_rules(ctx: Context) -> list[Finding]:
    findings, triggered = [], set()
    for rule in RULES:
        evidence = _dedupe(rule.check(ctx, triggered))
        if not evidence:
            continue
        triggered.add(rule.id)
        findings.append(Finding(rule.id, rule.title, rule.severity, rule.description,
                                rule.attack[0] if rule.attack else None, rule.attack[1] if rule.attack else None,
                                evidence[:MAX_EVIDENCE], len(evidence)))
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    return findings
