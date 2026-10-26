import json

from modscan.__main__ import main
from tests.factory import clean_mod, cls, make_jar


def write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def test_exit_codes_follow_the_worst_verdict(tmp_path, capsys):
    clean = write(tmp_path, "clean.jar", clean_mod())
    bad = write(tmp_path, "bad.jar", make_jar({"a/B.class": cls("a/B").string("\\Login Data")}))
    assert main(["scan", clean]) == 0
    assert main(["scan", clean, bad]) == 2
    assert "LIKELY MALICIOUS" in capsys.readouterr().out


def test_unreadable_files_exit_3(tmp_path, capsys):
    assert main(["scan", write(tmp_path, "notes.txt", b"hello")]) == 3
    assert main(["scan", str(tmp_path / "missing.jar")]) == 3
    assert "neither" in capsys.readouterr().err


def test_json_output(tmp_path, capsys):
    main(["scan", "--json", write(tmp_path, "clean.jar", clean_mod())])
    reports = json.loads(capsys.readouterr().out)
    assert reports[0]["verdict"] == "no_known_threats"


def test_terminal_control_codes_from_the_file_are_escaped(tmp_path, capsys):
    metadata = '{"schemaVersion": 1, "id": "x", "name": "Evil\\u001b[2J\\u001b[32mSAFE", "version": "1"}'
    main(["scan", write(tmp_path, "x.jar", make_jar({"fabric.mod.json": metadata}))])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "Evil\\u001b[2J" in out


def test_explain_without_a_key_says_how_to_add_one(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    main(["scan", "--explain", write(tmp_path, "clean.jar", clean_mod())])
    assert "needs your own Anthropic API key" in capsys.readouterr().out
