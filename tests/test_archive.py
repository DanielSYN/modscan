import io
import zipfile

import pytest

from modscan.archive import ArchiveError, Budget, iter_entries
from modscan.jar import analyse_jar
from tests.factory import make_jar


def test_zip_bomb_entries_are_skipped():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as jar:
        jar.writestr("bomb.bin", b"\0" * (8 * 2**20))  # 8 MB of zeros squeezes to a few KB
        jar.writestr("ok.txt", "fine")
    budget = Budget()
    names = [e.name for e in iter_entries(buffer.getvalue(), budget)]
    assert names == ["ok.txt"]
    assert "zip bomb" in budget.notes[0]


def test_entry_and_byte_budgets_stop_the_scan():
    data = make_jar({f"f{i}.txt": "x" * 100 for i in range(10)})
    budget = Budget(entries_left=3)
    assert len(list(iter_entries(data, budget))) == 3
    assert "Stopped after" in budget.notes[0]

    budget = Budget(bytes_left=250)
    assert len(list(iter_entries(data, budget))) == 2
    assert "read limit" in budget.notes[0]


def test_not_a_zip():
    with pytest.raises(ArchiveError):
        list(iter_entries(b"PK\x03\x04 not really a zip", Budget()))


def test_nested_jars_are_opened_up_to_the_depth_limit():
    level3 = make_jar({"deep.txt": "hi"})
    level2 = make_jar({"META-INF/jars/l3.jar": level3})
    level1 = make_jar({"META-INF/jars/l2.jar": level2})
    outer = make_jar({"META-INF/jars/l1.jar": level1})
    analysis = analyse_jar(outer)
    assert analysis.nested_jars == ["META-INF/jars/l1.jar", "META-INF/jars/l1.jar!/META-INF/jars/l2.jar",
                                    "META-INF/jars/l1.jar!/META-INF/jars/l2.jar!/META-INF/jars/l3.jar"]
    assert any("nested more than 2 deep" in note for note in analysis.notes)


def test_odd_entry_names_are_recorded():
    analysis = analyse_jar(make_jar({"../../escape.txt": "x", "normal.txt": "y"}))
    assert analysis.odd_entry_names == ["../../escape.txt"]
