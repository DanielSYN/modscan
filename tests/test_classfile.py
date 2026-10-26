import random
import shutil
import subprocess

import pytest

from modscan.classfile import ClassFormatError, parse_class
from tests.factory import ClassBuilder


def test_reads_names_strings_and_references():
    data = (ClassBuilder("com/example/Thing")
            .string("hello").long(1 << 40).string("after a long constant")
            .method_ref("java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;")
            .field_ref("java/lang/System", "out", "Ljava/io/PrintStream;")
            .method("run").field("count").build())
    info = parse_class(data)
    assert info.name == "com/example/Thing"
    assert info.strings == ["hello", "after a long constant"]
    assert [str(r) for r in info.method_refs] == ["java/lang/Runtime.exec"]
    assert [str(r) for r in info.field_refs] == ["java/lang/System.out"]
    assert info.declared_methods == ["run"] and info.declared_fields == ["count"]


def test_decodes_javas_modified_utf8():
    text = "nul\0 · emoji 🎮 · 中文"
    assert parse_class(ClassBuilder("A").string(text).build()).strings == [text]


@pytest.mark.parametrize("data", [b"", b"PK\x03\x04", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbe" + b"\x00" * 6 + b"\xff"])
def test_rejects_non_class_data(data):
    with pytest.raises(ClassFormatError):
        parse_class(data)


def test_garbage_and_truncation_only_ever_raise_class_format_error():
    valid = ClassBuilder("x/Y").string("text").method_ref("a/B", "c").method("m").build()
    rng = random.Random(1234)
    samples = [valid[:cut] for cut in range(len(valid))]
    for _ in range(500):
        mutated = bytearray(valid)
        for _ in range(rng.randint(1, 8)):
            mutated[rng.randrange(8, len(mutated))] = rng.randrange(256)
        samples.append(bytes(mutated))
    for sample in samples:
        try:
            parse_class(sample)
        except ClassFormatError:
            pass


@pytest.mark.skipif(shutil.which("javac") is None, reason="needs a JDK")
def test_reads_real_compiler_output(tmp_path):
    """Lambdas, string concatenation (invokedynamic), records, long/double constants, inner classes."""
    source = tmp_path / "Sample.java"
    source.write_text("""
        import java.util.List;
        public class Sample {
            record Point(int x, int y) {}
            static final long BIG = 9_000_000_000L;
            static final double PI = 3.14159;
            String greet(String name) { return "Hello, " + name + "!"; }
            List<String> names() { return List.of("a", "b").stream().map(s -> s + BIG).toList(); }
            void open() throws Exception { new ProcessBuilder("xdg-open", "https://example.com").start(); }
            class Inner { int value = 1; }
        }
    """)
    subprocess.run(["javac", "-d", str(tmp_path), str(source)], check=True, capture_output=True)
    info = parse_class((tmp_path / "Sample.class").read_bytes())
    assert info.name == "Sample"
    assert {"xdg-open", "https://example.com", "a", "b"} <= set(info.strings)
    assert "java/lang/ProcessBuilder.start" in {str(r) for r in info.method_refs}
    assert info.invokedynamic_count >= 2
    assert {"greet", "names", "open"} <= set(info.declared_methods)
    assert parse_class((tmp_path / "Sample$Point.class").read_bytes()).name == "Sample$Point"
