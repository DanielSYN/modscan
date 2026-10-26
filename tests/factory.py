"""Builds test class files and jars in memory.

The generated classes have a constant pool (names, strings, references to other classes'
methods) and declared member names, but no code at all. They contain the same text and
references the rules look for, so the tests exercise the scanner without any real malware.
"""

import io
import struct
import zipfile


def modified_utf8(text: str) -> bytes:
    out = bytearray()
    for ch in text:
        if ch == "\0":
            out += b"\xc0\x80"
        elif ord(ch) > 0xFFFF:
            code = ord(ch) - 0x10000
            for surrogate in (0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF)):
                out += chr(surrogate).encode("utf-8", "surrogatepass")
        else:
            out += ch.encode("utf-8", "surrogatepass")
    return bytes(out)


class ClassBuilder:
    def __init__(self, name: str, major: int = 65) -> None:
        self.name, self.major = name, major
        self.entries: list[bytes] = []
        self.cache: dict[tuple, int] = {}
        self.slot = 1
        self.methods: list[str] = []
        self.fields: list[str] = []

    def _add(self, key: tuple, raw: bytes, slots: int = 1) -> int:
        if key not in self.cache:
            self.cache[key] = self.slot
            self.entries.append(raw)
            self.slot += slots
        return self.cache[key]

    def utf8(self, text: str) -> int:
        data = modified_utf8(text)
        return self._add(("utf8", text), b"\x01" + struct.pack(">H", len(data)) + data)

    def class_ref(self, name: str) -> int:
        return self._add(("class", name), b"\x07" + struct.pack(">H", self.utf8(name)))

    def string(self, text: str) -> "ClassBuilder":
        self._add(("string", text), b"\x08" + struct.pack(">H", self.utf8(text)))
        return self

    def long(self, value: int) -> "ClassBuilder":
        self._add(("long", value), b"\x05" + struct.pack(">q", value), slots=2)
        return self

    def _name_and_type(self, name: str, descriptor: str) -> int:
        return self._add(("nat", name, descriptor),
                         b"\x0c" + struct.pack(">HH", self.utf8(name), self.utf8(descriptor)))

    def method_ref(self, owner: str, name: str, descriptor: str = "()V") -> "ClassBuilder":
        self._add(("method", owner, name, descriptor),
                  b"\x0a" + struct.pack(">HH", self.class_ref(owner), self._name_and_type(name, descriptor)))
        return self

    def field_ref(self, owner: str, name: str, descriptor: str = "I") -> "ClassBuilder":
        self._add(("field", owner, name, descriptor),
                  b"\x09" + struct.pack(">HH", self.class_ref(owner), self._name_and_type(name, descriptor)))
        return self

    def method(self, name: str) -> "ClassBuilder":
        self.methods.append(name)
        return self

    def field(self, name: str) -> "ClassBuilder":
        self.fields.append(name)
        return self

    def build(self) -> bytes:
        this = self.class_ref(self.name)
        sup = self.class_ref("java/lang/Object")
        members = []
        for names, descriptor in ((self.fields, "I"), (self.methods, "()V")):
            block = struct.pack(">H", len(names))
            for name in names:
                block += struct.pack(">HHHH", 0x0001, self.utf8(name), self.utf8(descriptor), 0)
            members.append(block)
        return (b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, self.major, self.slot) + b"".join(self.entries)
                + struct.pack(">HHHH", 0x0021, this, sup, 0) + members[0] + members[1] + struct.pack(">H", 0))


def make_jar(files: dict[str, bytes | str | ClassBuilder]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as jar:
        for path, content in files.items():
            if isinstance(content, ClassBuilder):
                content = content.build()
            jar.writestr(path, content)
    return buffer.getvalue()


def cls(name: str) -> ClassBuilder:
    return ClassBuilder(name)


FABRIC_METADATA = """{
  "schemaVersion": 1, "id": "coolmod", "version": "1.2.0", "name": "Cool Mod",
  "description": "Adds cool swords.", "authors": ["Alex", {"name": "Sam"}]
}"""


def clean_mod() -> bytes:
    """A normal-looking Fabric mod with an update checker."""
    return make_jar({
        "fabric.mod.json": FABRIC_METADATA,
        "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\n\r\n",
        "assets/coolmod/lang/en_us.json": '{"item.coolmod.cookie": "Cookies", "gui.coolmod.login": "Log in"}',
        "com/example/coolmod/CoolMod.class": cls("com/example/coolmod/CoolMod")
            .string("coolmod").string("Cool Mod loaded!").method("onInitialize")
            .method_ref("org/slf4j/Logger", "info", "(Ljava/lang/String;)V"),
        "com/example/coolmod/UpdateChecker.class": cls("com/example/coolmod/UpdateChecker")
            .string("https://api.modrinth.com/v2/project/coolmod/version")
            .method_ref("java/net/URL", "openStream", "()Ljava/io/InputStream;").method("check"),
        "com/example/coolmod/item/CoolSword.class": cls("com/example/coolmod/item/CoolSword").method("use"),
        "com/example/coolmod/item/ModItems.class": cls("com/example/coolmod/item/ModItems").string("cool_sword"),
        "com/example/coolmod/config/ModConfig.class": cls("com/example/coolmod/config/ModConfig")
            .string("coolmod.json").field("swordDamage"),
    })
