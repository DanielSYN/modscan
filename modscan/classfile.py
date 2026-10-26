"""Reads compiled Java .class files without running them or needing Java installed.

Only the parts useful for spotting behaviour are extracted: the class's own name, the
string literals it contains, and the methods and fields it references in other classes
(for example java/lang/Runtime.exec). Those references live in the constant pool, so we
don't need to understand the bytecode itself.

Format reference: https://docs.oracle.com/javase/specs/jvms/se21/html/jvms-4.html
"""

import struct
from dataclasses import dataclass, field

MAGIC = b"\xca\xfe\xba\xbe"

# Constant pool tags -> number of payload bytes, for entries we skip over.
_FIXED_SIZES = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}
UTF8, CLASS, STRING, FIELDREF, METHODREF, INTERFACE_METHODREF, NAME_AND_TYPE = 1, 7, 8, 9, 10, 11, 12
INVOKEDYNAMIC = 18


class ClassFormatError(ValueError):
    """The bytes aren't a class file we can read (truncated, corrupt, or deliberately malformed)."""


@dataclass
class MemberRef:
    owner: str  # internal form, e.g. java/lang/Runtime
    name: str
    descriptor: str

    def __str__(self) -> str:
        return f"{self.owner}.{self.name}"


@dataclass
class ClassInfo:
    name: str
    major_version: int
    strings: list[str] = field(default_factory=list)          # string literals in the code
    method_refs: list[MemberRef] = field(default_factory=list)
    field_refs: list[MemberRef] = field(default_factory=list)
    referenced_classes: list[str] = field(default_factory=list)
    declared_methods: list[str] = field(default_factory=list)
    declared_fields: list[str] = field(default_factory=list)
    invokedynamic_count: int = 0


def decode_modified_utf8(raw: bytes) -> str:
    """Java stores names and strings as 'modified UTF-8': NUL is C0 80 and characters outside
    the Basic Multilingual Plane are written as two encoded UTF-16 surrogates."""
    text = raw.replace(b"\xc0\x80", b"\x00").decode("utf-8", errors="surrogatepass")
    try:
        return text.encode("utf-16", errors="surrogatepass").decode("utf-16")
    except UnicodeDecodeError:  # unpaired surrogates (common in obfuscated or encrypted strings)
        return text.encode("utf-16", errors="surrogatepass").decode("utf-16", errors="replace")


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ClassFormatError("unexpected end of class file")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u1(self) -> int:
        return self.take(1)[0]

    def u2(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u4(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def skip_attributes(self) -> None:
        for _ in range(self.u2()):
            self.u2()
            self.take(self.u4())


def parse_class(data: bytes) -> ClassInfo:
    """Parse a class file. Raises ClassFormatError for anything malformed, never other errors."""
    try:
        return _parse(data)
    except ClassFormatError:
        raise
    except (UnicodeDecodeError, IndexError, KeyError, TypeError, struct.error) as exc:
        raise ClassFormatError(f"malformed class file ({type(exc).__name__})") from exc


def _parse(data: bytes) -> ClassInfo:
    r = _Reader(data)
    if r.take(4) != MAGIC:
        raise ClassFormatError("not a class file (missing CAFEBABE header)")
    r.u2()  # minor version
    major = r.u2()

    # Slot 0 is unused; long and double constants take two slots.
    count = r.u2()
    pool: list[tuple | None] = [None] * count
    i = 1
    while i < count:
        tag = r.u1()
        if tag == UTF8:
            pool[i] = (UTF8, decode_modified_utf8(r.take(r.u2())))
        elif tag in (CLASS, STRING):
            pool[i] = (tag, r.u2())
        elif tag in (FIELDREF, METHODREF, INTERFACE_METHODREF, NAME_AND_TYPE):
            pool[i] = (tag, r.u2(), r.u2())
        elif tag == INVOKEDYNAMIC:
            r.take(4)
            pool[i] = (INVOKEDYNAMIC,)
        elif tag in _FIXED_SIZES:
            r.take(_FIXED_SIZES[tag])
            if tag in (5, 6):
                i += 1
        else:
            raise ClassFormatError(f"unknown constant pool tag {tag} at entry {i}")
        i += 1

    def utf8(index: int) -> str:
        entry = pool[index] if 0 < index < count else None
        if not entry or entry[0] != UTF8:
            raise ClassFormatError(f"constant {index} is not a UTF-8 entry")
        return entry[1]

    def class_name(index: int) -> str:
        entry = pool[index] if 0 < index < count else None
        if not entry or entry[0] != CLASS:
            raise ClassFormatError(f"constant {index} is not a class entry")
        return utf8(entry[1])

    def member(entry: tuple) -> MemberRef:
        nat = pool[entry[2]] if 0 < entry[2] < count else None
        if not nat or nat[0] != NAME_AND_TYPE:
            raise ClassFormatError("member reference without a name-and-type entry")
        return MemberRef(class_name(entry[1]), utf8(nat[1]), utf8(nat[2]))

    r.u2()  # access flags
    info = ClassInfo(name=class_name(r.u2()), major_version=major)
    r.u2()  # super class
    r.take(2 * r.u2())  # interfaces

    for entry in pool:
        if entry is None:
            continue
        tag = entry[0]
        if tag == STRING:
            info.strings.append(utf8(entry[1]))
        elif tag == METHODREF or tag == INTERFACE_METHODREF:
            info.method_refs.append(member(entry))
        elif tag == FIELDREF:
            info.field_refs.append(member(entry))
        elif tag == CLASS:
            info.referenced_classes.append(utf8(entry[1]))
        elif tag == INVOKEDYNAMIC:
            info.invokedynamic_count += 1

    for names in (info.declared_fields, info.declared_methods):
        for _ in range(r.u2()):
            r.u2()  # access flags
            names.append(utf8(r.u2()))
            r.u2()  # descriptor
            r.skip_attributes()
    r.skip_attributes()
    return info
