"""Writes harmless example jars for trying ModScan: python scripts/make_examples.py [folder]

They contain the text and references the rules look for but no code that does anything, so
they're safe to keep around. They're generated rather than committed because files full of
stealer-like strings can upset antivirus software when someone clones the repo.
"""

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tests.factory import FABRIC_METADATA, clean_mod, cls, make_jar  # noqa: E402

EXAMPLES = {
    "clean-mod.jar": clean_mod(),
    "token-stealer-demo.jar": make_jar({
        "fabric.mod.json": FABRIC_METADATA.replace("Cool Mod", "Free Diamonds").replace("coolmod", "freediamonds"),
        "a/a.class": cls("a/a").string("\\discord\\Local Storage\\leveldb").string("dQw4w9WgXcQ:")
            .string("\\Google\\Chrome\\User Data\\Local State").string("encrypted_key")
            .method_ref("net/minecraft/class_320", "method_1674", "()Ljava/lang/String;"),
        "a/b.class": cls("a/b").string(base64.b64encode(b"https://discord.com/api/webhooks/0000/demo").decode())
            .string("https://api.ipify.org").method_ref("java/net/HttpURLConnection", "getOutputStream"),
        "a/c.class": cls("a/c").string("\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\")
            .method_ref("java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;"),
        "a/d.class": cls("a/d"), "a/e.class": cls("a/e"),
    }),
    "loader-demo.jar": make_jar({
        "fabric.mod.json": FABRIC_METADATA.replace("Cool Mod", "Better Tooltips").replace("coolmod", "tooltips"),
        "com/tooltips/Tooltips.class": cls("com/tooltips/Tooltips").string("tooltips").method("onInitialize"),
        "dev/neko/nekoinjector/Loader.class": cls("dev/neko/nekoinjector/Loader").string("http").string("Utility")
            .method_ref("java/net/URL", "<init>", "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V")
            .method_ref("java/net/URLClassLoader", "<init>", "([Ljava/net/URL;)V")
            .method_ref("java/lang/reflect/Method", "invoke"),
    }),
}

if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "examples")
    out.mkdir(parents=True, exist_ok=True)
    for name, data in EXAMPLES.items():
        (out / name).write_bytes(data)
        print(f"wrote {out / name}")
