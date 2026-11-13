"""Build a source-controlled multi-DEX/resource APK plus real corrupted variants."""

from pathlib import Path
import hashlib
import json
import os
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests" / "fixtures" / "extraction"
OUTPUT = ROOT / "artifacts" / "fixtures" / "f1"
JDK = ROOT / ".tools" / "jdk-17"
SDK = ROOT / ".tools" / "android-sdk"
BUILD = SDK / "build-tools" / "35.0.0"
PLATFORM = SDK / "platforms" / "android-28" / "android.jar"


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    classes = OUTPUT / "classes"
    generated = OUTPUT / "generated"
    dex1, dex2 = OUTPUT / "dex1", OUTPUT / "dex2"
    for path in [classes, generated, dex1, dex2]:
        path.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["JAVA_HOME"] = str(JDK)
    env["PATH"] = str(JDK / "bin") + os.pathsep + env.get("PATH", "")
    commands = []

    def run(argv):
        result = subprocess.run([str(item) for item in argv], cwd=ROOT, env=env, capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=90)
        commands.append({"argv": [str(item) for item in argv], "exit_code": result.returncode,
                         "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            raise RuntimeError(result.stderr)
        return result.stdout

    compiled = OUTPUT / "resources.zip"
    run([BUILD / "aapt2.exe", "compile", "--dir", SOURCE / "res", "-o", compiled])
    base = OUTPUT / "base.apk"
    run([BUILD / "aapt2.exe", "link", "--manifest", SOURCE / "AndroidManifest.xml", "-I", PLATFORM,
         compiled, "--java", generated, "--output-text-symbols", OUTPUT / "R.txt", "-o", base])
    java_sources = sorted(SOURCE.glob("*.java")) + sorted(generated.rglob("*.java"))
    run([JDK / "bin" / "javac.exe", "--release", "8", "-classpath", PLATFORM, "-d", classes, *java_sources])
    all_classes = sorted(classes.rglob("*.class"))
    helper = [path for path in all_classes if path.name == "Helper.class"]
    primary = [path for path in all_classes if path not in helper]
    d8 = [JDK / "bin" / "java.exe", "-cp", BUILD / "lib" / "d8.jar", "com.android.tools.r8.D8",
          "--debug", "--lib", PLATFORM, "--classpath", classes, "--min-api", "16"]
    run([*d8, "--output", dex1, *primary])
    run([*d8, "--output", dex2, *helper])
    with zipfile.ZipFile(base) as archive:
        entries = {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}
    entries.update({"classes.dex": (dex1 / "classes.dex").read_bytes(), "classes2.dex": (dex2 / "classes.dex").read_bytes()})
    variants = {
        "valid.apk": entries,
        "broken-dex.apk": {**entries, "classes2.dex": b"dex\n035\0broken fixture"},
        "broken-resources.apk": {**entries, "resources.arsc": b"broken fixture resource table"},
        "broken-manifest.apk": {**entries, "AndroidManifest.xml": b"broken fixture manifest"},
    }
    for name, contents in variants.items():
        with zipfile.ZipFile(OUTPUT / name, "w", zipfile.ZIP_DEFLATED) as archive:
            for entry, data in sorted(contents.items()):
                info = zipfile.ZipInfo(entry, (2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data)
    (OUTPUT / "invalid.apk").write_bytes(b"Not a ZIP or Android APK")
    for index, dex in enumerate([dex1 / "classes.dex", dex2 / "classes.dex"], start=1):
        text = run([BUILD / "dexdump.exe", "-d", "-f", dex])
        (OUTPUT / f"dexdump-{index}.txt").write_text(text, encoding="utf-8")
    for args, filename in [(["resources", OUTPUT / "valid.apk"], "aapt2-resources.txt"),
                           (["xmltree", OUTPUT / "valid.apk", "--file", "AndroidManifest.xml"], "aapt2-manifest.txt")]:
        (OUTPUT / filename).write_text(run([BUILD / "aapt2.exe", "dump", *args]), encoding="utf-8")
    files = java_sources + list((SOURCE / "res").rglob("*")) + [SOURCE / "AndroidManifest.xml"]
    record = {"kind": "source-controlled-real-apk-fixture", "commands": commands,
              "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files if path.is_file()},
              "apk_sha256": {name: hashlib.sha256((OUTPUT / name).read_bytes()).hexdigest() for name in [*variants, "invalid.apk"]}}
    (OUTPUT / "build.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(OUTPUT / "valid.apk")


if __name__ == "__main__":
    main()
