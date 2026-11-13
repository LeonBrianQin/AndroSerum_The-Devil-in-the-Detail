"""Compile the F3 same-line-call/overload/array/trap/phantom fixture and independent dumps."""

from pathlib import Path
import hashlib
import json
import os
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/java_backend"
OUTPUT = ROOT / "artifacts/fixtures/f3"
JDK = ROOT / ".tools/jdk-17"
BUILD = ROOT / ".tools/android-sdk/build-tools/35.0.0"
PLATFORM = ROOT / ".tools/android-sdk/platforms/android-28/android.jar"


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    classes, dex = OUTPUT / "classes", OUTPUT / "dex"
    classes.mkdir(exist_ok=True)
    dex.mkdir(exist_ok=True)
    commands = []
    def run(argv):
        result = subprocess.run([str(item) for item in argv], cwd=ROOT, capture_output=True, timeout=90)
        commands.append({"argv": [str(item) for item in argv], "exit_code": result.returncode,
                         "stdout": result.stdout.decode("utf-8", errors="replace"), "stderr": result.stderr.decode("utf-8", errors="replace")})
        if result.returncode:
            raise RuntimeError(commands[-1]["stderr"])
        return result.stdout
    run([BUILD / "aapt2.exe", "link", "--manifest", SOURCE / "AndroidManifest.xml", "-I", PLATFORM, "-o", OUTPUT / "base.apk"])
    run([JDK / "bin/javac.exe", "--release", "8", "-classpath", PLATFORM, "-d", classes, *sorted(SOURCE.glob("*.java"))])
    inputs = [path for path in sorted(classes.rglob("*.class")) if path.name != "MissingBase.class"]
    run([JDK / "bin/java.exe", "-cp", BUILD / "lib/d8.jar", "com.android.tools.r8.D8", "--debug", "--lib", PLATFORM,
         "--classpath", classes, "--min-api", "16", "--output", dex, *inputs])
    with zipfile.ZipFile(OUTPUT / "base.apk") as archive:
        entries = {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}
    entries["classes.dex"] = (dex / "classes.dex").read_bytes()
    with zipfile.ZipFile(OUTPUT / "valid.apk", "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(entries.items()):
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    (OUTPUT / "dexdump.txt").write_bytes(run([BUILD / "dexdump.exe", "-d", "-f", dex / "classes.dex"]))
    record = {"schema_version": "java-fixture-build.v1", "kind": "real compiled fixture; MissingBase deliberately excluded", "commands": commands,
              "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(SOURCE.iterdir()) if path.is_file()},
              "apk_sha256": hashlib.sha256((OUTPUT / "valid.apk").read_bytes()).hexdigest()}
    (OUTPUT / "build.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(OUTPUT / "valid.apk")


if __name__ == "__main__":
    main()
