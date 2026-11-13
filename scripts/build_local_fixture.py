"""Build an inert, source-controlled APK for the F4-A scalar-local acceptance cases."""
from pathlib import Path
import hashlib
import json
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/local_flow"
OUTPUT = ROOT / "artifacts/fixtures/f4a"


def main(*, source=SOURCE, output=OUTPUT, label="F4-A"):
    jdk = ROOT / ".tools/jdk-17/bin"
    build = ROOT / ".tools/android-sdk/build-tools/35.0.0"
    platform = ROOT / ".tools/android-sdk/platforms/android-28/android.jar"
    classes, dex = output / "classes", output / "dex"
    classes.mkdir(parents=True, exist_ok=True); dex.mkdir(exist_ok=True)
    commands = []
    def run(argv):
        result = subprocess.run([str(item) for item in argv], cwd=ROOT, capture_output=True, timeout=90)
        commands.append({"argv": [str(item) for item in argv], "exit_code": result.returncode,
                         "stdout": result.stdout.decode("utf-8", errors="replace"), "stderr": result.stderr.decode("utf-8", errors="replace")})
        if result.returncode: raise RuntimeError(commands[-1]["stderr"])
        return result.stdout
    run([build / "aapt2.exe", "link", "--manifest", source / "AndroidManifest.xml", "-I", platform, "-o", output / "base.apk"])
    run([jdk / "javac.exe", "--release", "8", "-classpath", platform, "-d", classes, *sorted(source.glob("*.java"))])
    run([jdk / "java.exe", "-cp", build / "lib/d8.jar", "com.android.tools.r8.D8", "--debug", "--lib", platform,
         "--min-api", "16", "--output", dex, *sorted(classes.rglob("*.class"))])
    with zipfile.ZipFile(output / "base.apk") as archive_source:
        entries = {name: archive_source.read(name) for name in archive_source.namelist() if not name.endswith("/")}
    entries["classes.dex"] = (dex / "classes.dex").read_bytes()
    with zipfile.ZipFile(output / "valid.apk", "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in sorted(entries.items()):
            entry = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)); entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, value)
    (output / "dexdump.txt").write_bytes(run([build / "dexdump.exe", "-d", "-f", dex / "classes.dex"]))
    report = {"kind": f"compiled benign {label} fixture, not manual analysis records", "commands": commands,
              "apk_sha256": hashlib.sha256((output / "valid.apk").read_bytes()).hexdigest(),
              "source_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in source.iterdir() if path.is_file()}}
    (output / "build.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(output / "valid.apk")


if __name__ == "__main__": main()
