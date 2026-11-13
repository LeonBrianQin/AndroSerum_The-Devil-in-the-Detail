"""Compile a benign, source-controlled Android fixture for static tool checks."""

from pathlib import Path
import os
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "toolchain"
OUTPUT = ROOT / "artifacts" / "toolchain-fixture"
SDK = ROOT / ".tools" / "android-sdk"
JDK = ROOT / ".tools" / "jdk-17"
BUILD = SDK / "build-tools" / "35.0.0"
PLATFORM = SDK / "platforms" / "android-28" / "android.jar"


def main() -> None:
    classes = OUTPUT / "classes"
    dex = OUTPUT / "dex"
    classes.mkdir(parents=True, exist_ok=True)
    dex.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["JAVA_HOME"] = str(JDK)
    env["PATH"] = str(JDK / "bin") + os.pathsep + env.get("PATH", "")
    subprocess.run([
        str(JDK / "bin" / "javac.exe"), "--release", "8", "-classpath", str(PLATFORM),
        "-d", str(classes), str(FIXTURE / "MainActivity.java"),
    ], env=env, check=True, timeout=60)
    subprocess.run([
        str(JDK / "bin" / "java.exe"), "-cp", str(BUILD / "lib" / "d8.jar"),
        "com.android.tools.r8.D8", "--lib", str(PLATFORM), "--min-api", "16",
        "--output", str(dex), str(classes / "org" / "androserum" / "fixture" / "MainActivity.class"),
    ], env=env, check=True, timeout=60)
    apk = OUTPUT / "toolchain-fixture.apk"
    subprocess.run([
        str(BUILD / "aapt2.exe"), "link", "--manifest", str(FIXTURE / "AndroidManifest.xml"),
        "-I", str(PLATFORM), "-o", str(apk),
    ], env=env, check=True, timeout=60)
    with zipfile.ZipFile(apk, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(dex / "classes.dex", "classes.dex")
    print(apk)


if __name__ == "__main__":
    main()
