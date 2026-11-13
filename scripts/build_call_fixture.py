"""Build the inert F4-B APK with the same javac/aapt2/D8 evidence procedure."""
from build_local_fixture import main, ROOT

if __name__ == "__main__":
    main(source=ROOT / "tests/fixtures/call_flow", output=ROOT / "artifacts/fixtures/f4b", label="F4-B")
