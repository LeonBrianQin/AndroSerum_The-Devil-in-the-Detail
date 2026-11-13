"""Compile the F4-C1 inert heap fixture and save independent DEX/build evidence."""
from build_local_fixture import main, ROOT

if __name__ == "__main__":
    main(source=ROOT / "tests/fixtures/heap_flow", output=ROOT / "artifacts/fixtures/f4c1", label="F4-C1")
