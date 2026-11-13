"""Install pinned portable Windows tools inside this project's .tools directory."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import time
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / ".tools"


def digest(path: Path, algorithm: str) -> str:
    checksum = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def install(spec: dict) -> dict:
    destination = (TOOLS / spec["destination"]).resolve()
    destination.relative_to(TOOLS.resolve())
    cache = TOOLS / "downloads" / spec["url"].rsplit("/", 1)[-1]
    cache.parent.mkdir(parents=True, exist_ok=True)
    algorithm = spec["checksum_algorithm"]
    if not cache.is_file() or digest(cache, algorithm) != spec["checksum"]:
        partial = cache.with_suffix(cache.suffix + ".partial")
        for attempt in range(3):
            try:
                request = urllib.request.Request(spec["url"], headers={"User-Agent": "AndroSerum-Setup/1"})
                with urllib.request.urlopen(request, timeout=45) as response, partial.open("wb") as output:
                    shutil.copyfileobj(response, output, 1024 * 1024)
                actual = digest(partial, algorithm)
                if actual != spec["checksum"]:
                    raise ValueError(f"Checksum mismatch: {spec['name']}: {actual}")
                partial.replace(cache)
                break
            except Exception:
                if attempt == 2:
                    raise
                time.sleep(2)
    marker = destination / ".androserum-install.json"
    installed_spec = json.loads(marker.read_text(encoding="utf-8")) if marker.is_file() else None
    if installed_spec != spec or not (destination / spec["required_file"]).is_file():
        with zipfile.ZipFile(cache) as archive:
            for member in archive.infolist():
                parts = PurePosixPath(member.filename).parts
                if len(parts) < 2:
                    continue
                target = destination.joinpath(*parts[1:]).resolve()
                target.relative_to(destination)
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(member) as source, target.open("wb") as output:
                        shutil.copyfileobj(source, output)
        if not (destination / spec["required_file"]).is_file():
            raise RuntimeError(f"Missing expected tool: {destination / spec['required_file']}")
        marker.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    result = {
        **spec,
        "absolute_destination": str(destination),
        "downloaded_bytes": cache.stat().st_size,
        "download_sha256": digest(cache, "sha256"),
        "vendor_checksum_verified": True,
    }
    print(f"Installed: {spec['name']}", flush=True)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", help="Install specs whose name contains this text")
    args = parser.parse_args()
    lock = json.loads((ROOT / "configs" / "toolchain-lock.json").read_text(encoding="utf-8"))
    specs = [s for s in lock["archives"] if not args.only or args.only.lower() in s["name"].lower()]
    results = []
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(install, spec) for spec in specs]
        for future in as_completed(futures):
            results.append(future.result())
    target = TOOLS / "installed-tools.json"
    previous = json.loads(target.read_text(encoding="utf-8")) if target.exists() else []
    records = {record["name"]: record for record in previous}
    records.update({record["name"]: record for record in results})
    target.write_text(json.dumps(list(records.values()), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
