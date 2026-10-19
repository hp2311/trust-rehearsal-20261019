#!/usr/bin/env python3
"""Write a CycloneDX SBOM for the built wheel in dist/.

Usage: python packaging/make_sbom.py [dist_dir]    (needs `cyclonedx-bom` installed)

The SBOM lists what a user gets when they install the wheel. It is built from the
wheel itself, not from the developer checkout: the wheel is installed into a fresh
virtual environment together with every dependency it declares, and that
environment is described with cyclonedx-py. Dependencies guarded by an
environment marker (tzdata, Windows only) are included, so the SBOM does not
depend on the operating system of the runner that built it.

Output: <dist_dir>/<distribution>-<version>.cdx.json
"""
from __future__ import annotations

import email
import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def declared_requirements(wheel: Path) -> list[str]:
    """Runtime requirements from the wheel's METADATA, environment markers dropped."""
    with zipfile.ZipFile(wheel) as z:
        name = next(n for n in z.namelist() if n.endswith(".dist-info/METADATA"))
        meta = email.message_from_bytes(z.read(name))
    reqs = []
    for line in meta.get_all("Requires-Dist") or []:
        spec, _, marker = line.partition(";")
        if "extra ==" in marker or "extra==" in marker:
            continue  # optional extras (dev) are not part of what an installer gets
        reqs.append(spec.strip())
    return reqs


def main() -> int:
    dist = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    wheels = sorted(dist.glob("*.whl"))
    if len(wheels) != 1:
        print(f"expected exactly one wheel in {dist}, found {len(wheels)}", file=sys.stderr)
        return 1
    wheel = wheels[0]
    dist_name, version = wheel.name.split("-")[:2]

    with tempfile.TemporaryDirectory() as tmp:
        venv = Path(tmp) / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
        py = venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        subprocess.run(
            [str(py), "-m", "pip", "install", "--quiet", "--no-input", str(wheel),
             *declared_requirements(wheel)],
            check=True,
        )
        # Describe the end-user environment, not the tooling used to create it
        subprocess.run([str(py), "-m", "pip", "uninstall", "--quiet", "-y", "pip"], check=True)
        raw = Path(tmp) / "raw.json"
        subprocess.run(
            ["cyclonedx-py", "environment", "--pyproject", "pyproject.toml",
             "--mc-type", "application", "--sv", "1.5", "--of", "JSON",
             "--output-reproducible", "--validate", "-o", str(raw), str(py)],
            check=True,
        )
        bom = json.loads(raw.read_text())

    # pyproject.toml takes the version dynamically from __init__.py, so cyclonedx-py
    # cannot see it. Take it from the wheel filename instead.
    root = bom["metadata"]["component"]
    root["version"] = version
    root["purl"] = f"pkg:pypi/{re.sub(r'[-_.]+', '-', dist_name).lower()}@{version}"
    bom.setdefault("components", [])

    out = dist / f"{dist_name}-{version}.cdx.json"
    out.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n")
    shutil.copystat(wheel, out)
    print(f"wrote {out} ({len(bom['components'])} dependency components)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
