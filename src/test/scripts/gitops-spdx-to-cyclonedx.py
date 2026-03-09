#!/usr/bin/env python3
"""
Create a CycloneDX JSON file for each unique container image referenced in the
gitops SPDX test case (or any SPDX file with OCI purls).

Reads the SPDX JSON, extracts image references from pkg:oci/ purls in package
externalRefs (same logic as SpdxParsingService.parseImageFromPurl), deduplicates
by image (registry/repo@sha256:digest), then runs syft for each image and
writes cyclonedx-json to the output directory.

Requires: syft on PATH, Python 3.6+

Usage:
  ./gitops-spdx-to-cyclonedx.py [SPDX_FILE] [--output-dir DIR]
  python3 gitops-spdx-to-cyclonedx.py src/test/resources/devservices/spdx-sboms/gitops-1.19.json
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

# Default paths relative to project root (script is in src/test/scripts/)
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent.parent
DEFAULT_SPDX = PROJECT_ROOT / "src/test/resources/devservices/spdx-sboms/gitops-1.19.json"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "src/test/resources/devservices/cyclonedx-from-gitops"


def parse_image_from_purl(purl: str) -> str | None:
    """
    Parse image from OCI PURL format: pkg:oci/name@sha256:hash?repository_url=...&tag=...
    Returns: repository_url@sha256:hash (same as SpdxParsingService.parseImageFromPurl).
    """
    if not purl or not purl.startswith("pkg:oci/"):
        return None
    at_sha = "@sha256:"
    sha_index = purl.find(at_sha)
    if sha_index == -1:
        return None
    query_index = purl.find("?", sha_index)
    if query_index == -1:
        sha_end = len(purl)
    else:
        sha_end = query_index
    sha = purl[sha_index + 1 : sha_end]  # +1 to skip '@', includes "sha256:hash"
    if not sha:
        return None
    if query_index == -1:
        return None
    query_string = purl[query_index + 1 :]
    repository_url = None
    for param in query_string.split("&"):
        if param.startswith("repository_url="):
            repository_url = unquote(param[len("repository_url=") :])
            break
    if repository_url and sha:
        return f"{repository_url}@{sha}"
    return None


def extract_images_from_spdx(spdx_path: Path) -> list[tuple[str, str]]:
    """
    Load SPDX JSON and return list of (image_ref, package_name) for each package
    that has an OCI purl. Deduplicates by image_ref; package_name is from the
    first package seen for that image.
    """
    with open(spdx_path, encoding="utf-8") as f:
        doc = json.load(f)
    packages = doc.get("packages") or []
    seen_images: set[str] = set()
    result: list[tuple[str, str]] = []
    for pkg in packages:
        name = pkg.get("name") or "unknown"
        refs = pkg.get("externalRefs") or []
        for ref in refs:
            if ref.get("referenceCategory") != "PACKAGE_MANAGER":
                continue
            if ref.get("referenceType") != "purl":
                continue
            locator = ref.get("referenceLocator")
            if not locator or not locator.startswith("pkg:oci/"):
                continue
            image = parse_image_from_purl(locator)
            if image and image not in seen_images:
                seen_images.add(image)
                result.append((image, name))
            break  # first purl only per package
    return result


def sanitize_filename(name: str, max_len: int = 100) -> str:
    """Make a safe filename from a package name or image ref."""
    safe = re.sub(r'[^\w\-.]', '_', name)
    safe = re.sub(r'_+', '_', safe).strip("_")
    if len(safe) > max_len:
        safe = safe[:max_len]
    return safe or "image"


def run_syft_cyclonedx(image: str, out_path: Path) -> bool:
    """Run syft image -o cyclonedx-json and write to out_path. Returns True on success."""
    try:
        proc = subprocess.run(
            ["syft", image, "-o", "cyclonedx-json"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if proc.returncode != 0:
            print(f"  syft failed: {proc.stderr or proc.stdout}", file=sys.stderr)
            return False
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(proc.stdout, encoding="utf-8")
        return True
    except FileNotFoundError:
        print("  syft not found on PATH. Install syft and retry.", file=sys.stderr)
        return False
    except subprocess.TimeoutExpired:
        print("  syft timed out.", file=sys.stderr)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate CycloneDX JSON per image from gitops SPDX"
    )
    parser.add_argument(
        "spdx_file",
        nargs="?",
        type=Path,
        default=DEFAULT_SPDX,
        help=f"SPDX JSON file (default: {DEFAULT_SPDX})",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for CycloneDX files (default: {DEFAULT_OUTPUT_DIR})",
    )
    args = parser.parse_args()
    spdx_path = args.spdx_file.resolve()
    out_dir = args.output_dir.resolve()

    if not spdx_path.is_file():
        print(f"SPDX file not found: {spdx_path}", file=sys.stderr)
        return 1

    images = extract_images_from_spdx(spdx_path)
    if not images:
        print("No OCI images found in SPDX packages.", file=sys.stderr)
        return 1

    print(f"Found {len(images)} unique image(s). Writing CycloneDX to {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    ok = 0
    used_names: set[str] = set()
    for i, (image, name) in enumerate(images, 1):
        base = sanitize_filename(name)
        if base == "unknown" or base in used_names:
            base = f"image_{i:03d}"
        used_names.add(base)
        out_name = f"{base}.json"
        out_path = out_dir / out_name
        print(f"  [{i}/{len(images)}] {name} -> {out_path.name}")
        if run_syft_cyclonedx(image, out_path):
            ok += 1
    print(f"Wrote {ok}/{len(images)} CycloneDX file(s) to {out_dir}")
    return 0 if ok == len(images) else 1


if __name__ == "__main__":
    sys.exit(main())
