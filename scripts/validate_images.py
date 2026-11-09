#!/usr/bin/env python3
"""Verify that rendered container image references resolve in their registries."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


DEFAULT_SKIP_PREFIXES = ("ghcr.io/web3-frozen/",)


def should_skip(image: str, skip_prefixes: tuple[str, ...]) -> bool:
    return image.startswith(skip_prefixes)


def check_image(crane: str, image: str, retries: int = 3) -> tuple[str, bool, str]:
    last_error = ""
    for attempt in range(1, retries + 1):
        try:
            result = subprocess.run(
                [crane, "digest", image, "--platform=linux/amd64"],
                text=True,
                capture_output=True,
                timeout=45,
                check=False,
            )
        except subprocess.TimeoutExpired:
            last_error = "timed out"
        else:
            if result.returncode == 0:
                return image, True, result.stdout.strip()
            last_error = (result.stderr or result.stdout).strip()
        if attempt < retries:
            time.sleep(attempt * 2)
    return image, False, last_error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("images_file", type=Path)
    parser.add_argument("--crane", default="crane")
    parser.add_argument(
        "--skip-prefix",
        action="append",
        default=[],
        help="Additional private image prefixes to skip",
    )
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()

    skip_prefixes = (
        *DEFAULT_SKIP_PREFIXES,
        *tuple(os.environ.get("IMAGE_VALIDATION_SKIP_PREFIXES", "").split(",")),
        *tuple(args.skip_prefix),
    )
    skip_prefixes = tuple(prefix for prefix in skip_prefixes if prefix)

    images = [
        line.strip()
        for line in args.images_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    checked = [image for image in images if not should_skip(image, skip_prefixes)]
    skipped = [image for image in images if should_skip(image, skip_prefixes)]

    failures: list[tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {
            executor.submit(check_image, args.crane, image): image
            for image in checked
        }
        for future in as_completed(futures):
            image, ok, detail = future.result()
            if ok:
                print(f"OK   {image} -> {detail}")
            else:
                print(f"FAIL {image}: {detail}", file=sys.stderr)
                failures.append((image, detail))

    print(
        f"validated={len(checked) - len(failures)} "
        f"failed={len(failures)} skipped_private={len(skipped)}"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
