#!/usr/bin/env python3
"""Fail packaging when its executable and bundle disagree on macOS support."""
from pathlib import Path
import plistlib
import re
import subprocess
import sys


def version(value):
    if not re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", value):
        raise ValueError("Invalid macOS deployment target")
    return tuple(int(part) for part in (value.split(".") + ["0"])[:3])


def check_target(expected, output):
    # vtool emits one minos value per Mach-O slice. Check every slice, not SDK.
    targets = re.findall(r"^\s*minos\s+(\S+)\s*$", output, re.MULTILINE)
    platforms = re.findall(r"^\s*platform\s+(\S+)\s*$", output, re.MULTILINE)
    if not targets or len(targets) != len(platforms) or any(p != "MACOS" for p in platforms):
        raise ValueError("Missing or unsupported Mach-O deployment metadata")
    if any(version(target) != version(expected) for target in targets):
        raise ValueError("Mach-O minimum {} disagrees with bundle {}".format(", ".join(targets), expected))


def main():
    app = Path(sys.argv[1])
    with (app / "Contents/Info.plist").open("rb") as source:
        info = plistlib.load(source)
    binary = app / "Contents/MacOS" / info["CFBundleExecutable"]
    output = subprocess.check_output(["xcrun", "vtool", "-show-build", str(binary)], text=True)
    check_target(info["LSMinimumSystemVersion"], output)
    print("Verified macOS deployment target:", info["LSMinimumSystemVersion"])


if __name__ == "__main__":
    main()
