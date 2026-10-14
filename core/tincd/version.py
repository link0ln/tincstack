#!/usr/bin/env python3

"""Print current tinc version for using in build scripts."""

from os import path, environ
import subprocess as subp

PREFIX = "release-"
SOURCE_ROOT = path.dirname(path.realpath(__file__))
SOURCE_ROOT = environ.get("MESON_SOURCE_ROOT", SOURCE_ROOT)

cmd = [
    "git",
    "--git-dir",
    path.join(SOURCE_ROOT, ".git"),
    "describe",
    "--always",
    "--tags",
    "--match=" + PREFIX + "*",
]

try:
    result = subp.run(cmd, stdout=subp.PIPE, stderr=subp.DEVNULL, encoding="utf-8", check=True)
    version = result.stdout.strip().replace("release-", "", 1)
except (FileNotFoundError, subp.CalledProcessError):
    version_file = path.join(SOURCE_ROOT, "VERSION")
    if path.exists(version_file):
        with open(version_file, "r", encoding="utf-8") as f:
            version = f.read().strip()
    else:
        version = "1.1pre18"
print(version)
