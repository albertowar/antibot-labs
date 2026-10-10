"""
Chapter 5 — Setup: download the pinned fingerproxy release

fingerproxy (github.com/wi1dcard/fingerproxy, Apache-2.0) is a Go reverse
proxy that terminates TLS and forwards JA3, JA4 and HTTP/2 fingerprints to
the backend as request headers. We use the prebuilt release binary, so you
don't need a Go toolchain.

The SHA-256 of every asset is pinned below (copied from the release's
fingerproxy.sha256sum). A download that doesn't match is deleted.

Run:
    python tools/get_fingerproxy.py        # → bin/fingerproxy (or bin/fingerproxy.exe)

No prebuilt binary for your platform? With Go 1.21+ installed (the main
package lives in cmd/, so the binary comes out named `cmd`):
    GOBIN="$PWD/bin" go install github.com/wi1dcard/fingerproxy/cmd@v1.2.3
    mv bin/cmd bin/fingerproxy
"""

import hashlib
import os
import platform
import stat
import sys
import urllib.request

VERSION = "v1.2.3"
SHA256 = {
    "fingerproxy_darwin_amd64": "284a4cc68b07a856ef9e1d76786e08d7ccf638c313ed39f3d34bbf1cd3224936",
    "fingerproxy_darwin_arm64": "384aa7b356205a9bb4aa0cce431b6291d157939bfe9c1132d7c4bdaa5cf3ff63",
    "fingerproxy_linux_amd64": "9d58bc623cf65c2ff1136eeb32e1a2af52bf6051dfa30e7fadc7660adb0ea77c",
    "fingerproxy_linux_arm": "c68251bf61084470a696be78e3fa207397fb69f63130b45de521bbda3bd90693",
    "fingerproxy_linux_arm64": "ae941bf6b0d6900caed5bdfcee4235b033e207a5ec3a81b51b6d19038ddc77e0",
    "fingerproxy_windows_amd64.exe": "70822b85e5630b1be9a7edc3a250be2e7a8909ec3fb4a5bf5d9838ca7a7db3f7",
    "fingerproxy_windows_arm64.exe": "f7262a9ffd7fb79e84835f7524d69fb7180e54350e192874e9ce983ab04b6b2b",
}
LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN_DIR = os.path.join(LAB, "bin")


def asset_name():
    system = {"Linux": "linux", "Darwin": "darwin", "Windows": "windows"}.get(platform.system())
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64",
            "armv7l": "arm"}.get(machine)
    if not system or not arch:
        return None
    name = f"fingerproxy_{system}_{arch}" + (".exe" if system == "windows" else "")
    return name if name in SHA256 else None


def binary_path():
    return os.path.join(BIN_DIR, "fingerproxy.exe" if platform.system() == "Windows" else "fingerproxy")


def main():
    name = asset_name()
    if name is None:
        sys.exit(f"No prebuilt fingerproxy for {platform.system()}/{platform.machine()}. "
                 "Use the `go install` command in this file's docstring.")
    target = binary_path()
    if os.path.exists(target):
        with open(target, "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() == SHA256[name]:
                print(f"{os.path.relpath(target, LAB)} already present ({VERSION}, checksum OK)")
                return
    url = f"https://github.com/wi1dcard/fingerproxy/releases/download/{VERSION}/{name}"
    print(f"Downloading {url}")
    with urllib.request.urlopen(url, timeout=120) as r:
        data = r.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256[name]:
        sys.exit(f"Checksum mismatch for {name}: got {digest}. Not installing.")
    os.makedirs(BIN_DIR, exist_ok=True)
    with open(target, "wb") as f:
        f.write(data)
    os.chmod(target, os.stat(target).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"Installed {os.path.relpath(target, LAB)} ({VERSION}, {len(data) // 1_000_000} MB, checksum OK)")


if __name__ == "__main__":
    main()
