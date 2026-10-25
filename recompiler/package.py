"""macOS packaging: translated executable -> .app bundle -> .dmg.

Packaging is deliberately separate from translation correctness: it only
wraps a binary that `translate.build` produced.

Bundle layout (console programs)::

    Hello.app/Contents/Info.plist
    Hello.app/Contents/MacOS/hello          launcher (POSIX sh)
    Hello.app/Contents/MacOS/hello-guest    translated native executable
    Hello.app/Contents/Resources/THIRD_PARTY_NOTICES.md

A Windows console program has no GUI. When the launcher is started from
Finder (no terminal on stdout) it opens Terminal.app to run the guest so the
output is visible; when started from a shell it execs the guest directly, so
stdout and the exit code are passed through unchanged.

Signing is ad-hoc (`codesign --sign -`), which is what Apple-silicon Macs
require to run locally built code. Distribution to other Macs additionally
needs a Developer ID signature and notarization, which are out of scope.
"""
from __future__ import annotations

import os
import platform
import plistlib
import re
import shutil
import subprocess
from pathlib import Path

from .translate import ROOT, TranslationError, build

LAUNCHER = """#!/bin/sh
# exe2mac launcher for a translated Windows console program.
here="$(cd "$(dirname "$0")" && pwd)"
guest="$here/{guest}"
if [ -t 1 ] || [ -n "${{EXE2MAC_DIRECT:-}}" ]; then
    exec "$guest" "$@"
fi
# Started from Finder: show the console output in Terminal.
exec /usr/bin/open -a Terminal "$guest"
"""


def _ident(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9-]", "-", name).strip("-").lower()
    return s or "app"


def make_app(binary, out_dir, app_name, bundle_id=None, version="0.1.0") -> Path:
    """Create ``<out_dir>/<app_name>.app`` around an already-built native binary."""
    binary = Path(binary)
    if not binary.is_file():
        raise TranslationError(f"binary not found: {binary}")
    exe_name = _ident(app_name)
    app = Path(out_dir) / f"{app_name}.app"
    if app.exists():
        shutil.rmtree(app)
    macos = app / "Contents" / "MacOS"
    res = app / "Contents" / "Resources"
    macos.mkdir(parents=True)
    res.mkdir(parents=True)

    guest = macos / f"{exe_name}-guest"
    shutil.copy2(binary, guest)
    guest.chmod(0o755)
    launcher = macos / exe_name
    launcher.write_text(LAUNCHER.format(guest=guest.name))
    launcher.chmod(0o755)
    shutil.copy2(ROOT / "THIRD_PARTY_NOTICES.md", res / "THIRD_PARTY_NOTICES.md")

    info = {
        "CFBundleDevelopmentRegion": "en",
        "CFBundleExecutable": exe_name,
        "CFBundleIdentifier": bundle_id or f"org.exe2mac.{exe_name}",
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": app_name,
        "CFBundleDisplayName": app_name,
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": version,
        "CFBundleVersion": version,
        "LSMinimumSystemVersion": "11.0",
        "LSArchitecturePriority": ["arm64"],
        "NSHighResolutionCapable": True,
    }
    with open(app / "Contents" / "Info.plist", "wb") as f:
        plistlib.dump(info, f, sort_keys=True)
    with open(app / "Contents" / "PkgInfo", "w") as f:
        f.write("APPL????")
    return app


def _run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise TranslationError(f"{' '.join(map(str, cmd))} failed:\n{r.stdout}{r.stderr}")
    return r


def sign_app(app: Path):
    _run(["codesign", "--force", "--sign", "-", "--timestamp=none",
          str(app / "Contents" / "MacOS" / (_ident(app.stem) + "-guest"))])
    _run(["codesign", "--force", "--sign", "-", "--timestamp=none", str(app)])
    _run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)])


def make_dmg(app: Path, dmg: Path, volname: str) -> Path:
    staging = dmg.parent / (dmg.stem + ".staging")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    _run(["ditto", str(app), str(staging / app.name)])
    os.symlink("/Applications", staging / "Applications")
    if dmg.exists():
        dmg.unlink()
    _run(["hdiutil", "create", "-volname", volname, "-srcfolder", str(staging),
          "-fs", "HFS+", "-format", "UDZO", "-ov", str(dmg)])
    shutil.rmtree(staging)
    _run(["hdiutil", "verify", str(dmg)])
    return dmg


def package(exe_path, out_dir, app_name=None, dmg=True, sign=True, cc=None) -> dict:
    """Translate, build, and package. On non-macOS hosts only the bundle is made."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    app_name = app_name or Path(exe_path).stem.capitalize()
    binary = build(exe_path, out_dir / "build" / _ident(app_name), cc=cc)
    app = make_app(binary, out_dir, app_name)
    result = {"binary": binary, "app": app, "dmg": None, "signed": False}
    on_mac = platform.system() == "Darwin"
    if sign and on_mac:
        sign_app(app)
        result["signed"] = True
    if dmg and on_mac:
        result["dmg"] = make_dmg(app, out_dir / f"{app_name}.dmg", app_name)
    return result


def doctor() -> list[tuple[str, bool, str]]:
    """Check prerequisites. Returns (check, ok, detail) tuples."""
    checks = []
    try:
        import capstone
        checks.append(("capstone", capstone.__version__.startswith("5."), capstone.__version__))
    except ImportError:
        checks.append(("capstone", False, "missing: pip install capstone==5.0.3"))
    cc = os.environ.get("CC") or shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if cc:
        probe = subprocess.run([cc, "-x", "c", "-c", "-o", os.devnull, "-"],
                               input="unsigned __int128 x; _Noreturn void f(void);",
                               capture_output=True, text=True)
        checks.append(("C11 compiler with __int128", probe.returncode == 0, cc))
    else:
        checks.append(("C11 compiler with __int128", False, "no cc/clang/gcc on PATH"))
    host = f"{platform.system()} {platform.machine()}"
    checks.append(("host is macOS arm64 (target)", platform.system() == "Darwin" and platform.machine() == "arm64", host))
    if platform.system() == "Darwin":
        for tool in ("codesign", "hdiutil", "ditto"):
            checks.append((tool, shutil.which(tool) is not None, shutil.which(tool) or "missing"))
    from .disasm import find_gnu_objdump
    gnu = find_gnu_objdump()
    checks.append(("GNU objdump (legacy tests only, optional)", True, gnu or "not found; 7 legacy tests will skip"))
    return checks
