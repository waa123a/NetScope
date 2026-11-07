# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller recipe for the portable NetScope build.

The executable is meant to stay small enough to copy around, so everything the
application never touches is left out: the TLS stack, build tooling that rides
along with the desktop backend, unused standard library corners and the
resources of the other platforms.
"""

import os

# PyInstaller injects SPECPATH (the directory holding this recipe), so the
# build works from any checkout instead of one hard-coded developer path.
ROOT = SPECPATH

EXCLUDES = [
    # TLS: NetScope serves plain HTTP on the loopback interface only.
    # Dropping _hashlib as well removes libcrypto-3.dll, which alone is 1.7 MB.
    "ssl", "_ssl", "_hashlib", "cryptography",
    # NOTE: cffi and its _cffi_backend must stay - clr_loader imports cffi to
    # load hostfxr, and cffi.FFI() imports the backend extension directly.
    # Without them the .NET runtime for the WebView2 shell cannot start.
    # Packaging helpers that come along with the desktop backend.
    "setuptools", "pkg_resources", "_distutils_hack", "distutils", "packaging",
    "jinja2", "tornado",
    # Standard library corners a windowed application never reaches.
    # zipfile is deliberately absent: the PyInstaller runtime hook reads
    # base_library.zip, so excluding it breaks the frozen build on startup.
    "pydoc", "pydoc_data", "doctest", "unittest", "test", "_pyrepl",
    "multiprocessing", "lib2to3", "idlelib", "tkinter", "sqlite3",
    "pdb", "bdb", "cProfile", "pstats", "profile", "difflib", "tarfile",
    "xmlrpc",
    # Optional compressors: shutil falls back gracefully without them.
    "lzma", "bz2",
    # Only random.statistics() needs the decimal stack.
    "decimal", "_decimal", "_pydecimal", "fractions", "statistics",
    # Only the WSGI server of pywebview needs bottle; the runtime hook
    # installs a stand-in so webview.http can still be imported.
    "bottle", "ujson", "configparser",
    # Python 3.13 ships every name pywebview borrows from typing_extensions.
    "typing_extensions",
    # urllib.request is only used for the health probe, which now speaks
    # HTTP/1.1 through http.client, and the XML parser only formats a .NET
    # error that never happens.
    "urllib.request", "http.cookiejar",
    "xml", "xml.etree", "xml.etree.ElementTree", "xml.parsers",
    "xml.parsers.expat", "xml.sax", "xml.dom", "pyexpat", "_elementtree",
    # Windows event log and COM bridges of the legacy browser backend.
    "win32evtlog", "pythoncom", "pywintypes", "win32api", "win32con",
    "win32gui", "win32process", "win32file",
    # Desktop backends that cannot run on Windows.
    "webview.platforms.qt", "webview.platforms.gtk", "webview.platforms.cocoa",
    "webview.platforms.cef", "webview.platforms.android",
    "webview.platforms.mshtml",
]

# Resources that belong to other platforms or are pure documentation.
DROP_DATA_PARTS = ("win-x86", "win-arm64", "clr_loader/ffi/dlls/x86")
DROP_DATA_FILES = ("pywebview-android.jar", "Python.Runtime.xml")

# pywebview adds the WebView2 loader folders to PATH before the .NET host is
# started, and it refuses to start when one of those folders is missing:
#
#     for platform in ('win-arm64', 'win-x64', 'win-x86'):
#         os.environ['Path'] += ';' + interop_dll_path(platform)
#
# interop_dll_path() only checks that the *folder* exists, never the DLL inside
# it. The arm64 and x86 loaders can therefore be replaced by a marker file: the
# folder survives the bundle, the 270 KB of foreign binaries do not, and the
# x64 loader that NetScope actually loads stays untouched.
RUNTIME_PLACEHOLDERS = (
    ("win-arm64", "webview\\lib\\runtimes\\win-arm64\\native"),
    ("win-x86", "webview\\lib\\runtimes\\win-x86\\native"),
)


def _wanted(entry) -> bool:
    source = entry[0].replace("\\", "/")
    if any(part in source for part in DROP_DATA_PARTS):
        return False
    return not source.endswith(DROP_DATA_FILES)


def _placeholder_entries() -> list:
    """Write the marker files that keep pywebview's runtime folders alive."""
    entries = []
    for name, destination in RUNTIME_PLACEHOLDERS:
        folder = os.path.join(workpath, "placeholders", name)
        os.makedirs(folder, exist_ok=True)
        marker = os.path.join(folder, "README.txt")
        with open(marker, "w", encoding="utf-8") as handle:
            handle.write(
                "This folder only exists so that pywebview can add it to PATH.\n"
                "The matching WebView2Loader.dll is not shipped: NetScope runs\n"
                "as a 64-bit process and loads lib/runtimes/win-x64/native.\n"
            )
        entries.append((os.path.join(destination, "README.txt"), marker, "DATA"))
    return entries


a = Analysis(
    [os.path.join(ROOT, "app.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[(os.path.join(ROOT, "static"), "static")],
    hiddenimports=[],
    hookspath=[os.path.join(ROOT, "hooks")],
    hooksconfig={},
    runtime_hooks=[os.path.join(ROOT, "runtime_hook.py")],
    excludes=EXCLUDES,
    noarchive=False,
    optimize=2,
)

a.datas = [entry for entry in a.datas if _wanted(entry)]
a.datas += _placeholder_entries()
a.binaries = [entry for entry in a.binaries if _wanted(entry)]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='NetScope',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=[os.path.join(ROOT, "static", "netscope.ico")],
)
