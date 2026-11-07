"""Simulate the frozen environment: block the excluded modules, install the
runtime hook stand-ins, then exercise the application end to end.

    python tests/frozen_simulation.py

A rebuild takes about half a minute, so validating an exclusion list against a
simulated bundle is much faster. The simulation proves that the exclusion list
is self-consistent - it cannot prove that the real frozen executable starts, so
``tests/acceptance_frozen.py`` still has to run against the packaged build.
"""

import json
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

BLOCKED = {
    # Mirrors NetScope.spec. zipfile is deliberately absent: the PyInstaller
    # runtime hook reads base_library.zip, so it has to stay in the bundle.
    "ssl", "_ssl", "_hashlib",
    "setuptools", "pkg_resources", "_distutils_hack", "distutils", "packaging",
    "jinja2", "tornado",
    "pydoc", "pydoc_data", "doctest", "unittest", "test", "_pyrepl",
    "multiprocessing", "lib2to3", "idlelib", "tkinter", "sqlite3",
    "pdb", "bdb", "cProfile", "pstats", "profile", "difflib", "tarfile",
    "xmlrpc",
    "lzma", "bz2",
    "decimal", "_decimal", "_pydecimal", "fractions", "statistics",
    "bottle", "ujson", "configparser",
    "typing_extensions",
    "urllib.request", "http.cookiejar",
    "xml", "xml.etree", "xml.etree.ElementTree", "xml.parsers",
    "xml.parsers.expat", "xml.sax", "xml.dom", "pyexpat", "_elementtree",
    "win32evtlog", "pythoncom", "pywintypes", "win32api", "win32con",
    "win32gui", "win32process", "win32file",
    "webview.platforms.qt", "webview.platforms.gtk", "webview.platforms.cocoa",
    "webview.platforms.cef", "webview.platforms.android",
    "webview.platforms.mshtml",
}


class Blocker:
    """Minimal meta path finder that refuses the excluded modules."""

    def find_spec(self, fullname, path=None, target=None):
        root = fullname.split(".")[0]
        if fullname in BLOCKED or root in BLOCKED:
            raise ImportError(f"blocked: {fullname}")
        return None


sys.meta_path.insert(0, Blocker())

import http.client  # noqa: E402  (after the blocker, so it sees the stand-ins)

import runtime_hook  # noqa: E402  (installs the stand-ins)

import app  # noqa: E402

print("app imported OK")

STUBBED = {"bottle", "typing_extensions", "xml", "xml.etree", "xml.etree.ElementTree", "ssl"}

# setuptools installs a .pth hook, so the interpreter loads _distutils_hack
# before the blocker exists. It is a build-machine artefact, not something the
# application pulls in, so the absence check does not apply to it.
PRELOADED = {"_distutils_hack"}

# Third-party packages that are installed on this machine: the application must
# not import them, but they cannot be checked for "not importable" here.
THIRD_PARTY = {"setuptools", "pkg_resources", "packaging", "jinja2", "tornado"}

# The excluded modules must really be gone (except the ones the runtime hook
# replaces with a stand-in).
for name in sorted(BLOCKED):
    if name in PRELOADED:
        continue
    if name in STUBBED:
        module = sys.modules.get(name)
        assert module is not None, f"FAIL: stand-in for {name} is missing"
        assert getattr(module, "_netscope_stub", False), f"FAIL: {name} is the real package"
        continue
    if name in sys.modules:
        raise SystemExit(f"FAIL: {name} was imported before the blocker")
    if name in THIRD_PARTY:
        continue
    try:
        __import__(name)
    except ImportError:
        continue
    raise SystemExit(f"FAIL: {name} is still importable")

print("all excluded modules are absent")

# hashlib must still work through the builtin implementations.
import hashlib  # noqa: E402
import hmac  # noqa: E402
import secrets as secrets_mod  # noqa: E402
import uuid  # noqa: E402

assert hashlib.sha256(b"netscope").hexdigest() == (
    "1930d4f04441c92608c4cea72e1b2e50f95e3694395b835f6ad9f7ffefbdcd64"
)
assert hashlib.new("sha256", b"netscope").digest()
assert hashlib.md5(b"netscope", usedforsecurity=False).hexdigest()
assert hashlib.sha3_256(b"netscope").hexdigest()
assert hmac.new(b"k", b"v", hashlib.sha256).digest()
assert secrets_mod.token_urlsafe(24)
assert uuid.uuid4()
print("hashlib / hmac / secrets / uuid work without _hashlib")

# The desktop shell dependencies must import with the stand-ins in place.
import webview  # noqa: E402
import webview.http  # noqa: E402
import clr_loader  # noqa: E402

print("webview + clr_loader import OK")

from http.server import ThreadingHTTPServer  # noqa: E402

server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
port = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()


def call(path, payload=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"X-NetScope-Token": app.TOKEN}
        if body:
            headers["Content-Type"] = "application/json"
        connection.request("GET" if payload is None else "POST", path, body, headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


status, payload = call("/api/health")
assert status == 200 and payload.get("name") == "NetScope", payload
print("health:", payload)

assert app.running_instance(port) is True, "single-instance probe must detect the running server"
assert app.running_instance(port + 1) is False, "probe must not report a free port as busy"
print("running_instance probe works")

status, started = call("/api/scan", {"targets": "127.0.0.1", "ports": "22,80", "timeout": 0.4,
                                     "concurrency": 16, "scanPorts": True})
print("scan started:", started["status"], started["total"])

deadline = time.time() + 30
while time.time() < deadline:
    _, state = call("/api/state")
    if state["status"] not in {"running", "stopping"}:
        break
    time.sleep(0.3)

print("scan finished:", state["status"], "online:", state["online"], "elapsed:", state["elapsed"])
assert state["status"] in {"completed", "stopped", "error"}, state
server.shutdown()
print("SIMULATION PASSED")
