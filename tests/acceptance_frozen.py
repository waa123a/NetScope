"""Acceptance test for the frozen portable build.

Copies the exe into an empty directory, starts it, drives a real scan through
the local API, checks the desktop window, the history, the CSV export, the
single-instance behaviour and the exit confirmation, then cleans up.

    python -m PyInstaller --noconfirm --clean --distpath portable \
        --workpath build NetScope.spec
    python tests/acceptance_frozen.py

The script drives the real window: WebView2's remote debugging port is used to
read the DOM and take a screenshot, and native dialogs are found by enumerating
the windows of the application process (matching by title alone also matches a
browser window left over from an earlier run).
"""

import base64
import ctypes
import http.client
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
EXE = PROJECT / "portable" / "NetScope.exe"
SANDBOX = Path(os.environ.get("TEMP", "C:/Temp")) / "netscope-accept"
PORT = 8765
CDP_PORT = 9333
WINDOW_TITLE = "NetScope · 网络扫描控制台"

user32 = ctypes.windll.user32
failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> bool:
    print(("PASS  " if ok else "FAIL  ") + label + (f"   [{detail}]" if detail else ""), flush=True)
    if not ok:
        failures.append(label)
    return ok


def api(path: str, payload=None, timeout: float = 10.0):
    connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    try:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {}
        if body:
            headers["Content-Type"] = "application/json"
        connection.request("GET" if payload is None else "POST", path, body, headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


def api_with_token(token: str, path: str, payload=None, timeout: float = 10.0):
    connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    try:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"X-NetScope-Token": token}
        if body:
            headers["Content-Type"] = "application/json"
        connection.request("GET" if payload is None else "POST", path, body, headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


def fetch(path: str, timeout: float = 10.0) -> bytes:
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=timeout) as response:
        return response.read()


def wait_for(predicate, timeout: float, label: str) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        time.sleep(0.25)
    check(f"{label}（等待 {timeout:.0f}s）", False)
    return False


def window_handle(title: str):
    return user32.FindWindowW(None, title)


def dialog_handle(title: str):
    return user32.FindWindowW("#32770", title)


def all_windows() -> list:
    """Return (class, title, hwnd, pid) of every top-level window."""
    found: list = []
    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

    def callback(hwnd, _):
        owner = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        buffer = ctypes.create_unicode_buffer(512)
        user32.GetClassNameW(hwnd, buffer, 512)
        title_buffer = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, title_buffer, 512)
        found.append((buffer.value, title_buffer.value, hwnd, owner.value))
        return True

    user32.EnumWindows(EnumWindowsProc(callback), 0)
    return found


def process_path(pid: int) -> str:
    """Return the executable path of a process (empty when unknown)."""
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return ""
    try:
        size = ctypes.c_ulong(512)
        buffer = ctypes.create_unicode_buffer(512)
        if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return buffer.value
        return ""
    finally:
        kernel32.CloseHandle(handle)


def own_window(title: str, exe: str):
    """Find a window by title that belongs to the application under test."""
    for _class, window_title, hwnd, pid in all_windows():
        if window_title == title and process_path(pid).lower() == exe.lower():
            return hwnd
    return None


def own_dialog(title: str, exe: str):
    """Find a message box by title that belongs to the application under test."""
    for window_class, window_title, hwnd, pid in all_windows():
        if window_class == "#32770" and window_title == title:
            if process_path(pid).lower() == exe.lower():
                return hwnd
    return None


# ---------------------------------------------------------------- prepare ---
if SANDBOX.exists():
    shutil.rmtree(SANDBOX, ignore_errors=True)
SANDBOX.mkdir(parents=True)
target = SANDBOX / "NetScope.exe"
shutil.copy2(EXE, target)
check("空目录中只放入 exe", sorted(p.name for p in SANDBOX.iterdir()) == ["NetScope.exe"])

# A leftover instance would answer the API instead of the one under test.
try:
    api("/api/health", timeout=1.0)
    print("端口 8765 已被占用，请先关闭其他 NetScope 实例", file=sys.stderr)
    sys.exit(2)
except Exception:
    pass

env = dict(os.environ)
env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
    f"--remote-debugging-port={CDP_PORT} --remote-allow-origins=*"
)
env["NETSCOPE_DEBUG_WEBVIEW"] = "1"

process = subprocess.Popen([str(target)], cwd=str(SANDBOX), env=env)
print(f"started pid={process.pid}", flush=True)

# ------------------------------------------------------------------ boot ---
booted = wait_for(lambda: api("/api/health")[1].get("name") == "NetScope", 90, "本地服务启动")
check("本地服务启动", booted)
if not booted:
    process.kill()
    sys.exit(1)

token = fetch("/").decode("utf-8")
start = token.find("__SCAN_TOKEN__")
token = token[start:].split('"')[1] if start >= 0 else ""
check("页面注入了访问令牌", bool(token))

check("桌面窗口已创建", wait_for(lambda: bool(own_window(WINDOW_TITLE, str(target))), 60, "桌面窗口"))

# --------------------------------------------------------------- scanning ---
_, network = api("/api/network")
print(f"本机网络：{network}", flush=True)
_, started = api_with_token(token, "/api/scan", {
    "targets": network["network"], "ports": "22,80,443,445,3389,8080",
    "timeout": 0.8, "concurrency": 256, "scanPorts": True, "resolveNames": False,
})
check("扫描任务已启动", started.get("status") == "running", f"total={started.get('total')}")


def finished() -> bool:
    return api("/api/state")[1]["status"] not in {"running", "stopping"}


wait_for(finished, 90, "扫描完成")
_, state = api("/api/state")
print(f"扫描结果：online={state['online']} elapsed={state['elapsed']}s", flush=True)
check("扫描发现在线设备", state["online"] > 0, f"online={state['online']}")
check("扫描耗时在合理范围", state["elapsed"] < 20, f"{state['elapsed']}s")
check("结果包含设备类型", all(item.get("deviceType") for item in state["results"]))
check("结果包含 MAC 地址", all(item.get("mac") for item in state["results"]))
check("本机在结果中", any(item["ip"] == network["address"] for item in state["results"]))

# --------------------------------------------------------------- history ---
_, history = api("/api/history")
check("历史记录已保存", len(history) >= 1, f"records={len(history)}")
if history:
    record = history[0]
    check("历史记录包含设备数", record.get("online", 0) > 0, f"online={record.get('online')}")
    check("历史记录可回读详情", api(f"/api/history/{record['id']}")[0] == 200)

# ------------------------------------------------------------------ csv ---
csv_bytes = fetch(f"/api/export?token={urllib.parse.quote(token)}")
csv_text = csv_bytes.decode("utf-8-sig")
lines = [line for line in csv_text.splitlines() if line.strip()]
check("CSV 可导出", len(lines) >= 2, f"lines={len(lines)}")
check("CSV 表头正确", lines[0].startswith("IP") or "IP" in lines[0], lines[0][:60])

# ------------------------------------------------------------------ dom ---
try:
    import websocket

    targets = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/list", timeout=5).read())
    pages = [t for t in targets if t.get("type") == "page" and "127.0.0.1" in t.get("url", "")]
    check("WebView2 远程调试可用", bool(pages))
    if pages:
        ws = websocket.create_connection(pages[0]["webSocketDebuggerUrl"], timeout=15)

        def evaluate(expression: str):
            ws.send(json.dumps({"id": 1, "method": "Runtime.evaluate",
                                "params": {"expression": expression, "returnByValue": True}}))
            while True:
                message = json.loads(ws.recv())
                if message.get("id") == 1:
                    return message.get("result", {}).get("result", {}).get("value")

        rows = 0
        deadline = time.time() + 15
        while time.time() < deadline:
            rows = evaluate("document.querySelectorAll('#resultsBody tr').length")
            if isinstance(rows, int) and rows > 0:
                break
            time.sleep(0.5)
        badge = evaluate("document.querySelector('#resultBadge')?.textContent")
        title = evaluate("document.title")
        print(f"页面：title={title!r} badge={badge!r} rows={rows}", flush=True)
        check("页面渲染出结果表格", isinstance(rows, int) and rows > 0, f"rows={rows}")

        ws.send(json.dumps({"id": 2, "method": "Page.captureScreenshot", "params": {"format": "png"}}))
        shot = None
        while True:
            message = json.loads(ws.recv())
            if message.get("id") == 2:
                shot = message.get("result", {}).get("data")
                break
        if shot:
            (SANDBOX / "netscope-ui.png").write_bytes(base64.b64decode(shot))
            print(f"截图已保存：{SANDBOX / 'netscope-ui.png'}", flush=True)
        ws.close()
except Exception as exc:
    check("WebView2 远程调试可用", False, repr(exc))

# ------------------------------------------------------- single instance ---
second = subprocess.Popen([str(target)], cwd=str(SANDBOX), env=env)
time.sleep(4)
check("第二次启动不会开第二个服务", second.poll() is not None or
      api("/api/health")[1].get("name") == "NetScope")
try:
    second.wait(timeout=8)
    check("第二个实例自行退出", True)
except subprocess.TimeoutExpired:
    check("第二个实例自行退出", False)
    second.kill()

# ------------------------------------------------------- exit confirmation ---
handle = own_window(WINDOW_TITLE, str(target))
check("主窗口仍在", bool(handle))
user32.PostMessageW(handle, 0x0010, 0, 0)  # WM_CLOSE
dialog = None
for _ in range(40):
    dialog = own_dialog("退出 NetScope", str(target))
    if dialog:
        break
    time.sleep(0.25)
check("关闭时弹出确认对话框", bool(dialog))
time.sleep(0.5)
check("取消前程序仍在运行", process.poll() is None)
if dialog:
    user32.SendMessageW(dialog, 0x0111, 6, 0)  # WM_COMMAND / IDYES
deadline = time.time() + 20
while time.time() < deadline and process.poll() is None:
    time.sleep(0.25)
check("确认后程序退出", process.poll() is not None)
time.sleep(1.5)
try:
    api("/api/health")
    check("端口已释放", False)
except Exception:
    check("端口已释放", True)

# ------------------------------------------------------------------ data ---
data_dir = SANDBOX / "data"
check("数据写在 exe 同级目录", (data_dir / "history.json").exists(),
      str(sorted(p.name for p in data_dir.iterdir())) if data_dir.exists() else "missing")
check("exe 同级不残留浏览器缓存", not (data_dir / "webview").exists(),
      str(sorted(p.name for p in data_dir.iterdir())) if data_dir.exists() else "missing")
cache_dir = Path(os.environ.get("LOCALAPPDATA", "C:/Users/Public")) / "NetScope" / "webview"
check("浏览器缓存改放用户目录", cache_dir.exists(), str(cache_dir))

print()
if failures:
    print(f"验收未通过：{len(failures)} 项失败 -> {failures}")
    sys.exit(1)
print("冻结版验收全部通过")
