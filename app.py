"""NetScope local web application. Run with: python app.py"""

from __future__ import annotations

import argparse
import csv
import http.client
import io
import json
import mimetypes
import os
import secrets
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from history import HistoryManager
from scanner import ScanManager, local_network

try:
    import webview
except Exception:  # The browser fallback still works without the desktop shell.
    webview = None

ROOT = Path(__file__).resolve().parent
RESOURCE_ROOT = Path(getattr(sys, "_MEIPASS", ROOT))
APP_ROOT = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else ROOT
STATIC = RESOURCE_ROOT / "static"
ICON = STATIC / "netscope.ico"
TOKEN = secrets.token_urlsafe(24)
HISTORY = HistoryManager(APP_ROOT / "data" / "history.json")
MANAGER = ScanManager(on_complete=HISTORY.add)
MAX_BODY = 16 * 1024
SERVER: ThreadingHTTPServer | None = None
WINDOW: object | None = None
EXITING = False
UI_MODE = "desktop"
WINDOW_TITLE = "NetScope · 网络扫描控制台"


def app_cache_dir() -> Path:
    """Return the per-user directory for rebuildable caches.

    Only caches belong here: the WebView2 profile grows past 10 MB of shader
    and page caches, and burying that next to the executable would make the
    portable folder look like leftover junk. User data stays in the portable
    folder so that it travels with the program.
    """
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / "NetScope"
    return Path.home() / "AppData" / "Local" / "NetScope"


def webview_log(message: str) -> None:
    """Write desktop-shell diagnostics when NETSCOPE_DEBUG_WEBVIEW=1."""
    if os.environ.get("NETSCOPE_DEBUG_WEBVIEW") != "1":
        return
    try:
        path = APP_ROOT / "data" / "webview-debug.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{time.strftime('%H:%M:%S')} {message}\n")
    except Exception:
        pass


def show_message(message: str, error: bool = False) -> None:
    """Show a native dialog for windowed builds; fall back to the console."""
    if os.environ.get("NETSCOPE_DEBUG_WEBVIEW") == "1":
        # A frozen build has no console to read, and the native dialog blocks
        # until it is dismissed, so mirror the message into the debug log.
        webview_log(f"message({error=}) {message}")
    if sys.platform == "win32" and getattr(sys, "frozen", False):
        try:
            import ctypes

            flags = 0x10 if error else 0x40
            ctypes.windll.user32.MessageBoxW(None, message, "NetScope", flags)
            return
        except Exception:
            pass
    stream = sys.stderr if error else sys.stdout
    if stream is not None:
        print(message, file=stream)


def request_shutdown() -> None:
    global EXITING
    server = SERVER
    if server is None:
        return
    EXITING = True
    MANAGER.stop()
    window = WINDOW
    if window is not None:
        try:
            window.destroy()
        except Exception:
            pass
    server.shutdown()


def confirm_exit() -> bool:
    """Ask before closing the desktop window; safe default is 'No'."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes

        hwnd = ctypes.windll.user32.FindWindowW(None, WINDOW_TITLE) or None
        flags = 0x04 | 0x20 | 0x100 | 0x40000 | 0x10000  # YESNO | QUESTION | DEFBUTTON2 | TOPMOST | SETFOREGROUND
        answer = ctypes.windll.user32.MessageBoxW(
            hwnd,
            "确定要退出 NetScope 吗？\n\n正在进行的扫描会停止，本地服务也会关闭。",
            "退出 NetScope",
            flags,
        )
        return answer == 6
    except Exception:
        return True


def desktop_background() -> str:
    """Match the window fill to the system theme to avoid a white flash."""
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        ) as key:
            light, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return "#f5f6fa" if light else "#111219"
    except Exception:
        return "#f5f6fa"


def open_browser(url: str) -> None:
    try:
        opened = webbrowser.open(url)
    except Exception:
        opened = False
    if not opened:
        show_message(f"NetScope 已启动，但无法自动打开浏览器。\n请在浏览器中访问：{url}")


def running_instance(port: int) -> bool:
    """Return True when a NetScope service already owns the local port."""
    connection = None
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1.0)
        connection.request("GET", "/api/health")
        response = connection.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        return payload.get("name") == "NetScope"
    except Exception:
        return False
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def focus_existing_window() -> bool:
    """Bring the already running desktop window back to the foreground."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        user32 = ctypes.windll.user32
        hwnd = user32.FindWindowW(None, WINDOW_TITLE)
        if not hwnd:
            return False
        if user32.IsIconic(hwnd):
            user32.ShowWindow(hwnd, 9)
        user32.AllowSetForegroundWindow(-1)
        user32.BringWindowToTop(hwnd)
        user32.SwitchToThisWindow(hwnd, True)
        user32.SetForegroundWindow(hwnd)
        return True
    except Exception:
        return False


def results_csv(results: list[dict]) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["IP 地址", "主机名", "设备类型", "MAC 地址", "开放端口", "服务"])
    for result in results:
        hostname = result["hostname"]
        if hostname.startswith(("=", "+", "-", "@")):
            hostname = "'" + hostname
        writer.writerow([result["ip"], hostname, result.get("deviceType", "未知设备"),
                         result.get("mac", ""),
                         " ".join(str(item["port"]) for item in result["ports"]),
                         " ".join(item["service"] for item in result["ports"])])
    return ("\ufeff" + output.getvalue()).encode("utf-8")


def choose_save_path(default_name: str) -> str | None:
    """Show the native Save As dialog for the desktop window."""
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    class OPENFILENAMEW(ctypes.Structure):
        _fields_ = [
            ("lStructSize", wintypes.DWORD),
            ("hwndOwner", wintypes.HWND),
            ("hInstance", ctypes.c_void_p),
            ("lpstrFilter", wintypes.LPCWSTR),
            ("lpstrCustomFilter", wintypes.LPWSTR),
            ("nMaxCustFilter", wintypes.DWORD),
            ("nFilterIndex", wintypes.DWORD),
            ("lpstrFile", wintypes.LPWSTR),
            ("nMaxFile", wintypes.DWORD),
            ("lpstrFileTitle", wintypes.LPWSTR),
            ("nMaxFileTitle", wintypes.DWORD),
            ("lpstrInitialDir", wintypes.LPCWSTR),
            ("lpstrTitle", wintypes.LPCWSTR),
            ("Flags", wintypes.DWORD),
            ("nFileOffset", wintypes.WORD),
            ("nFileExtension", wintypes.WORD),
            ("lpstrDefExt", wintypes.LPCWSTR),
            ("lCustData", wintypes.LPARAM),
            ("lpfnHook", ctypes.c_void_p),
            ("lpTemplateName", wintypes.LPCWSTR),
            ("pvReserved", ctypes.c_void_p),
            ("dwReserved", wintypes.DWORD),
            ("FlagsEx", wintypes.DWORD),
        ]

    downloads = Path.home() / "Downloads"
    initial = str(downloads if downloads.is_dir() else Path.home())
    buffer = ctypes.create_unicode_buffer(1024)
    buffer.value = default_name
    dialog = OPENFILENAMEW()
    dialog.lStructSize = ctypes.sizeof(OPENFILENAMEW)
    dialog.hwndOwner = ctypes.windll.user32.FindWindowW(None, WINDOW_TITLE)
    dialog.lpstrFilter = "CSV 文件 (*.csv)\0*.csv\0所有文件 (*.*)\0*.*\0\0"
    dialog.lpstrFile = ctypes.cast(buffer, wintypes.LPWSTR)
    dialog.nMaxFile = len(buffer)
    dialog.lpstrInitialDir = initial
    dialog.lpstrTitle = "保存扫描结果"
    dialog.lpstrDefExt = "csv"
    dialog.Flags = 0x00080002 | 0x00000800 | 0x00000008  # EXPLORER | OVERWRITEPROMPT | PATHMUSTEXIST | NOCHANGEDIR
    ole32 = ctypes.windll.ole32
    hr = ole32.CoInitializeEx(None, 0x2)  # APARTMENTTHREADED
    initialized = hr >= 0  # S_OK or S_FALSE; RPC_E_CHANGED_MODE means someone else owns COM
    try:
        get_save_name = ctypes.windll.comdlg32.GetSaveFileNameW
        get_save_name.argtypes = [ctypes.POINTER(OPENFILENAMEW)]
        get_save_name.restype = wintypes.BOOL
        if get_save_name(ctypes.byref(dialog)):
            return buffer.value
        return None
    finally:
        if initialized:
            ole32.CoUninitialize()


class DesktopApi:
    """Small JS bridge that gives the desktop window native file saving."""

    def save_csv(self, record_id: str = "") -> dict:
        record_id = (record_id or "").strip()
        if record_id:
            record = HISTORY.get(record_id)
            if record is None:
                return {"error": "历史记录不存在"}
            results = record["results"]
            default_name = f"netscope-history-{record_id}.csv"
        else:
            results = MANAGER.state()["results"]
            default_name = f"netscope-results-{time.strftime('%Y%m%d-%H%M%S')}.csv"
        if not results:
            return {"error": "没有可导出的扫描结果"}
        path = choose_save_path(default_name)
        if not path:
            return {"cancelled": True}
        try:
            Path(path).write_bytes(results_csv(results))
        except Exception as exc:
            return {"error": f"保存失败：{exc}"}
        return {"path": path}


class Handler(BaseHTTPRequestHandler):
    server_version = "NetScope/1.0"
    # Keep the connection alive: the interface polls the state endpoint every
    # few hundred milliseconds and a fresh TCP handshake per poll is wasteful.
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        return

    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data: dict | list, status: int = 200) -> None:
        self._send(status, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _error(self, message: str, status: int = 400) -> None:
        self._json({"error": message}, status)

    def _authorized(self) -> bool:
        supplied = self.headers.get("X-NetScope-Token", "")
        if not supplied:
            supplied = parse_qs(urlparse(self.path).query).get("token", [""])[0]
        return secrets.compare_digest(supplied, TOKEN)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        try:
            if path == "/":
                html = (
                    (STATIC / "index.html").read_text(encoding="utf-8")
                    .replace("__TOKEN__", TOKEN)
                    .replace("__UI_MODE_VALUE__", UI_MODE)
                )
                self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
            elif path in {"/static/app.js", "/static/styles.css", "/static/netscope.ico"}:
                file = STATIC / path.rsplit("/", 1)[-1]
                content_type = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
                self._send(200, file.read_bytes(), f"{content_type}; charset=utf-8")
            elif path == "/api/state":
                self._json(MANAGER.state())
            elif path == "/api/network":
                self._json(local_network())
            elif path == "/api/health":
                self._json({"ok": True, "name": "NetScope"})
            elif path == "/api/history":
                self._json(HISTORY.list())
            elif path.startswith("/api/history/") and path != "/api/history/export":
                record = HISTORY.get(path.rsplit("/", 1)[-1])
                if record is None:
                    self._error("历史记录不存在", 404)
                else:
                    self._json(record)
            elif path == "/api/history/export":
                if not self._authorized():
                    self._error("请求验证失败", 403)
                    return
                record_id = parse_qs(urlparse(self.path).query).get("id", [""])[0]
                record = HISTORY.get(record_id)
                if record is None:
                    self._error("历史记录不存在", 404)
                    return
                self._send(200, results_csv(record["results"]), "text/csv; charset=utf-8",
                           {"Content-Disposition": f"attachment; filename=netscope-history-{record_id}.csv"})
            elif path == "/api/export":
                if not self._authorized():
                    self._error("请求验证失败", 403)
                    return
                self._send(200, results_csv(MANAGER.state()["results"]), "text/csv; charset=utf-8",
                           {"Content-Disposition": "attachment; filename=netscope-results.csv"})
            else:
                self._error("未找到请求的资源", 404)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:
            self._error(f"服务错误：{exc}", 500)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if not self._authorized():
            self._error("请求验证失败", 403)
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            self._error("请求格式必须为 JSON", 415)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                self._error("请求内容无效", 413)
                return
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("请求内容必须是对象")
            if path == "/api/scan":
                job = MANAGER.start(payload)
                self._json(job.snapshot(), 202)
            elif path == "/api/stop":
                job = MANAGER.stop()
                self._json(job.snapshot() if job else MANAGER.state(), 202)
            elif path == "/api/shutdown":
                self._json({"ok": True})
                timer = threading.Timer(0.4, request_shutdown)
                timer.daemon = True
                timer.start()
            elif path == "/api/history/delete":
                if HISTORY.delete(str(payload.get("id", ""))):
                    self._json({"ok": True, "records": HISTORY.list()})
                else:
                    self._error("历史记录不存在", 404)
            elif path == "/api/history/clear":
                count = HISTORY.clear()
                self._json({"ok": True, "deleted": count, "records": []})
            else:
                self._error("未找到请求的资源", 404)
        except RuntimeError as exc:
            self._error(str(exc), 409)
        except (ValueError, json.JSONDecodeError) as exc:
            self._error(str(exc), 400)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:
            self._error(f"服务错误：{exc}", 500)


def run_server(server: ThreadingHTTPServer) -> None:
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在停止 NetScope…")
    finally:
        MANAGER.stop()
        server.server_close()


def run_browser(server: ThreadingHTTPServer, url: str, auto_open: bool = True) -> None:
    if auto_open:
        browser_timer = threading.Timer(0.5, lambda: open_browser(url))
        browser_timer.daemon = True
        browser_timer.start()
    run_server(server)


def run_desktop(server: ThreadingHTTPServer, url: str) -> None:
    global WINDOW, UI_MODE
    server_thread = threading.Thread(target=server.serve_forever, name="netscope-http", daemon=True)
    server_thread.start()
    width, height, x, y = 1440, 900, None, None
    try:
        screen = webview.screens[0] if webview.screens else None
        if screen:
            width = max(1000, min(1700, int(screen.width * 0.92)))
            height = max(680, min(1000, int(screen.height * 0.92)))
            x = max(0, int(screen.x + (screen.width - width) / 2))
            y = max(0, int(screen.y + (screen.height - height) / 2))
        WINDOW = webview.create_window(
            WINDOW_TITLE,
            url,
            width=width,
            height=height,
            x=x,
            y=y,
            min_size=(1024, 700),
            background_color=desktop_background(),
            text_select=True,
            js_api=DesktopApi(),
        )
        window = WINDOW

        def reset_scroll(*_: object) -> None:
            if os.environ.get("NETSCOPE_DEBUG_WEBVIEW") == "1":
                webview_log("loaded event")
                inspect("loaded")
            try:
                window.evaluate_js("window.scrollTo(0, 0)")
            except Exception:
                pass

        def nudge_repaint(*_: object) -> None:
            """WebView2 can stay unpainted when the window appears behind another app."""
            if sys.platform != "win32":
                return
            try:
                import ctypes

                hwnd = ctypes.windll.user32.FindWindowW(None, WINDOW_TITLE)
                if hwnd:
                    ctypes.windll.user32.RedrawWindow(hwnd, None, None, 0x0001 | 0x0080 | 0x0100 | 0x0004)
            except Exception:
                pass

        def inspect(label: str) -> None:
            for expr in (
                "location.href",
                "document.readyState",
                "document.title",
                "innerWidth + 'x' + innerHeight + ' @' + devicePixelRatio",
                "document.body ? document.body.children.length : -1",
                "document.body ? document.body.innerText.slice(0, 80) : ''",
            ):
                try:
                    webview_log(f"{label} {expr} -> {window.evaluate_js(expr)!r}")
                except Exception as exc:
                    webview_log(f"{label} {expr} !! {exc!r}")

        window.events.loaded += reset_scroll
        window.events.shown += nudge_repaint
        window.events.restored += nudge_repaint

        def on_closing(*_: object) -> bool:
            if EXITING:
                return True
            confirmed = confirm_exit()
            webview_log(f"closing confirmed={confirmed}")
            return confirmed

        window.events.closing += on_closing

        if os.environ.get("NETSCOPE_DEBUG_WEBVIEW") == "1":
            def on_shown(*_: object) -> None:
                webview_log("shown event")
                inspect("shown")

            window.events.shown += on_shown

            def watchdog() -> None:
                for delay in (2, 5, 10):
                    time.sleep(delay)
                    inspect(f"watch+{delay}s")

            threading.Thread(target=watchdog, name="netscope-webview-diag", daemon=True).start()

        # The WebView2 profile is a browser cache, not user data: it grows to
        # more than 10 MB of shader and page caches. Keeping it next to the exe
        # would bury the portable folder under junk, so it goes to the per-user
        # application data directory instead.
        storage = app_cache_dir() / "webview"
        storage.mkdir(parents=True, exist_ok=True)
        webview.start(debug=False, icon=str(ICON) if ICON.exists() else None,
                      private_mode=False, storage_path=str(storage))
    except Exception as exc:
        WINDOW = None
        UI_MODE = "browser"
        show_message(f"无法打开桌面窗口，已改用浏览器。\n\n{exc}", error=True)
        open_browser(url)
        try:
            server_thread.join()
        except KeyboardInterrupt:
            pass
    finally:
        MANAGER.stop()
        try:
            server.shutdown()
        except Exception:
            pass
        server.server_close()
        WINDOW = None


def main() -> None:
    global SERVER, UI_MODE
    parser = argparse.ArgumentParser(description="NetScope - 本地 IP 与端口扫描工具")
    parser.add_argument("--port", type=int, default=8765, help="本地网页端口，默认 8765")
    parser.add_argument("--browser", action="store_true", help="在默认浏览器中打开界面")
    parser.add_argument("--no-browser", action="store_true", help="仅启动本地服务，不打开界面（调试用）")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        show_message("端口应在 1024 到 65535 之间。", error=True)
        return
    url = f"http://127.0.0.1:{args.port}"
    if running_instance(args.port):
        if args.no_browser:
            return
        if args.browser:
            open_browser(url)
        elif not focus_existing_window():
            show_message("NetScope 已在运行。\n请从任务栏切换到已打开的窗口。")
        return
    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    except OSError as exc:
        if running_instance(args.port):
            if not args.no_browser:
                if args.browser or not focus_existing_window():
                    open_browser(url)
            return
        show_message(
            f"无法启动 NetScope。\n\n端口 {args.port} 可能已被占用，或没有权限。\n{exc}",
            error=True,
        )
        return
    SERVER = server
    mode = "server" if args.no_browser else ("browser" if args.browser else "desktop")
    if mode == "desktop" and webview is None:
        show_message("未找到桌面窗口组件，已改用浏览器打开。", error=True)
        mode = "browser"
    UI_MODE = "browser" if mode in {"browser", "server"} else "desktop"
    print(f"NetScope 已启动：{url}")
    print("仅监听本机地址。")
    if mode == "server":
        run_server(server)
    elif mode == "browser":
        run_browser(server, url)
    else:
        run_desktop(server, url)


if __name__ == "__main__":
    main()
