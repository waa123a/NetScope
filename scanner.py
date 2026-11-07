"""Core IPv4 discovery and TCP connect scanning primitives.

A job probes every ``(host, port)`` pair of the current run concurrently with
one non-blocking socket sweep, so a whole /24 finishes inside roughly a single
timeout window instead of spawning one ``ping`` process and one thread pool
per host.  Liveness is confirmed with the operating system neighbour cache
(ARP), which the sweep refreshes while it runs, and with a single ICMP echo
for the routed addresses the cache cannot reach.  Reverse lookups run with a
hard deadline so a slow resolver can never stall a scan.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from oui import vendor_for_mac

MAX_TARGETS = 1024
MAX_PORTS = 1024
MAX_SOCKETS = 2048          # concurrent TCP connects kept open by the sweep
PING_WORKERS = 48           # parallel ICMP echo helpers
DNS_DEADLINE = 3.0          # seconds allowed for the reverse lookup round
LOCAL_STATE_TTL = 30.0      # seconds before the local adapter list is refreshed
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP Alt", 8443: "HTTPS Alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}
PROBE_PORTS = (80, 443, 445, 22, 3389)

# Socket error codes that tell the outcome of a refused or dropped connect.
_ERR_REFUSED = {10061, 111}
_ERR_TIMEOUT = {10060, 110}
_ERR_UNREACHABLE = {10065, 10051, 113, 101}
_ERR_RESET = {10054, 104}

_ARP_ROW = re.compile(r"(?m)^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\b")
_MAC_TEXT = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")


def parse_targets(value: str, limit: int = MAX_TARGETS) -> list[str]:
    """Parse comma/newline separated IPs, CIDRs, and last-octet ranges."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("请输入至少一个 IP 地址或网段")
    targets: list[str] = []
    seen: set[str] = set()
    entries = [item.strip() for item in value.replace(";", ",").replace("\n", ",").split(",") if item.strip()]
    for entry in entries:
        try:
            if "/" in entry:
                addresses: Iterable[ipaddress.IPv4Address] = ipaddress.ip_network(entry, strict=False).hosts()
                network = ipaddress.ip_network(entry, strict=False)
                if not isinstance(network, ipaddress.IPv4Network):
                    raise ValueError("仅支持 IPv4 网段")
                if network.num_addresses <= 2:
                    addresses = list(network)
            elif "-" in entry:
                base, end_text = entry.rsplit("-", 1)
                end = int(end_text)
                start_ip = ipaddress.IPv4Address(base.strip())
                start = int(start_ip) & 0xFF
                if not 0 <= end <= 255 or end < start or str(start_ip).split(".")[-1] != str(start):
                    raise ValueError
                prefix = str(start_ip).rsplit(".", 1)[0]
                addresses = [ipaddress.IPv4Address(f"{prefix}.{part}") for part in range(start, end + 1)]
            else:
                addresses = [ipaddress.IPv4Address(entry)]
            for address in addresses:
                text = str(address)
                if text not in seen:
                    seen.add(text)
                    targets.append(text)
                    if len(targets) > limit:
                        raise ValueError(f"单次最多扫描 {limit} 个地址，请缩小范围")
        except ValueError as exc:
            if str(exc).startswith("单次最多"):
                raise
            raise ValueError(f"无效的目标：{entry}") from exc
    if not targets:
        raise ValueError("目标范围中没有可扫描的地址")
    return targets


def parse_ports(value: str, limit: int = MAX_PORTS) -> list[int]:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("请输入要扫描的端口")
    ports: set[int] = set()
    for entry in [part.strip() for part in value.replace("，", ",").split(",") if part.strip()]:
        try:
            if "-" in entry:
                start_text, end_text = entry.split("-", 1)
                start, end = int(start_text), int(end_text)
                if not 1 <= start <= end <= 65535:
                    raise ValueError
                ports.update(range(start, end + 1))
            else:
                port = int(entry)
                if not 1 <= port <= 65535:
                    raise ValueError
                ports.add(port)
        except ValueError as exc:
            raise ValueError(f"无效的端口：{entry}") from exc
        if len(ports) > limit:
            raise ValueError(f"单次最多扫描 {limit} 个端口")
    if not ports:
        raise ValueError("没有可扫描的端口")
    return sorted(ports)


def tcp_connect(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


def ping(host: str, timeout: float) -> bool:
    """Send one ICMP echo request through the system ping helper."""
    system = platform.system().lower()
    milliseconds = max(100, int(timeout * 1000))
    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(milliseconds), host]
    elif system == "darwin":
        command = ["ping", "-c", "1", "-W", str(milliseconds), host]
    else:
        command = ["ping", "-c", "1", "-W", str(max(1, round(timeout))), host]
    kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
              "timeout": timeout + 0.8, "check": False}
    if system == "windows":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        return subprocess.run(command, **kwargs).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def reverse_dns(host: str) -> str:
    try:
        name = socket.gethostbyaddr(host)[0]
        return "" if name == host else name
    except (OSError, socket.herror):
        return ""


# --------------------------------------------------------------------------- #
# Local adapters, neighbour cache and interface discovery
# --------------------------------------------------------------------------- #


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _decode(data: bytes) -> str:
    if not data:
        return ""
    encoding = "mbcs" if _is_windows() else "utf-8"
    try:
        return data.decode(encoding, errors="ignore")
    except LookupError:
        return data.decode("utf-8", errors="ignore")


def _run_command(command: list[str], timeout: float = 3.0) -> bytes:
    """Run a helper command without flashing a console window."""
    kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.DEVNULL,
              "timeout": timeout, "check": False}
    if _is_windows():
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        return subprocess.run(command, **kwargs).stdout or b""
    except (OSError, subprocess.TimeoutExpired):
        return b""


def _normalise_mac(text: str) -> str:
    return text.upper().replace("-", ":")


def _is_unicast_mac(mac: str) -> bool:
    """True for a real hardware address; broadcast and multicast are dropped."""
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first) and not first & 1


def _is_netmask(text: str) -> bool:
    try:
        value = int(ipaddress.IPv4Address(text))
    except ValueError:
        return False
    inverted = (~value) & 0xFFFFFFFF
    return inverted & (inverted + 1) == 0


def _network_for(address: str, mask: str) -> ipaddress.IPv4Network | None:
    if not mask:
        return None
    try:
        return ipaddress.ip_network(f"{address}/{mask}", strict=False)
    except ValueError:
        return None


def parse_windows_adapter_mac(text: str, host: str) -> str:
    """Match the IPv4 address to its own ipconfig adapter section."""
    headers = list(re.finditer(r"(?m)^(\S[^\r\n]*):\s*$", text))
    for index, header in enumerate(headers):
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        block = text[header.start():end]
        if not re.search(rf"(?<![\d.]){re.escape(host)}(?![\d.])", block):
            continue
        match = re.search(r"(?i)\b(?:[0-9a-f]{2}-){5}[0-9a-f]{2}\b", block)
        if match:
            return _normalise_mac(match.group(0))
    return ""


def _parse_windows_adapters(text: str) -> list[dict]:
    """Read the IPv4 address, subnet mask and MAC of every ipconfig adapter."""
    adapters: list[dict] = []
    for block in re.split(r"\r?\n\s*\r?\n", text):
        if "IPv4" not in block:
            continue
        address_match = re.search(r"IPv4[^\d]*(\d{1,3}(?:\.\d{1,3}){3})", block)
        if not address_match:
            continue
        address = address_match.group(1)
        mac_match = _MAC_TEXT.search(block)
        mask = ""
        for candidate in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", block[address_match.end():]):
            if _is_netmask(candidate):
                mask = candidate
                break
        adapters.append({"ip": address, "mac": _normalise_mac(mac_match.group(0)) if mac_match else "",
                         "mask": mask})
    return adapters


def _parse_posix_adapters(text: str) -> list[dict]:
    """Read the IPv4 address, subnet mask and MAC of every ifconfig interface."""
    adapters: list[dict] = []
    for block in re.split(r"\n(?=\S)", text):
        address_match = re.search(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3})", block)
        if not address_match:
            continue
        address = address_match.group(1)
        mac_match = _MAC_TEXT.search(block)
        mask_match = re.search(r"netmask\s+(\d{1,3}(?:\.\d{1,3}){3})", block)
        adapters.append({"ip": address, "mac": _normalise_mac(mac_match.group(0)) if mac_match else "",
                         "mask": mask_match.group(1) if mask_match else ""})
    return adapters


def primary_local_ip() -> str:
    """Address of the interface that carries the default route."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"


class _LocalState:
    """Cached view of the local adapters and the subnets they reach directly."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.addresses: set[str] = set()
        self.macs: dict[str, str] = {}
        self.zones: list[ipaddress.IPv4Network] = []
        self.loaded_at: float = 0.0

    def refresh(self) -> None:
        adapters: list[dict] = []
        if _is_windows():
            adapters = _parse_windows_adapters(_decode(_run_command(["ipconfig", "/all"])))
        else:
            adapters = _parse_posix_adapters(_decode(_run_command(["ifconfig"])))
        addresses = {"127.0.0.1"}
        macs: dict[str, str] = {}
        zones: list[ipaddress.IPv4Network] = []
        for adapter in adapters:
            address = adapter.get("ip", "")
            if not address:
                continue
            addresses.add(address)
            if adapter.get("mac"):
                macs[address] = adapter["mac"]
            network = _network_for(address, adapter.get("mask", ""))
            if network is not None and network not in zones:
                zones.append(network)
        primary = primary_local_ip()
        if primary:
            addresses.add(primary)
            if not zones:
                fallback = _network_for(primary, "255.255.255.0")
                if fallback is not None:
                    zones.append(fallback)
        with self.lock:
            self.addresses = addresses
            self.macs = macs
            self.zones = zones
            self.loaded_at = time.monotonic()

    def snapshot(self) -> tuple[set[str], dict[str, str], list[ipaddress.IPv4Network]]:
        with self.lock:
            stale = (time.monotonic() - self.loaded_at) > LOCAL_STATE_TTL
        if stale:
            self.refresh()
        with self.lock:
            return set(self.addresses), dict(self.macs), list(self.zones)


_LOCAL_STATE = _LocalState()


def _local_state() -> tuple[set[str], dict[str, str], list[ipaddress.IPv4Network]]:
    return _LOCAL_STATE.snapshot()


def is_local_host(host: str) -> bool:
    """True when the address belongs to this computer."""
    try:
        if ipaddress.IPv4Address(host).is_loopback:
            return True
    except ValueError:
        return False
    addresses, _, _ = _local_state()
    return host in addresses


def local_mac_address(host: str) -> str:
    """MAC of the local adapter that owns the given address."""
    try:
        loopback = ipaddress.IPv4Address(host).is_loopback
    except ValueError:
        loopback = False
    target = primary_local_ip() if loopback else host
    _, macs, _ = _local_state()
    return macs.get(target, "")


def arp_entries() -> dict[str, str]:
    """Map every IPv4 address in the neighbour cache to its MAC address."""
    command = ["arp", "-a"] if _is_windows() else ["arp", "-n"]
    text = _decode(_run_command(command, timeout=2.0))
    table: dict[str, str] = {}
    for address, mac in _ARP_ROW.findall(text):
        table[address] = _normalise_mac(mac)
    return table


def mac_address(host: str) -> str:
    """Read the active adapter or ARP cache; empty means unavailable."""
    if is_local_host(host):
        return local_mac_address(host)
    mac = arp_entries().get(host, "")
    if mac:
        return mac
    system = platform.system().lower()
    command = ["arp", "-a", host] if system == "windows" else ["arp", "-n", host]
    text = _decode(_run_command(command, timeout=2.0))
    match = _MAC_TEXT.search(text)
    return _normalise_mac(match.group(0)) if match else ""


# --------------------------------------------------------------------------- #
# Device type inference
# --------------------------------------------------------------------------- #

VENDOR_INFO = {
    # vendor key: (brand, fallback label, category)
    "apple": ("Apple", "Apple 设备", "apple"),
    "samsung": ("Samsung", "Samsung 设备", "generic"),
    "xiaomi": ("小米", "小米设备", "generic"),
    "huawei": ("华为", "华为设备", "generic"),
    "honor": ("荣耀", "荣耀设备", "generic"),
    "oppo": ("OPPO", "OPPO 手机", "phone"),
    "vivo": ("vivo", "vivo 手机", "phone"),
    "oneplus": ("OnePlus", "OnePlus 手机", "phone"),
    "motorola": ("Motorola", "Motorola 手机", "phone"),
    "tplink": ("TP-Link", "TP-Link 路由器", "network"),
    "tenda": ("Tenda", "Tenda 路由器", "network"),
    "mercury": ("水星", "水星路由器", "network"),
    "h3c": ("H3C", "H3C 网络设备", "network"),
    "ruijie": ("锐捷", "锐捷网络设备", "network"),
    "fiberhome": ("烽火", "烽火网络设备", "network"),
    "zte": ("ZTE", "ZTE 设备", "generic"),
    "netgear": ("Netgear", "Netgear 路由器", "network"),
    "asus": ("ASUS", "ASUS 设备", "generic"),
    "dlink": ("D-Link", "D-Link 路由器", "network"),
    "ubiquiti": ("Ubiquiti", "Ubiquiti 网络设备", "network"),
    "cisco": ("Cisco", "Cisco 网络设备", "network"),
    "synology": ("Synology", "Synology NAS", "nas"),
    "qnap": ("QNAP", "QNAP NAS", "nas"),
    "mikrotik": ("MikroTik", "MikroTik 路由器", "network"),
    "raspberry": ("树莓派", "树莓派", "computer"),
    "espressif": ("ESP", "ESP 智能设备", "iot"),
    "tuya": ("涂鸦", "涂鸦智能设备", "iot"),
    "sonos": ("Sonos", "Sonos 音箱", "iot"),
    "roku": ("Roku", "Roku 电视盒", "tv"),
    "google": ("Google", "Google 设备", "generic"),
    "amazon": ("Amazon", "Amazon 智能设备", "iot"),
    "lg": ("LG", "LG 设备", "generic"),
    "sony": ("Sony", "Sony 设备", "generic"),
    "playstation": ("PlayStation", "PlayStation 游戏主机", "console"),
    "nintendo": ("Nintendo", "Nintendo 游戏主机", "console"),
    "microsoft": ("Microsoft", "Microsoft 设备", "generic"),
    "intel": ("", "电脑", "chip"),
    "dell": ("Dell", "Dell 电脑", "computer"),
    "hp": ("HP", "HP 设备", "generic"),
    "lenovo": ("Lenovo", "Lenovo 电脑", "computer"),
    "hikvision": ("海康威视", "海康威视摄像头", "camera"),
    "dahua": ("大华", "大华摄像头", "camera"),
    "philips": ("飞利浦", "飞利浦智能设备", "iot"),
    "brother": ("Brother", "Brother 打印机", "printer"),
    "canon": ("Canon", "Canon 打印机", "printer"),
    "epson": ("Epson", "Epson 打印机", "printer"),
    "tcl": ("TCL", "TCL 电视", "tv"),
    "hisense": ("海信", "海信电视", "tv"),
    "skyworth": ("创维", "创维电视", "tv"),
    "sharp": ("夏普", "夏普电视", "tv"),
    "panasonic": ("松下", "松下设备", "generic"),
    "toshiba": ("东芝", "东芝设备", "generic"),
    "haier": ("海尔", "海尔智能设备", "iot"),
    "midea": ("美的", "美的智能设备", "iot"),
    "gree": ("格力", "格力智能设备", "iot"),
    "changhong": ("长虹", "长虹电视", "tv"),
    "vmware": ("VMware", "VMware 虚拟机", "vm"),
    "parallels": ("Parallels", "Parallels 虚拟机", "vm"),
    "virtualbox": ("VirtualBox", "VirtualBox 虚拟机", "vm"),
    "qemu": ("QEMU", "QEMU 虚拟机", "vm"),
    "hyperv": ("Hyper-V", "Hyper-V 虚拟机", "vm"),
    "realtek": ("", "电脑", "chip"),
}

HOSTNAME_HINTS = (
    ("平板", ("ipad", "tablet", "galaxy-tab", "matepad")),
    ("电视", ("androidtv", "android-tv", "bravia", "webos", "chromecast", "firetv",
              "fire-tv", "appletv", "apple-tv", "smarttv", "smart-tv", "roku", "tvbox", "tv-box")),
    ("摄像头", ("camera", "ipcam", "ip-cam", "nvr", "dvr", "hikvision", "dahua",
                "reolink", "tapo", "wyze")),
    ("打印机", ("printer", "print-", "epson", "canon", "brother", "xerox", "ricoh")),
    ("NAS", ("synology", "qnap", "readynas", "terramaster", "truenas", "freenas")),
    ("手机", ("iphone", "android", "pixel", "galaxy", "redmi", "oneplus", "phone",
              "smartphone")),
    ("游戏主机", ("xbox", "playstation", "nintendo", "ps4", "ps5")),
    ("路由器", ("router", "gateway", "openwrt", "mikrotik", "fritz", "unifi", "edgerouter",
                "deco", "orbi", "archer", "amplifi", "eero", "velop", "airport")),
    ("智能设备", ("esphome", "tasmota", "shelly", "tuya", "sonoff", "homeassistant",
                  "home-assistant", "smart-home", "smarthome", "nest", "echo", "alexa")),
    ("Mac 电脑", ("macbook", "imac", "mac-mini", "macmini", "mac-pro")),
    ("树莓派", ("raspberrypi", "raspberry-pi", "raspberry")),
    ("服务器", ("server",)),
    ("电脑", ("desktop", "laptop", "notebook", "workstation")),
)


def _branded(brand: str, kind: str) -> str:
    """Prefix a generic kind with a vendor brand, respecting CJK spacing."""
    if not brand:
        return kind
    separator = "" if ord(brand[-1]) > 127 else " "
    return f"{brand}{separator}{kind}"


def _hostname_kind(hostname: str) -> str:
    name = (hostname or "").lower()
    if not name:
        return ""
    if re.search(r"(^|[-_.])(nas|diskstation)([-_.]|$)", name):
        return "NAS"
    if re.search(r"(^|[-_.])tv([-_.]|$)", name):
        return "电视"
    if re.search(r"(^|[-_.])pc([-_.]|$)", name):
        return "电脑"
    for kind, hints in HOSTNAME_HINTS:
        if any(hint in name for hint in hints):
            return kind
    return ""


def infer_device_type(host: str, ports: Iterable[int], hostname: str = "", mac: str = "") -> str:
    """Conservative type hints from vendor prefix, hostname, and open ports."""
    numbers = set(ports)
    name = (hostname or "").lower()
    if is_local_host(host):
        return "本机"

    vendor_key = vendor_for_mac(mac) if mac else ""
    brand, vendor_label, category = VENDOR_INFO.get(vendor_key, ("", "", ""))

    if "xbox" in name:
        return "Xbox 游戏主机"
    if any(hint in name for hint in ("playstation", "ps4", "ps5")):
        return "PlayStation 游戏主机"
    if "nintendo" in name:
        return "Nintendo 游戏主机"

    kind = _hostname_kind(name)
    if kind == "Mac 电脑":
        return "Apple 电脑" if category == "apple" else "Mac 电脑"
    if kind == "树莓派":
        return "树莓派"
    if kind:
        return _branded(brand, kind)

    if 62078 in numbers:  # Apple lockdown service (iPhone / iPad)
        return "Apple 手机/平板" if category == "apple" else "手机 / 平板"
    if numbers.intersection({515, 631, 9100}):
        return _branded(brand, "打印机")
    if numbers.intersection({554, 8554, 37777}):
        return _branded(brand, "摄像头")
    if 32400 in numbers:  # Plex Media Server
        return "媒体服务器"
    if 5555 in numbers:  # Android ADB
        return _branded(brand, "手机")
    if category == "apple":
        if numbers.intersection({22, 445, 548, 3389}):
            return "Apple 电脑"
        return "Apple 设备"

    if category in {"network", "nas", "camera", "printer", "console", "tv", "phone", "iot", "computer", "vm"}:
        return vendor_label

    if category == "generic":
        if brand == "Samsung" and numbers.intersection({8001, 8002, 9197}):
            return "Samsung 电视"
        if brand == "LG" and numbers.intersection({3000, 3001, 9999}):
            return "LG 电视"
        if brand == "Google" and numbers.intersection({8008, 8009}):
            return "Chromecast"
        if brand == "Microsoft" and 3074 in numbers:
            return "Xbox 游戏主机"

    if numbers.intersection({135, 139, 445, 3389}):
        if category in {"generic", "chip"} and brand:
            return _branded(brand, "电脑")
        return "Windows 主机"
    if 22 in numbers:
        if category in {"generic", "chip"} and brand:
            return _branded(brand, "电脑")
        return "Linux / SSH 主机"
    if numbers.intersection({1883, 8883}):  # MQTT
        return _branded(brand, "智能设备")
    if 5900 in numbers:
        return "远程终端"
    if category in {"generic", "chip"}:
        return vendor_label
    if numbers.intersection({80, 443, 8080, 8443}):
        return "Web / 应用服务"
    return "未知设备"


# --------------------------------------------------------------------------- #
# Concurrent TCP sweep
# --------------------------------------------------------------------------- #


def _classify_socket_error(exc: OSError) -> str:
    code = getattr(exc, "winerror", None) or exc.errno or 0
    if code in _ERR_REFUSED:
        return "refused"
    if code in _ERR_RESET:
        return "reset"
    if code in _ERR_UNREACHABLE:
        return "unreachable"
    if code in _ERR_TIMEOUT:
        return "timeout"
    return "error"


async def _probe_tcp(host: str, port: int, timeout: float) -> str:
    """Open one non-blocking connection and report how it ended."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setblocking(False)
        await asyncio.wait_for(loop.sock_connect(sock, (host, port)), timeout)
        return "open"
    except asyncio.TimeoutError:
        return "timeout"
    except ConnectionRefusedError:
        return "refused"
    except ConnectionResetError:
        return "reset"
    except OSError as exc:
        return _classify_socket_error(exc)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _interleave(hosts: list[str], ports: list[int]) -> Iterator[tuple[str, int]]:
    """Yield the probe pairs round robin so every host finishes together."""
    for port in ports:
        for host in hosts:
            yield host, port


class _Sweeper:
    """Runs every probe of a job concurrently and collects the outcomes."""

    def __init__(self, timeout: float, cancel: threading.Event,
                 on_host_done=None) -> None:
        self.timeout = timeout
        self.cancel = cancel
        self.on_host_done = on_host_done
        self.open_ports: dict[str, list[int]] = {}
        self.responding: set[str] = set()
        self.latency: dict[str, int] = {}
        self._pending: dict[str, int] = {}
        self._started = 0.0

    async def run(self, hosts: list[str], ports: list[int], workers: int) -> None:
        self._pending = {host: len(ports) for host in hosts}
        self._started = time.perf_counter()
        queue = iter(_interleave(hosts, ports))
        workers = max(1, min(workers, max(1, len(hosts) * len(ports))))

        async def worker() -> None:
            while not self.cancel.is_set():
                try:
                    host, port = next(queue)
                except StopIteration:
                    return
                status = await _probe_tcp(host, port, self.timeout)
                if self.cancel.is_set():
                    return
                self._record(host, port, status)

        await asyncio.gather(*(worker() for _ in range(workers)))

    def _record(self, host: str, port: int, status: str) -> None:
        if status == "open":
            self.open_ports.setdefault(host, []).append(port)
        if status in {"open", "refused", "reset"}:
            if host not in self.responding:
                self.responding.add(host)
                self.latency[host] = round((time.perf_counter() - self._started) * 1000)
        remaining = self._pending.get(host, 0) - 1
        self._pending[host] = remaining
        if remaining <= 0 and self.on_host_done:
            self.on_host_done(host)


def _run_coroutine(coro) -> object:
    """Run an event loop that supports many parallel sockets."""
    try:
        loop = asyncio.ProactorEventLoop()  # Windows: IOCP, thousands of sockets
    except AttributeError:
        loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        asyncio.set_event_loop(None)
        loop.close()


def _resolve_names(hosts: list[str], deadline: float) -> dict[str, str]:
    """Reverse lookup with a hard deadline; slow resolvers are skipped."""
    names: dict[str, str] = {}
    if not hosts:
        return names
    lock = threading.Lock()
    workers = min(4, len(hosts))

    def worker(chunk: list[str]) -> None:
        for host in chunk:
            name = reverse_dns(host)
            with lock:
                names[host] = name

    threads = []
    for index in range(workers):
        chunk = hosts[index::workers]
        thread = threading.Thread(target=worker, args=(chunk,), name=f"dns-{index}", daemon=True)
        thread.start()
        threads.append(thread)
    end = time.monotonic() + deadline
    for thread in threads:
        thread.join(max(0.0, end - time.monotonic()))
    return names


def _ip_sort_key(address: str) -> int:
    try:
        return int(ipaddress.IPv4Address(address))
    except ValueError:
        return 0


# --------------------------------------------------------------------------- #
# Scan job
# --------------------------------------------------------------------------- #


@dataclass
class ScanJob:
    targets: list[str]
    ports: list[int]
    timeout: float = 0.8
    concurrency: int = 64
    resolve_names: bool = False
    scan_ports: bool = True
    target_spec: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    status: str = "running"
    completed: int = 0
    open_port_count: int = 0
    results: list[dict] = field(default_factory=list)
    error: str = ""
    created_at: float = field(default_factory=time.time)
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def stop(self) -> None:
        self._cancel.set()
        with self._lock:
            if self.status == "running":
                self.status = "stopping"

    def snapshot(self) -> dict:
        with self._lock:
            elapsed = (self.finished_at or time.time()) - self.started_at
            return {
                "id": self.id, "status": self.status, "completed": self.completed,
                "total": len(self.targets), "online": len(self.results),
                "openPorts": self.open_port_count, "results": list(self.results),
                "elapsed": round(max(0, elapsed), 1), "error": self.error,
                "targets": ", ".join(self.targets) if len(self.targets) <= 4 else f"{self.targets[0]} 等 {len(self.targets)} 个地址",
                "targetSpec": self.target_spec or ", ".join(self.targets),
                "ports": self.ports,
            }

    def run(self) -> None:
        try:
            self._scan()
            with self._lock:
                if self.status == "stopping" or self._cancel.is_set():
                    self.status = "stopped"
                else:
                    self.status = "completed"
                self.finished_at = time.time()
        except Exception as exc:
            with self._lock:
                self.status = "error"
                self.error = str(exc)
                self.finished_at = time.time()

    # -- internals -------------------------------------------------------- #

    def _publish(self, host: str, ports: list[int], latency: int,
                 hostname: str = "", mac: str = "") -> None:
        result = {
            "ip": host,
            "hostname": hostname,
            "deviceType": infer_device_type(host, ports, hostname, mac),
            "mac": mac,
            "ports": [{"port": port, "service": COMMON_SERVICES.get(port, "TCP")} for port in ports],
            "latency": latency,
            "foundAt": time.time(),
        }
        with self._lock:
            table = {item["ip"]: item for item in self.results}
            previous = table.pop(host, None)
            if previous:
                self.open_port_count -= len(previous.get("ports", []))
            table[host] = result
            self.open_port_count += len(result["ports"])
            self.results = [table[key] for key in sorted(table, key=_ip_sort_key)]

    def _scan(self) -> None:
        hosts = list(self.targets)
        report_ports = list(self.ports) if self.scan_ports else []
        probe_ports = report_ports or list(PROBE_PORTS)
        _, _, zones = _local_state()
        zone_ranges = [(int(net.network_address), int(net.broadcast_address)) for net in zones]

        def on_link(host: str) -> bool:
            try:
                value = int(ipaddress.IPv4Address(host))
            except ValueError:
                return False
            return any(start <= value <= end for start, end in zone_ranges)

        # Directly reachable hosts are proven by the neighbour cache: the sweep
        # refreshes every entry it touches, so an entry that is still mapped
        # afterwards belongs to a device that answered an ARP request.  Routed
        # addresses never reach the cache and need an ICMP echo instead, so the
        # echo helpers only run for them.
        ping_candidates = [host for host in hosts if not on_link(host)]
        ping_timeout = min(max(self.timeout, 0.3), 1.2)

        def on_host_done(host: str) -> None:
            with self._lock:
                self.completed += 1
            if host in sweeper.responding:
                self._publish(host, sweeper.open_ports.get(host, []),
                              sweeper.latency.get(host, 0))

        sweeper = _Sweeper(self.timeout, self._cancel, on_host_done)
        workers = min(MAX_SOCKETS, max(1, self.concurrency) * len(probe_ports))

        ping_results: dict[str, bool] = {}
        if ping_candidates:
            ping_workers = min(PING_WORKERS, len(ping_candidates))
            with concurrent.futures.ThreadPoolExecutor(max_workers=ping_workers,
                                                        thread_name_prefix="icmp") as pool:
                pending = [pool.submit(ping, host, ping_timeout) for host in ping_candidates]
                _run_coroutine(sweeper.run(hosts, probe_ports, workers))
                for host, future in zip(ping_candidates, pending):
                    try:
                        ping_results[host] = bool(future.result())
                    except Exception:
                        ping_results[host] = False
        else:
            _run_coroutine(sweeper.run(hosts, probe_ports, workers))

        neighbours = arp_entries()
        alive = set(sweeper.responding)
        for host in hosts:
            mac = neighbours.get(host, "")
            if mac and _is_unicast_mac(mac):
                alive.add(host)
        for host, ok in ping_results.items():
            if ok:
                alive.add(host)

        online = [host for host in hosts if host in alive]
        names = _resolve_names(online, DNS_DEADLINE) if self.resolve_names else {}

        for host in online:
            mac = neighbours.get(host, "")
            if not mac and is_local_host(host):
                mac = local_mac_address(host)
            ports = sweeper.open_ports.get(host, []) if self.scan_ports else []
            latency = sweeper.latency.get(host, round(self.timeout * 1000))
            self._publish(host, ports, latency, names.get(host, ""), mac)


class ScanManager:
    def __init__(self, on_complete=None) -> None:
        self._lock = threading.Lock()
        self.current: ScanJob | None = None
        self._on_complete = on_complete

    def _run_and_archive(self, job: ScanJob) -> None:
        job.run()
        if self._on_complete:
            try:
                self._on_complete(job)
            except Exception as exc:
                print(f"扫描历史保存失败：{exc}")

    def start(self, config: dict) -> ScanJob:
        targets = parse_targets(str(config.get("targets", "")))
        ports = parse_ports(str(config.get("ports", "22,80,443,445,3389,8080")))
        try:
            timeout = float(config.get("timeout", 0.8))
            concurrency = int(config.get("concurrency", 256))
        except (TypeError, ValueError) as exc:
            raise ValueError("超时和并发数必须是数字") from exc
        if not 0.2 <= timeout <= 5:
            raise ValueError("超时时间应在 0.2 到 5 秒之间")
        if not 1 <= concurrency <= 256:
            raise ValueError("并发数应在 1 到 256 之间")
        with self._lock:
            if self.current and self.current.status in {"running", "stopping"}:
                raise RuntimeError("已有扫描任务正在进行")
            job = ScanJob(targets=targets, ports=ports, timeout=timeout,
                          concurrency=concurrency, resolve_names=bool(config.get("resolveNames")),
                          scan_ports=bool(config.get("scanPorts", True)),
                          target_spec=str(config.get("targets", "")))
            self.current = job
        threading.Thread(target=self._run_and_archive, args=(job,), name=f"scan-{job.id}", daemon=True).start()
        return job

    def stop(self) -> ScanJob | None:
        job = self.current
        if job:
            job.stop()
        return job

    def state(self) -> dict:
        job = self.current
        return job.snapshot() if job else {
            "id": None, "status": "idle", "completed": 0, "total": 0,
            "online": 0, "openPorts": 0, "results": [], "elapsed": 0,
            "error": "", "targets": "", "targetSpec": "", "ports": [],
        }


def local_network() -> dict:
    host = socket.gethostname()
    address = primary_local_ip()
    try:
        network = str(ipaddress.ip_network(f"{address}/24", strict=False))
    except ValueError:
        address, network = "127.0.0.1", "127.0.0.1/32"
    return {"hostname": host, "address": address, "network": network}
