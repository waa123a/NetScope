import re
import socket
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from oui import OUI_VENDOR, vendor_for_mac
from scanner import ScanJob, infer_device_type, mac_address, parse_ports, parse_targets, parse_windows_adapter_mac, tcp_connect


class TargetParsingTests(unittest.TestCase):
    def test_single_cidr_range_and_deduplication(self):
        self.assertEqual(parse_targets("127.0.0.1"), ["127.0.0.1"])
        self.assertEqual(parse_targets("192.168.1.0/30"), ["192.168.1.1", "192.168.1.2"])
        self.assertEqual(parse_targets("192.168.1.0/31"), ["192.168.1.0", "192.168.1.1"])
        self.assertEqual(parse_targets("10.0.0.1-3,10.0.0.2"), ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        self.assertEqual(parse_targets("10.0.0.1\n10.0.0.2"), ["10.0.0.1", "10.0.0.2"])

    def test_invalid_or_excessive_targets(self):
        for value in ("", "not-an-ip", "10.0.0.9-2", "10.0.0.0/0", "::1", "2001:db8::/120"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_targets(value, limit=1024)

    def test_target_limit(self):
        with self.assertRaisesRegex(ValueError, "单次最多"):
            parse_targets("10.0.0.0/24", limit=10)


class PortParsingTests(unittest.TestCase):
    def test_ports_ranges_and_sorting(self):
        self.assertEqual(parse_ports("443,80,8000-8002,80"), [80, 443, 8000, 8001, 8002])
        self.assertEqual(len(parse_ports("1-1024")), 1024)

    def test_invalid_ports(self):
        for value in ("", "0", "65536", "20-10", "http", "1-2000"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_ports(value)


class DeviceInformationTests(unittest.TestCase):
    @patch("scanner.platform.system", return_value="windows")
    @patch("scanner.subprocess.run")
    def test_windows_arp_mac_is_normalized(self, run, _system):
        run.return_value = SimpleNamespace(stdout="接口: 192.168.1.5\r\n  192.168.1.1          aa-bb-cc-00-11-22     动态\r\n".encode("mbcs"))
        self.assertEqual(mac_address("192.168.1.1"), "AA:BB:CC:00:11:22")

    def test_active_adapter_is_matched_by_ip(self):
        text = (
            "以太网适配器 VMware Network Adapter VMnet8:\r\n"
            "   物理地址. . . . . . . . . . . . : 00-50-56-C0-00-08\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 192.168.80.1(首选)\r\n\r\n"
            "无线局域网适配器 WLAN:\r\n"
            "   物理地址. . . . . . . . . . . . : AA-BB-CC-00-11-22\r\n"
            "   IPv4 地址 . . . . . . . . . . . . : 192.168.6.105(首选)\r\n"
        )
        self.assertEqual(parse_windows_adapter_mac(text, "192.168.6.105"), "AA:BB:CC:00:11:22")
        self.assertEqual(parse_windows_adapter_mac(text, "192.168.6.106"), "")

    def test_device_type_hints(self):
        self.assertEqual(infer_device_type("127.0.0.1", []), "本机")
        self.assertEqual(infer_device_type("192.0.2.2", [135, 445]), "Windows 主机")
        self.assertEqual(infer_device_type("192.0.2.3", [22]), "Linux / SSH 主机")
        self.assertEqual(infer_device_type("192.0.2.4", [9100]), "打印机")
        self.assertEqual(infer_device_type("192.0.2.5", []), "未知设备")

    def test_vendor_and_hostname_hints(self):
        apple = "A4:83:E7:01:02:03"
        samsung = "8C:77:12:01:02:03"
        self.assertEqual(infer_device_type("192.0.2.10", [], "", apple), "Apple 设备")
        self.assertEqual(infer_device_type("192.0.2.11", [62078], "", apple), "Apple 手机/平板")
        self.assertEqual(infer_device_type("192.0.2.12", [], "iPhone-Alex", apple), "Apple 手机")
        self.assertEqual(infer_device_type("192.0.2.13", [], "", samsung), "Samsung 设备")
        self.assertEqual(infer_device_type("192.0.2.14", [8001], "", samsung), "Samsung 电视")
        self.assertEqual(infer_device_type("192.0.2.15", [], "LivingRoom-TV", samsung), "Samsung 电视")
        self.assertEqual(infer_device_type("192.0.2.16", [], "", "50:C7:BF:01:02:03"), "TP-Link 路由器")
        self.assertEqual(infer_device_type("192.0.2.17", [], "", "00:11:32:01:02:03"), "Synology NAS")
        self.assertEqual(infer_device_type("192.0.2.18", [], "", "DC:A6:32:01:02:03"), "树莓派")
        self.assertEqual(infer_device_type("192.0.2.19", [], "", "24:0A:C4:01:02:03"), "ESP 智能设备")
        self.assertEqual(infer_device_type("192.0.2.20", [9100], "", "00:1B:78:01:02:03"), "HP 打印机")
        self.assertEqual(infer_device_type("192.0.2.21", [445], "", "D0:67:E5:01:02:03"), "Dell 电脑")
        self.assertEqual(infer_device_type("192.0.2.22", [], "", "E4:40:97:01:02:03"), "OPPO 手机")
        self.assertEqual(infer_device_type("192.0.2.23", [8009], "", "3C:5A:B4:01:02:03"), "Chromecast")
        self.assertEqual(infer_device_type("192.0.2.24", [], "XBOX-SeriesX", "70:F8:AE:01:02:03"), "Xbox 游戏主机")
        self.assertEqual(infer_device_type("192.0.2.25", [], "", "52:54:00:01:02:03"), "QEMU 虚拟机")
        self.assertEqual(infer_device_type("192.0.2.26", [], "", "02:00:00:00:00:01"), "未知设备")
        self.assertEqual(infer_device_type("192.0.2.27", [], "", "80:8F:1D:01:02:03"), "TP-Link 路由器")
        self.assertEqual(infer_device_type("192.0.2.28", [], "", "BC:5E:91:01:02:03"), "荣耀设备")
        self.assertEqual(infer_device_type("192.0.2.29", [5555], "", "E4:57:68:01:02:03"), "vivo 手机")
        self.assertEqual(infer_device_type("192.0.2.30", [], "", "82:F1:E7:01:02:03"), "未知设备")
        self.assertEqual(infer_device_type("192.0.2.31", [80, 443], "", "08:40:F3:01:02:03"), "Tenda 路由器")
        self.assertEqual(infer_device_type("192.0.2.32", [], "", "00:0F:E2:01:02:03"), "H3C 网络设备")
        self.assertEqual(infer_device_type("192.0.2.33", [], "", "00:11:AD:01:02:03"), "锐捷网络设备")
        self.assertEqual(infer_device_type("192.0.2.34", [], "", "00:4B:F3:01:02:03"), "水星路由器")
        self.assertEqual(infer_device_type("192.0.2.35", [], "", "00:0A:C2:01:02:03"), "烽火网络设备")
        self.assertEqual(infer_device_type("192.0.2.36", [], "", "00:15:EB:01:02:03"), "ZTE 设备")


class OuiTableTests(unittest.TestCase):
    def test_table_integrity_and_known_prefixes(self):
        self.assertGreaterEqual(len(OUI_VENDOR), 11000)
        self.assertTrue(all(re.fullmatch(r"[0-9A-F]{6}", prefix) for prefix in OUI_VENDOR))
        self.assertEqual(vendor_for_mac("08:40:F3:04:FD:30"), "tenda")
        self.assertEqual(vendor_for_mac("50:BD:5F:65:87:7B"), "tplink")
        self.assertEqual(vendor_for_mac("00:0F:E2:01:02:03"), "h3c")
        self.assertEqual(vendor_for_mac("00:11:AD:01:02:03"), "ruijie")
        self.assertEqual(vendor_for_mac("00:4B:F3:01:02:03"), "mercury")
        self.assertEqual(vendor_for_mac("00:0A:C2:01:02:03"), "fiberhome")
        self.assertEqual(vendor_for_mac("00:15:EB:01:02:03"), "zte")
        self.assertEqual(vendor_for_mac("not-a-mac"), "")


class LocalScanTests(unittest.TestCase):
    def setUp(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(5)
        self.port = self.server.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def _accept(self):
        while self.running:
            try:
                connection, _ = self.server.accept()
                connection.close()
            except OSError:
                break

    def tearDown(self):
        self.running = False
        self.server.close()
        self.thread.join(timeout=1)

    def test_tcp_connect_detects_open_port(self):
        self.assertTrue(tcp_connect("127.0.0.1", self.port, 0.3))

    @patch("scanner.ping", return_value=True)
    def test_scan_job_returns_open_ports(self, _ping):
        job = ScanJob(targets=["127.0.0.1"], ports=[self.port], timeout=0.3, concurrency=1)
        job.run()
        state = job.snapshot()
        self.assertEqual(state["status"], "completed")
        self.assertEqual(state["completed"], 1)
        self.assertEqual(state["online"], 1)
        self.assertEqual(state["openPorts"], 1)
        self.assertEqual(state["results"][0]["ports"][0]["port"], self.port)
        self.assertEqual(state["results"][0]["deviceType"], "本机")
        self.assertRegex(state["results"][0]["mac"], r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")

    @patch("scanner.ping", return_value=False)
    @patch("scanner.tcp_connect", return_value=False)
    def test_offline_host_is_not_in_results(self, _connect, _ping):
        job = ScanJob(targets=["192.0.2.1"], ports=[80], timeout=0.2, concurrency=1)
        job.run()
        state = job.snapshot()
        self.assertEqual(state["completed"], 1)
        self.assertEqual(state["online"], 0)
        self.assertEqual(state["results"], [])

    @patch("scanner.ping", side_effect=lambda _host, _timeout: False)
    def test_stop_prevents_queued_work(self, _ping):
        job = ScanJob(targets=["192.0.2.1", "192.0.2.2"], ports=[80], timeout=0.2, concurrency=1)
        job.stop()
        job.run()
        self.assertEqual(job.status, "stopped")


if __name__ == "__main__":
    unittest.main()
