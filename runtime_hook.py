"""Runtime hook for the portable build.

The desktop shell only ever talks to NetScope over plain HTTP on the
loopback interface, yet the standard library and the packaged dependencies
drag in a few very large optional pieces:

``ssl`` / ``_ssl``
    pull in ``libcrypto-3.dll`` and ``libssl-3.dll`` (about 4.5 MB).  A few
    libraries read ``ssl.SSLWantReadError`` while they are imported
    (``asyncio.sslproto``) or build an HTTPS handler (``urllib.request``),
    so the module has to exist - it just never has to do anything.

``bottle``
    is imported by ``webview.http`` even though NetScope runs its own HTTP
    server and never starts pywebview's WSGI one.

``typing_extensions``
    is only used for names that ``typing`` has shipped since 3.11.

Each stand-in below is installed only when the real module is missing, so
running the sources with a normal interpreter keeps the genuine packages.
"""

from __future__ import annotations

import sys
import types


class _Placeholder(RuntimeError):
    """Stands in for a TLS helper: usable in except clauses, inert elsewhere."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args)

    def __call__(self, *args, **kwargs):
        return _Placeholder()

    def __getattr__(self, name: str):
        return _Placeholder

    def __bool__(self) -> bool:
        return False


def _module_available(name: str) -> bool:
    try:
        __import__(name)
    except ImportError:
        return False
    return True


def _install_tls_stand_in() -> None:
    if _module_available("ssl"):
        return  # the real module is bundled, nothing to do

    module = types.ModuleType("ssl")

    def __getattr__(name: str):
        placeholder = type(name, (_Placeholder,), {"__module__": "ssl"})
        setattr(module, name, placeholder)
        return placeholder

    module.__getattr__ = __getattr__
    module._netscope_stub = True
    sys.modules["ssl"] = module


def _install_bottle_stand_in() -> None:
    """Provide the handful of bottle names ``webview.http`` touches."""
    if _module_available("bottle"):
        return

    module = types.ModuleType("bottle")

    class ServerAdapter:
        """Base class of the pywebview server adapters."""

        def __init__(self, host="127.0.0.1", port=8080, **options):
            self.host = host
            self.port = port
            self.options = options
            self.quiet = options.get("quiet", False)

        def run(self, handler):
            raise RuntimeError("NetScope 使用内置 HTTP 服务，未启用 bottle 服务器")

    class Bottle:
        """Minimal route registry - pywebview only needs the decorator."""

        def __init__(self, *args, **kwargs):
            self.routes = {}

        def _register(self, path, method="GET", **options):
            def decorator(func):
                self.routes[(method, path)] = func
                return func
            return decorator

        def route(self, path, **options):
            return self._register(path, "GET", **options)

        def post(self, path, **options):
            return self._register(path, "POST", **options)

        def get(self, path, **options):
            return self._register(path, "GET", **options)

    class _Exchange:
        """Placeholder for ``bottle.request`` / ``bottle.response``."""

        headers: dict = {}
        body = None

        def read(self, *args, **kwargs):
            return b""

        def set_header(self, *args, **kwargs):
            return None

    module.ServerAdapter = ServerAdapter
    module.Bottle = Bottle
    module.request = _Exchange()
    module.response = _Exchange()
    module.static_file = lambda *args, **kwargs: None
    module.run = lambda *args, **kwargs: None
    module._netscope_stub = True
    sys.modules["bottle"] = module


def _install_typing_extensions_shim() -> None:
    """Re-export the ``typing`` names pywebview asks for."""
    if _module_available("typing_extensions"):
        return

    import typing

    module = types.ModuleType("typing_extensions")

    def __getattr__(name: str):
        try:
            return getattr(typing, name)
        except AttributeError:
            raise AttributeError(f"module 'typing_extensions' has no attribute {name!r}") from None

    module.__getattr__ = __getattr__
    module._netscope_stub = True
    sys.modules["typing_extensions"] = module


def _install_xml_stand_in() -> None:
    """Keep ``clr_loader`` importable when the XML parser is not bundled.

    ``clr_loader.util.coreclr_errors`` only touches the parser inside its
    ``__main__`` block, so the stand-in is never used in practice - it exists
    so that a future import of :mod:`xml.etree` fails with a clear message
    instead of a confusing one halfway through a scan.
    """
    if _module_available("xml.etree.ElementTree"):
        return

    xml_package = types.ModuleType("xml")
    xml_package.__path__ = []  # type: ignore[attr-defined]
    etree_package = types.ModuleType("xml.etree")
    etree_package.__path__ = []  # type: ignore[attr-defined]
    element_tree = types.ModuleType("xml.etree.ElementTree")

    def parse(*args, **kwargs):
        raise RuntimeError("便携版未包含 XML 解析器，无法读取 .NET 错误详情")

    element_tree.parse = parse  # type: ignore[attr-defined]
    etree_package.ElementTree = element_tree  # type: ignore[attr-defined]
    xml_package.etree = etree_package  # type: ignore[attr-defined]
    for stub in (xml_package, etree_package, element_tree):
        stub._netscope_stub = True
    sys.modules["xml"] = xml_package
    sys.modules["xml.etree"] = etree_package
    sys.modules["xml.etree.ElementTree"] = element_tree


_install_tls_stand_in()
_install_bottle_stand_in()
_install_typing_extensions_shim()
_install_xml_stand_in()
