"""Latido externo («interruptor de hombre muerto»): cada pocos minutos Sentinel avisa a un servicio de tu elección (por ejemplo healthchecks.io, gratis)
que sigue vivo. Si deja de avisar —porque lo apagaron a la fuerza o el equipo cayó— ese servicio te manda un correo o un mensaje al celular.

Solo se envía una petición GET vacía a tu dirección; no sale ningún dato del equipo."""
from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request

from . import core

URL_OK = re.compile(r"^https://[A-Za-z0-9.-]+(?::\d{2,5})?(?:/[A-Za-z0-9._~%/:?&=+-]*)?$")


def valid(url: str) -> bool:
    return bool(url) and len(url) <= 300 and bool(URL_OK.match(url)) and not urllib.parse.urlparse(url).hostname.replace(".", "").isdigit() and not url.startswith("https://localhost")


def ping(url: str, timeout: float = 8.0) -> bool:
    """Un GET a la dirección del latido. Devuelve True si respondió bien."""
    if not valid(url):
        return False
    try:
        req = urllib.request.Request(url, headers={"User-Agent": f"sentinel/{core.VERSION}"})
        with urllib.request.urlopen(req, timeout=timeout) as r:        # noqa: S310 (solo https, validado arriba)
            return 200 <= r.status < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False
