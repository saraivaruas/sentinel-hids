"""Cortafuegos ufw: lee las reglas numeradas, abre y cierra puertos. Lo usa el módulo firewall; Sentinel (detección) no lo conoce."""
from __future__ import annotations

import re
import shutil

from .. import core

NAME = "ufw"
RULE = re.compile(r"^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)(?: (IN|OUT|FWD))?\s+(.+?)(?:\s+#\s*(.*))?\s*$")


def available() -> bool:
    return bool(shutil.which("ufw"))


def active() -> bool:
    rc, out = core.run(["ufw", "status"])
    return rc == 0 and "active" in out.lower().split("\n")[0] or "activo" in out.lower().split("\n")[0]


def parse_rules(text: str) -> list[dict]:
    """Interpreta «ufw status numbered»."""
    out = []
    for line in text.splitlines():
        m = RULE.match(line.strip())
        if not m:
            continue
        num, to, action, direction, frm, comment = m.groups()
        pm = re.match(r"^(\d+)(?::\d+)?(?:/(tcp|udp))?(?:\s+\(v6\))?$", to.strip())
        out.append({"id": int(num), "num": int(num), "to": to.strip(), "port": int(pm.group(1)) if pm else None, "proto": (pm.group(2) if pm else None) or "", "action": action,
                    "dir": direction or "IN", "from": frm.strip(), "comment": comment or "", "v6": "(v6)" in to or "(v6)" in frm,
                    "iface": (re.search(r"on (\S+)", to) or re.search(r"on (\S+)", frm) or [None, None])[1], "label": f"[{num}] {to.strip()}"})
    return out


def rules() -> tuple[list[dict], str]:
    rc, out = core.run(["ufw", "status", "numbered"])
    return (parse_rules(out) if rc == 0 else []), ("" if rc == 0 else out.strip())


def outgoing_allowed() -> bool:
    rc, out = core.run(["ufw", "status", "verbose"])
    return "allow (outgoing)" in out.lower() or "allow (salientes)" in out.lower()


def files() -> list[str]:
    return ["/etc/ufw/user.rules", "/etc/ufw/user6.rules"]


def allow(port: int, proto: str = "tcp") -> tuple[int, str]:
    return core.run(["ufw", "allow", f"{port}/{proto}"])


def delete_all(rs: list[dict]) -> list[tuple[dict, int, str]]:
    """Borra de mayor a menor número (así los números restantes no cambian mientras se borra)."""
    out = []
    for r in sorted(rs, key=lambda r: -r["id"]):
        rc, o = core.run(["ufw", "--force", "delete", str(r["id"])]); out.append((r, rc, o))
    return out


def harden() -> list[str]:
    rc, o = core.run(["ufw", "default", "deny", "incoming"]); return ["ufw: entrantes denegados por defecto" if rc == 0 else o.strip()]


def save() -> str:
    return ""
