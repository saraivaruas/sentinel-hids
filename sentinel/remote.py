"""Varios servidores en un solo panel: para cada servidor que agregues, el panel pregunta por SSH (con TUS llaves, las mismas de tus despliegues) el resumen de su Sentinel.

Es solo lectura: el único comando que se ejecuta en el otro servidor es `sentinel resumen --json`, fijo y sin parámetros. Nada se escribe ni se cambia allá.
Requisitos en el otro servidor: Sentinel instalado y tu usuario con permiso de leer su estado (grupo `adm`). La primera conexión a ese servidor debe haberse hecho antes
desde una terminal (para que su huella esté en known_hosts): el panel nunca acepta huellas desconocidas."""
from __future__ import annotations

import concurrent.futures
import json
import os
import re
import subprocess
import time

from . import core

TARGET = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}@[A-Za-z0-9][A-Za-z0-9.-]{0,120}(?::\d{1,5})?$")
NAME = re.compile(r"^[\w .áéíóúñÁÉÍÓÚÑ-]{1,40}$")
MAX_SERVERS = 12
_cache: dict[str, tuple[float, dict]] = {}


def path() -> str:
    return os.path.join(os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "sentinel", "servers.json")


def load() -> list[dict]:
    try:
        with open(path(), encoding="utf-8") as f:
            return [s for s in json.load(f) if isinstance(s, dict) and TARGET.match(str(s.get("target", ""))) and NAME.match(str(s.get("name", "")))]
    except (OSError, ValueError):
        return []


def save(servers: list[dict]) -> None:
    os.makedirs(os.path.dirname(path()), mode=0o700, exist_ok=True)
    tmp = path() + ".tmp"
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as f:
        json.dump(servers, f, ensure_ascii=False)
    os.replace(tmp, path())


def add(name: str, target: str) -> tuple[bool, str]:
    name, target = name.strip(), target.strip()
    if not NAME.match(name):
        return False, "El nombre debe tener entre 1 y 40 letras, números o espacios."
    if not TARGET.match(target):
        return False, "Escribe el servidor como usuario@servidor o usuario@servidor:puerto (por ejemplo deploy@192.168.1.20)."
    cur = load()
    if len(cur) >= MAX_SERVERS:
        return False, f"Máximo {MAX_SERVERS} servidores."
    if any(s["target"] == target or s["name"].lower() == name.lower() for s in cur):
        return False, "Ese servidor o ese nombre ya está en la lista."
    save(cur + [{"name": name, "target": target}])
    return True, "Servidor agregado."


def remove(target: str) -> bool:
    cur = load()
    new = [s for s in cur if s["target"] != target]
    if len(new) != len(cur):
        save(new)
    _cache.pop(target, None)
    return len(new) != len(cur)


def ssh_command(target: str) -> list[str]:
    user_host, _, port = target.partition(":")
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6", "-o", "StrictHostKeyChecking=yes", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes"]
    if port:
        cmd += ["-p", port]
    return cmd + ["--", user_host, "sentinel", "resumen", "--json"]


def poll(server: dict, ttl: float = 30.0) -> dict:
    """Resumen de un servidor remoto (con caché de unos segundos). Nunca lanza errores: los devuelve como texto."""
    t = server["target"]
    hit = _cache.get(t)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    res = {"name": server["name"], "target": t, "ok": False, "error": "", "data": None, "at": time.time()}
    try:
        r = subprocess.run(ssh_command(t), capture_output=True, text=True, timeout=15, check=False, stdin=subprocess.DEVNULL)
        if r.returncode == 0:
            data = json.loads(r.stdout.strip().splitlines()[-1])
            res.update(ok=True, data={k: data.get(k) for k in ("hostname", "version", "level", "why", "alive", "heartbeat_age", "counts24", "bans", "firewall")})
        else:
            err = (r.stderr or "").strip().splitlines()
            res["error"] = ("No se pudo entrar por SSH: " + err[-1][:160]) if err else f"El comando terminó con código {r.returncode}"
            if "sentinel: command not found" in r.stderr or "no se encontró" in r.stderr:
                res["error"] = "Sentinel no está instalado en ese servidor"
    except subprocess.TimeoutExpired:
        res["error"] = "El servidor no respondió a tiempo"
    except (ValueError, IndexError):
        res["error"] = "El servidor respondió algo que no es un resumen de Sentinel (¿versión muy vieja?)"
    except OSError as e:
        res["error"] = f"No se pudo ejecutar ssh: {e.strerror}"
    _cache[t] = (time.time(), res)
    return res


def poll_all(ttl: float = 30.0) -> list[dict]:
    servers = load()
    if not servers:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(servers))) as ex:
        return list(ex.map(lambda s: poll(s, ttl), servers))
