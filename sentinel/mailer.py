"""Correo por SMTP, sin depender del comando «mail».

La contraseña NUNCA va en sentinel.conf (lo puede leer el grupo adm): vive en un archivo aparte, solo de root
(/etc/sentinel/smtp.pass). Se configura con «sudo sentinel smtp configurar» o importándola de un ~/.msmtprc.
"""
from __future__ import annotations

import os
import re
import smtplib
import socket
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from . import core

SECURITY = ("starttls", "ssl", "none")
EMAIL_RE = re.compile(r"[\w.+-]{1,64}@[\w.-]{1,120}\.[A-Za-z]{2,}")
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


def secret_path() -> str:
    return os.environ.get("SENTINEL_SMTP_SECRET") or os.path.join(os.path.dirname(core.conf_path()), "smtp.pass")


def settings(cfg) -> dict:
    """Ajustes de [smtp]. Si «to» está vacío usa general.email_to; «sender» cae al usuario."""
    g = lambda k, d="": cfg.get("smtp", k, fallback=d).strip()
    port = g("port", "587")
    to = core.csv(g("to")) or core.csv(cfg.get("general", "email_to", fallback=""))
    return {"enabled": g("enabled", "no").lower() in ("yes", "si", "sí", "true", "1"), "host": g("host"), "port": int(port) if port.isdigit() else 587,
            "security": g("security", "starttls").lower(), "user": g("user"), "sender": g("sender") or g("user"), "to": [t for t in to if EMAIL_RE.fullmatch(t)]}


def password() -> str:
    try:
        with open(secret_path(), encoding="utf-8") as f:
            return f.read().strip("\r\n")
    except OSError:
        return ""


def set_password(value: str) -> None:
    """Guarda la contraseña con permisos 0600 (solo el dueño); nunca la escribe en sentinel.conf."""
    if not value or "\n" in value or "\r" in value:
        raise ValueError("contraseña vacía o con saltos de línea")
    p = secret_path()
    core.ensure_dir(os.path.dirname(p), 0o755)
    tmp = p + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(value + "\n")
    os.replace(tmp, p)
    os.chmod(p, 0o600)


def clear_password() -> None:
    try:
        os.remove(secret_path())
    except OSError:
        pass


def password_present() -> bool:
    """¿Hay una contraseña guardada? (sin ser root no se puede leer, pero sí ver que el archivo existe)"""
    try:
        return os.path.getsize(secret_path()) > 1
    except OSError:
        return False


def configured(cfg) -> bool:
    s = settings(cfg)
    return bool(s["enabled"] and s["host"] and s["to"] and s["sender"] and s["security"] in SECURITY and (not s["user"] or password_present()))


def estado(cfg) -> dict:
    s = settings(cfg)
    p = secret_path()
    return {**s, "password": "guardada" if password() else "guardada (solo root puede leerla)" if password_present() else "falta", "secret": p, "ok": configured(cfg)}


def build_message(subject: str, text: str, sender: str, to: list[str], html: str | None = None, attachments=None) -> EmailMessage:
    """attachments: lista de (nombre, bytes, «tipo/subtipo»)."""
    m = EmailMessage()
    m["Subject"], m["From"], m["To"] = re.sub(r"[\r\n]+", " ", subject)[:200], sender, ", ".join(to)
    m["Date"], m["Message-ID"] = formatdate(localtime=True), make_msgid(domain=(sender.split("@")[-1] or "sentinel.local"))
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    for name, data, mime in attachments or []:
        main, _, sub = mime.partition("/")
        m.add_attachment(data, maintype=main or "application", subtype=sub or "octet-stream", filename=name)
    return m


def send(cfg, subject: str, text: str, html: str | None = None, attachments=None, to: list[str] | None = None, timeout: int = 25) -> tuple[bool, str]:
    """Envía un correo. Devuelve (ok, mensaje en español). Nunca lanza excepciones."""
    s = settings(cfg)
    dest = to or s["to"]
    if not s["host"] or not dest or not s["sender"]:
        return False, "SMTP sin configurar: falta servidor, remitente o destinatario (sudo sentinel smtp configurar)."
    if s["security"] not in SECURITY:
        return False, f"Seguridad SMTP no válida: {s['security']!r} (usa starttls, ssl o none)."
    pw = password() if s["user"] else ""
    if s["user"] and not pw:
        if password_present():
            return False, "La contraseña SMTP está guardada pero solo root puede leerla: ejecuta con sudo."
        return False, "Falta la contraseña SMTP (sudo sentinel smtp configurar)."
    if s["user"] and s["security"] == "none" and s["host"] not in LOCAL_HOSTS:
        return False, "Por seguridad no se envía usuario y contraseña sin cifrado a un servidor remoto (usa starttls o ssl)."
    msg = build_message(subject, text, s["sender"], dest, html, attachments)
    try:
        ctx = ssl.create_default_context()
        if s["security"] == "ssl":
            srv = smtplib.SMTP_SSL(s["host"], s["port"], timeout=timeout, context=ctx)
        else:
            srv = smtplib.SMTP(s["host"], s["port"], timeout=timeout)
        with srv:
            srv.ehlo()
            if s["security"] == "starttls":
                srv.starttls(context=ctx)
                srv.ehlo()
            if s["user"]:
                srv.login(s["user"], pw)
            srv.send_message(msg, from_addr=s["sender"], to_addrs=dest)
    except smtplib.SMTPAuthenticationError as e:
        return False, f"El servidor rechazó el usuario o la contraseña ({e.smtp_code}). Con Gmail hace falta una «contraseña de aplicación» de 16 letras, sin espacios."
    except smtplib.SMTPRecipientsRefused:
        return False, "El servidor rechazó al destinatario."
    except smtplib.SMTPException as e:
        return False, f"Error SMTP: {type(e).__name__}: {str(e)[:160]}"
    except ssl.SSLError as e:
        return False, f"Falló el cifrado TLS ({str(e)[:120]}): revisa el puerto y la opción de seguridad (587 starttls, 465 ssl)."
    except (socket.timeout, TimeoutError):
        return False, f"El servidor {s['host']}:{s['port']} no respondió en {timeout} s."
    except OSError as e:
        return False, f"No pude conectar con {s['host']}:{s['port']}: {e.strerror or e}"
    return True, f"Correo enviado a {', '.join(dest)}."


def test(cfg) -> tuple[bool, str]:
    return send(cfg, f"[Sentinel] Prueba de correo desde {socket.gethostname()}", "Si lees esto, el envío de correo de Sentinel por SMTP funciona.\n")


def from_msmtp(path: str) -> dict:
    """Lee host, puerto, usuario, contraseña y remitente de un ~/.msmtprc (para no volver a escribirlos). No escribe nada."""
    vals: dict = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        lineas = fh.read().splitlines()
    for ln in lineas:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        k, _, v = ln.partition(" ")
        k, v = k.strip(), v.strip()
        if k in ("host", "port", "user", "password", "from", "tls_starttls", "tls"):
            vals[k] = v
    port = vals.get("port", "587")
    security = "ssl" if (port == "465" or vals.get("tls_starttls", "").lower() in ("off", "no")) else "starttls" if vals.get("tls", "on").lower() != "off" else "none"
    return {"host": vals.get("host", ""), "port": port, "security": security, "user": vals.get("user", ""), "password": vals.get("password", ""), "sender": vals.get("from", vals.get("user", ""))}
