"""Explicaciones en lenguaje sencillo (como para un niño): qué es un paquete, qué hizo cada atacante, si es peligroso y para qué sirve cada cosa."""
from __future__ import annotations

from . import core, geoip

NIVELES = {"bajo": ("🟢", "Poco peligroso"), "medio": ("🟡", "Para vigilar"), "alto": ("🔴", "Peligroso")}

# ---------- tipos de intento (lo que hace un atacante)
TIPOS = {
    "ssh_clave": {"nombre": "Adivinar contraseñas", "nivel": "alto",
        "nino": "Es como alguien que prueba llaves una y otra vez en la cerradura de tu puerta, esperando que alguna abra. Aquí probó contraseñas para entrar a tu equipo.",
        "sirve": "Para el atacante sirve para colarse. Para ti, el acceso remoto (SSH) sirve para manejar el equipo desde lejos.",
        "peligro": "Peligroso si lo logra: con la contraseña correcta entraría como si fuera tú. Muchos intentos seguidos casi siempre son un robot, no una persona."},
    "ssh_usuario_invalido": {"nombre": "Probar nombres de usuario", "nivel": "medio",
        "nino": "Es como preguntar en la puerta «¿vive aquí Juan? ¿y María? ¿y Pedro?» hasta acertar un nombre real. Todavía no sabe tu contraseña; busca quién vive en la casa.",
        "sirve": "Sirve para armar una lista de usuarios reales y luego atacarlos.",
        "peligro": "Medio: es el paso previo a adivinar contraseñas. No entró, pero está investigando."},
    "ssh_llave": {"nombre": "Probar llaves SSH", "nivel": "alto",
        "nino": "Como alguien que intenta abrir con una llave que encontró en el suelo, a ver si por casualidad es la tuya.",
        "sirve": "Las llaves SSH son una forma muy segura de entrar sin contraseña.",
        "peligro": "Peligroso si alguna llave coincidiera; pero las llaves buenas casi no se adivinan."},
    "escaneo_puertos": {"nombre": "Revisar todas las puertas", "nivel": "medio",
        "nino": "Imagina un edificio con miles de puertas numeradas. Esta persona va tocando una por una para ver cuáles están abiertas. Eso es un «escaneo de puertos»: busca por dónde se puede entrar.",
        "sirve": "Cada servicio de tu equipo (web, correo, SSH…) vive detrás de una puerta con número, llamada «puerto». Escanear sirve para saber qué servicios hay.",
        "peligro": "Medio: no entró, solo miró. Pero casi siempre es el primer paso de un ataque."},
    "escaneo_syn": {"nombre": "Escaneo de puertos (toc-toc rápido)", "nivel": "medio",
        "nino": "Tocó el timbre de muchísimas puertas en pocos segundos y salió corriendo sin esperar que abrieran. Así averigua cuáles puertas existen sin dejar mucho rastro.",
        "sirve": "Es la forma más común y rápida de descubrir qué servicios tiene un equipo.",
        "peligro": "Medio: está buscando una puerta abierta."},
    "escaneo_sigiloso": {"nombre": "Escaneo sigiloso", "nivel": "alto",
        "nino": "Como un ladrón que se acerca en puntillas y prueba las ventanas sin tocar el timbre, para que nadie lo note. Envía paquetes «raros» que ninguna conexión normal enviaría.",
        "sirve": "Sirve para esquivar sistemas de alarma simples.",
        "peligro": "Alto: nadie legítimo envía paquetes así. Es una herramienta de hacking, casi seguro."},
    "escaneo_udp": {"nombre": "Escaneo de puertos UDP", "nivel": "medio",
        "nino": "Como tirar cartas por muchas rendijas para ver cuáles responden. UDP son mensajes sueltos, sin «¿lo recibiste?».",
        "sirve": "UDP lo usan servicios como DNS, música o videollamadas.",
        "peligro": "Medio: busca servicios olvidados o mal protegidos."},
    "inundacion_syn": {"nombre": "Inundación de timbres (SYN flood)", "nivel": "alto",
        "nino": "Como si mil personas tocaran tu timbre al mismo tiempo, tantas veces, que no puedes atender a nadie más. El objetivo es dejar tu servicio sin responder.",
        "sirve": "No sirve para nada bueno: es un ataque para tumbar servicios (denegación de servicio).",
        "peligro": "Alto: puede dejar tu equipo o tu página web sin funcionar."},
    "ping_masivo": {"nombre": "Ping masivo", "nivel": "medio",
        "nino": "Un «ping» es gritar «¿hay alguien?». Esta IP lo gritó cientos de veces seguidas, como un niño golpeando la puerta sin parar.",
        "sirve": "Un ping normal sirve para comprobar que un equipo está encendido y responde.",
        "peligro": "Medio: una sola vez es normal; cientos de veces es molestar o buscar equipos vivos."},
    "senuelo": {"nombre": "Cayó en la trampa (señuelo)", "nivel": "alto",
        "nino": "Pusimos una puerta falsa, como un frasco de miel para osos, que no lleva a ningún lado y que nadie honesto tiene motivo para tocar. Esta IP la tocó: seguro anda buscando por dónde entrar.",
        "sirve": "Los señuelos (honeypots) sirven para descubrir intrusos sin arriesgar nada real.",
        "peligro": "Alto: nadie legítimo toca esa puerta. Quien lo hace anda husmeando."},
}

# ---------- paquetes individuales
PAQUETES = {
    "toc_toc": {"nombre": "Toc-toc (SYN)", "nivel": "bajo", "nino": "El primer «hola» de una conversación en internet: alguien toca el timbre de una puerta (puerto) para preguntar «¿puedo pasar?».",
        "sirve": "Con este paquete empieza cada conexión: abrir una página, entrar por SSH, conectar a la base de datos.", "peligro": "Uno solo es normal. Muchos hacia puertas distintas = alguien explorando."},
    "ping": {"nombre": "Ping (ICMP eco)", "nivel": "bajo", "nino": "Es gritar «¿hay alguien?» y esperar que contesten «¡sí, aquí estoy!».",
        "sirve": "Sirve para saber si un equipo está encendido y cuánto tarda en responder.", "peligro": "Uno es inofensivo. Cientos seguidos son una molestia o una búsqueda de equipos."},
    "udp": {"nombre": "Mensaje suelto (UDP)", "nivel": "bajo", "nino": "Es una carta sin acuse de recibo: se manda y ya, sin preguntar si llegó.",
        "sirve": "Lo usan el DNS (la «guía telefónica» de internet), las videollamadas y los juegos, porque es muy rápido.", "peligro": "Normal si es a puertos conocidos. Sospechoso si va a muchos puertos distintos."},
    "null": {"nombre": "Paquete vacío (NULL)", "nivel": "alto", "nino": "Un sobre sin ninguna marca: no dice ni «hola» ni «adiós». Ninguna conversación normal envía algo así.",
        "sirve": "Solo lo usan herramientas de exploración para ver cómo reacciona tu equipo.", "peligro": "Peligroso: es un truco para espiar sin ser notado."},
    "fin": {"nombre": "Despedida sin saludo (FIN)", "nivel": "alto", "nino": "Es como decir «adiós» sin haber dicho «hola» antes: nadie se despide de una charla que no empezó.",
        "sirve": "Normalmente cierra una conversación ya abierta. Sin conversación previa, es un sondeo.", "peligro": "Peligroso: técnica de escaneo sigiloso."},
    "xmas": {"nombre": "Paquete «árbol de Navidad» (XMAS)", "nivel": "alto", "nino": "Un paquete con todas las banderitas levantadas a la vez, como un árbol de Navidad lleno de luces. Es tan raro que sirve para estudiar cómo reacciona un equipo.",
        "sirve": "Solo lo usan herramientas de exploración como nmap.", "peligro": "Peligroso: no existe en el uso normal de internet."},
    "rst": {"nombre": "Portazo (RST)", "nivel": "bajo", "nino": "Es cerrar la puerta de golpe: «aquí no se habla, vete».",
        "sirve": "Sirve para rechazar una conexión que no se desea o que falló.", "peligro": "Normal en pequeñas cantidades."},
    "otro": {"nombre": "Paquete poco común", "nivel": "medio", "nino": "Un mensaje de internet con un formato inusual.", "sirve": "Depende de quién lo mande.", "peligro": "Para vigilar."},
}

GLOSARIO = [
    ("Paquete", "Internet no manda las cosas enteras: las corta en trocitos, como cartas dentro de sobres. Cada sobre es un «paquete» y lleva escrito quién lo manda, a quién va y a qué puerta."),
    ("Dirección IP", "Es la dirección de la casa de un equipo en internet, como «calle y número». Cada equipo conectado tiene una."),
    ("Puerto", "Tu equipo es como un edificio con 65.535 puertas numeradas. Cada servicio vive detrás de una: la web en la 80 y la 443, el acceso remoto SSH en la 22."),
    ("Escaneo de puertos", "Ir tocando muchas puertas para ver cuáles están abiertas. No es un robo, es mirar por dónde se podría entrar."),
    ("Fuerza bruta", "Probar contraseñas sin parar hasta acertar, como probar todas las llaves de un llavero enorme. Lo hacen robots, miles de veces."),
    ("Cortafuegos (firewall)", "Es el portero del edificio: decide qué paquetes pasan y cuáles se quedan afuera."),
    ("Bloqueo", "Cuando Sentinel bloquea una IP, el portero deja de dejarla pasar durante un tiempo (24 horas). Pasado ese tiempo se levanta solo, por si fue un error."),
    ("Señuelo (honeypot)", "Una puerta falsa que no lleva a nada real. Quien la toca se delata."),
    ("SYN / toc-toc", "El primer paquete de toda conversación: «¿puedo pasar?»."),
    ("ACK", "«Recibido, gracias». Es el acuse de recibo que va confirmando cada trocito."),
    ("RST / portazo", "Cerrar la conexión de golpe."),
    ("ICMP / ping", "Mensajes de servicio entre equipos; el más famoso es el ping: «¿estás ahí?»."),
    ("UDP y TCP", "Dos formas de mandar paquetes. TCP es como un correo certificado (confirma que llegó); UDP es como tirar una carta al buzón sin confirmar."),
]


def nivel_str(n: str) -> str:
    e, t = NIVELES.get(n, NIVELES["medio"])
    return f"{e} {t}"


def clasificar_paquete(proto: str, flags: str | None, dport: int | None = None) -> str:
    """Nombre sencillo de un paquete según su protocolo y banderas."""
    f = set((flags or "").replace("+", " ").split())
    if proto == "icmp":
        return "ping"
    if proto == "udp":
        return "udp"
    if proto != "tcp":
        return "otro"
    if not f or f == {"NULL"}:
        return "null"
    if {"FIN", "PSH", "URG"} <= f:
        return "xmas"
    if f == {"FIN"}:
        return "fin"
    if "SYN" in f and "ACK" not in f:
        return "toc_toc"
    if "RST" in f:
        return "rst"
    return "otro"


def puntaje(by_kind: dict, ports: int = 0, packets: int = 0) -> tuple[int, str]:
    peso = {"ssh_clave": 2.5, "ssh_usuario_invalido": 1.5, "ssh_llave": 2.0, "escaneo_puertos": 18, "escaneo_syn": 22, "escaneo_sigiloso": 40, "escaneo_udp": 16, "inundacion_syn": 55, "ping_masivo": 15, "senuelo": 45}
    tope = {"ssh_clave": 45, "ssh_usuario_invalido": 25, "ssh_llave": 25}
    s = 0.0
    for k, n in by_kind.items():
        s += min(tope.get(k, 60), peso.get(k, 5) * (n if k in tope else min(n, 3)))
    s += min(15, ports / 4)
    s = int(min(100, s))
    return s, ("alto" if s >= 60 else "medio" if s >= 30 else "bajo")


def _n(n: int, uno: str, muchos: str) -> str:
    return f"{n} {uno if n == 1 else muchos}"


def explicar(d: dict) -> dict:
    """Informe completo, en lenguaje de niño, a partir del expediente de una IP (Store.dossier)."""
    ip = d["ip"]["ip"]
    g = d["ip"]
    kinds = d["by_kind"]
    total = sum(kinds.values())
    pts, nivel = puntaje(kinds, len(d["ports"]) + d.get("packet_ports", 0), d.get("packet_total", 0))
    if any(not b["released_at"] and b["until"] > core.now() for b in d["bans"]) and pts < 30:
        pts, nivel = 30, "medio"            # si hubo que bloquearla, nunca es «poco peligrosa»
    donde = geoip.place_text(g)
    bloques = []
    quien = f"Esta dirección ({ip}) viene de {g.get('city') + ', ' if g.get('city') else ''}{g.get('country') or 'un lugar que no pudimos identificar'}"
    if g.get("org"):
        quien += f" y pertenece a «{g['org']}»"
    if g.get("rdns"):
        quien += f" (se presenta como {g['rdns']})"
    quien += ". Es como saber en qué ciudad y de qué empresa es el teléfono desde el que te llaman."
    bloques.append({"titulo": "¿De dónde viene?", "texto": quien})
    cuanto = f"En total hizo {_n(total, 'intento', 'intentos')} " if total else "Todavía no hizo intentos registrados "
    if g.get("first_seen") and g.get("last_seen"):
        mins = max(1, int((g["last_seen"] - g["first_seen"]) / 60))
        cuanto += f"durante {mins} minutos" if mins < 120 else f"durante {mins // 60} horas"
    cuanto += "."
    bloques.append({"titulo": "¿Cuántas veces lo intentó?", "texto": cuanto})
    hechos = []
    for k, n in kinds.items():
        t = TIPOS.get(k)
        if t:
            hechos.append({"tipo": k, "nombre": t["nombre"], "veces": n, "nivel": t["nivel"], "nino": t["nino"], "sirve": t["sirve"], "peligro": t["peligro"]})
    bloques.append({"titulo": "¿Qué intentó hacer?", "items": hechos})
    if d["users"]:
        lista = ", ".join(f"«{u['user']}» ({u['n']})" for u in d["users"][:8])
        bloques.append({"titulo": "¿Qué nombres probó?", "texto": f"Probó {_n(len(d['users']), 'nombre de usuario', 'nombres de usuario')}: {lista}. Los robots suelen probar nombres comunes como «root» o «admin» porque esos existen en casi todos los equipos."})
    if d["ports"]:
        lista = ", ".join(f"{p['port']}/{p['proto'] or 'tcp'}" for p in d["ports"][:12])
        bloques.append({"titulo": "¿A qué puertas tocó?", "texto": f"Tocó las puertas número {lista}. Cada número es un servicio distinto; mientras más puertas distintas, más claro que está explorando."})
    pk = []
    por_clave: dict[str, dict] = {}
    for p in d["packets"]:
        c = clasificar_paquete(p["proto"], p["flags"], p["dport"])
        x = por_clave.setdefault(c, {"clave": c, "veces": 0, "bytes": 0, "puertos": set()})
        x["veces"] += p["count"]; x["bytes"] += p["bytes"] or 0
        if p["dport"]:
            x["puertos"].add(p["dport"])
    for c, x in sorted(por_clave.items(), key=lambda kv: -kv[1]["veces"]):
        t = PAQUETES[c]
        pk.append({"clave": c, "nombre": t["nombre"], "veces": x["veces"], "bytes": x["bytes"], "puertos": sorted(x["puertos"])[:20], "nivel": t["nivel"], "nino": t["nino"], "sirve": t["sirve"], "peligro": t["peligro"]})
    if pk:
        bloques.append({"titulo": "Los paquetes (los sobres) que mandó", "texto": f"Detectamos {d['packet_total']} paquetes de esta dirección, hacia {_n(d['packet_ports'], 'puerta distinta', 'puertas distintas')}. Un paquete es un sobre con un mensaje corto; mira qué clase de sobres eran:", "items": pk})
    ban_activo = next((b for b in d["bans"] if not b["released_at"] and b["until"] > core.now()), None)
    if ban_activo:
        h = max(1, int((ban_activo["until"] - core.now()) / 3600))
        hizo = f"Sentinel la bloqueó: el portero no la deja pasar durante unas {h} horas más (motivo: {ban_activo['reason']}). Después se levanta sola, por si fue un error."
    elif d["bans"] and d["bans"][0]["released_at"]:
        b = d["bans"][0]
        hizo = f"Estuvo bloqueada y fue liberada ({'por ti' if b['released_by'] not in (None, 'caducó') else 'al terminar el tiempo'})."
    else:
        hizo = "Por ahora no está bloqueada: solo la estamos observando."
    bloques.append({"titulo": "¿Qué hizo Sentinel?", "texto": hizo})
    rec = []
    if ban_activo:
        rec.append("Sentinel ya la bloqueó: mientras dure el bloqueo no puede seguir intentando. No tienes que hacer nada urgente.")
    elif nivel == "alto":
        rec.append("Te conviene bloquearla: pulsa «Bloquear 24 horas» en este expediente.")
    if any(k.startswith("ssh_") for k in kinds):
        rec.append("Si usas SSH, activa solo llaves (sin contraseñas): así, adivinar contraseñas no sirve de nada.")
    if any(k.startswith("escaneo") or k in ("senuelo", "ping_masivo") for k in kinds):
        rec.append("Si no usas algún servicio, apágalo: una puerta cerrada no se puede forzar.")
    if nivel == "bajo" and not ban_activo:
        rec.append("No hay nada que hacer. Es ruido normal de internet: miles de robots tocan puertas todo el día.")
    rec.append("Si bloqueamos a alguien que sí conoces (por ejemplo, tú mismo equivocándote de clave), pulsa «Liberar» y agrégala a la lista blanca.")
    return {"ip": ip, "donde": donde, "puntaje": pts, "nivel": nivel, "nivel_texto": nivel_str(nivel),
            "resumen": f"{nivel_str(nivel)} · {total} intentos · {donde}", "bloques": bloques, "recomendaciones": rec}
