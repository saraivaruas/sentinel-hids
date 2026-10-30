"""Genera datos de demostración (eventos, bloqueos, latido) en una carpeta, para ver el panel con actividad sin instalar nada.
Uso: python3 tools/demo_datos.py /tmp/demo   y luego:  SENTINEL_STATE=/tmp/demo/state SENTINEL_LOG=/tmp/demo/log python3 -m sentinel ui"""
import json
import os
import random
import sys
import time

D = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sentinel_demo"
os.makedirs(f"{D}/state", exist_ok=True); os.makedirs(f"{D}/log", exist_ok=True)
now = time.time(); random.seed(7)
iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(t))
ev = []
def add(ago, sev, src, kind, msg, **data):
    t = now - ago
    ev.append({"sev": sev, "source": src, "kind": kind, "msg": msg, "key": f"{src}:{kind}:{msg}:{int(t)}", "data": data, "ts": iso(t), "epoch": t})
attackers = ["203.0.113.9", "198.51.100.77", "185.220.101.4", "45.155.205.233", "91.240.118.50"]
for h in range(24, 0, -1):
    for _ in range(random.choice([0, 1, 2, 3, 5] if h > 8 else [0, 0, 1, 2])):
        ip = random.choice(attackers)
        add(h * 3600 - random.randint(0, 3500), random.choice(["high", "medium", "medium", "low", "info"]), "auth", "fuerza_bruta", f"{random.randint(5, 40)} intentos fallidos de acceso desde {ip} en 10 min (último usuario probado: {random.choice(['root', 'admin', 'ubuntu', 'oracle'])})", ip=ip)
add(2.4 * 3600, "critical", "fim", "added", "/var/www/html/marketplace/uploads/img.php: posible puerta trasera: php: eval de datos codificados", path="/var/www/html/marketplace/uploads/img.php")
add(2.3 * 3600, "high", "fim", "modified", "/etc/passwd: contenido modificado", path="/etc/passwd")
add(5 * 3600, "high", "decoy", "toque", "203.0.113.9 se conectó al puerto señuelo 2323 (nadie legítimo lo usa); envió: 'root\\r\\n'", ip="203.0.113.9", port=2323)
add(5 * 3600, "high", "ban", "bloqueada", "IP 203.0.113.9 bloqueada por 24 h con crowdsec: tocó el señuelo 2323", ip="203.0.113.9")
add(9 * 3600, "high", "auth", "escaneo_de_puertos", "Escaneo de puertos desde 185.220.101.4: 31 puertos distintos en 60s", ip="185.220.101.4")
add(30 * 60, "medium", "host", "puerto_nuevo", "Nuevo puerto en escucha tcp/8081 (node, solo local)")
add(12 * 60, "medium", "host", "lector_de_teclado", "evtest (PID 4411) lee directamente el teclado/ratón (/dev/input/event3); revisa que sea legítimo")
add(3 * 60, "low", "host", "reinicio_pendiente", "chrome (PID 1022) usa un programa actualizado: conviene reiniciarlo")
add(90, "info", "monitor", "inicio", "Sentinel 2.0.0 iniciado (vigilancia en vivo de archivos: sí)")
for d in range(1, 6):
    add(d * 86400 + 4000, random.choice(["high", "medium"]), "auth", "fuerza_bruta", f"Intentos fallidos desde {random.choice(attackers)}", ip=random.choice(attackers))
ev.sort(key=lambda e: e["epoch"])
with open(f"{D}/log/events.jsonl", "w", encoding="utf-8") as f:
    for e in ev:
        f.write(json.dumps(e, ensure_ascii=False) + "\n")
json.dump({"203.0.113.9": {"until": now + 18 * 3600, "reason": "tocó el señuelo 2323", "backend": "crowdsec", "since": iso(now)}, "185.220.101.4": {"until": now + 7 * 3600, "reason": "escaneo de 31 puertos", "backend": "crowdsec", "since": iso(now)}}, open(f"{D}/state/bans.json", "w"))
json.dump({"epoch": now, "pid": 1234, "version": "2.0.0"}, open(f"{D}/state/heartbeat.json", "w"))
json.dump({"created": iso(now - 3 * 86400), "count": 4821}, open(f"{D}/state/fim_meta.json", "w"))
print(f"{len(ev)} eventos de demostración en {D}")

# ---- expedientes de atacantes (incidents.db)
os.environ["SENTINEL_STATE"] = f"{D}/state"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentinel import incidents  # noqa: E402
st = incidents.Store(f"{D}/state/incidents.db")
def atk(ip, geo, ssh=0, users=("root", "admin"), scan_ports=(), decoy=None, bans=(), pk=(), gap=3000, kind="ssh_clave"):
    t0 = now - gap
    for i in range(ssh):
        st.record_attempt(ip, kind, user=users[i % len(users)], port=22, proto="tcp", detail="Failed password", ts=t0 + i * (gap / max(ssh, 1)) * 0.9)
    for p in scan_ports:
        st.record_attempt(ip, "escaneo_puertos", port=p, proto="tcp", detail="bloqueado por el cortafuegos", ts=now - 700 + p % 50)
    if decoy:
        st.record_attempt(ip, "senuelo", port=decoy, proto="tcp", detail="'root\\r\\n'", ts=now - 400)
    st.set_geo(ip, geo)
    for (until, reason, rel, by, manual) in bans:
        st.ban_started(ip, until, reason, "crowdsec", manual)
        if rel:
            st.ban_released(ip, by, expired=(by == "caducó"))
    if pk:
        st.add_packets({(ip, pr, dp, fl): (now - 600, now - 20, c, c * 60) for (pr, dp, fl, c) in pk},
                       [{"ts": now - 120 + i * 9, "ip": ip, "proto": pr, "sport": 40000 + i, "dport": dp, "flags": fl, "size": 60, "label": "demo"} for i, (pr, dp, fl, c) in enumerate(pk)])
atk("203.0.113.9", {"country": "Rusia", "country_code": "RU", "city": "Moscú", "asn": "AS12389", "org": "Ejemplo Telecom", "rdns": "srv9.ejemplo.ru", "network": "203.0.113.0/24", "geo_source": "demo"},
    ssh=38, decoy=2323, bans=[(now + 18 * 3600, "tocó el señuelo 2323", False, None, False)], pk=[("tcp", 22, "SYN", 41), ("tcp", 2323, "SYN", 3)])
atk("185.220.101.4", {"country": "Alemania", "country_code": "DE", "city": "Fráncfort", "asn": "AS205100", "org": "Hosting Anónimo GmbH", "network": "185.220.101.0/24", "geo_source": "demo"},
    scan_ports=list(range(20, 52)), bans=[(now + 7 * 3600, "escaneo de 32 puertos", False, None, False)], pk=[("tcp", 22, "SYN", 12), ("tcp", 80, "SYN", 12), ("tcp", 443, "SYN", 12), ("tcp", 3306, "SYN", 12), ("tcp", 0, "FIN+PSH+URG", 6)])
atk("45.155.205.233", {"country": "China", "country_code": "CN", "city": "Pekín", "asn": "AS4134", "org": "Chinanet Backbone", "geo_source": "demo"}, ssh=14, users=("ubuntu", "oracle", "test", "git"), kind="ssh_usuario_invalido",
    bans=[(now - 3600, "fuerza bruta", True, "caducó", False)], pk=[("tcp", 22, "SYN", 14)])
atk("198.51.100.77", {"country": "Brasil", "country_code": "BR", "city": "São Paulo", "asn": "AS28573", "org": "Claro S.A.", "geo_source": "demo"}, ssh=6, users=("root",), pk=[("icmp", 0, "ECHO", 4)], gap=1200)
atk("91.240.118.50", {"country": "Chile", "country_code": "CL", "city": "Santiago", "asn": "AS7418", "org": "Telefónica Chile", "geo_source": "demo"}, ssh=9, users=("pi", "admin"),
    bans=[(now - 86000, "fuerza bruta", True, "usuario", False)], gap=6000)
print("expedientes de ejemplo creados")
