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
