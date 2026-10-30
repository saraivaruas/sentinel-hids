# Sentinel — host-based intrusion detection for Linux (HIDS)

[![tests](https://github.com/saraivaruas/sentinel-hids/actions/workflows/tests.yml/badge.svg)](https://github.com/saraivaruas/sentinel-hids/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)
![Linux](https://img.shields.io/badge/platform-Linux-lightgrey)
![Zero Python dependencies](https://img.shields.io/badge/python%20dependencies-0-brightgreen)

**Sentinel** is an open-source **host-based intrusion detection system (HIDS)** for Linux. It watches **file integrity**, finds **web shells and reverse shells**, **SSH/sudo brute force**, **port scans** and **suspicious processes**, runs **honeypot** decoy ports, temporarily **blocks attackers**, and warns you with **pop-up alert windows** and a local **graphical dashboard**. Pure Python standard library — no third-party packages. 🇪🇸 [Versión en español](README.md).

![Sentinel dashboard](docs/panel-resumen-oscuro.png)

## What it detects

| Detector | What it does |
|---|---|
| **File integrity (FIM)** | SHA-256 baseline + permissions + owner of `/etc/passwd`, `shadow`, `sudoers`, SSH, PAM, cron, systemd units, `/usr/local/bin`, `authorized_keys`… New/changed/removed files, redirected symlinks, opened permissions and **new SUID/SGID**. Real-time (inotify) watching of whole directories, so it catches the rename-replace used by `useradd`/`vipw`. |
| **Web shells** | New or modified files in web roots (e.g. `/var/www/html`) are scanned for web-shell and reverse-shell signatures (`eval(base64_decode(...))`, `system($_POST…)`, `/dev/tcp/…`, `curl \| sh`). |
| **Live attacks** | Reads the systemd journal: SSH/sudo/su brute force, successful login after failures, remote root and **port scans** (firewall drops). |
| **Honeypots** | Decoy ports (SSH 2222, Telnet 2323, RDP 3390, VNC 5900, 60009) in an unprivileged, sandboxed process. Whoever connects is logged and blocked. |
| **Host** | New listening ports (or ports that become public), processes running from `/tmp`, deleted binaries, crypto-miners, unexpected keyboard readers, USB devices, kernel modules, new/UID 0/passwordless accounts, hidden processes, new SUID files. |
| **Posture audit** | `sentinel audit`: 16 configuration checks with the fix for each (firewall, SSH, web permissions, kernel parameters, updates, exposed credentials…). |

**Response:** attackers are blocked **temporarily** (24 h) with CrowdSec, firewalld, ufw or iptables — never your LAN, loopback or Tailscale. Sentinel **never kills processes or touches your files**.
**Alerts:** private JSONL log, journald, desktop notification, **pop-up window** with an *Open dashboard* button, optional e-mail or phone (ntfy).

## Install (dependencies are installed for you)

```bash
sudo apt install ./sentinel_2.0.0_all.deb     # Debian/Ubuntu: apt pulls every dependency
sudo ./install.sh                             # Ubuntu/Debian, Fedora/RHEL, Arch, openSUSE (add --dry-run to preview)
./install-gui.sh                              # guided installer with windows (asks for admin authorization in a dialog)
```

Then: `sentinel status`, `sentinel test` (an alert window should pop up), `sentinel audit`, `sentinel ui` (dashboard).

Requires Python ≥ 3.8 and systemd. Tested in CI on Ubuntu 22.04 and 24.04.

## Limits

Not an antivirus. An attacker who already has **root** can stop Sentinel (it makes that harder and alerts if it goes silent; use remote alerts for that case). Web-shell signatures cover common patterns, not advanced obfuscation. Install it on a machine you consider clean: the integrity baseline is taken at install time.

## Contributing

MIT-licensed, contributions welcome — **all changes go through a reviewed Pull Request**; nobody pushes to `main`. See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately: [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Jorge Luis Saraiva Ruas.

<sub>Keywords: HIDS, host intrusion detection, file integrity monitoring, FIM, web shell detector, honeypot, SSH brute force detection, port scan detection, Linux security, blue team, CrowdSec, ufw, firewalld, systemd, security dashboard, threat detection, incident response.</sub>
