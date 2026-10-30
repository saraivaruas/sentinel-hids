import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sentinel import core  # noqa: E402


class Env:
    """Entorno aislado: carpetas temporales de estado, registros y configuración; sin notificaciones reales."""

    def __init__(self, fim_paths="", www="", extra=""):
        self.dir = tempfile.mkdtemp(prefix="sentinel_test_")
        self.tree = os.path.join(self.dir, "tree")
        os.makedirs(self.tree)
        conf = os.path.join(self.dir, "sentinel.conf")
        with open(conf, "w", encoding="utf-8") as f:
            f.write(f"[general]\nenable_desktop = no\nenable_journal = no\n[fim]\npaths = {fim_paths or self.tree}\nwww = {www}\nexcludes = */.git/*,*.log\n[hostcheck]\nsuid_scan = no\n[ban]\nbackend = none\n{extra}\n")
        os.environ.update(SENTINEL_CONF=conf, SENTINEL_STATE=os.path.join(self.dir, "state"), SENTINEL_LOG=os.path.join(self.dir, "log"))
        self.cfg = core.load_config()
        self.alerter = core.Alerter(self.cfg, quiet=True)
        self.allow = core.Allow(self.cfg)
        self.banner = core.Banner(self.cfg, self.alerter, self.allow)

    def write(self, rel, text="x", mode=None):
        p = os.path.join(self.tree, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        if mode:
            os.chmod(p, mode)
        return p

    def events(self, min_sev="info"):
        return core.read_events(0, min_sev)

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)
