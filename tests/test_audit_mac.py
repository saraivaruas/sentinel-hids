import unittest
from unittest import mock

from helpers import Env, core
from sentinel import audit, audit_mac, plataforma

BIEN = {"socketfilterfw": "Firewall is enabled. (State = 1)", "csrutil": "System Integrity Protection status: enabled.", "fdesetup": "FileVault is On.",
        "spctl": "assessments enabled", "defaults": "{\n    AutomaticCheckEnabled = 1;\n    CriticalUpdateInstall = 1;\n}", "launchctl": None}
MAL = {"socketfilterfw": "Firewall is disabled. (State = 0)", "csrutil": "System Integrity Protection status: disabled.", "fdesetup": "FileVault is Off.",
       "spctl": "assessments disabled", "defaults": "{\n    CriticalUpdateInstall = 0;\n}", "launchctl": ""}


class AuditoriaMacTests(unittest.TestCase):
    def auditar(self, respuestas):
        e = Env(); self.addCleanup(e.close)

        def run(c, t=20):
            nombre = c[0].rsplit("/", 1)[-1]
            if nombre == "launchctl" and "com.openssh.sshd" in c[-1]:
                return (113, "") if respuestas["launchctl"] is None else (0, "")
            r = respuestas.get(nombre)
            return (0, r) if r is not None else (127, "")
        with mock.patch.object(plataforma, "ES_MAC", True), mock.patch.object(core, "run", side_effect=run), mock.patch.object(audit_mac.audit, "_read", return_value=""), \
             mock.patch.object(audit_mac.servicio, "estado", return_value="active"):
            res = audit.run_audit(e.cfg)
        return {c["id"]: c for c in res["checks"]}

    def test_equipo_bien_protegido(self):
        r = self.auditar(BIEN)
        for cid in ("firewall", "sip", "filevault", "gatekeeper", "autoupdates", "ssh", "sentinel"):
            self.assertEqual(r[cid]["status"], "ok", (cid, r[cid]))
        self.assertFalse({"auditd", "docker", "sysctl", "login_defs"} & set(r))        # nada de revisiones de Linux

    def test_equipo_expuesto(self):
        r = self.auditar(MAL)
        for cid in ("firewall", "sip", "filevault", "gatekeeper"):
            self.assertEqual(r[cid]["status"], "fallo", (cid, r[cid])); self.assertTrue(r[cid]["fix"])
        self.assertEqual(r["autoupdates"]["status"], "aviso"); self.assertEqual(r["ssh"]["status"], "aviso")

    def test_lo_que_no_se_reconoce_no_se_da_por_bueno(self):
        r = self.auditar(dict(BIEN, csrutil="algo inesperado", fdesetup=None))
        self.assertEqual(r["sip"]["status"], "info"); self.assertEqual(r["filevault"]["status"], "info")


if __name__ == "__main__":
    unittest.main()
