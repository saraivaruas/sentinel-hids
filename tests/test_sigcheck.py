from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
import unittest.mock as mock

from helpers import Env, core  # noqa: F401
from sentinel import sigcheck, update

SUMS = b"abc123  sentinel_2.2.0_all.deb\n"


def gpg(home, *a, data=None):
    return subprocess.run(["gpg", "--batch", "--no-tty", "--homedir", home, *a], input=data, capture_output=True, check=True)


def nueva_clave(home, correo):
    os.chmod(home, 0o700)
    gpg(home, "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", f"Prueba <{correo}>", "ed25519", "sign", "1d")
    fpr = [ln.split(":")[9] for ln in gpg(home, "--list-keys", "--with-colons", correo).stdout.decode().splitlines() if ln.startswith("fpr:")][0]
    return fpr, gpg(home, "--armor", "--export", fpr).stdout


def firmar(home, fpr, data):
    return gpg(home, "--pinentry-mode", "loopback", "--passphrase", "", "--armor", "--detach-sign", "--local-user", fpr, data=data).stdout


@unittest.skipUnless(shutil.which("gpg"), "falta gpg")
class FirmaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cls.h1, cls.h2 = os.path.join(cls.d, "a"), os.path.join(cls.d, "b")
        os.makedirs(cls.h1); os.makedirs(cls.h2)
        cls.fpr1, cls.pub1 = nueva_clave(cls.h1, "autor@example.cl")
        cls.fpr2, cls.pub2 = nueva_clave(cls.h2, "intruso@example.cl")
        cls.keyfile = os.path.join(cls.d, "release-key.asc"); open(cls.keyfile, "wb").write(cls.pub1)
        cls.sig_ok, cls.sig_otro = firmar(cls.h1, cls.fpr1, SUMS), firmar(cls.h2, cls.fpr2, SUMS)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_firma_correcta(self):
        self.assertEqual(sigcheck.verify(SUMS, self.sig_ok, self.keyfile), (True, "firma verificada"))
        self.assertIn(self.fpr1, sigcheck.fingerprints(self.keyfile))

    def test_archivo_alterado_se_rechaza(self):
        self.assertFalse(sigcheck.verify(SUMS + b"extra\n", self.sig_ok, self.keyfile)[0])

    def test_firma_de_otra_clave_se_rechaza(self):
        self.assertFalse(sigcheck.verify(SUMS, self.sig_otro, self.keyfile)[0])                 # firmada bien, pero no por el autor
        self.assertFalse(sigcheck.verify(SUMS, b"basura", self.keyfile)[0])

    def test_sin_clave_instalada_no_se_puede_verificar(self):
        ok, why = sigcheck.verify(SUMS, self.sig_ok, os.path.join(self.d, "no-existe.asc"))
        self.assertFalse(ok); self.assertIn("clave pública", why)

    def test_la_clave_instalada_manda_no_la_de_la_descarga(self):
        # un atacante firma con SU clave y publica la suya: como el equipo solo confía en la del paquete instalado, se rechaza
        self.assertFalse(sigcheck.verify(SUMS, self.sig_otro, self.keyfile)[0])


class PoliticaDeFirmaEnLaActualizacionTests(unittest.TestCase):
    def setUp(self):
        self.e = Env()
        self.info = {"current": "2.1.0", "latest": "2.2.0", "available": True, "enabled": True,
                     "asset_urls": {n: f"https://github.com/saraivaruas/sentinel-hids/releases/download/v2.2.0/{n}" for n in ("sentinel_2.2.0_all.deb", "SHA256SUMS", "SHA256SUMS.asc")}}
        self.deb = b"deb-de-prueba"
        import hashlib
        self.sums = f"{hashlib.sha256(self.deb).hexdigest()}  sentinel_2.2.0_all.deb\n".encode()

    def tearDown(self):
        self.e.close()

    def instalar(self, firma_ok=None, con_clave=False, requiere="auto", sin_asc=False):
        if sin_asc:
            self.info["asset_urls"].pop("SHA256SUMS.asc")
        if con_clave:
            open(os.environ["SENTINEL_RELEASE_KEY"], "w").write("clave")
        self.e.cfg.set("update", "require_signature", requiere)
        get = lambda url, t=8, limit=0: self.sums if url.endswith("SHA256SUMS") else b"firma" if url.endswith(".asc") else self.deb
        apt = mock.Mock(return_value=mock.Mock(returncode=0, stdout="", stderr=""))
        with mock.patch.object(core, "is_root", return_value=True), mock.patch.object(update, "check", return_value=self.info), mock.patch.object(update, "_get", side_effect=get), \
             mock.patch.object(update.shutil, "which", side_effect=lambda n: f"/usr/bin/{n}"), mock.patch.object(core, "run", return_value=(0, "Package: sentinel\nVersion: 2.2.0\n")), \
             mock.patch.object(subprocess, "run", apt), mock.patch.object(sigcheck, "verify", return_value=(bool(firma_ok), "x")) as v:
            return update.install(self.e.cfg, log=lambda *a: None), apt, v

    def test_sin_clave_en_el_equipo_basta_la_huella(self):
        (ok, _), apt, v = self.instalar(); self.assertTrue(ok); self.assertFalse(v.called)

    def test_con_clave_en_el_equipo_la_firma_es_obligatoria(self):
        (ok, msg), apt, _ = self.instalar(firma_ok=True, con_clave=True); self.assertTrue(ok, msg)
        (ok, msg), apt, _ = self.instalar(firma_ok=False, con_clave=True); self.assertFalse(ok); self.assertIn("firma", msg.lower()); self.assertFalse(apt.called)
        (ok, msg), apt, _ = self.instalar(firma_ok=True, con_clave=True, sin_asc=True); self.assertFalse(ok); self.assertIn("no trae la firma", msg); self.assertFalse(apt.called)

    def test_exigir_siempre_o_nunca(self):
        (ok, _), apt, _ = self.instalar(firma_ok=False, requiere="yes"); self.assertFalse(ok); self.assertFalse(apt.called)
        (ok, _), apt, _ = self.instalar(firma_ok=False, con_clave=True, requiere="no"); self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
