from __future__ import annotations

import hashlib
import os
import tempfile
import unittest

from helpers import core  # noqa: F401
from sentinel import fim, pkgcheck


class PkgcheckTests(unittest.TestCase):
    def armar(self, d, contenido=b"hola"):
        info = os.path.join(d, "info"); os.makedirs(info)
        open(os.path.join(d, "status"), "w").write("x")
        real = os.path.join(d, "usr", "bin"); os.makedirs(real)
        return info, real

    def test_coincide_con_el_paquete(self):
        with tempfile.TemporaryDirectory() as d:
            info, real = self.armar(d)
            # el índice trabaja con rutas absolutas del sistema; se simula con una ruta bajo /usr/ falsa dentro del índice
            ruta = "/usr/bin/herramienta-de-prueba"
            open(os.path.join(info, "paq.md5sums"), "w").write(f"{hashlib.md5(b'oficial').hexdigest()}  usr/bin/herramienta-de-prueba\n")
            pkgcheck._cache.update(idx={}, stamp=None)
            idx = pkgcheck.index(info)
            self.assertEqual(idx[ruta], hashlib.md5(b"oficial").hexdigest())

    def test_is_pristine_distingue_el_original_del_alterado(self):
        with tempfile.TemporaryDirectory() as d:
            info, _ = self.armar(d)
            f = os.path.join(d, "usr", "bin", "x")
            open(f, "wb").write(b"oficial")
            open(os.path.join(info, "p.md5sums"), "w").write(f"{hashlib.md5(b'oficial').hexdigest()}  {f[1:]}\n")
            pkgcheck._cache.update(idx={}, stamp=None)
            orig_roots = pkgcheck.ROOTS; pkgcheck.ROOTS = (d + "/usr/",)
            try:
                self.assertTrue(pkgcheck.is_pristine(f, info))
                open(f, "wb").write(b"troyano"); self.assertFalse(pkgcheck.is_pristine(f, info))            # contenido distinto: sigue avisando
                self.assertFalse(pkgcheck.is_pristine(os.path.join(d, "usr", "bin", "no-esta"), info))        # no pertenece a ningún paquete
                self.assertFalse(pkgcheck.is_pristine("/etc/passwd", info))                                   # fuera de las carpetas del sistema
            finally:
                pkgcheck.ROOTS = orig_roots; pkgcheck._cache.update(idx={}, stamp=None)

    def test_reclassify_baja_solo_si_es_el_original(self):
        r = lambda pristine, sigs=(), kind="modified": fim.reclassify("/usr/bin/x", kind, "high", "x", False, list(sigs), pristine)[0]
        self.assertEqual(r(True), "info"); self.assertEqual(r(False), "high")
        self.assertEqual(r(True, sigs=["php: x"]), "high"); self.assertEqual(r(True, kind="removed"), "high")

    def test_con_el_dpkg_real_del_equipo(self):
        if not os.path.exists("/var/lib/dpkg/info/coreutils.md5sums") or not os.path.exists("/bin/ls") and not os.path.exists("/usr/bin/ls"):
            self.skipTest("no es un sistema Debian")
        pkgcheck._cache.update(idx={}, stamp=None)
        ruta = "/usr/bin/ls" if os.path.exists("/usr/bin/ls") else "/bin/ls"
        self.assertTrue(pkgcheck.is_pristine(ruta))                                                           # el ls real coincide con su paquete (aunque la lista lo llame /bin/ls)
        self.assertIn("/bin/ls", pkgcheck.candidates("/usr/bin/ls")); self.assertIn("/usr/bin/ls", pkgcheck.candidates("/bin/ls"))


if __name__ == "__main__":
    unittest.main()
