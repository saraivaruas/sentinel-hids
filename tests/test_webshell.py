import base64
import unittest
import zlib

from helpers import core  # noqa: F401
from sentinel import webshell


def hit(code: str) -> list[str]:
    return webshell.analyze(code.encode())


class WebshellTests(unittest.TestCase):
    def test_firmas_directas_siguen_funcionando(self):
        self.assertTrue(hit("<?php eval(base64_decode($_POST['x']));"))
        self.assertTrue(hit("<?php system($_GET['c']);"))

    def test_texto_partido_en_pedazos(self):
        self.assertTrue(hit("<?php $f='ev'.'al'; $f($_POST['x']);"))                      # función elegida por una variable
        r = hit("<?php ('ev'.'al')($_POST['q']);")
        self.assertTrue(any("tras desofuscar" in x for x in r), r)
        r = hit("<?php ev/**/al($_POST['z']);")                                            # comentario dentro de la palabra
        self.assertTrue(any("tras desofuscar" in x for x in r), r)

    def test_chr_y_hex(self):
        self.assertTrue(hit("<?php $a = chr(101).chr(118).chr(97).chr(108); $a($_REQUEST['p']);"))
        self.assertTrue(hit("<?php $x = \"\\x73\\x79\\x73\\x74\\x65\\x6d\"; $x($_GET['c']);"))

    def test_funcion_elegida_por_la_peticion(self):
        self.assertIn("php: función elegida por la petición", hit("<?php $_GET['f']($_GET['a']);"))
        self.assertTrue(hit("<?php @$_POST['cmd']($_POST['arg']);"))

    def test_base64_y_gzip_anidados(self):
        interno = b"<?php system($_GET['c']); ?>"
        capa = base64.b64encode(zlib.compress(interno, 9)).decode()
        r = hit(f"<?php $d = '{capa}'; // algo\n$x = 1;")
        self.assertTrue(any("oculto en base64/gzip" in x for x in r), r)
        doble = base64.b64encode(base64.b64encode(interno)).decode()
        self.assertTrue(any("oculto en base64/gzip" in x for x in hit(f"<?php $d = '{doble}';")))

    def test_decodificadores_anidados(self):
        self.assertTrue(hit("<?php $z = gzinflate(base64_decode(str_rot13(strrev($d))));"))

    def test_callbacks_y_preg_replace_e(self):
        self.assertTrue(hit("<?php array_map('assert', array($_POST['a']));"))
        self.assertTrue(hit("<?php preg_replace('/.*/e', $_POST['c'], '');"))
        self.assertTrue(hit("<?php include($_GET['page']);"))

    def test_puntaje_de_ofuscacion(self):
        mal = "<?php $O0O0O0 = '" + "A1b2C3d4" * 40 + "'; " + "".join(f"$x{i} = chr({65 + i % 20}); " for i in range(20)) + "eval($O0O0O0);"
        r = hit(mal)
        self.assertTrue(any("ofuscación avanzada" in x for x in r), r)

    def test_codigo_legitimo_no_se_marca(self):
        legit = [
            "<?php\nclass Usuario { public function nombre() { return $this->nombre; } }\n$u = new Usuario(); echo htmlspecialchars($u->nombre());\n",
            "<?php\nforeach ($items as $i) { echo '<li>' . $i['name'] . '</li>'; }\ninclude 'cabecera.php';\nrequire_once __DIR__ . '/vendor/autoload.php';\n",
            "<?php\n$json = json_decode(file_get_contents('php://input'), true);\n$id = (int) $_GET['id'];\necho json_encode(['id' => $id]);\n",
            "<?php\n$img = '" + base64.b64encode(bytes(range(256)) * 4).decode() + "';\necho '<img src=\"data:image/png;base64,' . $img . '\">';\n",       # imagen embebida: mucho base64 pero nada se ejecuta
            "<?php\nfunction t($s) { return str_replace(['a', 'b'], ['1', '2'], $s); }\necho t($_GET['q'] ?? '');\n",
        ]
        for code in legit:
            self.assertEqual(hit(code), [], code[:60])

    def test_normalizar(self):
        self.assertEqual(webshell.normalize(b"'ev'.'al'"), b"'eval'")
        self.assertIn(b"'e'", webshell.normalize(b"chr(101)")); self.assertIn(b"system", webshell.normalize(b'"\\x73ystem"'))


if __name__ == "__main__":
    unittest.main()
