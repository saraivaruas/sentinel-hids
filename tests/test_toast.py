import unittest

from helpers import core  # noqa: F401
from sentinel import toast


class ToastTests(unittest.TestCase):
    def test_esquina_inferior_derecha(self):
        self.assertEqual(toast.corner((0, 0, 1920, 1080), (380, 160), 20), (1520, 900))

    def test_con_varios_monitores_usa_solo_el_monitor(self):
        # portátil de 1280x720 en (1920,207) y área útil de toda la pantalla 3200x1053: el aviso debe quedar dentro del portátil
        geo, work = (1920, 207, 1280, 720), (0, 27, 3200, 1053)
        area = toast.usable(geo, work)
        self.assertEqual(area, geo)
        x, y = toast.corner(area, (380, 165))
        self.assertTrue(1920 <= x and x + 380 <= 3200 and 207 <= y and y + 165 <= 927)

    def test_area_util_menor_que_el_monitor(self):
        self.assertEqual(toast.usable((0, 0, 1920, 1080), (70, 27, 1850, 1053)), (70, 27, 1850, 1053))
        self.assertEqual(toast.usable((0, 0, 100, 100), (500, 500, 10, 10)), (0, 0, 100, 100))      # datos incoherentes: se usa el monitor


if __name__ == "__main__":
    unittest.main()
