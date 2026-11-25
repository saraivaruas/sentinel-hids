"""Qué sistema operativo es y qué ofrece, para que cada módulo elija cómo vigilar (Linux o macOS).

Solo la biblioteca estándar. Los módulos no deben mirar `sys.platform` por su cuenta: preguntan aquí.
"""
from __future__ import annotations

import os
import sys

ES_MAC = sys.platform == "darwin"
ES_LINUX = sys.platform.startswith("linux")


def nombre() -> str:
    return "macOS" if ES_MAC else "Linux" if ES_LINUX else sys.platform


def tiene_proc() -> bool:
    """¿Existe /proc (procesos, módulos del kernel)? En Linux sí; en macOS no."""
    return os.path.isdir("/proc/self")
