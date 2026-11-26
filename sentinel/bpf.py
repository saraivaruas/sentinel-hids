"""Captura de paquetes en macOS con BPF (/dev/bpf*), sin tcpdump ni librerías. Es el equivalente del socket AF_PACKET de Linux.

Las constantes y la cabecera de cada paquete son las de <net/bpf.h> de macOS. Solo lee; no envía nada a la red.
"""
from __future__ import annotations

import errno
import os
import select
import struct

BIOCGBLEN = 0x40044266
BIOCSBLEN = 0xC0044266
BIOCSETIF = 0x8020426C
BIOCIMMEDIATE = 0x80044270
BIOCGDLT = 0x4004426A

DLT_NULL, DLT_EN10MB, DLT_RAW = 0, 1, 12
CABECERA = struct.Struct("=iiIIH")          # segundos, microsegundos, bytes capturados, bytes reales, largo de la cabecera
BUFFER = 1 << 19


def alinear(n: int) -> int:
    return (n + 3) & ~3


def trocear(bloque: bytes):
    """Una lectura de BPF trae varios paquetes seguidos, cada uno con su cabecera: los separa."""
    i = 0
    while i + CABECERA.size <= len(bloque):
        _, _, capturado, _, largo = CABECERA.unpack_from(bloque, i)
        if largo < CABECERA.size or i + largo + capturado > len(bloque):
            return
        yield bloque[i + largo:i + largo + capturado]
        i += alinear(largo + capturado)


def quitar_enlace(paquete: bytes, dlt: int) -> tuple[bytes, int] | None:
    """Devuelve (datos, tipo) como los espera packets.parse_frame: tipo 1 = trae cabecera Ethernet; otro = empieza en IP."""
    if dlt == DLT_EN10MB:
        return paquete, 1
    if dlt == DLT_NULL:                      # lo0 y túneles: 4 bytes con la familia delante
        return paquete[4:], 65534
    if dlt in (DLT_RAW, 101):
        return paquete, 65534
    return None


class Captura:
    def __init__(self, interfaz: str) -> None:
        import fcntl
        self.fd = self._abrir()
        try:
            fcntl.ioctl(self.fd, BIOCSBLEN, struct.pack("=I", BUFFER))
            fcntl.ioctl(self.fd, BIOCSETIF, struct.pack("16s16x", interfaz.encode()))
            fcntl.ioctl(self.fd, BIOCIMMEDIATE, struct.pack("=I", 1))
            self.largo = struct.unpack("=I", fcntl.ioctl(self.fd, BIOCGBLEN, b"\0" * 4))[0]
            self.dlt = struct.unpack("=I", fcntl.ioctl(self.fd, BIOCGDLT, b"\0" * 4))[0]
        except OSError:
            self.cerrar()
            raise

    @staticmethod
    def _abrir() -> int:
        for n in range(256):
            try:
                return os.open(f"/dev/bpf{n}", os.O_RDONLY)
            except OSError as e:
                if e.errno != errno.EBUSY:  # ocupado: se prueba el siguiente
                    raise
        raise OSError(errno.EBUSY, "todos los dispositivos de captura están ocupados")

    def leer(self, espera: float = 1.0) -> list[tuple[bytes, int]]:
        """Paquetes llegados (como mucho `espera` segundos esperando). Lista de (datos, tipo)."""
        if not select.select([self.fd], [], [], espera)[0]:
            return []
        bloque = os.read(self.fd, self.largo)
        return [x for x in (quitar_enlace(p, self.dlt) for p in trocear(bloque)) if x]

    def cerrar(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass
