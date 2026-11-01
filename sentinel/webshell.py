"""Detección de puertas traseras web con desofuscación: además de las firmas directas, reconstruye lo que el atacante escondió
(texto partido en pedazos, chr(), \\x41, comentarios dentro de palabras, base64 y gzip anidados) y puntúa señales de ofuscación.

No pretende ser infalible: un código muy ofuscado y a medida puede escapar. Solo mira texto, nunca ejecuta nada."""
from __future__ import annotations

import base64
import binascii
import math
import re
import zlib

LIT = re.compile(rb"""(['"])((?:[^'"\\\n]|\\.){0,200})\1""")
CONCAT = re.compile(rb"""(['"])((?:[^'"\\\n]|\\.){0,200})\1\s*\.\s*(['"])((?:[^'"\\\n]|\\.){0,200})\3""")
CHR = re.compile(rb"\bchr\s*\(\s*(0x[0-9a-fA-F]+|\d{1,3})\s*\)", re.I)
HEX = re.compile(rb"\\x([0-9a-fA-F]{2})")
OCT = re.compile(rb"\\([0-7]{3})")
BLOCK_COMMENT = re.compile(rb"/\*.*?\*/", re.S)
B64 = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")
SINKS = re.compile(rb"\b(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open|create_function|call_user_func(?:_array)?|array_map|usort|preg_replace|include|require)(?:_once)?\b|\$\w+\s*\(|`", re.I)

# Firmas que se buscan sobre el texto ya reconstruido (la otras, directas, están en fim.SIGNATURES)
DEOB_SIGNATURES = {
    "php: función elegida por la petición": re.compile(rb"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(", re.I),
    "php: función variable con datos de la petición": re.compile(rb"\$\w{1,40}\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b", re.I),
    "php: texto usado como función con datos de la petición": re.compile(rb"['\"][A-Za-z_]{3,20}['\"]\s*\)?\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b"),
    "php: include de la petición": re.compile(rb"\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)", re.I),
    "php: extract de la petición": re.compile(rb"\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", re.I),
    "php: callback con la petición": re.compile(rb"\b(?:call_user_func(?:_array)?|array_map|array_filter|usort|uasort|uksort|register_shutdown_function)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)|['\"](?:assert|system|exec|eval|passthru|shell_exec)['\"])", re.I),
    "php: preg_replace con /e": re.compile(rb"preg_replace\s*\(\s*(['\"])([^\w\s\\])(?:(?!\2).){0,80}\2[imsuxADSUXJ]*e[imsuxADSUXJ]*\1", re.I),
    "php: ejecución con comillas invertidas": re.compile(rb"`[^`\n]{0,80}\$_(?:GET|POST|REQUEST|COOKIE)", re.I),
    "php: ob_start con función peligrosa": re.compile(rb"ob_start\s*\(\s*['\"](?:assert|system|exec|passthru|shell_exec)['\"]", re.I),
    "php: eval de datos de entrada crudos": re.compile(rb"eval\s*\(\s*(?:file_get_contents\s*\(\s*['\"]php://input['\"]|\$\w+\s*\(\s*file_get_contents\s*\(\s*['\"]php://input)", re.I),
    "php: eval de contenido decodificado": re.compile(rb"eval\s*\(\s*(?:\$\w+|\w+\s*\([^;]{0,120}\))\s*\)\s*;?", re.I),
    "php: decodificadores anidados": re.compile(rb"(?:base64_decode|gzinflate|gzuncompress|str_rot13|strrev|convert_uudecode|rawurldecode|hex2bin|pack)\s*\([^;]{0,80}(?:base64_decode|gzinflate|gzuncompress|str_rot13|strrev|convert_uudecode|rawurldecode|hex2bin)\s*\([^;]{0,80}(?:base64_decode|gzinflate|gzuncompress|str_rot13|strrev|convert_uudecode|rawurldecode|hex2bin)", re.I),
}
# «eval de contenido decodificado» solo cuenta si hay un decodificador cerca (evita avisar por eval($x) legítimo en plantillas)
_DECODER_NEAR = re.compile(rb"base64_decode|gzinflate|gzuncompress|str_rot13|strrev|convert_uudecode|hex2bin|rawurldecode|pack\s*\(", re.I)


def _unesc(m: "re.Match[bytes]") -> bytes:
    return bytes([int(m.group(1), 16)])


def normalize(data: bytes) -> bytes:
    """Reconstruye lo que el atacante partió o codificó: ev/**/al, 'ev'.'al', chr(101).chr(118), \\x65\\x76…"""
    d = BLOCK_COMMENT.sub(b"", data)
    d = re.sub(rb"(?m)^\s*(?://|#)[^\n]*$", b"", d)

    def chr_sub(m: "re.Match[bytes]") -> bytes:
        n = int(m.group(1), 16) if m.group(1).lower().startswith(b"0x") else int(m.group(1))
        c = bytes([n]) if 32 <= n < 127 and bytes([n]) not in (b"'", b"\\") else b""
        return b"'" + c + b"'" if c else m.group(0)
    d = CHR.sub(chr_sub, d)
    d = HEX.sub(lambda m: _unesc(m) if 32 <= int(m.group(1), 16) < 127 and _unesc(m) not in (b"'", b'"', b"\\") else m.group(0), d)
    d = OCT.sub(lambda m: bytes([int(m.group(1), 8)]) if 32 <= int(m.group(1), 8) < 127 and bytes([int(m.group(1), 8)]) not in (b"'", b'"', b"\\") else m.group(0), d)
    for _ in range(12):                                     # 'a'.'b'.'c' → 'abc'
        n = CONCAT.sub(lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1), d)
        if n == d:
            break
        d = n
    return d


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    freq = [0] * 256
    for c in b:
        freq[c] += 1
    n = len(b)
    return -sum((f / n) * math.log2(f / n) for f in freq if f)


def _decode_blobs(data: bytes, depth: int, found: list[str], seen: set[bytes]) -> None:
    """Decodifica bloques base64 (y los descomprime) y vuelve a revisar su contenido; hasta 3 niveles."""
    if depth > 3:
        return
    for m in B64.finditer(data):
        blob = m.group(0)
        if blob in seen or len(seen) > 40:
            continue
        seen.add(blob)
        try:
            raw = base64.b64decode(blob + b"=" * (-len(blob) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        for wb in (None, -15, 31, 15):
            try:
                txt = raw if wb is None else zlib.decompress(raw, wb)
            except zlib.error:
                continue
            if len(txt) > 12 and sum(32 <= c < 127 or c in (9, 10, 13) for c in txt[:2000]) / min(len(txt), 2000) > 0.9:
                for name in extended(txt):
                    found.append(f"oculto en base64/gzip: {name}")
                _decode_blobs(txt, depth + 1, found, seen)


def direct(data: bytes) -> list[str]:
    """Firmas directas de fim.SIGNATURES."""
    from .fim import SIGNATURES
    return [n for n, rx in SIGNATURES.items() if rx.search(data)]


def extended(data: bytes) -> list[str]:
    """Firmas directas + las pensadas para código reconstruido u ofuscado."""
    out = direct(data)
    for n, rx in DEOB_SIGNATURES.items():
        if rx.search(data) and not (n == "php: eval de contenido decodificado" and not _DECODER_NEAR.search(data)):
            out.append(n)
    return out


def score(data: bytes) -> tuple[int, list[str]]:
    """Puntúa señales de ofuscación; solo se considera si el archivo además ejecuta algo (eval, system, include, $f()…)."""
    if not SINKS.search(data):
        return 0, []
    pts, why = 0, []
    lits = [m.group(2) for m in LIT.finditer(data) if len(m.group(2)) >= 200]
    if any(entropy(x) > 5.2 for x in lits):
        pts += 2; why.append("bloque de texto codificado largo")
    longest = max((len(l) for l in data.split(b"\n")), default=0)
    if longest > 3000 and data.count(b" ") / max(len(data), 1) < 0.02:
        pts += 2; why.append("línea enorme sin espacios")
    if len(re.findall(rb"(?:\\x[0-9a-fA-F]{2}){8,}", data)) >= 2 or len(re.findall(rb"(?:\\[0-7]{3}){8,}", data)) >= 2:
        pts += 2; why.append("palabras enteras escritas como \\x41")
    if len(CHR.findall(data)) >= 15:
        pts += 2; why.append("texto armado con chr()")
    if re.search(rb"\$(?:[Il1]{6,}|[Oo0]{6,}|_{3,}\w*|[a-z]{1,2}[0-9a-f]{8,})\b", data):
        pts += 2; why.append("nombres de variables sin sentido")
    if re.search(rb"@\s*(?:eval|assert|system|exec|include|require)", data, re.I):
        pts += 1; why.append("errores silenciados con @")
    if len(re.findall(rb"\$\w+\s*\[\s*\d+\s*\]\s*\(", data)) >= 2 or re.search(rb"\$\w+\s*=\s*['\"][a-z_]{3,12}['\"]\s*;[\s\S]{0,200}\$\w+\s*\(", data):
        pts += 1; why.append("funciones elegidas con variables")
    return pts, why


def analyze(data: bytes, threshold: int = 4) -> list[str]:
    """Todos los hallazgos de un archivo: firmas directas, firmas sobre el texto reconstruido, contenido oculto y ofuscación."""
    found = direct(data)
    norm = normalize(data)
    found += [n if norm == data else f"{n} (tras desofuscar)" for n in extended(norm) if n not in found]
    _decode_blobs(norm, 1, found, set())
    if not found:
        pts, why = score(data)
        if pts >= threshold:
            found.append(f"ofuscación avanzada (puntaje {pts}: {', '.join(why)})")
    seen, out = set(), []
    for f in found:
        if f not in seen:
            seen.add(f); out.append(f)
    return out
