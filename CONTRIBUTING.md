# Cómo contribuir a Sentinel

¡Gracias por querer mejorar Sentinel! El proyecto es de código abierto (licencia MIT), pero **todo cambio entra mediante un Pull Request** que revisa el mantenedor. Nadie escribe directamente en la rama `main`.

*(English summary at the end.)*

## Flujo

1. **Abre un issue** antes de un cambio grande, para acordar el enfoque. Para errores pequeños puedes ir directo al PR.
2. **Haz un fork** y crea una rama con un nombre claro: `fix/escaneo-de-puertos`, `feat/backend-nftables`, `docs/instalacion-fedora`.
3. **Programa y prueba.** Todo cambio de comportamiento lleva su prueba:
   ```bash
   cd tests && python3 -m unittest discover -s .
   ```
4. **Abre el Pull Request** hacia `main` y completa la plantilla. Las pruebas automáticas (GitHub Actions) deben pasar.
5. **Revisión.** El mantenedor revisa, puede pedir cambios y, si todo está bien, hace la fusión. Los PR se fusionan con *squash*; la rama `main` queda con historial lineal.

## Reglas del código

- Solo biblioteca estándar de Python (3.8 o superior): **no se agregan dependencias externas** sin discutirlo antes.
- Sentinel es una herramienta de seguridad: ningún texto que venga de un evento (registros, nombres de archivo, usuarios probados) puede tratarse como código ni como HTML. El panel usa `textContent`, las ventanas usan `--no-markup`, y las acciones son una lista cerrada con valores validados.
- Lo que Sentinel hace de forma automática debe ser **reversible y acotado**: bloqueos con caducidad, nunca borrar ni detener procesos.
- Textos para el usuario en español; nombres de código en el idioma del archivo que tocas.
- Los tests no deben depender del equipo donde corren (procesos, puertos, archivos reales): usa los ayudantes de `tests/helpers.py` y simulaciones.
- Cambios en los instaladores: pruébalos con `./install.sh --dry-run` y, si puedes, en un contenedor limpio.

## Qué es especialmente bienvenido

- Más motores de bloqueo (`nftables`), más distribuciones probadas (Fedora, Arch, openSUSE).
- Nuevas firmas de puertas traseras con una prueba que muestre un caso real y uno limpio (sin falsos positivos).
- Traducciones y mejoras del panel.

## Seguridad

**No publiques vulnerabilidades en issues.** Mira [SECURITY.md](SECURITY.md).

## Commits

Mensajes claros y en infinitivo o en pasado, uno por cambio lógico. Los commits conservan al autor real de cada cambio.

---

**English summary.** Sentinel is MIT-licensed open source. Every change goes through a Pull Request reviewed by the maintainer; nobody pushes to `main`. Fork, branch, add tests (`cd tests && python3 -m unittest discover -s .`), open the PR and let CI pass. Python standard library only; never treat event text as code or HTML; automatic actions must be bounded and reversible. Report vulnerabilities privately (see SECURITY.md).
