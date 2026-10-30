# Política de seguridad

Sentinel es una herramienta de seguridad: tomamos los reportes en serio.

## Versiones con soporte

| Versión | Soporte |
|---|---|
| 2.x | ✅ correcciones de seguridad |
| 1.x (scripts originales) | ❌ reemplazada por la 2.x |

## Cómo reportar una vulnerabilidad

**No abras un issue público.** Usa el reporte privado de GitHub: pestaña **Security → Report a vulnerability** de este repositorio. Incluye:

- qué versión usas y en qué distribución,
- los pasos para reproducirlo,
- qué impacto tiene (por ejemplo: escalada de privilegios, evasión de la detección, inyección en el panel).

Responderemos en un plazo de **7 días** y buscaremos publicar la corrección y el aviso de forma coordinada.

## Qué se considera vulnerabilidad

- Ejecución de código o escalada de privilegios a través del panel, el servicio, los instaladores o los archivos de estado.
- Que un atacante pueda **evitar la detección** de forma sencilla o hacer que Sentinel bloquee a una IP legítima (denegación de servicio sobre el propio sistema).
- Inyección (HTML, comandos, rutas) a partir del texto de los eventos.
- Fuga de la llave del panel o de las referencias de integridad.

## Límites conocidos (no son vulnerabilidades)

Están descritos en el README: un atacante que ya tiene `root` puede detener Sentinel; las firmas de puertas traseras cubren patrones comunes y no ofuscación avanzada.
