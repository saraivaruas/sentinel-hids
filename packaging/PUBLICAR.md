# Publicar Sentinel (lo que hace cada tienda y qué haces tú)

Todo lo técnico está listo y se prueba solo en cada cambio (`.github/workflows/paquetes.yml`). Lo que sigue necesita **tus cuentas y tu firma**; yo no las creo ni las uso.

## 1. Repositorio APT firmado (Debian, Ubuntu, Mint… y el Centro de Software)
1. Crea la clave de firma una vez: `./tools/crear-clave-de-publicacion.sh "Tu Nombre" tu@correo` (tú eliges la frase secreta).
2. En GitHub → Settings → Secrets → Actions agrega `APT_GPG_PRIVATE_KEY` (salida de `gpg --armor --export-secret-keys <huella>`) y `APT_GPG_PASSPHRASE`.
3. En Settings → Pages elige la rama `gh-pages`.
4. Publica una *Release* en GitHub: el trabajo `repo-apt` construye el .deb, firma el repositorio y lo sube a Pages.
5. Tus usuarios instalan con las 4 líneas de `LEEME.txt` (carpeta `apt/`). Desde ahí el Centro de Software lo muestra gracias a `packaging/appstream/…metainfo.xml`.
   - Prueba local sin publicar: `./tools/crear-repo-apt.sh <huella> /tmp/repo`.
   - Si quieres estar en los repositorios oficiales de Debian/Ubuntu, el camino es un paquete fuente enviado a Debian (mentors.debian.net); el .deb actual es la base.

## 2. Snap Store (confinamiento *classic*)
1. Cuenta en https://snapcraft.io y `snapcraft register sentinel-hids` (si el nombre está tomado, cambia `name:` en `snap/snapcraft.yaml`).
2. Descarga el `.snap` del trabajo `snap` de la CI (artefacto) o compila con `snapcraft`.
3. `snapcraft upload --release=candidate sentinel-hids_*.snap`.
4. **Pide el confinamiento classic** en https://forum.snapcraft.io (categoría *store-requests*): explica que Sentinel necesita leer registros y archivos del sistema y, con permiso, cambiar el cortafuegos. Un revisor humano lo aprueba; hasta entonces no se puede publicar en `stable`.

## 3. Flathub (solo el panel, lectura)
El motor necesita ser root, algo que Flatpak no permite; por eso Flathub llevaría **solo el panel** que muestra el estado del motor instalado por APT o Snap.
1. Sigue https://docs.flathub.org/docs/for-app-authors/submission con `packaging/flatpak/io.github.saraivaruas.sentinel.yml` (abre un PR a `flathub/flathub`).
2. Prepárate para explicar `--share=network` (el panel es un servidor local) y los permisos de solo lectura a `/var/lib/sentinel`, `/var/log/sentinel` y `/etc`.
