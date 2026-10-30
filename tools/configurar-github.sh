#!/usr/bin/env bash
# Crea y configura el repositorio público en GitHub: descripción, temas (para que aparezca en las búsquedas), seguridad y
# protección de la rama main (todo cambio entra por Pull Request con la revisión del mantenedor).
# Requiere la CLI «gh» autenticada con tu cuenta (gh auth login). Uso: tools/configurar-github.sh [usuario/repositorio]
set -euo pipefail
REPO="${1:-saraivaruas/sentinel-hids}"
DESC="Sentinel: detector de intrusiones para Linux (HIDS). Integridad de archivos, webshells, fuerza bruta, escaneo de puertos, honeypots y panel gráfico. Python sin dependencias. MIT"
cd "$(dirname "$0")/.."

echo "== 1/5 Crear el repositorio público (si no existe) y subir main"
if ! gh repo view "$REPO" >/dev/null 2>&1; then
  gh repo create "$REPO" --public --description "$DESC" --homepage "https://github.com/$REPO"
fi
git remote get-url origin >/dev/null 2>&1 || git remote add origin "https://github.com/$REPO.git"
git push -u origin main          # primera y única subida directa a main; después queda protegida

echo "== 2/5 Descripción, temas y ajustes"
gh repo edit "$REPO" --description "$DESC" --enable-issues --enable-discussions \
  --enable-wiki=false --enable-projects=false --delete-branch-on-merge \
  --enable-squash-merge --enable-merge-commit=false --enable-rebase-merge=false
for t in intrusion-detection hids file-integrity-monitoring honeypot linux-security cybersecurity security-monitoring threat-detection blue-team \
         webshell-detection brute-force-protection crowdsec ufw firewalld systemd linux python security-tools incident-response dashboard; do
  gh repo edit "$REPO" --add-topic "$t"
done

echo "== 3/5 Seguridad: reporte privado de vulnerabilidades, alertas de secretos y de dependencias"
gh api -X PUT "repos/$REPO/private-vulnerability-reporting" >/dev/null || echo "   (actívalo a mano en Settings > Security)"
gh api -X PATCH "repos/$REPO" -F "security_and_analysis[secret_scanning][status]=enabled" -F "security_and_analysis[secret_scanning_push_protection][status]=enabled" >/dev/null || true
gh api -X PUT "repos/$REPO/vulnerability-alerts" >/dev/null || true

echo "== 4/5 Esperando la primera ejecución de las pruebas automáticas…"
sleep 20; gh run list -R "$REPO" --limit 1 || true

echo "== 5/5 Protección de la rama main: solo con Pull Request, revisión del mantenedor y pruebas en verde"
gh api -X PUT "repos/$REPO/branches/main/protection" --input - >/dev/null <<'JSON'
{
  "required_status_checks": {"strict": true, "contexts": ["Python 3.10 en ubuntu-22.04", "Python 3.12 en ubuntu-24.04"]},
  "enforce_admins": false,
  "required_pull_request_reviews": {"required_approving_review_count": 1, "require_code_owner_reviews": true, "dismiss_stale_reviews": true},
  "restrictions": null,
  "required_linear_history": true,
  "required_conversation_resolution": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
echo "Listo: https://github.com/$REPO"
echo "Falta a mano (solo la web lo permite): Settings > General > Social preview > subir docs/social-preview.png"
