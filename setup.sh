#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

ENV_FILE=".env"
OUT_FILE="netduo_probe_connection.txt"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker no esta instalado. Instala Docker y vuelve a ejecutar."
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  echo "No se encontro docker compose."
  exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
  cp .env.example "$ENV_FILE"
fi

gen_key() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
  elif command -v node >/dev/null 2>&1; then
    node -e "console.log(require('crypto').randomBytes(24).toString('hex'))"
  else
    # Fallback simple random
    date +%s | sha256sum | cut -c1-48
  fi
}

API_KEY="$(grep -E '^PROBE_API_KEY=' "$ENV_FILE" | cut -d'=' -f2- || true)"
if [ -z "${API_KEY}" ] || [ "${API_KEY}" = "change-me" ]; then
  API_KEY="$(gen_key)"
  if grep -q '^PROBE_API_KEY=' "$ENV_FILE"; then
    sed -i.bak "s/^PROBE_API_KEY=.*/PROBE_API_KEY=${API_KEY}/" "$ENV_FILE"
  else
    echo "PROBE_API_KEY=${API_KEY}" >> "$ENV_FILE"
  fi
fi

PROBE_PORT="$(grep -E '^PROBE_PORT=' "$ENV_FILE" | cut -d'=' -f2- || true)"
if [ -z "${PROBE_PORT}" ]; then
  PROBE_PORT="9443"
  echo "PROBE_PORT=${PROBE_PORT}" >> "$ENV_FILE"
fi

PUBLIC_URL="$(grep -E '^PROBE_PUBLIC_URL=' "$ENV_FILE" | cut -d'=' -f2- || true)"
if [ -z "${PUBLIC_URL}" ]; then
  PUBLIC_IP="$(curl -fsS --max-time 6 https://api.ipify.org || true)"
  if [ -z "${PUBLIC_IP}" ]; then
    PUBLIC_URL="http://YOUR_VPS_IP:${PROBE_PORT}"
  else
    PUBLIC_URL="http://${PUBLIC_IP}:${PROBE_PORT}"
  fi
  if grep -q '^PROBE_PUBLIC_URL=' "$ENV_FILE"; then
    sed -i.bak "s|^PROBE_PUBLIC_URL=.*|PROBE_PUBLIC_URL=${PUBLIC_URL}|" "$ENV_FILE"
  else
    echo "PROBE_PUBLIC_URL=${PUBLIC_URL}" >> "$ENV_FILE"
  fi
fi

echo "Iniciando NetDuo WAN Probe..."
$COMPOSE up -d --build

echo "Esperando healthcheck..."
sleep 2
if ! curl -fsS --max-time 8 "http://127.0.0.1:${PROBE_PORT}/health" >/dev/null 2>&1; then
  echo "No se pudo validar /health local. Revisa logs: $COMPOSE logs -f"
fi

CREATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
PAYLOAD_JSON="$(printf '{"v":1,"kind":"netduo-wan-probe","url":"%s","apiKey":"%s","createdAt":"%s"}' "$PUBLIC_URL" "$API_KEY" "$CREATED_AT")"
if command -v openssl >/dev/null 2>&1; then
  TOKEN_ENC="$(printf '%s' "$PAYLOAD_JSON" | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
elif command -v python3 >/dev/null 2>&1; then
  TOKEN_ENC="$(PAYLOAD_JSON="$PAYLOAD_JSON" python3 - <<'PY'
import base64, json, os
payload = os.environ.get("PAYLOAD_JSON", "")
print(base64.urlsafe_b64encode(payload.encode()).decode().rstrip("="))
PY
)"
else
  echo "No se encontro openssl ni python3 para generar token."
  exit 1
fi
TOKEN="NDUO_PROBE_V1:${TOKEN_ENC}"

cat > "$OUT_FILE" <<EOF
NETDUO_PROBE_URL=${PUBLIC_URL}
NETDUO_PROBE_KEY=${API_KEY}
NETDUO_CONNECT_TOKEN=${TOKEN}
EOF

echo ""
echo "==============================================="
echo " NetDuo WAN Probe listo"
echo "==============================================="
cat "$OUT_FILE"
echo "==============================================="
echo "Archivo generado: ${ROOT_DIR}/${OUT_FILE}"
echo ""
echo "Pega NETDUO_CONNECT_TOKEN en la app NetDuo."
