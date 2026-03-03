# NetDuo WAN Probe

Self-hosted WAN exposure probe used by the NetDuo desktop app.
It runs scans from outside your local network and returns normalized security findings.

## Highlights

1. Real WAN scans with profiles: `quick`, `advanced`, `deep`.
2. Transport support: `tcp`, `udp`, `both`, `auto` (`auto` resolves to TCP).
3. Progressive job phases: `queued`, `tcp_sweep`, `udp_sweep`, `service_probe`, `analysis`.
4. Risk output with `findings`, `riskScore`, `confidenceScore`.
5. Secure API with API key auth and rate limiting.
6. Auto bootstrap for Node, Railway-like environments, and Pterodactyl.
7. Auto-generated NetDuo connect token.

## Requirements

1. Node.js `>=18` (recommended: Node 20+).
2. npm.

## Quick Start

```bash
npm install
npm start
```

On first boot, the service automatically:

1. Creates `.env` (from `.env.example` when available).
2. Generates a strong `PROBE_API_KEY` if the current value is a placeholder.
3. Resolves `PROBE_PUBLIC_URL` from platform domain, configured URL, or public IP fallback.
4. Writes `netduo_probe_connection.txt` with:
   - `NETDUO_PROBE_URL`
   - `NETDUO_PROBE_KEY`
   - `NETDUO_CONNECT_TOKEN`
5. Starts the server and prints runtime connection details.

## Connect to NetDuo

1. Open `netduo_probe_connection.txt`.
2. Copy `NETDUO_CONNECT_TOKEN`.
3. Paste it into NetDuo WAN Probe setup.

## Deploy

### Generic Node / VPS

```bash
npm install
npm start
```

### Railway / Render / similar

1. Deploy repo.
2. Set start command to `npm start`.
3. Expose a public domain in your platform.
4. Use the printed public URL (not container localhost/private IP).

Important:

1. Do not use `127.0.0.1` or internal container IPs for NetDuo connection.
2. Use the platform public URL only.
3. Do not append internal container port to an external managed URL.

### Pterodactyl

Recommended:

1. `MAIN_FILE=start.ts` (for eggs running `ts-node --esm`).
2. Alternative `MAIN_FILE=start.js` if your egg executes JS directly.
3. Keep default startup command from the panel.

The service bootstrap still auto-configures `.env` and `netduo_probe_connection.txt`.

## Main Configuration

Edit `.env`:

1. `PROBE_PORT` (default `9443`)
2. `PROBE_PUBLIC_URL`
3. `PROBE_API_KEY`
4. `PROBE_ALLOW_EXTERNAL_TARGET` (default `true`)
5. `PROBE_REQUIRE_PUBLIC_TARGET` (default `true`)
6. `PROBE_SCAN_TRANSPORT_DEFAULT` (`tcp`, `udp`, `both`, `auto`; default `tcp`)
7. `PROBE_ENABLE_UDP_SCAN` (default `true`)
8. `PROBE_PROFILE_DEFAULT` (`balanced` default)
9. `PROBE_ALLOWED_PORTS` (optional allowlist)
10. `PROBE_ENFORCE_ALLOWED_PORTS` (default `false`)
11. `PROBE_NODE_*` overrides (optional manual node metadata)

## API

Public endpoints:

1. `GET /health`
2. `GET /version`

Protected endpoints:

1. `GET /whoami`
2. `GET /connect`
3. `POST /scan/start`
4. `GET /scan/:jobId`

Auth headers:

```http
Authorization: Bearer <PROBE_API_KEY>
```

Alternative:

```http
x-api-key: <PROBE_API_KEY>
```

## API Versioning

The service exposes:

1. `packageVersion`: package release version.
2. `apiVersion`: semantic API contract version (`vX.Y.Z`).
3. `apiRevision`: compatibility alias (same value as `apiVersion`).
4. `capabilities.transport`: runtime transport support (`tcp`, `udp`, `both`, `auto`, `default`).

Current API contract:

1. `apiVersion = v1.1.0`
2. `apiRevision = v1.1.0`

## API Examples

Health:

```bash
curl http://127.0.0.1:9443/health
```

Version:

```bash
curl http://127.0.0.1:9443/version
```

Whoami:

```bash
curl -H "Authorization: Bearer YOUR_KEY" http://127.0.0.1:9443/whoami
```

Start quick TCP scan:

```bash
curl -X POST http://127.0.0.1:9443/scan/start \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"mode":"quick","profile":"balanced","transport":"tcp","target":"auto"}'
```

Start advanced TCP+UDP scan:

```bash
curl -X POST http://127.0.0.1:9443/scan/start \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"mode":"advanced","profile":"balanced","transport":"both","ports":[22,80,443,3389],"udpPorts":[53,123,161,1900]}'
```

Read job:

```bash
curl -H "Authorization: Bearer YOUR_KEY" http://127.0.0.1:9443/scan/<jobId>
```

## Scripts

1. `npm start`: auto-config + server start (recommended).
2. `npm run setup:auto`: generate config/token only.
3. `npm run start:server`: TS start with auto-config.
4. `npm run start:pterodactyl`: pterodactyl-safe start alias.
5. `npm run check`: TypeScript type check.
6. `npm run test`: automated tests.
7. `npm run build`: TypeScript build.
8. `npm run start:dist`: run compiled build.

## Security Defaults

1. API key required for all scan endpoints.
2. Rate limiting enabled.
3. External target scanning enabled by default.
4. Public IPv4 target required by default.

Adjust policy via `.env` before public use.

## Result Model

Each job returns:

1. Current phase + live progress counters.
2. Transport-aware port results (`tcp` / `udp`).
3. Findings and recommendations.
4. Risk and confidence scoring.
5. Scan runtime metadata.

## Notes

1. This service is for WAN exposure validation.
2. LAN checks (UPnP/NAT-PMP/local admin) belong in NetDuo LAN modules, not this service.
