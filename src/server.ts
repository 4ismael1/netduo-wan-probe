import Fastify from 'fastify'
import rateLimit from '@fastify/rate-limit'
import cors from '@fastify/cors'
import type { FastifyRequest } from 'fastify'
import { buildConnectToken } from './token'
import { JobStore } from './jobStore'
import { type ProbeConfig } from './config'
import { isPublicIPv4, performWanScan } from './scanner'
import { resolveNodeMetadata } from './nodeMetadata'
import type { ProbeLanguage, ScanMode, ScanProfile, ScanTransport } from './types'
import { resolveRuntimeVersionInfo } from './version'

function getBearerToken(req: FastifyRequest): string | null {
    const auth = req.headers.authorization
    if (!auth) return null
    const m = auth.match(/^Bearer\s+(.+)$/i)
    return m ? m[1].trim() : null
}

function getObservedIp(req: FastifyRequest): string {
    const raw = String(req.ip || '').trim()
    if (raw.startsWith('::ffff:')) return raw.slice(7)
    return raw
}

function parseTarget(raw: string | undefined, observedIp: string): string {
    const v = (raw || 'auto').trim().toLowerCase()
    if (!v || v === 'auto') return observedIp
    return v
}

function parseMode(raw: string | undefined): ScanMode {
    const value = String(raw || '').trim().toLowerCase()
    if (value === 'advanced' || value === 'deep') return value
    return 'quick'
}

function parseProfile(raw: string | undefined, fallback: ScanProfile): ScanProfile {
    const value = String(raw || '').trim().toLowerCase()
    if (value === 'safe' || value === 'balanced' || value === 'aggressive') return value
    return fallback
}

function parseTransport(raw: string | undefined, fallback: ScanTransport): ScanTransport {
    const value = String(raw || '').trim().toLowerCase()
    if (value === 'tcp' || value === 'udp' || value === 'both' || value === 'auto') return value
    return fallback
}

function parseLanguage(raw: string | undefined, fallback: ProbeLanguage): ProbeLanguage {
    const value = String(raw || '').trim().toLowerCase()
    if (value === 'es' || value === 'en') return value
    return fallback
}

function resolveTransport(requested: ScanTransport): ScanTransport {
    if (requested === 'auto') {
        return 'tcp'
    }
    return requested
}

function uniqueSortedPorts(ports: number[]): number[] {
    return Array.from(new Set(ports)).sort((a, b) => a - b)
}

function sanitizePortList(raw: unknown): number[] {
    if (!Array.isArray(raw)) return []
    return uniqueSortedPorts(
        raw
            .map(v => Number.parseInt(String(v), 10))
            .filter(n => Number.isInteger(n) && n >= 1 && n <= 65535),
    )
}

function allowlistedPorts(ports: number[], allowed: number[]) {
    const set = new Set(allowed)
    return ports.filter(p => set.has(p))
}

function sanitizePortRange(raw: unknown): number[] {
    if (!raw || typeof raw !== 'object') return []
    const obj = raw as { from?: unknown; to?: unknown }
    const from = Number.parseInt(String(obj.from ?? ''), 10)
    const to = Number.parseInt(String(obj.to ?? ''), 10)
    if (!Number.isInteger(from) || !Number.isInteger(to)) return []
    const start = Math.max(1, Math.min(from, to))
    const end = Math.min(65535, Math.max(from, to))
    if (end < start) return []
    const ports: number[] = []
    for (let port = start; port <= end; port += 1) ports.push(port)
    return ports
}

export async function buildServer(cfg: ProbeConfig) {
    const app = Fastify({
        logger: { level: cfg.logLevel },
        trustProxy: cfg.trustProxy,
        requestTimeout: Math.max(1000, cfg.requestTimeoutMs + 1500),
    })

    const jobStore = new JobStore(cfg.jobTtlMinutes, 2000)
    const node = await resolveNodeMetadata(cfg)
    const versionInfo = resolveRuntimeVersionInfo(cfg.appName)

    await app.register(cors, {
        origin: true,
        methods: ['GET', 'POST', 'OPTIONS'],
    })

    await app.register(rateLimit, {
        max: cfg.rateLimitMax,
        timeWindow: cfg.rateLimitTimeWindow,
        allowList: ['127.0.0.1'],
    })

    app.addHook('onRequest', async (req, reply) => {
        if (req.method === 'OPTIONS') return
        if (req.url === '/health') return
        if (req.url === '/version') return
        const token = getBearerToken(req) || String(req.headers['x-api-key'] || '').trim() || null
        if (!token || token !== cfg.apiKey) {
            return reply.code(401).send({
                ok: false,
                error: 'Unauthorized',
                message: 'Missing or invalid API key',
            })
        }
    })

    app.get('/health', async () => ({
        ok: true,
        service: cfg.appName,
        time: new Date().toISOString(),
        version: versionInfo,
        node,
    }))

    app.get('/version', async () => ({
        ok: true,
        time: new Date().toISOString(),
        ...versionInfo,
        capabilities: {
            localization: {
                default: cfg.defaultLanguage,
                supported: ['en', 'es'],
            },
            transport: {
                tcp: true,
                udp: cfg.enableUdpScan,
                both: cfg.enableUdpScan,
                auto: true,
                default: cfg.scanTransportDefault,
            },
            targets: {
                allowExternalTarget: cfg.allowExternalTarget,
                requirePublicTarget: cfg.requirePublicTarget,
            },
            probes: {
                http: cfg.enableHttpProbe,
                tls: cfg.enableTlsProbe,
                banner: cfg.enableBannerProbe,
            },
        },
        node: {
            nodeId: node.nodeId,
            label: node.label,
            region: node.region,
            country: node.country,
            publicIp: node.publicIp,
        },
    }))

    app.get('/whoami', async (req) => {
        const observedIp = getObservedIp(req)
        const publicCheck = isPublicIPv4(observedIp)
        const publicUrl = cfg.publicUrl || `http://${observedIp}:${cfg.port}`
        const token = buildConnectToken({ url: publicUrl, apiKey: cfg.apiKey })

        return {
            ok: true,
            observedIp,
            isPublicIp: publicCheck,
            mode: {
                allowExternalTarget: cfg.allowExternalTarget,
                requirePublicTarget: cfg.requirePublicTarget,
            },
            defaults: {
                mode: 'quick',
                profile: cfg.profileDefault,
                transport: cfg.scanTransportDefault,
                language: cfg.defaultLanguage,
            },
            quickPorts: cfg.quickPorts,
            advancedPorts: cfg.advancedPorts,
            deepPorts: cfg.deepPorts,
            quickUdpPorts: cfg.quickUdpPorts,
            advancedUdpPorts: cfg.advancedUdpPorts,
            deepUdpPorts: cfg.deepUdpPorts,
            udpEnabled: cfg.enableUdpScan,
            allowedPortsEnforced: cfg.enforceAllowedPorts,
            allowedPortsCount: cfg.allowedPorts?.length || 0,
            node,
            connect: {
                probeUrl: publicUrl,
                token,
            },
        }
    })

    app.get('/connect', async (req) => {
        const observedIp = getObservedIp(req)
        const probeUrl = cfg.publicUrl || `http://${observedIp}:${cfg.port}`
        return {
            ok: true,
            probeUrl,
            apiKey: cfg.apiKey,
            node,
            token: buildConnectToken({ url: probeUrl, apiKey: cfg.apiKey }),
        }
    })

    app.post('/scan/start', {
        schema: {
            body: {
                type: 'object',
                properties: {
                    mode: { type: 'string', enum: ['quick', 'advanced', 'deep'] },
                    profile: { type: 'string', enum: ['safe', 'balanced', 'aggressive'] },
                    transport: { type: 'string', enum: ['tcp', 'udp', 'both', 'auto'] },
                    language: { type: 'string', enum: ['en', 'es'] },
                    target: { type: 'string' },
                    ports: {
                        type: 'array',
                        items: { type: 'integer', minimum: 1, maximum: 65535 },
                    },
                    udpPorts: {
                        type: 'array',
                        items: { type: 'integer', minimum: 1, maximum: 65535 },
                    },
                    portRange: {
                        type: 'object',
                        properties: {
                            from: { type: 'integer', minimum: 1, maximum: 65535 },
                            to: { type: 'integer', minimum: 1, maximum: 65535 },
                        },
                        required: ['from', 'to'],
                        additionalProperties: false,
                    },
                    udpPortRange: {
                        type: 'object',
                        properties: {
                            from: { type: 'integer', minimum: 1, maximum: 65535 },
                            to: { type: 'integer', minimum: 1, maximum: 65535 },
                        },
                        required: ['from', 'to'],
                        additionalProperties: false,
                    },
                },
                additionalProperties: false,
            },
        },
    }, async (req, reply) => {
        const body = (req.body || {}) as {
            mode?: string
            profile?: string
            transport?: string
            language?: string
            target?: string
            ports?: number[]
            udpPorts?: number[]
            portRange?: { from: number; to: number }
            udpPortRange?: { from: number; to: number }
        }
        const observedIp = getObservedIp(req)
        const mode = parseMode(body.mode)
        const profile = parseProfile(body.profile, cfg.profileDefault)
        const requestedTransport = parseTransport(body.transport, cfg.scanTransportDefault)
        const language = parseLanguage(body.language, cfg.defaultLanguage)
        if (!cfg.enableUdpScan && (requestedTransport === 'udp' || requestedTransport === 'both')) {
            return reply.code(400).send({
                ok: false,
                error: 'UDP disabled',
                message: 'This probe has UDP scanning disabled (PROBE_ENABLE_UDP_SCAN=false). Enable UDP on the probe or request TCP/auto transport.',
                requestedTransport,
            })
        }
        const transport = resolveTransport(requestedTransport)
        const target = parseTarget(body.target, observedIp)

        if (!cfg.allowExternalTarget && target !== observedIp) {
            return reply.code(403).send({
                ok: false,
                error: 'Target not allowed',
                message: 'This probe only allows scanning your own observed public IP.',
                observedIp,
            })
        }
        if (cfg.requirePublicTarget && !isPublicIPv4(target)) {
            return reply.code(400).send({
                ok: false,
                error: 'Invalid target',
                message: 'Target must be a public IPv4 address.',
                target,
            })
        }

        const includeTcp = transport === 'tcp' || transport === 'both'
        const includeUdp = transport === 'udp' || transport === 'both'
        const genericPorts = uniqueSortedPorts([
            ...sanitizePortList(body.ports),
            ...sanitizePortRange(body.portRange),
        ])
        const udpSpecificPorts = uniqueSortedPorts([
            ...sanitizePortList(body.udpPorts),
            ...sanitizePortRange(body.udpPortRange),
        ])

        const selectedTcpBase = includeTcp
            ? (
                genericPorts.length
                    ? genericPorts.slice(0, cfg.maxCustomPorts)
                    : mode === 'deep'
                        ? cfg.deepPorts
                        : mode === 'advanced'
                            ? cfg.advancedPorts
                            : cfg.quickPorts
            )
            : []

        const selectedUdpRequested = udpSpecificPorts.length
            ? udpSpecificPorts
            : genericPorts

        const selectedUdpBase = includeUdp
            ? (
                selectedUdpRequested.length
                    ? selectedUdpRequested.slice(0, cfg.maxCustomUdpPorts)
                    : mode === 'deep'
                        ? cfg.deepUdpPorts
                        : mode === 'advanced'
                            ? cfg.advancedUdpPorts
                            : cfg.quickUdpPorts
            )
            : []

        const tcpPorts = (cfg.enforceAllowedPorts && cfg.allowedPorts)
            ? allowlistedPorts(uniqueSortedPorts(selectedTcpBase), cfg.allowedPorts)
            : uniqueSortedPorts(selectedTcpBase)

        const udpPorts = (cfg.enforceAllowedPorts && cfg.allowedPorts)
            ? allowlistedPorts(uniqueSortedPorts(selectedUdpBase), cfg.allowedPorts)
            : uniqueSortedPorts(selectedUdpBase)

        const ports = uniqueSortedPorts([...tcpPorts, ...udpPorts])
        if (!ports.length || (!tcpPorts.length && !udpPorts.length)) {
            return reply.code(400).send({
                ok: false,
                error: 'No valid ports',
                message: cfg.allowedPorts
                    ? 'No ports left after allowlist filtering.'
                    : 'No ports available for this scan transport/mode/request.',
            })
        }

        const job = jobStore.create({
            mode,
            profile,
            transport,
            language,
            target,
            observedIp,
            ports,
            tcpPorts,
            udpPorts,
        })

        void (async () => {
            try {
                jobStore.markRunning(job.id)
                const result = await performWanScan({
                    mode,
                    profile,
                    transport,
                    language,
                    target,
                    observedIp,
                    tcpPorts,
                    udpPorts,
                    cfg,
                    onProgress: progress => {
                        jobStore.updateProgress(job.id, progress)
                    },
                })
                jobStore.markDone(job.id, result)
            } catch (err) {
                const message = err instanceof Error ? err.message : 'Unknown scan error'
                app.log.error({ err }, 'scan failed')
                jobStore.markError(job.id, message)
            }
        })()

        return reply.code(202).send({
            ok: true,
            jobId: job.id,
            status: job.status,
            mode,
            profile,
            transport,
            language,
            target,
            observedIp,
            ports,
            tcpPorts,
            udpPorts,
            node,
        })
    })

    app.get('/scan/:jobId', async (req, reply) => {
        const params = req.params as { jobId: string }
        const observedIp = getObservedIp(req)
        const job = jobStore.get(params.jobId)
        if (!job) return reply.code(404).send({ ok: false, error: 'Job not found' })
        if (!cfg.allowExternalTarget && job.observedIp !== observedIp) {
            return reply.code(403).send({
                ok: false,
                error: 'Forbidden',
                message: 'This job belongs to a different requester IP.',
            })
        }
        return { ok: true, job }
    })

    app.setErrorHandler((err, req, reply) => {
        req.log.error({ err }, 'request failed')
        if (!reply.sent) {
            reply.code(500).send({
                ok: false,
                error: 'Internal server error',
            })
        }
    })

    if (cfg.apiKey === 'change-me') {
        app.log.warn('PROBE_API_KEY is set to "change-me". Run setup script before exposing this service.')
    }
    if (!cfg.enforceAllowedPorts && cfg.allowedPorts?.length) {
        app.log.warn('PROBE_ALLOWED_PORTS is configured but PROBE_ENFORCE_ALLOWED_PORTS=false, so allowlist filter is disabled.')
    }

    return app
}
