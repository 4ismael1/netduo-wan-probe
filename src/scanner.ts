import http from 'http'
import https from 'https'
import dgram from 'dgram'
import net from 'net'
import tls from 'tls'
import {
    retriesForModeTransport,
    runtimeForModeTransport,
    SERVICE_NAMES,
    type ProbeConfig,
} from './config'
import type {
    BannerProbeResult,
    Finding,
    HttpProbeResult,
    PortScanResult,
    PortState,
    ProbeLanguage,
    ScanMode,
    ScanPhase,
    ScanProfile,
    ScanProgress,
    ScanTransport,
    TlsProbeResult,
    WanScanResult,
} from './types'

export interface PerformWanScanInput {
    mode: ScanMode
    profile: ScanProfile
    transport: ScanTransport
    target: string
    observedIp: string
    tcpPorts: number[]
    udpPorts: number[]
    cfg: ProbeConfig
    language?: ProbeLanguage
    onProgress?: (progress: ScanProgress) => void
}

interface SocketAttemptResult {
    state: PortState
    rttMs: number | null
    error: string | null
}

interface UdpAttemptResult {
    state: PortState
    stateReason: string | null
    rttMs: number | null
    error: string | null
}

interface HttpAttemptResult {
    ok: boolean
    statusCode: number | null
    serverHeader: string | null
    poweredByHeader: string | null
    authHeader: string | null
    title: string | null
    locationHeader: string | null
    adminLike: boolean
    responseBytes: number
    error?: string
}

const HTTP_CANDIDATE_PORTS = new Set<number>([
    80, 81, 82, 83, 84, 85, 88, 443, 444, 554, 631, 7001, 7002, 7080, 7443, 7547, 8000, 8008, 8010, 8080,
    8081, 8088, 8090, 8443, 8888, 9000, 9090, 9200, 9443, 10000, 15672,
])

const HTTPS_CANDIDATE_PORTS = new Set<number>([
    443, 444, 465, 636, 990, 993, 995, 2376, 2484, 4443, 5001, 5061, 5986, 6443, 7002, 7443, 8443, 9443,
])

const ADMIN_PORTS = new Set<number>([
    22, 23, 80, 443, 554, 3389, 5900, 5985, 5986, 7001, 7002, 7443, 7547, 8080, 8081, 8443, 8888, 9000,
    9443, 10000,
])

const DANGEROUS_DATABASE_PORTS = new Set<number>([
    1433, 1521, 3306, 5432, 6379, 9200, 11211, 15672, 27017,
])

const LEGACY_PORTS = new Set<number>([21, 23, 69, 110, 143, 1723, 1900, 5000, 32764])
const UDP_ADMIN_PORTS = new Set<number>([53, 123, 161, 500, 1701, 1812, 1900, 4500, 5004, 5060, 5351])

function clamp(value: number, min: number, max: number): number {
    return Math.max(min, Math.min(max, value))
}

function isIPv4(text: string): boolean {
    const parts = text.split('.')
    if (parts.length !== 4) return false
    for (const part of parts) {
        if (!/^\d+$/.test(part)) return false
        const n = Number.parseInt(part, 10)
        if (n < 0 || n > 255) return false
    }
    return true
}

export function isPublicIPv4(text: string): boolean {
    if (!isIPv4(text)) return false
    const [a, b] = text.split('.').map(v => Number.parseInt(v, 10))

    if (a === 0 || a === 10 || a === 127) return false
    if (a === 100 && b >= 64 && b <= 127) return false
    if (a === 169 && b === 254) return false
    if (a === 172 && b >= 16 && b <= 31) return false
    if (a === 192 && b === 168) return false
    if (a === 198 && (b === 18 || b === 19)) return false
    if (a >= 224) return false

    return true
}

function classifySocketError(errorCode: string | undefined): PortState {
    if (!errorCode) return 'filtered'
    if (errorCode === 'ECONNREFUSED' || errorCode === 'ECONNRESET') return 'closed'
    if (
        errorCode === 'ETIMEDOUT'
        || errorCode === 'EHOSTUNREACH'
        || errorCode === 'ENETUNREACH'
        || errorCode === 'EHOSTDOWN'
        || errorCode === 'ENETDOWN'
    ) {
        return 'filtered'
    }
    return 'filtered'
}

function parseTitle(html: string): string | null {
    const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)
    if (!m) return null
    const compact = m[1].replace(/\s+/g, ' ').trim()
    return compact ? compact.slice(0, 120) : null
}

function toHeaderString(value: string | string[] | undefined): string | null {
    if (typeof value === 'string') return value
    if (Array.isArray(value) && value.length) return value.join(', ')
    return null
}

function looksAdminPage(title: string | null, location: string | null, authHeader: string | null): boolean {
    const combined = `${title || ''} ${location || ''} ${authHeader || ''}`.toLowerCase()
    if (!combined.trim()) return false
    return /(admin|login|router|gateway|management|dashboard|control panel|webmin|modem)/i.test(combined)
}

function sanitizeBanner(input: string): string {
    return input
        .replace(/[^\x20-\x7E\r\n\t]/g, '')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 180)
}

function bannerServiceHint(banner: string): string | null {
    const text = banner.toLowerCase()
    if (text.includes('ssh-')) return 'ssh'
    if (text.includes('ftp')) return 'ftp'
    if (text.includes('smtp')) return 'smtp'
    if (text.includes('imap')) return 'imap'
    if (text.includes('pop3')) return 'pop3'
    if (text.includes('redis')) return 'redis'
    if (text.includes('http/')) return 'http'
    if (text.includes('rtsp')) return 'rtsp'
    if (text.includes('mysql')) return 'mysql'
    return null
}

function certFieldToText(value: unknown): string | null {
    if (typeof value === 'string') return value || null
    if (Array.isArray(value)) {
        const joined = value.map(v => String(v)).join(', ').trim()
        return joined || null
    }
    return null
}

function runWithConcurrency<TInput, TResult>(
    items: TInput[],
    concurrency: number,
    worker: (item: TInput, index: number) => Promise<TResult>,
): Promise<TResult[]> {
    if (!items.length) return Promise.resolve([])
    const safeConcurrency = clamp(Math.floor(concurrency) || 1, 1, Math.max(1, items.length))
    const out: TResult[] = new Array(items.length)
    let nextIndex = 0

    const runner = async () => {
        while (true) {
            const idx = nextIndex
            nextIndex += 1
            if (idx >= items.length) return
            out[idx] = await worker(items[idx], idx)
        }
    }

    const workers = Array.from({ length: safeConcurrency }, () => runner())
    return Promise.all(workers).then(() => out)
}

function socketAttempt(target: string, port: number, timeoutMs: number): Promise<SocketAttemptResult> {
    return new Promise(resolve => {
        const started = Date.now()
        let settled = false
        const socket = new net.Socket()

        const finish = (result: SocketAttemptResult) => {
            if (settled) return
            settled = true
            socket.removeAllListeners()
            socket.destroy()
            resolve(result)
        }

        socket.setTimeout(timeoutMs)
        socket.once('connect', () => {
            finish({
                state: 'open',
                rttMs: Math.max(1, Date.now() - started),
                error: null,
            })
        })
        socket.once('timeout', () => {
            finish({
                state: 'filtered',
                rttMs: null,
                error: 'timeout',
            })
        })
        socket.once('error', (err: NodeJS.ErrnoException) => {
            finish({
                state: classifySocketError(err.code),
                rttMs: null,
                error: err.code || err.message || 'socket-error',
            })
        })

        socket.connect(port, target)
    })
}

async function probeTcpPort(
    target: string,
    port: number,
    retries: number,
    timeoutMs: number,
): Promise<PortScanResult> {
    const maxAttempts = clamp(retries, 1, 10)
    let finalState: PortState = 'filtered'
    let finalRtt: number | null = null
    let finalError: string | null = null
    let attempts = 0

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
        attempts = attempt
        const result = await socketAttempt(target, port, timeoutMs)
        finalState = result.state
        finalRtt = result.rttMs
        finalError = result.error
        if (result.state === 'open') break
        if (result.state === 'closed') break
    }

    return {
        port,
        protocol: 'tcp',
        service: SERVICE_NAMES[port] || 'unknown',
        state: finalState,
        attempts,
        rttMs: finalRtt,
        lastError: finalError,
    }
}

function classifyUdpError(errorCode: string | undefined): PortState {
    if (!errorCode) return 'filtered'
    if (errorCode === 'ECONNREFUSED' || errorCode === 'ECONNRESET') return 'closed'
    if (
        errorCode === 'ETIMEDOUT'
        || errorCode === 'EHOSTUNREACH'
        || errorCode === 'ENETUNREACH'
        || errorCode === 'EHOSTDOWN'
        || errorCode === 'ENETDOWN'
    ) {
        return 'filtered'
    }
    return 'filtered'
}

function udpProbePayload(port: number): Buffer {
    if (port === 53) {
        return Buffer.from([
            0x12, 0x34, // transaction id
            0x01, 0x00, // standard query
            0x00, 0x01, // questions
            0x00, 0x00, // answer RRs
            0x00, 0x00, // authority RRs
            0x00, 0x00, // additional RRs
            0x03, 0x77, 0x77, 0x77, // www
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // example
            0x03, 0x63, 0x6f, 0x6d, // com
            0x00, // root
            0x00, 0x01, // A
            0x00, 0x01, // IN
        ])
    }
    if (port === 123) {
        const ntp = Buffer.alloc(48)
        ntp[0] = 0x1b
        return ntp
    }
    if (port === 161) {
        return Buffer.from([
            0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
            0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
            0x04, 0x71, 0x6b, 0x21, 0x46, 0x02, 0x01, 0x00,
            0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06,
            0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
        ])
    }
    return Buffer.from('NetDuoProbe-UDP')
}

function udpSocketAttempt(target: string, port: number, timeoutMs: number): Promise<UdpAttemptResult> {
    return new Promise(resolve => {
        const started = Date.now()
        const socket = dgram.createSocket('udp4')
        const payload = udpProbePayload(port)
        let settled = false

        const finish = (result: UdpAttemptResult) => {
            if (settled) return
            settled = true
            socket.removeAllListeners()
            try {
                socket.close()
            } catch {
                // ignore
            }
            resolve(result)
        }

        const timer = setTimeout(() => {
            finish({
                state: 'filtered',
                stateReason: 'open|filtered',
                rttMs: null,
                error: 'timeout',
            })
        }, Math.max(250, timeoutMs))

        socket.once('error', (err: NodeJS.ErrnoException) => {
            clearTimeout(timer)
            finish({
                state: classifyUdpError(err.code),
                stateReason: null,
                rttMs: null,
                error: err.code || err.message || 'udp-error',
            })
        })

        socket.once('message', () => {
            clearTimeout(timer)
            finish({
                state: 'open',
                stateReason: null,
                rttMs: Math.max(1, Date.now() - started),
                error: null,
            })
        })

        socket.connect(port, target, () => {
            socket.send(payload, sendErr => {
                if (sendErr) {
                    clearTimeout(timer)
                    finish({
                        state: classifyUdpError((sendErr as NodeJS.ErrnoException).code),
                        stateReason: null,
                        rttMs: null,
                        error: (sendErr as NodeJS.ErrnoException).code || sendErr.message || 'send-error',
                    })
                }
            })
        })
    })
}

async function probeUdpPort(
    target: string,
    port: number,
    retries: number,
    timeoutMs: number,
): Promise<PortScanResult> {
    const maxAttempts = clamp(retries, 1, 10)
    let finalState: PortState = 'filtered'
    let finalStateReason: string | null = null
    let finalRtt: number | null = null
    let finalError: string | null = null
    let attempts = 0

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
        attempts = attempt
        const result = await udpSocketAttempt(target, port, timeoutMs)
        finalState = result.state
        finalStateReason = result.stateReason
        finalRtt = result.rttMs
        finalError = result.error
        if (result.state === 'open') break
        if (result.state === 'closed') break
    }

    return {
        port,
        protocol: 'udp',
        service: SERVICE_NAMES[port] || 'unknown',
        state: finalState,
        stateReason: finalStateReason,
        attempts,
        rttMs: finalRtt,
        lastError: finalError,
    }
}

function httpAttempt(
    target: string,
    port: number,
    protocol: 'http' | 'https',
    timeoutMs: number,
): Promise<HttpAttemptResult> {
    return new Promise(resolve => {
        const moduleImpl = protocol === 'https' ? https : http
        const req = moduleImpl.request({
            host: target,
            port,
            method: 'GET',
            path: '/',
            timeout: timeoutMs,
            rejectUnauthorized: false,
            headers: {
                'user-agent': 'NetDuoProbe/1.1',
                'accept': 'text/html,application/json;q=0.9,*/*;q=0.5',
                'connection': 'close',
            },
        }, res => {
            const chunks: Buffer[] = []
            let bytes = 0
            res.on('data', (chunk: Buffer) => {
                bytes += chunk.length
                if (bytes <= 32768) chunks.push(chunk)
            })
            res.on('end', () => {
                const body = chunks.length ? Buffer.concat(chunks).toString('utf8') : ''
                const title = parseTitle(body)
                const serverHeader = toHeaderString(res.headers.server)
                const poweredByHeader = toHeaderString(res.headers['x-powered-by'])
                const authHeader = toHeaderString(res.headers['www-authenticate'])
                const locationHeader = toHeaderString(res.headers.location)
                resolve({
                    ok: true,
                    statusCode: res.statusCode || null,
                    serverHeader,
                    poweredByHeader,
                    authHeader,
                    title,
                    locationHeader,
                    adminLike: looksAdminPage(title, locationHeader, authHeader),
                    responseBytes: bytes,
                })
            })
        })

        req.on('timeout', () => {
            req.destroy(new Error('timeout'))
        })
        req.on('error', err => {
            resolve({
                ok: false,
                statusCode: null,
                serverHeader: null,
                poweredByHeader: null,
                authHeader: null,
                title: null,
                locationHeader: null,
                adminLike: false,
                responseBytes: 0,
                error: err.message || 'http-error',
            })
        })
        req.end()
    })
}

function shouldHttpProbe(result: PortScanResult): boolean {
    if (HTTP_CANDIDATE_PORTS.has(result.port)) return true
    if (result.service.includes('http') || result.service.includes('web')) return true
    return false
}

function shouldTlsProbe(result: PortScanResult): boolean {
    if (HTTPS_CANDIDATE_PORTS.has(result.port)) return true
    if (result.service.includes('https') || result.service.includes('tls') || result.service.includes('ssl')) return true
    return false
}

async function runHttpProbe(target: string, port: number, timeoutMs: number): Promise<HttpProbeResult> {
    const protocols: Array<'http' | 'https'> = shouldTlsProbe({
        port,
        protocol: 'tcp',
        service: SERVICE_NAMES[port] || 'unknown',
        state: 'open',
        attempts: 1,
        rttMs: null,
        lastError: null,
    })
        ? ['https', 'http']
        : ['http', 'https']

    let fallback: HttpAttemptResult | null = null
    for (const protocol of protocols) {
        const attempt = await httpAttempt(target, port, protocol, timeoutMs)
        if (attempt.ok) {
            return {
                ok: true,
                protocol,
                statusCode: attempt.statusCode,
                serverHeader: attempt.serverHeader,
                poweredByHeader: attempt.poweredByHeader,
                authHeader: attempt.authHeader,
                title: attempt.title,
                locationHeader: attempt.locationHeader,
                adminLike: attempt.adminLike,
                responseBytes: attempt.responseBytes,
            }
        }
        fallback = attempt
    }

    return {
        ok: false,
        protocol: protocols[0],
        statusCode: null,
        serverHeader: null,
        poweredByHeader: null,
        authHeader: null,
        title: null,
        locationHeader: null,
        adminLike: false,
        responseBytes: 0,
        error: fallback?.error || 'http-probe-failed',
    }
}

function runTlsProbe(target: string, port: number, timeoutMs: number): Promise<TlsProbeResult> {
    return new Promise(resolve => {
        let settled = false
        const socket = tls.connect({
            host: target,
            port,
            servername: isIPv4(target) ? undefined : target,
            rejectUnauthorized: false,
            timeout: timeoutMs,
        })

        const finish = (result: TlsProbeResult) => {
            if (settled) return
            settled = true
            socket.removeAllListeners()
            socket.destroy()
            resolve(result)
        }

        socket.once('secureConnect', () => {
            const cert = socket.getPeerCertificate()
            const validTo = cert?.valid_to ? new Date(cert.valid_to).toISOString() : null
            const expired = validTo ? Date.parse(validTo) < Date.now() : null
            const subjectCn = certFieldToText(cert?.subject?.CN)
            const issuerCn = certFieldToText(cert?.issuer?.CN)
            const selfSigned = subjectCn && issuerCn ? subjectCn === issuerCn : null
            const cipher = socket.getCipher()
            const authErr = socket.authorizationError
            const authErrText = typeof authErr === 'string'
                ? authErr
                : authErr instanceof Error
                    ? authErr.message
                    : null

            finish({
                ok: true,
                protocol: socket.getProtocol() || null,
                cipher: cipher?.name || null,
                authorized: socket.authorized,
                authorizationError: authErrText,
                subject: subjectCn,
                issuer: issuerCn,
                validTo,
                expired,
                selfSigned,
            })
        })
        socket.once('timeout', () => {
            finish({
                ok: false,
                protocol: null,
                cipher: null,
                authorized: false,
                authorizationError: null,
                subject: null,
                issuer: null,
                validTo: null,
                expired: null,
                selfSigned: null,
                error: 'timeout',
            })
        })
        socket.once('error', err => {
            finish({
                ok: false,
                protocol: null,
                cipher: null,
                authorized: false,
                authorizationError: null,
                subject: null,
                issuer: null,
                validTo: null,
                expired: null,
                selfSigned: null,
                error: err.message || 'tls-error',
            })
        })
    })
}

function runBannerProbe(target: string, port: number, timeoutMs: number): Promise<BannerProbeResult> {
    return new Promise(resolve => {
        const socket = new net.Socket()
        let settled = false
        let data = ''

        const finish = (result: BannerProbeResult) => {
            if (settled) return
            settled = true
            socket.removeAllListeners()
            socket.destroy()
            resolve(result)
        }

        socket.setTimeout(timeoutMs)
        socket.once('connect', () => {
            socket.write('\r\n')
        })
        socket.on('data', chunk => {
            data += chunk.toString('utf8')
            if (data.length > 256) data = data.slice(0, 256)
            const banner = sanitizeBanner(data)
            if (banner) {
                finish({
                    ok: true,
                    serviceHint: bannerServiceHint(banner),
                    banner,
                })
            }
        })
        socket.once('timeout', () => {
            const banner = sanitizeBanner(data)
            if (banner) {
                finish({
                    ok: true,
                    serviceHint: bannerServiceHint(banner),
                    banner,
                })
            } else {
                finish({
                    ok: false,
                    serviceHint: null,
                    banner: null,
                    error: 'timeout',
                })
            }
        })
        socket.once('error', err => {
            finish({
                ok: false,
                serviceHint: null,
                banner: null,
                error: err.message || 'banner-error',
            })
        })
        socket.once('close', () => {
            const banner = sanitizeBanner(data)
            if (banner) {
                finish({
                    ok: true,
                    serviceHint: bannerServiceHint(banner),
                    banner,
                })
            } else {
                finish({
                    ok: false,
                    serviceHint: null,
                    banner: null,
                    error: 'closed-no-banner',
                })
            }
        })

        socket.connect(port, target)
    })
}

function addFinding(findings: Finding[], finding: Finding) {
    if (findings.some(f => f.id === finding.id)) return
    findings.push(finding)
}

function summarizePorts(ports: number[], max = 8, language: ProbeLanguage = 'en'): string {
    if (!ports.length) return language === 'es' ? 'ninguno' : 'none'
    const shown = ports.slice(0, max).join(', ')
    if (ports.length <= max) return shown
    return `${shown} (+${ports.length - max})`
}

const ES_TO_EN_REPLACEMENTS: Array<[RegExp, string]> = [
    [/Docker Remote API sin TLS expuest[ao]/gi, 'Docker Remote API exposed without TLS'],
    [/Servicios de base de datos visibles desde Internet/gi, 'Database services exposed to the internet'],
    [/SNMP expuesto por UDP en WAN/gi, 'SNMP exposed over UDP on WAN'],
    [/DNS UDP expuesto en WAN/gi, 'DNS over UDP exposed on WAN'],
    [/SSDP\/UPnP visible por UDP en WAN/gi, 'SSDP/UPnP exposed over UDP on WAN'],
    [/TFTP expuesto por UDP en WAN/gi, 'TFTP exposed over UDP on WAN'],
    [/Protocolos legacy\/inseguros expuestos/gi, 'Legacy/insecure protocols exposed'],
    [/Superficie de administracion remota visible/gi, 'Remote administration surface visible'],
    [/Superficie UDP administrativa visible/gi, 'UDP administrative surface visible'],
    [/Interfaz web de administracion detectada en WAN/gi, 'Administrative web interface detected on WAN'],
    [/Configuracion TLS debil o certificado no confiable/gi, 'Weak TLS configuration or untrusted certificate'],
    [/Superficie WAN extensa/gi, 'Broad WAN attack surface'],
    [/Varios puertos UDP quedaron en estado indeterminado/gi, 'Multiple UDP ports remained indeterminate'],
    [/No se detectaron puertos abiertos en el set escaneado/gi, 'No open ports detected in scanned set'],
    [/Puerto 2375 abierto en (.+)\./gi, 'Port 2375 is open on $1.'],
    [/Puertos detectados: (.+)\./gi, 'Detected ports: $1.'],
    [/SNMP detectado en: (.+)\./gi, 'SNMP detected on: $1.'],
    [/UDP\/53 abierto en: (.+)\./gi, 'UDP/53 is open on: $1.'],
    [/UDP\/1900 abierto en: (.+)\./gi, 'UDP/1900 is open on: $1.'],
    [/UDP\/69 abierto en: (.+)\./gi, 'UDP/69 is open on: $1.'],
    [/Puertos legacy abiertos: (.+)\./gi, 'Open legacy ports: $1.'],
    [/Puertos administrativos abiertos: (.+)\./gi, 'Open administrative ports: $1.'],
    [/Servicios UDP sensibles abiertos: (.+)\./gi, 'Open sensitive UDP services: $1.'],
    [/Admin\/login identificado en puertos: (.+)\./gi, 'Admin/login surface identified on ports: $1.'],
    [/Servicios con cert auto-firmado\/expirado en: (.+)\./gi, 'Services with self-signed/expired certs on: $1.'],
    [/(\d+)\s+puertos abiertos detectados \(TCP:\s*(\d+), UDP:\s*(\d+)\)\./gi, '$1 open ports detected (TCP: $2, UDP: $3).'],
    [/(\d+)\s+puertos UDP sin respuesta \(open\|filtered\)\./gi, '$1 UDP ports without response (open|filtered).'],
    [/Todos los puertos del escaneo respondieron como cerrados o filtrados\./gi, 'All scanned ports responded as closed or filtered.'],
    [/Deshabilita 2375 en WAN o fuerza TLS mutuo en 2376 con ACL estricta\./gi, 'Disable port 2375 on WAN or enforce mutual TLS on 2376 with strict ACLs.'],
    [/Restringe acceso por firewall y expone BD solo por VPN o red privada\./gi, 'Restrict access with firewall rules and expose databases only through VPN or private network.'],
    [/Bloquea SNMP en WAN o limita por ACL estricta y credenciales robustas\./gi, 'Block SNMP on WAN or restrict it with strict ACLs and strong credentials.'],
    [/Restringe recursion y permite consultas solo desde rangos autorizados\./gi, 'Restrict recursion and allow queries only from authorized ranges.'],
    [/Desactiva UPnP WAN y limita discovery solo a la red local\./gi, 'Disable WAN UPnP and limit discovery to the local network.'],
    [/Deshabilita TFTP en Internet o migra a protocolo cifrado y autenticado\./gi, 'Disable internet-exposed TFTP or migrate to encrypted, authenticated protocols.'],
    [/Deshabilita servicios legacy y migra a alternativas cifradas \(SSH\/TLS\/VPN\)\./gi, 'Disable legacy services and migrate to encrypted alternatives (SSH/TLS/VPN).'],
    [/Limita administracion remota a VPN\/IPs permitidas y activa MFA cuando exista\./gi, 'Restrict remote administration to VPN/allowlisted IPs and enable MFA when available.'],
    [/Limita servicios UDP de gestion a VPN o listas de IP permitidas\./gi, 'Restrict UDP management services to VPN or IP allowlists.'],
    [/Desactiva admin WAN o protege con VPN y listas de acceso\./gi, 'Disable WAN admin or protect it with VPN and access allowlists.'],
    [/Renueva certificados, evita self-signed en produccion y revisa cadena TLS\./gi, 'Renew certificates, avoid self-signed certs in production, and validate TLS chain.'],
    [/Reduce la exposicion: cierra puertos no necesarios y segmenta servicios\./gi, 'Reduce exposure: close unnecessary ports and segment services.'],
    [/Correlaciona con firewall del objetivo y repite UDP con timeout mayor si es necesario\./gi, 'Correlate with target firewall behavior and repeat UDP with higher timeout when required.'],
    [/Mantener politica de minimo privilegio y repetir escaneo periodico\./gi, 'Maintain least-privilege policy and repeat scans periodically.'],
    [/Control remoto de contenedores y potencial ejecucion de codigo\./gi, 'Remote container control and potential code execution.'],
    [/Filtracion o manipulacion de datos ante credenciales debiles o fugadas\./gi, 'Potential data leakage or manipulation when credentials are weak or leaked.'],
    [/Posible fuga de informacion sensible de red y dispositivos\./gi, 'Possible leakage of sensitive network and device information.'],
    [/Riesgo de abuso para amplificacion o recursion no autorizada\./gi, 'Risk of abuse for amplification or unauthorized recursion.'],
    [/Mayor superficie para abuso de discovery\/amplificacion\./gi, 'Expanded surface for discovery/amplification abuse.'],
    [/Transferencias sin cifrado ni autenticacion robusta\./gi, 'Transfers without encryption or strong authentication.'],
    [/Riesgo alto de sniffing, bruteforce y explotacion de servicios antiguos\./gi, 'High risk of sniffing, brute-force and exploitation of legacy services.'],
    [/Mayor probabilidad de acceso no autorizado y ataques de fuerza bruta\./gi, 'Higher probability of unauthorized access and brute-force attacks.'],
    [/Aumento de superficie para ataque de servicios no orientados a Internet\./gi, 'Expanded attack surface for services not meant for internet exposure.'],
    [/Ataques de credenciales y explotacion de paneles de administracion\./gi, 'Credential attacks and exploitation of admin panels.'],
    [/Riesgo de MITM o advertencias que degradan seguridad operacional\./gi, 'MITM risk or warnings that degrade operational security.'],
    [/Incremento de superficie de ataque y probabilidad de compromiso\./gi, 'Increased attack surface and compromise probability.'],
    [/El comportamiento UDP puede ocultar servicios tras filtrado silencioso\./gi, 'UDP behavior can hide services behind silent filtering.'],
    [/Postura WAN reducida para los puertos analizados\./gi, 'Reduced WAN exposure posture for scanned ports.'],
]

function translateEsToEn(text: string): string {
    let out = text
    for (const [pattern, replacement] of ES_TO_EN_REPLACEMENTS) {
        out = out.replace(pattern, replacement)
    }
    return out.replace(/\s{2,}/g, ' ').trim()
}

function localizeFindingText(text: string, language: ProbeLanguage): string {
    if (language === 'es') return text
    return translateEsToEn(text)
}

function localizeFinding(finding: Finding, language: ProbeLanguage): Finding {
    if (language === 'es') return finding
    return {
        ...finding,
        title: localizeFindingText(finding.title, language),
        evidence: localizeFindingText(finding.evidence, language),
        recommendation: localizeFindingText(finding.recommendation, language),
        impact: localizeFindingText(finding.impact, language),
    }
}

function progressMessage(
    language: ProbeLanguage,
    key: 'queued' | 'prepare' | 'tcp-running' | 'tcp-progress' | 'udp-running' | 'udp-progress' | 'service-running' | 'service-progress' | 'analysis' | 'done',
    context: { done?: number; total?: number } = {},
): string {
    const done = context.done ?? 0
    const total = context.total ?? 0
    if (language === 'es') {
        if (key === 'queued') return 'Scan en cola'
        if (key === 'prepare') return 'Preparando escaneo WAN'
        if (key === 'tcp-running') return 'Escaneo TCP en progreso'
        if (key === 'tcp-progress') return `Escaneo TCP ${done}/${total}`
        if (key === 'udp-running') return 'Escaneo UDP en progreso'
        if (key === 'udp-progress') return `Escaneo UDP ${done}/${total}`
        if (key === 'service-running') return 'Analizando servicios detectados'
        if (key === 'service-progress') return `Fingerprint de servicios ${done}/${total}`
        if (key === 'analysis') return 'Correlacionando evidencias y riesgo'
        return 'Escaneo completado'
    }
    if (key === 'queued') return 'Scan queued'
    if (key === 'prepare') return 'Preparing WAN scan'
    if (key === 'tcp-running') return 'TCP sweep in progress'
    if (key === 'tcp-progress') return `TCP sweep ${done}/${total}`
    if (key === 'udp-running') return 'UDP sweep in progress'
    if (key === 'udp-progress') return `UDP sweep ${done}/${total}`
    if (key === 'service-running') return 'Analyzing discovered services'
    if (key === 'service-progress') return `Service fingerprinting ${done}/${total}`
    if (key === 'analysis') return 'Correlating evidence and risk'
    return 'Scan completed'
}

function buildFindings(results: PortScanResult[], language: ProbeLanguage): Finding[] {
    const findings: Finding[] = []
    const open = results.filter(r => r.state === 'open')
    const openTcp = open.filter(r => r.protocol === 'tcp')
    const openUdp = open.filter(r => r.protocol === 'udp')
    const ambiguousUdp = results.filter(r => r.protocol === 'udp' && r.state === 'filtered' && r.stateReason === 'open|filtered')

    const openPorts = Array.from(new Set(open.map(r => r.port))).sort((a, b) => a - b)
    const openTcpPorts = Array.from(new Set(openTcp.map(r => r.port))).sort((a, b) => a - b)
    const openUdpPorts = Array.from(new Set(openUdp.map(r => r.port))).sort((a, b) => a - b)

    const remoteAdmin = openTcp.filter(r => ADMIN_PORTS.has(r.port))
    const adminUi = openTcp.filter(r => r.http?.ok && r.http.adminLike)
    const legacy = open.filter(r => LEGACY_PORTS.has(r.port))
    const databases = openTcp.filter(r => DANGEROUS_DATABASE_PORTS.has(r.port))
    const tlsWeak = openTcp.filter(r => r.tls?.ok && (r.tls.expired || r.tls.selfSigned))
    const dockerNoTls = openTcp.filter(r => r.port === 2375)
    const udpAdmin = openUdp.filter(r => UDP_ADMIN_PORTS.has(r.port))
    const snmpUdp = openUdp.filter(r => r.port === 161 || r.port === 162)
    const dnsUdp = openUdp.filter(r => r.port === 53)
    const ssdpUdp = openUdp.filter(r => r.port === 1900)
    const tftpUdp = openUdp.filter(r => r.port === 69)

    if (dockerNoTls.length) {
        addFinding(findings, {
            id: 'docker-remote-api',
            severity: 'critical',
            category: 'remote-admin',
            title: 'Docker Remote API sin TLS expuesta',
            evidence: `Puerto 2375 abierto en ${summarizePorts(dockerNoTls.map(v => v.port), 1)}.`,
            recommendation: 'Deshabilita 2375 en WAN o fuerza TLS mutuo en 2376 con ACL estricta.',
            scope: 'wan',
            confidence: 0.96,
            impact: 'Control remoto de contenedores y potencial ejecucion de codigo.',
            ports: dockerNoTls.map(v => v.port),
        })
    }

    if (databases.length) {
        addFinding(findings, {
            id: 'database-exposure',
            severity: 'high',
            category: 'exposure',
            title: 'Servicios de base de datos visibles desde Internet',
            evidence: `Puertos detectados: ${summarizePorts(databases.map(v => v.port))}.`,
            recommendation: 'Restringe acceso por firewall y expone BD solo por VPN o red privada.',
            scope: 'wan',
            confidence: 0.92,
            impact: 'Filtracion o manipulacion de datos ante credenciales debiles o fugadas.',
            ports: databases.map(v => v.port),
        })
    }

    if (snmpUdp.length) {
        addFinding(findings, {
            id: 'snmp-udp-exposure',
            severity: 'high',
            category: 'exposure',
            title: 'SNMP expuesto por UDP en WAN',
            evidence: `SNMP detectado en: ${summarizePorts(snmpUdp.map(v => v.port))}.`,
            recommendation: 'Bloquea SNMP en WAN o limita por ACL estricta y credenciales robustas.',
            scope: 'wan',
            confidence: 0.84,
            impact: 'Posible fuga de informacion sensible de red y dispositivos.',
            ports: snmpUdp.map(v => v.port),
        })
    }

    if (dnsUdp.length) {
        addFinding(findings, {
            id: 'dns-udp-exposure',
            severity: 'medium',
            category: 'exposure',
            title: 'DNS UDP expuesto en WAN',
            evidence: `UDP/53 abierto en: ${summarizePorts(dnsUdp.map(v => v.port))}.`,
            recommendation: 'Restringe recursion y permite consultas solo desde rangos autorizados.',
            scope: 'wan',
            confidence: 0.82,
            impact: 'Riesgo de abuso para amplificacion o recursion no autorizada.',
            ports: dnsUdp.map(v => v.port),
        })
    }

    if (ssdpUdp.length) {
        addFinding(findings, {
            id: 'ssdp-udp-exposure',
            severity: 'medium',
            category: 'legacy-service',
            title: 'SSDP/UPnP visible por UDP en WAN',
            evidence: `UDP/1900 abierto en: ${summarizePorts(ssdpUdp.map(v => v.port))}.`,
            recommendation: 'Desactiva UPnP WAN y limita discovery solo a la red local.',
            scope: 'wan',
            confidence: 0.86,
            impact: 'Mayor superficie para abuso de discovery/amplificacion.',
            ports: ssdpUdp.map(v => v.port),
        })
    }

    if (tftpUdp.length) {
        addFinding(findings, {
            id: 'tftp-udp-exposure',
            severity: 'high',
            category: 'legacy-service',
            title: 'TFTP expuesto por UDP en WAN',
            evidence: `UDP/69 abierto en: ${summarizePorts(tftpUdp.map(v => v.port))}.`,
            recommendation: 'Deshabilita TFTP en Internet o migra a protocolo cifrado y autenticado.',
            scope: 'wan',
            confidence: 0.9,
            impact: 'Transferencias sin cifrado ni autenticacion robusta.',
            ports: tftpUdp.map(v => v.port),
        })
    }

    if (legacy.length) {
        addFinding(findings, {
            id: 'legacy-protocols',
            severity: 'high',
            category: 'legacy-service',
            title: 'Protocolos legacy/inseguros expuestos',
            evidence: `Puertos legacy abiertos: ${summarizePorts(legacy.map(v => v.port))}.`,
            recommendation: 'Deshabilita servicios legacy y migra a alternativas cifradas (SSH/TLS/VPN).',
            scope: 'wan',
            confidence: 0.88,
            impact: 'Riesgo alto de sniffing, bruteforce y explotacion de servicios antiguos.',
            ports: legacy.map(v => v.port),
        })
    }

    if (remoteAdmin.length) {
        addFinding(findings, {
            id: 'remote-admin-surface',
            severity: adminUi.length ? 'high' : 'medium',
            category: 'remote-admin',
            title: 'Superficie de administracion remota visible',
            evidence: `Puertos administrativos abiertos: ${summarizePorts(remoteAdmin.map(v => v.port))}.`,
            recommendation: 'Limita administracion remota a VPN/IPs permitidas y activa MFA cuando exista.',
            scope: 'wan',
            confidence: 0.86,
            impact: 'Mayor probabilidad de acceso no autorizado y ataques de fuerza bruta.',
            ports: remoteAdmin.map(v => v.port),
        })
    }

    if (udpAdmin.length) {
        addFinding(findings, {
            id: 'udp-admin-surface',
            severity: 'medium',
            category: 'remote-admin',
            title: 'Superficie UDP administrativa visible',
            evidence: `Servicios UDP sensibles abiertos: ${summarizePorts(udpAdmin.map(v => v.port))}.`,
            recommendation: 'Limita servicios UDP de gestion a VPN o listas de IP permitidas.',
            scope: 'wan',
            confidence: 0.78,
            impact: 'Aumento de superficie para ataque de servicios no orientados a Internet.',
            ports: udpAdmin.map(v => v.port),
        })
    }

    if (adminUi.length) {
        addFinding(findings, {
            id: 'admin-web-ui-exposed',
            severity: 'high',
            category: 'remote-admin',
            title: 'Interfaz web de administracion detectada en WAN',
            evidence: `Admin/login identificado en puertos: ${summarizePorts(adminUi.map(v => v.port))}.`,
            recommendation: 'Desactiva admin WAN o protege con VPN y listas de acceso.',
            scope: 'wan',
            confidence: 0.9,
            impact: 'Ataques de credenciales y explotacion de paneles de administracion.',
            ports: adminUi.map(v => v.port),
        })
    }

    if (tlsWeak.length) {
        addFinding(findings, {
            id: 'tls-hygiene',
            severity: 'medium',
            category: 'crypto',
            title: 'Configuracion TLS debil o certificado no confiable',
            evidence: `Servicios con cert auto-firmado/expirado en: ${summarizePorts(tlsWeak.map(v => v.port))}.`,
            recommendation: 'Renueva certificados, evita self-signed en produccion y revisa cadena TLS.',
            scope: 'wan',
            confidence: 0.83,
            impact: 'Riesgo de MITM o advertencias que degradan seguridad operacional.',
            ports: tlsWeak.map(v => v.port),
        })
    }

    if (openPorts.length > 20 || openTcpPorts.length > 15 || openUdpPorts.length > 12) {
        addFinding(findings, {
            id: 'large-exposure-surface',
            severity: 'medium',
            category: 'exposure',
            title: 'Superficie WAN extensa',
            evidence: `${openPorts.length} puertos abiertos detectados (TCP: ${openTcpPorts.length}, UDP: ${openUdpPorts.length}).`,
            recommendation: 'Reduce la exposicion: cierra puertos no necesarios y segmenta servicios.',
            scope: 'wan',
            confidence: 0.8,
            impact: 'Incremento de superficie de ataque y probabilidad de compromiso.',
            ports: openPorts,
        })
    }

    if (ambiguousUdp.length >= 8) {
        addFinding(findings, {
            id: 'udp-ambiguous-surface',
            severity: 'info',
            category: 'hardening',
            title: 'Varios puertos UDP quedaron en estado indeterminado',
            evidence: `${ambiguousUdp.length} puertos UDP sin respuesta (open|filtered).`,
            recommendation: 'Correlaciona con firewall del objetivo y repite UDP con timeout mayor si es necesario.',
            scope: 'wan',
            confidence: 0.7,
            impact: 'El comportamiento UDP puede ocultar servicios tras filtrado silencioso.',
            ports: Array.from(new Set(ambiguousUdp.map(v => v.port))).sort((a, b) => a - b),
        })
    }

    if (!openPorts.length) {
        addFinding(findings, {
            id: 'no-open-ports',
            severity: 'info',
            category: 'hardening',
            title: 'No se detectaron puertos abiertos en el set escaneado',
            evidence: 'Todos los puertos del escaneo respondieron como cerrados o filtrados.',
            recommendation: 'Mantener politica de minimo privilegio y repetir escaneo periodico.',
            scope: 'wan',
            confidence: 0.78,
            impact: 'Postura WAN reducida para los puertos analizados.',
            ports: [],
        })
    }

    return findings.map(finding => localizeFinding(finding, language))
}

function computeRiskScore(findings: Finding[], openCount: number): number {
    let score = 0
    for (const finding of findings) {
        if (finding.severity === 'critical') score += 25
        else if (finding.severity === 'high') score += 14
        else if (finding.severity === 'medium') score += 8
        else if (finding.severity === 'low') score += 4
        else score += 1
    }
    score += Math.min(20, openCount * 1.5)
    return clamp(Math.round(score), 0, 100)
}

function computeConfidenceScore(
    mode: ScanMode,
    profile: ScanProfile,
    transport: ScanTransport,
    tcpRetries: number,
    tcpTimeoutMs: number,
    udpRetries: number,
    udpTimeoutMs: number,
    results: PortScanResult[],
): number {
    const tcpResults = results.filter(r => r.protocol === 'tcp')
    const udpResults = results.filter(r => r.protocol === 'udp')
    const total = Math.max(1, tcpResults.length + udpResults.length)

    const openTcp = tcpResults.filter(r => r.state === 'open')
    const openWithProbe = openTcp.filter(r => {
        return Boolean((r.http && r.http.ok) || (r.tls && r.tls.ok) || (r.banner && r.banner.ok))
    }).length
    const udpAmbiguous = udpResults.filter(r => r.state === 'filtered' && r.stateReason === 'open|filtered').length

    const modeBoost = mode === 'deep' ? 8 : mode === 'advanced' ? 5 : 2
    const profileBoost = profile === 'safe' ? 2 : profile === 'aggressive' ? 1 : 0
    const tcpRetryFactor = clamp(tcpRetries / 3, 0.33, 1)
    const tcpTimeoutFactor = clamp(tcpTimeoutMs / 3000, 0.25, 1)
    const udpRetryFactor = udpResults.length ? clamp(udpRetries / 3, 0.33, 1) : 1
    const udpTimeoutFactor = udpResults.length ? clamp(udpTimeoutMs / 4000, 0.2, 1) : 1
    const probeCoverage = openTcp.length ? openWithProbe / openTcp.length : 1
    const coverage = (tcpResults.length + udpResults.length) / total
    const udpDeterministicFactor = udpResults.length ? clamp((udpResults.length - udpAmbiguous) / udpResults.length, 0.25, 1) : 1
    const transportBoost = transport === 'both' ? 6 : transport === 'udp' ? 3 : 1

    const score = (
        45
        + modeBoost
        + profileBoost
        + transportBoost
        + coverage * 10
        + probeCoverage * 25
        + tcpRetryFactor * 6
        + tcpTimeoutFactor * 6
        + udpRetryFactor * 4
        + udpTimeoutFactor * 3
        + udpDeterministicFactor * 6
    )

    return clamp(Math.round(score), 1, 99)
}

export async function performWanScan(input: PerformWanScanInput): Promise<WanScanResult> {
    const { mode, profile, transport, target, observedIp, tcpPorts, udpPorts, cfg, onProgress } = input
    const language: ProbeLanguage = 'en'
    const includeTcp = transport === 'tcp' || transport === 'both'
    const includeUdp = transport === 'udp' || transport === 'both'
    const tcpRuntime = runtimeForModeTransport(mode, profile, 'tcp', cfg)
    const udpRuntime = runtimeForModeTransport(mode, profile, 'udp', cfg)
    const tcpRetries = retriesForModeTransport(mode, profile, 'tcp', cfg)
    const udpRetries = retriesForModeTransport(mode, profile, 'udp', cfg)
    const startedAt = new Date()
    const normalizedTcpPorts = Array.from(new Set(tcpPorts))
        .filter(p => Number.isInteger(p) && p >= 1 && p <= 65535)
        .sort((a, b) => a - b)
    const normalizedUdpPorts = Array.from(new Set(udpPorts))
        .filter(p => Number.isInteger(p) && p >= 1 && p <= 65535)
        .sort((a, b) => a - b)
    const plannedPorts = Array.from(new Set([...normalizedTcpPorts, ...normalizedUdpPorts]))
        .sort((a, b) => a - b)
    const totalPorts = normalizedTcpPorts.length + normalizedUdpPorts.length

    const progressBudget = {
        tcp: includeTcp ? (includeUdp ? 55 : 70) : 0,
        udp: includeUdp ? (includeTcp ? 20 : 70) : 0,
        service: includeTcp ? 20 : 0,
    }
    const startPercent = 2
    const percentBeforeService = startPercent + progressBudget.tcp + progressBudget.udp

    const progress: ScanProgress = {
        phase: 'queued',
        message: progressMessage(language, 'queued'),
        language,
        transport,
        totalPorts,
        scannedPorts: 0,
        openPorts: 0,
        closedPorts: 0,
        filteredPorts: 0,
        totalTcpPorts: normalizedTcpPorts.length,
        totalUdpPorts: normalizedUdpPorts.length,
        scannedTcpPorts: 0,
        scannedUdpPorts: 0,
        openTcpPorts: 0,
        closedTcpPorts: 0,
        filteredTcpPorts: 0,
        openUdpPorts: 0,
        closedUdpPorts: 0,
        filteredUdpPorts: 0,
        servicePortsScanned: 0,
        percent: 0,
        startedAt: startedAt.toISOString(),
        updatedAt: startedAt.toISOString(),
    }

    const emitProgress = (phase: ScanPhase, message: string, updates?: Partial<ScanProgress>) => {
        progress.phase = phase
        progress.message = message
        if (updates) {
            if (typeof updates.scannedPorts === 'number') progress.scannedPorts = updates.scannedPorts
            if (typeof updates.openPorts === 'number') progress.openPorts = updates.openPorts
            if (typeof updates.closedPorts === 'number') progress.closedPorts = updates.closedPorts
            if (typeof updates.filteredPorts === 'number') progress.filteredPorts = updates.filteredPorts
            if (typeof updates.scannedTcpPorts === 'number') progress.scannedTcpPorts = updates.scannedTcpPorts
            if (typeof updates.scannedUdpPorts === 'number') progress.scannedUdpPorts = updates.scannedUdpPorts
            if (typeof updates.openTcpPorts === 'number') progress.openTcpPorts = updates.openTcpPorts
            if (typeof updates.closedTcpPorts === 'number') progress.closedTcpPorts = updates.closedTcpPorts
            if (typeof updates.filteredTcpPorts === 'number') progress.filteredTcpPorts = updates.filteredTcpPorts
            if (typeof updates.openUdpPorts === 'number') progress.openUdpPorts = updates.openUdpPorts
            if (typeof updates.closedUdpPorts === 'number') progress.closedUdpPorts = updates.closedUdpPorts
            if (typeof updates.filteredUdpPorts === 'number') progress.filteredUdpPorts = updates.filteredUdpPorts
            if (typeof updates.servicePortsScanned === 'number') progress.servicePortsScanned = updates.servicePortsScanned
            if (typeof updates.percent === 'number') progress.percent = clamp(Math.round(updates.percent), 0, 100)
        }
        progress.updatedAt = new Date().toISOString()
        onProgress?.({ ...progress })
    }

    emitProgress('queued', progressMessage(language, 'prepare'), { percent: 1 })

    let scannedPorts = 0
    let openPorts = 0
    let closedPorts = 0
    let filteredPorts = 0
    let scannedTcpPorts = 0
    let scannedUdpPorts = 0
    let openTcpPorts = 0
    let closedTcpPorts = 0
    let filteredTcpPorts = 0
    let openUdpPorts = 0
    let closedUdpPorts = 0
    let filteredUdpPorts = 0

    let tcpResults: PortScanResult[] = []
    if (includeTcp && normalizedTcpPorts.length) {
        emitProgress('tcp_sweep', progressMessage(language, 'tcp-running'), { percent: startPercent })
        tcpResults = await runWithConcurrency(normalizedTcpPorts, tcpRuntime.concurrency, async port => {
            const result = await probeTcpPort(target, port, tcpRetries, tcpRuntime.timeoutMs)
            scannedPorts += 1
            scannedTcpPorts += 1
            if (result.state === 'open') {
                openPorts += 1
                openTcpPorts += 1
            } else if (result.state === 'closed') {
                closedPorts += 1
                closedTcpPorts += 1
            } else {
                filteredPorts += 1
                filteredTcpPorts += 1
            }

            const percent = normalizedTcpPorts.length
                ? startPercent + ((scannedTcpPorts / normalizedTcpPorts.length) * progressBudget.tcp)
                : startPercent + progressBudget.tcp

            emitProgress('tcp_sweep', progressMessage(language, 'tcp-progress', { done: scannedTcpPorts, total: normalizedTcpPorts.length }), {
                scannedPorts,
                openPorts,
                closedPorts,
                filteredPorts,
                scannedTcpPorts,
                scannedUdpPorts,
                openTcpPorts,
                closedTcpPorts,
                filteredTcpPorts,
                openUdpPorts,
                closedUdpPorts,
                filteredUdpPorts,
                percent,
            })

            return result
        })
    }

    let udpResults: PortScanResult[] = []
    if (includeUdp && normalizedUdpPorts.length) {
        emitProgress('udp_sweep', progressMessage(language, 'udp-running'), {
            percent: startPercent + progressBudget.tcp,
        })
        udpResults = await runWithConcurrency(normalizedUdpPorts, udpRuntime.concurrency, async port => {
            const result = await probeUdpPort(target, port, udpRetries, udpRuntime.timeoutMs)
            scannedPorts += 1
            scannedUdpPorts += 1
            if (result.state === 'open') {
                openPorts += 1
                openUdpPorts += 1
            } else if (result.state === 'closed') {
                closedPorts += 1
                closedUdpPorts += 1
            } else {
                filteredPorts += 1
                filteredUdpPorts += 1
            }

            const percent = normalizedUdpPorts.length
                ? startPercent + progressBudget.tcp + ((scannedUdpPorts / normalizedUdpPorts.length) * progressBudget.udp)
                : startPercent + progressBudget.tcp + progressBudget.udp

            emitProgress('udp_sweep', progressMessage(language, 'udp-progress', { done: scannedUdpPorts, total: normalizedUdpPorts.length }), {
                scannedPorts,
                openPorts,
                closedPorts,
                filteredPorts,
                scannedTcpPorts,
                scannedUdpPorts,
                openTcpPorts,
                closedTcpPorts,
                filteredTcpPorts,
                openUdpPorts,
                closedUdpPorts,
                filteredUdpPorts,
                percent,
            })

            return result
        })
    }

    const openTcpResults = tcpResults.filter(r => r.state === 'open')
    const serviceProbeEnabled = includeTcp && (cfg.enableHttpProbe || cfg.enableTlsProbe || cfg.enableBannerProbe)
    let servicePortsScanned = 0

    if (serviceProbeEnabled && openTcpResults.length) {
        emitProgress('service_probe', progressMessage(language, 'service-running'), {
            percent: percentBeforeService,
            servicePortsScanned: 0,
        })

        const serviceConcurrency = clamp(Math.floor(tcpRuntime.concurrency / 2), 1, 48)
        await runWithConcurrency(openTcpResults, serviceConcurrency, async result => {
            const serviceTimeout = clamp(Math.floor(tcpRuntime.timeoutMs * 1.2), 900, 7000)
            if (cfg.enableHttpProbe && shouldHttpProbe(result)) {
                result.http = await runHttpProbe(target, result.port, serviceTimeout)
            }
            if (cfg.enableTlsProbe && shouldTlsProbe(result)) {
                result.tls = await runTlsProbe(target, result.port, serviceTimeout)
            }
            if (cfg.enableBannerProbe) {
                result.banner = await runBannerProbe(target, result.port, Math.min(serviceTimeout, 2500))
            }

            servicePortsScanned += 1
            const percent = percentBeforeService + ((servicePortsScanned / openTcpResults.length) * progressBudget.service)
            emitProgress('service_probe', progressMessage(language, 'service-progress', { done: servicePortsScanned, total: openTcpResults.length }), {
                scannedPorts,
                openPorts,
                closedPorts,
                filteredPorts,
                scannedTcpPorts,
                scannedUdpPorts,
                openTcpPorts,
                closedTcpPorts,
                filteredTcpPorts,
                openUdpPorts,
                closedUdpPorts,
                filteredUdpPorts,
                servicePortsScanned,
                percent,
            })
            return result
        })
    }

    emitProgress('analysis', progressMessage(language, 'analysis'), { percent: 92 })
    const allResults = [...tcpResults, ...udpResults]
        .sort((a, b) => (a.port - b.port) || a.protocol.localeCompare(b.protocol))
    const findings = buildFindings(allResults, language)
    const riskScore = computeRiskScore(findings, openPorts)
    const confidenceScore = computeConfidenceScore(
        mode,
        profile,
        transport,
        tcpRetries,
        tcpRuntime.timeoutMs,
        udpRetries,
        udpRuntime.timeoutMs,
        allResults,
    )

    const finishedAt = new Date()
    const result: WanScanResult = {
        mode,
        profile,
        transport,
        language,
        target,
        observedIp,
        startedAt: startedAt.toISOString(),
        finishedAt: finishedAt.toISOString(),
        durationMs: Math.max(1, finishedAt.getTime() - startedAt.getTime()),
        ports: plannedPorts,
        tcpPorts: normalizedTcpPorts,
        udpPorts: normalizedUdpPorts,
        openCount: openPorts,
        closedCount: closedPorts,
        filteredCount: filteredPorts,
        openTcpCount: openTcpPorts,
        closedTcpCount: closedTcpPorts,
        filteredTcpCount: filteredTcpPorts,
        openUdpCount: openUdpPorts,
        closedUdpCount: closedUdpPorts,
        filteredUdpCount: filteredUdpPorts,
        results: allResults,
        findings,
        riskScore,
        confidenceScore,
        scanMeta: {
            transport,
            timeoutMs: Math.max(tcpRuntime.timeoutMs, udpRuntime.timeoutMs),
            retries: Math.max(tcpRetries, udpRetries),
            concurrency: Math.max(tcpRuntime.concurrency, udpRuntime.concurrency),
            tcp: {
                timeoutMs: tcpRuntime.timeoutMs,
                retries: tcpRetries,
                concurrency: tcpRuntime.concurrency,
            },
            udp: {
                timeoutMs: udpRuntime.timeoutMs,
                retries: udpRetries,
                concurrency: udpRuntime.concurrency,
            },
            httpProbe: cfg.enableHttpProbe,
            tlsProbe: cfg.enableTlsProbe,
            bannerProbe: cfg.enableBannerProbe,
        },
    }

    emitProgress('done', progressMessage(language, 'done'), {
        percent: 100,
        scannedPorts,
        openPorts,
        closedPorts,
        filteredPorts,
        scannedTcpPorts,
        scannedUdpPorts,
        openTcpPorts,
        closedTcpPorts,
        filteredTcpPorts,
        openUdpPorts,
        closedUdpPorts,
        filteredUdpPorts,
        servicePortsScanned,
    })

    return result
}
