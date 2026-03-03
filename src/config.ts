import type { ScanMode, ScanProfile, ScanTransport } from './types'

function toInt(value: string | undefined, fallback: number) {
    if (!value) return fallback
    const n = Number.parseInt(value, 10)
    return Number.isFinite(n) ? n : fallback
}

function toBool(value: string | undefined, fallback: boolean) {
    if (!value) return fallback
    const s = value.trim().toLowerCase()
    if (['1', 'true', 'yes', 'on'].includes(s)) return true
    if (['0', 'false', 'no', 'off'].includes(s)) return false
    return fallback
}

function parseTransport(raw: string | undefined, fallback: ScanTransport): ScanTransport {
    const value = String(raw || '').trim().toLowerCase()
    if (value === 'tcp' || value === 'udp' || value === 'both' || value === 'auto') return value
    return fallback
}

function parsePortList(raw: string | undefined, fallback: number[]) {
    if (!raw) return [...fallback]
    const ports = raw
        .split(',')
        .map(s => Number.parseInt(s.trim(), 10))
        .filter(p => Number.isInteger(p) && p >= 1 && p <= 65535)
    return Array.from(new Set(ports)).sort((a, b) => a - b)
}

function parseOptionalPortList(raw: string | undefined): number[] | null {
    if (!raw || !raw.trim()) return null
    const ports = raw
        .split(',')
        .map(s => Number.parseInt(s.trim(), 10))
        .filter(p => Number.isInteger(p) && p >= 1 && p <= 65535)
    const unique = Array.from(new Set(ports)).sort((a, b) => a - b)
    return unique.length ? unique : null
}

function parseProfile(raw: string | undefined): ScanProfile {
    const value = String(raw || '').trim().toLowerCase()
    if (value === 'safe' || value === 'aggressive' || value === 'balanced') return value
    return 'balanced'
}

function buildDeepPortsDefault(): number[] {
    const set = new Set<number>()
    for (let p = 1; p <= 2048; p++) set.add(p)

    const highValue = [
        1080, 1194, 1433, 1434, 1521, 1720, 1901, 2000, 2049, 2375, 2376, 25565,
        3000, 3128, 3306, 3389, 4000, 4443, 4444, 4567, 5000, 5001, 5060, 5061,
        5351, 5432, 5900, 5985, 5986, 6379, 6443, 7001, 7002, 7080, 7443, 7547,
        7681, 7777, 8000, 8008, 8010, 8080, 8081, 8088, 8090, 8443, 8888, 9000,
        9090, 9200, 9443, 10000, 11211, 15672, 27017, 49152, 49153, 49154, 49155,
    ]
    for (const p of highValue) set.add(p)
    return [...set].sort((a, b) => a - b)
}

function buildDeepUdpPortsDefault(): number[] {
    const set = new Set<number>()
    for (let p = 1; p <= 1024; p++) set.add(p)
    const highValue = [
        1194, 1434, 1701, 1812, 1900, 3478, 3702, 4500, 5004, 5060, 5061, 5349,
        5351, 5353, 5683, 10000, 17185, 27015, 3074, 33434,
    ]
    for (const p of highValue) set.add(p)
    return [...set].sort((a, b) => a - b)
}

export const QUICK_PORTS_DEFAULT = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 81, 88, 110, 123, 135, 137, 138, 139,
    143, 389, 443, 445, 465, 587, 993, 995, 1080, 1723, 1900, 5000, 5351, 554,
    7547, 8080, 8081, 8443, 8888, 9000, 10000, 32764,
]

export const ADVANCED_PORTS_DEFAULT = [
    1, 7, 9, 13, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 49, 53, 67, 68, 69,
    70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111,
    113, 119, 123, 135, 137, 138, 139, 143, 161, 162, 179, 389, 427, 443, 444,
    445, 465, 500, 502, 512, 513, 514, 515, 548, 554, 587, 631, 636, 646, 873,
    902, 989, 990, 993, 995, 1025, 1026, 1080, 1099, 1110, 1194, 1352, 1433,
    1434, 1521, 1720, 1723, 1812, 1900, 1935, 2000, 2049, 2082, 2083, 2086,
    2087, 2375, 2376, 2483, 2484, 25565, 3000, 3128, 3268, 3306, 3389, 4000,
    4443, 4444, 4567, 5000, 5001, 5060, 5061, 5351, 5432, 5601, 5631, 5632,
    5900, 5985, 5986, 6379, 6443, 6667, 7001, 7002, 7080, 7443, 7547, 7681,
    7777, 8000, 8008, 8010, 8080, 8081, 8088, 8090, 8443, 8888, 9000, 9090,
    9200, 9443, 10000, 11211, 15672, 27017, 32764, 49152, 49153, 49154,
]

export const DEEP_PORTS_DEFAULT = buildDeepPortsDefault()

export const QUICK_UDP_PORTS_DEFAULT = [
    53, 67, 68, 69, 123, 137, 138, 161, 500, 514, 1194, 1434, 1701, 1812, 1900,
    4500, 5004, 5060, 5351,
]

export const ADVANCED_UDP_PORTS_DEFAULT = [
    19, 53, 67, 68, 69, 111, 123, 137, 138, 161, 162, 389, 427, 500, 514, 520,
    623, 631, 1194, 1434, 1701, 1812, 1900, 2049, 3478, 3702, 4500, 5004, 5060,
    5061, 5351, 5353, 5683, 10000, 17185, 27015, 33434,
]

export const DEEP_UDP_PORTS_DEFAULT = buildDeepUdpPortsDefault()

export const SERVICE_NAMES: Record<number, string> = {
    19: 'chargen',
    20: 'ftp-data',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'dns',
    67: 'dhcp-server',
    68: 'dhcp-client',
    69: 'tftp',
    80: 'http',
    88: 'kerberos',
    110: 'pop3',
    111: 'rpcbind',
    123: 'ntp',
    135: 'msrpc',
    137: 'netbios-ns',
    138: 'netbios-dgm',
    139: 'netbios-ssn',
    143: 'imap',
    161: 'snmp',
    162: 'snmp-trap',
    179: 'bgp',
    389: 'ldap',
    427: 'svrloc',
    443: 'https',
    445: 'smb',
    465: 'smtps',
    500: 'isakmp',
    514: 'syslog',
    520: 'rip',
    587: 'smtp-submission',
    623: 'ipmi',
    631: 'ipp',
    636: 'ldaps',
    873: 'rsync',
    902: 'vmware-auth',
    989: 'ftps-data',
    990: 'ftps',
    993: 'imaps',
    995: 'pop3s',
    1080: 'socks',
    1194: 'openvpn',
    1433: 'mssql',
    1434: 'mssql-browser',
    1521: 'oracle-tns',
    1701: 'l2tp',
    1723: 'pptp',
    1812: 'radius',
    1900: 'ssdp',
    1935: 'rtmp',
    2049: 'nfs',
    2375: 'docker',
    2376: 'docker-tls',
    3000: 'http-dev',
    3074: 'xbox-live',
    3128: 'squid',
    3306: 'mysql',
    3389: 'rdp',
    3478: 'stun',
    3702: 'ws-discovery',
    4443: 'https-alt-2',
    4444: 'metasploit',
    4500: 'ipsec-nat-t',
    5000: 'upnp-http',
    5001: 'http-alt-5001',
    5004: 'rtp',
    5060: 'sip',
    5061: 'sips',
    5349: 'turns',
    5351: 'nat-pmp',
    5353: 'mdns',
    5432: 'postgresql',
    5683: 'coap',
    5900: 'vnc',
    5985: 'winrm-http',
    5986: 'winrm-https',
    6379: 'redis',
    6443: 'k8s-api',
    7001: 'weblogic',
    7080: 'http-alt-7080',
    7547: 'tr-069',
    7681: 'pando-p2p',
    8000: 'http-alt-8000',
    8080: 'http-alt',
    8081: 'http-alt-8081',
    8443: 'https-alt',
    8888: 'http-proxy',
    9000: 'http-alt-9000',
    9090: 'prometheus',
    9200: 'elasticsearch',
    9443: 'https-alt-9443',
    10000: 'webmin',
    11211: 'memcached',
    15672: 'rabbitmq-admin',
    17185: 'wdm',
    25565: 'minecraft',
    27015: 'steam',
    27017: 'mongodb',
    32764: 'router-backdoor',
    33434: 'traceroute',
}

export interface ScanRuntimeConfig {
    timeoutMs: number
    retries: number
    concurrency: number
}

export interface ProbeConfig {
    appName: string
    host: string
    port: number
    logLevel: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace'
    trustProxy: boolean
    apiKey: string
    publicUrl: string | null
    allowExternalTarget: boolean
    requirePublicTarget: boolean
    profileDefault: ScanProfile
    scanTransportDefault: ScanTransport
    requestTimeoutMs: number
    quickRetries: number
    advancedRetries: number
    deepRetries: number
    quickUdpRetries: number
    advancedUdpRetries: number
    deepUdpRetries: number
    scanConcurrency: number
    udpScanConcurrency: number
    quickConcurrency: number
    advancedConcurrency: number
    deepConcurrency: number
    quickUdpConcurrency: number
    advancedUdpConcurrency: number
    deepUdpConcurrency: number
    quickTimeoutMs: number
    advancedTimeoutMs: number
    deepTimeoutMs: number
    quickUdpTimeoutMs: number
    advancedUdpTimeoutMs: number
    deepUdpTimeoutMs: number
    maxCustomPorts: number
    maxCustomUdpPorts: number
    jobTtlMinutes: number
    rateLimitMax: number
    rateLimitTimeWindow: string
    quickPorts: number[]
    advancedPorts: number[]
    deepPorts: number[]
    quickUdpPorts: number[]
    advancedUdpPorts: number[]
    deepUdpPorts: number[]
    allowedPorts: number[] | null
    enforceAllowedPorts: boolean
    enableUdpScan: boolean
    enableHttpProbe: boolean
    enableTlsProbe: boolean
    enableBannerProbe: boolean
    nodeId: string | null
    nodeLabel: string | null
    nodeProvider: string | null
    nodeRegion: string | null
    nodeCity: string | null
    nodeCountry: string | null
    nodeAsn: string | null
}

export function loadConfig(): ProbeConfig {
    const quickPorts = parsePortList(process.env.PROBE_QUICK_PORTS, QUICK_PORTS_DEFAULT)
    const advancedPorts = parsePortList(process.env.PROBE_ADVANCED_PORTS, ADVANCED_PORTS_DEFAULT)
    const deepPorts = parsePortList(process.env.PROBE_DEEP_PORTS, DEEP_PORTS_DEFAULT)
    const quickUdpPorts = parsePortList(process.env.PROBE_QUICK_UDP_PORTS, QUICK_UDP_PORTS_DEFAULT)
    const advancedUdpPorts = parsePortList(process.env.PROBE_ADVANCED_UDP_PORTS, ADVANCED_UDP_PORTS_DEFAULT)
    const deepUdpPorts = parsePortList(process.env.PROBE_DEEP_UDP_PORTS, DEEP_UDP_PORTS_DEFAULT)
    const allowedPorts = parseOptionalPortList(process.env.PROBE_ALLOWED_PORTS)

    const cfg: ProbeConfig = {
        appName: process.env.PROBE_APP_NAME?.trim() || 'NetDuo WAN Probe',
        host: process.env.PROBE_HOST?.trim() || '0.0.0.0',
        port: toInt(process.env.PROBE_PORT || process.env.PORT || process.env.SERVER_PORT, 9443),
        logLevel: (process.env.PROBE_LOG_LEVEL as ProbeConfig['logLevel']) || 'info',
        trustProxy: toBool(process.env.PROBE_TRUST_PROXY, true),
        apiKey: process.env.PROBE_API_KEY?.trim() || 'change-me',
        publicUrl: process.env.PROBE_PUBLIC_URL?.trim() || null,
        allowExternalTarget: toBool(process.env.PROBE_ALLOW_EXTERNAL_TARGET, true),
        requirePublicTarget: toBool(process.env.PROBE_REQUIRE_PUBLIC_TARGET, true),
        profileDefault: parseProfile(process.env.PROBE_PROFILE_DEFAULT),
        scanTransportDefault: parseTransport(process.env.PROBE_SCAN_TRANSPORT_DEFAULT, 'tcp'),
        requestTimeoutMs: toInt(process.env.PROBE_REQUEST_TIMEOUT_MS, 2500),
        quickRetries: toInt(process.env.PROBE_QUICK_RETRIES, 1),
        advancedRetries: toInt(process.env.PROBE_ADVANCED_RETRIES, 2),
        deepRetries: toInt(process.env.PROBE_DEEP_RETRIES, 2),
        quickUdpRetries: toInt(process.env.PROBE_QUICK_UDP_RETRIES, 2),
        advancedUdpRetries: toInt(process.env.PROBE_ADVANCED_UDP_RETRIES, 2),
        deepUdpRetries: toInt(process.env.PROBE_DEEP_UDP_RETRIES, 3),
        scanConcurrency: toInt(process.env.PROBE_SCAN_CONCURRENCY, 96),
        udpScanConcurrency: toInt(process.env.PROBE_UDP_SCAN_CONCURRENCY, 48),
        quickConcurrency: toInt(process.env.PROBE_QUICK_CONCURRENCY, 64),
        advancedConcurrency: toInt(process.env.PROBE_ADVANCED_CONCURRENCY, 128),
        deepConcurrency: toInt(process.env.PROBE_DEEP_CONCURRENCY, 192),
        quickUdpConcurrency: toInt(process.env.PROBE_QUICK_UDP_CONCURRENCY, 24),
        advancedUdpConcurrency: toInt(process.env.PROBE_ADVANCED_UDP_CONCURRENCY, 36),
        deepUdpConcurrency: toInt(process.env.PROBE_DEEP_UDP_CONCURRENCY, 56),
        quickTimeoutMs: toInt(process.env.PROBE_QUICK_TIMEOUT_MS, 2200),
        advancedTimeoutMs: toInt(process.env.PROBE_ADVANCED_TIMEOUT_MS, 2600),
        deepTimeoutMs: toInt(process.env.PROBE_DEEP_TIMEOUT_MS, 3000),
        quickUdpTimeoutMs: toInt(process.env.PROBE_QUICK_UDP_TIMEOUT_MS, 2600),
        advancedUdpTimeoutMs: toInt(process.env.PROBE_ADVANCED_UDP_TIMEOUT_MS, 3200),
        deepUdpTimeoutMs: toInt(process.env.PROBE_DEEP_UDP_TIMEOUT_MS, 4200),
        maxCustomPorts: toInt(process.env.PROBE_MAX_CUSTOM_PORTS, 2048),
        maxCustomUdpPorts: toInt(process.env.PROBE_MAX_CUSTOM_UDP_PORTS, 2048),
        jobTtlMinutes: toInt(process.env.PROBE_JOB_TTL_MINUTES, 45),
        rateLimitMax: toInt(process.env.PROBE_RATE_LIMIT_MAX, 120),
        rateLimitTimeWindow: process.env.PROBE_RATE_LIMIT_WINDOW || '1 minute',
        quickPorts,
        advancedPorts,
        deepPorts,
        quickUdpPorts,
        advancedUdpPorts,
        deepUdpPorts,
        allowedPorts,
        enforceAllowedPorts: toBool(process.env.PROBE_ENFORCE_ALLOWED_PORTS, false),
        enableUdpScan: toBool(process.env.PROBE_ENABLE_UDP_SCAN, true),
        enableHttpProbe: toBool(process.env.PROBE_ENABLE_HTTP_PROBE, true),
        enableTlsProbe: toBool(process.env.PROBE_ENABLE_TLS_PROBE, true),
        enableBannerProbe: toBool(process.env.PROBE_ENABLE_BANNER_PROBE, true),
        nodeId: process.env.PROBE_NODE_ID?.trim() || null,
        nodeLabel: process.env.PROBE_NODE_LABEL?.trim() || null,
        nodeProvider: process.env.PROBE_NODE_PROVIDER?.trim() || null,
        nodeRegion: process.env.PROBE_NODE_REGION?.trim() || null,
        nodeCity: process.env.PROBE_NODE_CITY?.trim() || null,
        nodeCountry: process.env.PROBE_NODE_COUNTRY?.trim() || null,
        nodeAsn: process.env.PROBE_NODE_ASN?.trim() || null,
    }

    if (cfg.port < 1 || cfg.port > 65535) {
        throw new Error('PROBE_PORT must be between 1 and 65535')
    }
    if (cfg.maxCustomPorts < 1 || cfg.maxCustomPorts > 65535) {
        throw new Error('PROBE_MAX_CUSTOM_PORTS must be between 1 and 65535')
    }
    if (cfg.maxCustomUdpPorts < 1 || cfg.maxCustomUdpPorts > 65535) {
        throw new Error('PROBE_MAX_CUSTOM_UDP_PORTS must be between 1 and 65535')
    }

    return cfg
}

function modeBaseRuntime(mode: ScanMode, transport: 'tcp' | 'udp', cfg: ProbeConfig): ScanRuntimeConfig {
    if (transport === 'udp') {
        if (mode === 'deep') {
            return {
                timeoutMs: cfg.deepUdpTimeoutMs,
                retries: cfg.deepUdpRetries,
                concurrency: cfg.deepUdpConcurrency || cfg.udpScanConcurrency,
            }
        }
        if (mode === 'advanced') {
            return {
                timeoutMs: cfg.advancedUdpTimeoutMs,
                retries: cfg.advancedUdpRetries,
                concurrency: cfg.advancedUdpConcurrency || cfg.udpScanConcurrency,
            }
        }
        return {
            timeoutMs: cfg.quickUdpTimeoutMs,
            retries: cfg.quickUdpRetries,
            concurrency: cfg.quickUdpConcurrency || cfg.udpScanConcurrency,
        }
    }

    if (mode === 'deep') {
        return {
            timeoutMs: cfg.deepTimeoutMs,
            retries: cfg.deepRetries,
            concurrency: cfg.deepConcurrency || cfg.scanConcurrency,
        }
    }
    if (mode === 'advanced') {
        return {
            timeoutMs: cfg.advancedTimeoutMs,
            retries: cfg.advancedRetries,
            concurrency: cfg.advancedConcurrency || cfg.scanConcurrency,
        }
    }
    return {
        timeoutMs: cfg.quickTimeoutMs,
        retries: cfg.quickRetries,
        concurrency: cfg.quickConcurrency || cfg.scanConcurrency,
    }
}

export function runtimeForModeTransport(
    mode: ScanMode,
    profile: ScanProfile,
    transport: 'tcp' | 'udp',
    cfg: ProbeConfig,
): ScanRuntimeConfig {
    const base = modeBaseRuntime(mode, transport, cfg)

    const timeoutScale = profile === 'safe'
        ? (transport === 'udp' ? 1.28 : 1.2)
        : profile === 'aggressive'
            ? (transport === 'udp' ? 0.95 : 0.85)
            : 1

    const retriesDelta = transport === 'udp'
        ? (profile === 'safe' ? 1 : 0)
        : (profile === 'aggressive' ? 1 : 0)

    const concurrencyScale = profile === 'safe'
        ? (transport === 'udp' ? 0.62 : 0.7)
        : profile === 'aggressive'
            ? (transport === 'udp' ? 1.18 : 1.35)
            : 1

    const timeoutMs = Math.max(500, Math.round(base.timeoutMs * timeoutScale))
    const retries = Math.max(1, base.retries + retriesDelta)
    const concurrency = Math.max(1, Math.round(base.concurrency * concurrencyScale))
    return { timeoutMs, retries, concurrency }
}

export function runtimeForMode(mode: ScanMode, profile: ScanProfile, cfg: ProbeConfig): ScanRuntimeConfig {
    return runtimeForModeTransport(mode, profile, 'tcp', cfg)
}

export function retriesForModeTransport(
    mode: ScanMode,
    profile: ScanProfile,
    transport: 'tcp' | 'udp',
    cfg: ProbeConfig,
): number {
    return runtimeForModeTransport(mode, profile, transport, cfg).retries
}

export function retriesForMode(mode: ScanMode, profile: ScanProfile, cfg: ProbeConfig): number {
    return retriesForModeTransport(mode, profile, 'tcp', cfg)
}

