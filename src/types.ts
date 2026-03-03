export type ScanMode = 'quick' | 'advanced' | 'deep'
export type ScanProfile = 'safe' | 'balanced' | 'aggressive'
export type ScanTransport = 'tcp' | 'udp' | 'both' | 'auto'
export type ScanProtocol = 'tcp' | 'udp'
export type ProbeLanguage = 'en' | 'es'

export type ScanPhase =
    | 'queued'
    | 'tcp_sweep'
    | 'udp_sweep'
    | 'service_probe'
    | 'analysis'
    | 'done'
    | 'error'

export type PortState = 'open' | 'closed' | 'filtered'

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type JobStatus = 'queued' | 'running' | 'done' | 'error'

export interface HttpProbeResult {
    ok: boolean
    protocol: 'http' | 'https'
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

export interface TlsProbeResult {
    ok: boolean
    protocol: string | null
    cipher: string | null
    authorized: boolean
    authorizationError: string | null
    subject: string | null
    issuer: string | null
    validTo: string | null
    expired: boolean | null
    selfSigned: boolean | null
    error?: string
}

export interface BannerProbeResult {
    ok: boolean
    serviceHint: string | null
    banner: string | null
    error?: string
}

export interface PortScanResult {
    port: number
    protocol: ScanProtocol
    service: string
    state: PortState
    stateReason?: string | null
    attempts: number
    rttMs: number | null
    lastError: string | null
    http?: HttpProbeResult
    tls?: TlsProbeResult
    banner?: BannerProbeResult
}

export interface Finding {
    id: string
    severity: FindingSeverity
    category: 'remote-admin' | 'legacy-service' | 'exposure' | 'crypto' | 'hardening' | 'other'
    title: string
    evidence: string
    recommendation: string
    scope: 'wan'
    confidence: number
    impact: string
    ports?: number[]
}

export interface WanScanResult {
    mode: ScanMode
    profile: ScanProfile
    transport: ScanTransport
    language: ProbeLanguage
    target: string
    observedIp: string
    startedAt: string
    finishedAt: string
    durationMs: number
    ports: number[]
    tcpPorts: number[]
    udpPorts: number[]
    openCount: number
    closedCount: number
    filteredCount: number
    openTcpCount: number
    closedTcpCount: number
    filteredTcpCount: number
    openUdpCount: number
    closedUdpCount: number
    filteredUdpCount: number
    results: PortScanResult[]
    findings: Finding[]
    riskScore: number
    confidenceScore: number
    scanMeta: {
        transport: ScanTransport
        timeoutMs: number
        retries: number
        concurrency: number
        tcp: {
            timeoutMs: number
            retries: number
            concurrency: number
        }
        udp: {
            timeoutMs: number
            retries: number
            concurrency: number
        }
        httpProbe: boolean
        tlsProbe: boolean
        bannerProbe: boolean
    }
}

export interface ScanProgress {
    phase: ScanPhase
    message: string
    language?: ProbeLanguage
    transport: ScanTransport
    totalPorts: number
    scannedPorts: number
    openPorts: number
    closedPorts: number
    filteredPorts: number
    totalTcpPorts?: number
    totalUdpPorts?: number
    scannedTcpPorts?: number
    scannedUdpPorts?: number
    openTcpPorts?: number
    closedTcpPorts?: number
    filteredTcpPorts?: number
    openUdpPorts?: number
    closedUdpPorts?: number
    filteredUdpPorts?: number
    servicePortsScanned: number
    percent: number
    startedAt: string
    updatedAt: string
}

export interface NodeMetadata {
    nodeId: string
    label: string
    provider: string | null
    region: string | null
    city: string | null
    country: string | null
    asn: string | null
    publicIp: string | null
}

export interface ScanJob {
    id: string
    status: JobStatus
    phase: ScanPhase
    mode: ScanMode
    profile: ScanProfile
    transport: ScanTransport
    language: ProbeLanguage
    target: string
    observedIp: string
    ports: number[]
    tcpPorts: number[]
    udpPorts: number[]
    progress: ScanProgress
    createdAt: string
    startedAt?: string
    finishedAt?: string
    durationMs?: number
    error?: string
    result?: WanScanResult
}
